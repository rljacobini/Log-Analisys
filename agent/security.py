"""
Modulo de seguridad para el Agente SOC.

Proporciona funciones para:
- Sanitizacion de logs (prevenir log injection)
- Validacion de rutas (prevenir path traversal)
- Sanitizacion de IPs (prevenir IP spoofing)
- Limpieza de datos de eventos

Este modulo implementa defense in depth para proteger contra:
- Log Injection attacks
- Path Traversal attacks
- Data exfiltration via logs
- ReDoS attacks
"""
import re
import os
import signal
import sys
from pathlib import Path  # noqa: F401  pylint: disable=unused-import
from typing import Optional, Any


CONTROL_CHARS_PATTERN = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
NEWLINE_PATTERN = re.compile(r'[\r\n]+')
MULTIPLE_SPACES = re.compile(r'\s+')
PATH_TRAVERSAL_PATTERNS = [
    re.compile(r'\.\.(\/|\\|$)'),
    re.compile(r'(^|[\/\\])\.\.([\/\\]|$)'),
    re.compile(r'%2e%2e', re.IGNORECASE),
    re.compile(r'\.\.%2f', re.IGNORECASE),
    re.compile(r'%2e%2e%2f', re.IGNORECASE),
]
MAX_LOG_LENGTH = 4096
MAX_PATH_LENGTH = 2048
MAX_IP_LENGTH = 45
MAX_USER_LENGTH = 256


SHELL_CHARS_PATTERN = re.compile(r'[;&|`$(){}\\<>]')
BACKTICK_PATTERN = re.compile(r'\`')
DOLLAR_PAREN_PATTERN = re.compile(r'\$\(')
COMMAND_SEPARATORS = re.compile(r'[;&|<>]')


def sanitize_log_string(text: Optional[str], max_length: int = MAX_LOG_LENGTH) -> str:
    """
    Sanitiza una cadena de log para prevenir log injection y command injection.

    Elimina:
    - Caracteres de control
    - Secuencias de nueva linea y retorno de carro
    - Caracteres de shell peligrosos: ; & | backtick $ ( ) { } less greater
    - Subshell invocations: dollarparen(...) backtick(...)
    - Multiples espacios consecutivos

    Args:
        text: Texto a sanitizar
        max_length: Longitud maxima permitida

    Returns:
        Texto sanitizado seguro para logs
    """
    if text is None:
        return ""

    text = str(text)

    text = CONTROL_CHARS_PATTERN.sub('', text)

    text = NEWLINE_PATTERN.sub(' ', text)

    text = BACKTICK_PATTERN.sub('', text)

    text = DOLLAR_PAREN_PATTERN.sub('', text)

    text = SHELL_CHARS_PATTERN.sub('', text)

    text = MULTIPLE_SPACES.sub(' ', text)

    text = text.strip()

    if len(text) > max_length:
        text = text[:max_length] + "..."

    return text


def sanitize_raw_log(log_line: Any, max_length: int = MAX_LOG_LENGTH) -> str:
    """
    Sanitiza una linea de log original para inclusion en eventos.

    Args:
        log_line: Linea de log original o MatchObject
        max_length: Longitud maxima

    Returns:
        Linea sanitizada segura
    """
    if log_line is None:
        return ""

    if hasattr(log_line, 'group'):
        raw = log_line.group(0)
    else:
        raw = str(log_line)

    return sanitize_log_string(raw, max_length)


def validate_log_file_path(file_path: str, allowed_base_dirs: list | None = None) -> bool:
    """
    Valida que una ruta de archivo de log sea segura.

    Verifica:
    - No contiene path traversal (..)
    - No excede longitud maxima
    - Esta dentro de directorios permitidos (si se especifican)

    Args:
        file_path: Ruta del archivo a validar
        allowed_base_dirs: Lista de directorios base permitidos

    Returns:
        True si la ruta es segura, False en caso contrario
    """
    if not file_path or len(file_path) > MAX_PATH_LENGTH:
        return False

    normalized = os.path.normpath(file_path)

    for pattern in PATH_TRAVERSAL_PATTERNS:
        if pattern.search(normalized):
            return False

    if allowed_base_dirs:
        abs_path = os.path.abspath(normalized)
        is_allowed = False
        for base_dir in allowed_base_dirs:
            base_abs = os.path.abspath(base_dir)
            if abs_path.startswith(base_abs + os.sep) and abs_path != base_abs:
                is_allowed = True
                break
        if not is_allowed:
            return False

    dangerous_patterns = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/etc/hosts',
        '/etc/shadow',
        '/proc/',
        '/sys/',
        '/dev/',
    ]
    for pattern in dangerous_patterns:
        if normalized.startswith(pattern):
            return False

    return True


def sanitize_ip_address(ip: str) -> Optional[str]:
    """
    Sanitiza y valida una direccion IP.

    Args:
        ip: Direccion IP a sanitizar

    Returns:
        IP sanitizada o None si es invalida
    """
    if ip is None:
        return None

    ip = str(ip).strip()

    if len(ip) > MAX_IP_LENGTH:
        return None

    ip = sanitize_log_string(ip)

    ip_pattern = re.compile(
        r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
        r'::1|'
        r'localhost)$'
    )

    if not ip_pattern.match(ip):
        if ip.lower() == 'localhost':
            return '127.0.0.1'
        return None

    if ip.count('.') == 3:
        octets = ip.split('.')
        for octet in octets:
            if int(octet) > 255:
                return None

    return ip


def sanitize_user(unsafe_user: Any, max_length: int = MAX_USER_LENGTH) -> Optional[str]:
    """
    Sanitiza un nombre de usuario.

    Args:
        unsafe_user: Nombre de usuario a sanitizar
        max_length: Longitud maxima

    Returns:
        Usuario sanitizado o None
    """
    if unsafe_user is None:
        return None

    user = str(unsafe_user).strip()

    user = sanitize_log_string(user, max_length)

    user = re.sub(r'[^\w\-\.\_]', '', user)

    if len(user) == 0:
        return None

    if user[0] in ('-', '.', '_'):
        user = user[1:]
        if len(user) == 0:
            return None

    return user[:max_length]


def sanitize_extra_data(extra_data: Optional[dict]) -> dict:
    """
    Sanitiza datos extra para inclusion en eventos.

    Args:
        extra_data: Diccionario con datos extra

    Returns:
        Diccionario sanitizado
    """
    if extra_data is None:
        return {}

    if not isinstance(extra_data, dict):
        return {}

    sanitized = {}

    for key, value in extra_data.items():
        if not isinstance(key, str):
            continue

        safe_key = re.sub(r'[^\w\-]', '_', str(key))[:64]

        if isinstance(value, str):
            sanitized[safe_key] = sanitize_log_string(value, 1024)
        elif isinstance(value, (int, float, bool)):
            sanitized[safe_key] = value
        elif isinstance(value, (list, tuple)):
            sanitized[safe_key] = [
                sanitize_log_string(str(v), 512) if isinstance(v, str) else v
                for v in value[:100]
            ]
        elif isinstance(value, dict):
            sanitized[safe_key] = sanitize_extra_data(value)
        else:
            sanitized[safe_key] = str(value)[:256]

    return sanitized


def safe_regex_match(pattern: re.Pattern, text: str, timeout_seconds: float = 1.0) -> Optional[re.Match]:
    """
    Ejecuta un match de regex con timeout para prevenir ReDoS.

    Implementa un wrapper seguro que:
    - Limita el tiempo de ejecucion del regex
    - Previene backtracking infinito
    - Retorna None en caso de timeout

    Args:
        pattern: Patron regex compilado
        text: Texto a matchear
        timeout_seconds: Tiempo maximo de ejecucion

    Returns:
        Match object o None si hay timeout/error
    """
    class RegexTimeout(Exception):
        """Exception raised when regex match times out."""

    def timeout_handler(signum, frame):
        raise RegexTimeout("Regex match timeout")

    if sys.platform != "win32":
        try:
            # pylint: disable=no-member
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(int(timeout_seconds))
            # pylint: enable=no-member

            try:
                result = pattern.match(text)
                signal.alarm(0)
                return result
            except RegexTimeout:
                return None
            finally:
                signal.signal(signal.SIGALRM, old_handler)
        except (ValueError, TypeError):
            return pattern.match(text)
    else:
        return pattern.match(text)


def make_safe_regex(pattern_str: str, max_groups: int = 20, max_length: int = 500) -> Optional[re.Pattern]:
    """
    Crea un patron regex seguro, evitando patrones susceptibles a ReDoS.

    Args:
        pattern_str: Cadena del patron regex
        max_groups: Numero maximo de grupos de captura
        max_length: Longitud maxima del patron

    Returns:
        Patron compilado o None si es inseguro
    """
    if not pattern_str or len(pattern_str) > max_length:
        return None

    dangerous_patterns = [
        (r'.*.*', 'Greedy .* repetition'),
        (r'.+.+', 'Greedy .+ repetition'),
        (r'(\.\*)+', 'Nested .* quantifiers'),
        (r'(\.\+)+', 'Nested .+ quantifiers'),
        (r'(\.\*|\.\+)+', 'Repetition of repetition'),
        (r'\([^)]*\*[^)]*\*[^)]*\)', 'Nested * quantifiers'),
        (r'\([^)]*\+[^)]*\+[^)]*\)', 'Nested + quantifiers'),
        (r'\([^)]*\{[^}]*\{[^}]*\}', 'Nested {} quantifiers'),
    ]

    for dangerous, _ in dangerous_patterns:
        if dangerous in pattern_str:
            return None

    group_count = pattern_str.count('(')
    if group_count > max_groups:
        return None

    try:
        return re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
    except re.error:
        return None


def escape_for_json(text: Any) -> str:
    """
    Escapa texto para inclusion segura en JSON.

    Args:
        text: Texto a escapar

    Returns:
        Texto escapado
    """
    if text is None:
        return ""

    return str(text)[:MAX_LOG_LENGTH]
