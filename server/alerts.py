"""
Modulo de alertas via Telegram.

Este modulo se encarga de enviar notificaciones a Telegram cuando
se detectan eventos de seguridad de alto riesgo.

Las alertas incluyen informacion completa:
- IP origen del ataque
- Host objetivo (donde esta el agente)
- Servicio afectado
- Tipo y severidad del ataque
- Agente que reporto
"""

import logging
import os
import time
from functools import wraps

import requests


logger = logging.getLogger(__name__)


EMOJI_SEVERITY = {
    "CRITICAL": "\u26a0\ufe0f",
    "HIGH": "\ud83d\udd34",
    "MEDIUM": "\ud83d\udfe1",
    "LOW": "\ud83d\udfe2",
}

EMOJI_SERVICE = {
    "ssh": "\ud83d\udcbb",
    "http": "\ud83c\udf10",
    "https": "\ud83d\udd0d",
    "ftp": "\ud83d\udcce",
    "mysql": "\ud83d\udc30",
    "smtp": "\ud83d\udce7",
    "rdp": "\ud83d\udc5b",
}

EMOJI_DEFAULT = "\ud83d\udccc"


def get_emoji(severity=None, service=None):
    """Obtiene el emoji apropiado para la alerta."""
    if severity and severity in EMOJI_SEVERITY:
        return EMOJI_SEVERITY[severity]
    if service and service.lower() in EMOJI_SERVICE:
        return EMOJI_SERVICE[service.lower()]
    return EMOJI_DEFAULT


def sanitize_message(text):
    """Elimina caracteres Unicode invalidos del texto."""
    if not text:
        return text
    return text.encode('utf-8', errors='ignore').decode('utf-8', errors='ignore')


def retry(max_retries=3, delay=1):
    """Decorador que reintenta una funcion si falla."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except requests.RequestException as exc:
                    if attempt == max_retries - 1:
                        raise
                    wait_time = delay * (attempt + 1)
                    logger.warning(
                        "Retry %d/%d: %s. Esperando %ds",
                        attempt + 1, max_retries, exc, wait_time
                    )
                    time.sleep(wait_time)
        return wrapper
    return decorator


def format_alert_message(
    src_ip=None,
    risk=0,
    severity="LOW",
    attack_type="unknown",
    agent_id=None,
    target_host=None,
    target_service=None,
    source=None,
    **_kwargs
):
    """
    Formatea un mensaje de alerta para Telegram.

    Args:
        src_ip: IP origen del ataque.
        risk: Nivel de riesgo (0-100+).
        severity: Severidad (LOW, MEDIUM, HIGH, CRITICAL).
        attack_type: Tipo de ataque.
        agent_id: ID del agente que reporto.
        target_host: Host que esta siendo atacado.
        target_service: Servicio afectado (ssh, http, etc.).
        source: Fuente del log (auth.log, suricata.log, etc.).

    Returns:
        str: Mensaje formateado para Telegram.
    """
    emoji = get_emoji(severity, target_service)

    lines = [
        f"{emoji} *ALERTA DE SEGURIDAD* {emoji}",
        "",
    ]

    lines.append(f"\u2696\ufe0f *Severidad:* {severity} (risk={risk})")
    lines.append(f"\u26a1 *Tipo:* {attack_type}")

    if src_ip:
        lines.append(f"\ud83d\udcc5 *Origen:* `{src_ip}`")

    if target_host:
        target_line = f"\ud83c\udf0f *Objetivo:* `{target_host}`"
        if target_service:
            target_line += f" ({target_service})"
        lines.append(target_line)
    elif target_service:
        lines.append(f"\ud83c\udf0f *Objetivo:* {target_service}")

    if agent_id:
        lines.append(f"\ud83d\udce3 *Agente:* `{agent_id}`")

    if source:
        lines.append(f"\ud83d\udccc *Log:* `{source}`")

    lines.append("")
    lines.append("\u2014" * 15)
    lines.append("SOC Platform - Revisar dashboard")

    return "\n".join(lines)


def send_alert(
    src_ip=None,
    risk=0,
    severity="LOW",
    attack_type="unknown",
    agent_id=None,
    target_host=None,
    target_service=None,
    source=None,
    message=None
):
    """
    Envia una alerta a Telegram.

    Si se proporciona message, lo usa directamente.
    Si no, construye el mensaje a partir de los parametros.

    Args:
        src_ip: IP origen del ataque.
        risk: Nivel de riesgo.
        severity: Severidad.
        attack_type: Tipo de ataque.
        agent_id: ID del agente.
        target_host: Host objetivo.
        target_service: Servicio afectado.
        source: Fuente del log.
        message: Mensaje personalizado (opcional).

    Returns:
        bool: True si se envio exitosamente, False si hubo error.
    """
    token = os.environ.get("TELEGRAM_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    if not token or token == "PUT_YOUR_TOKEN":
        logger.warning("Telegram token no configurado. Alerta no enviada.")
        return False

    if not chat_id:
        logger.warning("Chat ID no configurado. Alerta no enviada.")
        return False

    if not message:
        message = format_alert_message(
            src_ip=src_ip,
            risk=risk,
            severity=severity,
            attack_type=attack_type,
            agent_id=agent_id,
            target_host=target_host,
            target_service=target_service,
            source=source
        )

    url = f"https://api.telegram.org/bot{token}/sendMessage"

    @retry(max_retries=3, delay=2)
    def _send():
        clean_message = sanitize_message(message)
        response = requests.post(
            url,
            data={
                "chat_id": chat_id,
                "text": clean_message,
                "parse_mode": "Markdown"
            },
            timeout=10
        )
        logger.warning(f"Telegram response: {response.status_code} - {response.text[:200]}")
        response.raise_for_status()
        return response

    try:
        _send()
        logger.info("Alerta enviada: %s from %s risk=%d", attack_type, src_ip, risk)
        return True
    except requests.RequestException as exc:
        logger.error("Error al enviar alerta: %s", exc)
        return False


def alert_brute_force(src_ip, agent_id, target_host, target_service="ssh", **kwargs):
    """Alerta especial para ataques de fuerza bruta."""
    return send_alert(
        src_ip=src_ip,
        risk=kwargs.get("risk", 25),
        severity="HIGH",
        attack_type="brute_force",
        agent_id=agent_id,
        target_host=target_host,
        target_service=target_service,
        source=kwargs.get("source", "auth.log")
    )


def alert_intrusion(src_ip, agent_id, target_host, attack_type,
                     target_service=None, **kwargs):
    """Alerta para intrusiones detectadas."""
    return send_alert(
        src_ip=src_ip,
        risk=kwargs.get("risk", 50),
        severity="CRITICAL",
        attack_type=attack_type,
        agent_id=agent_id,
        target_host=target_host,
        target_service=target_service,
        source=kwargs.get("source")
    )


def alert_dos(src_ip, agent_id, target_host, target_service=None, **kwargs):
    """Alerta para ataques DoS/DDoS."""
    return send_alert(
        src_ip=src_ip,
        risk=kwargs.get("risk", 40),
        severity="HIGH",
        attack_type="dos_attack",
        agent_id=agent_id,
        target_host=target_host,
        target_service=target_service,
        source=kwargs.get("source")
    )
