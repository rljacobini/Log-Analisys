"""
Dashboard web para visualizacion de eventos de seguridad.

Este modulo proporciona una interfaz grafica para ver:
- Estadisticas por agente, fuente, tipo de ataque, IP
- Grafica de IPs con mas ataques
- Distribucion por tipo de ataque y fuente
- Tabla de eventos recientes con filtrado y paginacion

ARQUITECTURA MULTI-AGENTE:
- Muestra informacion de todos los agentes
- Filtra por agente, fuente, nivel de riesgo
- Identifica el host objetivo de cada ataque

Uso:
    python dashboard/app.py

Acceso: http://localhost:8000
Autenticacion: HTTP Basic (usuario/contrasena del .env)
"""

import os
import sqlite3
from flask import Flask, render_template, request, make_response, redirect, url_for, flash
from functools import wraps
from collections import Counter

from chartkick.flask import chartkick_blueprint, BarChart, PieChart, LineChart, AreaChart
from .config import DASHBOARD_USERNAME, DASHBOARD_PASSWORD, DB_PATH, PAGE_SIZE, SECRET_KEY, FLASK_DEBUG

from .config import DASHBOARD_HOST, DASHBOARD_PORT, DASHBOARD_USE_SSL, DASHBOARD_CERT_FILE, DASHBOARD_KEY_FILE

from .config import USE_REMOTE_API, SOC_API_URL, SOC_VERIFY_SSL

api_client = None
if USE_REMOTE_API:
    try:
        from .api_client import SOCAPIClient
        api_client = SOCAPIClient(
            base_url=SOC_API_URL,
            verify_ssl=SOC_VERIFY_SSL
        )
    except Exception as e:
        print(f"Warning: Could not initialize API client: {e}")


# =============================================================================
# INICIALIZACION
# =============================================================================

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config['SECRET_KEY'] = SECRET_KEY
app.register_blueprint(chartkick_blueprint)


# =============================================================================
# AUTENTICACION
# =============================================================================

def require_auth(f):
    """Decorador para autenticacion HTTP Basic."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != DASHBOARD_USERNAME or auth.password != DASHBOARD_PASSWORD:
            return make_response(
                "Unauthorized", 
                401, 
                {"WWW-Authenticate": "Basic realm='SOC Dashboard'"}
            )
        return f(*args, **kwargs)
    return decorated


# =============================================================================
# UTILIDADES
# =============================================================================

def get_db_connection():
    """Crea conexion a la base de datos."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_all_stats():
    """
    Obtiene todas las estadisticas de la base de datos o API remota.

    Returns:
        dict con todas las estadisticas.
    """
    if USE_REMOTE_API and api_client:
        return _get_all_stats_from_api()

    conn = get_db_connection()
    c = conn.cursor()

    stats = {}

    c.execute("SELECT COUNT(*) FROM logs")
    stats['total_logs'] = c.fetchone()[0]

    c.execute("SELECT COUNT(DISTINCT agent_id) FROM logs")
    stats['total_agents'] = c.fetchone()[0]

    c.execute("SELECT risk FROM logs")
    risks = [r['risk'] for r in c.fetchall()]
    stats['risk_dist'] = {
        "Bajo (0-14)": len([r for r in risks if r < 15]),
        "Medio (15-29)": len([r for r in risks if 15 <= r < 30]),
        "Alto (30-49)": len([r for r in risks if 30 <= r < 50]),
        "Critico (50-99)": len([r for r in risks if 50 <= r < 100]),
        "Breach (100+)": len([r for r in risks if r >= 100])
    }
    stats['high'] = len([r for r in risks if 30 <= r < 50])
    stats['critical'] = len([r for r in risks if 50 <= r < 100])
    stats['breach'] = len([r for r in risks if r >= 100])
    stats['high_risk'] = stats['high'] + stats['critical'] + stats['breach']

    c.execute("""
        SELECT src_ip, COUNT(*) as count
        FROM logs
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
        ORDER BY count DESC
        LIMIT 10
    """)
    stats['top_attackers'] = [(r['src_ip'], r['count']) for r in c.fetchall()]

    c.execute("""
        SELECT attack_type, COUNT(*) as count
        FROM logs
        GROUP BY attack_type
        ORDER BY count DESC
    """)
    stats['by_type'] = [(r['attack_type'], r['count']) for r in c.fetchall()]

    c.execute("""
        SELECT source, COUNT(*) as count
        FROM logs
        WHERE source IS NOT NULL
        GROUP BY source
        ORDER BY count DESC
    """)
    stats['by_source'] = [(r['source'], r['count']) for r in c.fetchall()]

    c.execute("""
        SELECT agent_id, COUNT(*) as count
        FROM logs
        GROUP BY agent_id
        ORDER BY count DESC
    """)
    stats['by_agent'] = [(r['agent_id'], r['count']) for r in c.fetchall()]

    c.execute("""
        SELECT target_host, agent_id, COUNT(*) as count
        FROM logs
        WHERE target_host IS NOT NULL
        GROUP BY target_host
        ORDER BY count DESC
        LIMIT 10
    """)
    stats['by_target_host'] = [(r['target_host'], r['agent_id'], r['count']) for r in c.fetchall()]

    c.execute("""
        SELECT severity, COUNT(*) as count
        FROM logs
        GROUP BY severity
    """)
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, None: 4}
    stats['by_severity'] = sorted(
        [(r['severity'] or 'UNKNOWN', r['count']) for r in c.fetchall()],
        key=lambda x: severity_order.get(x[0], 5)
    )

    c.execute("SELECT DISTINCT agent_id FROM logs ORDER BY agent_id")
    stats['agents_list'] = [r['agent_id'] for r in c.fetchall()]

    c.execute("SELECT DISTINCT source FROM logs WHERE source IS NOT NULL ORDER BY source")
    stats['sources_list'] = [r['source'] for r in c.fetchall()]

    conn.close()

    return stats


def _get_all_stats_from_api():
    """Obtiene estadisticas desde la API remota."""
    stats = {
        'total_logs': 0,
        'total_agents': 0,
        'high': 0,
        'critical': 0,
        'high_risk': 0,
        'top_attackers': [],
        'by_type': [],
        'by_source': [],
        'by_agent': [],
        'by_target_host': [],
        'by_severity': [],
        'risk_dist': {"Bajo (0-14)": 0, "Medio (15-29)": 0, "Alto (30-49)": 0, "Critico (50-99)": 0, "Breach (100+)": 0},
        'agents_list': [],
        'sources_list': []
    }

    try:
        if api_client is not None:
            result = api_client.get_stats()
            if isinstance(result, dict) and result.get('status') == 'success':
                data = result.get('data', {})
                if isinstance(data, dict):
                    risk_dist_api = data.get('risk_distribution', {})
                    if isinstance(risk_dist_api, dict):
                        stats['risk_dist'] = {
                            "Bajo (0-14)": risk_dist_api.get('LOW', 0),
                            "Medio (15-29)": risk_dist_api.get('MEDIUM', 0),
                            "Alto (30-49)": risk_dist_api.get('HIGH', 0),
                            "Critico (50-99)": risk_dist_api.get('CRITICAL', 0),
                            "Breach (100+)": risk_dist_api.get('BREACH', 0)
                        }
                    stats['total_logs'] = data.get('total_logs', 0)
                    stats['total_agents'] = data.get('total_agents', 0)
                    stats['high_risk'] = data.get('high_risk_events', 0)
                    stats['critical'] = data.get('critical_events', 0)
                    stats['breach'] = data.get('breach_events', 0)
                    stats['high'] = stats['high_risk'] - stats['critical'] - stats['breach']
                    stats['by_severity'] = list(stats['risk_dist'].items())

            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {
                    'top_ips': executor.submit(api_client.get_chart_top_ips, 10),
                    'by_type': executor.submit(api_client.get_chart_by_type),
                    'by_source': executor.submit(api_client.get_chart_by_source),
                    'by_agent': executor.submit(api_client.get_chart_by_agent),
                    'agents': executor.submit(api_client.get_agents),
                }
                
                for key, future in futures.items():
                    try:
                        result = future.result(timeout=10)
                        if isinstance(result, dict) and result.get('status') == 'success':
                            data_list = result.get('data', [])
                            if isinstance(data_list, list):
                                if key == 'top_ips':
                                    stats['top_attackers'] = [(d['ip'], d['count']) for d in data_list if isinstance(d, dict)]
                                elif key == 'by_type':
                                    stats['by_type'] = [(d['type'], d['count']) for d in data_list if isinstance(d, dict)]
                                elif key == 'by_source':
                                    stats['by_source'] = [(d['source'], d['count']) for d in data_list if isinstance(d, dict)]
                                    stats['sources_list'] = [d['source'] for d in data_list if isinstance(d, dict)]
                                elif key == 'by_agent':
                                    stats['by_agent'] = [(d['agent'], d['count']) for d in data_list if isinstance(d, dict)]
                                elif key == 'agents':
                                    stats['agents_list'] = [a['agent_id'] for a in data_list if isinstance(a, dict)]
                    except Exception as e:
                        print(f"Error fetching {key}: {e}")

    except Exception as e:
        print(f"Error getting stats from API: {e}")

    return stats


def get_logs(filters=None, limit=50, offset=0):
    """
    Obtiene logs con filtros opcionales.

    Args:
        filters: Dict con filtros (agent_id, source, min_risk)
        limit: Numero maximo de registros
        offset: Offset para paginacion

    Returns:
        Lista de eventos.
    """
    if USE_REMOTE_API and api_client:
        return _get_logs_from_api(filters, limit, offset)

    conn = get_db_connection()
    c = conn.cursor()

    query = "SELECT * FROM logs WHERE 1=1"
    params = []

    if filters:
        if filters.get('agent_id'):
            query += " AND agent_id = ?"
            params.append(filters['agent_id'])

        if filters.get('source'):
            query += " AND source = ?"
            params.append(filters['source'])

        if filters.get('min_risk'):
            query += " AND risk >= ?"
            params.append(filters['min_risk'])

        if filters.get('src_ip'):
            query += " AND src_ip LIKE ?"
            params.append(f"%{filters['src_ip']}%")

    query += " ORDER BY event_time DESC, timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    c.execute(query, params)
    logs = c.fetchall()
    conn.close()

    return logs


def _get_logs_from_api(filters=None, limit=50, offset=0):
    """Obtiene logs desde la API remota."""
    if api_client is None:
        return []
    page = (offset // limit) + 1
    filter_params = {k: v for k, v in (filters or {}).items() if v}
    result = api_client.get_logs(page=page, per_page=limit, **filter_params)

    if isinstance(result, dict) and result.get('status') == 'success':
        logs_data = result.get('data', [])
        if isinstance(logs_data, list):
            return [dict(log) for log in logs_data]
    return []


def get_logs_count(filters=None):
    """Obtiene el total de logs con filtros."""
    if USE_REMOTE_API and api_client:
        return _get_logs_count_from_api(filters)

    conn = get_db_connection()
    c = conn.cursor()

    query = "SELECT COUNT(*) FROM logs WHERE 1=1"
    params = []

    if filters:
        if filters.get('agent_id'):
            query += " AND agent_id = ?"
            params.append(filters['agent_id'])

        if filters.get('source'):
            query += " AND source = ?"
            params.append(filters['source'])

        if filters.get('min_risk'):
            query += " AND risk >= ?"
            params.append(filters['min_risk'])

    c.execute(query, params)
    count = c.fetchone()[0]
    conn.close()

    return count


def _get_logs_count_from_api(filters=None):
    """Obtiene conteo de logs desde la API remota."""
    if api_client is None:
        return 0
    filter_params = {k: v for k, v in (filters or {}).items() if v}
    result = api_client.get_logs(page=1, per_page=1, **filter_params)

    if isinstance(result, dict) and result.get('status') == 'success':
        meta = result.get('meta', {})
        if isinstance(meta, dict):
            return meta.get('total', 0)
    return 0


# =============================================================================
# RUTAS
# =============================================================================

@app.route("/")
@require_auth
def dashboard():
    """
    Pagina principal del dashboard.
    """
    stats = get_all_stats()
    
    # Construir filtros desde query params
    filters = {}
    if request.args.get('agent'):
        filters['agent_id'] = request.args.get('agent')
    if request.args.get('source'):
        filters['source'] = request.args.get('source')
    if request.args.get('min_risk'):
        filters['min_risk'] = int(request.args.get('min_risk') or 0)
    if request.args.get('ip'):
        filters['src_ip'] = request.args.get('ip')
    
    # Paginacion
    page = request.args.get('page', 1, type=int)
    offset = (page - 1) * PAGE_SIZE
    
    # Obtener logs
    logs = get_logs(filters, PAGE_SIZE, offset)
    total_logs = get_logs_count(filters)
    total_pages = (total_logs + PAGE_SIZE - 1) // PAGE_SIZE
    
    # Graficos
    top_ips_chart = BarChart(
        dict(stats['top_attackers'][:10]),
        title="Top 10 IPs Atacantes",
        colors=["#ef4444"]
    )
    
    attack_types_chart = PieChart(
        dict(stats['by_type'][:8]),
        title="Tipos de Ataque"
    )
    
    by_source_chart = PieChart(
        dict(stats['by_source']),
        title="Por Fuente de Log"
    )
    
    by_agent_chart = BarChart(
        dict(stats['by_agent']),
        title="Eventos por Agente",
        colors=["#38bdf8"]
    )
    
    risk_chart = BarChart(
        stats['risk_dist'],
        title="Distribucion de Riesgo",
        colors=["#22c55e", "#eab308", "#f97316", "#ef4444"]
    )
    
    return render_template(
        "dashboard.html",
        stats=stats,
        logs=logs,
        page=page,
        total_pages=total_pages,
        total_logs=total_logs,
        filters=filters,
        top_ips_chart=top_ips_chart,
        attack_types_chart=attack_types_chart,
        by_source_chart=by_source_chart,
        by_agent_chart=by_agent_chart,
        risk_chart=risk_chart
    )


@app.route("/agents")
@require_auth
def agents_page():
    """Pagina con informacion de agentes."""
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        c.execute("""
            SELECT 
                a.agent_id,
                a.hostname,
                a.ip_address,
                a.status,
                a.last_seen,
                COUNT(l.id) as total_events,
                MAX(l.risk) as max_risk,
                MAX(l.timestamp) as last_event
            FROM agents a
            LEFT JOIN logs l ON a.agent_id = l.agent_id
            GROUP BY a.agent_id
            ORDER BY total_events DESC
        """)
        agents = c.fetchall()
        conn.close()
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Agents query error: {e}")
        agents = []
    
    return render_template("agents.html", agents=agents)


@app.route("/health")
def health():
    """Endpoint de verificacion."""
    return {"status": "healthy"}


@app.route("/.well-known/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE"])
def well_known(subpath):
    """Silencia requests de Chrome y otros browsers."""
    return {"status": "ok"}


@app.route('/favicon.ico')
def favicon():
    """Serve favicon."""
    from flask import send_from_directory
    return send_from_directory(app.static_folder, 'favicon.ico')


@app.route("/threats")
@require_auth
def threats_page():
    """Pagina de amenazas correlacionadas."""
    if USE_REMOTE_API and api_client:
        return _threats_from_api()
    
    return _threats_from_db()


def _threats_from_db():
    """Obtiene amenazas desde BD directa."""
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("""
        SELECT ip, max_risk, agent_count, attack_types, agent_ids,
               is_compromised, is_coordinated, event_count, last_seen
        FROM threat_intel
        ORDER BY max_risk DESC, event_count DESC
        LIMIT 50
    """)
    rows = c.fetchall()
    
    c.execute("SELECT COUNT(*) as total FROM threat_intel")
    total = c.fetchone()['total']
    
    c.execute("SELECT COUNT(*) as count FROM threat_intel WHERE is_compromised = 1")
    compromised = c.fetchone()['count']
    
    c.execute("SELECT COUNT(*) as count FROM threat_intel WHERE is_coordinated = 1")
    coordinated = c.fetchone()['count']
    
    conn.close()
    
    import json
    threats = []
    for row in rows:
        threat = dict(row)
        threat['attack_types'] = json.loads(threat['attack_types']) if threat['attack_types'] else {}
        if isinstance(threat['attack_types'], list):
            threat['attack_types_display'] = [f"{k} ({v})" for k, v in threat['attack_types'].items()]
        else:
            threat['attack_types_display'] = [f"{k} ({v})" for k, v in sorted(threat['attack_types'].items(), key=lambda x: -x[1])]
        threat['agent_ids'] = json.loads(threat['agent_ids']) if threat['agent_ids'] else []
        threats.append(threat)
    
    return render_template("threats.html",
                          threats=threats,
                          total=total,
                          compromised=compromised,
                          coordinated=coordinated)


def _threats_from_api():
    """Obtiene amenazas desde API."""
    try:
        summary_result = api_client.get_threats_summary()
        threats_result = api_client.get_threats(limit=50)
        
        summary = {}
        if summary_result.get('status') == 'success':
            summary = summary_result.get('data', {})
        
        threats = []
        if threats_result.get('status') == 'success':
            threats = threats_result.get('data', [])
        
        return render_template("threats.html",
                              threats=threats,
                              total=summary.get('total_threats', 0),
                              compromised=summary.get('compromised_count', 0),
                              coordinated=summary.get('coordinated_count', 0),
                              summary=summary)
    except Exception as e:
        flash(f"Error cargando amenazas: {e}")
        return render_template("threats.html", threats=[], total=0, compromised=0, coordinated=0)


@app.route("/pcap")
@app.route("/pcap/<int:page>")
@require_auth
def pcap_page(page=1):
    """Pagina de detecciones PCAP con paginacion."""
    try:
        if USE_REMOTE_API and api_client:
            return _pcap_from_api(page=page)
        return _pcap_from_db(page)
    except Exception as e:
        import traceback
        traceback.print_exc()
        flash(f"Error: {str(e)}")
        return render_template("pcap_detections.html", detections=[], total=0, page=1, total_pages=1)

PCAP_PAGE_SIZE = 25

def _pcap_from_db(page=1):
    """Obtiene detecciones PCAP desde BD direta con paginacion."""
    import json
    
    offset = (page - 1) * PCAP_PAGE_SIZE
    
    conn = get_db_connection()
    c = conn.cursor()
    
    # Contar total
    c.execute("""
        SELECT COUNT(*) FROM logs 
        WHERE source != 'test' AND (attack_type LIKE '%download%' OR attack_type LIKE '%flood%' OR 
              attack_type LIKE '%c2%' OR attack_type LIKE '%scan%' OR attack_type LIKE '%malware%'
              OR attack_type LIKE '%network_enumeration%' OR attack_type LIKE '%weak_crypto%')
    """)
    total = c.fetchone()[0]
    total_pages = (total + PCAP_PAGE_SIZE - 1) // PCAP_PAGE_SIZE
    
    # Calcular estadísticas sobre TODOS los registros (no solo la página actual)
    c.execute("""
        SELECT severity, attack_type FROM logs 
        WHERE source != 'test' AND (attack_type LIKE '%download%' OR attack_type LIKE '%flood%' OR 
              attack_type LIKE '%c2%' OR attack_type LIKE '%scan%' OR attack_type LIKE '%malware%'
              OR attack_type LIKE '%network_enumeration%' OR attack_type LIKE '%weak_crypto%')
    """)
    all_rows = c.fetchall()
    critical_count = len([r for r in all_rows if r[0] == 'CRITICAL'])
    high_count = len([r for r in all_rows if r[0] == 'HIGH'])
    medium_count = len([r for r in all_rows if r[0] == 'MEDIUM'])
    low_count = len([r for r in all_rows if r[0] == 'LOW'])
    info_count = len([r for r in all_rows if r[0] == 'INFO'])
    severity_summary = [
        ("CRITICAL", critical_count, "#ef4444"),
        ("HIGH", high_count, "#f97316"),
        ("MEDIUM", medium_count, "#eab308"),
        ("LOW", low_count, "#22c55e"),
        ("INFO", info_count, "#3b82f6")
    ]
    
    # Obtener conteo por tipo de ataque
    attack_type_counts = {}
    for r in all_rows:
        if r[1]:
            attack_type_counts[r[1]] = attack_type_counts.get(r[1], 0) + 1
    attack_type_summary = sorted(attack_type_counts.items(), key=lambda x: x[1], reverse=True)
    
    # Buscar por attack_type PCAP
    c.execute("""
        SELECT id, src_ip, src_port, target_host, target_port, attack_type, severity, risk, 
               report_time, extra_data, protocol, source
        FROM logs 
        WHERE source != 'test' AND (attack_type LIKE '%download%' OR attack_type LIKE '%flood%' OR 
              attack_type LIKE '%c2%' OR attack_type LIKE '%scan%' OR attack_type LIKE '%malware%'
              OR attack_type LIKE '%network_enumeration%' OR attack_type LIKE '%weak_crypto%')
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """, (PCAP_PAGE_SIZE, offset))
    rows = c.fetchall()
    conn.close()
    
    detections = []
    for row in rows:
        extra_data = {}
        try:
            if row[9]:
                extra_data = json.loads(row[9])
        except:
            pass
        
        db_protocol = row[10] if row[10] else ""
        source_ports = extra_data.get("indicators", {}).get("source_ports", [])
        protocol = db_protocol or ("HTTPS" if 443 in source_ports else "HTTP" if 80 in source_ports else "")
        if not protocol and source_ports:
            protocol = ",".join(map(str, source_ports[:3]))
        
        detections.append({
            "id": row[0],
            "source": row[1],
            "src_port": row[2],
            "target_host": row[3],
            "target_port": row[4],
            "attack_type": row[5],
            "severity": row[6],
            "risk": row[7],
            "timestamp": row[8],
            "mitre": extra_data.get("mitre_technique", ""),
            "protocol": protocol,
            "count": extra_data.get("indicators", {}).get("download_count") or extra_data.get("indicators", {}).get("packet_count", ""),
            "description": extra_data.get("evidence", [""])[0] if extra_data.get("evidence") else ""
        })
    
    return render_template("pcap_detections.html", 
                       detections=detections, 
                       total=total,
                       critical_count=critical_count,
                       high_count=high_count,
                       medium_count=medium_count,
                       low_count=low_count,
                       info_count=info_count,
                       severity_summary=severity_summary,
                       attack_type_summary=attack_type_summary,
                       page=page,
                       total_pages=total_pages)

def _pcap_from_api(page=1):
    """Obtiene detecciones PCAP desde API remota."""
    try:
        offset = (page - 1) * PCAP_PAGE_SIZE
        response = api_client.get("/logs", params={"source": "pcap", "limit": PCAP_PAGE_SIZE, "offset": offset})
        if response.status_code == 200:
            data = response.json()
            total = data.get("total", 0)
            total_pages = (total + PCAP_PAGE_SIZE - 1) // PCAP_PAGE_SIZE
            return render_template("pcap_detections.html", 
                             detections=data.get("data", []), 
                             total=total,
                             page=page,
                             total_pages=total_pages)
    except Exception as e:
        flash(f"Error cargando PCAP: {e}")
    
    return render_template("pcap_detections.html", detections=[], total=0, page=1, total_pages=1)

@app.route("/threats/<ip>")
@require_auth
def threat_detail_page(ip):
    """Pagina de detalle de una amenaza."""
    if USE_REMOTE_API and api_client:
        return _threat_detail_from_api(ip)
    
    return _threat_detail_from_db(ip)


def _threat_detail_from_db(ip):
    """Obtiene detalle desde BD directa."""
    import json
    
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("""
        SELECT * FROM threat_intel WHERE ip = ?
    """, (ip,))
    threat_row = c.fetchone()
    
    c.execute("""
        SELECT DISTINCT agent_id, attack_type, risk, timestamp, target_host
        FROM logs WHERE src_ip = ?
        ORDER BY event_time DESC
    """, (ip,))
    events = c.fetchall()
    
    c.execute("SELECT * FROM agents")
    agents = c.fetchall()
    
    conn.close()
    
    if not threat_row:
        flash(f"Amenaza no encontrada: {ip}")
        return redirect(url_for('threats_page'))
    
    threat = dict(threat_row)
    at_data = json.loads(threat['attack_types']) if threat['attack_types'] else {}
    if isinstance(at_data, list):
        threat['attack_types'] = at_data
        threat['attack_types_display'] = at_data
    else:
        threat['attack_types'] = at_data
        threat['attack_types_display'] = [f"{k} ({v})" for k, v in sorted(at_data.items(), key=lambda x: -x[1])]
    
    threat_dict = {
        'ip': threat['ip'],
        'max_risk': threat['max_risk'],
        'avg_risk': threat['avg_risk'],
        'agent_count': threat['agent_count'],
        'attack_types': threat['attack_types_display'],
        'agent_ids': json.loads(threat['agent_ids']) if threat['agent_ids'] else [],
        'is_compromised': threat['is_compromised'],
        'is_coordinated': threat['is_coordinated'],
        'event_count': threat['event_count'],
        'first_seen': threat['first_seen'],
        'last_seen': threat['last_seen'],
        'recommendations': json.loads(threat['recommendations']) if threat['recommendations'] else []
    }
    
    events_list = [dict(e) for e in events]
    
    return render_template("threat_detail.html", threat=threat_dict, events=events_list, agents=agents)


def _threat_detail_from_api(ip):
    """Obtiene detalle desde API."""
    try:
        result = api_client.get_threat_detail(ip)
        
        if result.get('status') != 'success':
            flash(f"Amenaza no encontrada: {ip}")
            return redirect(url_for('threats_page'))
        
        data = result.get('data', {})
        threat = data.get('threat', {})
        agents_data = data.get('agents_affected', [])
        
        return render_template("threat_detail.html", 
                              threat=threat, 
                              events=agents_data)
    except Exception as e:
        flash(f"Error: {e}")
        return redirect(url_for('threats_page'))


# =============================================================================
# INICIO
# =============================================================================

if __name__ == "__main__":
    import sys
    import os
    ssl_context = None
    
    print(f"DEBUG: DASHBOARD_USE_SSL = {DASHBOARD_USE_SSL}")
    print(f"DEBUG: DASHBOARD_CERT_FILE = {DASHBOARD_CERT_FILE}")
    print(f"DEBUG: DASHBOARD_KEY_FILE = {DASHBOARD_KEY_FILE}")
    
    if DASHBOARD_USE_SSL:
        if DASHBOARD_CERT_FILE and DASHBOARD_KEY_FILE:
            cert_path = DASHBOARD_CERT_FILE
            key_path = DASHBOARD_KEY_FILE
            
            print(f"DEBUG: Checking cert at {cert_path}")
            print(f"DEBUG: CERT exists = {os.path.exists(cert_path)}")
            print(f"DEBUG: KEY exists = {os.path.exists(key_path)}")
            
            if os.path.exists(cert_path) and os.path.exists(key_path):
                ssl_context = (cert_path, key_path)
                print(f"Iniciando con HTTPS: {cert_path}")
            else:
                print(f"ADVERTENCIA: Certificados no encontrados.")
                print(f"  CERT: {cert_path} - {'EXISTS' if os.path.exists(cert_path) else 'NOT FOUND'}")
                print(f"  KEY:  {key_path} - {'EXISTS' if os.path.exists(key_path) else 'NOT FOUND'}")
                print("Iniciando sin HTTPS...")
        else:
            print("ADVERTENCIA: DASHBOARD_USE_SSL=true pero certificados no configurados.")
            print("Iniciando sin HTTPS...")
    else:
        print("Iniciando con HTTP (DASHBOARD_USE_SSL=false)")
    
    protocol = "https" if ssl_context else "http"
    print(f"Dashboard disponible en: {protocol}://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    
    app.run(
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        debug=FLASK_DEBUG,
        ssl_context=ssl_context
    )
