import sqlite3
import json
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "logs.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    # Enable Write-Ahead Logging (WAL) mode for concurrent read/write support
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
    except sqlite3.OperationalError:
        pass
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyzed_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            alert_name TEXT,
            description TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            dst_service TEXT,
            protocol TEXT,
            freq_per_min INTEGER,
            time_context TEXT,
            risk_score INTEGER,
            prediction TEXT,
            proba_normal REAL,
            proba_fp REAL,
            proba_attack REAL,
            true_class TEXT,
            raw_log TEXT,
            llm_analyzed INTEGER DEFAULT 0,
            llm_summary TEXT,
            llm_risk_level TEXT,
            llm_attack_type TEXT,
            llm_mitre TEXT,
            llm_recommendations TEXT,
            llm_iocs TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_log(log_data):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # We might extract fields from the log_data dict
    raw_log_str = json.dumps(log_data)
    
    cursor.execute("""
        INSERT INTO analyzed_logs (
            timestamp, alert_name, description, src_ip, dst_ip, src_port, dst_port,
            dst_service, protocol, freq_per_min, time_context, risk_score, prediction,
            proba_normal, proba_fp, proba_attack, true_class, raw_log
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        log_data.get("timestamp"),
        log_data.get("alert_name"),
        log_data.get("description"),
        log_data.get("src_ip"),
        log_data.get("dst_ip"),
        log_data.get("src_port"),
        log_data.get("dst_port"),
        log_data.get("dst_service"),
        log_data.get("protocol"),
        log_data.get("freq_per_min"),
        log_data.get("time_context"),
        log_data.get("risk_score"),
        log_data.get("prediction"),
        log_data.get("proba_normal"),
        log_data.get("proba_fp"),
        log_data.get("proba_attack"),
        log_data.get("true_class"),
        raw_log_str
    ))
    log_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return log_id

def update_llm_analysis(log_id, analysis_data):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE analyzed_logs SET
            llm_analyzed = 1,
            llm_summary = ?,
            llm_risk_level = ?,
            llm_attack_type = ?,
            llm_mitre = ?,
            llm_recommendations = ?,
            llm_iocs = ?
        WHERE id = ?
    """, (
        analysis_data.get("summary"),
        analysis_data.get("risk_level"),
        analysis_data.get("attack_type"),
        analysis_data.get("mitre"),
        json.dumps(analysis_data.get("recommendations", [])),
        json.dumps(analysis_data.get("iocs", [])),
        log_id
    ))
    conn.commit()
    conn.close()

def get_logs(limit=100, offset=0, prediction=None, min_risk=0, search_query=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM analyzed_logs WHERE risk_score >= ?"
    params = [min_risk]
    
    if prediction:
        query += " AND prediction = ?"
        params.append(prediction)
        
    if search_query:
        query += " AND (alert_name LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ?)"
        like_str = f"%{search_query}%"
        params.extend([like_str, like_str, like_str])
        
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    # Get total count with same filters (without limit/offset)
    count_query = "SELECT COUNT(*) FROM analyzed_logs WHERE risk_score >= ?"
    count_params = [min_risk]
    
    if prediction:
        count_query += " AND prediction = ?"
        count_params.append(prediction)
        
    if search_query:
        count_query += " AND (alert_name LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ?)"
        count_params.extend([like_str, like_str, like_str])
        
    cursor.execute(count_query, count_params)
    total_count = cursor.fetchone()[0]
    
    conn.close()
    
    logs = []
    for row in rows:
        log_dict = dict(row)
        log_dict["llm_recommendations"] = json.loads(log_dict["llm_recommendations"]) if log_dict["llm_recommendations"] else []
        log_dict["llm_iocs"] = json.loads(log_dict["llm_iocs"]) if log_dict["llm_iocs"] else []
        log_dict["raw_log"] = json.loads(log_dict["raw_log"]) if log_dict["raw_log"] else {}
        logs.append(log_dict)
        
    return logs, total_count

def get_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM analyzed_logs")
    total = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM analyzed_logs WHERE prediction = 'attack'")
    attacks = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM analyzed_logs WHERE prediction = 'false_positive'")
    fps = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM analyzed_logs WHERE prediction = 'normal'")
    normals = cursor.fetchone()[0]
    
    cursor.execute("SELECT AVG(risk_score) FROM analyzed_logs")
    avg_risk_row = cursor.fetchone()
    avg_risk = round(avg_risk_row[0], 1) if avg_risk_row and avg_risk_row[0] is not None else 0.0
    
    # Timeline: last 50 logs
    cursor.execute("SELECT id, timestamp, prediction, risk_score, alert_name, src_ip FROM analyzed_logs ORDER BY id DESC LIMIT 50")
    timeline_rows = cursor.fetchall()
    timeline = [dict(row) for row in reversed(timeline_rows)]
    
    # Top triggered rules/alert names
    cursor.execute("SELECT alert_name, COUNT(*) as count FROM analyzed_logs GROUP BY alert_name ORDER BY count DESC LIMIT 5")
    top_rules = [dict(row) for row in cursor.fetchall()]
    
    # Scatter: Risk vs Frequency (last 200 logs)
    cursor.execute("SELECT freq_per_min, risk_score, prediction, alert_name, src_ip FROM analyzed_logs ORDER BY id DESC LIMIT 200")
    scatter = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return {
        "total": total,
        "attacks": attacks,
        "false_positives": fps,
        "normal": normals,
        "average_risk": avg_risk,
        "timeline": timeline,
        "top_rules": top_rules,
        "scatter": scatter
    }

def clear_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM analyzed_logs")
    conn.commit()
    conn.close()
