import sqlite3
import os

def get_connection(db_path):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def log_alert(db_path, alert):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (timestamp, src_ip, dst_ip, attack_type, severity, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert.get("timestamp"),
        alert.get("src_ip"),
        alert.get("dst_ip"),
        alert.get("attack_type"),
        alert.get("severity"),
        alert.get("status", "Active")
    ))
    conn.commit()
    conn.close()

def get_all_alerts(db_path):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 100")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_statistics(db_path):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT src_ip) FROM alerts")
    unique_ips = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='High'")
    high_sev = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status='Active'")
    active_threats = cursor.fetchone()[0]

    conn.close()
    return {
        "total_events": total_events,
        "unique_ips": unique_ips,
        "high_severity": high_sev,
        "active_threats": active_threats
    }

def get_suspicious_ips(db_path):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT src_ip, COUNT(*) as attack_count, MAX(severity) as max_severity
        FROM alerts
        GROUP BY src_ip
        ORDER BY attack_count DESC
        LIMIT 10
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def clear_alerts_db(db_path):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()