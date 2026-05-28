"""
database.py â€” SQLite persistence for alerts and incidents.
"""
import sqlite3, json
from datetime import datetime
from pathlib import Path
from detector import Alert

DB_PATH = Path(__file__).parent / "sentineliq.db"

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    with get_conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT, timestamp TEXT, severity_score INTEGER,
            severity_label TEXT, source_ip TEXT, username TEXT,
            description TEXT, plain_description TEXT, why_flagged TEXT,
            confidence INTEGER DEFAULT 50,
            evidence TEXT, mitre_id TEXT, mitre_tactic TEXT, mitre_name TEXT,
            mitre_stage INTEGER DEFAULT 0, status TEXT DEFAULT 'open',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY, source_ip TEXT,
            start_time TEXT, end_time TEXT, duration_minutes INTEGER,
            overall_severity TEXT, overall_score INTEGER, confidence INTEGER,
            incident_type TEXT, attack_chain TEXT, stage_timeline TEXT,
            ai_story TEXT, ai_conclusion TEXT, ai_intent TEXT,
            recommended_actions TEXT, risk_probability INTEGER DEFAULT 0,
            alert_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
        CREATE INDEX IF NOT EXISTS idx_a_ts  ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_a_ip  ON alerts(source_ip);
        CREATE INDEX IF NOT EXISTS idx_a_sev ON alerts(severity_score);
        CREATE INDEX IF NOT EXISTS idx_i_ts  ON incidents(start_time);
        """)

def insert_alert(a: Alert) -> int:
    with get_conn() as c:
        cur = c.execute("""
            INSERT INTO alerts (attack_type,timestamp,severity_score,severity_label,
            source_ip,username,description,plain_description,why_flagged,confidence,
            evidence,mitre_id,mitre_tactic,mitre_name,mitre_stage,status)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (a.attack_type, a.timestamp.isoformat(), a.severity_score, a.severity_label,
              a.source_ip, a.username, a.description, a.plain_description, a.why_flagged,
              a.confidence, json.dumps(a.evidence), a.mitre_id, a.mitre_tactic,
              a.mitre_name, a.mitre_stage, a.status))
        return cur.lastrowid

def insert_alerts(alerts): return [insert_alert(a) for a in alerts]

def upsert_incident(inc):
    d = inc.to_dict() if hasattr(inc,'to_dict') else inc
    with get_conn() as c:
        c.execute("""
            INSERT OR REPLACE INTO incidents
            (id,source_ip,start_time,end_time,duration_minutes,overall_severity,
             overall_score,confidence,incident_type,attack_chain,stage_timeline,
             ai_story,ai_conclusion,ai_intent,recommended_actions,risk_probability,alert_count)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (d["id"],d["source_ip"],d["start_time"],d["end_time"],d.get("duration_minutes",0),
              d["overall_severity"],d["overall_score"],d["confidence"],d["incident_type"],
              json.dumps(d["attack_chain"]),json.dumps(d["stage_timeline"]),
              d.get("ai_story",""),d.get("ai_conclusion",""),d.get("ai_intent",""),
              json.dumps(d.get("recommended_actions",[])),d.get("risk_probability",0),
              d.get("alert_count",0)))

def get_alerts(limit=200,offset=0,severity=None,attack_type=None,source_ip=None,status=None):
    clauses,params=[],[]
    if severity:    clauses.append("severity_label=?"); params.append(severity)
    if attack_type: clauses.append("attack_type=?");    params.append(attack_type)
    if source_ip:   clauses.append("source_ip=?");      params.append(source_ip)
    if status:      clauses.append("status=?");         params.append(status)
    where = ("WHERE "+" AND ".join(clauses)) if clauses else ""
    params+=[limit,offset]
    with get_conn() as c:
        rows = c.execute(f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",params).fetchall()
    result=[]
    for r in rows:
        d=dict(r); d["evidence"]=json.loads(d.get("evidence") or "{}"); result.append(d)
    return result

def get_incidents(limit=50):
    with get_conn() as c:
        rows = c.execute("SELECT * FROM incidents ORDER BY overall_score DESC, start_time DESC LIMIT ?", (limit,)).fetchall()
    result=[]
    for r in rows:
        d=dict(r)
        d["attack_chain"]=json.loads(d.get("attack_chain") or "[]")
        d["stage_timeline"]=json.loads(d.get("stage_timeline") or "[]")
        d["recommended_actions"]=json.loads(d.get("recommended_actions") or "[]")
        result.append(d)
    return result

def get_incident(incident_id):
    with get_conn() as c:
        r = c.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not r: return None
    d=dict(r)
    d["attack_chain"]=json.loads(d.get("attack_chain") or "[]")
    d["stage_timeline"]=json.loads(d.get("stage_timeline") or "[]")
    d["recommended_actions"]=json.loads(d.get("recommended_actions") or "[]")
    return d

def update_incident_ai(incident_id, story, conclusion, intent, actions, risk_prob):
    with get_conn() as c:
        c.execute("""UPDATE incidents SET ai_story=?,ai_conclusion=?,ai_intent=?,
                     recommended_actions=?,risk_probability=? WHERE id=?""",
                  (story,conclusion,intent,json.dumps(actions),risk_prob,incident_id))

def get_stats():
    with get_conn() as c:
        total    = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        critical = c.execute("SELECT COUNT(*) FROM alerts WHERE severity_label='Critical'").fetchone()[0]
        high     = c.execute("SELECT COUNT(*) FROM alerts WHERE severity_label='High'").fetchone()[0]
        open_cnt = c.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
        incidents= c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        by_type  = c.execute("SELECT attack_type,COUNT(*) cnt FROM alerts GROUP BY attack_type ORDER BY cnt DESC").fetchall()
        by_ip    = c.execute("SELECT source_ip,COUNT(*) cnt FROM alerts WHERE source_ip IS NOT NULL GROUP BY source_ip ORDER BY cnt DESC LIMIT 10").fetchall()
        timeline = c.execute("SELECT strftime('%Y-%m-%d %H:00',timestamp) hour,COUNT(*) cnt FROM alerts GROUP BY hour ORDER BY hour DESC LIMIT 48").fetchall()
    return {"total":total,"critical":critical,"high":high,"open":open_cnt,"incidents":incidents,
            "by_type":[dict(r) for r in by_type],"top_ips":[dict(r) for r in by_ip],
            "timeline":[dict(r) for r in reversed(timeline)]}

def get_setting(key,default=None):
    with get_conn() as c:
        r=c.execute("SELECT value FROM settings WHERE key=?",(key,)).fetchone()
    return r["value"] if r else default

def set_setting(key,value):
    with get_conn() as c:
        c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",(key,str(value)))

def update_alert_status(alert_id,status):
    with get_conn() as c:
        c.execute("UPDATE alerts SET status=? WHERE id=?",(status,alert_id))

def clear_all():
    with get_conn() as c:
        c.execute("DELETE FROM alerts")
        c.execute("DELETE FROM incidents")
