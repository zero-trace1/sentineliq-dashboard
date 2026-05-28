"""app.py â€” SentinelIQ Flask server."""
import os, threading, webbrowser, random
from pathlib import Path
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template, Response

import database as db
from log_parser import LogParser
from detector import DetectionEngine
from correlator import IncidentCorrelator
from ai_analyst import analyze_incident, analyze_single_alert
from emailer import maybe_send
from report_generator import generate_html_report

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
app.config["JSON_AS_ASCII"] = False

# Force UTF-8 on all responses â€” fixes emoji rendering on Windows
@app.after_request
def set_utf8(response):
    if response.content_type.startswith("text/html"):
        response.content_type = "text/html; charset=utf-8"
    return response
UPLOAD_FOLDER = Path(__file__).parent / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)
db.init_db()


def _ingest_and_correlate(events):
    engine = DetectionEngine()
    alerts = engine.process_events(events)
    ids    = db.insert_alerts(alerts)
    for a in alerts:
        maybe_send(a.to_dict())
    # Re-fetch alerts with IDs and correlate
    all_alerts = db.get_alerts(limit=500)
    incidents  = IncidentCorrelator().correlate(all_alerts)
    for inc in incidents:
        db.upsert_incident(inc)
    return alerts, ids, incidents


@app.route("/")
def index():
    onboarding_done = db.get_setting("onboarding_done","false") == "true"
    return render_template("dashboard.html", onboarding_done=onboarding_done)

@app.route("/api/stats")
def api_stats(): return jsonify(db.get_stats())

@app.route("/api/alerts")
def api_alerts():
    f = {k: request.args.get(k) for k in ["severity","attack_type","source_ip","status"]}
    alerts = db.get_alerts(
        limit=int(request.args.get("limit",200)),
        offset=int(request.args.get("offset",0)),
        **{k:v for k,v in f.items() if v})
    return jsonify({"alerts":alerts,"count":len(alerts)})

@app.route("/api/alerts/<int:aid>/status", methods=["PATCH"])
def api_alert_status(aid):
    s = request.get_json().get("status","open")
    if s not in ("open","acknowledged","resolved","false_positive"):
        return jsonify({"error":"invalid"}),400
    db.update_alert_status(aid, s)
    return jsonify({"ok":True})

@app.route("/api/incidents")
def api_incidents():
    return jsonify({"incidents": db.get_incidents()})

@app.route("/api/incidents/<incident_id>")
def api_incident(incident_id):
    inc = db.get_incident(incident_id)
    if not inc: return jsonify({"error":"not found"}),404
    return jsonify(inc)

@app.route("/api/incidents/<incident_id>/analyze", methods=["POST"])
def api_analyze_incident(incident_id):
    inc = db.get_incident(incident_id)
    if not inc: return jsonify({"error":"not found"}),404
    result = analyze_incident(inc)
    if "error" not in result:
        db.update_incident_ai(incident_id,
            result.get("story",""), result.get("conclusion",""),
            result.get("attacker_intent",""), result.get("recommended_actions",[]),
            result.get("risk_probability",0))
    return jsonify(result)

@app.route("/api/alerts/<int:aid>/analyze", methods=["POST"])
def api_analyze_alert(aid):
    rows = db.get_alerts(limit=500)
    row  = next((r for r in rows if r["id"]==aid), None)
    if not row: return jsonify({"error":"not found"}),404
    return jsonify(analyze_single_alert(row))

@app.route("/api/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files: return jsonify({"error":"no file"}),400
    f = request.files["file"]
    path = UPLOAD_FOLDER / f.filename
    f.save(path)
    events = LogParser().parse_file(str(path))
    alerts, ids, incidents = _ingest_and_correlate(events)
    path.unlink(missing_ok=True)
    return jsonify({"events_parsed":len(events),"alerts_generated":len(alerts),
                    "incidents_found":len(incidents),"alert_ids":ids})

@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    raw = request.get_json().get("logs","")
    if not raw: return jsonify({"error":"no logs"}),400
    events = LogParser().parse_text(raw)
    alerts, ids, incidents = _ingest_and_correlate(events)
    return jsonify({"events_parsed":len(events),"alerts_generated":len(alerts),
                    "incidents_found":len(incidents)})

@app.route("/api/settings", methods=["GET"])
def api_get_settings():
    keys=["smtp_host","smtp_user","smtp_to","smtp_port","smtp_tls","notify_level","onboarding_done","api_key_set"]
    return jsonify({k:db.get_setting(k,"") for k in keys})

@app.route("/api/settings", methods=["POST"])
def api_save_settings():
    data = request.get_json()
    for k,v in data.items():
        if k=="smtp_pass" and v=="â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢": continue
        db.set_setting(k,str(v))
    if data.get("anthropic_api_key"):
        os.environ["ANTHROPIC_API_KEY"] = data["anthropic_api_key"]
        db.set_setting("api_key_set","true")
    return jsonify({"ok":True})

@app.route("/api/onboarding/complete", methods=["POST"])
def api_onboarding():
    data = request.get_json() or {}
    for k,v in data.items():
        if v: db.set_setting(k,str(v))
    if data.get("anthropic_api_key"):
        os.environ["ANTHROPIC_API_KEY"] = data["anthropic_api_key"]
        db.set_setting("api_key_set","true")
    db.set_setting("onboarding_done","true")
    return jsonify({"ok":True})

@app.route("/api/report")
def api_report():
    html = generate_html_report(db.get_alerts(limit=200), db.get_stats())
    return Response(html, mimetype="text/html")

@app.route("/api/seed", methods=["POST"])
def api_seed():
    _seed(); return jsonify({"ok":True})

@app.route("/api/clear", methods=["POST"])
def api_clear():
    db.clear_all(); return jsonify({"ok":True})


def _seed():
    db.clear_all()
    now  = datetime.now()
    ips  = ["203.0.113.42","198.51.100.7","185.220.101.5","91.108.4.12","45.33.32.156"]
    users= ["root","admin","postgres","ubuntu","deploy"]

    # Build realistic correlated attack scenarios
    scenarios = [
        # Full kill chain from 203.0.113.42
        [("port_scan","T1046","Discovery","Network Service Scanning",
          f"Someone from 203.0.113.42 scanned 47 network entry points","port_scan detected",65,70,0),
         ("account_enumeration","T1087","Discovery","Account Discovery",
          f"Someone from 203.0.113.42 tried 12 different usernames","enum detected",50,55,5),
         ("brute_force","T1110","Credential Access","Brute Force",
          f"Someone from 203.0.113.42 tried 38 passwords on root","brute force detected",82,88,10),
         ("successful_breach","T1078","Initial Access","Valid Accounts",
          f"Someone from 203.0.113.42 got in after repeated failures","breach detected",95,92,13),
         ("powershell_obfuscation","T1059.001","Execution","PowerShell",
          f"A hidden command was run from 203.0.113.42","ps enc detected",90,85,15)],
        # Brute force from 198.51.100.7
        [("brute_force","T1110","Credential Access","Brute Force",
          f"Someone from 198.51.100.7 tried 22 passwords","brute force",75,80,0),
         ("privilege_escalation","T1548","Privilege Escalation","Abuse Elevation Control",
          f"User 'ubuntu' ran a command with full admin powers","priv esc",68,72,8)],
        # Port scan from 185.220.101.5
        [("port_scan","T1046","Discovery","Network Service Scanning",
          f"Someone from 185.220.101.5 scanned 31 ports","port scan",55,60,0),
         ("account_enumeration","T1087","Discovery","Account Discovery",
          f"Someone from 185.220.101.5 tried 9 usernames","enum",45,50,3)],
    ]

    from detector import Alert
    alerts = []
    for s_idx, scenario in enumerate(scenarios):
        base_time = now - timedelta(hours=random.uniform(1,48))
        for atype,mid,tactic,mname,plain,desc,score,conf,offset_min in scenario:
            ts = base_time + timedelta(minutes=offset_min)
            label = "Critical" if score>=80 else "High" if score>=60 else "Medium" if score>=40 else "Low"
            ip = scenarios[s_idx][0][0].split("from ")[-1].split(" ")[0] if "from" in scenarios[s_idx][0][3] else ips[s_idx]
            # Extract IP from plain description
            import re
            m = re.search(r'(\d+\.\d+\.\d+\.\d+)', plain)
            ip = m.group(1) if m else ips[s_idx]
            a = Alert(attack_type=atype,timestamp=ts,severity_score=score,severity_label=label,
                      source_ip=ip,username=random.choice(users),plain_description=plain,
                      description=desc,confidence=conf,evidence={"demo":True},
                      status=random.choice(["open","open","acknowledged"]))
            a.mitre_id=mid; a.mitre_tactic=tactic; a.mitre_name=mname
            alerts.append(a)

    # Add some standalone alerts
    for i in range(10):
        ip = random.choice(ips[2:])
        score = random.randint(25,65)
        label = "High" if score>=60 else "Medium" if score>=40 else "Low"
        a = Alert(attack_type="brute_force",
                  timestamp=now-timedelta(hours=random.uniform(0,72)),
                  severity_score=score,severity_label=label,source_ip=ip,
                  username=random.choice(users),
                  plain_description=f"Someone from {ip} tried {random.randint(5,20)} passwords",
                  description="brute force",confidence=random.randint(40,70),
                  evidence={"demo":True},status="open")
        a.mitre_id="T1110"; a.mitre_tactic="Credential Access"; a.mitre_name="Brute Force"
        alerts.append(a)

    db.insert_alerts(alerts)
    all_alerts = db.get_alerts(limit=500)
    incidents  = IncidentCorrelator().correlate(all_alerts)
    for inc in incidents:
        db.upsert_incident(inc)


import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    # Only open browser locally, not on Render
    if os.environ.get("RENDER") is None:
        threading.Timer(
            1.5,
            lambda: webbrowser.open(f"http://localhost:{port}")
        ).start()

        print("\n🛡️ SentinelIQ — AI Threat Reconstruction Platform")
        print(f"📡 Opening http://localhost:{port}")
        print("⏹️ Press Ctrl+C to stop\n")

    app.run(debug=False, host="0.0.0.0", port=port)