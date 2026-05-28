"""emailer.py â€” Plain-English email alerts."""
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import database as db

SEV_EMOJI = {"Critical":"ðŸ”´","High":"ðŸŸ ","Medium":"ðŸŸ¡","Low":"ðŸŸ¢"}
PLAIN_TYPE = {"brute_force":"Password Attack","port_scan":"Network Probe",
              "powershell_obfuscation":"Hidden Command","privilege_escalation":"Admin Access Attempt",
              "account_enumeration":"Username Guessing","successful_breach":"Account Compromise"}

def send_alert_email(alert: dict, smtp: dict) -> bool:
    try:
        emoji = SEV_EMOJI.get(alert.get("severity_label",""),"âš ï¸")
        atype = PLAIN_TYPE.get(alert.get("attack_type",""), alert.get("attack_type","").replace("_"," ").title())
        plain = alert.get("plain_description") or alert.get("description","")
        ip    = alert.get("source_ip","unknown")
        ts    = (alert.get("timestamp","")[:16] or "").replace("T"," ")
        why   = alert.get("why_flagged","")
        subject = f"{emoji} SentinelIQ Alert â€” {alert.get('severity_label','')}: {atype}"
        html = f"""<body style="font-family:Arial,sans-serif;max-width:580px;margin:0 auto;padding:20px;color:#333">
<div style="background:#1e3a5f;padding:20px;border-radius:8px 8px 0 0">
  <h1 style="color:white;margin:0;font-size:18px">ðŸ›¡ï¸ SentinelIQ Security Alert</h1>
</div>
<div style="background:#f8f9fa;padding:20px;border:1px solid #dee2e6;border-top:none;border-radius:0 0 8px 8px">
  <div style="background:white;border-left:4px solid {'#dc3545' if alert.get('severity_label')=='Critical' else '#fd7e14'};padding:16px;border-radius:0 8px 8px 0;margin-bottom:16px">
    <b>{plain}</b><br><small style="color:#888">ðŸ• {ts} &nbsp; ðŸŒ {ip} &nbsp; Confidence: {alert.get('confidence',50)}%</small>
  </div>
  {f'<p style="font-size:13px;color:#555"><b>Why flagged:</b> {why}</p>' if why else ''}
  <p><a href="http://localhost:5000" style="background:#1e3a5f;color:white;padding:10px 20px;text-decoration:none;border-radius:6px;font-size:13px">View in Dashboard â†’</a></p>
</div></body>"""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = smtp.get("from_addr", smtp.get("username",""))
        msg["To"]      = smtp["to_addr"]
        msg.attach(MIMEText(html,"html"))
        ctx = ssl.create_default_context()
        if smtp.get("use_tls",True):
            with smtplib.SMTP_SSL(smtp["host"],int(smtp.get("port",465)),context=ctx) as s:
                s.login(smtp["username"],smtp["password"]); s.sendmail(msg["From"],smtp["to_addr"],msg.as_string())
        else:
            with smtplib.SMTP(smtp["host"],int(smtp.get("port",587))) as s:
                s.ehlo(); s.starttls(context=ctx); s.login(smtp["username"],smtp["password"]); s.sendmail(msg["From"],smtp["to_addr"],msg.as_string())
        return True
    except Exception as e:
        print(f"[Email] {e}"); return False

def maybe_send(alert: dict):
    level = db.get_setting("notify_level","Critical")
    thresh = {"Critical":80,"High":60,"Medium":40,"Low":0}.get(level,80)
    if alert.get("severity_score",0) < thresh: return
    host = db.get_setting("smtp_host"); user = db.get_setting("smtp_user")
    pwd  = db.get_setting("smtp_pass"); to   = db.get_setting("smtp_to")
    if not all([host,user,pwd,to]): return
    send_alert_email(alert, {"host":host,"port":db.get_setting("smtp_port","465"),
        "username":user,"password":pwd,"to_addr":to,
        "use_tls":db.get_setting("smtp_tls","true")=="true"})
