"""report_generator.py â€” HTML report generation."""
from datetime import datetime
from pathlib import Path
import database as db

SEV_COLOR = {"Critical":"#dc3545","High":"#fd7e14","Medium":"#ffc107","Low":"#28a745"}
PLAIN_TYPE = {"brute_force":"Password Attack","port_scan":"Network Probe",
              "powershell_obfuscation":"Hidden Command","privilege_escalation":"Admin Access Attempt",
              "account_enumeration":"Username Guessing","successful_breach":"Account Compromise"}

def generate_html_report(alerts, stats, incidents=None):
    now = datetime.now().strftime("%B %d, %Y at %H:%M")
    c   = stats.get("critical",0); h=stats.get("high",0)
    overall = "All Clear ðŸŸ¢" if c==0 and h==0 else "Needs Attention ðŸŸ " if c==0 else "Act Immediately ðŸ”´"
    rows = ""
    for a in alerts[:50]:
        sev=a.get("severity_label",""); color=SEV_COLOR.get(sev,"#888")
        ptype=PLAIN_TYPE.get(a.get("attack_type",""),a.get("attack_type","").replace("_"," ").title())
        plain=a.get("plain_description") or a.get("description","")
        ts=(a.get("timestamp","")[:16] or "").replace("T"," ")
        conf=a.get("confidence",50); why=a.get("why_flagged","")
        rows+=f"""<tr>
          <td style="padding:10px;border-bottom:1px solid #eee"><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px">{sev}</span></td>
          <td style="padding:10px;border-bottom:1px solid #eee;font-size:13px">{ptype}</td>
          <td style="padding:10px;border-bottom:1px solid #eee;font-size:13px">{plain}</td>
          <td style="padding:10px;border-bottom:1px solid #eee;font-size:12px;color:#888">{a.get('source_ip','â€”')}</td>
          <td style="padding:10px;border-bottom:1px solid #eee;font-size:12px;color:#888">{conf}%</td>
          <td style="padding:10px;border-bottom:1px solid #eee;font-size:11px;color:#666">{why[:80]}</td>
          <td style="padding:10px;border-bottom:1px solid #eee;font-size:12px;color:#888">{ts}</td>
        </tr>"""
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>SentinelIQ Report</title>
<style>body{{font-family:Arial,sans-serif;color:#333;max-width:1000px;margin:0 auto;padding:40px 20px}}@media print{{.no-print{{display:none}}}}</style></head>
<body>
<div style="background:linear-gradient(135deg,#1e3a5f,#2d5a8e);color:white;padding:32px;border-radius:12px;margin-bottom:24px">
  <div style="font-size:26px;font-weight:bold">ðŸ›¡ï¸ SentinelIQ Security Report</div>
  <div style="opacity:.7;margin-top:4px">{now}</div>
  <div style="margin-top:12px;font-size:18px">Status: <b>{overall}</b></div>
</div>
<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px">
  {''.join(f'<div style="background:#f8f9fa;padding:16px;border-radius:8px;text-align:center"><div style="font-size:28px;font-weight:bold;color:{c2}">{v}</div><div style="color:#666;font-size:12px">{lbl}</div></div>'
    for v,lbl,c2 in [(stats.get("total",0),"Total Alerts","#333"),(stats.get("critical",0),"Critical","#dc3545"),(stats.get("high",0),"High","#fd7e14"),(stats.get("open",0),"Open","#ffc107"),(stats.get("incidents",0),"Incidents","#6f42c1")])}
</div>
<h2 style="border-bottom:2px solid #eee;padding-bottom:8px">Alert Details</h2>
<table style="width:100%;border-collapse:collapse;margin-bottom:24px">
  <thead><tr style="background:#f8f9fa">{''.join(f"<th style='padding:10px;text-align:left;font-size:11px;color:#666'>{h}</th>" for h in ['SEVERITY','TYPE','WHAT HAPPENED','IP','CONFIDENCE','WHY FLAGGED','WHEN'])}</tr></thead>
  <tbody>{rows or '<tr><td colspan="7" style="padding:20px;text-align:center;color:#888">No alerts</td></tr>'}</tbody>
</table>
<div class="no-print" style="text-align:center;margin-top:24px">
  <button onclick="window.print()" style="background:#1e3a5f;color:white;border:none;padding:12px 32px;border-radius:6px;font-size:15px;cursor:pointer">ðŸ–¨ï¸ Print / Save PDF</button>
</div></body></html>"""

def save_report():
    stats   = db.get_stats()
    alerts  = db.get_alerts(limit=200)
    html    = generate_html_report(alerts, stats)
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    path    = Path(__file__).parent / "reports" / f"report_{ts}.html"
    path.parent.mkdir(exist_ok=True)
    path.write_text(html)
    return str(path)
