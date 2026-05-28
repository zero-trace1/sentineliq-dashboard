"""
detector.py â€” Time-windowed behavioral detection engine.
"""
from collections import defaultdict, deque
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional
from log_parser import LogEvent

MITRE_MAP = {
    "brute_force":            {"id":"T1110",    "tactic":"Credential Access",    "name":"Brute Force",              "stage":2},
    "credential_stuffing":    {"id":"T1110.004","tactic":"Credential Access",    "name":"Credential Stuffing",       "stage":2},
    "port_scan":              {"id":"T1046",    "tactic":"Discovery",            "name":"Network Service Scanning",  "stage":1},
    "powershell_obfuscation": {"id":"T1059.001","tactic":"Execution",            "name":"PowerShell",                "stage":4},
    "privilege_escalation":   {"id":"T1548",    "tactic":"Privilege Escalation", "name":"Abuse Elevation Control",   "stage":3},
    "lateral_movement":       {"id":"T1021.004","tactic":"Lateral Movement",     "name":"SSH",                       "stage":4},
    "account_enumeration":    {"id":"T1087",    "tactic":"Discovery",            "name":"Account Discovery",         "stage":1},
    "successful_breach":      {"id":"T1078",    "tactic":"Initial Access",       "name":"Valid Accounts",            "stage":3},
}

PLAIN_LABELS = {
    "brute_force":            "Someone tried many passwords",
    "port_scan":              "Someone scanned your network for weak spots",
    "powershell_obfuscation": "A hidden command was run on your system",
    "privilege_escalation":   "Someone tried to gain admin access",
    "account_enumeration":    "Someone guessed many usernames",
    "successful_breach":      "A login succeeded after repeated failures",
}

ADMIN_ACCOUNTS = {"root","admin","administrator","sudo","sa","postgres","oracle"}

WHY_FLAGGED = {
    "brute_force":            "Multiple failed logins in a short window exceed normal behavior (threshold: 5 in 5 min).",
    "port_scan":              "Rapid connection attempts across many ports indicate automated scanning.",
    "powershell_obfuscation": "Base64-encoded PowerShell is a known malware and C2 obfuscation technique.",
    "privilege_escalation":   "Sudo command execution by a non-standard user warrants review.",
    "account_enumeration":    "Attempting many different usernames from one IP indicates automated enumeration.",
    "successful_breach":      "A successful login immediately following repeated failures is a strong breach indicator.",
}


@dataclass
class Alert:
    attack_type: str
    timestamp: datetime
    severity_score: int
    severity_label: str
    source_ip: Optional[str]
    username: Optional[str]
    description: str
    plain_description: str = ""
    why_flagged: str = ""
    confidence: int = 0
    evidence: dict = field(default_factory=dict)
    mitre_id: str = ""
    mitre_tactic: str = ""
    mitre_name: str = ""
    mitre_stage: int = 0
    status: str = "open"

    def __post_init__(self):
        m = MITRE_MAP.get(self.attack_type, {})
        self.mitre_id    = m.get("id","")
        self.mitre_tactic= m.get("tactic","")
        self.mitre_name  = m.get("name","")
        self.mitre_stage = m.get("stage",0)
        if not self.plain_description:
            self.plain_description = PLAIN_LABELS.get(self.attack_type, self.description)
        if not self.why_flagged:
            self.why_flagged = WHY_FLAGGED.get(self.attack_type,"")

    def to_dict(self):
        return {k:(v.isoformat() if isinstance(v,datetime) else v) for k,v in self.__dict__.items()}


def _score(base, is_admin=False, success_after=False, known_bad=False, off_hours=False):
    s = base
    if success_after: s = min(100, int(s*1.7))
    if is_admin:      s = min(100, int(s*1.4))
    if known_bad:     s = min(100, int(s*1.3))
    if off_hours:     s = min(100, s+10)
    s = max(0,min(100,s))
    label = "Critical" if s>=80 else "High" if s>=60 else "Medium" if s>=40 else "Low"
    return s, label

def _confidence(base, corroborating_signals=0, known_pattern=False, off_hours=False):
    c = base + (corroborating_signals * 8) + (10 if known_pattern else 0) + (5 if off_hours else 0)
    return min(99, max(10, c))

def _off_hours(ts):
    return ts is not None and (ts.hour < 6 or ts.hour >= 22 or ts.weekday() >= 5)


class DetectionEngine:
    BRUTE_WIN    = timedelta(minutes=5)
    SCAN_WIN     = timedelta(minutes=2)
    ENUM_WIN     = timedelta(minutes=10)
    BRUTE_THRESH = 5
    SCAN_THRESH  = 15
    ENUM_THRESH  = 8

    def __init__(self, known_bad_ips=None):
        self.known_bad_ips = known_bad_ips or set()
        self._fails    = defaultdict(deque)
        self._ports    = defaultdict(dict)
        self._users    = defaultdict(dict)
        self._success  = set()
        self._fired    = set()

    def process_events(self, events):
        alerts = []
        for e in events:
            alerts.extend(self._process(e))
        return alerts

    def _process(self, e):
        alerts = []
        if e.action == "failed_login":
            alerts += self._brute(e)
            alerts += self._enum(e)
        elif e.action == "success_login":
            if e.source_ip: self._success.add(e.source_ip)
        elif e.action == "connection":
            alerts += self._scan(e)
        elif e.action == "powershell_encoded":
            alerts += self._ps(e)
        elif e.action == "privilege_escalation":
            alerts += self._priv(e)
        return alerts

    def _brute(self, e):
        ip = e.source_ip
        if not ip: return []
        ts = e.timestamp or datetime.now()
        dq = self._fails[ip]
        dq.append((ts,e))
        self._prune(dq, ts, self.BRUTE_WIN)
        count = len(dq)
        if count < self.BRUTE_THRESH: return []
        key = f"brute_{ip}_{ts.strftime('%Y%m%d%H%M')[:-1]}"
        if key in self._fired: return []
        self._fired.add(key)
        is_admin      = any(ev.username in ADMIN_ACCOUNTS for _,ev in dq if ev.username)
        success_after = ip in self._success
        off           = _off_hours(ts)
        known         = ip in self.known_bad_ips
        base          = 30 + min(30,(count-self.BRUTE_THRESH)*3)
        score, label  = _score(base, is_admin, success_after, known, off)
        conf          = _confidence(55, corroborating_signals=(1 if is_admin else 0)+(1 if success_after else 0)+(1 if off else 0), known_pattern=True, off_hours=off)
        users         = list({ev.username for _,ev in dq if ev.username})
        plain = f"Someone from {ip} tried {count} passwords" + (" and eventually got in!" if success_after else "") + (" They targeted an admin account." if is_admin else "")
        a = Alert(attack_type="brute_force" if not success_after else "successful_breach",
                  timestamp=ts, severity_score=score, severity_label=label,
                  source_ip=ip, username=users[0] if len(users)==1 else None,
                  description=f"{count} failed logins from {ip} in {self.BRUTE_WIN.seconds//60}min",
                  plain_description=plain, confidence=conf,
                  evidence={"failed_count":count,"window_min":self.BRUTE_WIN.seconds//60,
                            "users_targeted":users[:10],"success_after":success_after,"off_hours":off})
        return [a]

    def _scan(self, e):
        ip = e.source_ip
        if not ip or not e.port: return []
        ts = e.timestamp or datetime.now()
        pm = self._ports[ip]; pm[e.port]=ts
        cutoff = ts-self.SCAN_WIN
        self._ports[ip] = {p:t for p,t in pm.items() if t>=cutoff}
        count = len(self._ports[ip])
        if count < self.SCAN_THRESH: return []
        key = f"scan_{ip}_{ts.strftime('%Y%m%d%H%M')[:-1]}"
        if key in self._fired: return []
        self._fired.add(key)
        base = 35+min(25,(count-self.SCAN_THRESH)*2)
        score,label = _score(base, known_bad=ip in self.known_bad_ips, off_hours=_off_hours(ts))
        conf = _confidence(50, corroborating_signals=1, known_pattern=True)
        return [Alert(attack_type="port_scan", timestamp=ts, severity_score=score, severity_label=label,
                      source_ip=ip, username=None, confidence=conf,
                      description=f"{count} ports probed from {ip}",
                      plain_description=f"Someone from {ip} scanned {count} network entry points looking for a way in.",
                      evidence={"port_count":count,"sample_ports":sorted(self._ports[ip].keys())[:20]})]

    def _enum(self, e):
        ip = e.source_ip
        if not ip or not e.username: return []
        ts = e.timestamp or datetime.now()
        um = self._users[ip]; um[e.username]=ts
        cutoff = ts-self.ENUM_WIN
        self._users[ip]={u:t for u,t in um.items() if t>=cutoff}
        count = len(self._users[ip])
        if count < self.ENUM_THRESH: return []
        key = f"enum_{ip}_{ts.strftime('%Y%m%d%H%M')[:-1]}"
        if key in self._fired: return []
        self._fired.add(key)
        score,label = _score(30, known_bad=ip in self.known_bad_ips, off_hours=_off_hours(ts))
        conf = _confidence(45, known_pattern=True)
        return [Alert(attack_type="account_enumeration", timestamp=ts, severity_score=score, severity_label=label,
                      source_ip=ip, username=None, confidence=conf,
                      description=f"{count} distinct usernames tried from {ip}",
                      plain_description=f"Someone from {ip} tried {count} different usernames â€” guessing who has an account.",
                      evidence={"username_count":count,"usernames":sorted(self._users[ip].keys())[:15]})]

    def _ps(self, e):
        ts = e.timestamp or datetime.now()
        ip = e.source_ip
        is_admin = e.username in ADMIN_ACCOUNTS if e.username else False
        score,label = _score(65, is_admin=is_admin, known_bad=ip in self.known_bad_ips if ip else False, off_hours=_off_hours(ts))
        conf = _confidence(75, corroborating_signals=(1 if is_admin else 0), known_pattern=True)
        return [Alert(attack_type="powershell_obfuscation", timestamp=ts, severity_score=score, severity_label=label,
                      source_ip=ip, username=e.username, confidence=conf,
                      description="Encoded PowerShell command detected",
                      plain_description="A hidden, scrambled command was run â€” a classic hacker technique to avoid detection.",
                      evidence={"raw":e.raw[:300]})]

    def _priv(self, e):
        if "sudo_command" not in e.tags: return []
        ts = e.timestamp or datetime.now()
        is_admin = e.username in ADMIN_ACCOUNTS if e.username else False
        score,label = _score(40, is_admin=is_admin, off_hours=_off_hours(ts))
        conf = _confidence(40, corroborating_signals=(1 if is_admin else 0))
        return [Alert(attack_type="privilege_escalation", timestamp=ts, severity_score=score, severity_label=label,
                      source_ip=e.source_ip, username=e.username, confidence=conf,
                      description=f"Sudo escalation by '{e.username}'",
                      plain_description=f"User '{e.username}' ran a command with full admin powers.",
                      evidence={"raw":e.raw[:300]})]

    @staticmethod
    def _prune(dq, now, win):
        cutoff=now-win
        while dq and dq[0][0]<cutoff: dq.popleft()
