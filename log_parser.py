"""
log_parser.py â€” Multi-format log ingestion.
Supports: auth.log, syslog, Apache, Windows Event Log
"""
import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
import ipaddress

LOG_TYPE_HINTS = {
    "auth":    ["Failed password", "Accepted password", "Invalid user", "sudo:"],
    "apache":  ["GET ", "POST ", "HTTP/1"],
    "windows": ["EventID", "Logon Type", "Account Name"],
    "syslog":  ["kernel:", "systemd", "CRON"],
}

@dataclass
class LogEvent:
    raw: str
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    action: Optional[str] = None
    service: Optional[str] = None
    pid: Optional[int] = None
    message: str = ""
    tags: list = field(default_factory=list)
    log_type: str = "unknown"

    def to_dict(self):
        return {k: (v.isoformat() if isinstance(v, datetime) else v)
                for k, v in self.__dict__.items()}

PATTERNS = {
    "ssh_failed":       re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"),
    "ssh_success":      re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"),
    "ssh_invalid_user": re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"),
    "conn_closed":      re.compile(r"Connection closed by (?:invalid user )?(?:\S+ )?(?P<ip>[\d.]+) port (?P<port>\d+)"),
    "sudo":             re.compile(r"sudo:\s+(?P<user>\S+)\s+:.*?COMMAND=(?P<cmd>.+)"),
    "powershell_enc":   re.compile(r"powershell(?:\.exe)?\s+.*?-[Ee]nc(?:odedCommand)?\s+(?P<payload>\S+)", re.IGNORECASE),
    "apache_access":    re.compile(r'(?P<ip>[\d.]+) .* "(?P<method>\w+) (?P<path>\S+).*" (?P<status>\d+)'),
    "syslog_header":    re.compile(r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<service>\w[\w\-]*)(?:\[(?P<pid>\d+)\])?:"),
    "iso_ts":           re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"),
    "ip_anywhere":      re.compile(r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b"),
}
MONTH_MAP = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,"Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}


def detect_log_type(lines):
    sample = "\n".join(lines[:50])
    scores = {t: sum(1 for kw in kws if kw in sample) for t, kws in LOG_TYPE_HINTS.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "unknown"


class LogParser:
    def __init__(self, year=None):
        self.year = year or datetime.now().year

    def parse_file(self, path):
        try:
            with open(path, "r", errors="replace") as f:
                lines = f.readlines()
        except FileNotFoundError:
            return []
        log_type = detect_log_type(lines)
        return [self._parse(line, log_type) for line in lines if line.strip()]

    def parse_text(self, text):
        lines = text.splitlines()
        log_type = detect_log_type(lines)
        return [self._parse(l, log_type) for l in lines if l.strip()]

    def _parse(self, raw, log_type="unknown"):
        line = raw.strip()
        e = LogEvent(raw=line, message=line, log_type=log_type)
        e.timestamp = self._ts(line)
        m = PATTERNS["syslog_header"].search(line)
        if m:
            e.hostname = m.group("host")
            e.service = m.group("service").lower()
            try: e.pid = int(m.group("pid"))
            except: pass
        self._classify(line, e)
        if not e.source_ip:
            m = PATTERNS["ip_anywhere"].search(line)
            if m and self._routable(m.group("ip")):
                e.source_ip = m.group("ip")
        return e

    def _classify(self, line, e):
        m = PATTERNS["powershell_enc"].search(line)
        if m:
            e.action="powershell_encoded"; e.service="powershell"; e.tags.append("powershell_enc"); return
        m = PATTERNS["ssh_failed"].search(line)
        if m:
            e.action="failed_login"; e.username=m.group("user"); e.source_ip=m.group("ip")
            e.port=int(m.group("port")); e.service=e.service or "sshd"; return
        m = PATTERNS["ssh_invalid_user"].search(line)
        if m:
            e.action="failed_login"; e.username=m.group("user"); e.source_ip=m.group("ip")
            e.tags.append("invalid_user"); e.service=e.service or "sshd"; return
        m = PATTERNS["ssh_success"].search(line)
        if m:
            e.action="success_login"; e.username=m.group("user"); e.source_ip=m.group("ip")
            e.port=int(m.group("port")); e.service=e.service or "sshd"; return
        m = PATTERNS["conn_closed"].search(line)
        if m:
            e.action="connection"; e.source_ip=m.group("ip"); e.port=int(m.group("port")); return
        m = PATTERNS["sudo"].search(line)
        if m:
            e.action="privilege_escalation"; e.username=m.group("user")
            e.service="sudo"; e.tags.append("sudo_command"); return

    def _ts(self, line):
        m = PATTERNS["iso_ts"].search(line)
        if m:
            try: return datetime.strptime(m.group("ts")[:19], "%Y-%m-%d %H:%M:%S")
            except: pass
        m = PATTERNS["syslog_header"].search(line)
        if m:
            try:
                mo=MONTH_MAP.get(m.group("month"),1); d=int(m.group("day"))
                h,mi,s=map(int,m.group("time").split(":"))
                return datetime(self.year,mo,d,h,mi,s)
            except: pass
        return None

    def _routable(self, ip):
        try:
            a=ipaddress.ip_address(ip)
            return not (a.is_loopback or a.is_unspecified)
        except: return False
