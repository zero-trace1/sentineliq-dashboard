"""
correlator.py â€” Groups individual alerts into multi-stage incidents.
This is the core differentiator: correlating events into attack chains.
"""
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional
from detector import Alert, MITRE_MAP

CORRELATION_WINDOW = timedelta(minutes=30)

ATTACK_STAGE_ORDER = {
    "port_scan":              1,
    "account_enumeration":    1,
    "brute_force":            2,
    "credential_stuffing":    2,
    "privilege_escalation":   3,
    "successful_breach":      3,
    "powershell_obfuscation": 4,
    "lateral_movement":       4,
}

STAGE_LABELS = {
    1: "Reconnaissance",
    2: "Credential Attack",
    3: "Initial Access",
    4: "Execution",
}

TACTIC_CHAIN_LABELS = {
    frozenset(["port_scan","brute_force","powershell_obfuscation"]): "Full Kill Chain",
    frozenset(["brute_force","successful_breach"]):                   "Successful Compromise",
    frozenset(["port_scan","brute_force"]):                           "Credential Attack After Recon",
    frozenset(["brute_force","privilege_escalation"]):                "Privilege Escalation Attempt",
    frozenset(["account_enumeration","brute_force"]):                 "Enumeration + Brute Force",
}


@dataclass
class Incident:
    id: str
    source_ip: str
    alerts: list = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    attack_chain: list = field(default_factory=list)
    overall_severity: str = "Low"
    overall_score: int = 0
    confidence: int = 0
    incident_type: str = ""
    ai_story: str = ""
    ai_conclusion: str = ""
    ai_intent: str = ""
    recommended_actions: list = field(default_factory=list)
    risk_probability: int = 0
    stage_timeline: list = field(default_factory=list)

    def to_dict(self):
        return {
            "id": self.id,
            "source_ip": self.source_ip,
            "alert_count": len(self.alerts),
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_minutes": int((self.end_time - self.start_time).total_seconds() / 60) if self.start_time and self.end_time else 0,
            "attack_chain": self.attack_chain,
            "overall_severity": self.overall_severity,
            "overall_score": self.overall_score,
            "confidence": self.confidence,
            "incident_type": self.incident_type,
            "ai_story": self.ai_story,
            "ai_conclusion": self.ai_conclusion,
            "ai_intent": self.ai_intent,
            "recommended_actions": self.recommended_actions,
            "risk_probability": self.risk_probability,
            "stage_timeline": self.stage_timeline,
            "alerts": [a.to_dict() if hasattr(a,'to_dict') else a for a in self.alerts],
        }


class IncidentCorrelator:
    def correlate(self, alerts: list) -> list:
        """Group alerts by IP and time window into incidents."""
        if not alerts:
            return []

        # Group by source IP
        by_ip = {}
        for a in alerts:
            ip = a.get("source_ip") if isinstance(a, dict) else a.source_ip
            if not ip:
                continue
            by_ip.setdefault(ip, []).append(a)

        incidents = []
        for ip, ip_alerts in by_ip.items():
            # Sort by timestamp
            def get_ts(a):
                ts = a.get("timestamp") if isinstance(a,dict) else a.timestamp
                if isinstance(ts, str):
                    try: return datetime.fromisoformat(ts)
                    except: return datetime.now()
                return ts or datetime.now()

            sorted_alerts = sorted(ip_alerts, key=get_ts)

            # Sliding window grouping
            groups = []
            current = []
            for a in sorted_alerts:
                ts = get_ts(a)
                if not current:
                    current.append(a)
                elif ts - get_ts(current[0]) <= CORRELATION_WINDOW:
                    current.append(a)
                else:
                    if len(current) >= 1:
                        groups.append(current)
                    current = [a]
            if current:
                groups.append(current)

            for i, group in enumerate(groups):
                if not group:
                    continue
                incident = self._build_incident(ip, group, f"{ip.replace('.','_')}_{i}")
                if incident:
                    incidents.append(incident)

        # Sort by severity score descending
        incidents.sort(key=lambda x: x.overall_score, reverse=True)
        return incidents

    def _build_incident(self, ip: str, alerts: list, incident_id: str) -> Optional[Incident]:
        def get_ts(a):
            ts = a.get("timestamp") if isinstance(a,dict) else a.timestamp
            if isinstance(ts, str):
                try: return datetime.fromisoformat(ts)
                except: return datetime.now()
            return ts or datetime.now()

        def get_field(a, field):
            return a.get(field) if isinstance(a,dict) else getattr(a,field,None)

        timestamps = [get_ts(a) for a in alerts]
        start_time = min(timestamps)
        end_time   = max(timestamps)

        attack_types = list({get_field(a,"attack_type") for a in alerts if get_field(a,"attack_type")})
        scores       = [get_field(a,"severity_score") or 0 for a in alerts]
        confs        = [get_field(a,"confidence") or 50 for a in alerts]

        overall_score = min(100, max(scores) + len(alerts) * 2)
        if overall_score >= 80:   overall_severity = "Critical"
        elif overall_score >= 60: overall_severity = "High"
        elif overall_score >= 40: overall_severity = "Medium"
        else:                     overall_severity = "Low"

        # Confidence: average + bonus for multi-stage
        avg_conf      = sum(confs) // len(confs) if confs else 50
        multi_bonus   = min(20, len(set(attack_types)) * 5)
        confidence    = min(99, avg_conf + multi_bonus)

        # Build stage timeline
        staged = sorted(alerts, key=lambda a: (ATTACK_STAGE_ORDER.get(get_field(a,"attack_type"),0), get_ts(a)))
        stage_timeline = []
        seen_stages = set()
        for a in staged:
            atype = get_field(a,"attack_type")
            stage_num = ATTACK_STAGE_ORDER.get(atype, 0)
            stage_timeline.append({
                "time": get_ts(a).strftime("%I:%M %p"),
                "timestamp": get_ts(a).isoformat(),
                "stage": stage_num,
                "stage_label": STAGE_LABELS.get(stage_num, "Unknown"),
                "attack_type": atype,
                "plain_description": get_field(a,"plain_description") or get_field(a,"description") or "",
                "severity": get_field(a,"severity_label") or "Low",
                "mitre_id": get_field(a,"mitre_id") or "",
                "mitre_tactic": get_field(a,"mitre_tactic") or "",
            })
            seen_stages.add(stage_num)

        # Build attack chain (unique tactics in order)
        chain = []
        seen = set()
        for a in staged:
            tactic = get_field(a,"mitre_tactic")
            if tactic and tactic not in seen:
                seen.add(tactic)
                chain.append({
                    "tactic": tactic,
                    "mitre_id": get_field(a,"mitre_id") or "",
                    "attack_type": get_field(a,"attack_type") or "",
                    "stage": ATTACK_STAGE_ORDER.get(get_field(a,"attack_type"),0),
                })

        # Incident type label
        type_key = frozenset(attack_types)
        incident_type = "Unknown Pattern"
        for k, v in TACTIC_CHAIN_LABELS.items():
            if k.issubset(type_key):
                incident_type = v
                break
        if incident_type == "Unknown Pattern" and len(attack_types) == 1:
            from detector import PLAIN_LABELS
            incident_type = PLAIN_LABELS.get(attack_types[0], attack_types[0].replace("_"," ").title())

        return Incident(
            id=incident_id,
            source_ip=ip,
            alerts=alerts,
            start_time=start_time,
            end_time=end_time,
            attack_chain=chain,
            overall_severity=overall_severity,
            overall_score=overall_score,
            confidence=confidence,
            incident_type=incident_type,
            stage_timeline=stage_timeline,
        )
