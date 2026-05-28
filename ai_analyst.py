"""
ai_analyst.py â€” AI-powered incident story reconstruction.
The core differentiator: correlates multi-stage events into a narrative.
"""
import json, httpx
from datetime import datetime

API_URL = "https://api.anthropic.com/v1/messages"
MODEL   = "claude-sonnet-4-20250514"

STORY_SYSTEM = """You are a senior SOC analyst explaining a multi-stage cyber attack to a non-technical person.
You receive a correlated incident with a timeline of events. Your job is to reconstruct what the attacker was doing, step by step, in plain English.

Respond ONLY with valid JSON â€” no markdown, no preamble:
{
  "story": "2-3 sentence narrative of what happened in chronological order, plain English, no jargon",
  "conclusion": "one sentence verdict â€” was this a real attack, a probe, or likely a false positive?",
  "attacker_intent": "what the attacker was trying to achieve in one sentence",
  "risk_probability": 0-100 integer â€” how likely this is a real attack,
  "recommended_actions": ["action 1", "action 2", "action 3"],
  "how_serious": "Not serious / Needs attention / Act immediately",
  "false_positive_reason": "why this might or might not be a false positive"
}"""

SINGLE_SYSTEM = """You are a cybersecurity assistant explaining a security alert to a non-technical person.
Use plain English. No jargon. Be honest about severity.

Respond ONLY with valid JSON:
{
  "simple_summary": "1-2 sentences in plain English",
  "what_it_means": "practical impact for the user",
  "how_serious": "Not serious / Needs attention / Act immediately",
  "what_to_do": ["step 1", "step 2", "step 3"],
  "is_likely_real": true or false,
  "confidence_explanation": "why the confidence score is what it is",
  "reassurance": "one honest closing sentence"
}"""


def _call(system, user_msg):
    try:
        r = httpx.post(API_URL,
            headers={"Content-Type":"application/json"},
            json={"model":MODEL,"max_tokens":1000,"system":system,
                  "messages":[{"role":"user","content":user_msg}]},
            timeout=30)
        r.raise_for_status()
        text = "".join(b.get("text","") for b in r.json().get("content",[]) if b.get("type")=="text")
        text = text.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        return json.loads(text)
    except Exception as ex:
        return {"error": str(ex)[:120]}


def analyze_incident(incident: dict) -> dict:
    """Full AI story reconstruction for a correlated multi-stage incident."""
    timeline = incident.get("stage_timeline",[])
    chain    = incident.get("attack_chain",[])

    payload = {
        "source_ip":     incident.get("source_ip"),
        "incident_type": incident.get("incident_type"),
        "duration_min":  incident.get("duration_minutes",0),
        "alert_count":   incident.get("alert_count",0),
        "attack_chain":  [c.get("tactic") for c in chain],
        "timeline": [
            {"time": e.get("time"), "what_happened": e.get("plain_description"),
             "stage": e.get("stage_label"), "mitre": e.get("mitre_tactic")}
            for e in timeline
        ],
        "overall_severity": incident.get("overall_severity"),
        "confidence":       incident.get("confidence"),
    }

    return _call(STORY_SYSTEM,
        "Reconstruct this security incident as a plain-English narrative:\n\n" +
        json.dumps(payload, indent=2))


def analyze_single_alert(alert: dict) -> dict:
    """Plain-English explanation for a single alert."""
    payload = {
        "what_happened":  alert.get("plain_description") or alert.get("description",""),
        "attack_type":    alert.get("attack_type"),
        "severity":       f"{alert.get('severity_label')} ({alert.get('severity_score')}/100)",
        "confidence":     f"{alert.get('confidence',50)}%",
        "why_flagged":    alert.get("why_flagged",""),
        "source_ip":      alert.get("source_ip"),
        "evidence":       alert.get("evidence",{}),
    }

    return _call(SINGLE_SYSTEM,
        "Explain this security alert in plain English:\n\n" +
        json.dumps(payload, indent=2))
