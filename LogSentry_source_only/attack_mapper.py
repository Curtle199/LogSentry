import json
from datetime import datetime

ATTACK_VERSION = "18.1"
NAVIGATOR_VERSION = "5.2.0"
LAYER_VERSION = "4.5"

TECHNIQUE_LIBRARY = {
    "T1110": {
        "name": "Brute Force",
        "tactics": ["credential-access"],
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactics": ["initial-access", "persistence", "privilege-escalation", "defense-evasion"],
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1498.001": {
        "name": "Direct Network Flood",
        "tactics": ["impact"],
        "url": "https://attack.mitre.org/techniques/T1498/001/",
    },
    "T1499.002": {
        "name": "Service Exhaustion Flood",
        "tactics": ["impact"],
        "url": "https://attack.mitre.org/techniques/T1499/002/",
    },
}

NETWORK_DDOS_EVENTS = {"syn_flood", "connection_spike", "rate_limit_triggered"}
SERVICE_DDOS_EVENTS = {
    "proxy_timeout",
    "http_503_surge",
    "active_connections_exceeded",
    "latency_spike",
    "health_check_failed",
    "worker_exhaustion",
    "queue_depth",
    "connection_pool_saturation",
}

SEVERITY_COLORS = {
    "low": "#93c5fd",
    "medium": "#fbbf24",
    "high": "#fb923c",
    "critical": "#ef4444",
}


def _bounded_score(value, floor=20, ceiling=100):
    return max(floor, min(ceiling, int(value)))


def _severity_for_score(score):
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def _add_technique(bucket, technique_id, score, comment, evidence_count, mapped_from):
    technique = TECHNIQUE_LIBRARY[technique_id]
    severity = _severity_for_score(score)
    bucket.append(
        {
            "technique_id": technique_id,
            "name": technique["name"],
            "tactics": technique["tactics"],
            "url": technique["url"],
            "score": score,
            "severity": severity,
            "color": SEVERITY_COLORS[severity],
            "comment": comment,
            "evidence_count": evidence_count,
            "mapped_from": mapped_from,
        }
    )


def build_attack_results(results):
    suspicious_ips = results.get("suspicious_ips", {}) or {}
    burst_ips = results.get("time_based_attacks", {}) or {}
    ddos_event_counts = results.get("ddos_event_counts", {}) or {}
    successful_logins = int(results.get("successful_logins", 0) or 0)

    techniques = []

    suspicious_ip_total = sum(int(count) for count in suspicious_ips.values())
    burst_total = sum(int(count) for count in burst_ips.values())

    if suspicious_ips or burst_ips:
        score = _bounded_score(45 + suspicious_ip_total * 5 + burst_total * 8)
        comment = (
            f"Mapped from repeated authentication failures and burst behavior across "
            f"{max(len(suspicious_ips), len(burst_ips))} source IP(s)."
        )
        _add_technique(
            techniques,
            "T1110",
            score,
            comment,
            evidence_count=suspicious_ip_total + burst_total,
            mapped_from=["suspicious_ips", "time_based_attacks"],
        )

    if successful_logins > 0 and (suspicious_ips or burst_ips):
        score = _bounded_score(50 + successful_logins * 10)
        comment = (
            "Mapped because successful authentication was observed in the same analysis "
            "window as suspicious authentication activity."
        )
        _add_technique(
            techniques,
            "T1078",
            score,
            comment,
            evidence_count=successful_logins,
            mapped_from=["successful_logins", "suspicious_ips", "time_based_attacks"],
        )

    network_count = sum(ddos_event_counts.get(event_name, 0) for event_name in NETWORK_DDOS_EVENTS)
    if network_count > 0:
        event_names = sorted(event_name for event_name in NETWORK_DDOS_EVENTS if ddos_event_counts.get(event_name, 0))
        score = _bounded_score(55 + network_count * 6)
        comment = "Mapped from network-flood style indicators: " + ", ".join(event_names) + "."
        _add_technique(
            techniques,
            "T1498.001",
            score,
            comment,
            evidence_count=network_count,
            mapped_from=event_names,
        )

    service_count = sum(ddos_event_counts.get(event_name, 0) for event_name in SERVICE_DDOS_EVENTS)
    if service_count > 0:
        event_names = sorted(event_name for event_name in SERVICE_DDOS_EVENTS if ddos_event_counts.get(event_name, 0))
        score = _bounded_score(55 + service_count * 5)
        comment = "Mapped from application/service exhaustion indicators: " + ", ".join(event_names) + "."
        _add_technique(
            techniques,
            "T1499.002",
            score,
            comment,
            evidence_count=service_count,
            mapped_from=event_names,
        )

    techniques.sort(key=lambda item: (-item["score"], item["technique_id"]))

    summary_lines = []
    if techniques:
        summary_lines.append(f"Mapped {len(techniques)} ATT&CK technique(s) from current analysis results.")
        for technique in techniques:
            tactic_text = ", ".join(technique["tactics"])
            summary_lines.append(
                f"{technique['technique_id']} | {technique['name']} | tactics: {tactic_text} | "
                f"severity: {technique['severity'].title()} | score: {technique['score']}"
            )
    else:
        summary_lines.append("No ATT&CK techniques were mapped from the current results.")

    return {
        "attack_version": ATTACK_VERSION,
        "navigator_version": NAVIGATOR_VERSION,
        "layer_version": LAYER_VERSION,
        "domain": "enterprise-attack",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "techniques": techniques,
        "summary_lines": summary_lines,
        "total_mapped": len(techniques),
    }


def build_navigator_layer(attack_results, layer_name="LogSentry ATT&CK Layer"):
    techniques = []
    for item in attack_results.get("techniques", []):
        techniques.append(
            {
                "techniqueID": item["technique_id"],
                "score": item["score"],
                "color": item["color"],
                "comment": item["comment"],
                "links": [{"label": "MITRE ATT&CK", "url": item["url"]}],
                "metadata": [
                    {"name": "Technique", "value": item["name"]},
                    {"name": "Severity", "value": item["severity"].title()},
                    {"name": "Evidence Count", "value": str(item["evidence_count"])},
                    {"name": "Mapped From", "value": ", ".join(item["mapped_from"])},
                ],
            }
        )

    return {
        "name": layer_name,
        "description": "Generated by LogSentry from current analysis results.",
        "domain": attack_results.get("domain", "enterprise-attack"),
        "versions": {
            "attack": attack_results.get("attack_version", ATTACK_VERSION),
            "navigator": attack_results.get("navigator_version", NAVIGATOR_VERSION),
            "layer": attack_results.get("layer_version", LAYER_VERSION),
        },
        "sorting": 3,
        "layout": {
            "layout": "side",
            "showName": True,
            "showID": False,
            "showAggregateScores": True,
            "countUnscored": False,
            "aggregateFunction": "max",
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "gradient": {
            "colors": ["#93c5fd", "#fbbf24", "#ef4444"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Low", "color": "#93c5fd"},
            {"label": "Medium", "color": "#fbbf24"},
            {"label": "High/Critical", "color": "#ef4444"},
        ],
        "techniques": techniques,
    }


def export_navigator_layer(attack_results, output_path, layer_name="LogSentry ATT&CK Layer"):
    layer = build_navigator_layer(attack_results, layer_name=layer_name)
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(layer, file, indent=2)
    return output_path
