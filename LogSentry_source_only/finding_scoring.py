from __future__ import annotations

from typing import Dict, List


def _clamp_score(value: int) -> int:
    return max(0, min(100, int(value)))


def _confidence_label(score: int, detected: bool) -> str:
    if not detected or score <= 0:
        return "Not Detected"
    if score >= 80:
        return "High"
    if score >= 55:
        return "Medium"
    return "Low"


def _section_payload(name: str, score: int, detected: bool, evidence_count: int, reasons: List[str], headline: str) -> Dict:
    score = _clamp_score(score)
    return {
        "name": name,
        "detected": bool(detected),
        "score": score,
        "confidence_label": _confidence_label(score, detected),
        "evidence_count": int(evidence_count),
        "headline": headline,
        "reasons": reasons,
    }


def build_finding_assessment(results: Dict) -> Dict:
    if not results or "error" in results:
        return {
            "overall": _section_payload(
                "overall",
                0,
                False,
                0,
                ["Analysis failed or returned no usable results."],
                "No reliable assessment available.",
            ),
            "sections": {},
            "summary_lines": [
                "Evidence Confidence Summary",
                "=" * 60,
                "Overall: Not Detected (0/100)",
                "Why flagged:",
                "  - Analysis failed or returned no usable results.",
            ],
        }

    suspicious_ips = results.get("suspicious_ips", {}) or {}
    burst_ips = results.get("time_based_attacks", {}) or {}
    ddos_event_counts = results.get("ddos_event_counts", {}) or {}
    ddos_source_ips = results.get("ddos_source_ips", {}) or {}
    loaded_sources = results.get("loaded_sources", []) or []

    failed_attempts = int(results.get("failed_attempts", 0) or 0)
    successful_logins = int(results.get("successful_logins", 0) or 0)
    matched_failed_lines = int(results.get("matched_failed_lines", 0) or 0)
    matched_success_lines = int(results.get("matched_success_lines", 0) or 0)
    failed_login_threshold = int(results.get("failed_login_threshold", 0) or 0)
    burst_threshold = int(results.get("burst_threshold", 0) or 0)
    time_window_seconds = int(results.get("time_window_seconds", 0) or 0)

    suspicious_ip_total = sum(int(count) for count in suspicious_ips.values())
    burst_total = sum(int(count) for count in burst_ips.values())
    ddos_event_total = sum(int(count) for count in ddos_event_counts.values())
    ddos_type_count = len(ddos_event_counts)
    ddos_ip_count = len(ddos_source_ips)

    auth_detected = bool(suspicious_ips or failed_attempts > 0)
    auth_reasons: List[str] = []
    auth_score = 0
    if failed_attempts > 0:
        auth_score += 25
        auth_reasons.append(f"{failed_attempts} failed authentication attempts were parsed.")
    if matched_failed_lines > 0:
        auth_score += min(25, matched_failed_lines * 3)
        auth_reasons.append(f"{matched_failed_lines} log line(s) matched failed-auth patterns.")
    if suspicious_ips:
        auth_score += min(25, suspicious_ip_total * 4)
        auth_reasons.append(
            f"{len(suspicious_ips)} IP(s) crossed the suspicious threshold of {failed_login_threshold} failed attempts."
        )
    if successful_logins > 0 and suspicious_ips:
        auth_score += 10
        auth_reasons.append(
            f"{successful_logins} successful login(s) occurred in the same analysis window as suspicious auth activity."
        )
    if loaded_sources:
        auth_reasons.append(f"Authentication evidence was correlated across {len(loaded_sources)} loaded source(s).")
    auth_headline = (
        "Repeated authentication abuse indicators were detected."
        if suspicious_ips
        else "Low-volume failed authentication activity was observed."
        if failed_attempts > 0
        else "No suspicious authentication pattern was detected."
    )
    auth_section = _section_payload(
        "authentication_abuse",
        auth_score if auth_detected else 0,
        auth_detected,
        suspicious_ip_total or failed_attempts,
        auth_reasons or ["No repeated authentication abuse pattern was detected."],
        auth_headline,
    )

    burst_detected = bool(burst_ips)
    burst_reasons: List[str] = []
    burst_score = 0
    if burst_ips:
        burst_score += 35
        burst_reasons.append(
            f"{len(burst_ips)} IP(s) triggered the burst rule of {burst_threshold} failures in {time_window_seconds} seconds."
        )
        burst_score += min(35, burst_total * 10)
        burst_reasons.append(f"{burst_total} burst-window hit(s) were identified.")
        if suspicious_ips:
            burst_score += 10
            burst_reasons.append("Burst detections align with IPs that were already suspicious on total failed attempts.")
    burst_headline = (
        "Rapid authentication burst behavior was detected."
        if burst_detected
        else "No burst-style authentication spike was detected."
    )
    burst_section = _section_payload(
        "burst_activity",
        burst_score if burst_detected else 0,
        burst_detected,
        burst_total,
        burst_reasons or ["No burst-style authentication spike was detected."],
        burst_headline,
    )

    ddos_detected = bool(ddos_event_counts)
    ddos_reasons: List[str] = []
    ddos_score = 0
    if ddos_event_total > 0:
        ddos_score += 30
        ddos_reasons.append(f"{ddos_event_total} service-flood indicator event(s) were matched.")
        ddos_score += min(35, ddos_event_total * 4)
    if ddos_type_count > 0:
        ddos_score += min(15, ddos_type_count * 5)
        ddos_reasons.append(f"{ddos_type_count} distinct service-flood event type(s) were observed.")
    if ddos_ip_count > 0:
        ddos_score += min(10, ddos_ip_count * 5)
        top_ip = max(ddos_source_ips, key=ddos_source_ips.get)
        ddos_reasons.append(
            f"Top service-flood source IP was {top_ip} with {ddos_source_ips[top_ip]} matching line(s)."
        )
    if ddos_event_counts:
        top_event = max(ddos_event_counts, key=ddos_event_counts.get)
        ddos_reasons.append(
            f"Most common service-flood signal was {top_event.replace('_', ' ')} with {ddos_event_counts[top_event]} hit(s)."
        )
    ddos_headline = (
        "Availability-impacting service-flood indicators were detected."
        if ddos_detected
        else "No service-flood pattern was detected."
    )
    ddos_section = _section_payload(
        "service_flood",
        ddos_score if ddos_detected else 0,
        ddos_detected,
        ddos_event_total,
        ddos_reasons or ["No service-flood pattern was detected."],
        ddos_headline,
    )

    detected_sections = [section for section in [auth_section, burst_section, ddos_section] if section["detected"]]
    overall_detected = bool(detected_sections)
    if detected_sections:
        max_section = max(detected_sections, key=lambda section: section["score"])
        overall_score = _clamp_score(
            int(round(sum(section["score"] for section in detected_sections) / len(detected_sections) + 10 * (len(detected_sections) - 1)))
        )
        overall_reasons = [
            f"{len(detected_sections)} finding category(ies) were triggered in this analysis.",
            f"Strongest category was {max_section['name'].replace('_', ' ')} at {max_section['score']}/100.",
        ]
        if successful_logins > 0:
            overall_reasons.append(f"{matched_success_lines or successful_logins} successful-auth line(s) were also present.")
        overall_headline = (
            "Correlated authentication and service-flood evidence was observed."
            if auth_section["detected"] and ddos_section["detected"]
            else max_section["headline"]
        )
        overall_evidence = sum(section["evidence_count"] for section in detected_sections)
    else:
        overall_score = 0
        overall_reasons = ["No category met a meaningful detection threshold."]
        overall_headline = "No major suspicious pattern was detected."
        overall_evidence = 0

    overall_section = _section_payload(
        "overall",
        overall_score,
        overall_detected,
        overall_evidence,
        overall_reasons,
        overall_headline,
    )

    summary_lines = [
        "Evidence Confidence Summary",
        "=" * 60,
        f"Overall: {overall_section['confidence_label']} ({overall_section['score']}/100)",
        f"Headline: {overall_section['headline']}",
        "",
    ]

    for section in [auth_section, burst_section, ddos_section]:
        pretty_name = section["name"].replace("_", " ").title()
        summary_lines.append(
            f"{pretty_name}: {section['confidence_label']} ({section['score']}/100) | evidence count: {section['evidence_count']}"
        )
        summary_lines.append("Why flagged:")
        for reason in section["reasons"]:
            summary_lines.append(f"  - {reason}")
        summary_lines.append("")

    return {
        "overall": overall_section,
        "sections": {
            "authentication_abuse": auth_section,
            "burst_activity": burst_section,
            "service_flood": ddos_section,
        },
        "summary_lines": summary_lines,
    }


def format_assessment_block(assessment: Dict) -> str:
    if not assessment:
        return ""
    lines = assessment.get("summary_lines", []) or []
    return "\n".join(lines).strip()
