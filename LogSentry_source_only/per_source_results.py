from __future__ import annotations

from typing import Dict, List

from attack_mapper import build_attack_results
from finding_scoring import build_finding_assessment


def build_per_source_results(raw_per_source_results: List[Dict]) -> List[Dict]:
    summaries = []

    for source_result in raw_per_source_results or []:
        assessment = build_finding_assessment(source_result)
        attack_results = build_attack_results(source_result)

        suspicious_ips = source_result.get("suspicious_ips", {}) or {}
        burst_ips = source_result.get("time_based_attacks", {}) or {}
        ddos_event_counts = source_result.get("ddos_event_counts", {}) or {}

        technique_ids = [item.get("technique_id", "") for item in attack_results.get("techniques", []) if item.get("technique_id")]
        top_failed_ip = max(suspicious_ips, key=suspicious_ips.get) if suspicious_ips else (
            max(source_result.get("failed_ips", {}), key=source_result.get("failed_ips", {}).get)
            if source_result.get("failed_ips") else None
        )
        top_ddos_event = max(ddos_event_counts, key=ddos_event_counts.get) if ddos_event_counts else None

        summaries.append({
            "source_file": source_result.get("source_file", "Unknown"),
            "file_path": source_result.get("file_path", ""),
            "source_profile_requested": source_result.get("source_profile_requested", "Auto Detect"),
            "source_profile_used": source_result.get("source_profile_used", "Unknown"),
            "total_lines": int(source_result.get("total_lines", 0) or 0),
            "successful_logins": int(source_result.get("successful_logins", 0) or 0),
            "failed_attempts": int(source_result.get("failed_attempts", 0) or 0),
            "suspicious_ip_count": len(suspicious_ips),
            "burst_ip_count": len(burst_ips),
            "ddos_detected": bool(source_result.get("ddos_detected")),
            "ddos_event_total": int(sum(ddos_event_counts.values())),
            "top_failed_ip": top_failed_ip,
            "top_ddos_event": top_ddos_event,
            "technique_ids": technique_ids,
            "attack_results": attack_results,
            "finding_assessment": assessment,
            "headline": assessment.get("overall", {}).get("headline", "No major finding"),
            "overall_confidence": assessment.get("overall", {}).get("confidence_label", "Not Detected"),
            "overall_score": int(assessment.get("overall", {}).get("score", 0) or 0),
            "raw_result": source_result,
        })

    summaries.sort(
        key=lambda item: (
            item.get("overall_score", 0),
            item.get("ddos_event_total", 0),
            item.get("failed_attempts", 0),
            item.get("source_file", "").lower(),
        ),
        reverse=True,
    )
    return summaries


def format_per_source_block(source_entries: List[Dict]) -> str:
    if not source_entries:
        return "Per-source results will appear here after analysis."

    lines = [
        "Per-Source Results",
        "=" * 100,
        f"Sources analyzed: {len(source_entries)}",
        "",
    ]

    for index, entry in enumerate(source_entries, start=1):
        lines.append(f"[{index}] {entry['source_file']}")
        lines.append("-" * 100)
        lines.append(
            f"Requested Profile: {entry['source_profile_requested']} | Used Profile: {entry['source_profile_used']}"
        )
        lines.append(
            f"Overall Confidence: {entry['overall_confidence']} ({entry['overall_score']}/100) | Headline: {entry['headline']}"
        )
        lines.append(
            f"Lines: {entry['total_lines']} | Success: {entry['successful_logins']} | Failed: {entry['failed_attempts']} | "
            f"Suspicious IPs: {entry['suspicious_ip_count']} | Burst IPs: {entry['burst_ip_count']} | "
            f"Service-Flood Events: {entry['ddos_event_total']}"
        )

        if entry.get("top_failed_ip"):
            lines.append(f"Top auth source IP: {entry['top_failed_ip']}")
        if entry.get("top_ddos_event"):
            lines.append(f"Top service-flood signal: {entry['top_ddos_event'].replace('_', ' ')}")

        techniques = entry.get("technique_ids", [])
        if techniques:
            lines.append(f"Mapped ATT&CK Techniques: {', '.join(techniques)}")

        sections = entry.get("finding_assessment", {}).get("sections", {})
        for section_name, section in sections.items():
            pretty_name = section_name.replace("_", " ").title()
            lines.append(
                f"{pretty_name}: {section.get('confidence_label', 'Not Detected')} "
                f"({section.get('score', 0)}/100) | evidence count: {section.get('evidence_count', 0)}"
            )
            for reason in section.get("reasons", [])[:3]:
                lines.append(f"  - {reason}")
        lines.append("")

    return "\n".join(lines).strip()
