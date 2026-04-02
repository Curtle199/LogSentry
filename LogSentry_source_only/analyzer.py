from collections import Counter, defaultdict
from datetime import datetime
import os
import re

DEFAULT_FAILED_LOGIN_THRESHOLD = 3
DEFAULT_TIME_WINDOW_SECONDS = 30
DEFAULT_BURST_THRESHOLD = 3
DEFAULT_SOURCE_PROFILE = "Auto Detect"

IP_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

SOURCE_PROFILES = [
    "Auto Detect",
    "Linux Auth / SSH",
    "Web / Reverse Proxy",
    "Firewall / Network",
    "Mixed Generic",
]

FAILED_PATTERNS = [
    (r"failed login attempt", "failed_login", "matched failed login pattern"),
    (r"failed password", "failed_password", "matched failed password pattern"),
    (r"authentication failure", "authentication_failure", "matched authentication failure pattern"),
    (r"invalid user .* from", "invalid_user", "matched invalid user pattern"),
    (r"login failed", "login_failed", "matched login failed pattern"),
    (r"failed logon", "failed_logon", "matched failed logon pattern"),
]

SUCCESS_PATTERNS = [
    (r"login successful", "login_success", "matched login success pattern"),
    (r"accepted password", "accepted_password", "matched accepted password pattern"),
    (r"accepted publickey", "accepted_publickey", "matched accepted publickey pattern"),
    (r"session opened for user", "session_opened", "matched session opened pattern"),
    (r"authentication succeeded", "authentication_succeeded", "matched authentication succeeded pattern"),
    (r"login succeeded", "login_succeeded", "matched login succeeded pattern"),
]

DDOS_PATTERNS = {
    "connection_spike": {
        "patterns": [r"connection spike detected"],
        "severity": "medium",
        "reason": "matched connection spike pattern",
    },
    "proxy_timeout": {
        "patterns": [r"reverse proxy timeout", r"gateway timeout", r"upstream timeout"],
        "severity": "high",
        "reason": "matched proxy timeout pattern",
    },
    "http_503_surge": {
        "patterns": [r"http 503 surge detected", r"\b503\b", r"service unavailable"],
        "severity": "high",
        "reason": "matched HTTP 503/service unavailable pattern",
    },
    "active_connections_exceeded": {
        "patterns": [r"active connections exceeded threshold", r"too many connections"],
        "severity": "high",
        "reason": "matched active connections threshold pattern",
    },
    "syn_flood": {
        "patterns": [r"syn flood suspected"],
        "severity": "critical",
        "reason": "matched SYN flood pattern",
    },
    "rate_limit_triggered": {
        "patterns": [
            r"firewall rate limit triggered",
            r"rate limit triggered",
            r"emergency rate limiting enabled",
            r"throttle engaged",
        ],
        "severity": "medium",
        "reason": "matched rate limiting/throttle pattern",
    },
    "latency_spike": {
        "patterns": [
            r"upstream latency increased",
            r"avg_latency=(?:[6-9]\d{2}|\d{4,})ms",
            r"latency=(?:[6-9]\d{2}|\d{4,})ms",
        ],
        "severity": "medium",
        "reason": "matched latency spike pattern",
    },
    "health_check_failed": {
        "patterns": [r"health check failed"],
        "severity": "high",
        "reason": "matched health check failure pattern",
    },
    "worker_exhaustion": {
        "patterns": [r"worker exhaustion", r"max_workers"],
        "severity": "high",
        "reason": "matched worker exhaustion pattern",
    },
    "queue_depth": {
        "patterns": [r"request queue depth elevated", r"queue depth"],
        "severity": "medium",
        "reason": "matched queue depth pattern",
    },
    "connection_pool_saturation": {
        "patterns": [r"connection pool saturation", r"pool saturation"],
        "severity": "high",
        "reason": "matched connection pool saturation pattern",
    },
}

PROFILE_HINTS = {
    "Linux Auth / SSH": [
        r"sshd",
        r"authpriv",
        r"invalid user",
        r"failed password",
        r"accepted password",
        r"session opened for user",
        r"login failed",
        r"authentication failure",
    ],
    "Web / Reverse Proxy": [
        r"reverse proxy",
        r"upstream",
        r"http 503",
        r"gateway timeout",
        r"service unavailable",
        r"latency",
        r"health check",
        r"route=",
    ],
    "Firewall / Network": [
        r"firewall",
        r"syn flood",
        r"rate limit",
        r"throttle",
        r"packets=",
        r"interface=",
        r"connections exceeded",
    ],
    "Mixed Generic": [],
}


def extract_ip(line):
    match = re.search(IP_PATTERN, line, re.IGNORECASE)
    return match.group() if match else None


def extract_timestamp(line):
    line = line.strip()

    iso_match = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
    if iso_match:
        try:
            return datetime.strptime(iso_match.group(1), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    syslog_match = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    if syslog_match:
        try:
            current_year = datetime.now().year
            timestamp_text = f"{current_year} {syslog_match.group(1)}"
            return datetime.strptime(timestamp_text, "%Y %b %d %H:%M:%S")
        except ValueError:
            pass

    return None


def normalize_timestamp(dt):
    if not dt:
        return "Unknown"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def make_event(
    timestamp,
    source_ip,
    event_category,
    event_type,
    severity,
    detection_reason,
    raw_log,
    source_profile,
    source_file,
):
    return {
        "timestamp": normalize_timestamp(timestamp),
        "source_ip": source_ip if source_ip else "Unknown",
        "event_category": event_category,
        "event_type": event_type,
        "severity": severity,
        "detection_reason": detection_reason,
        "raw_log": raw_log,
        "source_profile": source_profile,
        "source_file": source_file,
    }


def detect_profile_from_content(lines):
    profile_scores = {profile: 0 for profile in PROFILE_HINTS.keys()}

    for line in lines:
        lower_line = line.lower()
        for profile, patterns in PROFILE_HINTS.items():
            for pattern in patterns:
                if re.search(pattern, lower_line):
                    profile_scores[profile] += 1

    best_profile = max(profile_scores, key=profile_scores.get)
    if profile_scores[best_profile] == 0:
        return "Mixed Generic"

    auth_score = profile_scores["Linux Auth / SSH"]
    availability_score = profile_scores["Web / Reverse Proxy"] + profile_scores["Firewall / Network"]

    if auth_score > 0 and availability_score > 0:
        return "Mixed Generic"

    return best_profile


def profile_allows_auth(profile):
    return profile in ["Auto Detect", "Linux Auth / SSH", "Mixed Generic"]


def profile_allows_availability(profile):
    return profile in ["Auto Detect", "Web / Reverse Proxy", "Firewall / Network", "Mixed Generic"]


def detect_auth_event(line):
    lower_line = line.lower()

    for pattern, event_type, reason in FAILED_PATTERNS:
        if re.search(pattern, lower_line):
            return {
                "event_category": "authentication",
                "event_type": event_type,
                "severity": "medium",
                "detection_reason": reason,
                "is_failed": True,
                "is_success": False,
            }

    for pattern, event_type, reason in SUCCESS_PATTERNS:
        if re.search(pattern, lower_line):
            return {
                "event_category": "authentication",
                "event_type": event_type,
                "severity": "low",
                "detection_reason": reason,
                "is_failed": False,
                "is_success": True,
            }

    return None


def detect_ddos_events(line):
    lower_line = line.lower()
    matches = []

    for event_type, config in DDOS_PATTERNS.items():
        if any(re.search(pattern, lower_line) for pattern in config["patterns"]):
            matches.append({
                "event_category": "availability",
                "event_type": event_type,
                "severity": config["severity"],
                "detection_reason": config["reason"],
            })

    return matches


def detect_time_based_attacks(failed_events, time_window_seconds, burst_threshold):
    suspicious_bursts = {}

    for ip, timestamps in failed_events.items():
        if len(timestamps) < burst_threshold:
            continue

        sorted_times = sorted(timestamps)
        left = 0
        max_count_in_window = 0

        for right in range(len(sorted_times)):
            while (sorted_times[right] - sorted_times[left]).total_seconds() > time_window_seconds:
                left += 1

            current_count = right - left + 1
            if current_count > max_count_in_window:
                max_count_in_window = current_count

        if max_count_in_window >= burst_threshold:
            suspicious_bursts[ip] = max_count_in_window

    return suspicious_bursts


def _read_log_lines(file_path):
    with open(file_path, "r", encoding="utf-8", errors="replace") as file:
        return [line.strip() for line in file if line.strip()]


def _analyze_one_source(
    file_path,
    source_profile,
    failed_login_threshold,
    time_window_seconds,
    burst_threshold,
):
    raw_lines = _read_log_lines(file_path)
    total_lines = len(raw_lines)

    effective_profile = source_profile
    if source_profile == "Auto Detect":
        effective_profile = detect_profile_from_content(raw_lines)

    failed_attempts = 0
    successful_logins = 0
    failed_ips = Counter()
    failed_events = defaultdict(list)

    matched_failed_lines = 0
    matched_success_lines = 0

    ddos_event_counts = Counter()
    ddos_source_ips = Counter()
    ddos_lines = []

    normalized_events = []
    source_file_name = os.path.basename(file_path)

    for clean_line in raw_lines:
        timestamp = extract_timestamp(clean_line)
        source_ip = extract_ip(clean_line)

        if profile_allows_auth(effective_profile):
            auth_match = detect_auth_event(clean_line)
            if auth_match:
                event = make_event(
                    timestamp=timestamp,
                    source_ip=source_ip,
                    event_category=auth_match["event_category"],
                    event_type=auth_match["event_type"],
                    severity=auth_match["severity"],
                    detection_reason=auth_match["detection_reason"],
                    raw_log=clean_line,
                    source_profile=effective_profile,
                    source_file=source_file_name,
                )
                normalized_events.append(event)

                if auth_match["is_failed"]:
                    matched_failed_lines += 1
                    failed_attempts += 1
                    if source_ip:
                        failed_ips[source_ip] += 1
                        if timestamp:
                            failed_events[source_ip].append(timestamp)

                if auth_match["is_success"]:
                    matched_success_lines += 1
                    successful_logins += 1

        if profile_allows_availability(effective_profile):
            ddos_matches = detect_ddos_events(clean_line)
            if ddos_matches:
                ddos_lines.append(clean_line)

                for match in ddos_matches:
                    event = make_event(
                        timestamp=timestamp,
                        source_ip=source_ip,
                        event_category=match["event_category"],
                        event_type=match["event_type"],
                        severity=match["severity"],
                        detection_reason=match["detection_reason"],
                        raw_log=clean_line,
                        source_profile=effective_profile,
                        source_file=source_file_name,
                    )
                    normalized_events.append(event)

                    ddos_event_counts[match["event_type"]] += 1
                    if source_ip:
                        ddos_source_ips[source_ip] += 1

    return {
        "file_path": file_path,
        "source_file": source_file_name,
        "source_profile_requested": source_profile,
        "source_profile_used": effective_profile,
        "total_lines": total_lines,
        "successful_logins": successful_logins,
        "failed_attempts": failed_attempts,
        "failed_ips": failed_ips,
        "failed_events": failed_events,
        "matched_failed_lines": matched_failed_lines,
        "matched_success_lines": matched_success_lines,
        "ddos_event_counts": ddos_event_counts,
        "ddos_source_ips": ddos_source_ips,
        "ddos_lines": ddos_lines,
        "normalized_events": normalized_events,
    }


def analyze_multiple_logs(
    log_sources,
    failed_login_threshold=DEFAULT_FAILED_LOGIN_THRESHOLD,
    time_window_seconds=DEFAULT_TIME_WINDOW_SECONDS,
    burst_threshold=DEFAULT_BURST_THRESHOLD,
):
    """
    Analyze multiple log sources and merge results.

    log_sources format:
    [
        {"path": "C:/logs/auth.log", "profile": "Linux Auth / SSH"},
        {"path": "C:/logs/proxy.log", "profile": "Web / Reverse Proxy"},
    ]
    """
    if not log_sources:
        return {"error": "No log sources were provided."}

    total_lines = 0
    successful_logins = 0
    failed_attempts = 0

    merged_failed_ips = Counter()
    merged_failed_events = defaultdict(list)

    matched_failed_lines = 0
    matched_success_lines = 0

    merged_ddos_event_counts = Counter()
    merged_ddos_source_ips = Counter()
    merged_ddos_lines = []

    merged_normalized_events = []
    per_source_results = []

    try:
        for source in log_sources:
            file_path = source.get("path", "").strip()
            requested_profile = source.get("profile", DEFAULT_SOURCE_PROFILE)

            if not file_path:
                continue

            source_result = _analyze_one_source(
                file_path=file_path,
                source_profile=requested_profile,
                failed_login_threshold=failed_login_threshold,
                time_window_seconds=time_window_seconds,
                burst_threshold=burst_threshold,
            )
            per_source_results.append(source_result)

            total_lines += source_result["total_lines"]
            successful_logins += source_result["successful_logins"]
            failed_attempts += source_result["failed_attempts"]
            matched_failed_lines += source_result["matched_failed_lines"]
            matched_success_lines += source_result["matched_success_lines"]

            merged_failed_ips.update(source_result["failed_ips"])
            merged_ddos_event_counts.update(source_result["ddos_event_counts"])
            merged_ddos_source_ips.update(source_result["ddos_source_ips"])
            merged_ddos_lines.extend(source_result["ddos_lines"])
            merged_normalized_events.extend(source_result["normalized_events"])

            for ip, timestamps in source_result["failed_events"].items():
                merged_failed_events[ip].extend(timestamps)

    except FileNotFoundError as exc:
        return {"error": f"Could not find log file: {exc}"}
    except Exception as exc:
        return {"error": f"Unexpected error during multi-file analysis: {exc}"}

    suspicious_ips = {
        ip: count
        for ip, count in merged_failed_ips.items()
        if count >= failed_login_threshold
    }

    time_based_attacks = detect_time_based_attacks(
        merged_failed_events,
        time_window_seconds,
        burst_threshold
    )

    for ip, count in time_based_attacks.items():
        merged_normalized_events.append(
            make_event(
                timestamp=None,
                source_ip=ip,
                event_category="authentication",
                event_type="burst_detection",
                severity="high",
                detection_reason=f"detected {count} failed logins within {time_window_seconds} seconds across loaded sources",
                raw_log=f"Synthetic detection: {ip} triggered {count} failures within {time_window_seconds} seconds across multiple sources",
                source_profile="Correlation",
                source_file="MULTI_SOURCE",
            )
        )

    top_failed_ip = max(merged_failed_ips, key=merged_failed_ips.get) if merged_failed_ips else None
    top_ddos_ip = max(merged_ddos_source_ips, key=merged_ddos_source_ips.get) if merged_ddos_source_ips else None
    ddos_detected = sum(merged_ddos_event_counts.values()) > 0

    profile_summary = [
        f"{item['source_file']} -> requested: {item['source_profile_requested']}, used: {item['source_profile_used']}"
        for item in per_source_results
    ]

    summary = []
    summary.append(f"Loaded {len(per_source_results)} log source(s).")
    summary.extend(profile_summary)

    if suspicious_ips and top_failed_ip:
        summary.append(
            f"Most active suspicious auth source: {top_failed_ip} ({merged_failed_ips[top_failed_ip]} failed attempts across all sources)"
        )

    if time_based_attacks:
        summary.append(
            f"Rapid auth attack behavior detected from {len(time_based_attacks)} IP(s) within {time_window_seconds} seconds across loaded sources"
        )

    if ddos_detected:
        summary.append(
            f"Service-flood indicators detected across {len(merged_ddos_event_counts)} event type(s)"
        )
        if top_ddos_ip:
            summary.append(
                f"Most active service-flood source: {top_ddos_ip} ({merged_ddos_source_ips[top_ddos_ip]} matching events)"
            )

    if failed_attempts == 0:
        summary.append("No failed login attempts detected.")
    elif failed_attempts > successful_logins:
        summary.append("Failed login activity exceeds successful logins.")
    else:
        summary.append("Authentication activity appears mixed with normal usage.")

    if not ddos_detected:
        summary.append("No service-flood or DDoS-style indicators detected.")

    summary.append(
        f"Detected {matched_failed_lines} failed-auth lines and {matched_success_lines} successful-auth lines across all loaded sources."
    )

    merged_normalized_events.sort(
        key=lambda e: (
            e["timestamp"] if e["timestamp"] != "Unknown" else "9999-99-99 99:99:99",
            e.get("source_file", ""),
        )
    )

    return {
        "total_lines": total_lines,
        "successful_logins": successful_logins,
        "failed_attempts": failed_attempts,
        "failed_ips": dict(merged_failed_ips),
        "suspicious_ips": suspicious_ips,
        "time_based_attacks": time_based_attacks,
        "failed_login_threshold": failed_login_threshold,
        "time_window_seconds": time_window_seconds,
        "burst_threshold": burst_threshold,
        "summary": summary,
        "matched_failed_lines": matched_failed_lines,
        "matched_success_lines": matched_success_lines,
        "supported_formats": [
            "YYYY-MM-DD HH:MM:SS logs",
            "Syslog-style 'Mon DD HH:MM:SS' logs",
            "Custom 'failed login attempt' format",
            "SSH-style 'Failed password' / 'Accepted password'",
            "Authentication failure style logs",
            "Invalid user login attempts",
            "Service-flood / DDoS indicator lines",
        ],
        "ddos_detected": ddos_detected,
        "ddos_event_counts": dict(merged_ddos_event_counts),
        "ddos_source_ips": dict(merged_ddos_source_ips),
        "ddos_lines": merged_ddos_lines[:30],
        "normalized_events": merged_normalized_events,
        "source_profile_requested": "MULTI_SOURCE",
        "source_profile_used": "Per-source assignment",
        "available_source_profiles": SOURCE_PROFILES,
        "loaded_sources": [
            {
                "source_file": item["source_file"],
                "file_path": item["file_path"],
                "source_profile_requested": item["source_profile_requested"],
                "source_profile_used": item["source_profile_used"],
                "total_lines": item["total_lines"],
            }
            for item in per_source_results
        ],
        "per_source_results": [
            {
                "source_file": item["source_file"],
                "file_path": item["file_path"],
                "source_profile_requested": item["source_profile_requested"],
                "source_profile_used": item["source_profile_used"],
                "total_lines": item["total_lines"],
                "successful_logins": item["successful_logins"],
                "failed_attempts": item["failed_attempts"],
                "failed_ips": dict(item["failed_ips"]),
                "suspicious_ips": dict(
                    {
                        ip: count
                        for ip, count in item["failed_ips"].items()
                        if count >= failed_login_threshold
                    }
                ),
                "time_based_attacks": dict(
                    detect_time_based_attacks(
                        item["failed_events"],
                        time_window_seconds,
                        burst_threshold
                    )
                ),
                "failed_login_threshold": failed_login_threshold,
                "time_window_seconds": time_window_seconds,
                "burst_threshold": burst_threshold,
                "matched_failed_lines": item["matched_failed_lines"],
                "matched_success_lines": item["matched_success_lines"],
                "ddos_detected": sum(item["ddos_event_counts"].values()) > 0,
                "ddos_event_counts": dict(item["ddos_event_counts"]),
                "ddos_source_ips": dict(item["ddos_source_ips"]),
                "ddos_lines": item["ddos_lines"][:10],
                "normalized_event_count": len(item["normalized_events"]),
                "summary": [
                    f"{item['source_file']} used profile {item['source_profile_used']}",
                    f"Failed attempts: {item['failed_attempts']}, successful logins: {item['successful_logins']}",
                ],
            }
            for item in per_source_results
        ],
    }


def analyze_log(
    file_path,
    failed_login_threshold=DEFAULT_FAILED_LOGIN_THRESHOLD,
    time_window_seconds=DEFAULT_TIME_WINDOW_SECONDS,
    burst_threshold=DEFAULT_BURST_THRESHOLD,
    source_profile=DEFAULT_SOURCE_PROFILE
):
    """
    Backward-compatible single-file wrapper.
    """
    result = analyze_multiple_logs(
        log_sources=[{"path": file_path, "profile": source_profile}],
        failed_login_threshold=failed_login_threshold,
        time_window_seconds=time_window_seconds,
        burst_threshold=burst_threshold,
    )

    if "error" in result:
        return result

    if result.get("loaded_sources"):
        first_source = result["loaded_sources"][0]
        result["source_profile_requested"] = first_source["source_profile_requested"]
        result["source_profile_used"] = first_source["source_profile_used"]

    return result


def generate_report_string(results):
    if "error" in results:
        return f"ERROR: {results['error']}"

    output = []
    output.append("LogSentry Analysis Started...")
    output.append("")
    output.append("=" * 60)
    output.append("LOG ANALYSIS REPORT")
    output.append("=" * 60)
    output.append(f"Source profile requested: {results.get('source_profile_requested', 'Unknown')}")
    output.append(f"Source profile used: {results.get('source_profile_used', 'Unknown')}")

    loaded_sources = results.get("loaded_sources", [])
    if loaded_sources:
        output.append(f"Loaded sources: {len(loaded_sources)}")
        for source in loaded_sources:
            output.append(
                f"  - {source['source_file']} | requested={source['source_profile_requested']} | "
                f"used={source['source_profile_used']} | lines={source['total_lines']}"
            )

    output.append(f"Total log lines: {results['total_lines']}")
    output.append(f"Successful logins: {results['successful_logins']}")
    output.append(f"Failed login attempts: {results['failed_attempts']}")
    output.append(f"Suspicious IP threshold: {results['failed_login_threshold']}")
    output.append(
        f"Rapid burst rule: {results['burst_threshold']} failures in "
        f"{results['time_window_seconds']} seconds"
    )
    output.append("")

    output.append("Supported log handling:")
    for fmt in results["supported_formats"]:
        output.append(f"  - {fmt}")
    output.append("")

    output.append("Summary:")
    for item in results["summary"]:
        output.append(f"  - {item}")
    output.append("")

    if results["failed_ips"]:
        output.append("Failed login attempts by IP:")
        sorted_failed_ips = sorted(results["failed_ips"].items(), key=lambda item: item[1], reverse=True)
        for ip, count in sorted_failed_ips:
            output.append(f"  {ip}: {count}")
        output.append("")
    else:
        output.append("No failed login attempts found.")
        output.append("")

    if results["suspicious_ips"]:
        output.append("Suspicious IPs flagged by threshold:")
        sorted_suspicious_ips = sorted(results["suspicious_ips"].items(), key=lambda item: item[1], reverse=True)
        for ip, count in sorted_suspicious_ips:
            output.append(f"  ALERT: {ip} had {count} failed login attempts")
        output.append("")
    else:
        output.append("No suspicious IPs met the failed-login threshold.")
        output.append("")

    if results["time_based_attacks"]:
        output.append("Rapid burst detections:")
        sorted_bursts = sorted(results["time_based_attacks"].items(), key=lambda item: item[1], reverse=True)
        for ip, count in sorted_bursts:
            output.append(
                f"  WARNING: {ip} triggered {count} failures within {results['time_window_seconds']} seconds"
            )
        output.append("")
    else:
        output.append("No rapid burst attack patterns detected.")
        output.append("")

    if results["ddos_detected"]:
        output.append("Service-flood / DDoS indicators:")
        sorted_ddos_events = sorted(results["ddos_event_counts"].items(), key=lambda item: item[1], reverse=True)
        for event_name, count in sorted_ddos_events:
            friendly_name = event_name.replace("_", " ").title()
            output.append(f"  ALERT: {friendly_name}: {count}")
        output.append("")
    else:
        output.append("No service-flood / DDoS indicators detected.")
        output.append("")

    output.append(f"Normalized events created: {len(results.get('normalized_events', []))}")
    output.append("")
    output.append("=" * 60)
    output.append("")
    output.append("Analysis Complete.")

    return "\n".join(output)


if __name__ == "__main__":
    report = analyze_log("sample_log.txt")
    print(generate_report_string(report))