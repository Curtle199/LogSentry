import importlib.util
import os
import sys
import json
import csv
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from datetime import datetime


def get_runtime_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def get_writable_output_dir():
    runtime_dir = get_runtime_dir()
    probe_path = os.path.join(runtime_dir, ".logsentry_write_test")

    try:
        with open(probe_path, "w", encoding="utf-8") as probe_file:
            probe_file.write("ok")
        os.remove(probe_path)
        return runtime_dir
    except OSError:
        if sys.platform.startswith("win"):
            base_dir = os.getenv("LOCALAPPDATA") or os.path.expanduser("~")
        elif sys.platform == "darwin":
            base_dir = os.path.expanduser("~/Library/Application Support")
        else:
            base_dir = os.getenv("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")

        fallback_dir = os.path.join(base_dir, "LogSentry")
        os.makedirs(fallback_dir, exist_ok=True)
        return fallback_dir


def resolve_bundled_path(filename):
    candidates = [
        os.path.join(get_writable_output_dir(), filename),
        os.path.join(get_runtime_dir(), filename),
    ]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(os.path.join(meipass, filename))

    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate

    return candidates[0]


def load_write_sample_log():
    try:
        from generate_sample_log import write_sample_log as imported_write_sample_log
        return imported_write_sample_log
    except ImportError:
        for candidate_dir in [get_runtime_dir(), getattr(sys, "_MEIPASS", None)]:
            if not candidate_dir:
                continue
            generator_path = os.path.join(candidate_dir, "generate_sample_log.py")
            if not os.path.exists(generator_path):
                continue

            spec = importlib.util.spec_from_file_location("logsentry_generate_sample_log", generator_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                if hasattr(module, "write_sample_log"):
                    return module.write_sample_log
        return None

# ---- Embedded analyzer logic ----
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
            r"throttle",
        ],
        "severity": "medium",
        "reason": "matched rate limiting/throttle pattern",
    },
    "latency_spike": {
        "patterns": [r"upstream latency increased", r"latency=.*ms", r"avg_latency=.*ms"],
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
            timestamp_text = f"2026 {syslog_match.group(1)}"
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
    with open(file_path, "r", encoding="utf-8") as file:
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

# ---- End embedded analyzer logic ----

write_sample_log = load_write_sample_log()

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_AVAILABLE = True
except ImportError:
    DND_AVAILABLE = False
    DND_FILES = None
    TkinterDnD = None


class LogSentryApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LogSentry v2.4")
        self.root.geometry("1440x980")
        self.root.minsize(1180, 820)
        self.root.configure(bg="#0f172a")
        self.maximize_on_startup()

        self.file_path = ""
        self.last_report = ""
        self.last_results = None
        self.loaded_sources = []

        self.setup_styles()
        self.build_ui()

    def maximize_on_startup(self):
        try:
            self.root.state("zoomed")
            return
        except Exception:
            pass

        try:
            self.root.attributes("-zoomed", True)
            return
        except Exception:
            pass

    def setup_styles(self):
        self.colors = {
            "bg": "#0f172a",
            "panel": "#111827",
            "panel_2": "#1f2937",
            "border": "#334155",
            "text": "#e5e7eb",
            "muted": "#94a3b8",
            "accent": "#2563eb",
            "accent_hover": "#1d4ed8",
            "success": "#16a34a",
            "success_card": "#14532d",
            "warning": "#f59e0b",
            "warning_card": "#78350f",
            "danger": "#dc2626",
            "danger_card": "#7f1d1d",
            "neutral_card": "#1e3a8a",
            "purple_card": "#581c87",
            "input_bg": "#0b1220",
            "output_bg": "#020617",
            "output_success": "#86efac",
            "output_warning": "#fbbf24",
            "output_alert": "#f87171",
            "output_ddos": "#c084fc",
            "output_heading": "#93c5fd",
            "output_low": "#cbd5e1",
            "output_medium": "#fbbf24",
            "output_high": "#f87171",
            "output_critical": "#fb7185",
            "banner_high": "#7f1d1d",
            "banner_medium": "#78350f",
            "banner_low": "#14532d",
            "banner_error": "#3f3f46",
        }

        self.font_title = ("Segoe UI", 24, "bold")
        self.font_subtitle = ("Segoe UI", 11)
        self.font_heading = ("Segoe UI", 12, "bold")
        self.font_body = ("Segoe UI", 10)
        self.font_stat_value = ("Segoe UI", 18, "bold")
        self.font_stat_label = ("Segoe UI", 9)
        self.font_output = ("Consolas", 10)
        self.font_banner_value = ("Segoe UI", 12, "bold")
        self.font_banner_label = ("Segoe UI", 9)
        self.font_banner_reason = ("Segoe UI", 10)

        self.style = ttk.Style()
        self.style.theme_use("default")

        self.style.configure("TNotebook", background=self.colors["panel"], borderwidth=0)
        self.style.configure(
            "TNotebook.Tab",
            background=self.colors["panel_2"],
            foreground=self.colors["text"],
            padding=(18, 10),
            borderwidth=0
        )
        self.style.map(
            "TNotebook.Tab",
            background=[("selected", self.colors["accent"])],
            foreground=[("selected", "white")]
        )

        self.style.configure(
            "Treeview",
            background=self.colors["input_bg"],
            foreground=self.colors["text"],
            fieldbackground=self.colors["input_bg"],
            bordercolor=self.colors["border"],
            rowheight=26
        )
        self.style.configure(
            "Treeview.Heading",
            background=self.colors["panel_2"],
            foreground=self.colors["text"],
            relief="flat"
        )
        self.style.map(
            "Treeview",
            background=[("selected", "#1d4ed8")],
            foreground=[("selected", "white")]
        )

    def build_ui(self):
        self.main_frame = tk.Frame(self.root, bg=self.colors["bg"])
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        self.paned = tk.PanedWindow(
            self.main_frame,
            orient=tk.VERTICAL,
            bg=self.colors["bg"],
            sashwidth=8,
            sashrelief="flat",
            bd=0
        )
        self.paned.pack(fill="both", expand=True)

        self.top_frame = tk.Frame(self.paned, bg=self.colors["bg"])
        self.bottom_frame = tk.Frame(self.paned, bg=self.colors["bg"])

        self.paned.add(self.top_frame, minsize=820)
        self.paned.add(self.bottom_frame, minsize=320)

        self.build_header()
        self.build_incident_banner()
        self.build_controls_notebook()
        self.build_stats_section(self.bottom_frame)
        self.build_tabbed_output_section()

        self.root.after(150, self.apply_default_layout)

    def apply_default_layout(self):
        self.root.update_idletasks()
        total_height = max(self.main_frame.winfo_height(), self.root.winfo_height() - 40)
        desired_top = max(820, int(total_height * 0.64))
        max_top = max(820, total_height - 320)
        desired_top = min(desired_top, max_top)
        try:
            self.paned.sash_place(0, 0, desired_top)
        except Exception:
            pass

    def build_header(self):
        header = tk.Frame(
            self.top_frame,
            bg=self.colors["panel"],
            highlightbackground=self.colors["border"],
            highlightthickness=1
        )
        header.pack(fill="x", pady=(0, 16))

        tk.Label(
            header,
            text="LogSentry",
            font=self.font_title,
            fg=self.colors["text"],
            bg=self.colors["panel"]
        ).pack(pady=(18, 4))

        subtitle_text = "Multi-Source SOC Investigation Workspace"
        if DND_AVAILABLE:
            subtitle_text += "  |  Drag and Drop Enabled"
        else:
            subtitle_text += "  |  Drag and Drop Unavailable"

        tk.Label(
            header,
            text=subtitle_text,
            font=self.font_subtitle,
            fg=self.colors["muted"],
            bg=self.colors["panel"]
        ).pack(pady=(0, 18))

    def build_controls_notebook(self):
        controls_shell = tk.Frame(
            self.top_frame,
            bg=self.colors["panel"],
            highlightbackground=self.colors["border"],
            highlightthickness=1
        )
        controls_shell.pack(fill="x", expand=False, pady=(0, 16))

        title_row = tk.Frame(controls_shell, bg=self.colors["panel"])
        title_row.pack(fill="x", padx=16, pady=(14, 8))

        tk.Label(
            title_row,
            text="Operator Controls",
            font=self.font_heading,
            fg=self.colors["text"],
            bg=self.colors["panel"]
        ).pack(side="left")

        tk.Label(
            title_row,
            text="Each section gets its own tab so nothing important hides below the fold.",
            font=self.font_body,
            fg=self.colors["muted"],
            bg=self.colors["panel"]
        ).pack(side="right")

        self.controls_notebook = ttk.Notebook(controls_shell)
        self.controls_notebook.pack(fill="x", expand=False, padx=16, pady=(0, 16))

        self.single_file_tab = tk.Frame(self.controls_notebook, bg=self.colors["bg"])
        self.sources_tab = tk.Frame(self.controls_notebook, bg=self.colors["bg"])
        self.actions_tab = tk.Frame(self.controls_notebook, bg=self.colors["bg"])
        self.detection_controls_tab = tk.Frame(self.controls_notebook, bg=self.colors["bg"])
        self.investigation_controls_tab = tk.Frame(self.controls_notebook, bg=self.colors["bg"])

        self.controls_notebook.add(self.single_file_tab, text="Single File")
        self.controls_notebook.add(self.sources_tab, text="Loaded Sources")
        self.controls_notebook.add(self.actions_tab, text="Actions")
        self.controls_notebook.add(self.detection_controls_tab, text="Detection Settings")
        self.controls_notebook.add(self.investigation_controls_tab, text="Investigation Filters")

        self.build_file_section(self.single_file_tab)
        self.build_sources_section(self.sources_tab)
        self.build_action_section(self.actions_tab)
        self.build_settings_section(self.detection_controls_tab)
        self.build_filter_section(self.investigation_controls_tab)

    def build_incident_banner(self):
        self.banner_section = tk.Frame(
            self.top_frame,
            bg=self.colors["banner_low"],
            highlightbackground=self.colors["border"],
            highlightthickness=1
        )
        self.banner_section.pack(fill="x", pady=(0, 16))

        title_row = tk.Frame(self.banner_section, bg=self.colors["banner_low"])
        title_row.pack(fill="x", padx=16, pady=(12, 4))

        tk.Label(
            title_row,
            text="Incident Summary",
            font=self.font_heading,
            fg="white",
            bg=self.colors["banner_low"]
        ).pack(side="left")

        self.banner_time_label = tk.Label(
            title_row,
            text="Report Time: Not analyzed yet",
            font=self.font_body,
            fg="#f3f4f6",
            bg=self.colors["banner_low"]
        )
        self.banner_time_label.pack(side="right")

        cards_row = tk.Frame(self.banner_section, bg=self.colors["banner_low"])
        cards_row.pack(fill="x", padx=16, pady=(4, 8))

        self.risk_card = self.create_banner_card(cards_row, "Risk Level", "Low")
        self.risk_card.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.auth_banner_card = self.create_banner_card(cards_row, "Auth Abuse Detected", "No")
        self.auth_banner_card.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.burst_banner_card = self.create_banner_card(cards_row, "Burst Activity Detected", "No")
        self.burst_banner_card.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.ddos_banner_card = self.create_banner_card(cards_row, "Service-Flood Indicators", "No")
        self.ddos_banner_card.pack(side="left", fill="x", expand=True)

        self.banner_reason_label = tk.Label(
            self.banner_section,
            text="Why: No analysis has been run yet.",
            font=self.font_banner_reason,
            fg="#f8fafc",
            bg=self.colors["banner_low"],
            anchor="w",
            justify="left"
        )
        self.banner_reason_label.pack(fill="x", padx=16, pady=(0, 14))

    def create_banner_card(self, parent, label_text, value_text):
        card = tk.Frame(
            parent,
            bg="#0b1220",
            highlightbackground=self.colors["border"],
            highlightthickness=1
        )

        value_label = tk.Label(
            card,
            text=value_text,
            font=self.font_banner_value,
            fg="white",
            bg="#0b1220"
        )
        value_label.pack(anchor="w", padx=14, pady=(10, 2))

        text_label = tk.Label(
            card,
            text=label_text,
            font=self.font_banner_label,
            fg="#cbd5e1",
            bg="#0b1220"
        )
        text_label.pack(anchor="w", padx=14, pady=(0, 10))

        card.value_label = value_label
        return card

    def build_file_section(self, parent=None):
        container = parent or self.top_frame
        section = tk.Frame(
            container,
            bg=self.colors["panel"],
            highlightbackground=self.colors["border"],
            highlightthickness=1
        )
        section.pack(fill="x", pady=(0, 16))

        tk.Label(
            section,
            text="Quick File Selection",
            font=self.font_heading,
            fg=self.colors["text"],
            bg=self.colors["panel"]
        ).pack(anchor="w", padx=16, pady=(14, 10))

        row = tk.Frame(section, bg=self.colors["panel"])
        row.pack(fill="x", padx=16, pady=(0, 10))

        self.file_label = tk.Label(
            row,
            text="No single file selected",
            font=self.font_body,
            fg=self.colors["text"],
            bg=self.colors["input_bg"],
            anchor="w",
            padx=12,
            pady=10,
            relief="flat"
        )
        self.file_label.pack(side="left", fill="x", expand=True, padx=(0, 10))

        browse_button = tk.Button(
            row,
            text="Browse Single File",
            font=self.font_body,
            fg="white",
            bg=self.colors["accent"],
            activeforeground="white",
            activebackground=self.colors["accent_hover"],
            relief="flat",
            bd=0,
            padx=18,
            pady=10,
            cursor="hand2",
            command=self.browse_file
        )
        browse_button.pack(side="right")

        self.drop_zone = tk.Label(
            section,
            text="Drag and drop a .txt or .log file here to add it as a source" if DND_AVAILABLE else "Drag and drop requires: pip install tkinterdnd2",
            font=self.font_body,
            fg=self.colors["muted"],
            bg=self.colors["input_bg"],
            padx=12,
            pady=16,
            relief="flat",
            anchor="center"
        )
        self.drop_zone.pack(fill="x", padx=16, pady=(0, 16))

        if DND_AVAILABLE:
            self.drop_zone.drop_target_register(DND_FILES)
            self.drop_zone.dnd_bind("<<Drop>>", self.handle_drop)
            self.drop_zone.dnd_bind("<<DragEnter>>", self.handle_drag_enter)
            self.drop_zone.dnd_bind("<<DragLeave>>", self.handle_drag_leave)

    def build_sources_section(self, parent=None):
        container = parent or self.top_frame
        section = tk.Frame(
            container,
            bg=self.colors["panel"],
            highlightbackground=self.colors["border"],
            highlightthickness=1
        )
        section.pack(fill="both", pady=(0, 16))

        title_row = tk.Frame(section, bg=self.colors["panel"])
        title_row.pack(fill="x", padx=16, pady=(14, 10))

        tk.Label(
            title_row,
            text="Loaded Sources",
            font=self.font_heading,
            fg=self.colors["text"],
            bg=self.colors["panel"]
        ).pack(side="left")

        controls = tk.Frame(title_row, bg=self.colors["panel"])
        controls.pack(side="right")

        self.new_source_profile_var = tk.StringVar(value="Auto Detect")
        self.new_source_profile_combo = ttk.Combobox(
            controls,
            textvariable=self.new_source_profile_var,
            values=SOURCE_PROFILES,
            state="readonly",
            width=20
        )
        self.new_source_profile_combo.pack(side="left", padx=(0, 10))

        add_source_button = tk.Button(
            controls,
            text="Add Log File",
            font=("Segoe UI", 10, "bold"),
            fg="white",
            bg=self.colors["accent"],
            activeforeground="white",
            activebackground=self.colors["accent_hover"],
            relief="flat",
            bd=0,
            padx=16,
            pady=8,
            cursor="hand2",
            command=self.add_source_file
        )
        add_source_button.pack(side="left", padx=(0, 10))

        remove_source_button = tk.Button(
            controls,
            text="Remove Selected Source",
            font=("Segoe UI", 10, "bold"),
            fg="white",
            bg="#7f1d1d",
            activeforeground="white",
            activebackground="#991b1b",
            relief="flat",
            bd=0,
            padx=16,
            pady=8,
            cursor="hand2",
            command=self.remove_selected_source
        )
        remove_source_button.pack(side="left", padx=(0, 10))

        clear_sources_button = tk.Button(
            controls,
            text="Clear Sources",
            font=("Segoe UI", 10, "bold"),
            fg="white",
            bg="#475569",
            activeforeground="white",
            activebackground="#334155",
            relief="flat",
            bd=0,
            padx=16,
            pady=8,
            cursor="hand2",
            command=self.clear_sources
        )
        clear_sources_button.pack(side="left")

        table_frame = tk.Frame(section, bg=self.colors["panel"])
        table_frame.pack(fill="both", padx=16, pady=(0, 16))

        columns = ("source_file", "profile")
        self.sources_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=6)
        self.sources_tree.heading("source_file", text="Source File")
        self.sources_tree.heading("profile", text="Assigned Profile")
        self.sources_tree.column("source_file", width=560, anchor="w")
        self.sources_tree.column("profile", width=220, anchor="w")
        self.sources_tree.pack(fill="both", expand=True)

    def build_action_section(self, parent=None):
        container = parent or self.top_frame
        section = tk.Frame(container, bg=self.colors["bg"])
        section.pack(fill="x", pady=(0, 16))

        button_frame = tk.Frame(section, bg=self.colors["bg"])
        button_frame.pack(fill="x")

        buttons = [
            ("Generate Sample Attack", "#7c3aed", "#6d28d9", self.generate_sample_attack),
            ("Load Sample Log", self.colors["panel_2"], "#374151", self.load_sample_log),
            ("Analyze Single File", self.colors["success"], "#15803d", self.run_analysis),
            ("Analyze All Sources", "#0f766e", "#115e59", self.run_multi_analysis),
            ("Export TXT", self.colors["accent"], self.colors["accent_hover"], self.export_report),
            ("Export JSON", "#0f766e", "#115e59", self.export_json),
            ("Export CSV", "#b45309", "#92400e", self.export_csv),
            ("Clear", "#475569", "#334155", self.clear_all),
        ]

        for col in range(4):
            button_frame.grid_columnconfigure(col, weight=1)

        for index, (label, bg, active_bg, command) in enumerate(buttons):
            row = index // 4
            col = index % 4
            button = tk.Button(
                button_frame,
                text=label,
                font=("Segoe UI", 10, "bold"),
                fg="white",
                bg=bg,
                activeforeground="white",
                activebackground=active_bg,
                relief="flat",
                bd=0,
                padx=12,
                pady=12,
                cursor="hand2",
                command=command
            )
            button.grid(row=row, column=col, sticky="ew", padx=6, pady=6)

    def build_settings_section(self, parent=None):
        container = parent or self.top_frame
        section = tk.Frame(
            container,
            bg=self.colors["panel"],
            highlightbackground=self.colors["border"],
            highlightthickness=1
        )
        section.pack(fill="x", pady=(0, 16))

        tk.Label(
            section,
            text="Detection Settings",
            font=self.font_heading,
            fg=self.colors["text"],
            bg=self.colors["panel"]
        ).grid(row=0, column=0, columnspan=8, sticky="w", padx=16, pady=(14, 10))

        self.threshold_var = tk.StringVar(value="3")
        self.time_window_var = tk.StringVar(value="30")
        self.burst_threshold_var = tk.StringVar(value="3")
        self.source_profile_var = tk.StringVar(value="Auto Detect")

        labels = [
            ("Failed Login Threshold", self.threshold_var),
            ("Burst Time Window (sec)", self.time_window_var),
            ("Burst Threshold", self.burst_threshold_var),
        ]

        for index, (label_text, variable) in enumerate(labels):
            tk.Label(
                section,
                text=label_text,
                font=self.font_body,
                fg=self.colors["muted"],
                bg=self.colors["panel"]
            ).grid(row=1, column=index * 2, sticky="w", padx=(16, 8), pady=(0, 14))

            entry = tk.Entry(
                section,
                textvariable=variable,
                font=self.font_body,
                bg=self.colors["input_bg"],
                fg=self.colors["text"],
                insertbackground=self.colors["text"],
                relief="flat",
                bd=0,
                width=10
            )
            entry.grid(row=1, column=index * 2 + 1, sticky="w", padx=(0, 16), pady=(0, 14))
            entry.configure(highlightthickness=1, highlightbackground=self.colors["border"])

        tk.Label(
            section,
            text="Single-File Source Profile",
            font=self.font_body,
            fg=self.colors["muted"],
            bg=self.colors["panel"]
        ).grid(row=2, column=0, sticky="w", padx=(16, 8), pady=(0, 14))

        self.source_profile_combo = ttk.Combobox(
            section,
            textvariable=self.source_profile_var,
            values=SOURCE_PROFILES,
            state="readonly",
            width=22
        )
        self.source_profile_combo.grid(row=2, column=1, sticky="w", padx=(0, 16), pady=(0, 14))

    def build_filter_section(self, parent=None):
        container = parent or self.top_frame
        section = tk.Frame(
            container,
            bg=self.colors["panel"],
            highlightbackground=self.colors["border"],
            highlightthickness=1
        )
        section.pack(fill="x", pady=(0, 16))

        tk.Label(
            section,
            text="Investigation Filters",
            font=self.font_heading,
            fg=self.colors["text"],
            bg=self.colors["panel"]
        ).grid(row=0, column=0, columnspan=8, sticky="w", padx=16, pady=(14, 10))

        tk.Label(section, text="Filter by IP", font=self.font_body, fg=self.colors["muted"], bg=self.colors["panel"]).grid(row=1, column=0, sticky="w", padx=(16, 8), pady=(0, 14))
        self.ip_filter_var = tk.StringVar()
        self.ip_filter_entry = tk.Entry(section, textvariable=self.ip_filter_var, font=self.font_body, bg=self.colors["input_bg"], fg=self.colors["text"], insertbackground=self.colors["text"], relief="flat", bd=0, width=20)
        self.ip_filter_entry.grid(row=1, column=1, sticky="w", padx=(0, 16), pady=(0, 14))
        self.ip_filter_entry.configure(highlightthickness=1, highlightbackground=self.colors["border"])

        tk.Label(section, text="Finding Type", font=self.font_body, fg=self.colors["muted"], bg=self.colors["panel"]).grid(row=1, column=2, sticky="w", padx=(16, 8), pady=(0, 14))
        self.finding_type_var = tk.StringVar(value="All Findings")
        self.finding_type_combo = ttk.Combobox(section, textvariable=self.finding_type_var, values=["All Findings", "Authentication", "Burst Detections", "Service-Flood"], state="readonly", width=18)
        self.finding_type_combo.grid(row=1, column=3, sticky="w", padx=(0, 16), pady=(0, 14))

        tk.Label(section, text="Severity", font=self.font_body, fg=self.colors["muted"], bg=self.colors["panel"]).grid(row=1, column=4, sticky="w", padx=(16, 8), pady=(0, 14))
        self.severity_filter_var = tk.StringVar(value="All Severities")
        self.severity_filter_combo = ttk.Combobox(section, textvariable=self.severity_filter_var, values=["All Severities", "Low", "Medium", "High", "Critical"], state="readonly", width=18)
        self.severity_filter_combo.grid(row=1, column=5, sticky="w", padx=(0, 16), pady=(0, 14))

        tk.Label(section, text="Source File", font=self.font_body, fg=self.colors["muted"], bg=self.colors["panel"]).grid(row=2, column=0, sticky="w", padx=(16, 8), pady=(0, 14))
        self.source_file_filter_var = tk.StringVar(value="All Sources")
        self.source_file_filter_combo = ttk.Combobox(section, textvariable=self.source_file_filter_var, values=["All Sources"], state="readonly", width=26)
        self.source_file_filter_combo.grid(row=2, column=1, sticky="w", padx=(0, 16), pady=(0, 14))

        tk.Label(section, text="Selected IP", font=self.font_body, fg=self.colors["muted"], bg=self.colors["panel"]).grid(row=2, column=2, sticky="w", padx=(16, 8), pady=(0, 14))
        self.selected_ip_var = tk.StringVar()
        self.selected_ip_entry = tk.Entry(section, textvariable=self.selected_ip_var, font=self.font_body, bg=self.colors["input_bg"], fg=self.colors["text"], insertbackground=self.colors["text"], relief="flat", bd=0, width=20)
        self.selected_ip_entry.grid(row=2, column=3, sticky="w", padx=(0, 16), pady=(0, 14))
        self.selected_ip_entry.configure(highlightthickness=1, highlightbackground=self.colors["border"])

        apply_filter_button = tk.Button(section, text="Apply Filters", font=("Segoe UI", 10, "bold"), fg="white", bg=self.colors["accent"], activeforeground="white", activebackground=self.colors["accent_hover"], relief="flat", bd=0, padx=18, pady=10, cursor="hand2", command=self.apply_filters)
        apply_filter_button.grid(row=2, column=4, sticky="w", padx=(0, 10), pady=(0, 14))

        drilldown_button = tk.Button(section, text="Use IP Filter for Drill-Down", font=("Segoe UI", 10, "bold"), fg="white", bg="#7c2d12", activeforeground="white", activebackground="#9a3412", relief="flat", bd=0, padx=18, pady=10, cursor="hand2", command=self.use_ip_filter_for_drilldown)
        drilldown_button.grid(row=2, column=5, sticky="w", padx=(0, 10), pady=(0, 14))

        reset_filter_button = tk.Button(section, text="Reset Filters", font=("Segoe UI", 10, "bold"), fg="white", bg="#475569", activeforeground="white", activebackground="#334155", relief="flat", bd=0, padx=18, pady=10, cursor="hand2", command=self.reset_filters)
        reset_filter_button.grid(row=2, column=6, sticky="w", pady=(0, 14))

    def build_stats_section(self, parent=None):
        container = parent or self.top_frame
        self.stats_frame = tk.Frame(container, bg=self.colors["bg"])
        self.stats_frame.pack(fill="x", pady=(0, 16))

        self.total_lines_card = self.create_stat_card(self.stats_frame, "Total Lines", "0", self.colors["neutral_card"])
        self.total_lines_card.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.success_card = self.create_stat_card(self.stats_frame, "Successful Logins", "0", self.colors["success_card"])
        self.success_card.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.failed_card = self.create_stat_card(self.stats_frame, "Failed Attempts", "0", self.colors["warning_card"])
        self.failed_card.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.alert_card = self.create_stat_card(self.stats_frame, "Suspicious IPs", "0", self.colors["danger_card"])
        self.alert_card.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.ddos_card = self.create_stat_card(self.stats_frame, "Service-Flood Events", "0", self.colors["purple_card"])
        self.ddos_card.pack(side="left", fill="x", expand=True)

    def create_stat_card(self, parent, label_text, value_text, bg_color):
        card = tk.Frame(
            parent,
            bg=bg_color,
            highlightbackground=self.colors["border"],
            highlightthickness=1
        )

        value_label = tk.Label(
            card,
            text=value_text,
            font=self.font_stat_value,
            fg="white",
            bg=bg_color
        )
        value_label.pack(anchor="w", padx=16, pady=(14, 2))

        text_label = tk.Label(
            card,
            text=label_text,
            font=self.font_stat_label,
            fg="#e5e7eb",
            bg=bg_color
        )
        text_label.pack(anchor="w", padx=16, pady=(0, 14))

        card.value_label = value_label
        return card

    def build_tabbed_output_section(self):
        section = tk.Frame(
            self.bottom_frame,
            bg=self.colors["panel"],
            highlightbackground=self.colors["border"],
            highlightthickness=1
        )
        section.pack(fill="both", expand=True)

        section.grid_rowconfigure(1, weight=1)
        section.grid_columnconfigure(0, weight=1)

        top_row = tk.Frame(section, bg=self.colors["panel"])
        top_row.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 10))

        tk.Label(top_row, text="Analysis Findings", font=self.font_heading, fg=self.colors["text"], bg=self.colors["panel"]).pack(side="left")
        self.status_label = tk.Label(top_row, text="Ready", font=self.font_body, fg=self.colors["muted"], bg=self.colors["panel"])
        self.status_label.pack(side="right")

        self.notebook = ttk.Notebook(section)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 16))

        self.auth_tab = self.create_tab()
        self.burst_tab = self.create_tab()
        self.ddos_tab = self.create_tab()
        self.event_explorer_tab = self.create_event_explorer_tab()
        self.timeline_tab = self.create_tab()
        self.ip_tab = self.create_tab()
        self.case_tab = self.create_tab()
        self.summary_tab = self.create_tab()

        self.notebook.add(self.auth_tab["frame"], text="Authentication Findings")
        self.notebook.add(self.burst_tab["frame"], text="Burst Detections")
        self.notebook.add(self.ddos_tab["frame"], text="Service-Flood Findings")
        self.notebook.add(self.event_explorer_tab["frame"], text="Event Explorer")
        self.notebook.add(self.timeline_tab["frame"], text="Timeline")
        self.notebook.add(self.ip_tab["frame"], text="IP Drill-Down")
        self.notebook.add(self.case_tab["frame"], text="Case Summary")
        self.notebook.add(self.summary_tab["frame"], text="Raw Summary")

        self.auth_tab["widget"].insert("1.0", "Authentication findings will appear here after analysis.")
        self.burst_tab["widget"].insert("1.0", "Burst detections will appear here after analysis.")
        self.ddos_tab["widget"].insert("1.0", "Service-flood findings will appear here after analysis.")
        self.event_explorer_tab["detail_widget"].insert("1.0", "Select an event to inspect its evidence and metadata.")
        self.timeline_tab["widget"].insert("1.0", "Normalized event timeline will appear here after analysis.")
        self.ip_tab["widget"].insert("1.0", "IP drill-down details will appear here after analysis.")
        self.case_tab["widget"].insert("1.0", "Incident case summary will appear here after analysis.")
        self.summary_tab["widget"].insert("1.0", "Raw report summary will appear here after analysis.")

    def create_tab(self):
        frame = tk.Frame(self.notebook, bg=self.colors["panel"])
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        text_widget = scrolledtext.ScrolledText(
            frame,
            wrap="word",
            font=self.font_output,
            bg=self.colors["output_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            bd=0,
            padx=12,
            pady=12
        )
        text_widget.grid(row=0, column=0, sticky="nsew")

        text_widget.tag_config("success", foreground=self.colors["output_success"])
        text_widget.tag_config("warning", foreground=self.colors["output_warning"])
        text_widget.tag_config("alert", foreground=self.colors["output_alert"])
        text_widget.tag_config("heading", foreground=self.colors["output_heading"])
        text_widget.tag_config("ddos", foreground=self.colors["output_ddos"])
        text_widget.tag_config("low", foreground=self.colors["output_low"])
        text_widget.tag_config("medium", foreground=self.colors["output_medium"])
        text_widget.tag_config("high", foreground=self.colors["output_high"])
        text_widget.tag_config("critical", foreground=self.colors["output_critical"])

        return {"frame": frame, "widget": text_widget}

    def create_event_explorer_tab(self):
        frame = tk.Frame(self.notebook, bg=self.colors["panel"])
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_rowconfigure(5, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)

        info_label = tk.Label(
            frame,
            text="Sortable event table with analyst actions. Click a row to inspect evidence. Double-click to jump into IP drill-down.",
            font=self.font_body,
            fg=self.colors["muted"],
            bg=self.colors["panel"],
            anchor="w"
        )
        info_label.grid(row=0, column=0, columnspan=2, sticky="ew", padx=12, pady=(12, 8))

        action_row = tk.Frame(frame, bg=self.colors["panel"])
        action_row.grid(row=1, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 8))

        tk.Button(action_row, text="Open IP Drill-Down", font=("Segoe UI", 10, "bold"), fg="white", bg="#2563eb", activeforeground="white", activebackground="#1d4ed8", relief="flat", bd=0, padx=14, pady=8, cursor="hand2", command=lambda: self.open_selected_event_ip_drilldown(None)).pack(side="left", padx=(0, 8))
        tk.Button(action_row, text="Copy Raw Evidence", font=("Segoe UI", 10, "bold"), fg="white", bg="#0f766e", activeforeground="white", activebackground="#115e59", relief="flat", bd=0, padx=14, pady=8, cursor="hand2", command=self.copy_selected_raw_evidence).pack(side="left", padx=(0, 8))
        tk.Button(action_row, text="Export Filtered Events", font=("Segoe UI", 10, "bold"), fg="white", bg="#b45309", activeforeground="white", activebackground="#92400e", relief="flat", bd=0, padx=14, pady=8, cursor="hand2", command=self.export_filtered_events_csv).pack(side="left", padx=(0, 8))
        tk.Button(action_row, text="Export Selected Event", font=("Segoe UI", 10, "bold"), fg="white", bg="#7c3aed", activeforeground="white", activebackground="#6d28d9", relief="flat", bd=0, padx=14, pady=8, cursor="hand2", command=self.export_selected_event_json).pack(side="left")

        table_wrap = tk.Frame(frame, bg=self.colors["panel"])
        table_wrap.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=12, pady=(0, 10))
        table_wrap.grid_rowconfigure(0, weight=1)
        table_wrap.grid_columnconfigure(0, weight=1)

        columns = ("timestamp", "severity", "source_ip", "category", "event_type", "source_file")
        self.event_tree = ttk.Treeview(table_wrap, columns=columns, show="headings")
        self.event_tree.grid(row=0, column=0, sticky="nsew")

        for col, heading in [("timestamp", "Timestamp"), ("severity", "Severity"), ("source_ip", "Source IP"), ("category", "Category"), ("event_type", "Event Type"), ("source_file", "Source File")]:
            self.event_tree.heading(col, text=heading, command=lambda c=col: self.sort_event_tree(c))

        self.event_tree.column("timestamp", width=165, anchor="w")
        self.event_tree.column("severity", width=90, anchor="w")
        self.event_tree.column("source_ip", width=120, anchor="w")
        self.event_tree.column("category", width=120, anchor="w")
        self.event_tree.column("event_type", width=180, anchor="w")
        self.event_tree.column("source_file", width=180, anchor="w")

        tree_scroll = ttk.Scrollbar(table_wrap, orient="vertical", command=self.event_tree.yview)
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.event_tree.configure(yscrollcommand=tree_scroll.set)

        self.event_tree.tag_configure("sev_low", background="#0b1220", foreground="#cbd5e1")
        self.event_tree.tag_configure("sev_medium", background="#3a2a05", foreground="#fbbf24")
        self.event_tree.tag_configure("sev_high", background="#3f0d13", foreground="#fca5a5")
        self.event_tree.tag_configure("sev_critical", background="#4c0519", foreground="#fecdd3")

        self.event_tree.bind("<<TreeviewSelect>>", self.on_event_tree_select)
        self.event_tree.bind("<Double-1>", self.open_selected_event_ip_drilldown)

        detail_label = tk.Label(frame, text="Selected Evidence", font=self.font_heading, fg=self.colors["text"], bg=self.colors["panel"], anchor="w")
        detail_label.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 8))
        notes_label = tk.Label(frame, text="Case Notes", font=self.font_heading, fg=self.colors["text"], bg=self.colors["panel"], anchor="w")
        notes_label.grid(row=3, column=1, sticky="ew", padx=12, pady=(0, 8))

        detail_widget = scrolledtext.ScrolledText(frame, wrap="word", font=self.font_output, bg=self.colors["output_bg"], fg=self.colors["text"], insertbackground=self.colors["text"], relief="flat", bd=0, padx=12, pady=12, height=10)
        detail_widget.grid(row=5, column=0, sticky="nsew", padx=(12, 6), pady=(0, 12))

        notes_widget = scrolledtext.ScrolledText(frame, wrap="word", font=self.font_output, bg=self.colors["output_bg"], fg=self.colors["text"], insertbackground=self.colors["text"], relief="flat", bd=0, padx=12, pady=12, height=10)
        notes_widget.grid(row=5, column=1, sticky="nsew", padx=(6, 12), pady=(0, 12))

        notes_hint = tk.Label(frame, text="Analyst notes persist while the app is open and are included in filtered event exports.", font=self.font_body, fg=self.colors["muted"], bg=self.colors["panel"], anchor="w")
        notes_hint.grid(row=4, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 8))

        self.event_tree_rows = {}
        self.event_tree_sort_state = {}

        return {"frame": frame, "detail_widget": detail_widget, "notes_widget": notes_widget}

    def get_filtered_events(self, results, apply_filter=False):
        events = list(results.get("normalized_events", []))
        if not apply_filter:
            return events

        ip_filter = self.ip_filter_var.get().strip()
        finding_type = self.finding_type_var.get()
        severity_filter = self.severity_filter_var.get()
        source_filter = self.source_file_filter_var.get()

        filtered = []
        for event in events:
            source_ip = event.get("source_ip", "Unknown")
            category = event.get("event_category", "unknown")
            event_type = event.get("event_type", "unknown")
            severity = event.get("severity", "low")
            source_file = event.get("source_file", "Unknown")
            raw_log = event.get("raw_log", "")

            if ip_filter and ip_filter not in source_ip and ip_filter not in raw_log:
                continue
            if finding_type == "Authentication" and category != "authentication":
                continue
            if finding_type == "Burst Detections" and event_type != "burst_detection":
                continue
            if finding_type == "Service-Flood" and category != "availability":
                continue
            if severity_filter != "All Severities" and severity.lower() != severity_filter.lower():
                continue
            if source_filter != "All Sources" and source_file != source_filter:
                continue
            filtered.append(event)
        return filtered

    def refresh_source_file_filter_options(self, results=None):
        files = ["All Sources"]
        source_names = sorted({event.get("source_file", "Unknown") for event in (results or {}).get("normalized_events", [])})
        files.extend(source_names)
        self.source_file_filter_combo["values"] = files
        current = self.source_file_filter_var.get().strip() or "All Sources"
        if current not in files:
            self.source_file_filter_var.set("All Sources")

    def populate_event_explorer(self, results, apply_filter=False):
        for item in self.event_tree.get_children():
            self.event_tree.delete(item)
        self.event_tree_rows = {}
        self.clear_text_widget(self.event_explorer_tab["detail_widget"])
        events = self.get_filtered_events(results, apply_filter=apply_filter)
        self.refresh_source_file_filter_options(results)

        if not events:
            self.event_explorer_tab["detail_widget"].insert("1.0", "No events matched the current filters.")
            return

        severity_tag_map = {
            "low": "sev_low",
            "medium": "sev_medium",
            "high": "sev_high",
            "critical": "sev_critical",
        }

        for index, event in enumerate(events):
            item_id = f"event_{index}"
            values = (
                event.get("timestamp", "Unknown"),
                event.get("severity", "low").upper(),
                event.get("source_ip", "Unknown"),
                event.get("event_category", "unknown"),
                event.get("event_type", "unknown"),
                event.get("source_file", "Unknown"),
            )
            sev_tag = severity_tag_map.get(event.get("severity", "low").lower(), "sev_low")
            self.event_tree.insert("", "end", iid=item_id, values=values, tags=(sev_tag,))
            self.event_tree_rows[item_id] = event

        children = self.event_tree.get_children()
        if children:
            self.event_tree.selection_set(children[0])
            self.event_tree.focus(children[0])
            self.on_event_tree_select(None)

    def on_event_tree_select(self, event):
        selected = self.event_tree.selection()
        if not selected:
            return
        event_data = self.event_tree_rows.get(selected[0])
        if not event_data:
            return
        detail_widget = self.event_explorer_tab["detail_widget"]
        self.clear_text_widget(detail_widget)
        lines = [
            "Event Details",
            "=" * 72,
            f"Timestamp: {event_data.get('timestamp', 'Unknown')}",
            f"Severity: {event_data.get('severity', 'low').upper()}",
            f"Source IP: {event_data.get('source_ip', 'Unknown')}",
            f"Category: {event_data.get('event_category', 'unknown')}",
            f"Event Type: {event_data.get('event_type', 'unknown')}",
            f"Source Profile: {event_data.get('source_profile', 'Unknown')}",
            f"Source File: {event_data.get('source_file', 'Unknown')}",
            "",
            "Detection Reason",
            "-" * 72,
            event_data.get('detection_reason', ''),
            "",
            "Raw Evidence",
            "-" * 72,
            event_data.get('raw_log', ''),
        ]
        detail_widget.insert("1.0", "\n".join(lines))

    def open_selected_event_ip_drilldown(self, event):
        selected = self.event_tree.selection()
        if not selected or not self.last_results:
            return
        event_data = self.event_tree_rows.get(selected[0])
        if not event_data:
            return
        source_ip = event_data.get("source_ip", "Unknown")
        if not source_ip or source_ip == "Unknown":
            return
        self.selected_ip_var.set(source_ip)
        self.populate_ip_tab(self.last_results)
        self.notebook.select(self.ip_tab["frame"])
        self.status_label.config(text=f"Opened IP drill-down for {source_ip}")

    def copy_selected_raw_evidence(self):
        selected = self.event_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Select an event first.")
            return
        event_data = self.event_tree_rows.get(selected[0])
        raw = event_data.get("raw_log", "") if event_data else ""
        if not raw:
            messagebox.showwarning("No Evidence", "The selected event does not contain raw evidence.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(raw)
        self.status_label.config(text="Copied raw evidence to clipboard")

    def export_filtered_events_csv(self):
        if not self.last_results:
            messagebox.showwarning("No Data", "Run an analysis first.")
            return
        events = self.get_filtered_events(self.last_results, apply_filter=True)
        if not events:
            messagebox.showwarning("No Events", "No filtered events are available to export.")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")], title="Save Filtered Events CSV")
        if not save_path:
            return
        try:
            with open(save_path, "w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=["timestamp", "severity", "source_ip", "event_category", "event_type", "source_profile", "source_file", "detection_reason", "raw_log", "analyst_notes"])
                writer.writeheader()
                notes = self.event_explorer_tab["notes_widget"].get("1.0", tk.END).strip()
                for event in events:
                    row = dict(event)
                    row["analyst_notes"] = notes
                    writer.writerow(row)
            self.status_label.config(text=f"Exported {len(events)} filtered events")
            messagebox.showinfo("Success", "Filtered events exported successfully.")
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to export filtered events: {exc}")

    def export_selected_event_json(self):
        selected = self.event_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Select an event first.")
            return
        event_data = self.event_tree_rows.get(selected[0])
        if not event_data:
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")], title="Save Selected Event JSON")
        if not save_path:
            return
        try:
            payload = dict(event_data)
            payload["analyst_notes"] = self.event_explorer_tab["notes_widget"].get("1.0", tk.END).strip()
            with open(save_path, "w", encoding="utf-8") as file:
                json.dump(payload, file, indent=2)
            self.status_label.config(text="Selected event exported")
            messagebox.showinfo("Success", "Selected event exported successfully.")
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to export selected event: {exc}")

    def sort_event_tree(self, column):
        items = [(self.event_tree.set(item, column), item) for item in self.event_tree.get_children("")]
        reverse = self.event_tree_sort_state.get(column, False)
        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

        def sort_key(entry):
            value = entry[0]
            if column == "severity":
                return severity_rank.get(value.upper(), 0)
            return value.lower() if isinstance(value, str) else value

        items.sort(key=sort_key, reverse=reverse)
        for index, (_, item) in enumerate(items):
            self.event_tree.move(item, "", index)
        self.event_tree_sort_state[column] = not reverse

    def add_source_row(self, path, profile):
        normalized_path = os.path.abspath(path)
        if not os.path.isfile(normalized_path):
            messagebox.showerror("Invalid File", f"Could not find file:\n{normalized_path}")
            return

        for source in self.loaded_sources:
            if os.path.abspath(source["path"]) == normalized_path:
                messagebox.showwarning("Duplicate Source", "That file is already loaded as a source.")
                return

        source = {"path": normalized_path, "profile": profile}
        self.loaded_sources.append(source)
        self.refresh_sources_tree()
        self.status_label.config(text=f"Added source: {os.path.basename(normalized_path)}")

    def refresh_sources_tree(self):
        for item in self.sources_tree.get_children():
            self.sources_tree.delete(item)

        for source in self.loaded_sources:
            self.sources_tree.insert(
                "",
                "end",
                values=(os.path.basename(source["path"]), source["profile"])
            )

    def add_source_file(self):
        selected_file = filedialog.askopenfilename(
            title="Select a log source",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if selected_file:
            self.add_source_row(selected_file, self.new_source_profile_var.get())

    def remove_selected_source(self):
        selected = self.sources_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Select a source to remove.")
            return

        index = self.sources_tree.index(selected[0])
        if 0 <= index < len(self.loaded_sources):
            removed = self.loaded_sources.pop(index)
            self.refresh_sources_tree()
            self.status_label.config(text=f"Removed source: {os.path.basename(removed['path'])}")

    def clear_sources(self):
        self.loaded_sources = []
        self.refresh_sources_tree()
        self.status_label.config(text="Cleared loaded sources")

    def insert_line_with_tag(self, widget, line):
        lower_line = line.lower()
        tag = None

        if "service-flood" in lower_line or "ddos" in lower_line:
            tag = "ddos"
        elif "alert:" in lower_line:
            tag = "alert"
        elif "warning:" in lower_line or "rapid burst" in lower_line:
            tag = "warning"
        elif "successful" in lower_line:
            tag = "success"
        elif (
            "summary:" in lower_line
            or "failed login attempts by ip:" in lower_line
            or "suspicious ips flagged by threshold:" in lower_line
            or "rapid burst detections:" in lower_line
            or "top service-flood source ips:" in lower_line
            or "sample service-flood log lines:" in lower_line
            or "supported log handling:" in lower_line
            or "log analysis report" in lower_line
            or "authentication findings" in lower_line
            or "burst findings" in lower_line
            or "service-flood findings" in lower_line
            or "timeline" in lower_line
            or "ip drill-down" in lower_line
            or "case summary" in lower_line
            or "raw summary" in lower_line
            or "source profile" in lower_line
            or "loaded sources" in lower_line
        ):
            tag = "heading"

        if tag:
            widget.insert(tk.END, line + "\n", tag)
        else:
            widget.insert(tk.END, line + "\n")

    def insert_timeline_line(self, widget, line, severity):
        tag = severity.lower() if severity else None
        if tag in ["low", "medium", "high", "critical"]:
            widget.insert(tk.END, line + "\n", tag)
        else:
            widget.insert(tk.END, line + "\n")

    def clear_text_widget(self, widget):
        widget.delete("1.0", tk.END)

    def matches_ip_filter(self, line, ip_filter):
        if not ip_filter:
            return True
        return ip_filter in line

    def build_risk_reason(self, results, auth_abuse_bool, burst_bool, ddos_bool, risk_level):
        if "error" in results:
            return "Why: Analysis failed, so no risk explanation is available."

        reasons = []
        profile_used = results.get("source_profile_used", "Unknown")
        reasons.append(f"source handling mode was {profile_used}")

        loaded_sources = results.get("loaded_sources", [])
        if loaded_sources:
            reasons.append(f"{len(loaded_sources)} source(s) were correlated")

        if ddos_bool:
            ddos_total = sum(results["ddos_event_counts"].values())
            reasons.append(f"service-flood indicators were detected ({ddos_total} matching events)")

        if auth_abuse_bool:
            reasons.append(f"suspicious authentication abuse was detected from {len(results['suspicious_ips'])} IP(s)")

        if burst_bool:
            reasons.append(f"rapid burst activity was detected from {len(results['time_based_attacks'])} IP(s)")

        joined = " and ".join(reasons)
        return f"Why: risk is {risk_level.lower()} because {joined}."

    def update_incident_banner(self, results):
        timestamp_text = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")
        self.banner_time_label.config(text=f"Report Time: {timestamp_text}")

        if "error" in results:
            risk_level = "Error"
            auth_abuse = "No"
            burst_detected = "No"
            ddos_detected = "No"
            banner_color = self.colors["banner_error"]
            reason_text = "Why: Analysis failed, so no risk explanation is available."
        else:
            auth_abuse_bool = len(results["suspicious_ips"]) > 0
            burst_bool = len(results["time_based_attacks"]) > 0
            ddos_bool = results.get("ddos_detected", False)

            auth_abuse = "Yes" if auth_abuse_bool else "No"
            burst_detected = "Yes" if burst_bool else "No"
            ddos_detected = "Yes" if ddos_bool else "No"

            if ddos_bool or (auth_abuse_bool and burst_bool):
                risk_level = "High"
                banner_color = self.colors["banner_high"]
            elif auth_abuse_bool or burst_bool:
                risk_level = "Medium"
                banner_color = self.colors["banner_medium"]
            else:
                risk_level = "Low"
                banner_color = self.colors["banner_low"]

            reason_text = self.build_risk_reason(results, auth_abuse_bool, burst_bool, ddos_bool, risk_level)

        self.banner_section.config(bg=banner_color)
        for widget in self.banner_section.winfo_children():
            widget.config(bg=banner_color)
            for child in widget.winfo_children():
                if isinstance(child, tk.Label):
                    child.config(bg=banner_color)

        self.risk_card.value_label.config(text=risk_level)
        self.auth_banner_card.value_label.config(text=auth_abuse)
        self.burst_banner_card.value_label.config(text=burst_detected)
        self.ddos_banner_card.value_label.config(text=ddos_detected)
        self.banner_reason_label.config(text=reason_text, bg=banner_color)

    def browse_file(self):
        selected_file = filedialog.askopenfilename(
            title="Select a single log file",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if selected_file:
            self.file_path = selected_file
            self.file_label.config(text=os.path.basename(selected_file))
            self.status_label.config(text="Single file selected")

    def handle_drag_enter(self, event):
        self.drop_zone.config(bg="#172554", fg="white")
        return event.action

    def handle_drag_leave(self, event):
        self.drop_zone.config(bg=self.colors["input_bg"], fg=self.colors["muted"])
        return event.action

    def handle_drop(self, event):
        raw_data = event.data.strip()

        if raw_data.startswith("{") and raw_data.endswith("}"):
            raw_data = raw_data[1:-1]

        path = raw_data.strip('"')

        if not os.path.isfile(path):
            messagebox.showerror("Invalid File", "The dropped item is not a valid file.")
            self.drop_zone.config(bg=self.colors["input_bg"], fg=self.colors["muted"])
            return

        if not path.lower().endswith((".txt", ".log")):
            messagebox.showerror("Invalid File Type", "Please drop a .txt or .log file.")
            self.drop_zone.config(bg=self.colors["input_bg"], fg=self.colors["muted"])
            return

        self.add_source_row(path, self.new_source_profile_var.get())
        self.drop_zone.config(bg=self.colors["input_bg"], fg=self.colors["text"])

    def load_sample_log(self):
        sample_path = resolve_bundled_path("sample_log.txt")
        if os.path.exists(sample_path):
            self.file_path = sample_path
            self.file_label.config(text=os.path.basename(sample_path))
            self.status_label.config(text="Sample log loaded as single file")
        else:
            messagebox.showerror("Missing File", "Could not find sample_log.txt in the app folder.")

    def generate_sample_attack(self):
        if write_sample_log is None:
            messagebox.showerror("Missing Generator", "generate_sample_log.py is not in this folder, so sample generation is unavailable.")
            self.status_label.config(text="Sample generation unavailable")
            return
        try:
            output_path = os.path.join(get_writable_output_dir(), "sample_log.txt")
            path, count = write_sample_log(output_path)
            self.file_path = path
            self.file_label.config(text=os.path.basename(path))
            self.status_label.config(text=f"Generated sample attack log ({count} lines)")
            messagebox.showinfo("Sample Generated", f"Created sample_log.txt with {count} lines of mixed attack and normal activity.")
        except Exception as exc:
            messagebox.showerror("Generation Error", f"Could not generate sample log: {exc}")

    def get_detection_settings(self):
        try:
            failed_login_threshold = int(self.threshold_var.get().strip())
            time_window_seconds = int(self.time_window_var.get().strip())
            burst_threshold = int(self.burst_threshold_var.get().strip())
        except ValueError:
            messagebox.showerror("Invalid Settings", "Detection settings must be whole numbers.")
            return None
        if failed_login_threshold < 1 or time_window_seconds < 1 or burst_threshold < 1:
            messagebox.showerror("Invalid Settings", "Detection settings must all be greater than 0.")
            return None
        return failed_login_threshold, time_window_seconds, burst_threshold

    def update_stats(self, results):
        if "error" in results:
            self.total_lines_card.value_label.config(text="0")
            self.success_card.value_label.config(text="0")
            self.failed_card.value_label.config(text="0")
            self.alert_card.value_label.config(text="0")
            self.ddos_card.value_label.config(text="0")
            return

        self.total_lines_card.value_label.config(text=str(results["total_lines"]))
        self.success_card.value_label.config(text=str(results["successful_logins"]))
        self.failed_card.value_label.config(text=str(results["failed_attempts"]))
        suspicious_total = len(set(results["suspicious_ips"]) | set(results["time_based_attacks"]))
        self.alert_card.value_label.config(text=str(suspicious_total))
        self.ddos_card.value_label.config(text=str(sum(results["ddos_event_counts"].values())))

    def use_ip_filter_for_drilldown(self):
        ip_from_filter = self.ip_filter_var.get().strip()
        if not ip_from_filter:
            messagebox.showwarning("No IP", "Enter an IP in the filter field first.")
            return

        self.selected_ip_var.set(ip_from_filter)

        if self.last_results and self.last_report:
            self.populate_ip_tab(self.last_results)
            self.notebook.select(self.ip_tab["frame"])
            self.status_label.config(text=f"Drill-down loaded for {ip_from_filter}")

    def apply_filters(self):
        if not self.last_results or not self.last_report:
            messagebox.showwarning("No Data", "Run an analysis first.")
            return

        self.populate_tabs(self.last_results, self.last_report, apply_filter=True)
        self.status_label.config(text="Filters applied")

    def reset_filters(self):
        self.ip_filter_var.set("")
        self.finding_type_var.set("All Findings")
        self.severity_filter_var.set("All Severities")
        self.source_file_filter_var.set("All Sources")

        if self.last_results and self.last_report:
            self.populate_tabs(self.last_results, self.last_report, apply_filter=False)
            self.status_label.config(text="Filters reset")

    def populate_auth_tab(self, results, apply_filter=False):
        widget = self.auth_tab["widget"]
        self.clear_text_widget(widget)

        ip_filter = self.ip_filter_var.get().strip() if apply_filter else ""
        finding_type = self.finding_type_var.get() if apply_filter else "All Findings"

        if finding_type not in ["All Findings", "Authentication"]:
            self.insert_line_with_tag(widget, "Authentication findings are hidden by the current finding-type filter.")
            return

        lines = [
            "Authentication Findings",
            "=" * 60,
            f"Source Profile Used: {results.get('source_profile_used', 'Unknown')}",
            f"Successful logins: {results['successful_logins']}",
            f"Failed login attempts: {results['failed_attempts']}",
            f"Threshold for suspicious IPs: {results['failed_login_threshold']}",
            ""
        ]

        loaded_sources = results.get("loaded_sources", [])
        if loaded_sources:
            lines.append("Loaded Sources:")
            for source in loaded_sources:
                lines.append(
                    f"  {source['source_file']} | requested={source['source_profile_requested']} | "
                    f"used={source['source_profile_used']}"
                )
            lines.append("")

        if results["failed_ips"]:
            lines.append("Failed login attempts by IP:")
            sorted_failed_ips = sorted(results["failed_ips"].items(), key=lambda item: item[1], reverse=True)
            found_any = False
            for ip, count in sorted_failed_ips:
                line = f"  {ip}: {count}"
                if self.matches_ip_filter(line, ip_filter):
                    lines.append(line)
                    found_any = True
            if not found_any and ip_filter:
                lines.append("  No authentication entries matched the IP filter.")
            lines.append("")
        else:
            lines.append("No failed login attempts found.")
            lines.append("")

        if results["suspicious_ips"]:
            lines.append("Suspicious IPs flagged by threshold:")
            sorted_suspicious_ips = sorted(results["suspicious_ips"].items(), key=lambda item: item[1], reverse=True)
            found_any = False
            for ip, count in sorted_suspicious_ips:
                line = f"  ALERT: {ip} had {count} failed login attempts"
                if self.matches_ip_filter(line, ip_filter):
                    lines.append(line)
                    found_any = True
            if not found_any and ip_filter:
                lines.append("  No suspicious authentication entries matched the IP filter.")
            lines.append("")
        else:
            lines.append("No suspicious IPs met the failed-login threshold.")
            lines.append("")

        lines.append(f"Matched failed-auth lines: {results.get('matched_failed_lines', 0)}")
        lines.append(f"Matched successful-auth lines: {results.get('matched_success_lines', 0)}")

        for line in lines:
            self.insert_line_with_tag(widget, line)

    def populate_burst_tab(self, results, apply_filter=False):
        widget = self.burst_tab["widget"]
        self.clear_text_widget(widget)

        ip_filter = self.ip_filter_var.get().strip() if apply_filter else ""
        finding_type = self.finding_type_var.get() if apply_filter else "All Findings"

        if finding_type not in ["All Findings", "Burst Detections"]:
            self.insert_line_with_tag(widget, "Burst findings are hidden by the current finding-type filter.")
            return

        lines = [
            "Burst Findings",
            "=" * 60,
            f"Source Profile Used: {results.get('source_profile_used', 'Unknown')}",
            f"Rule: {results['burst_threshold']} failures in {results['time_window_seconds']} seconds",
            ""
        ]

        if results["time_based_attacks"]:
            lines.append("Rapid burst detections:")
            sorted_bursts = sorted(results["time_based_attacks"].items(), key=lambda item: item[1], reverse=True)
            found_any = False
            for ip, count in sorted_bursts:
                line = f"  WARNING: {ip} triggered {count} failures within {results['time_window_seconds']} seconds"
                if self.matches_ip_filter(line, ip_filter):
                    lines.append(line)
                    found_any = True
            if not found_any and ip_filter:
                lines.append("  No burst detections matched the IP filter.")
        else:
            lines.append("No rapid burst attack patterns detected.")

        for line in lines:
            self.insert_line_with_tag(widget, line)

    def populate_ddos_tab(self, results, apply_filter=False):
        widget = self.ddos_tab["widget"]
        self.clear_text_widget(widget)

        ip_filter = self.ip_filter_var.get().strip() if apply_filter else ""
        finding_type = self.finding_type_var.get() if apply_filter else "All Findings"

        if finding_type not in ["All Findings", "Service-Flood"]:
            self.insert_line_with_tag(widget, "Service-flood findings are hidden by the current finding-type filter.")
            return

        lines = [
            "Service-Flood Findings",
            "=" * 60,
            f"Source Profile Used: {results.get('source_profile_used', 'Unknown')}",
        ]

        if results["ddos_detected"]:
            lines.append("Service-flood / DDoS indicators:")
            sorted_ddos_events = sorted(results["ddos_event_counts"].items(), key=lambda item: item[1], reverse=True)
            for event_name, count in sorted_ddos_events:
                friendly_name = event_name.replace("_", " ").title()
                lines.append(f"  ALERT: {friendly_name}: {count}")

            lines.append("")

            if results["ddos_source_ips"]:
                lines.append("Top service-flood source IPs:")
                sorted_ddos_ips = sorted(results["ddos_source_ips"].items(), key=lambda item: item[1], reverse=True)
                found_any = False
                for ip, count in sorted_ddos_ips[:20]:
                    line = f"  WARNING: {ip}: {count} matching service-flood events"
                    if self.matches_ip_filter(line, ip_filter):
                        lines.append(line)
                        found_any = True
                if not found_any and ip_filter:
                    lines.append("  No service-flood source IPs matched the IP filter.")

            lines.append("")

            if results["ddos_lines"]:
                lines.append("Sample service-flood log lines:")
                found_any = False
                for line in results["ddos_lines"]:
                    display_line = f"  {line}"
                    if self.matches_ip_filter(display_line, ip_filter):
                        lines.append(display_line)
                        found_any = True
                if not found_any and ip_filter:
                    lines.append("  No service-flood log lines matched the IP filter.")
        else:
            lines.append("No service-flood / DDoS indicators detected.")

        for line in lines:
            self.insert_line_with_tag(widget, line)

    def populate_timeline_tab(self, results, apply_filter=False):
        widget = self.timeline_tab["widget"]
        self.clear_text_widget(widget)
        events = self.get_filtered_events(results, apply_filter=apply_filter)

        lines = [
            "Timeline",
            "=" * 140,
            f"Source Profile Used: {results.get('source_profile_used', 'Unknown')}",
            "Timestamp            Severity   Source IP         Category         Event Type               Profile                  Source File                 Detection Reason",
            "-" * 140,
        ]

        if not events:
            for line in lines:
                self.insert_line_with_tag(widget, line)
            self.insert_line_with_tag(widget, "No timeline events matched the current filters.")
            return

        for event in events:
            line = (
                f"{event.get('timestamp', 'Unknown'):<20} "
                f"{event.get('severity', 'low').upper():<10} "
                f"{event.get('source_ip', 'Unknown'):<16} "
                f"{event.get('event_category', 'unknown'):<16} "
                f"{event.get('event_type', 'unknown'):<24} "
                f"{event.get('source_profile', 'Unknown'):<24} "
                f"{event.get('source_file', 'Unknown'):<26} "
                f"{event.get('detection_reason', '')}"
            )
            lines.append(line)

        for index, line in enumerate(lines):
            if index < 5:
                self.insert_line_with_tag(widget, line)
            else:
                sev = "low"
                if " CRITICAL " in f" {line} ":
                    sev = "critical"
                elif " HIGH " in f" {line} ":
                    sev = "high"
                elif " MEDIUM " in f" {line} ":
                    sev = "medium"
                self.insert_timeline_line(widget, line, sev)

    def populate_ip_tab(self, results):
        widget = self.ip_tab["widget"]
        self.clear_text_widget(widget)

        selected_ip = self.selected_ip_var.get().strip()

        lines = [
            "IP Drill-Down",
            "=" * 100,
            f"Source Profile Used: {results.get('source_profile_used', 'Unknown')}",
        ]

        if not selected_ip:
            lines.append("No IP selected. Enter an IP in the Selected IP field or use 'Use IP Filter for Drill-Down'.")
            for line in lines:
                self.insert_line_with_tag(widget, line)
            return

        events = [
            event for event in results.get("normalized_events", [])
            if event.get("source_ip") == selected_ip or selected_ip in event.get("raw_log", "")
        ]

        if not events:
            lines.append(f"No events found for IP: {selected_ip}")
            for line in lines:
                self.insert_line_with_tag(widget, line)
            return

        known_timestamps = [event["timestamp"] for event in events if event["timestamp"] != "Unknown"]
        first_seen = min(known_timestamps) if known_timestamps else "Unknown"
        last_seen = max(known_timestamps) if known_timestamps else "Unknown"

        auth_events = [e for e in events if e["event_category"] == "authentication" and e["event_type"] != "burst_detection"]
        burst_events = [e for e in events if e["event_type"] == "burst_detection"]
        ddos_events = [e for e in events if e["event_category"] == "availability"]

        severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        highest_severity = max(events, key=lambda e: severity_rank.get(e["severity"], 0))["severity"]

        source_files = sorted({event.get("source_file", "Unknown") for event in events})

        lines.extend([
            f"IP Address: {selected_ip}",
            f"First Seen: {first_seen}",
            f"Last Seen: {last_seen}",
            f"Total Related Events: {len(events)}",
            f"Authentication Events: {len(auth_events)}",
            f"Burst Detections: {len(burst_events)}",
            f"Service-Flood Events: {len(ddos_events)}",
            f"Highest Severity: {highest_severity.upper()}",
            f"Observed In Sources: {', '.join(source_files)}",
            "",
            "Related Events",
            "-" * 120
        ])

        for event in events:
            lines.append(
                f"{event['timestamp']} | {event['severity'].upper():<8} | "
                f"{event['event_category']:<14} | {event['event_type']:<22} | "
                f"{event.get('source_profile', 'Unknown'):<22} | "
                f"{event.get('source_file', 'Unknown'):<20} | "
                f"{event['detection_reason']}"
            )

        lines.append("")
        lines.append("Raw Evidence")
        lines.append("-" * 120)

        seen_raw = set()
        for event in events:
            raw = f"[{event.get('source_file', 'Unknown')}] {event['raw_log']}"
            if raw not in seen_raw:
                seen_raw.add(raw)
                lines.append(raw)

        for index, line in enumerate(lines):
            if index < 3 or line in ["Related Events", "Raw Evidence"] or line.startswith("-" * 20):
                self.insert_line_with_tag(widget, line)
            else:
                sev = None
                if "| LOW " in f" {line} ":
                    sev = "low"
                elif "| MEDIUM " in f" {line} ":
                    sev = "medium"
                elif "| HIGH " in f" {line} ":
                    sev = "high"
                elif "| CRITICAL " in f" {line} ":
                    sev = "critical"

                if sev:
                    self.insert_timeline_line(widget, line, sev)
                else:
                    self.insert_line_with_tag(widget, line)

    def build_case_summary(self, results):
        events = results.get("normalized_events", [])
        suspicious_ips = results.get("suspicious_ips", {})
        burst_ips = results.get("time_based_attacks", {})
        ddos_ips = results.get("ddos_source_ips", {})
        ddos_detected = results.get("ddos_detected", False)

        known_times = [e["timestamp"] for e in events if e["timestamp"] != "Unknown"]
        start_time = min(known_times) if known_times else "Unknown"
        end_time = max(known_times) if known_times else "Unknown"

        auth_detected = len(suspicious_ips) > 0
        burst_detected = len(burst_ips) > 0

        if ddos_detected and auth_detected:
            incident_type = "Authentication Abuse with Service-Flood Activity"
        elif ddos_detected:
            incident_type = "Service-Flood / Availability Disruption"
        elif auth_detected or burst_detected:
            incident_type = "Authentication Abuse"
        else:
            incident_type = "Low-Signal or Benign Activity"

        if ddos_detected or (auth_detected and burst_detected):
            severity = "High"
        elif auth_detected or burst_detected:
            severity = "Medium"
        else:
            severity = "Low"

        combined_scores = {}
        for ip, count in suspicious_ips.items():
            combined_scores[ip] = combined_scores.get(ip, 0) + count
        for ip, count in burst_ips.items():
            combined_scores[ip] = combined_scores.get(ip, 0) + count
        for ip, count in ddos_ips.items():
            combined_scores[ip] = combined_scores.get(ip, 0) + count

        top_entities = sorted(combined_scores.items(), key=lambda x: x[1], reverse=True)[:5]

        evidence_lines = []
        seen = set()
        for event in events:
            if event["severity"] in ["high", "critical"]:
                raw = f"[{event.get('source_file', 'Unknown')}] {event['raw_log']}"
                if raw not in seen:
                    seen.add(raw)
                    evidence_lines.append(raw)
            if len(evidence_lines) >= 6:
                break

        loaded_sources = results.get("loaded_sources", [])
        findings = [f"Loaded and correlated {len(loaded_sources)} source(s)."]
        for source in loaded_sources:
            findings.append(
                f"{source['source_file']} was parsed using requested profile "
                f"'{source['source_profile_requested']}' and effective profile '{source['source_profile_used']}'."
            )

        if auth_detected:
            findings.append(f"Repeated suspicious authentication activity was detected from {len(suspicious_ips)} IP(s).")
        if burst_detected:
            findings.append(f"Rapid auth burst behavior was detected from {len(burst_ips)} IP(s).")
        if ddos_detected:
            findings.append(
                f"Service-flood indicators were detected across {len(results.get('ddos_event_counts', {}))} event type(s)."
            )
        if len(findings) == len(loaded_sources) + 1:
            findings.append("No strong malicious pattern met current thresholds.")

        next_steps = []
        next_steps.append("Validate whether all loaded sources belong to the same incident window and affected environment.")
        if auth_detected:
            next_steps.append("Review suspicious authentication sources and confirm whether exposed services should be restricted or blocked.")
        if burst_detected:
            next_steps.append("Investigate burst-pattern IPs for brute-force behavior and consider temporary blocking or rate limiting.")
        if ddos_detected:
            next_steps.append("Confirm whether mitigation controls reduced impact and whether upstream protections should be tightened.")
        next_steps.append("Preserve source-attributed evidence for handoff or escalation.")
        next_steps.append("Tune parser profiles per source if any loaded file appears misclassified or under-parsed.")

        return {
            "incident_type": incident_type,
            "severity": severity,
            "time_range": f"{start_time} to {end_time}",
            "top_entities": top_entities,
            "findings": findings,
            "evidence_lines": evidence_lines,
            "next_steps": next_steps,
        }

    def populate_case_tab(self, results):
        widget = self.case_tab["widget"]
        self.clear_text_widget(widget)
        case = self.build_case_summary(results)
        analyst_notes = ""
        if hasattr(self, "event_explorer_tab"):
            analyst_notes = self.event_explorer_tab["notes_widget"].get("1.0", tk.END).strip()

        lines = [
            "Case Summary",
            "=" * 100,
            f"Incident Type: {case['incident_type']}",
            f"Severity: {case['severity']}",
            f"Time Range: {case['time_range']}",
            "",
            "Primary Suspected IPs",
            "-" * 100,
        ]

        if case["top_entities"]:
            for ip, score in case["top_entities"]:
                lines.append(f"{ip} | combined activity score: {score}")
        else:
            lines.append("No strong suspected IPs identified.")

        lines.extend(["", "Key Findings", "-" * 100])
        for finding in case["findings"]:
            lines.append(f"- {finding}")

        lines.extend(["", "Evidence Highlights", "-" * 100])
        if case["evidence_lines"]:
            for line in case["evidence_lines"]:
                lines.append(line)
        else:
            lines.append("No high-severity evidence lines were selected.")

        lines.extend(["", "Recommended Next Steps", "-" * 100])
        for step in case["next_steps"]:
            lines.append(f"- {step}")

        lines.extend(["", "Analyst Notes", "-" * 100])
        lines.append(analyst_notes if analyst_notes else "No analyst notes recorded yet.")

        for line in lines:
            self.insert_line_with_tag(widget, line)

    def populate_summary_tab(self, report_text, apply_filter=False):
        widget = self.summary_tab["widget"]
        self.clear_text_widget(widget)

        ip_filter = self.ip_filter_var.get().strip() if apply_filter else ""
        finding_type = self.finding_type_var.get() if apply_filter else "All Findings"

        lines = report_text.splitlines()

        for line in lines:
            if finding_type == "Authentication":
                allowed = (
                    "auth" in line.lower()
                    or "failed login" in line.lower()
                    or "successful login" in line.lower()
                    or "suspicious ip" in line.lower()
                    or "matched failed-auth" in line.lower()
                    or "matched successful-auth" in line.lower()
                )
                if not allowed:
                    continue
            elif finding_type == "Burst Detections":
                allowed = "burst" in line.lower() or "warning:" in line.lower()
                if not allowed:
                    continue
            elif finding_type == "Service-Flood":
                allowed = (
                    "service-flood" in line.lower()
                    or "ddos" in line.lower()
                    or "503" in line.lower()
                    or "proxy timeout" in line.lower()
                    or "connection spike" in line.lower()
                )
                if not allowed:
                    continue

            if ip_filter and ip_filter not in line and not any(
                keyword in line.lower()
                for keyword in ["summary:", "log analysis report", "supported log handling:", "loaded sources"]
            ):
                continue

            self.insert_line_with_tag(widget, line)

    def populate_tabs(self, results, report_text, apply_filter=False):
        self.refresh_source_file_filter_options(results)
        self.populate_auth_tab(results, apply_filter=apply_filter)
        self.populate_burst_tab(results, apply_filter=apply_filter)
        self.populate_ddos_tab(results, apply_filter=apply_filter)
        self.populate_event_explorer(results, apply_filter=apply_filter)
        self.populate_timeline_tab(results, apply_filter=apply_filter)
        self.populate_ip_tab(results)
        self.populate_case_tab(results)
        self.populate_summary_tab(report_text, apply_filter=apply_filter)

    def run_analysis(self):
        if not self.file_path:
            messagebox.showwarning("No File", "Please select a single file first.")
            return

        settings = self.get_detection_settings()
        if settings is None:
            return

        failed_login_threshold, time_window_seconds, burst_threshold = settings
        source_profile = self.source_profile_var.get()

        results = analyze_log(
            self.file_path,
            failed_login_threshold=failed_login_threshold,
            time_window_seconds=time_window_seconds,
            burst_threshold=burst_threshold,
            source_profile=source_profile
        )
        report_text = generate_report_string(results)

        self.last_results = results
        self.last_report = report_text
        self.update_stats(results)
        self.update_incident_banner(results)
        self.populate_tabs(results, report_text, apply_filter=False)

        if "error" in results:
            self.status_label.config(text="Single-file analysis failed")
        else:
            self.status_label.config(text=f"Single-file analysis complete ({results.get('source_profile_used', 'Unknown')})")

    def run_multi_analysis(self):
        if not self.loaded_sources:
            messagebox.showwarning("No Sources", "Add one or more log sources first.")
            return

        settings = self.get_detection_settings()
        if settings is None:
            return

        failed_login_threshold, time_window_seconds, burst_threshold = settings

        results = analyze_multiple_logs(
            log_sources=self.loaded_sources,
            failed_login_threshold=failed_login_threshold,
            time_window_seconds=time_window_seconds,
            burst_threshold=burst_threshold,
        )
        report_text = generate_report_string(results)

        self.last_results = results
        self.last_report = report_text
        self.update_stats(results)
        self.update_incident_banner(results)
        self.populate_tabs(results, report_text, apply_filter=False)

        if "error" in results:
            self.status_label.config(text="Multi-source analysis failed")
        else:
            self.status_label.config(text=f"Multi-source analysis complete ({len(self.loaded_sources)} sources)")

    def export_report(self):
        if not self.last_report:
            messagebox.showwarning("No Data", "Run an analysis first.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt")],
            title="Save TXT Report"
        )

        if save_path:
            try:
                with open(save_path, "w", encoding="utf-8") as file:
                    file.write(self.last_report)
                messagebox.showinfo("Success", "TXT report exported successfully.")
                self.status_label.config(text="TXT report exported")
            except Exception as exc:
                messagebox.showerror("Error", f"Failed to save TXT file: {exc}")

    def export_json(self):
        if not self.last_results:
            messagebox.showwarning("No Data", "Run an analysis first.")
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")], title="Save JSON Report")
        if save_path:
            try:
                payload = dict(self.last_results)
                payload["filtered_events"] = self.get_filtered_events(self.last_results, apply_filter=True)
                payload["analyst_notes"] = self.event_explorer_tab["notes_widget"].get("1.0", tk.END).strip() if hasattr(self, "event_explorer_tab") else ""
                with open(save_path, "w", encoding="utf-8") as file:
                    json.dump(payload, file, indent=2, default=str)
                messagebox.showinfo("Success", "JSON report exported successfully.")
                self.status_label.config(text="JSON report exported")
            except Exception as exc:
                messagebox.showerror("Error", f"Failed to save JSON file: {exc}")

    def export_csv(self):
        if not self.last_results:
            messagebox.showwarning("No Data", "Run an analysis first.")
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")], title="Save CSV Report")
        if save_path:
            try:
                filtered_events = self.get_filtered_events(self.last_results, apply_filter=True)
                with open(save_path, "w", newline="", encoding="utf-8") as file:
                    writer = csv.writer(file)
                    writer.writerow(["section", "item", "value"])
                    writer.writerow(["summary", "source_profile_used", self.last_results.get("source_profile_used", "Unknown")])
                    writer.writerow(["summary", "total_lines", self.last_results.get("total_lines", 0)])
                    writer.writerow(["summary", "successful_logins", self.last_results.get("successful_logins", 0)])
                    writer.writerow(["summary", "failed_attempts", self.last_results.get("failed_attempts", 0)])
                    writer.writerow(["summary", "filtered_event_count", len(filtered_events)])
                    writer.writerow(["summary", "analyst_notes", self.event_explorer_tab["notes_widget"].get("1.0", tk.END).strip() if hasattr(self, "event_explorer_tab") else ""])
                    for event in filtered_events:
                        writer.writerow(["filtered_events", event.get("event_type", ""), json.dumps(event)])
                messagebox.showinfo("Success", "CSV report exported successfully.")
                self.status_label.config(text="CSV report exported")
            except Exception as exc:
                messagebox.showerror("Error", f"Failed to save CSV file: {exc}")

    def clear_all(self):
        self.file_path = ""
        self.last_report = ""
        self.last_results = None
        self.loaded_sources = []

        self.file_label.config(text="No single file selected")
        self.drop_zone.config(text="Drag and drop a .txt or .log file here to add it as a source" if DND_AVAILABLE else "Drag and drop requires: pip install tkinterdnd2", fg=self.colors["muted"], bg=self.colors["input_bg"])

        self.threshold_var.set("3")
        self.time_window_var.set("30")
        self.burst_threshold_var.set("3")
        self.source_profile_var.set("Auto Detect")
        self.new_source_profile_var.set("Auto Detect")
        self.ip_filter_var.set("")
        self.finding_type_var.set("All Findings")
        self.severity_filter_var.set("All Severities")
        self.source_file_filter_var.set("All Sources")
        self.selected_ip_var.set("")

        self.refresh_sources_tree()
        self.total_lines_card.value_label.config(text="0")
        self.success_card.value_label.config(text="0")
        self.failed_card.value_label.config(text="0")
        self.alert_card.value_label.config(text="0")
        self.ddos_card.value_label.config(text="0")

        self.banner_time_label.config(text="Report Time: Not analyzed yet")
        self.risk_card.value_label.config(text="Low")
        self.auth_banner_card.value_label.config(text="No")
        self.burst_banner_card.value_label.config(text="No")
        self.ddos_banner_card.value_label.config(text="No")
        self.banner_reason_label.config(text="Why: No analysis has been run yet.")
        self.banner_section.config(bg=self.colors["banner_low"])
        for widget in self.banner_section.winfo_children():
            widget.config(bg=self.colors["banner_low"])
            for child in widget.winfo_children():
                if isinstance(child, tk.Label):
                    child.config(bg=self.colors["banner_low"])

        for tab in [self.auth_tab, self.burst_tab, self.ddos_tab, self.timeline_tab, self.ip_tab, self.case_tab, self.summary_tab]:
            self.clear_text_widget(tab["widget"])

        for item in self.event_tree.get_children():
            self.event_tree.delete(item)
        self.event_tree_rows = {}
        self.event_tree_sort_state = {}
        self.clear_text_widget(self.event_explorer_tab["detail_widget"])
        self.clear_text_widget(self.event_explorer_tab["notes_widget"])

        self.auth_tab["widget"].insert("1.0", "Authentication findings will appear here after analysis.")
        self.burst_tab["widget"].insert("1.0", "Burst detections will appear here after analysis.")
        self.ddos_tab["widget"].insert("1.0", "Service-flood findings will appear here after analysis.")
        self.event_explorer_tab["detail_widget"].insert("1.0", "Select an event to inspect its evidence and metadata.")
        self.timeline_tab["widget"].insert("1.0", "Normalized event timeline will appear here after analysis.")
        self.ip_tab["widget"].insert("1.0", "IP drill-down details will appear here after analysis.")
        self.case_tab["widget"].insert("1.0", "Incident case summary will appear here after analysis.")
        self.summary_tab["widget"].insert("1.0", "Raw report summary will appear here after analysis.")

        self.status_label.config(text="Cleared")

    def run(self):
        self.root.mainloop()


def create_root():
    if DND_AVAILABLE:
        return TkinterDnD.Tk()
    return tk.Tk()


if __name__ == "__main__":
    root = create_root()
    app = LogSentryApp(root)
    app.run()