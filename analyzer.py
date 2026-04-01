from collections import Counter
import re

FAILED_LOGIN_THRESHOLD = 3


def extract_ip(line):
    """Extract an IPv4 address from a log line."""
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
    return match.group() if match else None


def analyze_log(file_path):
    total_lines = 0
    failed_attempts = 0
    successful_logins = 0
    failed_ips = Counter()

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                total_lines += 1
                lower_line = line.lower()

                if "failed login attempt" in lower_line:
                    failed_attempts += 1
                    ip = extract_ip(line)
                    if ip:
                        failed_ips[ip] += 1

                elif "login successful" in lower_line:
                    successful_logins += 1

    except FileNotFoundError:
        return {"error": f"Could not find log file: {file_path}"}
    except Exception as exc:
        return {"error": f"Unexpected error: {exc}"}

    suspicious_ips = {
        ip: count
        for ip, count in failed_ips.items()
        if count >= FAILED_LOGIN_THRESHOLD
    }

    return {
        "total_lines": total_lines,
        "successful_logins": successful_logins,
        "failed_attempts": failed_attempts,
        "failed_ips": dict(failed_ips),
        "suspicious_ips": suspicious_ips,
    }


def print_report(results):
    if "error" in results:
        print(results["error"])
        return

    print("=" * 50)
    print("LOG ANALYSIS REPORT")
    print("=" * 50)
    print(f"Total log lines: {results['total_lines']}")
    print(f"Successful logins: {results['successful_logins']}")
    print(f"Failed login attempts: {results['failed_attempts']}")
    print()

    if results["failed_ips"]:
        print("Failed login attempts by IP:")
        for ip, count in results["failed_ips"].items():
            print(f"  {ip}: {count}")
        print()
    else:
        print("No failed login attempts found.\n")

    if results["suspicious_ips"]:
        print("Suspicious IPs flagged:")
        for ip, count in results["suspicious_ips"].items():
            print(f"  ALERT: {ip} had {count} failed login attempts")
    else:
        print("No suspicious IPs met the alert threshold.")

    print("=" * 50)


if __name__ == "__main__":
    report = analyze_log("sample_log.txt")
    print_report(report)
