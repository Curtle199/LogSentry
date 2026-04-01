# LogSentry - Python Log Analyzer

LogSentry is a Python-based tool that analyzes authentication logs to detect suspicious activity.

## Features
- Detects failed login attempts
- Extracts IP addresses from logs
- Counts repeated login failures
- Flags suspicious IPs based on thresholds

## How It Works
The script scans log files and identifies patterns that may indicate brute-force attacks or unauthorized access attempts.

## How to Run
1. Download the project files
2. Make sure `sample_log.txt` is in the same directory
3. Run:

```bash
python analyzer.py
