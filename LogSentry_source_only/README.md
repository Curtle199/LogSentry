# LogSentry

**LogSentry** is a desktop SOC investigation workspace for analyzing authentication abuse, burst attack behavior, and service-flood / DDoS indicators across one or more log sources.

Built as a portfolio project, LogSentry focuses on practical analyst workflow: load logs quickly, review findings by category, map detections to MITRE ATT&CK, and export investigation-ready artifacts.

## Features

- **Multi-source log analysis**
  - Analyze a single file or multiple loaded sources in one workspace
  - Assign source profiles manually or use auto-detection

- **Authentication abuse detection**
  - Failed login counting
  - Suspicious IP thresholding
  - Burst activity detection inside a configurable time window

- **Service-flood / DDoS detection**
  - Detects common service-flood indicators from log patterns
  - Highlights high-volume source IPs and matching events

- **MITRE ATT&CK mapping**
  - Maps supported detections to ATT&CK techniques
  - Exports an ATT&CK Navigator-style layer JSON

- **Investigation workflow views**
  - Authentication findings
  - Burst detections
  - Service-flood findings
  - Timeline
  - IP drill-down
  - Case summary
  - Per-source results
  - Visual charts
  - Raw summary

- **Confidence + evidence scoring**
  - Adds confidence labels and “why flagged” reasoning
  - Improves analyst explainability during triage

- **Export options**
  - TXT report
  - JSON report
  - CSV report
  - ATT&CK layer export
  - One-click export package

## Why I Built It

LogSentry was built to show how a lightweight desktop tool can support real SOC-style triage without requiring a full SIEM deployment. The project focuses on:

- detection logic
- evidence presentation
- analyst usability
- exportability
- structured reporting

## Tech Stack

- **Python**
- **Tkinter** for the desktop GUI
- **CSV / JSON** export support
- **PyInstaller** spec for packaging
- Custom modules for:
  - ATT&CK mapping
  - confidence scoring
  - per-source breakdowns
  - visual summaries

## Project Highlights

- Hardened generator and sample-log workflow
- Improved packaged path handling
- Cleaner tabbed GUI layout
- ATT&CK integration as a separate logic layer
- Per-source analysis summaries
- Built-in visual charts without adding heavy plotting dependencies

## Running the Project

1. Clone or download the repository
2. Open the project folder
3. Run the GUI entry point

```bash
python gui.pyw
```

Debug entry point:

```bash
python gui_debug.py
```

## Packaging

The repository includes a `LogSentry.spec` file for packaging with PyInstaller.

## Example Workflow

1. Generate Sample Attack
2. Load Sample Log
3. Analyze Single File
4. Review findings
5. Export reports and ATT&CK layer

## Export Artifacts

LogSentry can generate:

- analyst-facing text reports
- structured JSON output
- CSV output
- ATT&CK Navigator layer JSON
- a timestamped export package folder

## Screenshots

Add screenshots here for the GitHub repo / LinkedIn post, for example:

- Main dashboard
  <img width="3839" height="2108" alt="image" src="https://github.com/user-attachments/assets/f2360768-041c-467a-8370-d9567aaefb74" />

- ATT&CK tab
  <img width="3833" height="2101" alt="image" src="https://github.com/user-attachments/assets/6479c44d-6ba4-4b8f-892d-eab804161244" />
  
- Per-source results tab
  <img width="3830" height="2093" alt="image" src="https://github.com/user-attachments/assets/3b7bdb09-24e6-47bd-9329-2c016094bc35" />
  
- Visuals tab
  <img width="3834" height="2107" alt="image" src="https://github.com/user-attachments/assets/744aaffb-bc4c-43ed-b009-98a97a245075" />
  
## Roadmap

Planned / possible next improvements:

- field-normalized export
- Sigma-style rule support
- richer case management notes
- release packaging improvements
- deeper SOC workflow integrations

## Author

Created as a cybersecurity / software portfolio project focused on SOC investigation workflow and desktop detection tooling.
