import importlib.util
import os
import sys
import json
import csv
import traceback
from collections import Counter
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from datetime import datetime
from analyzer import analyze_log, analyze_multiple_logs, generate_report_string, SOURCE_PROFILES
from attack_mapper import build_attack_results, export_navigator_layer
from finding_scoring import build_finding_assessment, format_assessment_block
from per_source_results import build_per_source_results, format_per_source_block


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
        self.last_attack_results = None
        self.last_finding_assessment = None
        self.last_per_source_results = None
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

        self.top_frame = tk.Frame(self.main_frame, bg=self.colors["bg"])
        self.top_frame.pack(fill="x", side="top")

        self.bottom_frame = tk.Frame(self.main_frame, bg=self.colors["bg"])
        self.bottom_frame.pack(fill="both", expand=True, side="top")

        self.build_header()
        self.build_incident_banner()
        self.build_controls_notebook()
        self.build_stats_section()
        self.build_tabbed_output_section()

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
        controls_shell.pack(fill="x", pady=(0, 16))

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
        self.controls_notebook.pack(fill="x", padx=16, pady=(0, 16))

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

        self.controls_notebook.update_idletasks()
        requested_heights = [
            self.single_file_tab.winfo_reqheight(),
            self.sources_tab.winfo_reqheight(),
            self.actions_tab.winfo_reqheight(),
            self.detection_controls_tab.winfo_reqheight(),
            self.investigation_controls_tab.winfo_reqheight(),
        ]
        self.controls_notebook.configure(height=max(requested_heights) + 24)

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
        section.pack(fill="x", pady=(0, 16))

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

        table_frame = tk.Frame(section, bg=self.colors["panel"], height=190)
        table_frame.pack(fill="x", padx=16, pady=(0, 16))
        table_frame.pack_propagate(False)

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
            ("Export ATT&CK Layer", "#1d4ed8", "#1e40af", self.export_attack_layer),
            ("Export Package", "#7c2d12", "#9a3412", self.export_package),
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
        ).grid(row=0, column=0, columnspan=9, sticky="w", padx=16, pady=(14, 10))

        tk.Label(
            section,
            text="Filter by IP",
            font=self.font_body,
            fg=self.colors["muted"],
            bg=self.colors["panel"]
        ).grid(row=1, column=0, sticky="w", padx=(16, 8), pady=(0, 14))

        self.ip_filter_var = tk.StringVar()
        self.ip_filter_entry = tk.Entry(
            section,
            textvariable=self.ip_filter_var,
            font=self.font_body,
            bg=self.colors["input_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            bd=0,
            width=20
        )
        self.ip_filter_entry.grid(row=1, column=1, sticky="w", padx=(0, 16), pady=(0, 14))
        self.ip_filter_entry.configure(highlightthickness=1, highlightbackground=self.colors["border"])

        tk.Label(
            section,
            text="Finding Type",
            font=self.font_body,
            fg=self.colors["muted"],
            bg=self.colors["panel"]
        ).grid(row=1, column=2, sticky="w", padx=(16, 8), pady=(0, 14))

        self.finding_type_var = tk.StringVar(value="All Findings")
        self.finding_type_combo = ttk.Combobox(
            section,
            textvariable=self.finding_type_var,
            values=["All Findings", "Authentication", "Burst Detections", "Service-Flood"],
            state="readonly",
            width=18
        )
        self.finding_type_combo.grid(row=1, column=3, sticky="w", padx=(0, 16), pady=(0, 14))

        tk.Label(
            section,
            text="Selected IP",
            font=self.font_body,
            fg=self.colors["muted"],
            bg=self.colors["panel"]
        ).grid(row=1, column=4, sticky="w", padx=(16, 8), pady=(0, 14))

        self.selected_ip_var = tk.StringVar()
        self.selected_ip_entry = tk.Entry(
            section,
            textvariable=self.selected_ip_var,
            font=self.font_body,
            bg=self.colors["input_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            bd=0,
            width=20
        )
        self.selected_ip_entry.grid(row=1, column=5, sticky="w", padx=(0, 16), pady=(0, 14))
        self.selected_ip_entry.configure(highlightthickness=1, highlightbackground=self.colors["border"])

        apply_filter_button = tk.Button(
            section,
            text="Apply Filters",
            font=("Segoe UI", 10, "bold"),
            fg="white",
            bg=self.colors["accent"],
            activeforeground="white",
            activebackground=self.colors["accent_hover"],
            relief="flat",
            bd=0,
            padx=18,
            pady=10,
            cursor="hand2",
            command=self.apply_filters
        )
        apply_filter_button.grid(row=1, column=6, sticky="w", padx=(0, 10), pady=(0, 14))

        drilldown_button = tk.Button(
            section,
            text="Use IP Filter for Drill-Down",
            font=("Segoe UI", 10, "bold"),
            fg="white",
            bg="#7c2d12",
            activeforeground="white",
            activebackground="#9a3412",
            relief="flat",
            bd=0,
            padx=18,
            pady=10,
            cursor="hand2",
            command=self.use_ip_filter_for_drilldown
        )
        drilldown_button.grid(row=1, column=7, sticky="w", padx=(0, 10), pady=(0, 14))

        reset_filter_button = tk.Button(
            section,
            text="Reset Filters",
            font=("Segoe UI", 10, "bold"),
            fg="white",
            bg="#475569",
            activeforeground="white",
            activebackground="#334155",
            relief="flat",
            bd=0,
            padx=18,
            pady=10,
            cursor="hand2",
            command=self.reset_filters
        )
        reset_filter_button.grid(row=1, column=8, sticky="w", pady=(0, 14))

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

        tk.Label(
            top_row,
            text="Analysis Findings",
            font=self.font_heading,
            fg=self.colors["text"],
            bg=self.colors["panel"]
        ).pack(side="left")

        self.status_label = tk.Label(
            top_row,
            text="Ready",
            font=self.font_body,
            fg=self.colors["muted"],
            bg=self.colors["panel"]
        )
        self.status_label.pack(side="right")

        self.notebook = ttk.Notebook(section)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 16))

        self.auth_tab = self.create_tab()
        self.burst_tab = self.create_tab()
        self.ddos_tab = self.create_tab()
        self.timeline_tab = self.create_tab()
        self.ip_tab = self.create_tab()
        self.case_tab = self.create_tab()
        self.visuals_tab = self.create_visuals_tab()
        self.source_results_tab = self.create_tab()
        self.attack_tab = self.create_tab()
        self.summary_tab = self.create_tab()

        self.notebook.add(self.auth_tab["frame"], text="Authentication Findings")
        self.notebook.add(self.burst_tab["frame"], text="Burst Detections")
        self.notebook.add(self.ddos_tab["frame"], text="Service-Flood Findings")
        self.notebook.add(self.timeline_tab["frame"], text="Timeline")
        self.notebook.add(self.ip_tab["frame"], text="IP Drill-Down")
        self.notebook.add(self.case_tab["frame"], text="Case Summary")
        self.notebook.add(self.visuals_tab["frame"], text="Visuals")
        self.notebook.add(self.source_results_tab["frame"], text="Per-Source Results")
        self.notebook.add(self.attack_tab["frame"], text="MITRE ATT&CK")
        self.notebook.add(self.summary_tab["frame"], text="Raw Summary")

        self.auth_tab["widget"].insert("1.0", "Authentication findings will appear here after analysis.")
        self.burst_tab["widget"].insert("1.0", "Burst detections will appear here after analysis.")
        self.ddos_tab["widget"].insert("1.0", "Service-flood findings will appear here after analysis.")
        self.timeline_tab["widget"].insert("1.0", "Normalized event timeline will appear here after analysis.")
        self.ip_tab["widget"].insert("1.0", "IP drill-down details will appear here after analysis.")
        self.case_tab["widget"].insert("1.0", "Incident case summary will appear here after analysis.")
        self.clear_visuals_tab()
        self.source_results_tab["widget"].insert("1.0", "Per-source results will appear here after analysis.")
        self.attack_tab["widget"].insert("1.0", "MITRE ATT&CK mappings will appear here after analysis.")
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

    def create_visuals_tab(self):
        frame = tk.Frame(self.notebook, bg=self.colors["panel"])
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_rowconfigure(3, weight=1)

        auth_label = tk.Label(
            frame,
            text="Top Source IPs",
            font=("Segoe UI", 11, "bold"),
            bg=self.colors["panel"],
            fg=self.colors["text"]
        )
        auth_label.grid(row=0, column=0, sticky="w", padx=12, pady=(12, 6))

        auth_canvas = tk.Canvas(
            frame,
            bg=self.colors["output_bg"],
            highlightthickness=0,
            relief="flat",
            height=240
        )
        auth_canvas.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))

        timeline_label = tk.Label(
            frame,
            text="Event Timeline",
            font=("Segoe UI", 11, "bold"),
            bg=self.colors["panel"],
            fg=self.colors["text"]
        )
        timeline_label.grid(row=2, column=0, sticky="w", padx=12, pady=(0, 6))

        timeline_canvas = tk.Canvas(
            frame,
            bg=self.colors["output_bg"],
            highlightthickness=0,
            relief="flat",
            height=240
        )
        timeline_canvas.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0, 12))

        caption_label = tk.Label(
            frame,
            text="Charts will appear here after analysis.",
            font=("Segoe UI", 9),
            bg=self.colors["panel"],
            fg=self.colors["muted"]
        )
        caption_label.grid(row=4, column=0, sticky="w", padx=12, pady=(0, 12))

        return {
            "frame": frame,
            "auth_canvas": auth_canvas,
            "timeline_canvas": timeline_canvas,
            "caption_label": caption_label,
        }

    def clear_visuals_tab(self):
        if not hasattr(self, "visuals_tab"):
            return

        for canvas in [self.visuals_tab["auth_canvas"], self.visuals_tab["timeline_canvas"]]:
            canvas.delete("all")
            width = int(canvas.cget("width") or 900)
            height = int(canvas.cget("height") or 240)
            canvas.create_text(
                width / 2,
                height / 2,
                text="Run an analysis to generate charts.",
                fill=self.colors["muted"],
                font=("Segoe UI", 11, "italic")
            )

        self.visuals_tab["caption_label"].config(text="Charts will appear here after analysis.")

    def get_chart_dimensions(self, canvas):
        self.root.update_idletasks()
        width = canvas.winfo_width()
        height = canvas.winfo_height()
        if width <= 10:
            width = int(canvas.cget("width") or 900)
        if height <= 10:
            height = int(canvas.cget("height") or 240)
        return width, height

    def draw_bar_chart(self, canvas, title, data_points, empty_message):
        canvas.delete("all")
        width, height = self.get_chart_dimensions(canvas)

        if not data_points:
            canvas.create_text(
                width / 2,
                height / 2,
                text=empty_message,
                fill=self.colors["muted"],
                font=("Segoe UI", 11, "italic")
            )
            return

        left = 170
        right = width - 40
        top = 40
        bottom = height - 35
        max_value = max(value for _, value in data_points) or 1
        usable_height = bottom - top
        row_height = usable_height / max(len(data_points), 1)
        bar_height = max(16, row_height * 0.55)

        canvas.create_text(left, 18, text=title, anchor="w", fill=self.colors["text"], font=("Segoe UI", 11, "bold"))

        for index, (label, value) in enumerate(data_points):
            y = top + index * row_height + row_height / 2
            bar_end = left + ((right - left) * (value / max_value))
            canvas.create_text(left - 10, y, text=label, anchor="e", fill=self.colors["text"], font=("Segoe UI", 9))
            canvas.create_rectangle(left, y - bar_height / 2, bar_end, y + bar_height / 2, fill="#2563eb", outline="")
            canvas.create_text(bar_end + 8, y, text=str(value), anchor="w", fill=self.colors["muted"], font=("Segoe UI", 9))

    def build_top_ip_chart_data(self, results):
        suspicious_ips = results.get("suspicious_ips", {}) or {}
        failed_ips = results.get("failed_ips", {}) or {}
        ddos_source_ips = results.get("ddos_source_ips", {}) or {}

        if suspicious_ips:
            sorted_items = sorted(suspicious_ips.items(), key=lambda item: item[1], reverse=True)[:6]
            return "Suspicious Auth Source IPs", sorted_items

        if failed_ips:
            sorted_items = sorted(failed_ips.items(), key=lambda item: item[1], reverse=True)[:6]
            return "Failed Authentication Source IPs", sorted_items

        if ddos_source_ips:
            sorted_items = sorted(ddos_source_ips.items(), key=lambda item: item[1], reverse=True)[:6]
            return "Service-Flood Source IPs", sorted_items

        return "Top Source IPs", []

    def build_timeline_chart_data(self, results):
        buckets = Counter()
        for event in results.get("normalized_events", []) or []:
            timestamp = event.get("timestamp")
            if timestamp and timestamp != "Unknown":
                bucket = timestamp[:16]
                buckets[bucket] += 1

        if not buckets:
            return []

        sorted_items = sorted(buckets.items())
        if len(sorted_items) > 12:
            sorted_items = sorted_items[-12:]
        return sorted_items

    def populate_visuals_tab(self, results):
        title, auth_points = self.build_top_ip_chart_data(results)
        self.draw_bar_chart(
            self.visuals_tab["auth_canvas"],
            title,
            auth_points,
            "No source-IP data is available for this analysis."
        )

        timeline_points = self.build_timeline_chart_data(results)
        self.draw_bar_chart(
            self.visuals_tab["timeline_canvas"],
            "Event Timeline (per minute)",
            timeline_points,
            "No timestamped events were available for a timeline chart."
        )

        caption_bits = [
            f"Sources: {len(results.get('loaded_sources', [])) or 1}",
            f"Events: {len(results.get('normalized_events', []))}",
        ]
        overall = (self.last_finding_assessment or {}).get("overall", {})
        if overall:
            caption_bits.append(f"Overall confidence: {overall.get('confidence_label', 'Not Detected')} {overall.get('score', 0)}/100")
        self.visuals_tab["caption_label"].config(text=" | ".join(caption_bits))

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
            or "confidence scoring" in lower_line
            or "evidence confidence summary" in lower_line
            or "raw summary" in lower_line
            or "source profile" in lower_line
            or "loaded sources" in lower_line
            or "per-source results" in lower_line
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
            messagebox.showerror("Missing File", "Could not find sample_log.txt in the project folder.")

    def generate_sample_attack(self):
        if write_sample_log is None:
            messagebox.showerror(
                "Missing Generator",
                "generate_sample_log.py is not in this folder, so sample generation is unavailable."
            )
            self.status_label.config(text="Sample generation unavailable")
            return

        try:
            output_path = os.path.join(get_writable_output_dir(), "sample_log.txt")
            path, count = write_sample_log(output_path)
            self.file_path = path
            self.file_label.config(text=os.path.basename(path))
            self.status_label.config(text=f"Generated sample attack log ({count} lines)")
            messagebox.showinfo(
                "Sample Generated",
                f"Created sample_log.txt with {count} lines of mixed attack and normal activity."
            )
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

        ip_filter = self.ip_filter_var.get().strip() if apply_filter else ""
        finding_type = self.finding_type_var.get() if apply_filter else "All Findings"

        events = results.get("normalized_events", [])

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
            self.insert_line_with_tag(widget, "No normalized events are available.")
            return

        shown = 0
        for event in events:
            source_ip = event.get("source_ip", "Unknown")
            category = event.get("event_category", "unknown")
            event_type = event.get("event_type", "unknown")
            severity = event.get("severity", "low")
            timestamp = event.get("timestamp", "Unknown")
            detection_reason = event.get("detection_reason", "")
            profile = event.get("source_profile", "Unknown")
            source_file = event.get("source_file", "Unknown")

            if ip_filter and ip_filter not in source_ip and ip_filter not in event.get("raw_log", ""):
                continue

            if finding_type == "Authentication" and category != "authentication":
                continue
            elif finding_type == "Burst Detections" and event_type != "burst_detection":
                continue
            elif finding_type == "Service-Flood" and category != "availability":
                continue

            line = (
                f"{timestamp:<20} "
                f"{severity.upper():<10} "
                f"{source_ip:<16} "
                f"{category:<16} "
                f"{event_type:<24} "
                f"{profile:<24} "
                f"{source_file:<26} "
                f"{detection_reason}"
            )
            lines.append(line)
            shown += 1

        if shown == 0:
            lines.append("No timeline events matched the current filters.")

        for index, line in enumerate(lines):
            if index < 5:
                self.insert_line_with_tag(widget, line)
            else:
                severity = "low"
                if " CRITICAL " in f" {line} ":
                    severity = "critical"
                elif " HIGH " in f" {line} ":
                    severity = "high"
                elif " MEDIUM " in f" {line} ":
                    severity = "medium"
                self.insert_timeline_line(widget, line, severity)

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

    def build_report_text(self, results):
        assessment = self.last_finding_assessment or build_finding_assessment(results)
        assessment_block = format_assessment_block(assessment)
        base_report = generate_report_string(results)

        if assessment_block:
            return assessment_block + "\n\n" + base_report
        return base_report

    def refresh_per_source_results(self):
        raw_per_source_results = []
        if self.last_results:
            raw_per_source_results = self.last_results.get("per_source_results", []) or []
        self.last_per_source_results = build_per_source_results(raw_per_source_results)
        return self.last_per_source_results

    def build_export_payload(self):
        export_payload = dict(self.last_results or {})
        export_payload["attack_mappings"] = self.last_attack_results or {}
        export_payload["finding_assessment"] = self.last_finding_assessment or {}
        export_payload["per_source_results"] = self.last_per_source_results or []
        export_payload["exported_at"] = datetime.utcnow().isoformat() + "Z"
        return export_payload

    def write_txt_report(self, output_path):
        with open(output_path, "w", encoding="utf-8") as file:
            file.write(self.last_report)
        return output_path

    def write_json_report(self, output_path):
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(self.build_export_payload(), file, indent=2, default=str)
        return output_path

    def write_csv_report(self, output_path):
        with open(output_path, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["section", "item", "value"])

            writer.writerow(["summary", "source_profile_used", self.last_results.get("source_profile_used", "Unknown")])
            writer.writerow(["summary", "total_lines", self.last_results.get("total_lines", 0)])
            writer.writerow(["summary", "successful_logins", self.last_results.get("successful_logins", 0)])
            writer.writerow(["summary", "failed_attempts", self.last_results.get("failed_attempts", 0)])

            for source in self.last_results.get("loaded_sources", []):
                writer.writerow([
                    "loaded_sources",
                    source.get("source_file", ""),
                    json.dumps(source)
                ])

            for ip, count in self.last_results.get("failed_ips", {}).items():
                writer.writerow(["failed_ips", ip, count])

            for ip, count in self.last_results.get("suspicious_ips", {}).items():
                writer.writerow(["suspicious_ips", ip, count])

            for ip, count in self.last_results.get("time_based_attacks", {}).items():
                writer.writerow(["burst_detections", ip, count])

            for event_name, count in self.last_results.get("ddos_event_counts", {}).items():
                writer.writerow(["ddos_event_counts", event_name, count])

            for ip, count in self.last_results.get("ddos_source_ips", {}).items():
                writer.writerow(["ddos_source_ips", ip, count])

            assessment = self.last_finding_assessment or {}
            overall = assessment.get("overall", {})
            if overall:
                writer.writerow(["finding_assessment", "overall", json.dumps(overall)])

            for section_name, section in assessment.get("sections", {}).items():
                writer.writerow(["finding_assessment", section_name, json.dumps(section)])

            for entry in self.last_per_source_results or []:
                writer.writerow([
                    "per_source_results",
                    entry.get("source_file", ""),
                    json.dumps({
                        "source_profile_requested": entry.get("source_profile_requested"),
                        "source_profile_used": entry.get("source_profile_used"),
                        "overall_confidence": entry.get("overall_confidence"),
                        "overall_score": entry.get("overall_score"),
                        "headline": entry.get("headline"),
                        "total_lines": entry.get("total_lines"),
                        "successful_logins": entry.get("successful_logins"),
                        "failed_attempts": entry.get("failed_attempts"),
                        "suspicious_ip_count": entry.get("suspicious_ip_count"),
                        "burst_ip_count": entry.get("burst_ip_count"),
                        "ddos_event_total": entry.get("ddos_event_total"),
                        "technique_ids": entry.get("technique_ids", []),
                    })
                ])

            for event in self.last_results.get("normalized_events", []):
                writer.writerow(["normalized_events", event.get("event_type", ""), json.dumps(event)])

            for technique in (self.last_attack_results or {}).get("techniques", []):
                writer.writerow(["attack_techniques", technique.get("technique_id", ""), json.dumps(technique)])
        return output_path

    def write_package_readme(self, output_path, package_dir_name):
        assessment = self.last_finding_assessment or {}
        overall = assessment.get("overall", {})
        lines = [
            "LogSentry Export Package",
            "=" * 60,
            f"Package Folder: {package_dir_name}",
            f"Exported At (UTC): {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "Files",
            "-" * 60,
            "analysis_report.txt - Analyst-friendly text report with confidence scoring.",
            "analysis_results.json - Structured analysis payload, ATT&CK mappings, and finding assessment.",
            "analysis_results.csv - Flat export for spreadsheet or quick filtering.",
            "attack_navigator_layer.json - MITRE ATT&CK Navigator layer when techniques were mapped.",
            "",
        ]

        if self.last_per_source_results:
            lines.extend([
                "Per-Source Snapshot",
                "-" * 60,
                f"Sources summarized: {len(self.last_per_source_results)}",
                f"Top source: {self.last_per_source_results[0].get('source_file', 'Unknown')} "
                f"({self.last_per_source_results[0].get('overall_confidence', 'Not Detected')} "
                f"{self.last_per_source_results[0].get('overall_score', 0)}/100)",
                "",
            ])

        if overall:
            lines.extend([
                "Overall Assessment",
                "-" * 60,
                f"Detected: {'Yes' if overall.get('detected') else 'No'}",
                f"Confidence: {overall.get('confidence_label', 'Not Detected')} ({overall.get('score', 0)}/100)",
                f"Headline: {overall.get('headline', 'No major finding')}",
                "",
            ])

        with open(output_path, "w", encoding="utf-8") as file:
            file.write("\n".join(lines))
        return output_path

    def export_package(self):
        if not self.last_results:
            messagebox.showwarning("No Data", "Run an analysis first.")
            return

        selected_dir = filedialog.askdirectory(title="Choose Export Folder")
        if not selected_dir:
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        package_dir_name = f"logsentry_export_{timestamp}"
        package_dir = os.path.join(selected_dir, package_dir_name)
        os.makedirs(package_dir, exist_ok=True)

        try:
            self.write_txt_report(os.path.join(package_dir, "analysis_report.txt"))
            self.write_json_report(os.path.join(package_dir, "analysis_results.json"))
            self.write_csv_report(os.path.join(package_dir, "analysis_results.csv"))
            self.write_package_readme(os.path.join(package_dir, "README.txt"), package_dir_name)

            if self.last_attack_results and self.last_attack_results.get("techniques"):
                export_navigator_layer(
                    self.last_attack_results,
                    os.path.join(package_dir, "attack_navigator_layer.json")
                )

            messagebox.showinfo("Success", f"Export package created:\n{package_dir}")
            self.status_label.config(text=f"Export package created: {os.path.basename(package_dir)}")
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to build export package: {exc}")

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

        assessment = self.last_finding_assessment or build_finding_assessment(results)

        lines = [
            "Case Summary",
            "=" * 100,
            f"Incident Type: {case['incident_type']}",
            f"Severity: {case['severity']}",
            f"Time Range: {case['time_range']}",
            "",
            "Confidence Scoring",
            "-" * 100,
            f"Overall: {assessment.get('overall', {}).get('confidence_label', 'Not Detected')} ({assessment.get('overall', {}).get('score', 0)}/100)",
            f"Headline: {assessment.get('overall', {}).get('headline', 'No major finding')}",
        ]

        for section_name, section in assessment.get("sections", {}).items():
            pretty_name = section_name.replace("_", " ").title()
            lines.append(
                f"{pretty_name}: {section.get('confidence_label', 'Not Detected')} "
                f"({section.get('score', 0)}/100) | evidence count: {section.get('evidence_count', 0)}"
            )
            for reason in section.get("reasons", []):
                lines.append(f"  - {reason}")

        lines.extend([
            "",
            "Primary Suspected IPs",
            "-" * 100,
        ])

        if case["top_entities"]:
            for ip, score in case["top_entities"]:
                lines.append(f"{ip} | combined activity score: {score}")
        else:
            lines.append("No strong suspected IPs identified.")

        lines.extend([
            "",
            "Key Findings",
            "-" * 100,
        ])

        for finding in case["findings"]:
            lines.append(f"- {finding}")

        lines.extend([
            "",
            "Evidence Highlights",
            "-" * 100,
        ])

        if case["evidence_lines"]:
            for line in case["evidence_lines"]:
                lines.append(line)
        else:
            lines.append("No high-severity evidence lines were selected.")

        lines.extend([
            "",
            "Recommended Next Steps",
            "-" * 100,
        ])

        for step in case["next_steps"]:
            lines.append(f"- {step}")

        for line in lines:
            self.insert_line_with_tag(widget, line)

    def populate_source_results_tab(self):
        widget = self.source_results_tab["widget"]
        self.clear_text_widget(widget)

        block = format_per_source_block(self.last_per_source_results or [])
        for line in block.splitlines():
            self.insert_line_with_tag(widget, line)

    def populate_attack_tab(self):
        widget = self.attack_tab["widget"]
        self.clear_text_widget(widget)

        attack_results = self.last_attack_results or {}
        techniques = attack_results.get("techniques", [])

        lines = [
            "MITRE ATT&CK Mappings",
            "=" * 100,
            f"Domain: {attack_results.get('domain', 'enterprise-attack')}",
            f"ATT&CK Version: {attack_results.get('attack_version', 'Unknown')}",
            f"Mapped Techniques: {attack_results.get('total_mapped', 0)}",
            "",
        ]

        for summary_line in attack_results.get("summary_lines", []):
            lines.append(summary_line)

        if techniques:
            lines.extend([
                "",
                "Technique Details",
                "-" * 100,
            ])
            for technique in techniques:
                lines.append(
                    f"{technique['technique_id']} | {technique['name']} | "
                    f"Severity: {technique['severity'].title()} | Score: {technique['score']}"
                )
                lines.append(f"  Tactics: {', '.join(technique['tactics'])}")
                lines.append(f"  URL: {technique['url']}")
                lines.append(f"  Evidence Count: {technique['evidence_count']}")
                lines.append(f"  Mapped From: {', '.join(technique['mapped_from'])}")
                lines.append(f"  Notes: {technique['comment']}")
                lines.append("")
        else:
            lines.append("No ATT&CK techniques were mapped from the current analysis.")

        lines.extend([
            "Navigator Export",
            "-" * 100,
            "Use the 'Export ATT&CK Layer' button to create a MITRE ATT&CK Navigator JSON layer.",
        ])

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
        self.populate_auth_tab(results, apply_filter=apply_filter)
        self.populate_burst_tab(results, apply_filter=apply_filter)
        self.populate_ddos_tab(results, apply_filter=apply_filter)
        self.populate_timeline_tab(results, apply_filter=apply_filter)
        self.populate_ip_tab(results)
        self.populate_case_tab(results)
        self.populate_visuals_tab(results)
        self.populate_source_results_tab()
        self.populate_attack_tab()
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
        self.last_results = results
        self.last_attack_results = build_attack_results(results)
        self.last_finding_assessment = build_finding_assessment(results)
        self.refresh_per_source_results()
        report_text = self.build_report_text(results)
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
        self.last_results = results
        self.last_attack_results = build_attack_results(results)
        self.last_finding_assessment = build_finding_assessment(results)
        self.refresh_per_source_results()
        report_text = self.build_report_text(results)
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
                self.write_txt_report(save_path)
                messagebox.showinfo("Success", "TXT report exported successfully.")
                self.status_label.config(text="TXT report exported")
            except Exception as exc:
                messagebox.showerror("Error", f"Failed to save TXT file: {exc}")

    def export_json(self):
        if not self.last_results:
            messagebox.showwarning("No Data", "Run an analysis first.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
            title="Save JSON Report"
        )

        if save_path:
            try:
                self.write_json_report(save_path)
                messagebox.showinfo("Success", "JSON report exported successfully.")
                self.status_label.config(text="JSON report exported")
            except Exception as exc:
                messagebox.showerror("Error", f"Failed to save JSON file: {exc}")

    def export_csv(self):
        if not self.last_results:
            messagebox.showwarning("No Data", "Run an analysis first.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title="Save CSV Report"
        )

        if save_path:
            try:
                self.write_csv_report(save_path)
                messagebox.showinfo("Success", "CSV report exported successfully.")
                self.status_label.config(text="CSV report exported")
            except Exception as exc:
                messagebox.showerror("Error", f"Failed to save CSV file: {exc}")

    def export_attack_layer(self):
        if not self.last_attack_results or not self.last_attack_results.get("techniques"):
            messagebox.showwarning("No ATT&CK Data", "Run an analysis first to generate ATT&CK mappings.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("Navigator Layer JSON", "*.json")],
            title="Save ATT&CK Navigator Layer"
        )

        if save_path:
            try:
                export_navigator_layer(self.last_attack_results, save_path)
                messagebox.showinfo("Success", "ATT&CK Navigator layer exported successfully.")
                self.status_label.config(text="ATT&CK layer exported")
            except Exception as exc:
                messagebox.showerror("Error", f"Failed to save ATT&CK layer: {exc}")

    def clear_all(self):
        self.file_path = ""
        self.last_report = ""
        self.last_results = None
        self.last_attack_results = None
        self.last_finding_assessment = None
        self.last_per_source_results = None
        self.loaded_sources = []

        self.file_label.config(text="No single file selected")
        self.drop_zone.config(
            text="Drag and drop a .txt or .log file here to add it as a source" if DND_AVAILABLE else "Drag and drop requires: pip install tkinterdnd2",
            fg=self.colors["muted"],
            bg=self.colors["input_bg"]
        )

        self.threshold_var.set("3")
        self.time_window_var.set("30")
        self.burst_threshold_var.set("3")
        self.source_profile_var.set("Auto Detect")
        self.new_source_profile_var.set("Auto Detect")
        self.ip_filter_var.set("")
        self.finding_type_var.set("All Findings")
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

        for tab in [self.auth_tab, self.burst_tab, self.ddos_tab, self.timeline_tab, self.ip_tab, self.case_tab, self.source_results_tab, self.attack_tab, self.summary_tab]:
            self.clear_text_widget(tab["widget"])

        self.clear_visuals_tab()

        self.auth_tab["widget"].insert("1.0", "Authentication findings will appear here after analysis.")
        self.burst_tab["widget"].insert("1.0", "Burst detections will appear here after analysis.")
        self.ddos_tab["widget"].insert("1.0", "Service-flood findings will appear here after analysis.")
        self.timeline_tab["widget"].insert("1.0", "Normalized event timeline will appear here after analysis.")
        self.ip_tab["widget"].insert("1.0", "IP drill-down details will appear here after analysis.")
        self.case_tab["widget"].insert("1.0", "Incident case summary will appear here after analysis.")
        self.source_results_tab["widget"].insert("1.0", "Per-source results will appear here after analysis.")
        self.attack_tab["widget"].insert("1.0", "MITRE ATT&CK mappings will appear here after analysis.")
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