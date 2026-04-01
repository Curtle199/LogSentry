import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from analyzer import analyze_log, generate_report_string
import os


class LogSentryApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LogSentry v1.1")
        self.root.geometry("980x700")
        self.root.minsize(980, 700)
        self.root.configure(bg="#0f172a")

        self.file_path = ""
        self.last_report = ""

        self.setup_styles()
        self.build_ui()

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
            "input_bg": "#0b1220",
            "output_bg": "#020617",
        }

        self.font_title = ("Segoe UI", 24, "bold")
        self.font_subtitle = ("Segoe UI", 11)
        self.font_heading = ("Segoe UI", 12, "bold")
        self.font_body = ("Segoe UI", 10)
        self.font_stat_value = ("Segoe UI", 18, "bold")
        self.font_stat_label = ("Segoe UI", 9)
        self.font_output = ("Consolas", 10)

    def build_ui(self):
        self.main_frame = tk.Frame(self.root, bg=self.colors["bg"])
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        self.build_header()
        self.build_file_section()
        self.build_action_section()
        self.build_stats_section()
        self.build_output_section()

    def build_header(self):
        header = tk.Frame(
            self.main_frame,
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

        tk.Label(
            header,
            text="Authentication Log Monitoring and Suspicious Activity Detection",
            font=self.font_subtitle,
            fg=self.colors["muted"],
            bg=self.colors["panel"]
        ).pack(pady=(0, 18))

    def build_file_section(self):
        section = tk.Frame(
            self.main_frame,
            bg=self.colors["panel"],
            highlightbackground=self.colors["border"],
            highlightthickness=1
        )
        section.pack(fill="x", pady=(0, 16))

        tk.Label(
            section,
            text="Log File Selection",
            font=self.font_heading,
            fg=self.colors["text"],
            bg=self.colors["panel"]
        ).pack(anchor="w", padx=16, pady=(14, 10))

        row = tk.Frame(section, bg=self.colors["panel"])
        row.pack(fill="x", padx=16, pady=(0, 16))

        self.file_label = tk.Label(
            row,
            text="No file selected",
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
            text="Browse",
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

    def build_action_section(self):
        section = tk.Frame(self.main_frame, bg=self.colors["bg"])
        section.pack(fill="x", pady=(0, 16))

        button_frame = tk.Frame(section, bg=self.colors["bg"])
        button_frame.pack(anchor="w")

        sample_button = tk.Button(
            button_frame,
            text="Load Sample Log",
            font=("Segoe UI", 10, "bold"),
            fg="white",
            bg=self.colors["panel_2"],
            activeforeground="white",
            activebackground="#374151",
            relief="flat",
            bd=0,
            padx=24,
            pady=12,
            cursor="hand2",
            command=self.load_sample_log
        )
        sample_button.pack(side="left", padx=(0, 10))

        analyze_button = tk.Button(
            button_frame,
            text="Analyze Log",
            font=("Segoe UI", 10, "bold"),
            fg="white",
            bg=self.colors["success"],
            activeforeground="white",
            activebackground="#15803d",
            relief="flat",
            bd=0,
            padx=24,
            pady=12,
            cursor="hand2",
            command=self.run_analysis
        )
        analyze_button.pack(side="left", padx=(0, 10))

        export_button = tk.Button(
            button_frame,
            text="Export Report",
            font=("Segoe UI", 10, "bold"),
            fg="white",
            bg=self.colors["accent"],
            activeforeground="white",
            activebackground=self.colors["accent_hover"],
            relief="flat",
            bd=0,
            padx=24,
            pady=12,
            cursor="hand2",
            command=self.export_report
        )
        export_button.pack(side="left")

    def build_stats_section(self):
        self.stats_frame = tk.Frame(self.main_frame, bg=self.colors["bg"])
        self.stats_frame.pack(fill="x", pady=(0, 16))

        self.total_lines_card = self.create_stat_card(
            self.stats_frame,
            "Total Lines",
            "0",
            self.colors["neutral_card"]
        )
        self.total_lines_card.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.success_card = self.create_stat_card(
            self.stats_frame,
            "Successful Logins",
            "0",
            self.colors["success_card"]
        )
        self.success_card.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.failed_card = self.create_stat_card(
            self.stats_frame,
            "Failed Attempts",
            "0",
            self.colors["warning_card"]
        )
        self.failed_card.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.alert_card = self.create_stat_card(
            self.stats_frame,
            "Suspicious IPs",
            "0",
            self.colors["danger_card"]
        )
        self.alert_card.pack(side="left", fill="x", expand=True)

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
            fg="#dbeafe" if bg_color == self.colors["neutral_card"] else "#e5e7eb",
            bg=bg_color
        )
        text_label.pack(anchor="w", padx=16, pady=(0, 14))

        card.value_label = value_label
        return card

    def build_output_section(self):
        section = tk.Frame(
            self.main_frame,
            bg=self.colors["panel"],
            highlightbackground=self.colors["border"],
            highlightthickness=1
        )
        section.pack(fill="both", expand=True)

        top_row = tk.Frame(section, bg=self.colors["panel"])
        top_row.pack(fill="x", padx=16, pady=(14, 10))

        tk.Label(
            top_row,
            text="Analysis Report",
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

        self.results_box = scrolledtext.ScrolledText(
            section,
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
        self.results_box.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self.results_box.insert(
            "1.0",
            "LogSentry is ready.\n\nLoad a log file and click 'Analyze Log' to begin."
        )

    def browse_file(self):
        selected_file = filedialog.askopenfilename(
            title="Select a log file",
            filetypes=[
                ("Log files", "*.log"),
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )

        if selected_file:
            self.file_path = selected_file
            self.file_label.config(text=os.path.basename(selected_file))
            self.status_label.config(text="File selected")

    def load_sample_log(self):
        sample_path = os.path.join(os.path.dirname(__file__), "sample_log.txt")

        if os.path.exists(sample_path):
            self.file_path = sample_path
            self.file_label.config(text=os.path.basename(sample_path))
            self.status_label.config(text="Sample log loaded")
        else:
            messagebox.showerror(
                "Missing File",
                "Could not find sample_log.txt in the project folder."
            )

    def update_stats(self, results):
        if "error" in results:
            self.total_lines_card.value_label.config(text="0")
            self.success_card.value_label.config(text="0")
            self.failed_card.value_label.config(text="0")
            self.alert_card.value_label.config(text="0")
            return

        self.total_lines_card.value_label.config(text=str(results["total_lines"]))
        self.success_card.value_label.config(text=str(results["successful_logins"]))
        self.failed_card.value_label.config(text=str(results["failed_attempts"]))
        self.alert_card.value_label.config(text=str(len(results["suspicious_ips"])))

    def run_analysis(self):
        if not self.file_path:
            messagebox.showwarning("No File", "Please select a log file first.")
            return

        results = analyze_log(self.file_path)
        report_text = generate_report_string(results)

        self.last_report = report_text
        self.update_stats(results)

        self.results_box.delete("1.0", tk.END)
        self.results_box.insert(tk.END, report_text)

        if "error" in results:
            self.status_label.config(text="Analysis failed")
        else:
            self.status_label.config(text="Analysis complete")

    def export_report(self):
        if not self.last_report:
            messagebox.showwarning("No Data", "Run an analysis first.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt")],
            title="Save Report"
        )

        if save_path:
            try:
                with open(save_path, "w", encoding="utf-8") as file:
                    file.write(self.last_report)
                messagebox.showinfo("Success", "Report exported successfully.")
                self.status_label.config(text="Report exported")
            except Exception as exc:
                messagebox.showerror("Error", f"Failed to save file: {exc}")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    root = tk.Tk()
    app = LogSentryApp(root)
    app.run()
