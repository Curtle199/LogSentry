import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from analyzer import analyze_log


class LogSentryApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LogSentry - Log Analyzer")
        self.root.geometry("750x550")

        self.file_path = ""

        title_label = tk.Label(
            root,
            text="LogSentry",
            font=("Arial", 20, "bold")
        )
        title_label.pack(pady=10)

        subtitle_label = tk.Label(
            root,
            text="Python Log Analyzer for Failed Login Detection",
            font=("Arial", 11)
        )
        subtitle_label.pack()

        top_frame = tk.Frame(root)
        top_frame.pack(pady=15)

        self.file_label = tk.Label(
            top_frame,
            text="No file selected",
            width=55,
            anchor="w",
            relief="sunken",
            padx=8
        )
        self.file_label.grid(row=0, column=0, padx=5)

        browse_button = tk.Button(
            top_frame,
            text="Browse Log File",
            command=self.browse_file,
            width=15
        )
        browse_button.grid(row=0, column=1, padx=5)

        analyze_button = tk.Button(
            root,
            text="Analyze Log",
            command=self.run_analysis,
            width=20,
            height=2
        )
        analyze_button.pack(pady=10)

        self.results_box = scrolledtext.ScrolledText(
            root,
            width=85,
            height=22,
            font=("Courier New", 10)
        )
        self.results_box.pack(padx=10, pady=10)

    def browse_file(self):
        selected_file = filedialog.askopenfilename(
            title="Select a log file",
            filetypes=[("Text files", "*.txt"), ("Log files", "*.log"), ("All files", "*.*")]
        )

        if selected_file:
            self.file_path = selected_file
            self.file_label.config(text=selected_file)

    def run_analysis(self):
        if not self.file_path:
            messagebox.showwarning("No File", "Please select a log file first.")
            return

        results = analyze_log(self.file_path)

        self.results_box.delete("1.0", tk.END)

        if "error" in results:
            self.results_box.insert(tk.END, f"ERROR: {results['error']}\n")
            return

        self.results_box.insert(tk.END, "=" * 55 + "\n")
        self.results_box.insert(tk.END, "               LOGSENTRY ANALYSIS REPORT\n")
        self.results_box.insert(tk.END, "=" * 55 + "\n\n")
        self.results_box.insert(tk.END, f"Total log lines: {results['total_lines']}\n")
        self.results_box.insert(tk.END, f"Successful logins: {results['successful_logins']}\n")
        self.results_box.insert(tk.END, f"Failed login attempts: {results['failed_attempts']}\n\n")

        self.results_box.insert(tk.END, "Failed login attempts by IP:\n")
        if results["failed_ips"]:
            for ip, count in results["failed_ips"].items():
                self.results_box.insert(tk.END, f"  - {ip}: {count}\n")
        else:
            self.results_box.insert(tk.END, "  None found.\n")

        self.results_box.insert(tk.END, "\nSuspicious IPs flagged:\n")
        if results["suspicious_ips"]:
            for ip, count in results["suspicious_ips"].items():
                self.results_box.insert(tk.END, f"  ALERT: {ip} had {count} failed login attempts\n")
        else:
            self.results_box.insert(tk.END, "  No suspicious IPs met the alert threshold.\n")

        self.results_box.insert(tk.END, "\n" + "=" * 55 + "\n")
        self.results_box.insert(tk.END, "Analysis complete.\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = LogSentryApp(root)
    root.mainloop()
