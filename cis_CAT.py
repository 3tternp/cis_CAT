# cis_CAT.py

import tkinter as tk
from tkinter import filedialog, messagebox
import os
import threading
import webbrowser
from typing import Optional
from datetime import datetime

# Line 16: CRITICAL IMPORT (Needs onyx_core.py to be error-free)
try:
    from cisCAT_core import run_assessment_live, run_assessment_offline
except ImportError as e:
    messagebox.showerror("Startup Error", f"Could not load onyx_core.py or core dependencies. Error: {e}")
    exit()


class OnyxGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CIS CAT - Cisco CIS Auditor (GUI)")
        self.geometry("700x600")
        self.resizable(False, False)

        self.last_report_path: Optional[str] = None
        self.config_file_path: Optional[str] = None
        self.create_widgets()

    def create_widgets(self):
        header = tk.Label(
            self,
            text="CIS CAT - Cisco CIS Auditor",
            font=("Segoe UI", 18, "bold"),
            fg="#004d99"
        )
        header.pack(pady=12)

        # --- File Selection ---
        file_frame = tk.LabelFrame(self, text="1. Select Configuration File (Offline Mode)", padx=10, pady=10)
        file_frame.pack(padx=20, pady=10, fill="x")

        self.config_path_label = tk.Label(file_frame, text="No file selected.", width=50, anchor="w", bg="#f0f0f0")
        self.config_path_label.pack(side=tk.LEFT, padx=5, pady=5)

        tk.Button(file_frame, text="Browse Config File", command=self.select_config_file).pack(side=tk.RIGHT)
        
        # --- Run Button ---
        tk.Button(
            self, 
            text="2. RUN OFFLINE CIS AUDIT", 
            command=self.start_offline_assessment,
            font=("Segoe UI", 12, "bold"), 
            bg="#4CAF50", 
            fg="white", 
            height=2
        ).pack(pady=20, padx=50, fill="x")

        # --- Status & Results ---
        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(self, textvariable=self.status_var, fg="#004d99", font=("Segoe UI", 10, "italic")).pack(pady=5)
        
        results_frame = tk.LabelFrame(self, text="Assessment Output Log", padx=10, pady=5)
        results_frame.pack(padx=20, pady=10, fill="both", expand=True)
        
        self.results_box = tk.Text(results_frame, height=15, state=tk.DISABLED, bg="#333", fg="#00FF00") 
        self.results_box.pack(fill="both", expand=True)

        # --- Bottom Buttons ---
        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Open Report", command=self.open_report, padx=10).pack(side=tk.LEFT, padx=10)
        tk.Button(button_frame, text="Exit", command=self.quit, padx=10).pack(side=tk.LEFT, padx=10)


    def select_config_file(self):
        file_path = filedialog.askopenfilename(
            defaultextension=".cfg",
            filetypes=[("Configuration Files", "*.cfg *.txt *.ios"), ("All files", "*.*")]
        )
        if file_path:
            self.config_file_path = file_path
            self.config_path_label.config(text=os.path.basename(file_path))
            self.status_var.set(f"File loaded: {os.path.basename(file_path)}. Ready to audit.")

    def start_offline_assessment(self):
        if not self.config_file_path or not os.path.exists(self.config_file_path):
            messagebox.showerror("Error", "Please select a valid configuration file first.")
            return

        self._clear_results()
        self.status_var.set("Starting offline assessment...")
        
        threading.Thread(target=self._run_offline_thread, args=(self.config_file_path,), daemon=True).start()

    def _run_offline_thread(self, config_path):
        try:
            self._append_result(f"Starting audit on: {os.path.basename(config_path)}...")
            
            result = run_assessment_offline(config_path)
            score = result.get("score")
            report = result.get("report_file")
            version_label = result.get("version_label", "Cisco Audit")

            self._append_result(f"Audit completed for: {version_label}")
            self._append_result(f"Compliance Score: {score}/100")
            self._append_result(f"Report saved to: {report}")

            self.status_var.set(f"Audit complete. Score: {score}")
            self.last_report_path = report

            if report and os.path.exists(report):
                webbrowser.open('file://' + os.path.abspath(report))

        except Exception as e:
            self.status_var.set("Error during assessment.")
            self._append_result(f"FATAL Error: {e}")
            messagebox.showerror("Assessment Error", str(e))

    def open_report(self):
        if self.last_report_path and os.path.exists(self.last_report_path):
            webbrowser.open('file://' + os.path.abspath(self.last_report_path))
        else:
            messagebox.showinfo("Info", "No report has been generated yet.")

    def _clear_results(self):
        self.results_box.config(state=tk.NORMAL)
        self.results_box.delete(1.0, tk.END)
        self.results_box.config(state=tk.DISABLED)

    def _append_result(self, text):
        self.results_box.config(state=tk.NORMAL)
        self.results_box.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n")
        self.results_box.see(tk.END)
        self.results_box.config(state=tk.DISABLED)


if __name__ == "__main__":
    app = OnyxGUI()
    app.mainloop()