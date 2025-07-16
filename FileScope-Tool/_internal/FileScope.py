from Imports import*
from reportlab.platypus import Image
from reportlab.lib.utils import ImageReader
from file_analyzer import FileAnalyzer

class FileScope:
    def __init__(self, root):
        self.root = root
        self.root.title("📂 FileScope - See Beyond the Extension")
        self.root.geometry("900x800")
        self.root.configure(bg="#25273a")

        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=8, background="#5c6bc0", foreground="white", borderwidth=0)
        style.map("TButton", background=[("active", "#7986cb")])
        style.configure("TLabel", background="#25273a", foreground="#e0e0e0", font=("Segoe UI", 14))
        style.configure("TFrame", background="#25273a")
        style.configure("TProgressbar", thickness=20)

        main_frame = ttk.Frame(self.root)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=10)
        main_frame.rowconfigure(3, weight=1)
        main_frame.columnconfigure(0, weight=1)

        self.label = ttk.Label(main_frame, text="🔍 FileScope Forensic Analyzer", font=("Segoe UI", 16, "bold"))
        self.label.grid(row=0, column=0, pady=(5, 10))

        drop_frame = ttk.Frame(main_frame, style="TFrame")
        drop_frame.grid(row=1, column=0, sticky="ew", pady=5)
        drop_frame.columnconfigure(0, weight=1)

        self.drop_zone = tk.Text(drop_frame, height=10, bg="#32354e", fg="#b0bec5", font=("Consolas", 10), relief="flat", bd=2)
        self.drop_zone.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
        self.drop_zone.insert(tk.END, "📁 Drag a file here or click to browse...")
        self.drop_zone.configure(cursor="hand2")
        self.drop_zone.bind("<Button-1>", self.browse_file)
        self.drop_zone.drop_target_register(DND_FILES)
        self.drop_zone.dnd_bind("<<Drop>>", self.handle_drop)

        button_frame = ttk.Frame(main_frame, style="TFrame")
        button_frame.grid(row=2, column=0, sticky="ew", pady=10)
        self.export_button = ttk.Button(button_frame, text="📤 Export PDF Report", command=self.export_pdf, style="TButton")
        self.export_button.pack()

        self.export_button.bind("<Enter>", lambda e: self.export_button.configure(style="Hover.TButton"))
        self.export_button.bind("<Leave>", lambda e: self.export_button.configure(style="TButton"))
        style.configure("Hover.TButton", background="#7986cb")

        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=3, column=0, sticky="ew", pady=5)
        self.progress.grid_remove()

        output_frame = ttk.Frame(main_frame, style="TFrame")
        output_frame.grid(row=4, column=0, sticky="nsew", pady=10)
        output_frame.rowconfigure(0, weight=1)
        output_frame.columnconfigure(0, weight=1)

        scrollbar = tk.Scrollbar(output_frame, orient="vertical")
        scrollbar.grid(row=0, column=1, sticky="ns")

        self.output_text = tk.Text(output_frame, bg="#1a1c2c", fg="#d0d0e0", font=("Consolas", 10), relief="flat", bd=2, wrap="word", yscrollcommand=scrollbar.set, height=15)
        self.output_text.grid(row=0, column=0, sticky="nsew", padx=(10, 0))
        self.output_text.tag_configure("link", foreground="#5c6bc0", underline=True)
        self.output_text.tag_bind("link", "<Button-1>", self.open_file_location)

        scrollbar.config(command=self.output_text.yview)

        entropy_frame = ttk.Frame(main_frame, style="TFrame")
        entropy_frame.grid(row=5, column=0, sticky="ew", pady=10)
        self.entropy_canvas = tk.Canvas(entropy_frame, height=200, bg="#1a1c2c", highlightthickness=1, highlightbackground="#5c6bc0")
        self.entropy_canvas.pack(fill="both", expand=True, padx=10)
        self.entropy_canvas.create_text(300, 100, text="Entropy Graph", fill="#b0bec5", font=("Segoe UI", 12, "italic"))

        self.file_path = None
        self.analyzer = FileAnalyzer()
        self.analysis_results = {}

    def open_file_location(self, event):
        if self.file_path:
            import subprocess
            import platform
            directory = os.path.dirname(self.file_path)
            if platform.system() == "Windows":
                subprocess.run(['explorer', directory])
            elif platform.system() == "Darwin":
                subprocess.run(['open', directory])
            elif platform.system() == "Linux":
                subprocess.run(['xdg-open', directory])

    def handle_drop(self, event):
        dropped_file = event.data.strip("{}")
        if os.path.isfile(dropped_file):
            self.file_path = dropped_file
            self.drop_zone.delete(1.0, tk.END)
            self.drop_zone.insert(tk.END, os.path.basename(self.file_path))
            self.analyze_file()

    def browse_file(self, event=None):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.drop_zone.delete(1.0, tk.END)
            self.drop_zone.insert(tk.END, os.path.basename(self.file_path))
            self.analyze_file()

    def analyze_file(self):
        if not self.file_path or not os.path.isfile(self.file_path):
            messagebox.showerror("Error", "Invalid or no file selected!")
            return
        
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Analyzing file: {self.file_path}\n...\n")
        self.entropy_canvas.delete("all")
        self.entropy_canvas.create_text(300, 100, text="Analyzing...", fill="#b0bec5", font=("Segoe UI", 12, "italic"))
        self.progress.grid()
        self.progress.start()

        self.root.update()
        try:
            self.analysis_results = self.analyzer.analyze(self.file_path)
            self.display_results()
            self.plot_entropy()
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
        finally:
            self.progress.stop()
            self.progress.grid_remove()

    def display_results(self):
        output = "FileScope Analysis Results\n" + "="*30 + "\n"
        output += f"File: {os.path.basename(self.file_path)}\n"
        output += f"Full Path: "
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, output)
        self.output_text.insert(tk.END, self.file_path, "link")
        output = f"\nTime: {datetime.datetime.now().strftime('%d-%Y-%m_%H:%M_IST')}\n\n"
        output += f"[SUMMARY]\n"
        output += f"Detected Type: {self.analysis_results['magic']['Detected Type']}\n"
        output += f"Declared Type: {self.analysis_results['magic']['Declared Type']}\n"
        output += f"Status: {self.analysis_results['magic']['Status']}\n"
        output += f"Risk Level: {self.analysis_results['risk']['Level']}\n\n"

        output += "[DETAILS]\n"
        output += f"- Magic Number: {self.analysis_results['magic']['Detected Type']}\n"
        output += f"- Extension: {self.analysis_results['magic']['Extension']}\n"
        output += f"- Structure Validity: {self.analysis_results['structure']['Valid']} ({self.analysis_results['structure']['Details']})\n"
        output += f"- Entropy Analysis: Mean {self.analysis_results['entropy']['Mean Entropy']}, Overall {self.analysis_results['entropy']['Overall Entropy']} ({self.analysis_results['entropy']['LSB Check']}, Anomaly: {self.analysis_results['entropy']['Anomaly Detected']})\n"
        output += f"- Spoof Check: {self.analysis_results['spoof']['Spoof Detected']} ({self.analysis_results['spoof']['Details']})\n"
        output += f"- Byte Pattern Similarity: {self.analysis_results['pattern']['Similarity to EXE']}\n"
        if self.analysis_results["pe"]["Analyzed"]:
            output += f"- PE Header Analysis:\n"
            output += f"  - Machine Type: {self.analysis_results['pe']['Machine Type']}\n"
            output += f"  - Number of Sections: {self.analysis_results['pe']['Number of Sections']}\n"
            output += f"  - Compilation Time: {self.analysis_results['pe']['Compilation Time']}\n"
            output += f"  - Entry Point: {self.analysis_results['pe']['Entry Point']}\n"
        if self.analysis_results["magic"]["Embedded Objects"]:
            output += f"- Embedded Objects: {self.analysis_results['magic']['Embedded Objects']}\n"
        if self.analysis_results["static"].get("notes"):
            output += f"- Notes: {self.analysis_results['static']['notes']}\n"

        output += "\n[RECOMMENDATION]\n"
        output += f"Risk Score: {self.analysis_results['risk']['Score']}\n"
        output += "Quarantine the file immediately. DO NOT run on production systems." if self.analysis_results['risk']['Level'] == "HIGH" else "File appears safe but verify before execution."

        self.output_text.insert(tk.END, output)

    def plot_entropy(self):
        entropies = self.analysis_results.get("entropy_chunks", [])
        if not entropies:
            self.entropy_canvas.delete("all")
            self.entropy_canvas.create_text(300, 100, text="No Entropy Data", fill="#b0bec5", font=("Segoe UI", 12, "italic"))
            return

        self.entropy_canvas.delete("all")
        canvas_width = 600
        canvas_height = 200
        padding = 40
        max_bars = 150
        bar_width = (canvas_width - 2 * padding) // min(len(entropies), max_bars) if entropies else 4

        self.entropy_canvas.create_line(padding, canvas_height - padding, canvas_width - padding, canvas_height - padding, fill="#e0e0e0")
        self.entropy_canvas.create_line(padding, canvas_height - padding, padding, padding, fill="#e0e0e0")

        for i in range(0, 9):
            y = canvas_height - padding - (i * (canvas_height - 2 * padding - 20) / 8)
            self.entropy_canvas.create_text(padding - 20, y, text=str(i), fill="#e0e0e0", font=("Segoe UI", 8))
            self.entropy_canvas.create_line(padding - 5, y, padding, y, fill="#e0e0e0")

        step = 20
        for i in range(0, min(len(entropies), max_bars) + 1, step):
            x = padding + i * bar_width
            self.entropy_canvas.create_text(x + bar_width / 2, canvas_height - padding + 15, text=str(i), fill="#e0e0e0", font=("Segoe UI", 8))
            self.entropy_canvas.create_line(x, canvas_height - padding, x, canvas_height - padding + 5, fill="#e0e0e0")

        for i, entropy in enumerate(entropies[:max_bars]):
            height = (entropy / 8) * (canvas_height - 2 * padding - 20)
            x1 = padding + i * bar_width
            y1 = canvas_height - padding - height
            x2 = x1 + bar_width
            y2 = canvas_height - padding
            self.entropy_canvas.create_rectangle(x1, y1, x2, y2, fill="#5c6bc0", outline="#7986cb")

        self.entropy_canvas.create_text((canvas_width - padding) // 2, 20, text="Entropy Distribution", fill="#e0e0e0", font=("Segoe UI", 10, "bold"))

    def export_pdf(self):
        if not self.file_path or not self.analysis_results:
            messagebox.showwarning("Warning", "No analysis results to export!")
            return

        reports_dir = "Reports"
        os.makedirs(reports_dir, exist_ok=True)
        uploaded_filename = os.path.basename(self.file_path).rsplit('.', 1)[0]  # Get filename without extension
        default_filename = f"Report_{uploaded_filename}_{datetime.datetime.now().strftime('%d-%m-%y_%H-%M-%S')}.pdf"
        pdf_path = os.path.join(reports_dir, default_filename)

        doc = SimpleDocTemplate(pdf_path, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch, leftMargin=0.5*inch, rightMargin=0.5*inch)
        styles = getSampleStyleSheet()
        styles['Title'].fontSize = 14
        styles['Heading1'].fontSize = 12
        styles['Normal'].fontSize = 8
        styles['Normal'].leading = 10

        story = [
            Paragraph("FileScope Forensic Report", styles['Title']),
            Spacer(1, 6),
        ]

        # 1. File Identification
        story.append(Paragraph("1. File Identification", styles['Heading1']))
        file_info = [
            ["File Name", self.analysis_results['metadata'].get('filename', 'N/A')],
            ["File Path", self.file_path],
            ["File Size", f"{os.path.getsize(self.file_path)} bytes"],
            ["File Type", self.analysis_results['magic']['Detected Type']],
            ["File Extension", self.analysis_results['magic']['Extension']],
            ["Timestamp (Creation)", self.analysis_results['metadata'].get('creation_time', 'N/A')],
            ["Timestamp (Modification)", self.analysis_results['metadata'].get('modification_time', 'N/A')],
            ["Timestamp (Access)", self.analysis_results['metadata'].get('access_time', 'N/A')],
            ["MD5", self.analysis_results['hashes'].get('md5', 'N/A')],
            ["SHA-1", self.analysis_results['hashes'].get('sha1', 'N/A')],
            ["SHA-256", self.analysis_results['hashes'].get('sha256', 'N/A')],
        ]
        table = Table(file_info, colWidths=[1.5*inch, 4.5*inch])
        table.setStyle([
            ('GRID', (0,0), (-1,-1), 0.5, (0,0,0)),
            ('FONT', (0,0), (-1,-1), 'Helvetica', 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEADING', (0,0), (-1,-1), 10)
        ])
        story.append(table)

        # 2. Detection Details
        story.append(Spacer(1, 6))
        story.append(Paragraph("2. Detection Details", styles['Heading1']))
        detection_info = [
            ["Detection Name / Signature ID", self.analysis_results['detection'].get('name', 'N/A')],
            ["Detection Engine(s)", "FileScope v1.1 (Static Analysis)"],
            ["Severity Level", self.analysis_results['risk']['Level']],
            ["Confidence Score", f"{self.analysis_results['risk']['Score']}/100"],
            ["Detection Timestamp", datetime.datetime.now().strftime('%d-%Y-%m_%H:%M_IST')],
        ]
        table = Table(detection_info, colWidths=[1.5*inch, 4.5*inch])
        table.setStyle([
            ('GRID', (0,0), (-1,-1), 0.5, (0,0,0)),
            ('FONT', (0,0), (-1,-1), 'Helvetica', 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEADING', (0,0), (-1,-1), 10)
        ])
        story.append(table)

        # 3. Behavioral Analysis
        story.append(Spacer(1, 6))
        story.append(Paragraph("3. Behavioral Analysis", styles['Heading1']))
        story.append(Paragraph("Note: Dynamic analysis not performed. Placeholder data shown.", styles['Normal']))
        behavior_info = [
            ["Processes Spawned", "N/A"],
            ["Network Activity", "N/A"],
            ["Registry Changes", "N/A"],
            ["File System Modifications", "N/A"],
            ["Persistence Mechanisms", "N/A"],
            ["Dropped Files", "N/A"],
            ["Command and Control (C2) Indicators", "N/A"],
        ]
        table = Table(behavior_info, colWidths=[1.5*inch, 4.5*inch])
        table.setStyle([
            ('GRID', (0,0), (-1,-1), 0.5, (0,0,0)),
            ('FONT', (0,0), (-1,-1), 'Helvetica', 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEADING', (0,0), (-1,-1), 10)
        ])
        story.append(table)

        # 4. Static Analysis Details
        story.append(Spacer(1, 6))
        story.append(Paragraph("4. Static Analysis Details", styles['Heading1']))
        static_info = [
            ["Strings Found", self.analysis_results['static'].get('strings', 'N/A')],
            ["Packers or Obfuscation", self.analysis_results['static'].get('obfuscation', 'N/A')],
            ["Embedded Resources", str(self.analysis_results['magic'].get('Embedded Objects', 'None'))],
            ["Digital Signature", self.analysis_results['static'].get('signature', 'N/A')],
            ["Imports/Exports", self.analysis_results['pe'].get('Analyzed', False) and self.analysis_results['pe'].get('Imports', 'N/A') or 'N/A'],
            ["Entropy Level", f"Mean {self.analysis_results['entropy']['Mean Entropy']}, Overall {self.analysis_results['entropy']['Overall Entropy']}"],
            ["Notes", self.analysis_results['static'].get('notes', 'N/A')],
        ]
        table = Table(static_info, colWidths=[1.5*inch, 4.5*inch])
        table.setStyle([
            ('GRID', (0,0), (-1,-1), 0.5, (0,0,0)),
            ('FONT', (0,0), (-1,-1), 'Helvetica', 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEADING', (0,0), (-1,-1), 10)
        ])
        story.append(table)

        # 5. Threat Intelligence
        story.append(Spacer(1, 6))
        story.append(Paragraph("5. Threat Intelligence", styles['Heading1']))
        story.append(Paragraph("Note: Threat intelligence requires external database integration. Placeholder data shown.", styles['Normal']))
        threat_info = [
            ["Known Malicious Hashes", "N/A"],
            ["Related Threat Campaigns", "N/A"],
            ["Reputation Data", "N/A"],
            ["MITRE ATT&CK Mapping", "N/A"],
        ]
        table = Table(threat_info, colWidths=[1.5*inch, 4.5*inch])
        table.setStyle([
            ('GRID', (0,0), (-1,-1), 0.5, (0,0,0)),
            ('FONT', (0,0), (-1,-1), 'Helvetica', 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEADING', (0,0), (-1,-1), 10)
        ])
        story.append(table)

        # 6. Remediation and Recommendations
        story.append(Spacer(1, 6))
        story.append(Paragraph("6. Remediation and Recommendations", styles['Heading1']))
        remediation_info = [
            ["Suggested Actions", "Quarantine the file immediately. DO NOT run on production systems." if self.analysis_results['risk']['Level'] == "HIGH" else "Verify before execution."],
            ["System Cleanup Instructions", "Remove file if confirmed malicious."],
            ["Indicators of Compromise (IOCs)", self.analysis_results['hashes'].get('sha256', 'N/A')],
            ["Preventive Measures", "Update antivirus and apply patches."],
        ]
        table = Table(remediation_info, colWidths=[1.5*inch, 4.5*inch])
        table.setStyle([
            ('GRID', (0,0), (-1,-1), 0.5, (0,0,0)),
            ('FONT', (0,0), (-1,-1), 'Helvetica', 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEADING', (0,0), (-1,-1), 10)
        ])
        story.append(table)

        # 7. Report Metadata
        story.append(Spacer(1, 6))
        story.append(Paragraph("7. Report Metadata", styles['Heading1']))
        import random
        metadata_info = [
            ["Report Generated By", "FileScope v2.0"],
            ["Analyst Name", "Pratyush"],
            ["Report Timestamp", datetime.datetime.now().strftime('%d-%Y-%m_%H:%M_IST')],
            ["Case or Incident ID", random.randint(0, 999)],
        ]
        table = Table(metadata_info, colWidths=[1.5*inch, 4.5*inch])
        table.setStyle([
            ('GRID', (0,0), (-1,-1), 0.5, (0,0,0)),
            ('FONT', (0,0), (-1,-1), 'Helvetica', 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEADING', (0,0), (-1,-1), 10)
        ])
        story.append(table)

        # 8 Entropy Graph
        graph_buffer = self.analyzer.generate_entropy_graph(self.analysis_results.get("entropy_chunks", []))
        if graph_buffer:
            story.append(Spacer(1, 6))
            story.append(Paragraph("Entropy Graph", styles['Heading1']))
            story.append(Image(graph_buffer, width=5*inch, height=2*inch))
            story.append(Spacer(1, 12))
            story.append(Paragraph("Generated by FileScope v2.0", styles['Normal']))

        doc.build(story)
        messagebox.showinfo("Success", f"PDF report saved to {pdf_path}")

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = FileScope(root)
    root.mainloop()