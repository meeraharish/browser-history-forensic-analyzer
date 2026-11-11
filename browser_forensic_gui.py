#!/usr/bin/env python3
"""
Browser History Forensic Analyser - GUI (Tkinter)
-------------------------------------------------
Run:  python browser_forensic_gui.py

Keep this file in the SAME folder as browser_forensic_analyser.py,
because the GUI re-uses its functions (hashing, parsing, URL scoring).
"""

import os
import tkinter as tk
from collections import Counter
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlparse

import browser_forensic_analyser as bfa

HERE = os.path.dirname(os.path.abspath(__file__))

# colours used for risk levels
COLORS = {
    "HIGH": "#f8d7da",
    "MEDIUM": "#ffe5b4",
    "LOW": "#fff6bf",
    "NONE": "#ffffff",
}
TEXT_COLORS = {"HIGH": "#b00020", "MEDIUM": "#c75b00", "LOW": "#8a6d00", "NONE": "#1b7a2b"}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Browser History Forensic Analyser")
        self.geometry("1150x720")
        self.minsize(900, 600)

        # data holders
        self.db_path = None
        self.visits = []
        self.downloads = []
        self.report_text = ""

        style = ttk.Style(self)
        style.theme_use("clam")  # 'clam' shows row colours reliably on every OS
        style.configure("Treeview", rowheight=24)
        style.configure("Card.TLabel", font=("Segoe UI", 20, "bold"))
        style.configure("CardTitle.TLabel", font=("Segoe UI", 9))

        self.build_toolbar()
        self.build_cards()
        self.build_tabs()
        self.set_status("Ready. Click 'Load Demo Data' to begin.")

    # ------------------------------------------------------------------
    # LAYOUT
    # ------------------------------------------------------------------
    def build_toolbar(self):
        bar = ttk.Frame(self, padding=8)
        bar.pack(fill="x")
        ttk.Button(bar, text="▶  Load Demo Data", command=self.load_demo).pack(side="left", padx=3)
        ttk.Button(bar, text="📂  Open History File...", command=self.open_file).pack(side="left", padx=3)
        ttk.Button(bar, text="💾  Save Report...", command=self.save_report).pack(side="left", padx=3)

        self.info_var = tk.StringVar(value="No file loaded")
        ttk.Label(self, textvariable=self.info_var, padding=(10, 0), foreground="#444").pack(fill="x")
        self.integrity_label = tk.Label(self, text="", anchor="w", justify="left", font=("Segoe UI", 10, "bold"))
        self.integrity_label.pack(fill="x", padx=10)

    def build_cards(self):
        row = ttk.Frame(self, padding=8)
        row.pack(fill="x")
        self.card_vars = {}
        for key, title in [("total", "Total entries"), ("high", "HIGH risk"),
                           ("medium", "MEDIUM risk"), ("low", "LOW risk"),
                           ("night", "Off-hours (00-05 IST)")]:
            box = ttk.LabelFrame(row, text=title, padding=8)
            box.pack(side="left", expand=True, fill="x", padx=4)
            var = tk.StringVar(value="-")
            ttk.Label(box, textvariable=var, style="Card.TLabel").pack()
            self.card_vars[key] = var

    def build_tabs(self):
        # status bar is packed FIRST so it is always visible at the bottom
        self.status_var = tk.StringVar()
        ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w",
                  padding=4).pack(fill="x", side="bottom")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=4)

        # ---- Tab 1: history ------------------------------------------------
        t1 = ttk.Frame(self.nb, padding=6)
        self.nb.add(t1, text="  History & Risk  ")

        filt = ttk.Frame(t1)
        filt.pack(fill="x", pady=(0, 6))
        ttk.Label(filt, text="Show:").pack(side="left")
        self.level_var = tk.StringVar(value="ALL")
        box = ttk.Combobox(filt, textvariable=self.level_var, width=10, state="readonly",
                           values=["ALL", "HIGH", "MEDIUM", "LOW", "NONE"])
        box.pack(side="left", padx=5)
        box.bind("<<ComboboxSelected>>", lambda e: self.refresh_history())
        ttk.Label(filt, text="Search:").pack(side="left", padx=(15, 0))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self.refresh_history())
        ttk.Entry(filt, textvariable=self.search_var, width=35).pack(side="left", padx=5)

        cols = ("time", "risk", "score", "url")
        self.tree = ttk.Treeview(t1, columns=cols, show="headings", height=9)
        for c, w, t in [("time", 150, "Time (IST)"), ("risk", 80, "Risk"),
                        ("score", 60, "Score"), ("url", 700, "URL")]:
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="w")
        for lvl, col in COLORS.items():
            self.tree.tag_configure(lvl, background=col)
        sb = ttk.Scrollbar(t1, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="top", fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.show_details)

        ttk.Label(t1, text="Details (click a row above):").pack(anchor="w", pady=(8, 2))
        self.details = tk.Text(t1, height=10, wrap="word", state="disabled", bg="#fafafa")
        self.details.pack(fill="x")

        # ---- Tab 2: top domains -------------------------------------------
        t2 = ttk.Frame(self.nb, padding=6)
        self.nb.add(t2, text="  Top Domains  ")
        self.dom_tree = ttk.Treeview(t2, columns=("visits", "domain", "bar"), show="headings")
        for c, w, t in [("visits", 80, "Visits"), ("domain", 380, "Domain"), ("bar", 500, "")]:
            self.dom_tree.heading(c, text=t)
            self.dom_tree.column(c, width=w, anchor="w")
        self.dom_tree.pack(fill="both", expand=True)

        # ---- Tab 3: downloads ---------------------------------------------
        t3 = ttk.Frame(self.nb, padding=6)
        self.nb.add(t3, text="  Downloads  ")
        self.dl_tree = ttk.Treeview(t3, columns=("time", "risky", "file", "source"), show="headings")
        for c, w, t in [("time", 150, "Time (IST)"), ("risky", 80, "Risky?"),
                        ("file", 400, "File"), ("source", 450, "Downloaded from")]:
            self.dl_tree.heading(c, text=t)
            self.dl_tree.column(c, width=w, anchor="w")
        self.dl_tree.tag_configure("HIGH", background=COLORS["HIGH"])
        self.dl_tree.pack(fill="both", expand=True)

        # ---- Tab 4: URL checker -------------------------------------------
        t4 = ttk.Frame(self.nb, padding=15)
        self.nb.add(t4, text="  URL Checker  ")
        ttk.Label(t4, text="Type or paste any URL to check if it looks dangerous:",
                  font=("Segoe UI", 11)).pack(anchor="w")
        row = ttk.Frame(t4)
        row.pack(fill="x", pady=8)
        self.check_var = tk.StringVar()
        entry = ttk.Entry(row, textvariable=self.check_var, font=("Segoe UI", 11))
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda e: self.check_url())
        ttk.Button(row, text="Check", command=self.check_url).pack(side="left", padx=6)
        ttk.Label(t4, text="Try: http://paypal-secure-login.xyz/verify   or   https://www.google.com",
                  foreground="#666").pack(anchor="w")
        self.result_label = tk.Label(t4, text="", font=("Segoe UI", 18, "bold"))
        self.result_label.pack(anchor="w", pady=(20, 5))
        self.result_text = tk.Text(t4, height=10, wrap="word", state="disabled", bg="#fafafa")
        self.result_text.pack(fill="both", expand=True)

        # ---- Tab 5: full report -------------------------------------------
        t5 = ttk.Frame(self.nb, padding=6)
        self.nb.add(t5, text="  Full Report  ")
        self.report_box = tk.Text(t5, wrap="none", font=("Consolas", 10), state="disabled")
        ys = ttk.Scrollbar(t5, orient="vertical", command=self.report_box.yview)
        self.report_box.configure(yscrollcommand=ys.set)
        ys.pack(side="right", fill="y")
        self.report_box.pack(fill="both", expand=True)


    # ------------------------------------------------------------------
    # ACTIONS
    # ------------------------------------------------------------------
    def set_status(self, msg):
        self.status_var.set(msg)

    def load_demo(self):
        path = bfa.create_demo_db(os.path.join(HERE, "demo_History"))
        self.analyse(path)

    def open_file(self):
        path = filedialog.askopenfilename(
            title="Select a Chrome 'History' or Firefox 'places.sqlite' file")
        if path:
            self.analyse(path)

    def analyse(self, path):
        try:
            self.set_status("Hashing evidence and reading history ...")
            self.update_idletasks()
            sha256, md5 = bfa.hash_file(path)
            browser, visits, downloads = bfa.load_history(path)
            sha256_after, _ = bfa.hash_file(path)  # hash again to prove nothing changed
            report, visits = bfa.build_report(path, browser, visits, downloads, sha256, md5, sha256_after)
        except SystemExit as e:  # load_history calls sys.exit on bad files
            messagebox.showerror("Error", str(e))
            return
        except Exception as e:
            messagebox.showerror("Error", f"Could not analyse the file:\n{e}")
            return

        self.db_path, self.visits, self.downloads, self.report_text = path, visits, downloads, report
        self.info_var.set(f"File: {os.path.basename(path)}   |   Browser: {browser}")
        if sha256 == sha256_after:
            self.integrity_label.config(
                fg="#1b7a2b",
                text=f"✔ Integrity PASSED - hash before = hash after (evidence not modified)\n"
                     f"   SHA-256 before: {sha256}\n   SHA-256 after : {sha256_after}")
        else:
            self.integrity_label.config(fg="#b00020", text="✖ Integrity FAILED - file changed during analysis!")
        self.fill_cards()
        self.refresh_history()
        self.fill_domains()
        self.fill_downloads()
        self.set_text(self.report_box, report)
        self.set_status(f"Analysis complete - {len(visits)} entries loaded.")

    def fill_cards(self):
        c = Counter(v["level"] for v in self.visits)
        self.card_vars["total"].set(str(len(self.visits)))
        self.card_vars["high"].set(str(c["HIGH"]))
        self.card_vars["medium"].set(str(c["MEDIUM"]))
        self.card_vars["low"].set(str(c["LOW"]))
        self.card_vars["night"].set(str(sum(1 for v in self.visits if 0 <= v["time"].hour < 5)))

    def refresh_history(self):
        self.tree.delete(*self.tree.get_children())
        level = self.level_var.get()
        needle = self.search_var.get().strip().lower()
        # show most dangerous first
        order = sorted(range(len(self.visits)), key=lambda i: -self.visits[i]["score"])
        for i in order:
            v = self.visits[i]
            if level != "ALL" and v["level"] != level:
                continue
            if needle and needle not in v["url"].lower():
                continue
            self.tree.insert("", "end", iid=str(i), tags=(v["level"],),
                             values=(v["time"].strftime("%Y-%m-%d %H:%M"), v["level"], v["score"], v["url"]))

    def show_details(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        v = self.visits[int(sel[0])]
        lines = [f"URL        : {v['url']}",
                 f"Title      : {v['title'] or '(none)'}",
                 f"Time (IST) : {v['time']}",
                 f"Visits     : {v['count']}",
                 f"Risk       : {v['level']} (score {v['score']})"]
        if v["reasons"]:
            lines.append("Why it was flagged:")
            lines += [f"   • {r}" for r in v["reasons"]]
        else:
            lines.append("No suspicious indicators found.")
        self.set_text(self.details, "\n".join(lines))

    def fill_domains(self):
        self.dom_tree.delete(*self.dom_tree.get_children())
        counts = Counter()
        for v in self.visits:
            counts[urlparse(v["url"]).hostname or "unknown"] += max(v["count"], 1)
        top = counts.most_common(15)
        biggest = top[0][1] if top else 1
        for domain, n in top:
            self.dom_tree.insert("", "end", values=(n, domain, "█" * max(1, int(40 * n / biggest))))

    def fill_downloads(self):
        self.dl_tree.delete(*self.dl_tree.get_children())
        if not self.downloads:
            self.dl_tree.insert("", "end", values=("", "", "No downloads recorded in this database", ""))
            return
        for d in self.downloads:
            risky = (d["file"] or "").lower().endswith(bfa.RISKY_EXT)
            self.dl_tree.insert("", "end", tags=("HIGH",) if risky else (),
                                values=(d["time"].strftime("%Y-%m-%d %H:%M") if d["time"] else "",
                                        "YES" if risky else "no", d["file"], d["source"]))

    def check_url(self):
        url = self.check_var.get().strip()
        if not url:
            return
        if "://" not in url:
            url = "http://" + url
        score, reasons = bfa.analyse_url(url)
        level = bfa.risk_level(score)
        self.result_label.config(text=f"{level} RISK  (score {score})", fg=TEXT_COLORS[level])
        if reasons:
            text = "Reasons:\n" + "\n".join(f"  • {r}" for r in reasons)
        else:
            text = "No suspicious indicators found. (This does not guarantee a site is safe.)"
        self.set_text(self.result_text, text)

    def save_report(self):
        if not self.visits:
            messagebox.showinfo("Nothing to save", "Load some data first.")
            return
        folder = filedialog.askdirectory(title="Choose a folder to save the report")
        if folder:
            txt, csv_path = bfa.save_outputs(self.report_text, self.visits, folder)
            messagebox.showinfo("Saved", f"Saved:\n{txt}\n{csv_path}")

    @staticmethod
    def set_text(widget, text):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.config(state="disabled")


if __name__ == "__main__":
    App().mainloop()
