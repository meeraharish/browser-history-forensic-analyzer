#!/usr/bin/env python3
"""
Simple Browser History Forensic Analyser
----------------------------------------
Reads a Chrome / Edge / Brave / Firefox history database (SQLite),
and produces a forensic report with:

  1. Evidence integrity  -> SHA-256 / MD5 hash of the original file
  2. Timeline            -> readable timestamps (IST)
  3. Top visited sites   -> who the user talked to most
  4. Suspicious URLs     -> rule-based risk scoring (phishing, IP URLs, etc.)
  5. Risky downloads     -> .exe, .bat, .ps1 ... files
  6. Off-hours activity  -> browsing between 00:00 and 05:00

Usage:
    python browser_forensic_analyser.py --demo
    python browser_forensic_analyser.py --db "path/to/History"
    python browser_forensic_analyser.py --db "path/to/places.sqlite"

IMPORTANT: only analyse browsers/evidence you own or are authorised to examine.
"""

import argparse
import csv
import hashlib
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from collections import Counter
from datetime import datetime, timedelta
from urllib.parse import urlparse

# ----------------------------------------------------------------------
# 1. TIME HELPERS
# Chrome counts microseconds since 1601-01-01, Firefox since 1970-01-01.
# ----------------------------------------------------------------------
CHROME_EPOCH = datetime(1601, 1, 1)
UNIX_EPOCH = datetime(1970, 1, 1)

# Browsers store time in UTC. India is UTC + 5:30, so we add this offset.
# >>> CHANGE THIS LINE if you want another time zone <<<
IST_OFFSET = timedelta(hours=5, minutes=30)


def to_datetime(value, epoch):
    """Convert a raw browser timestamp into a normal datetime (IST)."""
    try:
        return epoch + timedelta(microseconds=int(value)) + IST_OFFSET
    except (OverflowError, ValueError, TypeError):
        return None


# ----------------------------------------------------------------------
# 2. EVIDENCE INTEGRITY
# In forensics we hash the original file first, so we can later prove
# that we did not change it.
# ----------------------------------------------------------------------
def hash_file(path):
    sha256, md5 = hashlib.sha256(), hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


# ----------------------------------------------------------------------
# 3. LOADING THE HISTORY
# We work on a COPY of the database so the original evidence is never
# touched (and so we avoid the "database is locked" error).
# ----------------------------------------------------------------------
def load_history(db_path):
    tmp_dir = tempfile.mkdtemp()
    tmp_db = os.path.join(tmp_dir, "evidence_copy.sqlite")
    shutil.copy2(db_path, tmp_db)

    conn = sqlite3.connect(tmp_db)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    visits, downloads = [], []

    if "urls" in tables:  # Chrome / Edge / Brave
        browser = "Chromium-based (Chrome/Edge/Brave)"
        for url, title, count, ts in conn.execute(
                "SELECT url, title, visit_count, last_visit_time FROM urls"):
            visits.append({"url": url, "title": title or "", "count": count,
                           "time": to_datetime(ts, CHROME_EPOCH)})
        if "downloads" in tables:
            for path, src, size, ts in conn.execute(
                    "SELECT target_path, tab_url, total_bytes, start_time FROM downloads"):
                downloads.append({"file": path, "source": src, "size": size,
                                  "time": to_datetime(ts, CHROME_EPOCH)})

    elif "moz_places" in tables:  # Firefox
        browser = "Mozilla Firefox"
        for url, title, count, ts in conn.execute(
                "SELECT url, title, visit_count, last_visit_date FROM moz_places "
                "WHERE last_visit_date IS NOT NULL"):
            visits.append({"url": url, "title": title or "", "count": count,
                           "time": to_datetime(ts, UNIX_EPOCH)})
    else:
        conn.close()
        shutil.rmtree(tmp_dir, ignore_errors=True)
        sys.exit("[!] Not a recognised Chrome/Firefox history database.")

    conn.close()
    shutil.rmtree(tmp_dir, ignore_errors=True)
    visits = [v for v in visits if v["time"]]
    visits.sort(key=lambda v: v["time"])
    return browser, visits, downloads


# ----------------------------------------------------------------------
# 4. SUSPICIOUS URL DETECTION (the cyber-security core)
# Each rule adds points. Total points decide the risk level.
# ----------------------------------------------------------------------
SUSPICIOUS_TLDS = (".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".zip", ".work")
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy")
PHISH_WORDS = ("login", "signin", "verify", "secure", "update", "account",
               "password", "wallet", "bank", "confirm")
RISKY_EXT = (".exe", ".bat", ".ps1", ".scr", ".msi", ".vbs", ".jar", ".apk", ".js", ".cmd")
# brand -> legitimate domains. Brand in hostname but NOT legit = impersonation.
BRANDS = {
    "paypal": ("paypal.com",),
    "google": ("google.com", "google.co.in", "googleapis.com", "googleusercontent.com"),
    "amazon": ("amazon.com", "amazon.in"),
    "microsoft": ("microsoft.com", "live.com"),
    "facebook": ("facebook.com",),
    "netflix": ("netflix.com",),
    "apple": ("apple.com",),
    "hdfcbank": ("hdfcbank.com",),
}
IP_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def analyse_url(url):
    """Return (score, [reasons]) for one URL."""
    score, reasons = 0, []
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    low = url.lower()

    if IP_REGEX.match(host):
        score += 3; reasons.append("Uses a raw IP address instead of a domain name")
    if host.endswith(".onion"):
        score += 3; reasons.append("Tor hidden service (.onion)")
    if host.endswith(SUSPICIOUS_TLDS):
        score += 2; reasons.append("Suspicious / commonly abused TLD")
    if "xn--" in host:
        score += 3; reasons.append("Punycode domain (possible look-alike / homograph attack)")
    if "@" in parsed.netloc:
        score += 3; reasons.append("'@' in URL (hides the real destination)")
    if host in SHORTENERS:
        score += 1; reasons.append("URL shortener (real destination hidden)")
    if host.count(".") >= 4:
        score += 1; reasons.append("Too many subdomains")
    if len(url) > 150:
        score += 1; reasons.append("Very long URL")
    if any(w in host for w in PHISH_WORDS) and "-" in host:
        score += 2; reasons.append("Phishing-style hostname (keyword + hyphen)")
    if parsed.scheme == "http" and any(w in low for w in PHISH_WORDS):
        score += 2; reasons.append("Login/account page over unencrypted HTTP")
    for brand, legit in BRANDS.items():
        if brand in host and not any(host == d or host.endswith("." + d) for d in legit):
            score += 3; reasons.append(f"Possible '{brand}' impersonation")
            break
    if parsed.path.lower().endswith(RISKY_EXT):
        score += 3; reasons.append("Link to an executable / script file")

    return score, reasons


def risk_level(score):
    if score >= 5:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "NONE"


# ----------------------------------------------------------------------
# 5. REPORT BUILDING
# ----------------------------------------------------------------------
def build_report(db_path, browser, visits, downloads, sha256, md5, sha256_after=None):
    L = []  # report lines
    add = L.append
    line = "=" * 72

    add(line)
    add("  BROWSER HISTORY FORENSIC REPORT")
    add(line)
    add(f"Generated (local) : {datetime.now():%Y-%m-%d %H:%M:%S}")
    add(f"Evidence file     : {db_path}")
    add(f"Browser type      : {browser}")
    add(f"SHA-256 (before)  : {sha256}")
    if sha256_after:
        add(f"SHA-256 (after)   : {sha256_after}")
        if sha256_after == sha256:
            add("Integrity check   : PASSED - hashes match, evidence was NOT modified")
        else:
            add("Integrity check   : FAILED - hashes differ, evidence was changed!")
    add(f"MD5               : {md5}")
    add("(Hash is taken before and after analysis; matching hashes prove nothing changed.)")
    add("All timestamps below are in IST.\n")

    # --- summary
    add("1. SUMMARY")
    add("-" * 72)
    add(f"Total history entries : {len(visits)}")
    if visits:
        add(f"First activity        : {visits[0]['time']}")
        add(f"Last activity         : {visits[-1]['time']}")

    # --- top domains
    domains = Counter()
    for v in visits:
        domains[urlparse(v["url"]).hostname or "unknown"] += max(v["count"], 1)
    add("\n2. TOP 10 VISITED DOMAINS")
    add("-" * 72)
    for d, c in domains.most_common(10):
        add(f"{c:5d} visits  {d}")

    # --- suspicious urls
    findings = []
    for v in visits:
        score, reasons = analyse_url(v["url"])
        v["score"], v["reasons"], v["level"] = score, reasons, risk_level(score)
        if score > 0:
            findings.append(v)
    findings.sort(key=lambda v: v["score"], reverse=True)

    levels = Counter(v["level"] for v in findings)
    add("\n3. SUSPICIOUS URLS")
    add("-" * 72)
    add(f"HIGH: {levels['HIGH']}   MEDIUM: {levels['MEDIUM']}   LOW: {levels['LOW']}\n")
    if not findings:
        add("No suspicious URLs found.")
    for v in findings:
        add(f"[{v['level']}] score={v['score']}  {v['time']}")
        add(f"   URL : {v['url'][:120]}")
        for r in v["reasons"]:
            add(f"   - {r}")
        add("")

    # --- downloads
    add("4. RISKY DOWNLOADS")
    add("-" * 72)
    risky = [d for d in downloads if (d["file"] or "").lower().endswith(RISKY_EXT)]
    if not downloads:
        add("No download table found in this database (normal for Firefox).")
    elif not risky:
        add("No risky file types downloaded.")
    for d in risky:
        add(f"{d['time']}  {d['file']}  ({d['size']} bytes)")
        add(f"   from: {d['source']}")

    # --- off hours
    add("\n5. OFF-HOURS ACTIVITY (00:00 - 05:00 IST)")
    add("-" * 72)
    night = [v for v in visits if 0 <= v["time"].hour < 5]
    add(f"{len(night)} entries during off-hours.")
    for v in night[:10]:
        add(f"{v['time']}  {v['url'][:90]}")

    # --- timeline
    add("\n6. TIMELINE (last 15 entries)")
    add("-" * 72)
    for v in visits[-15:]:
        add(f"{v['time']}  [{v['level']:<6}] {v['url'][:80]}")

    add("\n" + line)
    add("END OF REPORT")
    add(line)
    return "\n".join(L), visits


def save_outputs(report_text, visits, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    txt = os.path.join(out_dir, "forensic_report.txt")
    csv_path = os.path.join(out_dir, "history_analysis.csv")
    with open(txt, "w", encoding="utf-8") as f:
        f.write(report_text)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["time_ist", "url", "title", "visit_count", "risk_level", "score", "reasons"])
        for v in visits:
            w.writerow([v["time"], v["url"], v["title"], v["count"],
                        v["level"], v["score"], "; ".join(v["reasons"])])
    return txt, csv_path


# ----------------------------------------------------------------------
# 6. DEMO MODE - builds a fake Chrome history so you can test safely
# ----------------------------------------------------------------------
def create_demo_db(path):
    if os.path.exists(path):
        os.remove(path)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, "
                 "visit_count INTEGER, last_visit_time INTEGER)")
    conn.execute("CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, "
                 "tab_url TEXT, total_bytes INTEGER, start_time INTEGER)")

    def chrome_time(y, mo, d, h, mi):
        return int((datetime(y, mo, d, h, mi) - CHROME_EPOCH - IST_OFFSET).total_seconds() * 1_000_000)

    rows = [
        ("https://www.google.com/search?q=python+tutorial", "Google Search", 25, chrome_time(2026, 11, 9, 10, 15)),
        ("https://github.com/python/cpython", "GitHub - cpython", 12, chrome_time(2026, 11, 9, 10, 40)),
        ("https://www.youtube.com/watch?v=abc123", "YouTube", 30, chrome_time(2026, 11, 9, 13, 5)),
        ("https://stackoverflow.com/questions/1", "Stack Overflow", 9, chrome_time(2026, 11, 10, 9, 20)),
        ("http://192.168.45.12/admin/login.php", "Admin Login", 2, chrome_time(2026, 11, 10, 2, 30)),
        ("http://paypal-secure-login.xyz/verify/account", "PayPal Verification", 1, chrome_time(2026, 11, 10, 3, 10)),
        ("http://free-games-download.top/setup_installer.exe", "Free Games", 1, chrome_time(2026, 11, 10, 3, 25)),
        ("https://bit.ly/3xFakeLink", "Redirect", 1, chrome_time(2026, 11, 10, 3, 40)),
        ("http://xn--pypal-4ve.com/login", "Login", 1, chrome_time(2026, 11, 10, 4, 5)),
        ("https://www.amazon.in/dp/B09XYZ", "Amazon.in", 4, chrome_time(2026, 11, 10, 18, 0)),
        ("http://microsoft.com@evil-site.tk/update", "Update", 1, chrome_time(2026, 11, 10, 4, 30)),
        ("http://hdfcbank-account-verify.click/netbanking", "Netbanking", 1, chrome_time(2026, 11, 11, 1, 15)),
        ("https://www.wikipedia.org/wiki/Computer_forensics", "Computer forensics", 3, chrome_time(2026, 11, 11, 8, 45)),
    ]
    conn.executemany("INSERT INTO urls (url,title,visit_count,last_visit_time) VALUES (?,?,?,?)", rows)
    conn.execute("INSERT INTO downloads (target_path,tab_url,total_bytes,start_time) VALUES (?,?,?,?)",
                 ("C:\\Users\\demo\\Downloads\\setup_installer.exe",
                  "http://free-games-download.top/setup_installer.exe", 2457600,
                  chrome_time(2026, 11, 10, 3, 26)))
    conn.execute("INSERT INTO downloads (target_path,tab_url,total_bytes,start_time) VALUES (?,?,?,?)",
                 ("C:\\Users\\demo\\Downloads\\notes.pdf", "https://example.com/notes.pdf", 120000,
                  chrome_time(2026, 11, 9, 11, 0)))
    conn.commit()
    conn.close()
    return path


# ----------------------------------------------------------------------
# 7. MAIN
# ----------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Simple Browser History Forensic Analyser")
    ap.add_argument("--db", help="Path to Chrome 'History' or Firefox 'places.sqlite'")
    ap.add_argument("--demo", action="store_true", help="Analyse a generated sample database")
    ap.add_argument("--out", default="output", help="Folder for report files (default: output)")
    args = ap.parse_args()

    if args.demo:
        db_path = create_demo_db("demo_History")
        print(f"[*] Demo database created: {db_path}")
    elif args.db and os.path.isfile(args.db):
        db_path = args.db
    else:
        ap.error("Give --db <file> or use --demo")

    print("[*] Hashing evidence ...")
    sha256, md5 = hash_file(db_path)
    print("[*] Reading history (on a copy) ...")
    browser, visits, downloads = load_history(db_path)
    print("[*] Analysing ...\n")
    print("[*] Re-hashing evidence to verify integrity ...")
    sha256_after, _ = hash_file(db_path)
    report, visits = build_report(db_path, browser, visits, downloads, sha256, md5, sha256_after)
    print(report)
    txt, csv_path = save_outputs(report, visits, args.out)
    print(f"\n[+] Saved: {txt}\n[+] Saved: {csv_path}")


if __name__ == "__main__":
    main()
