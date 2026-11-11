# Browser History Forensic Analyser

A simple Python tool that checks a browser's history for suspicious activity,
like a digital detective. It has a desktop window (GUI) and needs no installation.

## Files
- `browser_forensic_analyser.py` - the engine (does the analysis)
- `browser_forensic_gui.py` - the window (run this one)

Keep both files in the **same folder**.

## How to run
```
python browser_forensic_gui.py
```
Then click **Load Demo Data**. The tool creates a sample (dummy) browser history,
so no real data is needed.

## What you can see in the window
- **History & Risk** - all websites, coloured by danger (red = high). Click a row to see why.
- **Top Domains** - most visited sites
- **Downloads** - downloaded files, risky ones highlighted
- **URL Checker** - paste any link to check if it looks dangerous
- **Full Report** - complete text report (can be saved)

## What the tool does
1. **Hashes the file (SHA-256)** before and after analysis. Same hash = evidence was not changed.
2. **Works on a copy**, so the original is never touched.
3. **Shows times in IST** (Indian time).
4. **Finds suspicious links**, such as:
   - fake brand names (e.g. `paypal-secure-login.xyz`)
   - web addresses made of numbers (e.g. `192.168.1.5`)
   - strange endings like `.xyz`, `.tk`, `.top`
   - login pages without HTTPS
   - `.exe` downloads
5. **Gives a risk level:** HIGH, MEDIUM or LOW.
6. **Flags night-time activity** (12 AM to 5 AM IST).

## Why the hash matters
A hash is a digital fingerprint of the file. If even one letter changes, the
fingerprint changes. Matching "before" and "after" hashes prove the evidence
was not tampered with.

## If something goes wrong
- `python is not recognized` -> try `py browser_forensic_gui.py`
- `No module named browser_forensic_analyser` -> put both files in the same folder
- `No module named tkinter` -> reinstall Python with the default options

