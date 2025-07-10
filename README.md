# TheLogRipper

**TheLogRipper** is an interactive PowerShell tool for parsing and analyzing Windows Event Log (`.evtx`) files. It extracts key fields, flags suspicious behavior, and offers export to JSON or CSV. Built for threat hunters, SOC analysts, and DFIR workflows.

---

## 🔍 Why Use TheLogRipper?

Because Event Viewer sucks when you're on a mission.

Manual `.evtx` analysis is slow, clunky, and frustrating. TheLogRipper gives you:
- CLI-based interaction
- Highlighted suspicious strings
- Fast extraction of useful metadata
- Optional export for offline analysis or reporting

Whether you're triaging a system post-breach or trying to track a specific type of event this is your drop-in forensic blade.

---

## ⚙️ Features

- Interactive prompt-based interface
- Supports multiple Event IDs at once
- Detects suspicious strings (`.exe`, `powershell`, `shutdown`, `Invoke-*`, `bypass`, etc.)
- Outputs full parsed event data in readable format
- Optional export to:
  - JSON (`TheLogRipper_output.json`)
  - CSV (`TheLogRipper_output.csv`)
- Compatible with PowerShell 5.1+ (no PowerShell 7 required)
- Infinite loop mode for multiple log investigations

---

## 📥 Usage

### 1. Clone the repo:
```bash
git clone https://github.com/yourusername/TheLogRipper.git
cd TheLogRipper
```
### 2. Run the script:
```bash
.\TheLogRipper.ps1
```

### 3. Follow prompts:
- Enter path to .evtx file
- Enter Event ID(s) to search (comma-separated)
- Choose to export or not
- Type exit when done

### Suspicious Value Detection
TheLogRipper flags fields containing known suspicious keywords like:

- .exe, cmd.exe, powershell, base64
- shutdown, curl, wget
- Invoke-*, bypass, wscript
- Base64 strings and encoded payloads
- These are highlighted in red for fast visual triage.

## Example Session

https://github.com/user-attachments/assets/2a4708f7-54cd-49dd-955d-f3f4cbce252b



