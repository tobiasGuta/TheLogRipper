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

## 🧠 TheLogRipper Versions Explained

### 🔹 TheLogRipper.ps1 (Stable)
This is the original version of the tool. It performs event log analysis based on specified Event IDs and highlights suspicious values in common fields like `DataValues`. It’s reliable and simple — ideal for general log inspection or incident triage.

- ✅ Takes `.evtx` file input
- ✅ Filters by Event ID
- ✅ Highlights suspicious terms (e.g., PowerShell, base64, etc.)
- ✅ Optional export to JSON/CSV

> Use this if you want a solid base log parser without too much complexity.

---

### 🔸 TheLogRipper2.0.ps1 (Advanced, In Progress)
This version builds on the original by introducing **conditional smart filtering** for authentication events like `4624` and `4625`. It prompts the user for more specific filtering **only when** those event types are present.

#### 🔍 Features added in 2.0:

- 🧠 Detection of authentication-related events
- 🔐 Optional filter prompts:
  - Logon Type(s) (e.g., 3, 10)
  - TargetUserName (e.g., Administrator)
  - IpAddress (e.g., 10.10.53.248)
- 🛡️ More fine-tuned triage for brute force, lateral movement, and failed logon attempts
- 💬 Future plans: coming soon

> ⚠️ This version is actively being enhanced. Expect rapid updates and experimental logic.

---

### 📌 TL;DR

| Version | Status | Best For | Features |
|--------|--------|----------|----------|
| `TheLogRipper.ps1` | ✅ Stable | Basic Event Log Analysis | Event ID filtering, suspicious term matching |
| `TheLogRipper2.0.ps1` | 🚧 In Progress | Threat Hunting / Logon Event Triage | Smart filters: LogonType, TargetUserName, IpAddress |

---

## Example Session

### 🛠️ Contributing / Feature Ideas

Pull requests and feature ideas are welcome. Some ideas on the roadmap:

- Command-line arg parsing
- Regex keyword filter input
- GUI version (WinForms or WPF)
- YAML/JSON config-driven automation


