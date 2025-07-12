# Contributing to TheLogRipper

First off thanks for checking out **TheLogRipper**! Whether you're fixing a bug, adding a feature, improving documentation, or just suggesting an idea  you're helping make this tool better for everyone. 

This guide will walk you through how to get involved.

---

## Requirements

- PowerShell 5.1+ (Windows)
- A `.evtx` event log file for testing (can use samples from Event Viewer)

> **Optional (for contributors):** Git, VS Code, and PowerShell ISE make development smoother.

---

## Submitting Changes

### 1. Fork the Repo
Click "Fork" on the repo and clone it locally:
```sh
git clone https://github.com/tobiasGuta/TheLogRippe.git
```

### 2. Create a Branch
```sh
git checkout -b feature/add-your-feature
```

### 3. Make Changes
Edit either `TheLogRipper.ps1` or `TheLogRipper2.0.ps1`. Add comments to explain complex logic. Use consistent formatting and variable casing.

### 4. Test Your Code
Run the script with various `.evtx` files and test filters thoroughly.

> Make sure you test both the basic flow and the advanced filtering logic (for Event IDs like 4624/4625).

### 5. Commit + Push
```sh
git add .
git commit -m "Added: new filter for X"
git push origin feature/add-your-feature
```

### 6. Open a Pull Request
Go to your forked repo and click "New Pull Request." Fill out the PR template:

- What you added/changed
- Why it's useful
- How to test it

---

## Code Style Guidelines

- Use `PascalCase` or `camelCase` for variable names
- Align `Write-Host` output for readability
- Use `-ForegroundColor` for meaningful visual context
- Comment logic-heavy sections

---

## Feature Ideas (PRs welcome!)
- CLI argument support (`-EventIDs`, `-Username`, etc.)
- Export to custom directory
- More event ID presets (Sysmon, AppLocker, etc.)
- GUI front-end
- YAML/JSON config loading

---

##  Need Help?
Open an issue with the label `question` or `help wanted`, and we’ll take a look ASAP.

Thanks again for contributing to TheLogRipper!

— Tobias 
