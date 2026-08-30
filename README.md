# process-deglose

A **read-only Windows inventory** that takes a full picture of your PC — including kernel-level telemetry — and writes it to a local report. Nothing is installed, nothing is changed, nothing leaves your machine unless you send it.

It exists so you can hand that report to another tool or AI and get back **performance recommendations** (RAM cuts, background noise, universal IF-THEN tweaks) tailored to your exact hardware.

---

## 🚀 Install & run in 2 minutes

**Requirements:** Windows 10 or 11. PowerShell 5.1 (built into Windows — nothing to install).

1. **Get the code** — click the green **Code** button → **Download ZIP**, unzip anywhere (or `git clone` if you know git).
2. **Double-click `Run-Snapshot.bat`** (the one without "NoAdmin").
3. **Click "Yes" on the UAC prompt** (elevation unlocks kernel modules, pool, minifilters and a 15-second kernel trace).
4. **Wait ~1 minute.** It prints progress like `[13/13] Aggregates + Markdown...`.
5. **Grab the report** — a new folder appears on your Desktop:

```
Desktop\process-deglose-report-<COMPUTER>-<timestamp>\
├── snapshot-<COMPUTER>-<timestamp>.md    ← the main report (readable)
├── snapshot-<COMPUTER>-<timestamp>.json  ← the full data dump (for tools/AI)
└── SEND_THIS_FOLDER_TO_THE_OTHER_AI.txt  ← what to send and how
```

6. **Send that folder** (or just the `.md`) to the AI or optimization tool that will analyze it.

> 💡 The first run also drops a **"Process snapshot for AI"** shortcut on your Desktop, so next time it's just double-click → UAC → done.

**Can't elevate?** Use `Run-Snapshot-NoAdmin.bat`. Coverage is weaker (pool tags, minifilters and the ETW trace need admin) and the report says so — still useful.

---

## What it captures

- **Machine facts:** laptop vs desktop, HDD/SSD/NVMe, GPU (incl. `nvidia-smi`), AC vs battery, RAM sticks, commit, page files, CPU/BIOS/board, resolution/refresh
- **Power & boot:** power schemes, fast startup/hibernate, `bcdedit`, Secure Boot, TPM, VBS/HVCI, BitLocker
- **Software:** processes (with command lines, redacted secrets), services, startup entries, scheduled tasks, installed programs, AppX packages, optional features
- **Performance policy:** visual effects, Game Bar, HAGS, MMCSS, prefetch, telemetry, Edge/Copilot/Widgets policies
- **Security posture:** Defender, other AV, firewall profiles, 7-day error digest
- **Kernel surface:** loaded kernel modules, kernel-side process list, pool tags (RAMMap-style), per-core CPU time shares, kernel counters, registered kernel drivers, minifilter stack, short ETW kernel trace (process/image/disk, aggregated)
- **Extended telemetry:** routes, ARP/ND, DNS cache/servers, adapter statistics, UDP endpoints, local accounts/groups/shares, logon sessions, thermal zones, battery wear, audio, monitors

## How it behaves

- **Read-only.** It queries WMI/CIM, performance counters, `fltmc`, `logman` and read-only kernel APIs. It never disables services, edits the registry, installs drivers, or applies changes.
- **Local first.** Everything lands in the Desktop folder. The raw kernel trace is deleted after digesting unless you pass `-KeepEtl`.
- **Your call.** You decide what to send. The report even contains a "Contract for the analyzing agent" so the other tool knows the limits (don't touch OS-critical stuff, etc.).
- **Honest about limits.** Kernel-hidden *processes* are out of reach, but since v2.1 every loaded kernel *module* is enumerated — a driver can't hide from the report.

## From a prompt (optional)

```text
powershell -NoProfile -ExecutionPolicy Bypass -File snapshot.ps1
```

Switches: `-SkipSignature` (faster), `-SkipNetwork`, `-SkipTasks`, `-SkipHeavy` (skip Uninstall + AppX), `-NoJson`, `-NoExplorer`, `-OutDir D:\path`. Kernel: `-SkipKernel`, `-SkipKernelTrace`, `-KernelTraceSeconds N` (default 15, 5–120), `-KernelTraceDeep` (adds file/network/registry/thread ETW keywords), `-KeepEtl` (keep the raw `.etl`).

## Files

| File | What it does |
| --- | --- |
| `snapshot.ps1` | Main collector (13 steps) |
| `Collect-SystemSurface.ps1` | Hardware, power, security, policy |
| `Collect-KernelSurface.ps1` | Kernel-level telemetry (modules, pool, ETW…) |
| `Collect-ExtendedSurface.ps1` | Network, accounts, thermal, battery… |
| `Run-Snapshot.bat` | Double-click launcher, requests UAC |
| `Run-Snapshot-NoAdmin.bat` | Launcher without elevation |

## License

All rights reserved — feel free to use it on your own machines. (No license file yet.)
