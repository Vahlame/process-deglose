# process-deglose

[![GitHub release](https://img.shields.io/github/v/release/Vahlame/process-deglose)](https://github.com/Vahlame/process-deglose/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Vahlame/process-deglose/actions/workflows/ci.yml/badge.svg)](https://github.com/Vahlame/process-deglose/actions)

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
- **Communication:** named pipes, firewall rules, hosts file, system proxy, top network talkers per process, services on listening ports

## How it behaves

- **Read-only.** It queries WMI/CIM, performance counters, `fltmc`, `logman` and read-only kernel APIs. It never disables services, edits the registry, installs drivers, or applies changes.
- **Local first.** Everything lands in the Desktop folder. The raw kernel trace is deleted after digesting unless you pass `-KeepEtl`.
- **Your call.** You decide what to send. The report even contains a "Contract for the analyzing agent" so the other tool knows the limits (don't touch OS-critical stuff, etc.).
- **Honest about limits.** Kernel-hidden *processes* are out of reach, but since v2.2 every loaded kernel *module* is enumerated — a driver can't hide from the report.

## Guía de uso

### Primer run (recomendado)

```text
Run-Snapshot.bat            ← eleva con UAC y captura TODO (incluye kernel + ETW 15 s)
```

Espera ~1–2 min. Al terminar verás la carpeta en el Desktop. Abre el `.md` para revisar a simple vista; el `.json` es el data-dump completo para herramientas.

### Qué enviar al optimizador

- **Carpeta completa** (`.md` + `.json`) — máximo contexto.
- O solo el `.md` si la IA solo lee texto. El archivo `SEND_THIS_FOLDER_TO_THE_OTHER_AI.txt` lo recuerda por ti.

### Secciones del reporte (para interpretar)

| Sección | Para qué sirve |
| --- | --- |
| TL;DR | Resumen de 15 líneas: equipo, RAM, top de procesos, kernel, firewall, problemas |
| Decision facts | ChassisHint/DiskHint/GpuHint/PowerHint — la IA debe condicionar cada tweak a estos |
| RAM y commit | Cuánto puedes recortar en realidad (working set = cota superior) |
| Procesos | Qué corre, de quién, con qué líneas de comando (secretos redactados) |
| Kernel surface | Drivers y módulos cargados, pool, tiempos por núcleo, procesos ocultos |
| Communication surface | Quién se conecta con quién: puertos, firewall, pipes, proxy |
| Collection issues | Lo que no se pudo leer y por qué (necesita admin, etc.) |

### Switches de conveniencia

| Switch | Efecto |
| --- | --- |
| `-SkipSignature` | Mucho más rápido (no firma digital por binario) |
| `-SkipNetwork` / `-SkipTasks` / `-SkipHeavy` | Salta red / tareas / Uninstall+AppX |
| `-NoJson` / `-NoExplorer` / `-OutDir D:\path` | Sin JSON / sin abrir carpeta / destino propio |
| `-SkipKernel` | Salta todo el paso kernel |
| `-SkipKernelTrace` | Igual que arriba pero solo la traza ETW |
| `-KernelTraceSeconds N` | Duración de la traza (5–120, default 15) |
| `-KernelTraceDeep` | ETW con file/network/registry/thread (traza grande) |
| `-KeepEtl` | Conserva el `.etl` crudo en la carpeta de reporte |
| `-Help` | Muestra la ayuda de uso y sale |

### Solución de problemas

- **Secciones kernel vacías** → ejecuta con `Run-Snapshot.bat` (elevado), no el NoAdmin.
- **Muy lento** → añade `-SkipSignature -SkipKernelTrace`.
- **SmartScreen/Defender al ejecutar el .bat** → es un script sin firma; usa "More info → Run anyway" o ejecuta desde PowerShell: `powershell -NoProfile -ExecutionPolicy Bypass -File snapshot.ps1`.
- **El reporte no cambia la máquina** — si quieres aplicar tweaks, hazlo después con otra herramienta y con respaldo.

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
| `Collect-CommunicationSurface.ps1` | Pipes, firewall, hosts, proxy, top talkers |
| `Run-Snapshot.bat` | Double-click launcher, requests UAC |
| `Run-Snapshot-NoAdmin.bat` | Launcher without elevation |

## License

MIT — úsalo, modifícalo y compártelo libremente. Ver [LICENSE](LICENSE).
