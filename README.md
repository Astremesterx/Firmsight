# FirmSight: IoT Firmware Emulation & Dynamic Analysis Sandbox

![Domain](https://img.shields.io/badge/Domain-Reverse%20Engineering%20%2F%20IoT%20Security-red)
![Platform](https://img.shields.io/badge/Platform-Linux%20%2F%20WSL2-blue)
![Python](https://img.shields.io/badge/Python-3.10%2B-green)

**FirmSight** is an automated dynamic analysis sandbox designed to unpack, emulate, trace, and audit embedded IoT Linux firmware without requiring physical hardware. By virtualizing foreign CPU architectures (ARM/MIPS) through QEMU and trapping outbound network activity in real time, FirmSight empowers security researchers to dynamically uncover backdoors, botnet command-and-control (C2) beaconing, and memory vulnerabilities.

---

## 🔍 Core Architecture & Key Modules

1. **Extraction Engine (`firmsight/extractor/`)**:
   - Automated signature parsing for multi-format firmware images (SquashFS, CramFS, U-Boot, gzip).
   - Carves out embedded Linux root filesystems from raw binary blobs.
2. **Emulation Sandbox (`firmsight/emulator/`)**:
   - Boots foreign architecture binaries (ARM/MIPS) on host systems using QEMU (`qemu-user-static` and system emulation).
   - Simulates NVRAM and system peripherals to enable standalone web server execution.
3. **Dynamic Tracer (`firmsight/tracer/` & `firmsight/analyzer/`)**:
   - Hooks into emulated processes via Radare2 (`r2pipe`).
   - Dumps active memory maps (`/proc/$PID/maps`) and watches for dangerous function calls (`system`, `strcpy`).
4. **Network Interceptor & Behavioral Engine (`firmsight/network/`)**:
   - Traps guest traffic inside an isolated virtual bridge (`TUN/TAP`).
   - Inspects real-time PCAP traffic with `tcpdump` to alert on malicious C2 communications.
5. **Interactive Terminal UI (`firmsight/tui/`)**:
   - Built with Python `Textual` featuring live panes for Filesystem Tree, Emulation Status, Memory Maps, and Network Logs.

---

## 👥 Team Work Breakdown

Developed as an Infotact Solutions Advanced Cybersecurity Engineering project:

| Contributor | Dedicated Branch | Subsystem Domain |
| :--- | :--- | :--- |
| **Salif (Lead)** | `salif` | Firmware Extraction Pipeline, QEMU Emulation, Core Architecture |
| **Ashmi** | `Ashmi` | Radare2 Dynamic Memory Tracer, Vulnerability Analysis & Exploits |
| **Poornima** | `poornima` | Virtual Network Isolation, PCAP Behavioral Heuristics, Textual TUI |

See [docs/WORK_DISTRIBUTION.md](docs/WORK_DISTRIBUTION.md) for full week-by-week implementation milestones and review criteria.

---

## 🚀 Quickstart & Complete CLI Usage

### Prerequisites
- Windows 10/11 (PowerShell / CMD), Linux (Ubuntu/Debian/Kali), or WSL2
- Python 3.10+ (Standard library pure-Python engine with optional QEMU/Radare2 acceleration)

### Installation
```bash
git clone https://github.com/Astremesterx/Firmsight.git
cd Firmsight
pip install -r requirements.txt
```

---

## 🕹️ Command Reference & Manual Demonstration

### 1. One-Command Master End-to-End Emulation & Analysis
Executes the unified 10-stage pipeline: extraction -> architecture detection -> NVRAM virtualization -> network bridge & subnet routing -> firewall isolation -> PCAP capture -> daemon emulation -> dynamic tracing -> health probe -> executive HTML report generation.
```bash
python -m firmsight.cli run firmware_samples/vulnerable_router_arm.bin --force-shim --enable-tracing
```

### 2. Interactive Terminal UI (TUI) Dashboard
Launches the real-time terminal monitoring console displaying system status, rootfs tree, active network bindings, hooked libc APIs, and C2 threat gauge.
```bash
# Snapshot mode
python -m firmsight.cli tui

# Continuous interactive live refresh loop
python -m firmsight.cli tui --interactive
```

### 3. Track 2: Static Binary, Memory Layout & Dangerous API Audit
Inspects foreign ELF binaries for architecture, endianness, RWX memory segments (DEP/NX violations), and banned C library calls (`system`, `strcpy`, `popen`).
```bash
python -m firmsight.cli analyze firmware_samples/vulnerable_router_arm.bin
```

### 4. Track 2: Hardcoded Credential & Secret Scanner
Scans firmware images or extracted rootfs directories for leaked passwords, default logins (`admin:admin`), and unencrypted private keys (`RSA PRIVATE KEY`).
```bash
python -m firmsight.cli scan-creds firmware_samples/
```

### 5. Track 2: Proof-of-Concept Buffer Overflow Exploit
Delivers dynamic cyclic overflow payloads against the emulated web server and captures CPU register corruption (Instruction Pointer `PC` hijacking).
```bash
python -m firmsight.cli exploit --force-shim
```

### 6. Track 3: PCAP Deep Packet Inspection & C2 Botnet Threat Monitor
Performs Layer 2 through Layer 7 forensic analysis on `.pcap` captures, detecting IoT botnet check-ins (Mirai, Gafgyt) and unauthorized WAN egress.
```bash
python -m firmsight.cli pcap-analyze sandbox_workspace/captures/firmware_emulation_*.pcap
```

### 7. Executive HTML Security Audit Report
Synthesizes all findings into a responsive, visual executive dashboard report viewable in any web browser.
```bash
python -m firmsight.cli report
# Opens: sandbox_workspace/reports/firmware_audit_report.html
```

### 8. Graceful Teardown & Resource Cleanup
Reclaims all allocated system resources, unmounts rootfs binds, flushes netfilter firewall chains, closes socket proxies, and cleans temporary files.
```bash
python -m firmsight.cli teardown --force-shim
```

---

## 🧪 Comprehensive Test Suite (117 Tests)
FirmSight includes 117 automated unit and integration tests with **100% pass rate** across Windows native and Linux/WSL environments:
```bash
# Run all tests on Windows:
python -m unittest discover -s tests -p "test_*.py"

# Run all tests on Linux / WSL:
python3 -m unittest discover -s tests -p "test_*.py"
```

