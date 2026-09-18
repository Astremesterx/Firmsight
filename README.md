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

## 🚀 Quickstart & Installation

### Prerequisites
- Linux host or Windows Subsystem for Linux (WSL2 with Kali Linux / Ubuntu)
- Python 3.10+
- `binwalk`, `qemu-user-static`, `radare2`, `tcpdump`

```bash
# Clone the repository
git clone https://github.com/Astremesterx/Firmsight.git
cd Firmsight

# Switch to your team branch
git checkout <your-branch-name>

# Install Python dependencies
pip install -r requirements.txt
```

### Running Tests
```bash
pytest tests/ -v
```
