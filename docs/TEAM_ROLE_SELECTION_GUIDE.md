# 🛡️ FirmSight — Team Work Distribution & Role Selection Guide

**Project Name:** FirmSight: IoT Firmware Emulation & Dynamic Analysis Sandbox  
**Domain:** Reverse Engineering / IoT Security  
**Repository:** [Astremesterx/Firmsight](https://github.com/Astremesterx/Firmsight.git)  
**Team Members:** Salif, Ashmi, Poornima  

---

## 📌 Executive Summary
**FirmSight** is an automated dynamic analysis sandbox designed to unpack, emulate, trace, and audit embedded IoT Linux firmware (routers, cameras, smart devices) without physical hardware.

To satisfy the **Infotact Solutions Standard Operating Procedures (SOP)**:
1. The project is divided into **3 modular, independent tracks** with equal weight and workload.
2. Each member works exclusively in their **own dedicated GitHub branch** (`salif`, `Ashmi`, `poornima`).
3. Each track has its **own isolated folder structure**, preventing Git merge conflicts.
4. Each member must maintain **daily commit discipline** (minimum 10 different commit days for Mid Review; 20 days for Final Review).

---

## 🗺️ System Architecture & Responsibility Map

```
                           +---------------------------------------+
                           |           RAW FIRMWARE BLOB           |
                           |          (e.g., router.bin)           |
                           +---------------------------------------+
                                               |
                                               v
+--------------------------------------------------------------------------------------------------+
| TRACK 1: Systems & Emulation (firmsight/extractor/ & firmsight/emulator/)                       |
| - Header signature scanning (SquashFS, CramFS, U-Boot, Gzip)                                     |
| - Filesystem carving & rootfs reconstruction                                                     |
| - QEMU foreign architecture virtualization (ARM/MIPS) + chroot + mock NVRAM                      |
+--------------------------------------------------------------------------------------------------+
             |                                                                 |
             v                                                                 v
+---------------------------------------------+   +------------------------------------------------+
| TRACK 2: Memory & Exploits (firmsight/tracer/ |   | TRACK 3: Network & TUI (firmsight/network/ &   |
|           & firmsight/analyzer/)            |   |          firmsight/tui/)                       |
| - ELF binary inspection & symbol parsing    |   | - Terminal UI dashboard (Textual)              |
| - Radare2 (r2pipe) memory hooking & maps    |   | - Virtual TUN/TAP bridge & tcpdump captures    |
| - Call-stack & buffer overflow detection    |   | - Real-time C2 beaconing alerts & threat meter |
| - Proof-of-concept web server exploit       |   | - Filesystem tree viewer & log streamer        |
+---------------------------------------------+   +------------------------------------------------+
```

---

## 🛠️ Detailed Track Breakdowns

---

### 🔹 TRACK 1: Firmware Extraction & QEMU Emulation Engineer
> **Domain:** Low-Level Systems, Linux Virtualization & Architecture Emulation  
> **Primary Directories:** `firmsight/extractor/`, `firmsight/emulator/`  
> **Key Technologies:** Python, Bash, QEMU (`qemu-arm-static`, `qemu-system-arm`), Binwalk, Linux `chroot`, SquashFS tools  

#### What You Will Build:
You are the engine of FirmSight. You take an opaque `.bin` firmware file, carve out its hidden Linux filesystem, set up a QEMU virtual CPU (ARM or MIPS) on an x86 host machine, and boot the extracted web server binary inside a chroot environment with simulated hardware variables (NVRAM).

#### Week-by-Week Deliverables:
- **Week 1: Firmware Carving Pipeline**
  - Binary header parser detecting magic bytes (SquashFS, CramFS, U-Boot, gzip).
  - Automated carving engine to extract root filesystems.
  - Generator for synthetic vulnerable IoT firmware images for offline testing.
- **Week 2: QEMU Bootstrapping & Chroot (Mid Review Milestone)**
  - Python and Bash wrappers configuring QEMU user-mode and system-mode emulation.
  - Setup chroot environment with foreign architecture libraries (`/lib`, `/bin`).
  - Implement mock NVRAM service to satisfy router binary startup checks.
  - **Milestone:** Successfully run an ARM binary on an x86 host without crashing.
- **Week 3: Virtualization Bridge Integration**
  - Isolate QEMU guest processes in sandbox containers.
  - Hook guest I/O and process lifecycle management.
- **Week 4: CLI Orchestrator & Graceful Teardown**
  - Implement the core CLI command (`firmsight run <firmware.bin>`).
  - Ensure safe teardown of QEMU processes, unmounting, and cleanup on exit.

#### Who should pick this?
- Someone who enjoys low-level Linux systems, virtualization, operating system internals, and command-line automation.

---

### 🔹 TRACK 2: Dynamic Memory Tracer & Exploit Analyst
> **Domain:** Binary Reverse Engineering, Memory Analysis & Vulnerability Research  
> **Primary Directories:** `firmsight/tracer/`, `firmsight/analyzer/`  
> **Key Technologies:** Python, Radare2, `r2pipe`, GDB / Pwntools, ELF Binary Format  

#### What You Will Build:
You are the security auditor. While Track 1 runs the emulated binary, you attach to its active memory using Radare2 (`r2pipe`). You inspect its memory segments (`/proc/$PID/maps`), track dynamic function calls, search for vulnerable functions like `strcpy()` or `system()`, and craft a buffer overflow exploit to prove the device's vulnerability.

#### Week-by-Week Deliverables:
- **Week 1: Static Binary Analysis Engine**
  - ELF header parser: identify target architecture, endianness, imported libraries, and exported symbols.
  - Static security auditor: scan binaries for dangerous functions (`strcpy`, `system`, `popen`) and hardcoded credentials.
- **Week 2: Radare2 Dynamic Memory Hooking (Mid Review Milestone)**
  - Implement the Radare2 daemon using `r2pipe`.
  - Attach to running emulated processes, dumping active virtual memory maps (`stack`, `heap`, code segments).
  - Export memory maps in JSON format for the UI dashboard to display.
- **Week 3: Behavioral Memory Watchdog**
  - Dynamic breakpoint tracer: hook sensitive API calls during execution.
  - Buffer overflow detector: watch for stack canary overwrites and invalid instruction pointers (`PC`/`EIP`).
- **Week 4: Exploit Testing Harness (Bonus Milestone)**
  - Develop a Proof-of-Concept (PoC) buffer overflow exploit script targeting the emulated web server.
  - Dynamic crash analyzer: capture register states at the point of crash and generate vulnerability reports.

#### Who should pick this?
- Someone interested in reverse engineering, binary exploitation, cybersecurity CTFs, and memory forensics.

---

### 🔹 TRACK 3: Network Interceptor, C2 Heuristics & Terminal UI Developer
> **Domain:** Network Forensics, Threat Detection & Terminal GUI Engineering  
> **Primary Directories:** `firmsight/network/`, `firmsight/tui/`  
> **Key Technologies:** Python `Textual` & `Rich`, Linux `iptables`, `TUN/TAP`, `tcpdump`, `dpkt` / `scapy`  

#### What You Will Build:
You are the eyes and ears of FirmSight. You build the rich interactive Terminal User Interface (TUI) where the user monitors the analysis. You also build the network sandbox: trapping the emulated device in an isolated virtual bridge, capturing all outbound network traffic with `tcpdump`, and analyzing PCAP packets in real-time to alert when malware tries to phone home to a Command-and-Control (C2) server.

#### Week-by-Week Deliverables:
- **Week 1: Terminal UI Scaffolding**
  - Design and scaffold the Python `Textual` dashboard.
  - Create interactive UI panes: "Filesystem Tree", "Emulation Status", and "Network Logs".
- **Week 2: TUI Live Integration (Mid Review Milestone)**
  - Connect TUI reactive widgets to live process outputs and extracted filesystem trees.
  - Implement dynamic memory map visualizer panel fed by Track 2.
  - **Milestone:** TUI displays real-time system state and browsable extracted filesystem.
- **Week 3: Virtual Network Isolation & PCAP Sniffer**
  - Create virtual bridge scripts (`TUN/TAP`) with iptables routing rules.
  - Route all emulator traffic through `tcpdump` to capture PCAP files.
  - Build real-time PCAP heuristic engine: alert when firmware queries suspicious DNS domains or contacts blacklisted C2 IPs.
- **Week 4: Threat Gauge & UI Polish**
  - Add an interactive visual "Threat Level" meter (Normal, Suspicious, Critical).
  - Add flashing intrusion banner popups, PCAP export feature, and graceful UI exit handling.

#### Who should pick this?
- Someone who enjoys frontend/TUI design (Python Textual), network packet analysis, and building real-time interactive tools.

---

## 📊 Summary Comparison Matrix

| Feature | Track 1 (Systems & Emulation) | Track 2 (Memory & Exploits) | Track 3 (Network & TUI) |
| :--- | :--- | :--- | :--- |
| **Main Tech** | QEMU, Binwalk, Bash, Python | Radare2, `r2pipe`, GDB, ELF | `Textual`, `tcpdump`, `scapy`, Linux TUN |
| **Key Output** | Unpacked rootfs & running QEMU | Memory dumps & buffer overflow PoC | Interactive dashboard & C2 alerts |
| **Git Folder** | `firmsight/extractor/`, `firmsight/emulator/` | `firmsight/tracer/`, `firmsight/analyzer/` | `firmsight/network/`, `firmsight/tui/` |
| **Effort / Week** | ~4-6 hours | ~4-6 hours | ~4-6 hours |
| **Daily Commit Focus** | Carving algorithms, QEMU configs, CLI | Binary parsers, r2 hooks, exploit scripts | TUI widgets, PCAP filters, network scripts |

---

## 🤝 Next Steps for the Team

1. **Review:** Salif, Ashmi, and Poornima read the 3 tracks above.
2. **Select:** Each member chooses one track based on their interests:
   - **Track 1:** Systems & Emulation
   - **Track 2:** Memory & Exploits
   - **Track 3:** Network & Terminal UI
3. **Confirm:** Reply with the chosen assignments (e.g., *Salif -> Track 1, Ashmi -> Track 2, Poornima -> Track 3*).
4. **Starter Templates:** Once decided, starter code, test suites, and documentation templates will be created for each branch so everyone can start committing immediately!
