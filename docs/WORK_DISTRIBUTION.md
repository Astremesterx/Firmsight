# Infotact Solutions — Work Distribution & Project Execution Plan
## Project 2: FirmSight — IoT Firmware Emulation & Dynamic Analysis Sandbox

**Domain:** Reverse Engineering / IoT Security  
**Repository:** [Astremesterx/Firmsight](https://github.com/Astremesterx/Firmsight.git)  
**Standard Operating Procedure Version:** 1.0  

---

## 1. Team Composition & Role Assignment

Per Infotact Solutions Project Guidelines, each team member is assigned a dedicated subsystem and branch. Work is distributed equally to guarantee full modularity and zero branch collisions.

| Member Name | Branch Name | Project Role | Core Subsystem Focus |
| :--- | :--- | :--- | :--- |
| **Salif (Team Lead)** | `salif` | **Lead Systems Architect & Emulation Engineer** | Firmware Extraction Pipeline (`firmsight/extractor/`), QEMU Hardware Virtualization (`firmsight/emulator/`), Core Orchestrator |
| **Ashmi** | `Ashmi` | **Binary Reverse Engineer & Memory Auditor** | Radare2 / `r2pipe` Dynamic Memory Hooking (`firmsight/tracer/`), Buffer Overflow & Vulnerability Analysis (`firmsight/analyzer/`) |
| **Poornima** | `poornima` | **Network Security Engineer & TUI Developer** | Network Interception & Isolation (`firmsight/network/`), C2 Traffic Behavioral Heuristics, Textual Terminal UI (`firmsight/tui/`) |

---

## 2. Weekly Deliverables & Task Breakdown

### Week 1: Scaffolding, Extraction Engine & TUI Foundation
- **Salif (`salif`)**:
  - Implement Binary Header Parser (`firmsight/extractor/header_parser.py`) for magic bytes detection (SquashFS, CramFS, U-Boot, gzip).
  - Build Mock Vulnerable IoT Firmware Generator (`firmsight/extractor/mock_firmware.py`) for offline sandbox testing.
  - Implement Firmware Extraction Pipeline (`firmsight/extractor/extractor.py`) with Binwalk integration and fallback carving.
  - Automated tests for extraction verification.
- **Ashmi (`Ashmi`)**:
  - Implement ELF Binary Parser & Architecture Validator (`firmsight/analyzer/elf_parser.py`).
  - Build Static Vulnerability Scanner detecting dangerous symbols (`system`, `strcpy`, `popen`, hardcoded secrets).
- **Poornima (`poornima`)**:
  - Design & scaffold Textual Terminal UI layout (`firmsight/tui/app.py`).
  - Implement "Filesystem Tree" navigation pane and "Emulation Status" indicators.

### Week 2: QEMU Emulation, Memory Hooking & UI Integration (Mid Review)
- **Salif (`salif`)**:
  - Write QEMU bootstrapping scripts & Python wrappers (`firmsight/emulator/qemu_runner.py`) for ARM/MIPS foreign architectures.
  - Setup chroot execution environment, mock NVRAM daemon, and mock `/dev` peripherals.
  - Prove successful execution of foreign ARM binaries on x86 host without crashing.
- **Ashmi (`Ashmi`)**:
  - Implement Radare2 daemon (`firmsight/tracer/r2_hook.py`) using `r2pipe`.
  - Attach to running emulated processes and dump active virtual memory maps (`/proc/$PID/maps`).
- **Poornima (`poornima`)**:
  - Connect TUI event bus to live process outputs and Radare2 memory map visualizer.
  - Complete Mid-Project review milestone: display extracted filesystem tree and active process state.

### Week 3: Virtual Network Isolation & Behavioral C2 Analysis
- **Salif (`salif`)**:
  - Create virtual bridge interface (`TUN/TAP`) and Linux routing isolation scripts (`firmsight/network/bridge.sh`).
  - Ensure all outbound packets from QEMU are trapped and routed through `tcpdump`.
- **Ashmi (`Ashmi`)**:
  - Implement dynamic memory breakpoints and call-stack monitor to detect heap/stack corruption in real-time.
- **Poornima (`poornima`)**:
  - Build PCAP Stream Sniffer & C2 Behavioral Heuristic Engine (`firmsight/network/pcap_analyzer.py`).
  - Detect unauthorized DNS queries, malicious IP beacons, and notify the TUI alert stream.

### Week 4: Exploit Testing, Teardown & Final Polish (Final Review)
- **Salif (`salif`)**:
  - Build FirmSight CLI orchestrator (`firmsight/cli.py`) linking end-to-end extraction -> emulation -> monitoring -> cleanup.
  - Implement safe sandbox teardown (process killing, network bridge removal, unmounting).
- **Ashmi (`Ashmi`)**:
  - Develop Proof-of-Concept buffer overflow exploit against the emulated router web server (`tests/exploit_poc.py`).
- **Poornima (`poornima`)**:
  - Finalize Terminal UI polishing: "Threat Level" gauge, real-time alert popups, PCAP export button.
  - Verify graceful UI exit and system state cleanup.

---

## 3. GitHub Discipline & Compliance Rules

According to the **Infotact SOP**:
1. **Dedicated Branches**: Each member must commit **only** to their designated branch (`salif`, `Ashmi`, `poornima`).
2. **Main Branch**: The `main` branch is reserved for stable merged releases reviewed by the Team Lead.
3. **Commit Frequency**:
   - **Mid Review**: Minimum **10 different days** of commits across the 14 days preceding review.
   - **Final Review**: Minimum **20 different days** of commits with **no zero-commit gaps**.
4. **Commit Quality**:
   - Every commit must contain meaningful progress (code, unit tests, configurations, or detailed technical documentation).
   - Empty commits or single-character modifications are flagged as invalid.
5. **Team Communication & Unresponsive Member Policy**:
   - Response time expectation is within 24 hours.
   - If a member is unresponsive for >48 hours, they are officially flagged to Infotact mentor, and the remaining members step up to fulfill commit day requirements.
