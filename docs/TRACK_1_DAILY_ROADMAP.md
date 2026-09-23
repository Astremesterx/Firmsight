# 🗓️ Track 1 (Salif) — 20-Day Daily Implementation & Commit Roadmap
## Subsystem: Firmware Extraction & QEMU Emulation Engine

**Owner:** Salif (Team Lead)  
**Branch:** `salif`  
**Standard Operating Procedure Goal:** 20 distinct, verified daily commits with zero fluff to achieve 100% compliance on Mid Review and Final Review.

---

### Phase 1: Foundations & Architecture Identification (Days 1–5)
- [x] **Day 1:** Scaffolding, repository configuration, binary header parser, mock vulnerable firmware generator, and carving pipeline.
- [ ] **Day 2 (Today):** Architecture & Endianness Resolver (`firmsight/emulator/arch.py`) and Mock NVRAM Simulator (`firmsight/emulator/nvram.py`).
- [ ] **Day 3:** RootFS Sanitizer & Linker Bridge (`firmsight/emulator/rootfs_prep.py`): verify rootfs layout, create missing device directories, map QEMU static binaries.
- [ ] **Day 4:** Chroot Execution Sandbox (`firmsight/emulator/chroot_runner.py`): execute guest binaries inside chroot via `qemu-arm-static`.
- [ ] **Day 5:** Emulation Health Monitor (`firmsight/emulator/health_monitor.py`): detect segfaults, missing shared libraries, and exit codes.

### Phase 2: Services & Virtualization (Days 6–10) — *Mid Review Milestone*
- [ ] **Day 6:** Web Server Service Launcher (`firmsight/emulator/service_launcher.py`): automatic detection and invocation of router HTTP daemons (`httpd`, `boa`, `goahead`).
- [ ] **Day 7:** Mock Device Nodes Generator: create simulated `/dev/null`, `/dev/urandom`, `/dev/nvram`, and flash memory blocks.
- [ ] **Day 8:** Process Lifecycle Daemon (`firmsight/emulator/daemon.py`): asynchronous background process runner with live stdout/stderr capture pipes.
- [ ] **Day 9:** Extraction Engine v2 (`firmsight/extractor/squashfs_handler.py`): advanced multi-partition SquashFS handling.
- [ ] **Day 10 (Mid Review Milestone):** End-to-end emulation proof: boot foreign ARM web server binary on host machine without crashes.

### Phase 3: Network Virtualization & Sandboxing (Days 11–15)
- [ ] **Day 11:** Network Bridge Interface (`firmsight/emulator/network_bridge.py`): virtual TAP interface generation.
- [ ] **Day 12:** Subnet & IP configuration for guest-to-host virtual routing.
- [ ] **Day 13:** IPTables sandbox rules: isolation and packet forwarding to sniffer interface.
- [ ] **Day 14:** Integration bridge with Track 3's PCAP capture engine.
- [ ] **Day 15:** Port forwarding and external curl/HTTP trigger harness for emulated IoT web interface.

### Phase 4: Master Orchestrator, Integration & Polish (Days 16–20) — *Final Review Milestone*
- [ ] **Day 16:** FirmSight Master CLI Runner (`firmsight run <firmware.bin>`): one-command end-to-end pipeline.
- [ ] **Day 17:** Dynamic API hook injector for Track 2's Radare2 memory tracer (`r2pipe` hook port exposure).
- [ ] **Day 18:** Sandbox Teardown & Resource Cleanup (`firmsight/emulator/cleanup.py`): unmount filesystems, kill child QEMU processes, release virtual interfaces.
- [ ] **Day 19:** Comprehensive End-to-End Stress & Regression Testing with multiple firmware samples (ARM & MIPS).
- [ ] **Day 20 (Final Review Milestone):** Production Documentation, Architecture diagrams, and demonstration runbook.
