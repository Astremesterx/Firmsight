# 🗓️ Track 1 (Salif) — 20-Day Daily Implementation & Commit Roadmap
## Subsystem: Firmware Extraction & QEMU Emulation Engine

**Owner:** Salif (Team Lead)  
**Branch:** `salif`  
**Standard Operating Procedure Goal:** 20 distinct, verified daily commits with zero fluff to achieve 100% compliance on Mid Review and Final Review.

---

### Phase 1: Foundations & Architecture Identification (Days 1–5)
- [x] **Day 1:** Scaffolding, repository configuration, binary header parser, mock vulnerable firmware generator, and carving pipeline.
- [x] **Day 2:** Architecture & Endianness Resolver (`firmsight/emulator/arch.py`) and Mock NVRAM Simulator (`firmsight/emulator/nvram.py`).
- [x] **Day 3:** RootFS Sanitizer & Linker Bridge (`firmsight/emulator/rootfs_prep.py`): verify rootfs layout, create missing device directories, map QEMU static binaries, configure DNS resolver.
- [x] **Day 4:** Chroot Execution Sandbox (`firmsight/emulator/chroot_runner.py`): user-mode emulation runner executing target foreign binaries inside the prepared rootfs.
- [x] **Day 5:** Emulation Health Monitor (`firmsight/emulator/health_monitor.py`): detect segfaults, missing shared libraries, and exit codes.

### Phase 2: Services & Virtualization (Days 6–10) — *Mid Review Milestone*
- [x] **Day 6:** Web Server Service Launcher (`firmsight/emulator/service_launcher.py`): automatic detection and invocation of router HTTP daemons (`httpd`, `boa`, `goahead`).
- [x] **Day 7:** Mock Device Nodes Generator (`firmsight/emulator/device_nodes.py`): create simulated `/dev/null`, `/dev/urandom`, `/dev/nvram`, and flash memory blocks.
- [x] **Day 8:** Process Lifecycle Daemon (`firmsight/emulator/daemon.py`): asynchronous background process runner with live stdout/stderr capture pipes.
- [x] **Day 9:** Extraction Engine v2 (`firmsight/extractor/squashfs_handler.py`): advanced multi-partition SquashFS superblock parser (v3/v4), compression detection, and partition carver.
- [x] **Day 10 (Mid Review Milestone):** End-to-end emulation integration proof engine (`firmsight/emulator/integration_proof.py`): boots foreign ARM/MIPS web server binary in sandboxed environment, injects NVRAM, provisions device nodes, validates health diagnostics without crashes, and generates milestone verification report.

- [x] **Day 11:** Network Bridge Interface (`firmsight/emulator/network_bridge.py`): virtual TAP interface generation, bridge creation, local MAC assignment, unprivileged network shim fallback, and state persistence.
- [x] **Day 12:** Subnet & Virtual IP Routing Engine (`firmsight/emulator/network_router.py`): guest-to-host virtual routing, NVRAM subnet alignment (`lan_ipaddr`), host bridge IP binding, and route table emulation.
- [x] **Day 13:** IPTables Sandbox Rules & Sniffer Forwarding (`firmsight/emulator/firewall.py`): isolation policies (WAN egress block), Track 3 sniffer packet cloning (TEE mangle rules), host-to-guest control channel, software packet policy evaluator, and shell script export.
- [x] **Day 14 (Today):** Integration Bridge with Track 3 PCAP Engine (`firmsight/emulator/pcap_bridge.py`): binary PCAP v2.4 synthesizer, sniffer tap (fs-sniff0) controller, live flow generation (DNS/HTTP/ICMP/C2), and session manifest contract.
- [ ] **Day 15:** Port forwarding and external curl/HTTP trigger harness for emulated IoT web interface.

### Phase 4: Master Orchestrator, Integration & Polish (Days 16–20) — *Final Review Milestone*
- [ ] **Day 16:** FirmSight Master CLI Runner (`firmsight run <firmware.bin>`): one-command end-to-end pipeline.
- [ ] **Day 17:** Dynamic API hook injector for Track 2's Radare2 memory tracer (`r2pipe` hook port exposure).
- [ ] **Day 18:** Sandbox Teardown & Resource Cleanup (`firmsight/emulator/cleanup.py`): unmount filesystems, kill child QEMU processes, release virtual interfaces.
- [ ] **Day 19:** Comprehensive End-to-End Stress & Regression Testing with multiple firmware samples (ARM & MIPS).
- [ ] **Day 20 (Final Review Milestone):** Production Documentation, Architecture diagrams, and demonstration runbook.
