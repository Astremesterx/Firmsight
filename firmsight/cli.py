"""Command-line interface for FirmSight."""

import argparse
import json
import sys
from pathlib import Path

from firmsight.core.config import SAMPLES_DIR, ensure_directories
from firmsight.emulator.arch import ArchitectureResolver
from firmsight.emulator.chroot_runner import ChrootRunner
from firmsight.emulator.daemon import DaemonManager
from firmsight.emulator.device_nodes import DeviceNodeManager
from firmsight.emulator.firewall import FirewallManager
from firmsight.emulator.health_monitor import HealthMonitor
from firmsight.emulator.integration_proof import EmulationProofEngine
from firmsight.emulator.network_bridge import NetworkBridgeManager
from firmsight.emulator.network_router import NetworkRouter
from firmsight.emulator.nvram import MockNVRAM
from firmsight.emulator.pcap_bridge import PCAPBridge
from firmsight.emulator.port_forward import HTTPTriggerHarness, PortForwarder
from firmsight.emulator.rootfs_prep import RootFSPreparer
from firmsight.emulator.service_launcher import ServiceLauncher
from firmsight.extractor.extractor import FirmwareExtractor
from firmsight.extractor.header_parser import HeaderParser
from firmsight.extractor.mock_firmware import MockFirmwareBuilder
from firmsight.extractor.squashfs_handler import SquashFSHandler


def main() -> None:
    """FirmSight main CLI router."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    ensure_directories()
    parser = argparse.ArgumentParser(
        prog="firmsight",
        description="FirmSight: IoT Firmware Emulation & Dynamic Analysis Sandbox",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: generate-mock
    mock_parser = subparsers.add_parser(
        "generate-mock", help="Generate synthetic vulnerable IoT firmware for testing"
    )
    mock_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=str(SAMPLES_DIR / "vulnerable_router_arm.bin"),
        help="Path to save synthetic firmware image",
    )

    # Command: scan
    scan_parser = subparsers.add_parser(
        "scan", help="Scan firmware binary for magic headers and partitions"
    )
    scan_parser.add_argument("file", type=str, help="Firmware binary path")

    # Command: extract
    extract_parser = subparsers.add_parser(
        "extract", help="Carve and unpack Linux root filesystem from firmware"
    )
    extract_parser.add_argument("file", type=str, help="Firmware binary path")
    extract_parser.add_argument(
        "--output-dir",
        "-o",
        type=str,
        default=None,
        help="Custom output directory for extracted filesystem",
    )

    # Command: identify-arch
    arch_parser = subparsers.add_parser(
        "identify-arch", help="Detect CPU architecture and QEMU emulator for a binary or rootfs"
    )
    arch_parser.add_argument("target", type=str, help="Path to ELF binary or rootfs directory")

    # Command: init-nvram
    nvram_parser = subparsers.add_parser(
        "init-nvram", help="Initialize mock NVRAM configuration for a rootfs"
    )
    nvram_parser.add_argument(
        "rootfs", type=str, help="Path to extracted rootfs directory"
    )

    # Command: prep-rootfs
    prep_parser = subparsers.add_parser(
        "prep-rootfs", help="Sanitize rootfs and bridge QEMU static binaries for chroot execution"
    )
    prep_parser.add_argument(
        "rootfs", type=str, help="Path to extracted rootfs directory"
    )

    # Command: execute
    exec_parser = subparsers.add_parser(
        "execute", help="Execute a foreign architecture binary inside the rootfs sandbox"
    )
    exec_parser.add_argument("rootfs", type=str, help="Path to extracted rootfs directory")
    exec_parser.add_argument("binary", type=str, help="Relative path to binary inside rootfs (e.g. usr/sbin/httpd)")
    exec_parser.add_argument("--timeout", "-t", type=int, default=5, help="Execution timeout in seconds")
    exec_parser.add_argument("--args", nargs="*", default=[], help="Arguments to pass to target binary")

    # Command: diagnose
    diag_parser = subparsers.add_parser(
        "diagnose", help="Execute binary and run automated emulation health diagnostics"
    )
    diag_parser.add_argument("rootfs", type=str, help="Path to extracted rootfs directory")
    diag_parser.add_argument("binary", type=str, help="Relative path to binary inside rootfs (e.g. usr/sbin/httpd)")
    diag_parser.add_argument("--timeout", "-t", type=int, default=5, help="Execution timeout in seconds")

    # Command: launch-web
    web_parser = subparsers.add_parser(
        "launch-web", help="Auto-discover and launch embedded router web server inside QEMU"
    )
    web_parser.add_argument("rootfs", type=str, help="Path to extracted rootfs directory")
    web_parser.add_argument("--port", "-p", type=int, default=80, help="Web server port (default: 80)")
    web_parser.add_argument("--timeout", "-t", type=int, default=5, help="Execution timeout in seconds")

    # Command: init-dev
    dev_parser = subparsers.add_parser(
        "init-dev", help="Provision simulated Linux character devices and MTD flash blocks"
    )
    dev_parser.add_argument("rootfs", type=str, help="Path to extracted rootfs directory")
    dev_parser.add_argument("--no-mtd", action="store_true", help="Skip creating MTD flash partition blocks")

    # Command: daemon
    daemon_parser = subparsers.add_parser(
        "daemon", help="Manage asynchronous background emulator processes"
    )
    daemon_sub = daemon_parser.add_subparsers(dest="daemon_action", help="Daemon action")

    d_start = daemon_sub.add_parser("start", help="Spawn a background daemon")
    d_start.add_argument("rootfs", type=str, help="Path to extracted rootfs directory")
    d_start.add_argument("binary", type=str, help="Relative path to binary inside rootfs")
    d_start.add_argument("--name", "-n", type=str, default=None, help="Custom daemon identifier")

    daemon_sub.add_parser("list", help="List all background daemons")

    d_status = daemon_sub.add_parser("status", help="Get daemon status and recent logs")
    d_status.add_argument("name", type=str, help="Daemon name")

    d_stop = daemon_sub.add_parser("stop", help="Stop a background daemon")
    d_stop.add_argument("name", type=str, help="Daemon name")

    # Command: inspect-squashfs
    squash_parser = subparsers.add_parser(
        "inspect-squashfs", help="Deep inspection and multi-partition carving of SquashFS superblocks"
    )
    squash_parser.add_argument("file", type=str, help="Firmware binary path")
    squash_parser.add_argument("--carve", action="store_true", help="Carve identified partitions to disk")
    squash_parser.add_argument("--output-dir", "-o", type=str, default=None, help="Output directory for carved partitions")

    # Command: emulate-proof (Mid-Review Milestone)
    proof_parser = subparsers.add_parser(
        "emulate-proof",
        help="End-to-End emulation integration verification proof (Mid Review Milestone)",
    )
    proof_parser.add_argument(
        "target",
        type=str,
        help="Path to firmware image (.bin) or extracted rootfs directory",
    )
    proof_parser.add_argument(
        "--port", "-p", type=int, default=8080, help="Port to bind web service (default: 8080)"
    )
    proof_parser.add_argument(
        "--binary", "-b", type=str, default=None, help="Explicit service binary override relative to rootfs"
    )
    proof_parser.add_argument(
        "--markdown-out", "-m", type=str, default=None, help="Output path to export Markdown proof report"
    )
    proof_parser.add_argument(
        "--json-out", "-j", type=str, default=None, help="Output path to export JSON proof telemetry"
    )

    # Command: network (Virtual Network Bridge & TAP Interface Manager)
    net_parser = subparsers.add_parser("network", help="Virtual Network Bridge & TAP Interface Manager")
    net_sub = net_parser.add_subparsers(dest="net_action", required=True)

    # network setup
    n_setup = net_sub.add_parser("setup", help="Provision virtual TAP device and network bridge")
    n_setup.add_argument("--tap", type=str, default="fs-tap0", help="TAP interface name (default: fs-tap0)")
    n_setup.add_argument("--bridge", type=str, default="fs-br0", help="Bridge interface name (default: fs-br0)")
    n_setup.add_argument("--force-shim", action="store_true", help="Force unprivileged shim mode")

    # network status
    net_sub.add_parser("status", help="Query virtual bridge network status")

    # network teardown
    n_tear = net_sub.add_parser("teardown", help="Tear down virtual network bridge and TAP devices")
    n_tear.add_argument("--tap", type=str, default=None, help="TAP interface name")
    n_tear.add_argument("--bridge", type=str, default=None, help="Bridge interface name")

    # network route-setup
    r_setup = net_sub.add_parser("route-setup", help="Configure subnet and guest-to-host virtual routing")
    r_setup.add_argument("--bridge", type=str, default="fs-br0", help="Bridge interface name (default: fs-br0)")
    r_setup.add_argument("--guest-ip", type=str, default="192.168.1.1", help="Emulated IoT router IP (default: 192.168.1.1)")
    r_setup.add_argument("--netmask", type=str, default="255.255.255.0", help="Subnet mask (default: 255.255.255.0)")
    r_setup.add_argument("--force-shim", action="store_true", help="Force unprivileged shim mode")

    # network route-status
    net_sub.add_parser("route-status", help="Query virtual routing and subnet configurations")

    # network route-teardown
    r_tear = net_sub.add_parser("route-teardown", help="Tear down virtual IP routing configurations")
    r_tear.add_argument("--bridge", type=str, default=None, help="Bridge interface name")

    # network firewall-apply
    fw_apply = net_sub.add_parser("firewall-apply", help="Apply sandbox isolation and sniffer forwarding rules")
    fw_apply.add_argument("--bridge", type=str, default="fs-br0", help="Bridge interface name (default: fs-br0)")
    fw_apply.add_argument("--sniffer", type=str, default="fs-sniff0", help="Sniffer interface name (default: fs-sniff0)")
    fw_apply.add_argument("--guest-ip", type=str, default="192.168.1.1", help="Guest IP (default: 192.168.1.1)")
    fw_apply.add_argument("--host-ip", type=str, default="192.168.1.254", help="Host IP (default: 192.168.1.254)")
    fw_apply.add_argument("--subnet", type=str, default="192.168.1.0/24", help="Subnet CIDR (default: 192.168.1.0/24)")
    fw_apply.add_argument("--no-wan-block", action="store_true", help="Disable outbound WAN egress blocking")
    fw_apply.add_argument("--no-sniffer-mirror", action="store_true", help="Disable Track 3 sniffer packet mirroring")
    fw_apply.add_argument("--force-shim", action="store_true", help="Force unprivileged shim mode")

    # network firewall-status
    net_sub.add_parser("firewall-status", help="Query sandbox firewall rules and isolation status")

    # network firewall-flush
    fw_flush = net_sub.add_parser("firewall-flush", help="Flush sandbox firewall rules and purge state")
    fw_flush.add_argument("--force-shim", action="store_true", help="Force unprivileged shim mode")

    # network firewall-test
    fw_test = net_sub.add_parser("firewall-test", help="Simulate packet evaluation against active sandbox rules")
    fw_test.add_argument("--src", type=str, default="192.168.1.1", help="Source IP (default: 192.168.1.1)")
    fw_test.add_argument("--dst", type=str, default="8.8.8.8", help="Destination IP (default: 8.8.8.8)")
    fw_test.add_argument("--port", type=int, default=80, help="Destination port (default: 80)")
    fw_test.add_argument("--proto", type=str, default="tcp", help="Protocol (default: tcp)")
    fw_test.add_argument("--in-iface", type=str, default="fs-br0", help="Ingress interface (default: fs-br0)")
    fw_test.add_argument("--out-iface", type=str, default=None, help="Egress interface (default: None)")

    # network capture-start
    cap_start = net_sub.add_parser("capture-start", help="Start PCAP packet capture on sniffer interface")
    cap_start.add_argument("--interface", type=str, default="fs-sniff0", help="Sniffer interface (default: fs-sniff0)")
    cap_start.add_argument("--bridge", type=str, default="fs-br0", help="Bridge interface (default: fs-br0)")
    cap_start.add_argument("--output", type=str, default=None, help="Output .pcap file path")
    cap_start.add_argument("--filter", type=str, default=None, help="BPF capture filter expression")
    cap_start.add_argument("--guest-ip", type=str, default="192.168.1.1", help="Guest IP (default: 192.168.1.1)")
    cap_start.add_argument("--host-ip", type=str, default="192.168.1.254", help="Host IP (default: 192.168.1.254)")
    cap_start.add_argument("--force-shim", action="store_true", help="Force unprivileged synthesizer shim mode")

    # network capture-stop
    net_sub.add_parser("capture-stop", help="Stop active PCAP packet capture session")

    # network capture-status
    net_sub.add_parser("capture-status", help="Query active PCAP packet capture session and telemetry")

    # network capture-inject
    cap_inj = net_sub.add_parser("capture-inject", help="Inject a synthetic packet into the active PCAP capture")
    cap_inj.add_argument("--type", type=str, default="http_request", choices=["http_request", "http_response", "dns_query", "icmp_ping", "c2_beacon"], help="Packet type")
    cap_inj.add_argument("--src", type=str, default=None, help="Source IP override")
    cap_inj.add_argument("--dst", type=str, default=None, help="Destination IP override")
    cap_inj.add_argument("--port", type=int, default=80, help="Destination port")

    # network capture-flow
    cap_flow = net_sub.add_parser("capture-flow", help="Synthesize and inject realistic IoT traffic flows into PCAP")
    cap_flow.add_argument("--count", type=int, default=5, help="Number of packets to synthesize (default: 5)")
    cap_flow.add_argument("--inject-c2", action="store_true", help="Inject simulated malicious C2 beacon packet")

    # network forward-add
    pf_add = net_sub.add_parser("forward-add", help="Add port forwarding rule from host to emulated guest")
    pf_add.add_argument("--host-port", type=int, required=True, help="Host port to bind on localhost")
    pf_add.add_argument("--guest-port", type=int, default=80, help="Target emulated device port (default: 80)")
    pf_add.add_argument("--host-ip", type=str, default="127.0.0.1", help="Host interface IP (default: 127.0.0.1)")
    pf_add.add_argument("--guest-ip", type=str, default="192.168.1.1", help="Guest router IP (default: 192.168.1.1)")
    pf_add.add_argument("--mode", type=str, choices=["auto", "socket-proxy", "iptables-nat"], default="auto", help="Forwarding mode")
    pf_add.add_argument("--force-shim", action="store_true", help="Force unprivileged socket-proxy mode")

    # network forward-list
    net_sub.add_parser("forward-list", help="List all active host-to-guest port forwarding channels")

    # network forward-remove
    pf_rm = net_sub.add_parser("forward-remove", help="Remove an active port forwarding rule")
    pf_rm.add_argument("--rule-id", type=str, required=True, help="ID of rule to remove (e.g. pf-8080-80)")

    # network http-probe
    http_pb = net_sub.add_parser("http-probe", help="Execute an external HTTP probe against forwarded web interface")
    http_pb.add_argument("--host-port", type=int, default=8080, help="Host forwarded port (default: 8080)")
    http_pb.add_argument("--path", type=str, default="/", help="URI path to probe (default: /)")
    http_pb.add_argument("--method", type=str, default="GET", choices=["GET", "POST", "HEAD"], help="HTTP method")

    # network http-scan
    http_sc = net_sub.add_parser("http-scan", help="Run automated diagnostic endpoint scan on emulated web daemon")
    http_sc.add_argument("--host-port", type=int, default=8080, help="Host forwarded port (default: 8080)")

    args = parser.parse_args()

    if args.command == "generate-mock":
        builder = MockFirmwareBuilder(args.output)
        output_file = builder.build()
        print(f"[+] Successfully generated mock firmware: {output_file}")
        print(f"[+] File size: {output_file.stat().st_size} bytes")

    elif args.command == "scan":
        target = Path(args.file)
        if not target.exists():
            print(f"[-] Error: File not found: {target}", file=sys.stderr)
            sys.exit(1)
        header_parser = HeaderParser(target)
        matches = header_parser.scan()
        print(f"[*] Signature scan results for: {target.name}")
        print("-" * 70)
        print(f"{'Offset (Hex)':<15} {'Name':<30} {'Arch':<10}")
        print("-" * 70)
        for m in matches:
            arch = m.architecture_hint or "N/A"
            print(f"0x{m.offset:08X}     {m.name:<30} {arch:<10}")
        print("-" * 70)

    elif args.command == "extract":
        target = Path(args.file)
        if not target.exists():
            print(f"[-] Error: File not found: {target}", file=sys.stderr)
            sys.exit(1)
        extractor = FirmwareExtractor(output_base=args.output_dir)
        res = extractor.extract(target)
        if res.success:
            print(f"[+] Extraction SUCCESSFUL!")
            print(f"[+] Architecture detected: {res.architecture}")
            print(f"[+] RootFS Location: {res.rootfs_dir}")
            print(f"[+] Total files extracted: {len(res.extracted_files)}")
            if res.critical_artifacts:
                print("\n[+] Critical Artifacts Found:")
                for k, v in res.critical_artifacts.items():
                    print(f"    - {k}: {v[:60]}...")
        else:
            print(f"[-] Extraction failed: {res.error}", file=sys.stderr)
    elif args.command == "identify-arch":
        target = Path(args.target)
        if not target.exists():
            print(f"[-] Error: Target not found: {target}", file=sys.stderr)
            sys.exit(1)

        info = None
        if target.is_dir():
            info = ArchitectureResolver.resolve_rootfs(target)
            if not info:
                print(f"[-] Could not infer architecture from binaries in {target}", file=sys.stderr)
                sys.exit(1)
        else:
            info = ArchitectureResolver.resolve_binary(target)

        print(f"[+] Architecture Resolved: {info.architecture.upper()} ({info.bitness}-bit, {info.endianness}-endian)")
        print(f"    - Machine: {info.machine_name} (code: 0x{info.machine_code:02x})")
        print(f"    - Required QEMU User Emulator:   {info.qemu_static_bin}")
        print(f"    - Matching QEMU System Target:  {info.qemu_system_bin}")

    elif args.command == "init-nvram":
        rootfs = Path(args.rootfs)
        if not rootfs.exists() or not rootfs.is_dir():
            print(f"[-] Error: RootFS directory not found: {rootfs}", file=sys.stderr)
            sys.exit(1)

        nvram = MockNVRAM()
        ini_file = nvram.write_to_rootfs(rootfs)
        print(f"[+] Mock NVRAM successfully initialized in: {ini_file.parent}")
        print(f"[+] Generated: nvram.ini, nvram.conf, nvram_env.sh")
    elif args.command == "prep-rootfs":
        rootfs = Path(args.rootfs)
        if not rootfs.exists() or not rootfs.is_dir():
            print(f"[-] Error: RootFS directory not found: {rootfs}", file=sys.stderr)
            sys.exit(1)

        preparer = RootFSPreparer(rootfs)
        report = preparer.prepare()
        print(f"[+] RootFS Preparation: {report.status.upper()}")
        print(f"[+] Target Architecture: {report.architecture}")
        print(f"[+] QEMU Static Binary: {report.qemu_static_bin} (copied: {report.qemu_copied})")
        print(f"[+] Created Directories: {len(report.created_directories)}")
        print(f"[+] Configured Files: {', '.join(report.configured_files) or 'None'}")
        if report.warnings:
            print("[!] Notices / Warnings:")
            for w in report.warnings:
                print(f"    - {w}")

    elif args.command == "execute":
        rootfs = Path(args.rootfs)
        if not rootfs.exists() or not rootfs.is_dir():
            print(f"[-] Error: RootFS directory not found: {rootfs}", file=sys.stderr)
            sys.exit(1)

        runner = ChrootRunner(rootfs)
        res = runner.run(args.binary, args=args.args, timeout=args.timeout)
        print(f"[+] Execution completed in {res.duration_seconds}s (Mode: {res.emulation_mode})")
        print(f"[+] Exit Code: {res.exit_code} (Timed out: {res.timed_out})")
        if res.stdout:
            print(f"\n[+] Standard Output:\n{res.stdout.strip()}")
        if res.stderr:
            print(f"\n[!] Standard Error:\n{res.stderr.strip()}")

    elif args.command == "diagnose":
        rootfs = Path(args.rootfs)
        if not rootfs.exists() or not rootfs.is_dir():
            print(f"[-] Error: RootFS directory not found: {rootfs}", file=sys.stderr)
            sys.exit(1)

        runner = ChrootRunner(rootfs)
        exec_res = runner.run(args.binary, timeout=args.timeout)
        report = HealthMonitor.diagnose(exec_res, binary_rel_path=args.binary, rootfs_dir=rootfs)

        print(f"[*] Diagnostics Report for: {report.binary_path}")
        print(f"[+] Emulation Status: {report.status}")
        print(f"[+] Exit Code:        {report.exit_code}")
        if report.signal_name:
            print(f"[!] Crash Signal:     {report.signal_name}")
        if report.missing_libraries:
            print(f"[!] Missing Libs:     {', '.join(report.missing_libraries)}")
        if report.issues:
            print("\n[!] Issues Detected:")
            for issue in report.issues:
                print(f"    - [{issue.severity}] {issue.description}")
        if report.recommendations:
            print("\n[+] Recommended Remediation:")
            for rec in report.recommendations:
                print(f"    - {rec}")

    elif args.command == "launch-web":
        rootfs = Path(args.rootfs)
        if not rootfs.exists() or not rootfs.is_dir():
            print(f"[-] Error: RootFS directory not found: {rootfs}", file=sys.stderr)
            sys.exit(1)

        launcher = ServiceLauncher(rootfs)
        discovered = launcher.discover_services()
        print(f"[*] Discovered {len(discovered)} potential embedded services:")
        for svc in discovered:
            print(f"    - {svc.name} ({svc.binary_path}) -> Default Port: {svc.default_port}")

        if not discovered:
            print("[-] No web servers found to launch.", file=sys.stderr)
            sys.exit(1)

        res = launcher.launch(port=args.port, timeout=args.timeout)
        print(f"\n[+] Launched Service: {res.service.name} (Port: {res.port})")
        print(f"[+] Status:           {'RUNNING' if res.is_running else 'FAILED'}")
        print(f"[+] Execution Mode:   {res.execution.emulation_mode}")
        if res.notes:
            for note in res.notes:
                print(f"    - {note}")
        if res.execution.stdout:
            print(f"\n[+] Daemon Output:\n{res.execution.stdout.strip()}")
        if res.execution.stderr:
            print(f"\n[!] Daemon Errors / Warnings:\n{res.execution.stderr.strip()}")

    elif args.command == "init-dev":
        rootfs = Path(args.rootfs)
        if not rootfs.exists() or not rootfs.is_dir():
            print(f"[-] Error: RootFS directory not found: {rootfs}", file=sys.stderr)
            sys.exit(1)

        manager = DeviceNodeManager(rootfs)
        report = manager.provision_all(create_mtd=not args.no_mtd)
        print(f"[+] Device Node Provisioning: {report.status.upper()}")
        print(f"[+] Provisioning Mode:        {report.provisioning_mode}")
        print(f"[+] Created Device Nodes:     {', '.join(report.created_nodes)}")
        if report.mtd_partitions:
            print(f"[+] Mock MTD Partitions:     {', '.join(report.mtd_partitions)}")

    elif args.command == "daemon":
        mgr = DaemonManager()
        if args.daemon_action == "start":
            d_proc = mgr.spawn(args.rootfs, args.binary, name=args.name)
            print(f"[+] Started daemon '{d_proc.name}' with PID {d_proc.pid}")
            print(f"[+] Streaming logs to: {d_proc.log_file}")
        elif args.daemon_action == "list":
            daemons = mgr.list_active()
            print(f"[*] Total Tracked Daemons: {len(daemons)}")
            for d in daemons:
                state = "ALIVE" if d.is_alive else "STOPPED"
                print(f"    - {d.name:<15} (PID: {d.pid:<6}) [{state}] Uptime: {d.uptime_seconds}s")
        elif args.daemon_action == "status":
            st = mgr.poll(args.name)
            if not st:
                print(f"[-] No daemon found with name: {args.name}", file=sys.stderr)
                sys.exit(1)
            state = "ALIVE" if st.is_alive else "STOPPED"
            print(f"[+] Daemon:  {st.name} (PID: {st.pid}) [{state}]")
            print(f"[+] Uptime:  {st.uptime_seconds}s")
            if st.recent_logs:
                print("\n[+] Recent Logs:")
                for line in st.recent_logs:
                    print(f"    {line}")
        elif args.daemon_action == "stop":
            stopped = mgr.stop(args.name)
            if stopped:
                print(f"[+] Successfully stopped daemon '{args.name}'.")
            else:
                print(f"[-] Daemon '{args.name}' not found or already stopped.", file=sys.stderr)

    elif args.command == "inspect-squashfs":
        target = Path(args.file)
        if not target.exists():
            print(f"[-] Error: Firmware file not found: {target}", file=sys.stderr)
            sys.exit(1)

        superblocks = SquashFSHandler.scan_superblocks(target)
        print(f"[*] SquashFS Partition Scan for: {target.name}")
        print(f"[*] Discovered {len(superblocks)} valid SquashFS superblock(s):\n")

        for i, sb in enumerate(superblocks, 1):
            print(f"--- Partition #{i} ---")
            print(f"  Offset:        0x{sb.offset:08X} ({sb.offset} bytes)")
            print(f"  Version:       SquashFS {sb.version} ({sb.endianness}-endian)")
            print(f"  Compression:   {sb.compression_name.upper()} (ID: {sb.compression_id})")
            print(f"  Block Size:    {sb.block_size} bytes ({sb.block_size // 1024} KB)")
            print(f"  Inodes:        {sb.inode_count}")
            print(f"  Payload Size:  {sb.bytes_used} bytes ({sb.bytes_used / (1024*1024):.2f} MB)")
            print(f"  Created:       {sb.creation_time_str}")

            if args.carve:
                out_dir = Path(args.output_dir) if args.output_dir else target.parent / f"{target.stem}_partitions"
                res = SquashFSHandler.carve_and_unpack(target, sb, out_dir, partition_idx=i)
                print(f"  [+] Carved Blob:  {res.carved_blob_path}")
                if res.unpacked_dir and res.unpacked_dir.exists():
                    print(f"  [+] Unpacked Dir: {res.unpacked_dir} ({res.file_count} files)")
                if res.error:
                    print(f"  [!] Notice:       {res.error}")
            print()

    elif args.command == "emulate-proof":
        target = Path(args.target)
        if not target.exists():
            print(f"[-] Error: Target path not found: {target}", file=sys.stderr)
            sys.exit(1)

        engine = EmulationProofEngine()
        print(f"[*] Initiating End-to-End Emulation Proof for: {target.name}")
        print("[*] Verifying Phase 1 (Foundations) and Phase 2 (Virtualization) subsystems...\n")

        if target.is_dir():
            report = engine.verify_rootfs(
                rootfs_dir=target,
                port=args.port,
                binary_override=args.binary,
            )
        else:
            report = engine.verify_firmware(
                firmware_path=target,
                port=args.port,
                binary_override=args.binary,
            )

        print("--- [MID-REVIEW MILESTONE REPORT] ---")
        print(f"Target:       {report.target_path.name}")
        print(f"Arch:         {report.architecture} ({report.endianness}-endian)")
        print(f"Foreign Mode: {'Yes (QEMU Static)' if report.is_foreign_arch else 'Host Native'}")
        print(f"Verdict:      {report.overall_verdict}\n")

        print("Verification Matrix:")
        for c in report.checks:
            mark = "[PASS]" if c.passed else "[FAIL]"
            print(f"  {mark:6} {c.check_id:14} [{c.phase}]: {c.title}")
            print(f"         └─ {c.details}")

        if args.markdown_out:
            md_path = Path(args.markdown_out)
            md_path.parent.mkdir(parents=True, exist_ok=True)
            md_path.write_text(report.export_markdown(), encoding="utf-8")
            print(f"\n[+] Exported Markdown proof report to: {md_path}")

        if args.json_out:
            json_path = Path(args.json_out)
            json_path.parent.mkdir(parents=True, exist_ok=True)
            json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
            print(f"[+] Exported JSON telemetry to: {json_path}")

        if report.overall_verdict != "PASSED":
            sys.exit(1)

    elif args.command == "network":
        net_mgr = NetworkBridgeManager()

        if args.net_action == "setup":
            print(f"[*] Provisioning virtual network bridge '{args.bridge}' with TAP '{args.tap}'...")
            status = net_mgr.setup_bridge_network(
                tap_name=args.tap,
                bridge_name=args.bridge,
                force_shim=args.force_shim,
            )
            print(f"[+] Network Bridge Status: {'ACTIVE' if status.is_active else 'INACTIVE'}")
            print(f"[+] Operational Mode:     {status.mode}")
            print(f"[+] Bridge Interface:     {status.bridge_name}")
            for t in status.tap_interfaces:
                print(f"    └─ TAP Interface:     {t.name} (MAC: {t.mac_address}, MTU: {t.mtu}, State: {t.state})")
            print(f"[+] State cached in:      {net_mgr.state_file}")

        elif args.net_action == "status":
            status = net_mgr.get_status()
            if not status or not status.is_active:
                print("[-] No active virtual network bridge found in current workspace.")
            else:
                print(f"[*] Virtual Network Bridge: {status.bridge_name} [ACTIVE]")
                print(f"    Mode:       {status.mode}")
                print(f"    Created At: {status.created_at}")
                print(f"    Interfaces ({len(status.tap_interfaces)}):")
                for t in status.tap_interfaces:
                    print(f"      - {t.name:10} MAC: {t.mac_address} | State: {t.state} | Shim: {t.is_shim}")

        elif args.net_action == "teardown":
            print("[*] Tearing down virtual network bridge and TAP devices...")
            success = net_mgr.teardown_bridge_network(tap_name=args.tap, bridge_name=args.bridge)
            if success:
                print("[+] Successfully released virtual network interfaces.")
            else:
                print("[-] Error releasing network interfaces.", file=sys.stderr)

        elif args.net_action == "route-setup":
            r_mgr = NetworkRouter()
            sub = r_mgr.calculate_subnet(gateway_ip=args.guest_ip, netmask=args.netmask)
            print(f"[*] Configuring virtual subnet {sub.cidr} on bridge '{args.bridge}'...")
            r_status = r_mgr.setup_guest_routing(bridge_name=args.bridge, subnet=sub, force_shim=args.force_shim)
            print(f"[+] Routing Status:       {'ACTIVE' if r_status.is_active else 'INACTIVE'}")
            print(f"[+] Operational Mode:     {r_status.mode}")
            print(f"[+] Subnet CIDR:          {r_status.subnet.cidr}")
            print(f"[+] Host Bridge IP:       {r_status.subnet.host_ip} ({r_status.subnet.netmask})")
            print(f"[+] Guest Gateway IP:     {r_status.subnet.gateway_ip}")
            print(f"[+] IPv4 Forwarding:      {'ENABLED' if r_status.forwarding_enabled else 'DISABLED/SHIM'}")
            print(f"[+] Route Rules ({len(r_status.routes)}):")
            for r in r_status.routes:
                print(f"    └─ Dest: {r.destination:16} via {r.gateway:15} dev {r.interface} (metric {r.metric})")

        elif args.net_action == "route-status":
            r_mgr = NetworkRouter()
            r_status = r_mgr.get_routing_status()
            if not r_status or not r_status.is_active:
                print("[-] No active virtual routing configuration found in current workspace.")
            else:
                print(f"[*] Virtual Subnet Routing: {r_status.bridge_name} [ACTIVE]")
                print(f"    Mode:          {r_status.mode}")
                print(f"    Subnet:        {r_status.subnet.cidr}")
                print(f"    Host IP:       {r_status.subnet.host_ip}")
                print(f"    Guest IP:      {r_status.subnet.gateway_ip}")
                print(f"    Forwarding:    {r_status.forwarding_enabled}")
                print(f"    Routes ({len(r_status.routes)}):")
                for r in r_status.routes:
                    print(f"      - {r.destination:16} via {r.gateway:15} dev {r.interface} (metric {r.metric})")

        elif args.net_action == "route-teardown":
            r_mgr = NetworkRouter()
            print("[*] Tearing down virtual IP routing rules...")
            success = r_mgr.teardown_guest_routing(bridge_name=args.bridge)
            if success:
                print("[+] Successfully released virtual routing configurations.")
            else:
                print("[-] Error releasing virtual routing.", file=sys.stderr)

        elif args.net_action == "firewall-apply":
            fw_mgr = FirewallManager()
            print(f"[*] Configuring sandbox firewall on bridge '{args.bridge}'...")
            status = fw_mgr.apply_rules(
                bridge_name=args.bridge,
                sniffer_iface=args.sniffer,
                guest_ip=args.guest_ip,
                host_ip=args.host_ip,
                subnet_cidr=args.subnet,
                block_wan=not args.no_wan_block,
                mirror_sniffer=not args.no_sniffer_mirror,
                force_shim=args.force_shim,
            )
            print(f"[+] Firewall Status:      {'ACTIVE' if status.is_active else 'INACTIVE'}")
            print(f"[+] Operational Mode:     {status.mode}")
            print(f"[+] Security Policy:      {status.policy}")
            print(f"[+] Bridge Interface:     {status.bridge_name}")
            print(f"[+] Sniffer Target:       {status.sniffer_interface} (Mirroring: {'ENABLED' if status.packet_mirroring else 'DISABLED'})")
            print(f"[+] WAN Isolation:        {'ENABLED (Egress Blocked)' if status.wan_isolation else 'DISABLED'}")
            print(f"[+] Active Rules ({len(status.rules)}):")
            for r in status.rules:
                proto = f"p:{r.protocol}" if r.protocol != "all" else "all"
                port = f"dport:{r.dport}" if r.dport else ""
                print(f"    └─ [{r.table.upper()}:{r.chain}] {proto} {port} -> {r.action} ({r.comment})")
            print(f"[+] Generated Script:     {fw_mgr.script_file}")

        elif args.net_action == "firewall-status":
            fw_mgr = FirewallManager()
            status = fw_mgr.get_status()
            if not status or not status.is_active:
                print("[-] No active sandbox firewall rules found in current workspace.")
            else:
                print(f"[*] FirmSight Sandbox Firewall: {status.bridge_name} [ACTIVE]")
                print(f"    Mode:             {status.mode}")
                print(f"    Policy:           {status.policy}")
                print(f"    Host IP:          {status.host_ip}")
                print(f"    Guest IP:         {status.guest_ip}")
                print(f"    Subnet CIDR:      {status.subnet_cidr}")
                print(f"    WAN Isolation:    {status.wan_isolation}")
                print(f"    Sniffer Target:   {status.sniffer_interface} (Mirroring: {status.packet_mirroring})")
                print(f"    Created At:       {status.created_at}")
                print(f"    Total Rules:      {len(status.rules)}")
                for r in status.rules:
                    proto = f"proto={r.protocol}" if r.protocol != "all" else "all"
                    port = f"port={r.dport}" if r.dport else ""
                    print(f"      - {r.chain:<11} {proto:<10} {port:<10} -> {r.action:<6} | {r.comment}")

        elif args.net_action == "firewall-flush":
            fw_mgr = FirewallManager()
            print("[*] Flushing sandbox firewall rules and clearing state...")
            success = fw_mgr.flush_rules(force_shim=args.force_shim)
            if success:
                print("[+] Successfully flushed sandbox firewall rules.")
            else:
                print("[-] Error flushing firewall rules.", file=sys.stderr)

        elif args.net_action == "firewall-test":
            fw_mgr = FirewallManager()
            eval_res = fw_mgr.evaluate_packet(
                source_ip=args.src,
                dest_ip=args.dst,
                protocol=args.proto,
                dest_port=args.port,
                in_interface=args.in_iface,
                out_interface=args.out_iface,
            )
            print("--- [SANDBOX PACKET EVALUATION RESULT] ---")
            print(f"Flow:        {eval_res.source_ip} -> {eval_res.dest_ip}:{eval_res.dest_port} ({eval_res.protocol.upper()})")
            print(f"Interface:   {eval_res.in_interface} -> {eval_res.out_interface or 'N/A'}")
            print(f"Verdict:     {eval_res.verdict}")
            print(f"Sniffer TEE: {'MIRRORED to ' + str(eval_res.sniffer_interface) if eval_res.mirrored_to_sniffer else 'NO'}")
            print(f"Rule:        {eval_res.matched_rule or 'N/A'}")
            print(f"Reason:      {eval_res.reason}")

        elif args.net_action == "capture-start":
            pcap_mgr = PCAPBridge()
            print(f"[*] Initializing PCAP packet capture on interface '{args.interface}'...")
            session = pcap_mgr.start_capture(
                interface=args.interface,
                bridge_name=args.bridge,
                output_pcap=args.output,
                filter_expr=args.filter,
                guest_ip=args.guest_ip,
                host_ip=args.host_ip,
                force_shim=args.force_shim,
            )
            print(f"[+] Capture Session:   {session.session_id} [ACTIVE]")
            print(f"[+] Operational Mode:  {session.mode}")
            print(f"[+] Sniffer Interface: {session.interface} (Bridge: {session.bridge_name})")
            print(f"[+] Output PCAP:       {session.pcap_file}")
            print(f"[+] Track 3 Manifest:  {session.manifest_file}")
            if session.filter_expr:
                print(f"[+] BPF Filter:        {session.filter_expr}")

        elif args.net_action == "capture-stop":
            pcap_mgr = PCAPBridge()
            print("[*] Stopping active PCAP packet capture session...")
            session = pcap_mgr.stop_capture()
            if not session:
                print("[-] No active PCAP capture session found in current workspace.")
            else:
                print(f"[+] Successfully stopped capture session: {session.session_id}")
                print(f"[+] Total Packets:    {session.packet_count}")
                print(f"[+] Total Bytes:      {session.byte_count}")
                print(f"[+] Saved PCAP File:  {session.pcap_file}")
                print(f"[+] Track 3 Manifest: {session.manifest_file}")

        elif args.net_action == "capture-status":
            pcap_mgr = PCAPBridge()
            session = pcap_mgr.get_active_session()
            if not session:
                manifest_data = pcap_mgr.export_track3_manifest()
                if manifest_data:
                    print(f"[*] Most Recent PCAP Capture Session: {manifest_data.get('session_id')} [INACTIVE]")
                    print(f"    Mode:          {manifest_data.get('mode')}")
                    print(f"    Interface:     {manifest_data.get('interface')} ({manifest_data.get('bridge_name')})")
                    print(f"    Packets:       {manifest_data.get('packet_count')}")
                    print(f"    Bytes:         {manifest_data.get('byte_count')}")
                    print(f"    PCAP File:     {manifest_data.get('pcap_file')}")
                    print(f"    Protocols:     {manifest_data.get('protocols')}")
                else:
                    print("[-] No active or recorded PCAP capture session found.")
            else:
                print(f"[*] Active PCAP Capture Session: {session.session_id} [ACTIVE]")
                print(f"    Mode:          {session.mode}")
                print(f"    Interface:     {session.interface} (Bridge: {session.bridge_name})")
                print(f"    Packets:       {session.packet_count}")
                print(f"    Bytes:         {session.byte_count}")
                print(f"    PCAP File:     {session.pcap_file}")
                print(f"    Protocols:     {session.protocols}")
                print(f"    Started At:    {session.start_time}")

        elif args.net_action == "capture-inject":
            pcap_mgr = PCAPBridge()
            session = pcap_mgr.get_active_session()
            if not session:
                print("[-] No active capture session. Starting background session first...")
                session = pcap_mgr.start_capture()
            success = pcap_mgr.inject_packet(
                packet_type=args.type,
                src_ip=args.src,
                dst_ip=args.dst,
                dst_port=args.port,
            )
            if success:
                print(f"[+] Injected synthetic packet '{args.type}' into {session.pcap_file}")
                print(f"[+] Updated packet count: {session.packet_count}")
            else:
                print("[-] Failed to inject packet.", file=sys.stderr)

        elif args.net_action == "capture-flow":
            pcap_mgr = PCAPBridge()
            session = pcap_mgr.get_active_session()
            if not session:
                print("[-] No active capture session. Starting background session first...")
                session = pcap_mgr.start_capture()
            print(f"[*] Synthesizing realistic IoT traffic flow ({args.count} packets, inject_c2={args.inject_c2})...")
            count = pcap_mgr.inject_traffic_flow(count=args.count, inject_c2=args.inject_c2)
            print(f"[+] Successfully synthesized and recorded {count} packets.")
            print(f"[+] Output PCAP:      {session.pcap_file}")
            print(f"[+] Protocol stats:   {session.protocols}")

        elif args.net_action == "forward-add":
            pf = PortForwarder()
            rule = pf.add_forward(
                host_port=args.host_port,
                guest_port=args.guest_port,
                host_ip=args.host_ip,
                guest_ip=args.guest_ip,
                mode=args.mode,
                force_shim=args.force_shim,
            )
            print(f"[+] Configured Port Forward: {rule.rule_id} [ACTIVE]")
            print(f"[+] Forwarding Mapping:     {rule.host_ip}:{rule.host_port} -> {rule.guest_ip}:{rule.guest_port}")
            print(f"[+] Operational Mode:       {rule.mode}")
            print(f"[+] Quick Curl Verification: {rule.to_curl_command()}")

        elif args.net_action == "forward-list":
            pf = PortForwarder()
            forwards = pf.list_forwards()
            if not forwards:
                print("[-] No active port forwarders configured in current workspace.")
            else:
                print(f"[*] Active Port Forwarders ({len(forwards)}):")
                for r in forwards:
                    print(f"    - [{r.rule_id}] {r.host_ip}:{r.host_port} -> {r.guest_ip}:{r.guest_port} ({r.mode}) | Conns: {r.connections_handled}")

        elif args.net_action == "forward-remove":
            pf = PortForwarder()
            success = pf.remove_forward(args.rule_id)
            if success:
                print(f"[+] Removed port forward rule: {args.rule_id}")
            else:
                print(f"[-] Rule {args.rule_id} not found or failed to remove.", file=sys.stderr)

        elif args.net_action == "http-probe":
            harness = HTTPTriggerHarness()
            print(f"[*] Sending external HTTP {args.method} probe to port {args.host_port} (path: {args.path})...")
            res = harness.probe_endpoint(target=args.host_port, path=args.path, method=args.method)
            print("--- [HTTP PROBE RESULT] ---")
            print(f"URL:          {res.url}")
            print(f"Status Code:  {res.status_code or 'UNREACHABLE'}")
            print(f"Latency:      {res.response_time_ms} ms")
            if res.server_banner:
                print(f"Server:       {res.server_banner}")
            if res.error:
                print(f"Notice:       {res.error}")
            print(f"Curl Command: {res.curl_command}")
            if res.body_snippet:
                print(f"\nResponse Preview:\n{res.body_snippet.strip()}")

        elif args.net_action == "http-scan":
            harness = HTTPTriggerHarness()
            print(f"[*] Launching automated diagnostic HTTP scan against emulated router port {args.host_port}...")
            results = harness.run_diagnostic_scan(host_port=args.host_port)
            print("----------------------------------------------------------------------")
            print(f"{'Endpoint':<25} {'Status':<10} {'Latency':<12} {'Server Banner':<15}")
            print("----------------------------------------------------------------------")
            for r in results:
                status_str = str(r.status_code) if r.status_code else "FAIL"
                server_str = r.server_banner or "N/A"
                print(f"{r.url.split(str(args.host_port))[-1]:<25} {status_str:<10} {r.response_time_ms:<6} ms    {server_str:<15}")
            print("----------------------------------------------------------------------")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
