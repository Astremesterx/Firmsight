"""FirmSight: IoT Firmware Emulation & Dynamic Analysis Sandbox."""

__version__ = "1.0.0"
__author__ = "Salif (Team Lead), Ashmi, Poornima — Infotact Solutions"

# Core Subsystems
from firmsight.core.config import SAMPLES_DIR, ensure_directories

# Track 1: Extraction & Emulation Engine
from firmsight.extractor.extractor import FirmwareExtractor
from firmsight.extractor.header_parser import HeaderParser
from firmsight.extractor.mock_firmware import MockFirmwareBuilder
from firmsight.extractor.squashfs_handler import SquashFSHandler
from firmsight.emulator.arch import ArchitectureResolver
from firmsight.emulator.chroot_runner import ChrootRunner
from firmsight.emulator.cleanup import SandboxCleanupManager
from firmsight.emulator.daemon import DaemonManager
from firmsight.emulator.device_nodes import DeviceNodeManager
from firmsight.emulator.firewall import FirewallManager
from firmsight.emulator.health_monitor import HealthMonitor
from firmsight.emulator.network_bridge import NetworkBridgeManager
from firmsight.emulator.network_router import NetworkRouter
from firmsight.emulator.nvram import MockNVRAM
from firmsight.emulator.orchestrator import MasterOrchestrator, OrchestrationConfig
from firmsight.emulator.pcap_bridge import PCAPBridge
from firmsight.emulator.port_forward import PortForwarder
from firmsight.emulator.rootfs_prep import RootFSPreparer
from firmsight.emulator.service_launcher import ServiceLauncher
from firmsight.emulator.tracer_hook import DynamicHookInjector

# Track 2: Binary Reverse Engineering & Memory Auditor
from firmsight.analyzer.credential_scanner import CredentialScanner, scan_credentials
from firmsight.analyzer.elf_parser import ELFParser, parse_elf
from firmsight.analyzer.exploit_poc import ExploitHarness, generate_cyclic_pattern
from firmsight.analyzer.vulnerability_scanner import VulnerabilityScanner, extract_memory_map
from firmsight.tracer.r2_hook import Radare2Tracer

# Track 3: Network Forensics, Threat Detection & Terminal UI
from firmsight.network.pcap_analyzer import PCAPAnalyzer
from firmsight.tui.app import FirmSightTUI, launch_tui
from firmsight.reports.generator import ReportGenerator

__all__ = [
    "ArchitectureResolver",
    "ChrootRunner",
    "CredentialScanner",
    "DaemonManager",
    "DeviceNodeManager",
    "DynamicHookInjector",
    "ELFParser",
    "ExploitHarness",
    "FirewallManager",
    "FirmSightTUI",
    "FirmwareExtractor",
    "HeaderParser",
    "HealthMonitor",
    "MasterOrchestrator",
    "MockFirmwareBuilder",
    "MockNVRAM",
    "NetworkBridgeManager",
    "NetworkRouter",
    "OrchestrationConfig",
    "PCAPAnalyzer",
    "PCAPBridge",
    "PortForwarder",
    "Radare2Tracer",
    "ReportGenerator",
    "RootFSPreparer",
    "SandboxCleanupManager",
    "ServiceLauncher",
    "SquashFSHandler",
    "VulnerabilityScanner",
    "ensure_directories",
    "extract_memory_map",
    "generate_cyclic_pattern",
    "launch_tui",
    "parse_elf",
    "scan_credentials",
]
