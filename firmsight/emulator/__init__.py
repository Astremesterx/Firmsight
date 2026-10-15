"""Firmware emulation, QEMU architecture virtualization, and mock runtime services."""

from firmsight.emulator.arch import ArchitectureInfo, ArchitectureResolver
from firmsight.emulator.chroot_runner import ChrootExecutionResult, ChrootRunner
from firmsight.emulator.daemon import DaemonManager, DaemonProcess, DaemonStatus
from firmsight.emulator.device_nodes import DeviceNodeManager, DeviceNodeReport
from firmsight.emulator.firewall import (
    FirewallManager,
    FirewallRule,
    FirewallStatus,
    IPTablesManager,
    PacketEvaluation,
)
from firmsight.emulator.health_monitor import HealthIssue, HealthMonitor, HealthReport
from firmsight.emulator.integration_proof import (
    EmulationProofEngine,
    EmulationProofReport,
    MilestoneCheck,
)
from firmsight.emulator.network_bridge import BridgeStatus, NetworkBridgeManager, TAPConfig
from firmsight.emulator.network_router import (
    NetworkRouter,
    RouteRule,
    RoutingStatus,
    SubnetConfig,
)
from firmsight.emulator.nvram import MockNVRAM
from firmsight.emulator.orchestrator import (
    MasterOrchestrator,
    OrchestrationConfig,
    OrchestrationResult,
    OrchestrationStage,
)
from firmsight.emulator.pcap_bridge import (
    CaptureSessionInfo,
    PCAPBridge,
    SnifferBridge,
)
from firmsight.emulator.port_forward import (
    HTTPProbeResult,
    HTTPTriggerHarness,
    PortForwardRule,
    PortForwardStatus,
    PortForwarder,
)
from firmsight.emulator.rootfs_prep import PreparationReport, RootFSPreparer
from firmsight.emulator.service_launcher import DiscoveredService, ServiceLaunchResult, ServiceLauncher
from firmsight.emulator.tracer_hook import (
    APIInvocationEvent,
    DANGEROUS_APIS,
    DynamicHookInjector,
    GDBStubSession,
    HookTarget,
    Radare2Bridge,
)

__all__ = [
    "APIInvocationEvent",
    "ArchitectureInfo",
    "ArchitectureResolver",
    "BridgeStatus",
    "CaptureSessionInfo",
    "ChrootExecutionResult",
    "ChrootRunner",
    "DANGEROUS_APIS",
    "DaemonManager",
    "DaemonProcess",
    "DaemonStatus",
    "DeviceNodeManager",
    "DeviceNodeReport",
    "DiscoveredService",
    "DynamicHookInjector",
    "EmulationProofEngine",
    "EmulationProofReport",
    "FirewallManager",
    "FirewallRule",
    "FirewallStatus",
    "GDBStubSession",
    "HealthIssue",
    "HealthMonitor",
    "HealthReport",
    "HookTarget",
    "HTTPProbeResult",
    "HTTPTriggerHarness",
    "IPTablesManager",
    "MasterOrchestrator",
    "MilestoneCheck",
    "MockNVRAM",
    "NetworkBridgeManager",
    "NetworkRouter",
    "OrchestrationConfig",
    "OrchestrationResult",
    "OrchestrationStage",
    "PCAPBridge",
    "PacketEvaluation",
    "PortForwardRule",
    "PortForwardStatus",
    "PortForwarder",
    "PreparationReport",
    "Radare2Bridge",
    "RootFSPreparer",
    "RouteRule",
    "RoutingStatus",
    "ServiceLaunchResult",
    "ServiceLauncher",
    "SnifferBridge",
    "SubnetConfig",
    "TAPConfig",
]
