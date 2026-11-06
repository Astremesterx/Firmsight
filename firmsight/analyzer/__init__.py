"""Binary Reverse Engineering, Static Auditing, and Vulnerability Analysis (Track 2)."""

from firmsight.analyzer.credential_scanner import (
    CredentialFinding,
    CredentialScanner,
    scan_credentials,
)
from firmsight.analyzer.elf_parser import (
    ELFAnalysisReport,
    ELFHeaderInfo,
    ELFParser,
    SectionInfo,
    SegmentInfo,
    parse_elf,
)
from firmsight.analyzer.exploit_poc import (
    ExploitHarness,
    ExploitResult,
    RegisterState,
    generate_cyclic_pattern,
)
from firmsight.analyzer.vulnerability_scanner import (
    BannedFunctionFinding,
    MemorySegmentAudit,
    VulnerabilityAuditReport,
    VulnerabilityScanner,
    extract_memory_map,
)

__all__ = [
    "BannedFunctionFinding",
    "CredentialFinding",
    "CredentialScanner",
    "ELFAnalysisReport",
    "ELFHeaderInfo",
    "ELFParser",
    "ExploitHarness",
    "ExploitResult",
    "MemorySegmentAudit",
    "RegisterState",
    "SectionInfo",
    "SegmentInfo",
    "VulnerabilityAuditReport",
    "VulnerabilityScanner",
    "extract_memory_map",
    "generate_cyclic_pattern",
    "parse_elf",
    "scan_credentials",
]
