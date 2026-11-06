"""Hardcoded Credential and Secret Scanner for Track 2.

Scans firmware binaries, configuration files, and extracted root filesystems
for hardcoded credentials, private cryptographic keys, API tokens,
and authentication defaults.
"""

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Union


@dataclass
class CredentialFinding:
    """Structure representing an identified secret or credential."""
    file_path: str
    category: str                      # PASSWORD, PRIVATE_KEY, API_TOKEN, DEFAULT_LOGIN, SHADOW_HASH
    severity: str                      # CRITICAL, HIGH, MEDIUM, LOW
    snippet: str                       # Masked preview of finding
    offset: int
    rule_name: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


SECRET_PATTERNS = [
    # Private Cryptographic Keys
    (
        "RSA Private Key",
        "PRIVATE_KEY",
        "CRITICAL",
        r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        "Found unencrypted private cryptographic key material",
    ),
    # UNIX Password Hashes (/etc/shadow, passwd)
    (
        "UNIX Password Hash",
        "SHADOW_HASH",
        "CRITICAL",
        r"\$([156])\$[a-zA-Z0-9./]{4,16}\$[a-zA-Z0-9./]{22,86}",
        "Found salted UNIX crypt password hash (MD5/SHA-256/SHA-512)",
    ),
    # Router Default Credentials
    (
        "Default Router Credential",
        "DEFAULT_LOGIN",
        "HIGH",
        r"(?i)(?:admin|root|guest|user|support)\s*[:=]\s*(?:admin|root|password|1234|12345|123456|pass|toor|default|system)\b",
        "Found common default factory router credentials",
    ),
    # Explicit Password Assignments
    (
        "Hardcoded Password",
        "PASSWORD",
        "HIGH",
        r"(?i)(?:password|passwd|pwd|passphrase)\s*[:=]\s*['\"]?([^\s,'\";]{4,40})['\"]?",
        "Hardcoded password assignment discovered in plaintext",
    ),
    # Generic API Keys and Tokens
    (
        "API Key or Token",
        "API_TOKEN",
        "HIGH",
        r"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,64})['\"]?",
        "Discovered API key or authentication secret token",
    ),
    # Hardcoded Authorization Headers
    (
        "Bearer Authorization Token",
        "API_TOKEN",
        "HIGH",
        r"(?i)Authorization:\s*Bearer\s+([a-zA-Z0-9._\-]{20,})",
        "Discovered hardcoded HTTP Bearer authorization token",
    ),
    # NVRAM Hardcoded Parameters
    (
        "NVRAM Admin Secret",
        "PASSWORD",
        "MEDIUM",
        r"(?i)(?:http_passwd|http_username|admin_password|lan_ipaddr)\s*=\s*([^\s;]+)",
        "Discovered hardcoded router NVRAM authentication variable",
    ),
]


class CredentialScanner:
    """Scans firmware binaries, files, and directory trees for leaked secrets."""

    def __init__(self, target_path: Union[str, Path]) -> None:
        self.target_path = Path(target_path)

    def scan_file(self, file_path: Path) -> List[CredentialFinding]:
        """Scans a single file for sensitive strings and cryptographic artifacts."""
        findings: List[CredentialFinding] = []
        if not file_path.exists() or not file_path.is_file():
            return findings

        # Skip files larger than 25MB to prevent scanning stalls
        try:
            if file_path.stat().st_size > 25 * 1024 * 1024:
                return findings
        except OSError:
            return findings

        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()
        except Exception:
            return findings

        # Decode using latin-1 to safely handle binary files without decoding errors
        text = raw_bytes.decode("latin-1", errors="ignore")

        for rule_name, category, severity, pattern, desc in SECRET_PATTERNS:
            try:
                for match in re.finditer(pattern, text):
                    full_match = match.group(0)
                    offset = match.start()

                    # Mask sensitive characters if long enough
                    if len(full_match) > 8:
                        masked = full_match[:6] + "..." + full_match[-4:]
                    else:
                        masked = full_match[:2] + "****"

                    findings.append(
                        CredentialFinding(
                            file_path=str(file_path),
                            category=category,
                            severity=severity,
                            snippet=masked,
                            offset=offset,
                            rule_name=rule_name,
                            description=desc,
                        )
                    )
            except Exception:
                pass

        return findings

    def scan(self) -> List[CredentialFinding]:
        """Scans the target file or walks rootfs directory tree."""
        if not self.target_path.exists():
            return []

        if self.target_path.is_file():
            return self.scan_file(self.target_path)

        all_findings: List[CredentialFinding] = []
        for root, _, files in os.walk(self.target_path):
            for file in files:
                p = Path(root) / file
                all_findings.extend(self.scan_file(p))

        return all_findings


def scan_credentials(file_path: Union[str, Path]) -> List[Dict[str, Any]]:
    """Ashmi Track 2 compatibility entry point."""
    scanner = CredentialScanner(file_path)
    findings = scanner.scan()

    if not findings:
        print("No potential hardcoded credentials detected.")
        return []

    for item in findings:
        print(f"Potential {item.rule_name} ({item.severity}) found at offset {item.offset}: {item.snippet}")

    return [f.to_dict() for f in findings]
