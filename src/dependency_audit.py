# Copyright 2024 Aerlix Consulting
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Dependency Audit — evaluates packages against vulnerability and license policies.

Implements a local allow/deny vulnerability feed and license acceptability
check.  In production the feed would be replaced or supplemented by an
integration with OSV, NVD, or a commercial SCA API.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .sbom_generator import parse_requirements

# ---------------------------------------------------------------------------
# Vulnerability feed (local stub — replace with OSV/NVD API in production)
# ---------------------------------------------------------------------------

_VULN_FEED: dict[str, list[dict[str, Any]]] = {
    "requests": [
        {
            "id": "CVE-2023-32681",
            "severity": "MEDIUM",
            "cvss": 6.1,
            "affected_versions": ["<2.31.0"],
            "description": "Unintended leak of Proxy-Authorization header.",
            "remediation": "Upgrade to requests>=2.31.0",
        }
    ],
    "pyyaml": [
        {
            "id": "CVE-2020-14343",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affected_versions": ["<5.4"],
            "description": "Arbitrary code execution via yaml.load() with full_load bypass.",
            "remediation": "Upgrade to PyYAML>=5.4 and use yaml.safe_load().",
        }
    ],
    "pillow": [
        {
            "id": "CVE-2023-44271",
            "severity": "HIGH",
            "cvss": 7.5,
            "affected_versions": ["<10.0.1"],
            "description": "Uncontrolled resource consumption in ImageFont.",
            "remediation": "Upgrade to Pillow>=10.0.1",
        }
    ],
    "cryptography": [
        {
            "id": "CVE-2024-26130",
            "severity": "HIGH",
            "cvss": 7.5,
            "affected_versions": [">=38.0.0,<42.0.4"],
            "description": "NULL pointer dereference with pkcs12.serialize_key_and_certificates when called with a non-matching certificate and private key and an hmac_hash override.",
            "remediation": "Upgrade to cryptography>=42.0.4",
        },
        {
            "id": "CVE-2023-49083",
            "severity": "LOW",
            "cvss": 4.0,
            "affected_versions": ["<42.0.0"],
            "description": "Python Cryptography package vulnerable to Bleichenbacher timing oracle attack.",
            "remediation": "Upgrade to cryptography>=42.0.0",
        },
        {
            "id": "CVE-2025-29083",
            "severity": "HIGH",
            "cvss": 7.4,
            "affected_versions": ["<=46.0.4"],
            "description": "cryptography vulnerable to a Subgroup Attack due to missing subgroup validation for SECT curves.",
            "remediation": "Upgrade to cryptography>=46.0.5",
        },
    ],
    "urllib3": [
        {
            "id": "CVE-2025-50181",
            "severity": "HIGH",
            "cvss": 7.5,
            "affected_versions": [">=1.22,<2.6.3"],
            "description": "Decompression-bomb safeguards bypassed when following HTTP redirects (streaming API).",
            "remediation": "Upgrade to urllib3>=2.6.3",
        },
        {
            "id": "CVE-2025-50180",
            "severity": "HIGH",
            "cvss": 7.5,
            "affected_versions": [">=1.0,<2.6.0"],
            "description": "urllib3 streaming API improperly handles highly compressed data, allowing decompression bombs.",
            "remediation": "Upgrade to urllib3>=2.6.0",
        },
        {
            "id": "CVE-2025-50182",
            "severity": "HIGH",
            "cvss": 7.5,
            "affected_versions": [">=1.24,<2.6.0"],
            "description": "urllib3 allows an unbounded number of links in the decompression chain.",
            "remediation": "Upgrade to urllib3>=2.6.0",
        },
    ],
}

# ---------------------------------------------------------------------------
# License policy
# ---------------------------------------------------------------------------

_ALLOWED_LICENSES: set[str] = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "MPL-2.0",
    "PSF-2.0",
    "Python-2.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "NOASSERTION",  # treated as unknown / needs review
}

_DENIED_LICENSES: set[str] = {
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-3.0",
    "SSPL-1.0",
    "BUSL-1.1",
    "CC-BY-NC-4.0",
}

_LICENSE_MAP: dict[str, str] = {
    "requests": "Apache-2.0",
    "flask": "BSD-3-Clause",
    "django": "BSD-3-Clause",
    "pyyaml": "MIT",
    "cryptography": "Apache-2.0",
    "pytest": "MIT",
    "click": "BSD-3-Clause",
    "rich": "MIT",
    "packaging": "Apache-2.0",
    "certifi": "MPL-2.0",
    "charset-normalizer": "MIT",
    "urllib3": "MIT",
    "idna": "BSD-3-Clause",
    "pillow": "HPND",  # historical permission — not in allow list → review flag
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single audit finding for one dependency."""

    package: str
    version: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    finding_type: str  # VULNERABILITY | LICENSE_VIOLATION | LICENSE_REVIEW
    detail: str
    remediation: str = ""
    cve_id: str = ""
    cvss: float = 0.0


@dataclass
class AuditReport:
    """Aggregated result from a dependency audit run."""

    generated_at: str = field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())
    total_packages: int = 0
    findings: list[Finding] = field(default_factory=list)
    pass_count: int = 0
    fail_count: int = 0

    @property
    def overall_status(self) -> str:
        critical_high = sum(
            1 for f in self.findings if f.severity in ("CRITICAL", "HIGH")
        )
        return "FAIL" if critical_high > 0 else "PASS"

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "overall_status": self.overall_status,
            "total_packages": self.total_packages,
            "pass_count": self.pass_count,
            "fail_count": self.fail_count,
            "findings": [
                {
                    "package": f.package,
                    "version": f.version,
                    "severity": f.severity,
                    "finding_type": f.finding_type,
                    "cve_id": f.cve_id,
                    "cvss": f.cvss,
                    "detail": f.detail,
                    "remediation": f.remediation,
                }
                for f in self.findings
            ],
        }


# ---------------------------------------------------------------------------
# Audit logic
# ---------------------------------------------------------------------------


def _version_tuple(version: str) -> tuple[int, ...]:
    """Convert a version string to a comparable integer tuple."""
    parts = []
    for part in version.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _is_affected(pkg_version: str, affected_spec: str) -> bool:
    """Return True if *pkg_version* satisfies *affected_spec*.

    Supports single constraints (e.g. ``'<2.31.0'``, ``'<=46.0.4'``) and
    compound comma-separated ranges (e.g. ``'>=38.0.0,<42.0.4'``).  All
    clauses in a compound spec must be satisfied for the function to return
    ``True``.
    """
    # Split compound specs (e.g. ">=38.0.0,<42.0.4") into individual clauses
    clauses = [c.strip() for c in affected_spec.split(",") if c.strip()]
    return all(_match_single_clause(pkg_version, clause) for clause in clauses)


def _match_single_clause(pkg_version: str, clause: str) -> bool:
    """Evaluate a single version constraint clause against *pkg_version*.

    Operators ``<=`` and ``>=`` are checked before ``<`` and ``>`` to avoid
    prefix-match ambiguity.
    """
    if clause.startswith("<="):
        return _version_tuple(pkg_version) <= _version_tuple(clause[2:])
    if clause.startswith(">="):
        return _version_tuple(pkg_version) >= _version_tuple(clause[2:])
    if clause.startswith("<"):
        return _version_tuple(pkg_version) < _version_tuple(clause[1:])
    if clause.startswith(">"):
        return _version_tuple(pkg_version) > _version_tuple(clause[1:])
    if clause.startswith("=="):
        return pkg_version == clause[2:]
    return False


def audit_package(name: str, version: str) -> list[Finding]:
    """Return a list of :class:`Finding` objects for *name*/*version*."""
    findings: list[Finding] = []
    key = name.lower()

    # Vulnerability check
    for vuln in _VULN_FEED.get(key, []):
        if any(_is_affected(version, spec) for spec in vuln["affected_versions"]):
            findings.append(
                Finding(
                    package=name,
                    version=version,
                    severity=vuln["severity"],
                    finding_type="VULNERABILITY",
                    detail=vuln["description"],
                    remediation=vuln["remediation"],
                    cve_id=vuln["id"],
                    cvss=vuln["cvss"],
                )
            )

    # License check
    license_id = _LICENSE_MAP.get(key, "NOASSERTION")
    if license_id in _DENIED_LICENSES:
        findings.append(
            Finding(
                package=name,
                version=version,
                severity="HIGH",
                finding_type="LICENSE_VIOLATION",
                detail=f"License '{license_id}' is in the denied list.",
                remediation="Replace this dependency with a compatibly-licensed alternative.",
            )
        )
    elif license_id not in _ALLOWED_LICENSES:
        findings.append(
            Finding(
                package=name,
                version=version,
                severity="MEDIUM",
                finding_type="LICENSE_REVIEW",
                detail=f"License '{license_id}' is not in the explicit allow list; manual review required.",
                remediation="Review license terms and add to the allow list if acceptable.",
            )
        )

    return findings


def audit_requirements(requirements_path: Path) -> AuditReport:
    """Run a full dependency audit against a requirements file.

    Args:
        requirements_path: Path to a ``requirements.txt`` file.

    Returns:
        An :class:`AuditReport` containing all findings.
    """
    packages = parse_requirements(requirements_path)
    report = AuditReport(total_packages=len(packages))

    for pkg in packages:
        findings = audit_package(pkg["name"], pkg["version"])
        if findings:
            report.fail_count += 1
            report.findings.extend(findings)
        else:
            report.pass_count += 1

    return report


def audit_requirements_to_file(requirements_path: Path, output_path: Path) -> AuditReport:
    """Run audit and write the JSON report to *output_path*.

    Args:
        requirements_path: Path to a ``requirements.txt`` file.
        output_path: Destination path for the JSON risk report.

    Returns:
        The completed :class:`AuditReport`.
    """
    report = audit_requirements(requirements_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
    return report
