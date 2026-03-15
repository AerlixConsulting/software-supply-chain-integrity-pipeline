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

"""Tests for src/dependency_audit.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.dependency_audit import (
    AuditReport,
    audit_package,
    audit_requirements,
    audit_requirements_to_file,
)

SAMPLE_REQS_CLEAN = """\
requests==2.31.0
PyYAML==6.0.1
packaging==23.2
"""

SAMPLE_REQS_VULNS = """\
requests==2.28.0
PyYAML==5.3
click==8.1.7
"""


@pytest.fixture()
def clean_req_file(tmp_path: Path) -> Path:
    p = tmp_path / "requirements_clean.txt"
    p.write_text(SAMPLE_REQS_CLEAN, encoding="utf-8")
    return p


@pytest.fixture()
def vuln_req_file(tmp_path: Path) -> Path:
    p = tmp_path / "requirements_vuln.txt"
    p.write_text(SAMPLE_REQS_VULNS, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# audit_package
# ---------------------------------------------------------------------------


def test_audit_package_no_findings_for_patched() -> None:
    findings = audit_package("requests", "2.31.0")
    vuln_ids = [f.cve_id for f in findings if f.finding_type == "VULNERABILITY"]
    assert "CVE-2023-32681" not in vuln_ids


def test_audit_package_vulnerability_detected() -> None:
    findings = audit_package("requests", "2.28.0")
    cves = [f.cve_id for f in findings if f.finding_type == "VULNERABILITY"]
    assert "CVE-2023-32681" in cves


def test_audit_package_critical_vulnerability() -> None:
    findings = audit_package("pyyaml", "5.3")
    critical = [f for f in findings if f.severity == "CRITICAL"]
    assert len(critical) >= 1
    assert critical[0].cve_id == "CVE-2020-14343"


def test_audit_package_unknown_package_no_findings() -> None:
    findings = audit_package("some-unknown-lib", "1.0.0")
    # No vulns in feed for unknown lib; license is NOASSERTION (in allowed set)
    vuln_findings = [f for f in findings if f.finding_type == "VULNERABILITY"]
    assert len(vuln_findings) == 0


# ---------------------------------------------------------------------------
# audit_requirements
# ---------------------------------------------------------------------------


def test_audit_requirements_clean(clean_req_file: Path) -> None:
    report = audit_requirements(clean_req_file)
    assert isinstance(report, AuditReport)
    assert report.total_packages == 3
    assert report.overall_status == "PASS"


def test_audit_requirements_with_vulns(vuln_req_file: Path) -> None:
    report = audit_requirements(vuln_req_file)
    assert report.overall_status == "FAIL"
    cves = [f.cve_id for f in report.findings if f.finding_type == "VULNERABILITY"]
    assert "CVE-2023-32681" in cves
    assert "CVE-2020-14343" in cves


def test_audit_report_counts(vuln_req_file: Path) -> None:
    report = audit_requirements(vuln_req_file)
    assert report.total_packages == 3
    assert report.fail_count + report.pass_count == report.total_packages


def test_audit_requirements_to_file(tmp_path: Path, vuln_req_file: Path) -> None:
    out = tmp_path / "risk_report.json"
    audit_requirements_to_file(vuln_req_file, out)
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "findings" in data
    assert data["overall_status"] == "FAIL"
    assert len(data["findings"]) >= 2


def test_audit_report_to_dict_structure(vuln_req_file: Path) -> None:
    report = audit_requirements(vuln_req_file)
    d = report.to_dict()
    assert "generated_at" in d
    assert "overall_status" in d
    assert "findings" in d
    for finding in d["findings"]:
        assert "package" in finding
        assert "severity" in finding
        assert "finding_type" in finding
