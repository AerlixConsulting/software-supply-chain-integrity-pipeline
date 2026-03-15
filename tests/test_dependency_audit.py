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
    _is_affected,
    _match_single_clause,
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
# _match_single_clause / _is_affected — version comparison correctness
# ---------------------------------------------------------------------------


def test_match_single_clause_lt() -> None:
    assert _match_single_clause("2.28.0", "<2.31.0") is True
    assert _match_single_clause("2.31.0", "<2.31.0") is False


def test_match_single_clause_lte() -> None:
    assert _match_single_clause("46.0.4", "<=46.0.4") is True
    assert _match_single_clause("46.0.5", "<=46.0.4") is False


def test_match_single_clause_gte() -> None:
    assert _match_single_clause("38.0.0", ">=38.0.0") is True
    assert _match_single_clause("37.9.9", ">=38.0.0") is False


def test_match_single_clause_gt() -> None:
    assert _match_single_clause("2.0.0", ">1.24") is True
    assert _match_single_clause("1.0.0", ">1.24") is False


def test_match_single_clause_eq() -> None:
    assert _match_single_clause("2.31.0", "==2.31.0") is True
    assert _match_single_clause("2.31.1", "==2.31.0") is False


def test_is_affected_compound_in_range() -> None:
    # cryptography 41.0.7 is in range >=38.0.0,<42.0.4
    assert _is_affected("41.0.7", ">=38.0.0,<42.0.4") is True


def test_is_affected_compound_below_lower_bound() -> None:
    # 37.0.0 is below >=38.0.0 lower bound
    assert _is_affected("37.0.0", ">=38.0.0,<42.0.4") is False


def test_is_affected_compound_at_upper_bound() -> None:
    # 42.0.4 equals the exclusive upper bound — should NOT be affected
    assert _is_affected("42.0.4", ">=38.0.0,<42.0.4") is False


def test_is_affected_compound_urllib3_affected() -> None:
    # urllib3 2.2.1 is in range >=1.22,<2.6.3
    assert _is_affected("2.2.1", ">=1.22,<2.6.3") is True


def test_is_affected_compound_urllib3_patched() -> None:
    # urllib3 2.6.3 is at the exclusive upper bound — should NOT be affected
    assert _is_affected("2.6.3", ">=1.22,<2.6.3") is False


def test_is_affected_lte_operator() -> None:
    # Subgroup attack: <=46.0.4 — versions at and below are affected
    assert _is_affected("46.0.4", "<=46.0.4") is True
    assert _is_affected("46.0.5", "<=46.0.4") is False


# ---------------------------------------------------------------------------
# New CVEs in feed
# ---------------------------------------------------------------------------


def test_cryptography_null_ptr_deref_affected() -> None:
    # CVE-2024-26130: >=38.0.0,<42.0.4 — 41.0.7 is in range
    findings = audit_package("cryptography", "41.0.7")
    cves = [f.cve_id for f in findings if f.finding_type == "VULNERABILITY"]
    assert "CVE-2024-26130" in cves


def test_cryptography_null_ptr_deref_patched() -> None:
    # 42.0.4 is the patched boundary — should not be affected
    findings = audit_package("cryptography", "42.0.4")
    cves = [f.cve_id for f in findings if f.finding_type == "VULNERABILITY"]
    assert "CVE-2024-26130" not in cves


def test_cryptography_subgroup_attack_affected() -> None:
    # CVE-2025-29083: <=46.0.4 — 41.0.7 is affected
    findings = audit_package("cryptography", "41.0.7")
    cves = [f.cve_id for f in findings if f.finding_type == "VULNERABILITY"]
    assert "CVE-2025-29083" in cves


def test_cryptography_subgroup_attack_patched() -> None:
    # 46.0.5 is the patched version
    findings = audit_package("cryptography", "46.0.5")
    cves = [f.cve_id for f in findings if f.finding_type == "VULNERABILITY"]
    assert "CVE-2025-29083" not in cves


def test_cryptography_bleichenbacher_affected() -> None:
    # CVE-2023-49083 (Bleichenbacher): <42.0.0 — 41.0.7 is affected
    findings = audit_package("cryptography", "41.0.7")
    cves = [f.cve_id for f in findings if f.finding_type == "VULNERABILITY"]
    assert "CVE-2023-49083" in cves


def test_cryptography_bleichenbacher_patched() -> None:
    # 42.0.0 is the patched version
    findings = audit_package("cryptography", "42.0.0")
    cves = [f.cve_id for f in findings if f.finding_type == "VULNERABILITY"]
    assert "CVE-2023-49083" not in cves


def test_urllib3_decompression_bomb_affected() -> None:
    # CVE-2025-50181: >=1.22,<2.6.3 — 2.2.1 is affected
    findings = audit_package("urllib3", "2.2.1")
    cves = [f.cve_id for f in findings if f.finding_type == "VULNERABILITY"]
    assert "CVE-2025-50181" in cves


def test_urllib3_decompression_bomb_patched() -> None:
    # 2.6.3 is the patched version
    findings = audit_package("urllib3", "2.6.3")
    cves = [f.cve_id for f in findings if f.finding_type == "VULNERABILITY"]
    assert "CVE-2025-50181" not in cves


def test_urllib3_unbounded_chain_affected() -> None:
    # CVE-2025-50182: >=1.24,<2.6.0 — 2.2.1 is affected
    findings = audit_package("urllib3", "2.2.1")
    cves = [f.cve_id for f in findings if f.finding_type == "VULNERABILITY"]
    assert "CVE-2025-50182" in cves


def test_urllib3_fully_patched() -> None:
    # urllib3 2.6.3 should have no vulnerability findings
    findings = audit_package("urllib3", "2.6.3")
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
