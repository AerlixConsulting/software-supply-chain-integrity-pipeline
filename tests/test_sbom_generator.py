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

"""Tests for src/sbom_generator.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.sbom_generator import generate_sbom, generate_sbom_to_file, parse_requirements

SAMPLE_REQUIREMENTS = """\
# Example requirements
requests==2.31.0
PyYAML==6.0.1
cryptography==41.0.7
click==8.1.7
packaging==23.2
"""


@pytest.fixture()
def req_file(tmp_path: Path) -> Path:
    p = tmp_path / "requirements.txt"
    p.write_text(SAMPLE_REQUIREMENTS, encoding="utf-8")
    return p


def test_parse_requirements_returns_packages(req_file: Path) -> None:
    packages = parse_requirements(req_file)
    assert len(packages) == 5
    names = [p["name"] for p in packages]
    assert "requests" in names
    assert "PyYAML" in names


def test_parse_requirements_skips_comments_and_blanks(tmp_path: Path) -> None:
    p = tmp_path / "req.txt"
    p.write_text("# comment\n\nrequests==2.31.0\n", encoding="utf-8")
    packages = parse_requirements(p)
    assert len(packages) == 1
    assert packages[0]["name"] == "requests"
    assert packages[0]["version"] == "2.31.0"


def test_generate_sbom_structure(req_file: Path) -> None:
    sbom = generate_sbom(req_file)
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert "serialNumber" in sbom
    assert sbom["serialNumber"].startswith("urn:uuid:")
    assert "metadata" in sbom
    assert "components" in sbom


def test_generate_sbom_component_count(req_file: Path) -> None:
    sbom = generate_sbom(req_file)
    assert len(sbom["components"]) == 5


def test_generate_sbom_component_fields(req_file: Path) -> None:
    sbom = generate_sbom(req_file)
    comp = sbom["components"][0]
    assert comp["type"] == "library"
    assert "name" in comp
    assert "version" in comp
    assert "purl" in comp
    assert comp["purl"].startswith("pkg:pypi/")
    assert "licenses" in comp


def test_generate_sbom_to_file(tmp_path: Path, req_file: Path) -> None:
    out = tmp_path / "sbom.json"
    sbom = generate_sbom_to_file(req_file, out)
    assert out.exists()
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["bomFormat"] == "CycloneDX"
    assert len(loaded["components"]) == len(sbom["components"])


def test_generate_sbom_empty_requirements(tmp_path: Path) -> None:
    p = tmp_path / "empty.txt"
    p.write_text("# no packages\n", encoding="utf-8")
    sbom = generate_sbom(p)
    assert sbom["components"] == []


def test_generate_sbom_metadata_tool(req_file: Path) -> None:
    sbom = generate_sbom(req_file, tool_name="test-tool", tool_version="9.9.9")
    tool = sbom["metadata"]["tools"][0]
    assert tool["name"] == "test-tool"
    assert tool["version"] == "9.9.9"
