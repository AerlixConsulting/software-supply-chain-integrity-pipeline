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

"""SBOM Generator — produces CycloneDX 1.5 JSON SBOMs from requirements files.

Parses a ``requirements.txt``-style lockfile (``name==version`` pins) and
emits a minimal CycloneDX 1.5 JSON document suitable for ingestion by
vulnerability scanners, policy engines, and compliance tools.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9_\-\.]+)\s*==\s*([^\s;#]+)",
)

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
}


def parse_requirements(path: Path) -> list[dict[str, str]]:
    """Return a list of ``{name, version}`` dicts parsed from *path*."""
    packages: list[dict[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _REQ_LINE.match(line)
        if m:
            packages.append({"name": m.group(1), "version": m.group(2)})
    return packages


def _purl(name: str, version: str) -> str:
    """Return a minimal PyPI Package URL string."""
    return f"pkg:pypi/{name.lower()}@{version}"


def _component(pkg: dict[str, str]) -> dict[str, Any]:
    """Build a CycloneDX component entry for *pkg*."""
    name = pkg["name"]
    version = pkg["version"]
    blob = f"{name}=={version}".encode()
    bom_ref = hashlib.sha256(blob).hexdigest()[:16]
    license_id = _LICENSE_MAP.get(name.lower(), "NOASSERTION")

    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": name,
        "version": version,
        "purl": _purl(name, version),
        "licenses": [{"license": {"id": license_id}}],
    }
    return component


def generate_sbom(
    requirements_path: Path,
    *,
    tool_name: str = "aerlix-sbom-generator",
    tool_version: str = "0.1.0",
) -> dict[str, Any]:
    """Generate and return a CycloneDX 1.5 SBOM dict.

    Args:
        requirements_path: Path to a ``requirements.txt`` file.
        tool_name: Name of the generating tool embedded in the SBOM metadata.
        tool_version: Version string of the generating tool.

    Returns:
        A CycloneDX 1.5 compliant dictionary ready for JSON serialisation.
    """
    packages = parse_requirements(requirements_path)
    serial_number = f"urn:uuid:{uuid.uuid4()}"
    now = datetime.now(tz=timezone.utc).isoformat()

    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "Aerlix Consulting", "name": tool_name, "version": tool_version}],
            "component": {
                "type": "application",
                "name": "software-supply-chain-integrity-pipeline",
                "version": "0.1.0",
            },
        },
        "components": [_component(p) for p in packages],
    }
    return sbom


def generate_sbom_to_file(requirements_path: Path, output_path: Path) -> dict[str, Any]:
    """Generate a CycloneDX SBOM and write it to *output_path* as JSON.

    Args:
        requirements_path: Path to a ``requirements.txt`` file.
        output_path: Destination path for the JSON output.

    Returns:
        The generated SBOM dictionary.
    """
    sbom = generate_sbom(requirements_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
    return sbom
