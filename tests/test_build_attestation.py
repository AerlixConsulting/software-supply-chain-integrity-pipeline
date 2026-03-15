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

"""Tests for src/build_attestation.py."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from src.build_attestation import generate_attestation, generate_attestation_to_file

SOURCE_URI = "https://github.com/AerlixConsulting/software-supply-chain-integrity-pipeline"
SOURCE_DIGEST = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"


@pytest.fixture()
def sample_artifact(tmp_path: Path) -> Path:
    p = tmp_path / "output.bin"
    p.write_bytes(b"build output data for attestation test\n")
    return p


def _decode_statement(envelope: dict) -> dict:
    """Decode and return the in-toto statement from a DSSE envelope."""
    payload = envelope["payload"]
    # Add padding if needed
    padded = payload + "==" if len(payload) % 4 else payload
    raw = base64.urlsafe_b64decode(padded)
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Envelope structure
# ---------------------------------------------------------------------------


def test_generate_attestation_envelope_keys(sample_artifact: Path) -> None:
    env = generate_attestation(
        artifact_paths=[sample_artifact],
        source_uri=SOURCE_URI,
        source_digest=SOURCE_DIGEST,
    )
    assert "payloadType" in env
    assert "payload" in env
    assert "signatures" in env
    assert env["payloadType"] == "application/vnd.in-toto+json"


def test_generate_attestation_has_signature_block(sample_artifact: Path) -> None:
    env = generate_attestation(
        artifact_paths=[sample_artifact],
        source_uri=SOURCE_URI,
        source_digest=SOURCE_DIGEST,
    )
    assert isinstance(env["signatures"], list)
    assert len(env["signatures"]) == 1
    sig = env["signatures"][0]
    assert "keyid" in sig
    assert "sig" in sig


# ---------------------------------------------------------------------------
# Decoded statement
# ---------------------------------------------------------------------------


def test_attestation_subject_digest(sample_artifact: Path) -> None:
    env = generate_attestation(
        artifact_paths=[sample_artifact],
        source_uri=SOURCE_URI,
        source_digest=SOURCE_DIGEST,
    )
    stmt = _decode_statement(env)
    assert stmt["_type"] == "https://in-toto.io/Statement/v0.1"
    subjects = stmt["subject"]
    assert len(subjects) == 1
    assert subjects[0]["name"] == sample_artifact.name
    assert "sha256" in subjects[0]["digest"]


def test_attestation_predicate_type(sample_artifact: Path) -> None:
    env = generate_attestation(
        artifact_paths=[sample_artifact],
        source_uri=SOURCE_URI,
        source_digest=SOURCE_DIGEST,
    )
    stmt = _decode_statement(env)
    assert stmt["predicateType"] == "https://slsa.dev/provenance/v1"


def test_attestation_materials_contain_source(sample_artifact: Path) -> None:
    env = generate_attestation(
        artifact_paths=[sample_artifact],
        source_uri=SOURCE_URI,
        source_digest=SOURCE_DIGEST,
    )
    stmt = _decode_statement(env)
    materials = stmt["predicate"]["materials"]
    uris = [m["uri"] for m in materials]
    assert SOURCE_URI in uris


def test_attestation_multiple_artifacts(tmp_path: Path) -> None:
    a1 = tmp_path / "a1.bin"
    a2 = tmp_path / "a2.bin"
    a1.write_bytes(b"artifact one")
    a2.write_bytes(b"artifact two")
    env = generate_attestation(
        artifact_paths=[a1, a2],
        source_uri=SOURCE_URI,
        source_digest=SOURCE_DIGEST,
    )
    stmt = _decode_statement(env)
    assert len(stmt["subject"]) == 2


def test_attestation_missing_artifact_excluded(tmp_path: Path) -> None:
    existing = tmp_path / "exists.bin"
    existing.write_bytes(b"exists")
    missing = tmp_path / "missing.bin"
    env = generate_attestation(
        artifact_paths=[existing, missing],
        source_uri=SOURCE_URI,
        source_digest=SOURCE_DIGEST,
    )
    stmt = _decode_statement(env)
    # Only the existing artifact should appear
    assert len(stmt["subject"]) == 1


# ---------------------------------------------------------------------------
# generate_attestation_to_file
# ---------------------------------------------------------------------------


def test_generate_attestation_to_file(tmp_path: Path, sample_artifact: Path) -> None:
    out = tmp_path / "attestation.json"
    env = generate_attestation_to_file(
        artifact_paths=[sample_artifact],
        source_uri=SOURCE_URI,
        source_digest=SOURCE_DIGEST,
        output_path=out,
    )
    assert out.exists()
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["payloadType"] == env["payloadType"]
