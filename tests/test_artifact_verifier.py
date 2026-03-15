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

"""Tests for src/artifact_verifier.py."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from src.artifact_verifier import (
    VerificationStatus,
    compute_digest,
    verify_artifacts,
    verify_checksum_file,
    verify_digest,
    write_checksum_file,
)


@pytest.fixture()
def sample_artifact(tmp_path: Path) -> Path:
    p = tmp_path / "build.bin"
    p.write_bytes(b"Hello, Aerlix Supply Chain!\n")
    return p


# ---------------------------------------------------------------------------
# compute_digest
# ---------------------------------------------------------------------------


def test_compute_sha256(sample_artifact: Path) -> None:
    expected = hashlib.sha256(sample_artifact.read_bytes()).hexdigest()
    assert compute_digest(sample_artifact, "sha256") == expected


def test_compute_sha512(sample_artifact: Path) -> None:
    expected = hashlib.sha512(sample_artifact.read_bytes()).hexdigest()
    assert compute_digest(sample_artifact, "sha512") == expected


def test_compute_digest_unsupported_algorithm(sample_artifact: Path) -> None:
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        compute_digest(sample_artifact, "md5")


def test_compute_digest_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        compute_digest(tmp_path / "nonexistent.bin")


# ---------------------------------------------------------------------------
# write_checksum_file / read_checksum_file
# ---------------------------------------------------------------------------


def test_write_and_read_checksum_file(sample_artifact: Path) -> None:
    checksum_path = write_checksum_file(sample_artifact)
    assert checksum_path.exists()
    content = checksum_path.read_text(encoding="utf-8").strip()
    digest, name = content.split(None, 1)
    assert name == sample_artifact.name
    assert len(digest) == 64  # sha256 hex


# ---------------------------------------------------------------------------
# verify_digest
# ---------------------------------------------------------------------------


def test_verify_digest_pass(sample_artifact: Path) -> None:
    expected = compute_digest(sample_artifact)
    result = verify_digest(sample_artifact, expected)
    assert result.digest_match is True
    assert result.status == VerificationStatus.PASS


def test_verify_digest_fail(sample_artifact: Path) -> None:
    result = verify_digest(sample_artifact, "aabbcc" + "0" * 58)
    assert result.digest_match is False
    assert result.status == VerificationStatus.FAIL
    assert "mismatch" in result.detail.lower()


# ---------------------------------------------------------------------------
# verify_checksum_file
# ---------------------------------------------------------------------------


def test_verify_checksum_file_pass(sample_artifact: Path) -> None:
    checksum_path = write_checksum_file(sample_artifact)
    result = verify_checksum_file(sample_artifact, checksum_path)
    assert result.status == VerificationStatus.PASS


def test_verify_checksum_file_tampered(sample_artifact: Path, tmp_path: Path) -> None:
    checksum_path = write_checksum_file(sample_artifact)
    # Tamper with the artifact
    sample_artifact.write_bytes(b"tampered content")
    result = verify_checksum_file(sample_artifact, checksum_path)
    assert result.status == VerificationStatus.FAIL


# ---------------------------------------------------------------------------
# verify_artifacts (batch)
# ---------------------------------------------------------------------------


def test_verify_artifacts_batch(sample_artifact: Path) -> None:
    digest = compute_digest(sample_artifact)
    results = verify_artifacts([
        {"path": str(sample_artifact), "expected_digest": digest},
    ])
    assert len(results) == 1
    assert results[0].status == VerificationStatus.PASS


def test_verify_artifacts_no_expected(sample_artifact: Path) -> None:
    results = verify_artifacts([{"path": str(sample_artifact)}])
    assert len(results) == 1
    assert results[0].status == VerificationStatus.PASS
    assert "No expected digest" in results[0].detail


# ---------------------------------------------------------------------------
# Integration with examples/
# ---------------------------------------------------------------------------


def test_example_artifact_checksum() -> None:
    """Verify the committed example artifact matches its checksum file."""
    base = Path(__file__).parent.parent / "examples"
    artifact = base / "artifact.bin"
    checksum = base / "artifact.bin.sha256"
    if not artifact.exists() or not checksum.exists():
        pytest.skip("Example artifact or checksum not present")
    result = verify_checksum_file(artifact, checksum)
    assert result.status == VerificationStatus.PASS, result.detail
