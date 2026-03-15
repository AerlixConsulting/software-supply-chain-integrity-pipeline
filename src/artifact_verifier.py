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

"""Artifact Verifier — hashing and signature verification for build outputs.

Provides:

* SHA-256 / SHA-512 digest computation and checksum-file creation.
* Checksum file verification (both individual and batch).
* RSA-PSS signature verification using the ``cryptography`` library when
  available, with a safe fallback that clearly reports the limitation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUPPORTED_ALGORITHMS = {"sha256", "sha512"}
CHECKSUM_SUFFIX = {
    "sha256": ".sha256",
    "sha512": ".sha512",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class VerificationStatus(str, Enum):
    """Outcome of a verification operation."""

    PASS = "PASS"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"


@dataclass
class VerificationResult:
    """Result from a single artefact verification step."""

    artifact: str
    algorithm: str
    expected_digest: str
    actual_digest: str
    digest_match: bool
    signature_status: VerificationStatus
    status: VerificationStatus
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact,
            "algorithm": self.algorithm,
            "expected_digest": self.expected_digest,
            "actual_digest": self.actual_digest,
            "digest_match": self.digest_match,
            "signature_status": self.signature_status.value,
            "status": self.status.value,
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def compute_digest(artifact_path: Path, algorithm: str = "sha256") -> str:
    """Return the hex-encoded digest of *artifact_path*.

    Args:
        artifact_path: Path to the file to hash.
        algorithm: Hash algorithm — ``"sha256"`` or ``"sha512"``.

    Returns:
        Lowercase hex digest string.

    Raises:
        ValueError: If *algorithm* is not supported.
        FileNotFoundError: If *artifact_path* does not exist.
    """
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Choose from {SUPPORTED_ALGORITHMS}.")
    if not artifact_path.exists():
        raise FileNotFoundError(f"Artifact not found: {artifact_path}")

    h = hashlib.new(algorithm)
    with artifact_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_checksum_file(artifact_path: Path, algorithm: str = "sha256") -> Path:
    """Compute the digest and write a ``<artifact>.<algo>`` checksum file.

    The file follows the BSD-style ``<digest>  <filename>`` format.

    Args:
        artifact_path: Path to the artifact to hash.
        algorithm: Hash algorithm.

    Returns:
        Path to the written checksum file.
    """
    digest = compute_digest(artifact_path, algorithm)
    checksum_path = artifact_path.with_suffix(
        artifact_path.suffix + CHECKSUM_SUFFIX.get(algorithm, f".{algorithm}")
    )
    checksum_path.write_text(f"{digest}  {artifact_path.name}\n", encoding="utf-8")
    return checksum_path


def read_checksum_file(checksum_path: Path) -> tuple[str, str]:
    """Parse a checksum file and return ``(digest, filename)``.

    Args:
        checksum_path: Path to the checksum file.

    Returns:
        A ``(digest, filename)`` tuple.
    """
    line = checksum_path.read_text(encoding="utf-8").strip()
    parts = line.split(None, 1)
    if len(parts) != 2:
        raise ValueError(f"Malformed checksum file: {checksum_path}")
    return parts[0], parts[1]


# ---------------------------------------------------------------------------
# Digest verification
# ---------------------------------------------------------------------------


def verify_digest(
    artifact_path: Path,
    expected_digest: str,
    algorithm: str = "sha256",
) -> VerificationResult:
    """Verify the digest of *artifact_path* against *expected_digest*.

    Args:
        artifact_path: Path to the artifact to verify.
        expected_digest: The expected hex digest string.
        algorithm: Hash algorithm used to compute the expected digest.

    Returns:
        A :class:`VerificationResult` indicating pass or fail.
    """
    actual = compute_digest(artifact_path, algorithm)
    match = actual.lower() == expected_digest.lower()
    status = VerificationStatus.PASS if match else VerificationStatus.FAIL
    return VerificationResult(
        artifact=str(artifact_path),
        algorithm=algorithm,
        expected_digest=expected_digest,
        actual_digest=actual,
        digest_match=match,
        signature_status=VerificationStatus.SKIPPED,
        status=status,
        detail="" if match else f"Digest mismatch: expected {expected_digest}, got {actual}",
    )


def verify_checksum_file(artifact_path: Path, checksum_path: Path, algorithm: str = "sha256") -> VerificationResult:
    """Verify an artifact against its accompanying checksum file.

    Args:
        artifact_path: Path to the artifact to verify.
        checksum_path: Path to the ``.sha256`` / ``.sha512`` file.
        algorithm: Algorithm used in the checksum file.

    Returns:
        A :class:`VerificationResult`.
    """
    expected_digest, _ = read_checksum_file(checksum_path)
    return verify_digest(artifact_path, expected_digest, algorithm)


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


def verify_signature(
    artifact_path: Path,
    signature_path: Path,
    public_key_path: Path,
    algorithm: str = "sha256",
) -> VerificationResult:
    """Verify an RSA-PSS signature over the artifact digest.

    Uses the ``cryptography`` library when available.  Returns a
    ``SKIPPED`` result with an explanatory message if the library is not
    installed.

    Args:
        artifact_path: Path to the signed artifact.
        signature_path: Path to the ``.sig`` file containing the raw bytes of
            the RSA-PSS signature.
        public_key_path: Path to the PEM-encoded RSA public key.
        algorithm: Digest algorithm (used for the PSS hash and MGF1 hash).

    Returns:
        A :class:`VerificationResult` with ``signature_status`` indicating
        the outcome.
    """
    actual_digest = compute_digest(artifact_path, algorithm)

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        _HASH_MAP = {
            "sha256": hashes.SHA256(),
            "sha512": hashes.SHA512(),
        }
        hash_algo = _HASH_MAP.get(algorithm)
        if hash_algo is None:
            raise ValueError(f"Unsupported algorithm for signature verification: {algorithm}")

        public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
        raw_sig = signature_path.read_bytes()

        public_key.verify(  # type: ignore[call-arg]
            raw_sig,
            artifact_path.read_bytes(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hash_algo,
        )
        sig_status = VerificationStatus.PASS
        detail = "Signature verification passed."
    except ImportError:
        sig_status = VerificationStatus.SKIPPED
        detail = "cryptography package not installed; signature verification skipped."
    except InvalidSignature:
        sig_status = VerificationStatus.FAIL
        detail = "Signature verification FAILED — signature is invalid."
    except Exception as exc:
        sig_status = VerificationStatus.FAIL
        detail = f"Signature verification error: {exc}"

    overall = (
        VerificationStatus.FAIL
        if sig_status == VerificationStatus.FAIL
        else VerificationStatus.PASS
    )
    return VerificationResult(
        artifact=str(artifact_path),
        algorithm=algorithm,
        expected_digest="",
        actual_digest=actual_digest,
        digest_match=True,
        signature_status=sig_status,
        status=overall,
        detail=detail,
    )


# ---------------------------------------------------------------------------
# Batch verification (JSON report)
# ---------------------------------------------------------------------------


def verify_artifacts(
    artifacts: list[dict[str, Any]],
) -> list[VerificationResult]:
    """Batch-verify a list of artifact descriptors.

    Each descriptor is a dict with keys:

    * ``path`` (required): path to the artifact file.
    * ``checksum_path`` (optional): path to the checksum file.
    * ``expected_digest`` (optional): expected digest hex string.
    * ``algorithm`` (optional, default ``"sha256"``): algorithm.
    * ``signature_path`` (optional): path to the signature file.
    * ``public_key_path`` (optional): path to the public key PEM.

    Args:
        artifacts: List of artifact descriptor dicts.

    Returns:
        List of :class:`VerificationResult` objects.
    """
    results: list[VerificationResult] = []
    for desc in artifacts:
        path = Path(desc["path"])
        algo = desc.get("algorithm", "sha256")

        if "checksum_path" in desc:
            result = verify_checksum_file(path, Path(desc["checksum_path"]), algo)
        elif "expected_digest" in desc:
            result = verify_digest(path, desc["expected_digest"], algo)
        else:
            digest = compute_digest(path, algo)
            result = VerificationResult(
                artifact=str(path),
                algorithm=algo,
                expected_digest=digest,
                actual_digest=digest,
                digest_match=True,
                signature_status=VerificationStatus.SKIPPED,
                status=VerificationStatus.PASS,
                detail="No expected digest supplied; digest computed only.",
            )

        if "signature_path" in desc and "public_key_path" in desc:
            sig_result = verify_signature(path, Path(desc["signature_path"]), Path(desc["public_key_path"]), algo)
            result.signature_status = sig_result.signature_status
            if sig_result.signature_status == VerificationStatus.FAIL:
                result.status = VerificationStatus.FAIL
                result.detail += f" | {sig_result.detail}"

        results.append(result)
    return results


def verify_artifacts_to_file(
    artifacts: list[dict[str, Any]],
    output_path: Path,
) -> list[VerificationResult]:
    """Batch-verify artifacts and write a JSON report to *output_path*.

    Args:
        artifacts: List of artifact descriptor dicts.
        output_path: Destination for the JSON verification report.

    Returns:
        List of :class:`VerificationResult` objects.
    """
    results = verify_artifacts(artifacts)
    report = {
        "results": [r.to_dict() for r in results],
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r.status == VerificationStatus.PASS),
            "failed": sum(1 for r in results if r.status == VerificationStatus.FAIL),
            "skipped": sum(1 for r in results if r.status == VerificationStatus.SKIPPED),
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return results
