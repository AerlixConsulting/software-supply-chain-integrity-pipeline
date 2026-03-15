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

"""Build Attestation — generates in-toto / SLSA-inspired provenance statements.

Produces a signed JSON envelope (DSSE — Dead Simple Signing Envelope) that
records:

* the build environment and builder identity,
* the set of materials (source digest, dependencies) consumed,
* the subjects (output artifacts with their digests),
* the build configuration and invocation parameters.

This implementation signs the attestation payload with an RSA-PSS private key
when one is supplied, or embeds a placeholder signature for demonstration
purposes when running without key material.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# DSSE payload type
# ---------------------------------------------------------------------------

_PAYLOAD_TYPE = "application/vnd.in-toto+json"
_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    """Return the hex-encoded SHA-256 digest of the file at *path*."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _encode_payload(payload: dict[str, Any]) -> str:
    """JSON-serialise and base64url-encode *payload* for DSSE."""
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _sign_payload(encoded_payload: str, private_key_path: Path | None) -> dict[str, str]:
    """Return a DSSE signature block.

    If *private_key_path* is provided and the ``cryptography`` package is
    available, signs with RSA-PSS SHA-256.  Otherwise returns a placeholder.
    """
    if private_key_path is not None and private_key_path.exists():
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding

            private_key_bytes = private_key_path.read_bytes()
            private_key = serialization.load_pem_private_key(private_key_bytes, password=None)

            pae = _pae(_PAYLOAD_TYPE, encoded_payload)
            signature = private_key.sign(  # type: ignore[call-arg]
                pae,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.DIGEST_LENGTH,
                ),
                hashes.SHA256(),
            )
            return {
                "keyid": str(private_key_path),
                "sig": base64.b64encode(signature).decode("ascii"),
            }
        except Exception:
            pass  # fall through to placeholder

    # Placeholder signature — not cryptographically valid
    placeholder = base64.b64encode(b"PLACEHOLDER-SIGNATURE").decode("ascii")
    return {"keyid": "placeholder", "sig": placeholder}


def _pae(payload_type: str, encoded_payload: str) -> bytes:
    """Pre-Authentication Encoding as defined by the DSSE specification."""

    def le_int(n: int) -> bytes:
        return n.to_bytes(8, "little")

    pt_bytes = payload_type.encode("utf-8")
    ep_bytes = encoded_payload.encode("utf-8")
    return (
        b"DSSEv1 "
        + le_int(len(pt_bytes))
        + b" "
        + pt_bytes
        + b" "
        + le_int(len(ep_bytes))
        + b" "
        + ep_bytes
    )


# ---------------------------------------------------------------------------
# Attestation generation
# ---------------------------------------------------------------------------


def generate_attestation(
    *,
    artifact_paths: list[Path],
    source_uri: str,
    source_digest: str,
    builder_id: str = "https://github.com/AerlixConsulting/software-supply-chain-integrity-pipeline/.github/workflows/ci.yml",
    build_type: str = "https://slsa.dev/container-based-build/v0.1",
    private_key_path: Path | None = None,
    extra_materials: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Generate a SLSA provenance attestation in DSSE envelope format.

    Args:
        artifact_paths: Output artifacts to attest.  Each file's SHA-256 is
            computed and recorded as a *subject*.
        source_uri: Git repository URI of the source being built.
        source_digest: Git commit SHA (hex) of the source revision.
        builder_id: URI identifying the trusted build platform / workflow.
        build_type: URI identifying the build type schema.
        private_key_path: Optional path to a PEM-encoded RSA private key for
            signing.  When ``None`` a placeholder signature is embedded.
        extra_materials: Optional list of additional material entries to
            include in the provenance predicate.

    Returns:
        A DSSE envelope dict containing the base64-encoded payload and
        the signature block.
    """
    now = datetime.now(tz=timezone.utc).isoformat()

    subjects = [
        {
            "name": p.name,
            "digest": {"sha256": _sha256_file(p)},
        }
        for p in artifact_paths
        if p.exists()
    ]

    materials = [
        {
            "uri": source_uri,
            "digest": {"sha1": source_digest},
        }
    ]
    if extra_materials:
        materials.extend(extra_materials)

    predicate: dict[str, Any] = {
        "buildType": build_type,
        "builder": {
            "id": builder_id,
        },
        "invocation": {
            "configSource": {
                "uri": source_uri,
                "digest": {"sha1": source_digest},
                "entryPoint": ".github/workflows/ci.yml",
            },
            "parameters": {},
            "environment": {
                "GITHUB_RUN_ID": os.environ.get("GITHUB_RUN_ID", "local"),
                "GITHUB_SHA": os.environ.get("GITHUB_SHA", source_digest),
            },
        },
        "buildConfig": {},
        "metadata": {
            "buildStartedOn": now,
            "buildFinishedOn": now,
            "completeness": {
                "parameters": False,
                "environment": False,
                "materials": False,
            },
            "reproducible": False,
        },
        "materials": materials,
    }

    statement: dict[str, Any] = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": _PREDICATE_TYPE,
        "subject": subjects,
        "predicate": predicate,
    }

    encoded_payload = _encode_payload(statement)
    sig = _sign_payload(encoded_payload, private_key_path)

    envelope: dict[str, Any] = {
        "payloadType": _PAYLOAD_TYPE,
        "payload": encoded_payload,
        "signatures": [sig],
        "_metadata": {
            "statement_id": f"urn:uuid:{uuid.uuid4()}",
            "generated_at": now,
        },
    }
    return envelope


def generate_attestation_to_file(
    *,
    artifact_paths: list[Path],
    source_uri: str,
    source_digest: str,
    output_path: Path,
    private_key_path: Path | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Generate attestation and write it to *output_path*.

    Args:
        artifact_paths: Output artifacts to attest.
        source_uri: Git repository URI of the source.
        source_digest: Git commit SHA of the source revision.
        output_path: Destination path for the JSON attestation envelope.
        private_key_path: Optional PEM RSA private key path for signing.
        **kwargs: Additional keyword arguments forwarded to
            :func:`generate_attestation`.

    Returns:
        The generated attestation envelope dict.
    """
    envelope = generate_attestation(
        artifact_paths=artifact_paths,
        source_uri=source_uri,
        source_digest=source_digest,
        private_key_path=private_key_path,
        **kwargs,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    return envelope
