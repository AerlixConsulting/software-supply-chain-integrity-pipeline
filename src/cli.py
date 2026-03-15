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

"""CLI entrypoint for the Software Supply Chain Integrity Pipeline.

Usage::

    python -m src.cli --help
    python -m src.cli sbom   --requirements examples/requirements.txt --output out/sbom.json
    python -m src.cli audit  --requirements examples/requirements.txt --output out/risk_report.json
    python -m src.cli attest --artifact examples/artifact.bin \\
                             --source-uri https://github.com/org/repo \\
                             --source-digest abc123 \\
                             --output out/attestation.json
    python -m src.cli verify --artifact examples/artifact.bin \\
                             --checksum examples/artifact.bin.sha256
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _cmd_sbom(args: argparse.Namespace) -> int:
    from .sbom_generator import generate_sbom_to_file

    req_path = Path(args.requirements)
    out_path = Path(args.output)
    sbom = generate_sbom_to_file(req_path, out_path)
    component_count = len(sbom.get("components", []))
    print(f"[sbom] Generated CycloneDX 1.5 SBOM with {component_count} component(s) → {out_path}")
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    from .dependency_audit import audit_requirements_to_file

    req_path = Path(args.requirements)
    out_path = Path(args.output)
    report = audit_requirements_to_file(req_path, out_path)
    status = report.overall_status
    print(
        f"[audit] Audited {report.total_packages} package(s): "
        f"{report.pass_count} clean, {report.fail_count} with findings. "
        f"Overall status: {status} → {out_path}"
    )
    if status == "FAIL" and not args.no_fail:
        return 1
    return 0


def _cmd_attest(args: argparse.Namespace) -> int:
    from .build_attestation import generate_attestation_to_file

    artifact_paths = [Path(p) for p in args.artifacts]
    key_path = Path(args.private_key) if args.private_key else None
    out_path = Path(args.output)

    envelope = generate_attestation_to_file(
        artifact_paths=artifact_paths,
        source_uri=args.source_uri,
        source_digest=args.source_digest,
        output_path=out_path,
        private_key_path=key_path,
    )
    subject_count = len(json.loads(
        __import__("base64").urlsafe_b64decode(envelope["payload"] + "==").decode()
    ).get("subject", []))
    print(f"[attest] Attestation generated for {subject_count} subject(s) → {out_path}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    from .artifact_verifier import verify_checksum_file, verify_digest

    artifact_path = Path(args.artifact)
    if args.checksum:
        result = verify_checksum_file(artifact_path, Path(args.checksum))
    elif args.expected_digest:
        result = verify_digest(artifact_path, args.expected_digest)
    else:
        from .artifact_verifier import compute_digest

        digest = compute_digest(artifact_path)
        print(f"[verify] SHA-256 of {artifact_path.name}: {digest}")
        return 0

    status_icon = "✓" if result.status.value == "PASS" else "✗"
    print(
        f"[verify] {status_icon} {artifact_path.name}: {result.status.value} "
        f"(digest match={result.digest_match}, sig={result.signature_status.value})"
    )
    if result.detail:
        print(f"         {result.detail}")
    return 0 if result.status.value == "PASS" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pipeline",
        description="Software Supply Chain Integrity Pipeline CLI",
    )
    parser.add_argument("--version", action="version", version="0.1.0")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- sbom ---
    sp_sbom = subparsers.add_parser("sbom", help="Generate a CycloneDX SBOM from requirements.txt")
    sp_sbom.add_argument("--requirements", required=True, metavar="PATH", help="Path to requirements.txt")
    sp_sbom.add_argument("--output", required=True, metavar="PATH", help="Output JSON file path")

    # --- audit ---
    sp_audit = subparsers.add_parser("audit", help="Audit dependencies for vulnerabilities and license issues")
    sp_audit.add_argument("--requirements", required=True, metavar="PATH", help="Path to requirements.txt")
    sp_audit.add_argument("--output", required=True, metavar="PATH", help="Output risk report JSON file path")
    sp_audit.add_argument("--no-fail", action="store_true", help="Return exit code 0 even if findings exist")

    # --- attest ---
    sp_attest = subparsers.add_parser("attest", help="Generate a SLSA-inspired build attestation")
    sp_attest.add_argument(
        "--artifacts", nargs="+", required=True, metavar="PATH", help="One or more artifact paths to attest"
    )
    sp_attest.add_argument("--source-uri", required=True, metavar="URI", help="Source repository URI")
    sp_attest.add_argument("--source-digest", required=True, metavar="SHA", help="Git commit SHA of the source")
    sp_attest.add_argument("--output", required=True, metavar="PATH", help="Output attestation JSON file path")
    sp_attest.add_argument("--private-key", metavar="PATH", help="PEM private key for signing (optional)")

    # --- verify ---
    sp_verify = subparsers.add_parser("verify", help="Verify artifact digest and/or signature")
    sp_verify.add_argument("--artifact", required=True, metavar="PATH", help="Path to the artifact file")
    group = sp_verify.add_mutually_exclusive_group()
    group.add_argument("--checksum", metavar="PATH", help="Path to checksum file (.sha256 or .sha512)")
    group.add_argument("--expected-digest", metavar="HEX", help="Expected digest hex string")
    sp_verify.add_argument("--signature", metavar="PATH", help="Path to signature file (.sig)")
    sp_verify.add_argument("--public-key", metavar="PATH", help="Path to PEM public key for signature verification")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "sbom": _cmd_sbom,
        "audit": _cmd_audit,
        "attest": _cmd_attest,
        "verify": _cmd_verify,
    }
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
