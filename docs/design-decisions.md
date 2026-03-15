# Design Decisions

This document records the significant design choices made during the implementation of the Software Supply Chain Integrity Pipeline, the alternatives considered, and the rationale for each decision.

---

## DD-01: CycloneDX 1.5 over SPDX 2.3

**Decision**: Use CycloneDX 1.5 as the primary SBOM format.

**Context**: Two dominant SBOM standards exist: SPDX (Linux Foundation) and CycloneDX (OWASP). Both satisfy NTIA minimum elements.

**Alternatives considered**:
- SPDX 2.3 JSON — broader adoption in open-source tooling and the formal ISO/IEC 5962:2021 standard.
- CycloneDX 1.5 — native VEX support, cleaner JSON structure, tighter SLSA integration, broader commercial SCA tool support.

**Rationale**: CycloneDX 1.5 was selected because:
1. Its VEX (Vulnerability Exploitability eXchange) extension maps directly to the audit findings model.
2. The `purl` (Package URL) field provides a universally-parseable package identifier.
3. Its schema is more compact and predictable, reducing integration complexity.
4. Major SCA tools (Grype, Trivy, Snyk) natively consume CycloneDX JSON.

**Consequences**: SPDX generation is not provided in this release. The architecture is extensible — an `SpdxGenerator` class could be added to `sbom_generator.py` using the same `parse_requirements` foundation.

---

## DD-02: DSSE Envelope for Attestations

**Decision**: Use the Dead Simple Signing Envelope (DSSE) format for build attestation.

**Context**: Several envelope formats exist: JWS, JWT, OpenPGP armor, DSSE. The SLSA v1.0 specification mandates DSSE for provenance attestations.

**Rationale**:
1. DSSE is the format specified by SLSA v1.0 and in-toto v1.0.
2. It supports multiple signing algorithms without format changes.
3. The PAE (Pre-Authentication Encoding) construction prevents signature confusion attacks.
4. Tools like `cosign` and `slsa-verifier` can consume DSSE natively.

**Consequences**: Attestation envelopes are not directly verifiable with standard JWT tooling. A DSSE-aware verifier is required.

---

## DD-03: RSA-PSS for Signing

**Decision**: Use RSA-PSS (RSASSA-PSS) with SHA-256 for artifact and attestation signing.

**Context**: ECDSA (P-256) is faster and produces smaller signatures. RSA-PSS is more widely supported in enterprise environments, HSMs, and FIPS-validated modules.

**Rationale**:
1. RSA-2048 and RSA-4096 are universally supported across HSM vendors and FIPS 140-2 validated modules in federal environments.
2. PSS provides provably-secure padding (unlike PKCS#1 v1.5) while remaining compatible with existing RSA key infrastructure.
3. The `cryptography` library provides a high-quality, audited RSA-PSS implementation.

**Consequences**: Signatures are larger than ECDSA. The implementation uses the `cryptography` library as an optional dependency — if not installed, a clearly-labelled placeholder is embedded, and the system degrades gracefully rather than failing.

---

## DD-04: Local Vulnerability Feed Stub

**Decision**: Implement the vulnerability feed as a local in-memory dictionary with a small set of real CVE entries.

**Context**: Production deployments would integrate with OSV, NVD, or commercial APIs. Network-dependent lookups would complicate local testing and CI runs.

**Rationale**:
1. Local feed enables deterministic, network-free unit tests.
2. The API contract (`_VULN_FEED`, `audit_package`) is identical to what a production OSV client would need, making substitution straightforward.
3. Including real CVE IDs (CVE-2023-32681, CVE-2020-14343, etc.) makes the demonstration realistic and credible.

**Consequences**: The vulnerability data is not updated automatically. Operators integrating this into production should replace `_VULN_FEED` with an OSV or NVD API client.

---

## DD-05: Pure Standard Library Core (Optional `cryptography`)

**Decision**: The core pipeline modules (`sbom_generator.py`, `dependency_audit.py`) use only Python standard library. The `cryptography` package is an optional dependency used only for signing/verification.

**Rationale**:
1. Zero mandatory external dependencies simplifies deployment in air-gapped environments.
2. Signature operations are genuinely optional — an operator may choose to verify integrity via digest alone in lower-trust environments.
3. The `cryptography` library is audited, actively maintained, and available in most enterprise Python environments.

**Consequences**: Signature features (RSA-PSS sign/verify) silently degrade to placeholders or `SKIPPED` status when `cryptography` is not installed. The CLI and tests handle this gracefully.

---

## DD-06: Exit Code Semantics for CI Integration

**Decision**: The `audit` CLI command returns exit code `1` when CRITICAL or HIGH findings exist, and `0` otherwise. A `--no-fail` flag bypasses this.

**Rationale**:
1. Non-zero exit codes are the standard mechanism for CI pipeline gates (GitHub Actions, GitLab CI, Jenkins).
2. A separate `--no-fail` flag allows audit runs in monitoring-only mode without blocking deployments.
3. MEDIUM findings are reported but do not cause build failure — balancing security signal with developer experience.

**Consequences**: Teams must understand that MEDIUM findings are reported but not blocking. Organizations with stricter policies should modify the `overall_status` logic in `AuditReport`.
