# Component Architecture

This diagram describes the internal component structure of the Supply Chain Integrity Pipeline and the data flows between them.

```mermaid
flowchart TB
    subgraph CLI["CLI Layer — src/cli.py"]
        cmd_sbom["sbom command"]
        cmd_audit["audit command"]
        cmd_attest["attest command"]
        cmd_verify["verify command"]
    end

    subgraph Core["Core Modules — src/"]
        sbom_gen["sbom_generator.py\n─────────────────\nparse_requirements()\ngenerate_sbom()\ngenerate_sbom_to_file()"]
        dep_audit["dependency_audit.py\n─────────────────\naudit_package()\naudit_requirements()\naudit_requirements_to_file()"]
        attestation["build_attestation.py\n─────────────────\ngenerate_attestation()\ngenerate_attestation_to_file()\n_sign_payload()"]
        verifier["artifact_verifier.py\n─────────────────\ncompute_digest()\nwrite_checksum_file()\nverify_digest()\nverify_checksum_file()\nverify_signature()\nverify_artifacts()"]
    end

    subgraph Data["Data / Policy"]
        vuln_feed["Vulnerability Feed\n(local + OSV API)"]
        license_policy["License Policy\n(allow / deny lists)"]
        signing_key["Signing Key\n(PEM RSA private key)"]
        public_key["Verification Key\n(PEM RSA public key)"]
    end

    subgraph Outputs["Outputs"]
        sbom_json["sbom.json\n(CycloneDX 1.5)"]
        risk_report["dependency_risk_report.json"]
        attestation_json["attestation.json\n(DSSE envelope)"]
        checksum_file["artifact.bin.sha256"]
        verify_report["verification_report.json"]
    end

    cmd_sbom --> sbom_gen
    cmd_audit --> dep_audit
    cmd_attest --> attestation
    cmd_verify --> verifier

    sbom_gen --> sbom_json
    dep_audit --> risk_report
    attestation --> attestation_json
    verifier --> checksum_file
    verifier --> verify_report

    dep_audit --> vuln_feed
    dep_audit --> license_policy
    attestation --> signing_key
    verifier --> public_key
```

---

## Module Responsibilities

### `sbom_generator.py`

- Parses `requirements.txt` format lockfiles.
- Maps package names to known SPDX license identifiers.
- Constructs CycloneDX 1.5 JSON with PURL identifiers for every component.
- Assigns BOM-ref identifiers using SHA-256 of the `name==version` string.

### `dependency_audit.py`

- Evaluates each package against a local vulnerability feed keyed by package name.
- Performs version range comparisons (`<`, `<=`, `>=`, `>`, `==`).
- Checks resolved license against allow and deny sets.
- Aggregates findings into an `AuditReport` with overall PASS/FAIL status.

### `build_attestation.py`

- Computes SHA-256 digests of all subject artifacts.
- Constructs an in-toto statement with SLSA provenance predicate.
- Encodes the statement using PAE (Pre-Authentication Encoding).
- Signs with RSA-PSS when a private key is provided; embeds a placeholder otherwise.
- Wraps in a DSSE envelope.

### `artifact_verifier.py`

- Supports SHA-256 and SHA-512 digest computation.
- Reads and writes BSD-style checksum files.
- Verifies artifact digests against expected values or checksum files.
- Verifies RSA-PSS signatures using the `cryptography` library.
- Supports batch verification with JSON report output.

### `cli.py`

- Provides a unified `argparse`-based CLI with four subcommands.
- Translates CLI arguments to module API calls.
- Returns appropriate exit codes for CI gate integration.
