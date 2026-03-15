# Trust Boundaries

This diagram describes the trust boundaries within and around the Supply Chain Integrity Pipeline, identifying where cryptographic verification is required and where trust is assumed.

```mermaid
flowchart TB
    subgraph TB1["Trust Zone 1 — Developer Workstation (Untrusted)"]
        dev_code["Source Code\n(developer commits)"]
        dev_deps["requirements.txt\n(developer-managed)"]
    end

    subgraph TB2["Trust Zone 2 — CI / Build Environment (Conditionally Trusted)"]
        ci_pipeline["CI Workflow\n(GitHub Actions / GitLab CI)"]
        sbom_gen["SBOM Generator"]
        dep_audit["Dependency Auditor"]
        attest_gen["Attestation Generator"]
        private_key["Build Signing Key\n(ephemeral / HSM-backed)"]
        build_artifact["Build Artifact"]
    end

    subgraph TB3["Trust Zone 3 — Artifact Registry (Trusted Store)"]
        registry["Artifact Registry\n(immutable storage)"]
        sbom_store["sbom.json"]
        risk_store["dependency_risk_report.json"]
        attest_store["attestation.json"]
        checksum_store["artifact.bin.sha256"]
    end

    subgraph TB4["Trust Zone 4 — Deployment / Production (Highly Trusted)"]
        verifier["Artifact Verifier"]
        public_key["Public Verification Key\n(out-of-band distribution)"]
        deployment["Deployment System"]
    end

    subgraph TB5["Trust Zone 5 — Compliance / Audit (External)"]
        auditor["Compliance Auditor"]
    end

    %% Cross-boundary flows
    dev_code -->|"git push (authenticated)"| ci_pipeline
    dev_deps --> ci_pipeline

    ci_pipeline --> sbom_gen
    ci_pipeline --> dep_audit
    ci_pipeline --> attest_gen
    private_key -->|"signs attestation\n[TRUST BOUNDARY CROSSING]"| attest_gen

    sbom_gen -->|"SHA-256 verified upload\n[TRUST BOUNDARY CROSSING]"| sbom_store
    dep_audit --> risk_store
    attest_gen -->|"DSSE envelope\n[TRUST BOUNDARY CROSSING]"| attest_store
    build_artifact --> checksum_store

    sbom_store --> verifier
    attest_store --> verifier
    checksum_store --> verifier
    public_key -->|"out-of-band distribution\n[TRUST ANCHOR]"| verifier

    verifier -->|"PASS/FAIL\n[TRUST BOUNDARY CROSSING]"| deployment

    registry --> auditor
```

---

## Trust Boundary Analysis

### TB1 → TB2: Developer to CI

- **Risk**: Malicious code or dependency updates injected at commit time.
- **Mitigations**: Branch protection rules, code review requirements, signed commits, CODEOWNERS.
- **Pipeline role**: The CI environment is the first point where integrity checks are enforced automatically.

### TB2 → TB3: CI to Registry

- **Risk**: Man-in-the-middle attack between CI and the artifact registry; artifact substitution.
- **Mitigations**: TLS for all registry communications; artifact upload with content hash verification; immutable artifact storage.
- **Pipeline role**: The `artifact.bin.sha256` checksum file and `attestation.json` are the integrity anchors stored at this boundary.

### TB3 → TB4: Registry to Deployment

- **Risk**: Tampered artifact retrieved from registry; stale or replayed attestation.
- **Mitigations**: The `artifact_verifier.py` re-computes the digest before deployment; the attestation envelope's `buildFinishedOn` timestamp detects replay; the public key is distributed out-of-band (not via the registry itself).
- **Pipeline role**: `verify_checksum_file()` and `verify_signature()` enforce integrity at this crossing.

### Signing Key Trust

- The build signing key (private key) must be stored in a secrets manager or HSM, **never** committed to source control.
- The public verification key is distributed to deployment systems via a separate, trusted channel (e.g., organisation key ring, HashiCorp Vault, AWS KMS).
- Key rotation invalidates past signatures — teams should retain old public keys for verification of archived artifacts.

---

## Security Controls at Trust Boundaries

| Boundary | Control | NIST 800-53 |
|---|---|---|
| Developer → CI | Signed commits, branch protection | CM-3, SA-10 |
| CI → Registry | TLS, content hash upload | SI-7, SC-8 |
| CI Signing | HSM-backed signing key | SC-12, SC-17 |
| Registry → Deploy | Digest re-verification, signature check | SI-7, CM-14 |
| Audit Trail | Immutable attestation envelopes | AU-10, AU-9 |
