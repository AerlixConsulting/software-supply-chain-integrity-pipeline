# Architecture Overview

## Introduction

The **Software Supply Chain Integrity Pipeline** is a reference implementation that demonstrates how organizations can achieve end-to-end visibility and verifiability across their software supply chain. The pipeline integrates SBOM generation, dependency auditing, build attestation, and artifact verification into a cohesive Python toolkit with a unified CLI.

This document describes the high-level architecture, the major components, their responsibilities, and how they interact.

---

## Design Goals

1. **Transparency** — Every software component used in a build is catalogued in a machine-readable SBOM.
2. **Auditability** — All audit results, attestations, and verification outcomes are written as immutable JSON records suitable for submission to compliance teams or automated governance gates.
3. **Integrity** — Build outputs are cryptographically bound to their inputs through SHA-256/SHA-512 digests and optional RSA-PSS signatures embedded in DSSE attestation envelopes.
4. **Standards Alignment** — The implementation directly maps to SLSA v1.0, in-toto, CycloneDX 1.5, NIST SP 800-53, and the NIST Cybersecurity Framework.
5. **Extensibility** — Each module is independently usable and replaceable. The vulnerability feed, license policy, and signing key material are all externally configurable.

---

## Component Summary

| Component | Module | Primary Output |
|---|---|---|
| SBOM Generator | `src/sbom_generator.py` | `sbom.json` (CycloneDX 1.5) |
| Dependency Auditor | `src/dependency_audit.py` | `dependency_risk_report.json` |
| Attestation Generator | `src/build_attestation.py` | `attestation.json` (DSSE) |
| Artifact Verifier | `src/artifact_verifier.py` | Verification result + report |
| CLI | `src/cli.py` | Orchestration of all above |

---

## Data Flow Summary

```
requirements.txt
       │
       ▼
┌─────────────────┐        ┌──────────────────────────┐
│  SBOM Generator │──────▶ │  sbom.json (CycloneDX)   │
└─────────────────┘        └──────────────────────────┘
       │
       ▼
┌──────────────────┐       ┌──────────────────────────────┐
│ Dependency Audit │──────▶│  dependency_risk_report.json │
└──────────────────┘       └──────────────────────────────┘
       │
       ▼
┌────────────────────────┐  ┌──────────────────────────┐
│  Attestation Generator │─▶│  attestation.json (DSSE) │
└────────────────────────┘  └──────────────────────────┘
       │
       ▼
┌──────────────────┐       ┌──────────────────────────┐
│ Artifact Verifier│──────▶│  verification_report.json│
└──────────────────┘       └──────────────────────────┘
```

---

## Key Architectural Decisions

### CycloneDX 1.5 as SBOM Format

CycloneDX 1.5 was selected over SPDX 2.3 for its tighter integration with vulnerability databases (VEX), more compact JSON representation, and broader tooling ecosystem adoption.

### DSSE Envelope for Attestations

The Dead Simple Signing Envelope (DSSE) format was chosen for attestations because it is the foundation of both SLSA provenance and in-toto. The format is simple, extensible, and supports RSA-PSS, ECDSA, and other signing algorithms.

### Local Vulnerability Feed Stub

The vulnerability feed in `dependency_audit.py` is intentionally implemented as a local in-memory structure. In production deployments this would be replaced by an integration with:

- [OSV (Open Source Vulnerabilities)](https://osv.dev)
- [NVD (National Vulnerability Database)](https://nvd.nist.gov)
- A commercial SCA API (Snyk, Mend, Grype)

### Modular Design

Each module exports a clear Python API in addition to CLI support. This allows the pipeline to be embedded directly into CI/CD systems, policy engines, or governance platforms without the CLI layer.

---

## Related Documentation

- [Use Cases](use-cases.md)
- [Design Decisions](design-decisions.md)
- [Control Mapping](../controls/control-mapping.md)
