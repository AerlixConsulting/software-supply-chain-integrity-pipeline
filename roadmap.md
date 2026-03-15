# Roadmap

This document outlines the planned evolution of the Software Supply Chain Integrity Pipeline across three development phases.

---

## Current Release: v0.1.0

The initial release provides a complete reference implementation with:

- CycloneDX 1.5 SBOM generation from `requirements.txt` lockfiles
- Dependency vulnerability and license audit with local feed
- SLSA-inspired build attestation in DSSE envelope format
- SHA-256/SHA-512 artifact verification + RSA-PSS signature check
- Unified CLI (`python -m src.cli`)
- NIST 800-53 / CSF / RMF control mapping
- pytest test suite with 37 tests

---

## Phase 2: Production Integrations (v0.2.0)

**Target**: Q3 2024

### Vulnerability Feed

- [ ] **OSV API Integration** — Replace local stub with real-time queries to [osv.dev](https://osv.dev) for all supported ecosystems.
- [ ] **NVD API v2 Integration** — Secondary feed for NIST NVD CVE data with CVSS v3.1/v4.0 scoring.
- [ ] **Feed Caching** — Local cache with TTL to reduce API calls and support air-gapped environments.

### SBOM Enhancements

- [ ] **SPDX 2.3 Generator** — Add parallel SPDX JSON output for organisations requiring ISO/IEC 5962:2021 compliance.
- [ ] **Multi-Ecosystem Support** — Extend beyond `requirements.txt` to support `package-lock.json`, `go.sum`, `pom.xml`, `Gemfile.lock`.
- [ ] **VEX (Vulnerability Exploitability eXchange)** — Embed VEX statements in CycloneDX SBOMs to communicate exploitability context.

### Attestation

- [ ] **ECDSA P-256 Signing** — Add ECDSA signing support as a smaller-footprint alternative to RSA-PSS.
- [ ] **Sigstore Integration** — Support keyless signing via Sigstore/Fulcio with Rekor transparency log upload.
- [ ] **Attestation Verification CLI** — `python -m src.cli verify-attestation` command to verify DSSE envelopes.

### CI / Policy

- [ ] **GitHub Reusable Workflow** — Publish a reusable GitHub Actions workflow that other repositories can call.
- [ ] **OPA Policy Integration** — Emit OPA-compatible JSON reports for integration with Conftest policy gates.

---

## Phase 3: Enterprise Platform Features (v0.3.0)

**Target**: Q1 2025

### Governance and Reporting

- [ ] **Evidence Package Export** — Aggregate SBOM, risk report, attestation, and verification results into a single ZIP evidence package for ATO submissions.
- [ ] **OSCAL Integration** — Output findings mapped to OSCAL component definition and system security plan formats.
- [ ] **Dashboard** — Web-based dashboard (FastAPI + HTMX) for visualising supply chain posture across multiple services.

### Platform Integrations

- [ ] **AWS ECR / S3** — Native integration with ECR for container image SBOMs and S3 for evidence storage.
- [ ] **Azure Container Registry** — Azure-native SBOM and attestation upload.
- [ ] **HashiCorp Vault** — Vault Transit secrets engine integration for signing operations.

### Advanced Attestation

- [ ] **SLSA Build Level 3** — Implement hermetic, isolated build environment controls to achieve SLSA Build L3.
- [ ] **Binary Authorisation** — Integration with GCP Binary Authorisation or Kyverno for Kubernetes deployment gates.

### Compliance Expansion

- [ ] **FedRAMP Alignment** — Map capabilities to FedRAMP High baseline controls.
- [ ] **DoD CMMC 2.0** — Map capabilities to CMMC 2.0 Level 2 practices.
- [ ] **ISO 27001:2022** — Map capabilities to ISO 27001 Annex A controls.

---

## Long-Term Vision

The pipeline is designed to evolve from a standalone tool into a **supply chain governance platform** that:

1. Provides a centralised evidence store for all SBOMs, attestations, and risk reports across an organisation's portfolio.
2. Integrates with policy engines to enforce promotion gates automatically across all CI/CD platforms.
3. Generates ATO-ready evidence packages that map findings directly to NIST 800-53 control families.
4. Supports real-time alerting when new CVEs affect deployed component versions.

---

## Contributing to the Roadmap

If you have a use case not covered above, please open a GitHub issue with the label `enhancement`. See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to propose and contribute features.
