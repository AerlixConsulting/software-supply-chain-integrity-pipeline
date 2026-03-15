# Control Mapping

This document maps the capabilities of the Software Supply Chain Integrity Pipeline to security controls defined in:

- **NIST SP 800-53 Rev. 5** — Security and Privacy Controls for Information Systems and Organizations
- **NIST Cybersecurity Framework (CSF) 2.0** — Core Functions and Categories
- **NIST Risk Management Framework (RMF)** — Lifecycle Phases

---

## Capability-to-Control Matrix

### CA-01: SBOM Generation

**Capability**: Automated generation of CycloneDX 1.5 Software Bills of Materials from dependency lockfiles, providing a machine-readable inventory of all software components.

| Framework | Control ID | Control Name | Mapping Rationale |
|---|---|---|---|
| NIST 800-53 | **SA-12** | Supply Chain Protection | Direct: SBOM is the foundational artefact for supply chain transparency |
| NIST 800-53 | **CM-8** | System Component Inventory | Direct: SBOM provides the authoritative component inventory |
| NIST 800-53 | **SA-15** | Development Process, Standards and Tools | Supporting: SBOM documents the third-party components incorporated into development |
| NIST CSF 2.0 | **ID.AM-02** | Software assets are inventoried | Direct: CycloneDX SBOM is a software asset inventory |
| NIST CSF 2.0 | **GV.SC-06** | Cybersecurity practices are included in supplier contracts | Supporting: SBOM requirement in supplier agreements |
| NIST RMF | **Prepare / Select** | Identify system components for categorisation | SBOM supports component identification during RMF Prepare phase |

---

### CA-02: Dependency Vulnerability Audit

**Capability**: Automated assessment of third-party dependencies against a vulnerability feed (CVE/OSV), producing a structured risk report with severity scoring and remediation guidance.

| Framework | Control ID | Control Name | Mapping Rationale |
|---|---|---|---|
| NIST 800-53 | **RA-5** | Vulnerability Monitoring and Scanning | Direct: Automated vulnerability assessment of software components |
| NIST 800-53 | **SI-2** | Flaw Remediation | Direct: Risk report identifies components requiring remediation |
| NIST 800-53 | **SA-12** | Supply Chain Protection | Supporting: Dependency audit is a supply chain risk assessment activity |
| NIST 800-53 | **CM-14** | Signed Components | Supporting: Identifies unsigned or un-attested components |
| NIST CSF 2.0 | **ID.RA-01** | Vulnerabilities in assets are identified | Direct: Dependency audit identifies asset vulnerabilities |
| NIST CSF 2.0 | **ID.RA-02** | Cyber threat intelligence is received | Supporting: Vulnerability feed provides threat intelligence |
| NIST CSF 2.0 | **RS.AN-06** | Actions are performed to contain the impact | Supporting: CI gate blocks vulnerable dependencies |
| NIST RMF | **Assess** | Assess security control effectiveness | Dependency audit is a continuous assessment activity |

---

### CA-03: License Compliance Enforcement

**Capability**: Automated detection of dependencies with disallowed or unreviewed licenses, preventing introduction of copyleft or proprietary-licensed components.

| Framework | Control ID | Control Name | Mapping Rationale |
|---|---|---|---|
| NIST 800-53 | **SA-15** | Development Process, Standards and Tools | Direct: License policy is a development process control |
| NIST 800-53 | **CM-14** | Signed Components | Supporting: License compliance is a component acceptance criterion |
| NIST 800-53 | **SA-4** | Acquisition Process | Supporting: License terms are a component of acquisition requirements |
| NIST CSF 2.0 | **GV.SC-04** | Suppliers are known | Supporting: License status reflects known supplier terms |
| NIST RMF | **Select / Implement** | Select and implement controls | License policy is implemented as a CI gate control |

---

### CA-04: Build Attestation (Provenance)

**Capability**: Generation of cryptographically signed SLSA-level provenance attestations (in-toto DSSE envelopes) recording builder identity, build inputs, and build outputs.

| Framework | Control ID | Control Name | Mapping Rationale |
|---|---|---|---|
| NIST 800-53 | **SI-7** | Software, Firmware and Information Integrity | Direct: Attestation provides a cryptographic integrity record for build outputs |
| NIST 800-53 | **SA-10** | Developer Configuration Management | Direct: Attestation captures the configuration of build inputs and parameters |
| NIST 800-53 | **AU-10** | Non-Repudiation | Direct: Signed attestation provides non-repudiation of the build event |
| NIST 800-53 | **CM-14** | Signed Components | Direct: Attestation is the signed component record |
| NIST 800-53 | **SA-12** | Supply Chain Protection | Supporting: Provenance chain demonstrates supply chain integrity |
| NIST CSF 2.0 | **PR.DS-01** | Data-at-rest are protected | Supporting: Signed attestation protects the integrity of provenance data |
| NIST CSF 2.0 | **ID.SC-04** | Suppliers are routinely assessed | Supporting: Attestations enable ongoing assessment of build pipeline integrity |
| NIST RMF | **Implement / Assess** | Implement and assess integrity controls | Attestation implements and provides evidence of SI-7 compliance |

---

### CA-05: Artifact Integrity Verification

**Capability**: Cryptographic verification of artifact digests (SHA-256/SHA-512) and RSA-PSS signatures before deployment, preventing deployment of tampered or unverified artifacts.

| Framework | Control ID | Control Name | Mapping Rationale |
|---|---|---|---|
| NIST 800-53 | **SI-7** | Software, Firmware and Information Integrity | Direct: Artifact digest verification is the primary SI-7 implementation |
| NIST 800-53 | **CM-14** | Signed Components | Direct: Signature verification enforces the signed components policy |
| NIST 800-53 | **SA-12** | Supply Chain Protection | Supporting: Pre-deployment verification is a supply chain integrity gate |
| NIST 800-53 | **SC-12** | Cryptographic Key Establishment and Management | Supporting: RSA key management underpins signature verification |
| NIST CSF 2.0 | **PR.DS-02** | Data-in-transit are protected | Supporting: Digest verification detects in-transit tampering |
| NIST CSF 2.0 | **DE.CM-09** | Computing hardware and software are monitored | Supporting: Continuous verification detects integrity drift |
| NIST RMF | **Assess / Authorise** | Verify security controls before authorising operation | Artifact verification supports the RMF Authorise phase |

---

## SLSA Level Alignment

The pipeline demonstrates capabilities consistent with **SLSA Build Level 2** and provides building blocks toward **SLSA Build Level 3**:

| SLSA Requirement | Pipeline Capability | Status |
|---|---|---|
| Scripted build | CI workflow (`ci.yml`) | ✅ Implemented |
| Build service | GitHub Actions | ✅ Implemented |
| Provenance exists | `build_attestation.py` | ✅ Implemented |
| Provenance is authenticated | RSA-PSS signing | ✅ Implemented (key required) |
| Provenance non-falsifiable | DSSE envelope + PAE | ✅ Implemented |
| Isolated build | Ephemeral GitHub runner | ✅ Platform-provided |
| Parameterless top-level build | Declarative CI workflow | ✅ Implemented |

---

## RMF Lifecycle Mapping

| RMF Phase | Pipeline Activity |
|---|---|
| **Categorise** | SBOM provides component inventory for system categorisation |
| **Select** | License and vulnerability policies define applicable controls |
| **Implement** | SBOM generator, audit, attestation, and verifier implement controls |
| **Assess** | Automated audit reports serve as continuous assessment evidence |
| **Authorise** | Attestation and verification evidence support ATO package preparation |
| **Monitor** | Scheduled `supply-chain.yml` workflow provides continuous monitoring |
