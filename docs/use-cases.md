# Use Cases

This document describes the primary use cases for the Software Supply Chain Integrity Pipeline and the workflows they enable.

---

## UC-01: Generate SBOM for a Python Service

**Actor**: DevSecOps Engineer  
**Trigger**: Merging a dependency update PR or tagging a release  
**Preconditions**: A `requirements.txt` lockfile exists with pinned versions  

**Steps**:
1. The engineer invokes the SBOM generator against the lockfile.
2. A CycloneDX 1.5 JSON SBOM is produced listing all direct dependencies with name, version, PURL, and license.
3. The SBOM is uploaded to the artifact registry and stored alongside the build artifact.
4. Downstream consumers (vulnerability scanners, compliance teams) ingest the SBOM.

**Outcome**: Complete, machine-readable inventory of all software components in the release.

**Controls**: NIST 800-53 SA-12, CM-8, RA-5

---

## UC-02: Enforce Dependency Vulnerability and License Policy

**Actor**: CI/CD Pipeline (automated gate)  
**Trigger**: Every pull request and merge to `main`  
**Preconditions**: `requirements.txt` is present in the repository  

**Steps**:
1. The CI workflow invokes `python -m src.cli audit`.
2. Each dependency is checked against the vulnerability feed and license policy.
3. CRITICAL or HIGH findings cause the pipeline to return a non-zero exit code, blocking the PR.
4. A JSON risk report is archived as a CI artifact for review.

**Outcome**: Dependencies with known critical/high vulnerabilities or disallowed licenses are blocked before they enter the main branch.

**Controls**: NIST 800-53 RA-5, SI-2, SA-15, CM-14

---

## UC-03: Generate a SLSA Provenance Attestation

**Actor**: CI/CD Build System  
**Trigger**: Successful completion of a build job  
**Preconditions**: Build artifact exists; source commit SHA is available  

**Steps**:
1. The build system invokes `python -m src.cli attest` with artifact paths, source URI, and commit SHA.
2. The attestation generator computes SHA-256 digests of each artifact.
3. An in-toto statement is constructed capturing builder identity, invocation parameters, materials (source + dependencies), and subjects (outputs).
4. The statement is encoded in a DSSE envelope and optionally signed with an RSA-PSS private key.
5. The envelope is published to the artifact registry or attestation store.

**Outcome**: A cryptographically verifiable provenance record linking build outputs to their source inputs and build environment.

**Controls**: NIST 800-53 SI-7, SA-10, AU-10, CM-14

---

## UC-04: Verify Artifact Integrity Before Deployment

**Actor**: Deployment Operator / Automated Deployment System  
**Trigger**: Pre-deployment gate in the release pipeline  
**Preconditions**: Artifact and its checksum file are available; optional signature and public key are available  

**Steps**:
1. The operator invokes `python -m src.cli verify --artifact <path> --checksum <path.sha256>`.
2. The verifier computes the SHA-256 digest of the artifact and compares it to the expected value in the checksum file.
3. If a signature file and public key are provided, RSA-PSS signature verification is performed.
4. The result (PASS/FAIL) is logged and the exit code communicates pass/fail to the calling system.

**Outcome**: Confidence that the artifact has not been tampered with since it was built and signed.

**Controls**: NIST 800-53 SI-7, CM-14, SA-12

---

## UC-05: Compliance Reporting for Regulators

**Actor**: Compliance Officer / Security Operations  
**Trigger**: Quarterly compliance review or FedRAMP/FISMA audit  
**Preconditions**: SBOMs and risk reports have been generated for the current release  

**Steps**:
1. The compliance team collects the JSON SBOM, risk report, and attestation from the artifact store.
2. The SBOM provides the component inventory required by NTIA minimum elements.
3. The risk report documents the vulnerability assessment and license compliance posture.
4. The attestation provides cryptographic evidence of the build provenance chain.
5. These artefacts are submitted as evidence packages to the auditor.

**Outcome**: An auditable, machine-readable evidence package that satisfies supply chain transparency requirements for regulated environments.

**Controls**: NIST 800-53 SA-12, RA-5, AU-2, SI-7

---

## UC-06: Continuous Supply Chain Monitoring

**Actor**: Security Operations Centre (SOC)  
**Trigger**: Scheduled weekly run (via `supply-chain.yml` workflow) or new CVE advisory  

**Steps**:
1. The scheduled CI workflow regenerates the SBOM and re-runs the audit against the latest vulnerability feed.
2. New findings since the last run are highlighted in the updated risk report.
3. Alerts are raised via the CI notification channel for any new CRITICAL or HIGH findings.
4. The security team triages, remediates, or accepts findings with documented rationale.

**Outcome**: Ongoing awareness of newly discovered vulnerabilities in deployed software, enabling rapid response.

**Controls**: NIST 800-53 RA-5, SI-2, IR-6, CA-7
