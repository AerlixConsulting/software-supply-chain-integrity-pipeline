# System Context

This diagram shows the Software Supply Chain Integrity Pipeline in the context of the broader software delivery ecosystem — the external actors, systems, and trust boundaries it interacts with.

```mermaid
C4Context
    title Software Supply Chain Integrity Pipeline — System Context

    Person(dev, "Developer / Engineer", "Commits code, manages dependencies, and triggers builds")
    Person(soc, "Security Operations", "Monitors findings, triages vulnerabilities, reviews attestations")
    Person(auditor, "Compliance Auditor", "Reviews SBOM, risk reports, and attestation evidence")

    System(pipeline, "Supply Chain Integrity Pipeline", "Generates SBOMs, audits dependencies, produces attestations, and verifies artifact integrity")

    System_Ext(github, "GitHub / CI Platform", "Hosts source code and executes build workflows")
    System_Ext(registry, "Artifact Registry", "Stores build outputs, SBOMs, and attestations")
    System_Ext(vuln_db, "Vulnerability Database", "Provides CVE/vulnerability data (OSV, NVD)")
    System_Ext(policy_engine, "Policy Engine / Gate", "Enforces promotion policies based on audit results")

    Rel(dev, github, "Commits code and dependency updates")
    Rel(github, pipeline, "Triggers pipeline on push/PR")
    Rel(pipeline, registry, "Publishes SBOM, attestation, risk report")
    Rel(pipeline, vuln_db, "Queries vulnerability feed")
    Rel(pipeline, policy_engine, "Reports audit status via exit code")
    Rel(soc, registry, "Reviews findings and attestations")
    Rel(auditor, registry, "Downloads evidence packages")
```

---

## Key Actors

| Actor | Role |
|---|---|
| Developer | Initiates builds; responsible for resolving dependency findings |
| CI Platform | Automated execution environment; enforces exit-code-based gates |
| Artifact Registry | Persistent store for build outputs and integrity evidence |
| Vulnerability Database | Authoritative source of CVE data (OSV/NVD in production) |
| Policy Engine | Downstream consumer of audit exit codes and JSON reports |
| Security Operations | Monitors and triages ongoing vulnerability findings |
| Compliance Auditor | Independent review of evidence packages |
