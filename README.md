# Software Supply Chain Integrity Pipeline

[![CI](https://github.com/AerlixConsulting/software-supply-chain-integrity-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/AerlixConsulting/software-supply-chain-integrity-pipeline/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A **contract-ready reference implementation** for end-to-end software supply chain integrity, built by [Aerlix Consulting](https://aerlixconsulting.com). This pipeline demonstrates SBOM generation, dependency auditing, build attestation, and artifact verification aligned with SLSA, in-toto, NIST 800-53, and the NIST Cybersecurity Framework.

---

## Capabilities

| Capability | Description | Standards Alignment |
|---|---|---|
| **SBOM Generation** | Produces CycloneDX 1.5 JSON SBOMs from `requirements.txt` lockfiles | CycloneDX 1.5, NTIA Minimum Elements |
| **Dependency Audit** | Checks packages against a vulnerability feed and license policy | NIST SP 800-53 RA-5, SA-12 |
| **Build Attestation** | Generates SLSA-inspired provenance in DSSE envelope format | SLSA v1.0, in-toto |
| **Artifact Verification** | SHA-256/SHA-512 digest verification + RSA-PSS signature check | NIST SP 800-53 SI-7, CM-14 |

---

## Repository Structure

```
software-supply-chain-integrity-pipeline/
├── src/                        # Core Python modules
│   ├── sbom_generator.py       # CycloneDX SBOM generation
│   ├── dependency_audit.py     # Vulnerability & license audit
│   ├── build_attestation.py    # SLSA/in-toto attestation generation
│   ├── artifact_verifier.py    # Hashing & signature verification
│   └── cli.py                  # Unified CLI entrypoint
├── tests/                      # pytest test suite
├── examples/                   # Sample inputs and outputs
├── docs/                       # Deep documentation
├── architecture/               # Mermaid architecture diagrams
├── controls/                   # Compliance control mappings
├── assets/                     # Diagrams and images
├── tools/                      # Legacy workflow stubs
├── .github/workflows/          # CI workflows
├── pyproject.toml
├── LICENSE
└── README.md
```

---

## Quick Start

### Prerequisites

- Python 3.10+
- `pip`

### Installation

```bash
git clone https://github.com/AerlixConsulting/software-supply-chain-integrity-pipeline.git
cd software-supply-chain-integrity-pipeline
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography
```

### Generate an SBOM

```bash
python -m src.cli sbom \
  --requirements examples/requirements.txt \
  --output out/sbom.json
```

### Audit Dependencies

```bash
python -m src.cli audit \
  --requirements examples/requirements.txt \
  --output out/risk_report.json
```

### Generate a Build Attestation

```bash
python -m src.cli attest \
  --artifacts examples/artifact.bin \
  --source-uri https://github.com/AerlixConsulting/software-supply-chain-integrity-pipeline \
  --source-digest "$(git rev-parse HEAD)" \
  --output out/attestation.json
```

### Verify an Artifact

```bash
python -m src.cli verify \
  --artifact examples/artifact.bin \
  --checksum examples/artifact.bin.sha256
```

---

## Development

```bash
pip install ruff pytest cryptography
ruff check src/ tests/
pytest -v
```

---

## Documentation

- [Architecture Overview](docs/architecture-overview.md)
- [Use Cases](docs/use-cases.md)
- [Design Decisions](docs/design-decisions.md)
- [Control Mapping](controls/control-mapping.md)
- [Roadmap](roadmap.md)
- [Contributing](CONTRIBUTING.md)

---

## Architecture Diagrams

- [System Context](architecture/system-context.md)
- [Component Architecture](architecture/component-architecture.md)
- [Data Flow](architecture/data-flow.md)
- [Trust Boundaries](architecture/trust-boundaries.md)

---

## License

Copyright 2024 Aerlix Consulting. Licensed under the [Apache License, Version 2.0](LICENSE).

---

## Contact

- **Website**: [aerlixconsulting.com](https://aerlixconsulting.com)
- **Email**: [dylan@aerlixconsulting.com](mailto:dylan@aerlixconsulting.com)
