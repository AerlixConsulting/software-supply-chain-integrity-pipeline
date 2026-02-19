# Software Supply Chain Integrity Pipeline

This project provides a framework for SBOM (Software Bill of Materials) governance and software supply chain integrity. It is designed to help organizations manage, analyze, and act upon dependency information in order to mitigate risks across the development lifecycle.

## Purpose

Modern software supply chains rely on numerous third‑party components. Maintaining visibility into these dependencies and ensuring they meet organizational standards is critical. This repository implements a structured workflow to:

- Generate and ingest SBOMs from various sources.
- Analyze packages and dependencies for known vulnerabilities and license compliance.
- Score and categorize supply chain risks.
- Enforce policies based on organizational risk appetite and compliance requirements.
- Produce audit‑ready reports for regulators and stakeholders.

The goal is to provide a repeatable, auditable process for supply chain integrity management.

## Key Features

- **SBOM ingestion and generation**: Support for CycloneDX, SPDX, and other SBOM formats.
- **Vulnerability analysis**: Integration with vulnerability databases and CVE feeds to flag insecure components.
- **License compliance**: Detection of incompatible or disallowed licenses.
- **Risk scoring**: Customizable risk scoring based on CVSS, exploit maturity, and organizational impact.
- **Policy enforcement**: Rules engine to block, warn, or allow components based on risk thresholds.
- **Reporting**: Generation of summary and detailed reports for auditors and compliance teams.
- **CI/CD integration**: Designed to plug into GitHub Actions, GitLab CI, or other pipelines to provide continuous assurance.

## Architecture Overview

At a high level, the pipeline performs the following steps:

1. **Ingest**: Accept SBOMs generated from build tools or scans and normalize them.
2. **Analyze**: Query vulnerability and license data for each component and compute risk scores.
3. **Evaluate**: Apply policy rules to determine if components meet acceptance criteria.
4. **Report**: Produce machine‑readable and human‑readable outputs summarizing findings.
5. **Enforce**: Optionally block deployments or alert owners when high risk issues are detected.

An architecture diagram can be placed in the `docs/` directory to illustrate data flow and system boundaries.

## Quick Start

The pipeline is written in Python and packaged as a reusable module. To run a basic analysis:

```
git clone https://github.com/AerlixConsulting/software-supply-chain-integrity-pipeline.git
cd software-supply-chain-integrity-pipeline
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# Generate or place your SBOM file (CycloneDX JSON or SPDX)
python tools/analyze_sbom.py --input path/to/sbom.json --output report.json
```

To run the test suite:

```
pip install -r requirements-dev.txt
pytest -v
```

You can also integrate this into a CI pipeline using the provided GitHub Actions workflow in `.github/workflows/ci.yml`.

## Security & Compliance

This project follows secure coding practices:

- Secrets and API keys should be provided via environment variables or a secrets manager (do not commit sensitive data).
- Dependency versions are pinned and monitored via Dependabot and security scanning features.
- Code scanning and automated tests validate functionality and guard against regressions.
- See the accompanying `SECURITY.md` for details on vulnerability reporting and disclosure.

## Contributing

Contributions are welcome! Please review the `CONTRIBUTING.md` for guidelines on how to propose changes, report issues, and submit pull requests. By participating in this project you agree to abide by the code of conduct outlined in `CODE_OF_CONDUCT.md`.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

For questions or support, contact the maintainers at Aerlix Consulting:

- Website: <https://aerlixconsulting.com>
- Email: <dylan@aerlixconsulting.com>
