from __future__ import annotations
from datetime import date
from pathlib import Path

def main() -> None:
    today = date.today().isoformat()
    out_dir = Path("generated")
    out_dir.mkdir(parents=True, exist_ok=True)

    content = f"""Vulnerability Triage Log (Generated)

Date: {today}
Item: example-lib 2.3
Severity: Moderate
Decision: Upgrade scheduled
Rationale: No active exploit; mitigation in place (reference)
Owner: Engineering
Review Date: {today}
"""
    (out_dir / f"vuln-triage-{today}.md").write_text(content, encoding="utf-8")
    print("Wrote triage log.")

if __name__ == "__main__":
    main()
