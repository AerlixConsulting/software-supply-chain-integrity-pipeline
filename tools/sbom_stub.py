from __future__ import annotations
from datetime import date
from pathlib import Path
import json

def main() -> None:
    today = date.today().isoformat()
    out_dir = Path("generated")
    out_dir.mkdir(parents=True, exist_ok=True)

    sbom = {
        "generated": today,
        "format": "SBOM-stub",
        "components": [
            {"name": "example-service", "version": "1.0.0"},
            {"name": "PyYAML", "version": "6.x"},
        ],
        "notes": "Synthetic SBOM stub for portfolio demonstration.",
    }

    sbom_path = out_dir / f"sbom-{today}.json"
    sbom_path.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")

    summary = f"""SBOM Summary (Generated)
Generated: {today}
Component count: {len(sbom["components"])}

Components:
- example-service 1.0.0
- PyYAML 6.x
"""
    (out_dir / f"sbom-summary-{today}.md").write_text(summary, encoding="utf-8")
    print(f"Wrote {sbom_path}")

if __name__ == "__main__":
    main()
