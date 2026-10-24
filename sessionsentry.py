"""Command-line entry point for SessionSentry."""
import argparse
import csv
import json
from pathlib import Path
from sessionsentry.analyzer import analyze_assessment


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit supplied web-session configuration evidence offline.")
    parser.add_argument("input", help="Path to a JSON assessment file")
    parser.add_argument("--json", dest="json_output", help="Write findings as JSON")
    parser.add_argument("--csv", dest="csv_output", help="Write findings as CSV")
    args = parser.parse_args()
    try:
        assessment = json.loads(Path(args.input).read_text(encoding="utf-8"))
        if not isinstance(assessment, dict):
            raise ValueError("The input JSON root must be an object")
        result = analyze_assessment(assessment)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    print(f"SessionSentry — {result['application']}")
    print(f"Risk: {result['risk_label']} ({result['risk_score']}/100)")
    print(f"Findings: {result['finding_count']}")
    print(result["score_note"])
    for item in result["findings"]:
        print(f"[{item['severity'].upper():8}] {item['rule_id']} {item['title']}")
        print(f"           Evidence: {item['evidence']}")
        print(f"           Fix:      {item['remediation']}")
    if args.json_output:
        output = Path(args.json_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"JSON report: {output}")
    if args.csv_output:
        output = Path(args.csv_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["rule_id", "title", "severity", "evidence", "remediation"])
            writer.writeheader()
            writer.writerows(result["findings"])
        print(f"CSV report: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
