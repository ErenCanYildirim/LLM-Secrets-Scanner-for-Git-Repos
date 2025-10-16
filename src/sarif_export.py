import json
from typing import Dict, Any, List


def export_to_sarif(report: Dict[str, Any], output_file: str = "results.sarif") -> str:
    """Exports the results of the Scan to a SARIF format"""

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Git-Secrets-Scanner",
                        "informationUri": "https://github.com/ErenCanYildirim/LLM-Git-Repo-Secrets-Scanner",
                        "version": "1.0.0",
                        "rules": _generate_rules(report),
                    }
                },
                "results": _generate_results(report),
            }
        ],
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)

    return output_file


def _generate_rules(report: Dict[str, Any]) -> List[Dict]:
    """Function to generate SARIF rule definitions from finding types

    The function collects unique finding types and creates a rule entry for each.
    """

    finding_types = set()

    for findings in report.get("findings_by_commit", {}).values():
        for finding in findings:
            finding_types.add(finding.get("finding_type", "unknown"))

    rules = []
    for finding_type in sorted(finding_types):
        rules.append(
            {
                "id": finding_type,
                "name": finding_type.replace("_", " ").title(),
                "shortDescription": {
                    "text": f"Detects {finding_type.replace('_', ' ')}"
                },
                "fullDescription": {
                    "text": f"This rule identifies potential {finding_type.replace('_', ' ')} in the codebase."
                },
                "help": {
                    "text": "Remove hardcoded secrets and use environment variables or secret management services."
                },
                "defaultConfiguration": {"level": "error"},
                "properties": {"tags": ["security", "secrets"], "precision": "high"},
            }
        )

    return rules


def _generate_results(report: Dict[str, Any]) -> List[Dict]:
    """Generate a list of SARIF result objects from the scan report findings

    This function iterates over commits and their findings and constructs a SARIF 'result' dict for each finding. Each result includes:
     - rule reference
     - severity level
     - message
     - location details
     - fingerprints for deduplication
    """
    results = []

    for commit_hash, findings in report.get("findings_by_commit", {}).items():
        for finding in findings:
            confidence = finding.get("confidence", "low")

            result = {
                "ruleId": finding.get("finding_type", "unknown"),
                "level": _map_level(confidence),
                "message": {
                    "text": finding.get("rationale", "Potential secret detected")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get("file_path", "unknown"),
                                "uriBaseId": "SRCROOT",
                            },
                            "region": {
                                "startLine": finding.get("line_number", 1),
                                "snippet": {"text": finding.get("snippet", "")},
                            },
                        }
                    }
                ],
                "partialFingerprints": {
                    "commitHash": (
                        commit_hash[:8]
                        if commit_hash != "uncommitted"
                        else "uncommitted"
                    )
                },
                "properties": {
                    "confidence": confidence,
                    "commit": (
                        commit_hash[:8]
                        if commit_hash != "uncommitted"
                        else "uncommitted"
                    ),
                    "author": finding.get("author", "unknown"),
                    "date": finding.get("date", "unknown"),
                },
            }
            results.append(result)

    return results


def _map_level(confidence: str) -> str:
    mapping = {"high": "error", "medium": "warning", "low": "note"}
    return mapping.get(confidence.lower(), "note")
