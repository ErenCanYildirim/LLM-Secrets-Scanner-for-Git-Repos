import json
import sys
import argparse
import logging

from secrets_scanner import SecretsScanner
from llm_analyzer import LLMAnalyzer
from ollama_provider import OllamaProvider

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore.connection").setLevel(logging.WARNING)
logging.getLogger("httpcore.http11").setLevel(logging.WARNING)
logging.getLogger("git.cmd").setLevel(logging.WARNING)
logging.getLogger("git.util").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="Git repository secrets scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
            #Scan a local repository
            %(prog)s --repo /path/to/repo --n 10 --out report.json
            #Scan a remote repository
            %(prog)s --repo https://github.com/user/repo.git --n 20 --out report.json
            #scan with verbose output
            %(prog)s --repo . --n 5 --out report.json --verbose
        """,
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Path to local repository or remote URL (https)",
    )
    parser.add_argument(
        "--n", type=int, default=10, help="Number of commits to scan (default = 10)"
    )
    parser.add_argument(
        "--out",
        default="report.json",
        help="Output file for JSON report (default: report.json)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--model",
        default="llama3.2",
        help="Ollama model to use (default: llama3.2)",
    )

    parser.add_argument(
        "--redaction",
        choices=["0", "1"],
        default="1",
        help="Redaction for secrets in report (default=True(1))",
    )

    parser.add_argument(
        "--sarif",
        action="store_true",
        help="Export findings in SARIF format (compatible with GitHub, JetBrains IDEs, VS Code)",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        scanner = SecretsScanner(args.repo, args.n, redaction=int(args.redaction))

        provider = OllamaProvider(model_name=args.model, auto_start=True)
        scanner.llm_analyzer = LLMAnalyzer(provider=provider)

        logger.info(f"Scanning repository: {args.repo}")
        logger.info(f"Analyzing last: {args.n} commits")

        report = scanner.scan()

        with open(args.out, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print("Scan completed")
        print(f"Repository: {report['scan_info']['repository']}")
        print(f"Commits scanned: {report['scan_info']['commits_scanned']}")
        print(f"Total findings: {report['scan_info']['total_findings']}")
        print(f"High confidence: {report['scan_info']['high_confidence']}")
        print(f"Medium confidence: {report['scan_info']['medium_confidence']}")
        print(f"Low confidence: {report['scan_info']['low_confidence']}")
        print("Finding types:")
        for finding_type, count in report["summary"]["finding_types"].items():
            print(f"  - {finding_type}: {count}")
        print(f"Detailed report saved to: {args.out}")

        if args.sarif:
            from sarif_export import export_to_sarif

            sarif_file = export_to_sarif(report, "results.sarif")
            print(f"SARIF exported: {sarif_file}")

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
