import os
import re
import shutil
import tempfile
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import asdict
import hashlib
from dotenv import load_dotenv

from patterns_registry import PatternRegistry
from llm_analyzer import LLMAnalyzer
from data_classes import Finding

try:
    import git
    from git import Repo
except ImportError:
    print("Error: Git for python not installed, install via: pip install GitPython")
    sys.exit(1)

load_dotenv()

logger = logging.getLogger(__name__)


class SecretsScanner:
    """This class handles github repo cloning, and runs the secret scanning"""

    def __init__(self, repo_path: str, num_commits: int = 10, redaction: int = 1):
        """
        Initializes SecretsScanner

        Args:
            repo_path (str): Local path or remote URL for the Git repo.
            num_commits (int, optional): Number of recent commits to scan with a default of 10.
            redaction (int, optional): 1 = true, and the redact_snippet() function applies, else 0. default=1

        The function initializes the PatternRegistry, LLMAnalyzer and an in-memory cache
        """

        self.repo_path = repo_path
        self.num_commits = num_commits
        self.redaction = redaction
        self.pattern_registry = PatternRegistry()
        self.llm_analyzer = LLMAnalyzer()
        self.temp_dir = None
        self.repo = None

        # In memory cache for LLM calls
        self._analyzed_cache = {}

        # Stats for LLM-Cache tracking, however not further implemented in the code for now.
        self.stats = {"llm_calls": 0, "cache_hits": 0, "files_processed": 0}

    def _get_chunk_size(self) -> int:
        """Gets the chunk size from the env. variable, default fallback"""
        try:
            return int(os.getenv("CHUNK_SIZE", 2000))
        except ValueError:
            logger.warning("Invalid CHUNK_SIZE env var, using default 2000")
            return 2000

    def _get_content_hash(self, content: str) -> str:
        """generate a hash of a content for caching llm calls"""
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _clone_remote_repo(self, url: str) -> str:
        """clones a remote Git repo into a temporary directory"""

        self.temp_dir = tempfile.mkdtemp(prefix="git_scan_")
        logger.info(f"Cloning repository to {self.temp_dir}...")

        try:
            Repo.clone_from(url, self.temp_dir, depth=self.num_commits + 10)
            return self.temp_dir
        except Exception as e:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            raise Exception(f"Failed to clone repository: {e}")

    def _is_remote_url(self, path: str) -> bool:
        return path.startswith(("http://", "https://", "git@", "ssh://"))

    def _setup_repo(self) -> Repo:
        """Sets up and returns a GitPython repo"""

        if self._is_remote_url(self.repo_path):
            local_path = self._clone_remote_repo(self.repo_path)
        else:
            local_path = self.repo_path

        if not os.path.exists(local_path):
            raise Exception(f"Repository path does not exist: {local_path}")

        try:
            return Repo(local_path)
        except Exception as e:
            raise Exception(f"Invalid Git repository: {e}")

    def _apply_regex_patterns(self, content: str) -> List[Dict[str, Any]]:
        """
        This method applies the regex patterns from the pattern registry to detect
        common secrets.
        """
        findings = []
        patterns = self.pattern_registry.get_pattern()
        # logger.debug(    f"Total patterns to check: {len(self.pattern_registry.get_pattern())}")
        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                # logger.debug(f"Testing pattern: {pattern.name}")
                if pattern.regex:
                    matches = re.finditer(pattern.regex, line)
                    for match in matches:
                        # logger.debug(f"Match found for {pattern.name} at line {i}")
                        findings.append(
                            {
                                "line": i,
                                "snippet": line[
                                    max(0, match.start() - 20) : min(
                                        len(line), match.end() + 20
                                    )
                                ],
                                "type": pattern.name,
                                "confidence": (
                                    "high"
                                    if pattern.confidence_boost > 0.3
                                    else "medium"
                                ),
                                "rationale": f"Regex pattern match for {pattern.description}",
                                "pattern_match": True,
                            }
                        )

        return findings

    def _deduplicate_findings(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """This method ensures that duplicate detections from the regex-pattern matching and the LLM-search are
        removed.
        """

        seen = set()
        deduplicated = []

        for f in findings:
            key = (f.get("line"), f.get("type"), f.get("snippet", "")[:50])
            if key not in seen:
                seen.add(key)
                deduplicated.append(f)

        return deduplicated

    def _scan_uncommitted_changes(self) -> List[Finding]:
        """Scans uncommitted changes (staged, unstaged and untracked) for secrets"""

        logger.info("Scanning uncommitted changes...")
        findings = []

        logger.debug("Checking staged diff...")

        staged_diff = self.repo.index.diff("HEAD")
        for diff in staged_diff:
            if diff.b_path:
                logger.debug(f"Processing staged file: {diff.b_path}")
                content = self._get_file_content(diff.b_path)
                if content:
                    findings.extend(
                        self._analyze_content(
                            content, "uncommitted", diff.b_path, is_uncommitted=True
                        )
                    )

        logger.debug("Checking unstaged diff")
        # unstaged changes
        unstaged_diff = self.repo.index.diff(None)
        for diff in unstaged_diff:
            if diff.b_path:
                logger.debug(f"Processing unstaged file: {diff.b_path}")
                content = self._get_file_content(diff.b_path)
                if content:
                    findings.extend(
                        self._analyze_content(
                            content, "uncommitted", diff.b_path, is_uncommitted=True
                        )
                    )

        # logger.debug("Checking untracked files...")
        # untracked files
        for item in self.repo.untracked_files:
            # logger.debug(f"Processing untracked file: {item}")
            content = self._get_file_content(item)
            if content:
                findings.extend(
                    self._analyze_content(
                        content, "uncommitted", item, is_uncommitted=True
                    )
                )

        return findings

    def _get_file_content(self, file_path: str) -> Optional[str]:
        """Reads file content from the repos working directory, while skipping binaries.

        This function checks for null bytes to detect binaries.
        """

        full_path = os.path.join(self.repo.working_dir, file_path)

        if os.path.exists(full_path):
            try:
                with open(full_path, "rb") as f:
                    chunk = f.read(1024)
                    if b"\x00" in chunk:
                        return None

                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read()

            except Exception as e:
                logger.debug(f"Could not read file: {file_path}: {e}")
        return None

    def redact_snippet(self, snippet: str, finding_type: str) -> str:
        """redacts sensitive parts of the secret snippets to ensure context without leaking data
        this function is not fully fleshed out, improvements may be made for proper redaction.
        """

        if self.redaction == 0:
            return snippet

        if finding_type in ["aws_secret_key", "aws_secret_access_key"]:
            return re.sub(
                r'["\']([^"\']{20,})["\']', '"[REDACTED-AWS-SECRET]"', snippet
            )

        # for keys and tokens, we only show first 4 and last 4 chars
        if finding_type in [
            "aws_access_key",
            "github_token",
            "api_key_generic",
            "stripe_key",
            "jwt_token",
            "slack_token",
        ]:
            if len(snippet) > 12:
                # the below regex patterns are matching secrets in quotes and after equals signs to extract the actual secret from the snippet
                for pattern in [r'["\']([^"\']{12,})["\']', r"=\s*([^\s]{12,})"]:
                    match = re.search(pattern, snippet)
                    if match:
                        secret = match.group(1)
                        redacted = secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
                        return snippet.replace(secret, redacted)

        # for passwords only the structure is shown
        if finding_type == "password":
            return re.sub(r'["\']([^"\']{8,})["\']', '"********"', snippet)

        # shows the beginning of private keys
        if "private_key" in finding_type:
            return snippet[:10] + "...[REDACTED]"

        # db conn strings
        if finding_type in ["db_connection", "connection_string"]:
            snippet = re.sub(
                r"(password=|pwd=|:)([^;@\s]+)",
                r"\1********",
                snippet,
                flags=re.IGNORECASE,
            )

            # username followed by password is redacted
            snippet = re.sub(
                r"(user=|username=|uid=)([^;:\s]+)",
                r"\1****",
                snippet,
                flags=re.IGNORECASE,
            )
            return snippet

        # fully redacts encryption keys instead of masking partially
        if finding_type in ["encryption_key", "hex_secret"]:
            return re.sub(r'["\']([^"\']{16,})["\']', '"[REDACTED-KEY]"', snippet)

        # show structure for s3 bucket, redacts sensitive parts
        if finding_type == "s3_bucket_url":
            return re.sub(r"(s3://[^/]+/)(.+)", r"\1[REDACTED-PATH]", snippet)

        return snippet

    def _analyze_content(
        self,
        content: str,
        commit_hash: str,
        file_path: str,
        author: str = None,
        date: str = None,
        is_uncommitted: bool = False,
    ) -> List[Finding]:
        """
        Analyzes a chunks content for secrets using regex and LLM.
        Caching checks if the chunk has been processed before sending it to the LLM.

        NOTE: Chunk_size is 2000 chars for now.
        """

        findings = []

        self.stats["files_processed"] += 1

        logger.debug(f"Analyzing content for {file_path}, length: {len(content)}")

        if len(content) < 10:
            return findings

        content_hash = self._get_content_hash(content)
        cache_key = f"{file_path}:{content_hash}"

        if cache_key in self._analyzed_cache:
            logger.info(f"Cache hit for {file_path}")
            self.stats["cache_hits"] += 1

            cached_findings = self._analyzed_cache[cache_key]
            return [
                Finding(
                    commit_hash=commit_hash,
                    file_path=file_path,
                    line_number=f.line_number,
                    snippet=f.snippet,
                    finding_type=f.finding_type,
                    confidence=f.confidence,
                    rationale=f.rationale,
                    author=author,
                    date=date,
                    is_uncommitted=is_uncommitted,
                )
                for f in cached_findings
            ]

        try:
            regex_findings = self._apply_regex_patterns(content)
            # logger.debug(f"Regex findings: {len(regex_findings)}")
        except Exception as e:
            logger.error(f"Error in regex patterns: {e}")
            raise

        # 2kb chunks for content processing
        chunk_size = self._get_chunk_size()
        chunks = [
            content[i : i + chunk_size] for i in range(0, len(content), chunk_size)
        ]

        llm_findings = []
        patterns = self.pattern_registry.get_pattern()

        for idx, chunk in enumerate(chunks, start=1):
            # logger.debug(f"Processing chunk {idx}/{min(5, len(chunks))}")
            try:
                chunk_findings = self.llm_analyzer.analyze_chunk(chunk, patterns)
                logger.info(f"LLM findings in chunk {idx+1}: {len(chunk_findings)}")
                llm_findings.extend(chunk_findings)
            except Exception as e:
                logger.warning(f"LLM analysis failed for chunk: {idx}: {e}")
                continue

        all_findings = self._deduplicate_findings(regex_findings + llm_findings)
        # logger.debug(f"Total findings after deduplication: {len(all_findings)}")

        for f in all_findings:
            snippet = f.get("snippet", "")[:200]
            redacted_snippet = self.redact_snippet(snippet, f.get("type", "unknown"))

            findings.append(
                Finding(
                    commit_hash=commit_hash,
                    file_path=file_path,
                    line_number=f.get("line"),
                    snippet=redacted_snippet,
                    finding_type=f.get("type", "unknown"),
                    confidence=f.get("confidence", "low"),
                    rationale=f.get("rationale", "Potential secret detected"),
                    author=author,
                    date=date,
                    is_uncommitted=is_uncommitted,
                )
            )

        self._analyzed_cache[cache_key] = findings

        return findings

    def scan(self) -> Dict[str, Any]:
        """
        Performs a full secret scan on the repo (uncommitted + committed) and builds the report.
        """

        logger.info("Starting repo scanning...")

        try:
            self.repo = self._setup_repo()
            all_findings = []

            # first uncommitted changes are scanned
            all_findings.extend(self._scan_uncommitted_changes())

            # last N commits
            commits = list(self.repo.iter_commits("HEAD", max_count=self.num_commits))
            logger.info(f"Scanning last {len(commits)} commits...")

            all_findings.extend(self._scan_commits(commits))

            report = self._build_report(commits, all_findings)
            return report

        finally:
            self._cleanup_temp_files()

    def _scan_commits(self, commits: List[Any]) -> List[Any]:
        all_findings = []

        for i, commit in enumerate(commits, 1):
            logger.info(f"Processing commit: {i}/{len(commits)} : {commit.hexsha[:8]}")
            all_findings.extend(self._scan_commit_message(commit))
            all_findings.extend(self._scan_commit_diffs(commit))

        return all_findings

    def _scan_commit_message(self, commit: Any) -> List[Any]:
        commit_message = commit.message
        if commit_message and len(commit_message) > 5:
            # logger.debug(f"Scanning commit message: {commit_message[:50]}...")
            return self._analyze_content(
                commit_message,
                commit.hexsha,
                file_path="<commit_message>",
                author=(
                    commit.author.email
                    if commit.author and hasattr(commit.author, "email")
                    else None
                ),
                date=(
                    commit.committed_datetime.isoformat()
                    if commit.committed_datetime
                    else None
                ),
            )
        return []

    def _get_commit_diffs(self, commit: Any) -> List[Any]:
        """check git history to get diffs, else takes the initial commit"""
        if commit.parents:
            return commit.parents[0].diff(commit)
        else:
            return commit.diff(None)

    def _get_diff_content(self, diff: Any) -> str:
        if diff.b_blob:
            return diff.b_blob.data_stream.read().decode("utf-8", errors="ignore")
        else:
            return self._get_file_content(diff.b_path)

    def _scan_commit_diffs(self, commit: Any) -> List[Any]:
        """
        Scans diffs in a commit for changed content containing secrets.

        Skips deleted files.
        """

        all_findings = []
        diffs = self._get_commit_diffs(commit)

        for diff in diffs:
            # skipping deleted files
            if not diff.b_path:
                continue

            try:
                content = self._get_diff_content(diff)
                if content:
                    findings = self._analyze_content(
                        content,
                        commit.hexsha,
                        diff.b_path,
                        author=(
                            commit.author.email
                            if commit.author and hasattr(commit.author, "email")
                            else None
                        ),
                        date=(
                            commit.committed_datetime.isoformat()
                            if commit.committed_datetime
                            else None
                        ),
                    )
                    all_findings.extend(findings)
            except Exception as e:
                logger.debug(f"Error processing {diff.b_path}: {e}")
                continue
        return all_findings

    def _build_report(
        self, commits: List[Any], all_findings: List[Any]
    ) -> Dict[str, Any]:
        """Compiles the findings into a structured report dictionary"""

        grouped_findings = self._group_findings_by_commit(all_findings)

        report = {
            "scan_info": self._build_scan_info(commits, all_findings),
            "findings_by_commit": grouped_findings,
            "summary": self._build_summary(all_findings),
        }

        return report

    def _group_findings_by_commit(
        self, all_findings: List[Any]
    ) -> Dict[str, List[Dict]]:
        grouped_findings = {}
        for finding in all_findings:
            commit = finding.commit_hash
            if commit not in grouped_findings:
                grouped_findings[commit] = []
            grouped_findings[commit].append(asdict(finding))

        return grouped_findings

    def _build_scan_info(
        self, commits: List[Any], all_findings: List[Any]
    ) -> Dict[str, Any]:
        uncommitted_findings = [
            f for f in all_findings if f.commit_hash == "uncommitted"
        ]

        return {
            "repository": self.repo_path,
            "scan_date": datetime.now().isoformat(),
            "commits_scanned": len(commits),
            "uncommitted_changes_scanned": len(uncommitted_findings) > 0,
            "total_findings": len(all_findings),
            "high_confidence": len([f for f in all_findings if f.confidence == "high"]),
            "medium_confidence": len(
                [f for f in all_findings if f.confidence == "medium"]
            ),
            "low_confidence": len([f for f in all_findings if f.confidence == "low"]),
        }

    def _build_summary(self, all_findings: List[Any]) -> Dict[str, Any]:
        summary = {"finding_types": {}}

        for finding in all_findings:
            f_type = finding.finding_type
            if f_type not in summary["finding_types"]:
                summary["finding_types"][f_type] = 0
            summary["finding_types"][f_type] += 1

        return summary

    def _cleanup_temp_files(self) -> None:
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            logger.info("Cleaned up temp. files")
