from typing import List, Optional
from dataclasses import dataclass


@dataclass
class Finding:
    """Represents a single security finding detected during a scan"""

    commit_hash: str
    file_path: str
    line_number: Optional[int]
    snippet: str
    finding_type: str
    confidence: str
    rationale: str
    author: Optional[str]
    date: Optional[str]
    is_uncommitted: bool = False


@dataclass
class ScanPattern:
    """Defines a pattern that is used for detecting secrets or vulnerabilities in code scans"""

    name: str
    regex: Optional[str]
    keywords: List[str]
    description: str
    confidence_boost: float = 0.0
