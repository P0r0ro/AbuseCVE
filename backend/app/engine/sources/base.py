"""Abstract base class for CVE data sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone


@dataclass
class CVSSEntry:
    """A single CVSS score from a specific provider."""
    provider: str = ""
    score: Optional[float] = None
    vector: Optional[str] = None
    version: Optional[str] = None  # "2.0", "3.0", "3.1", "4.0"
    severity: Optional[str] = None  # LOW, MEDIUM, HIGH, CRITICAL


@dataclass
class NormalizedCVE:
    """Standardized CVE record from any source."""
    cve_id: str
    vendor: Optional[str] = None
    product: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    source: str = "UNKNOWN"
    sources: List[str] = field(default_factory=list)
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    kev_flag: bool = False
    cpe_names: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    raw_json: Optional[dict] = None
    cvss_scores: Dict[str, Any] = field(default_factory=dict)
    weaknesses: List[str] = field(default_factory=list)  # CWE IDs
    affected_products: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.source and self.source not in self.sources:
            self.sources.append(self.source)
        # DB columns are naive DateTime (UTC). Some feeds (Red Hat, MITRE)
        # return "...Z" timestamps that parse as tz-aware; asyncpg rejects
        # those for naive columns and dedup comparisons would raise too.
        self.published_date = _to_naive_utc(self.published_date)
        self.modified_date = _to_naive_utc(self.modified_date)


def _to_naive_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is not None and dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


class BaseCVESource(ABC):
    """Abstract base class for CVE data source connectors."""

    name: str = "base"

    @abstractmethod
    async def fetch_recent(self, since: Optional[datetime] = None) -> List[NormalizedCVE]:
        """Fetch recent CVEs, optionally since a given date."""
        ...

    @abstractmethod
    async def fetch_by_keyword(self, keyword: str) -> List[NormalizedCVE]:
        """Fetch CVEs matching a keyword search."""
        ...

    @abstractmethod
    async def fetch_all(self, start_index: int = 0, page_size: int = 2000) -> List[NormalizedCVE]:
        """Fetch all CVEs for local mirroring (paginated)."""
        ...
