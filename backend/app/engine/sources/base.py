"""Abstract base class for CVE data sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


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
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    kev_flag: bool = False
    cpe_names: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    raw_json: Optional[dict] = None


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
