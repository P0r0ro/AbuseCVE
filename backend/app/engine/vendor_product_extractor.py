"""Vendor/product extraction utilities.

Extracts vendor and product from multiple data sources within a CVE record,
used both during ingestion and for backfilling existing records.

Extraction priority:
1. CPE names (most reliable — structured data)
2. Affected products list
3. Source-specific raw_json parsing
4. Reference URL mining (GitHub/GitLab repo URLs)
5. Description text parsing (pattern-based)
6. sourceIdentifier (CNA email domain mapping — own-product CNAs only)
"""

from __future__ import annotations

import logging
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ── CNA email → vendor mapping ──────────────────────────────────────────────
# Maps sourceIdentifier email domains to known vendors.
# ONLY includes CNAs that report their OWN products (not third-party reporters).
CNA_VENDOR_MAP = {
    "asustor.com": "asustor",
    "apple.com": "apple",
    "cisco.com": "cisco",
    "dell.com": "dell",
    "f5.com": "f5",
    "fortinet.com": "fortinet",
    "huawei.com": "huawei",
    "ibm.com": "ibm",
    "intel.com": "intel",
    "juniper.net": "juniper",
    "lenovo.com": "lenovo",
    "microsoft.com": "microsoft",
    "mozilla.org": "mozilla",
    "oracle.com": "oracle",
    "paloaltonetworks.com": "paloaltonetworks",
    "qualcomm.com": "qualcomm",
    "redhat.com": "redhat",
    "sap.com": "sap",
    "samsung.com": "samsung",
    "siemens.com": "siemens",
    "sophos.com": "sophos",
    "suse.com": "suse",
    "synology.com": "synology",
    "trendmicro.com": "trendmicro",
    "vmware.com": "vmware",
    "zoom.us": "zoom",
    "zyxel.com.tw": "zyxel",
    "apache.org": "apache",
    "jenkins.io": "jenkins",
    "drupal.org": "drupal",
    "gitlab.com": "gitlab",
    "hashicorp.com": "hashicorp",
    "elastic.co": "elastic",
    "mongodb.com": "mongodb",
    "netapp.com": "netapp",
    "schneider-electric.com": "schneider-electric",
    "bosch.com": "bosch",
    "abb.com": "abb",
    "hp.com": "hp",
    "hpe.com": "hpe",
    "adobe.com": "adobe",
    "atlassian.com": "atlassian",
    "autodesk.com": "autodesk",
    "trellix.com": "trellix",
    "ivanti.com": "ivanti",
    "nvidia.com": "nvidia",
    "qnap.com": "qnap",
    "tp-link.com": "tp-link",
    "dlink.com": "d-link",
    "google.com": "google",
    "chromium.org": "google",
    "arm.com": "arm",
    "mattermost.com": "mattermost",
    "progress.com": "progress",
    "splunk.com": "splunk",
    "zscaler.com": "zscaler",
    "veritas.com": "veritas",
    "withsecure.com": "withsecure",
    "rockwellautomation.com": "rockwell_automation",
    "jci.com": "johnson_controls",
    "productsecurity@jci.com": "johnson_controls",
    "lge.com": "lg",
    "hitachi.co.jp": "hitachi",
    "open-xchange.com": "open-xchange",
    "hcl.com": "hcl",
    "psirt@hcl.com": "hcl",
    "linux.org.uk": "linux",
    "kernel.org": "linux",
    "canonical.com": "canonical",
    "debian.org": "debian",
    "fedoraproject.org": "fedora",
    "gentoo.org": "gentoo",
    "opensuse.org": "opensuse",
    "nozominetworks.com": "nozomi_networks",
    "tp-link.com.cn": "tp-link",
    "mediatek.com": "mediatek",
    "unisoc.com": "unisoc",
    "liferay.com": "liferay",
    "mitel.com": "mitel",
    "tibco.com": "tibco",
    "zohocorp.com": "zoho",
    "checkmk.com": "checkmk",
    "grafana.com": "grafana",
    "sonicwall.com": "sonicwall",
    "watchguard.com": "watchguard",
    "beckhoff.com": "beckhoff",
    "phoenixcontact.com": "phoenix_contact",
    "moxa.com": "moxa",
    "deltaww.com": "delta_electronics",
    "advantech.com": "advantech",
    "wago.com": "wago",
}

# CNAs that are third-party reporters — sourceIdentifier tells us the ecosystem, not the vendor.
# These are NOT vendors themselves; they report CVEs on behalf of others.
# The value is the ecosystem hint (used only if description parsing finds nothing better).
CNA_ECOSYSTEM_MAP = {
    "wordfence.com": "wordpress",
    "patchstack.com": "wordpress",
    "wpscan.com": "wordpress",
    # Third-party security reporters / coordinating CNAs — NOT vendors
    "github.com": None,        # GitHub Security Advisories — reports for any project
    "cert.pl": None,           # CERT Poland — reports for any vendor
    "cert.vde.com": None,      # CERT@VDE — reports for industrial vendors
    "vulncheck.com": None,     # VulnCheck — vulnerability intelligence, not a vendor
    "tenable.com": None,       # Tenable — scanner vendor, reports others' vulns
    "rapid7.com": None,        # Rapid7 — scanner vendor, reports others' vulns
    "cisa.gov": None,          # CISA — US gov coordinator, reports for any vendor
}


def extract_from_cpe(cpe_string: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract vendor and product from a CPE 2.3 string.

    CPE format: cpe:2.3:part:vendor:product:version:...
    """
    parts = cpe_string.split(":")
    if len(parts) >= 5:
        vendor = parts[3] if parts[3] not in ("*", "-", "") else None
        product = parts[4] if parts[4] not in ("*", "-", "") else None
        return vendor, product
    return None, None


def extract_from_cpe_list(cpe_names: list) -> Tuple[Optional[str], Optional[str]]:
    """Try each CPE in the list until we find vendor/product."""
    for cpe in (cpe_names or []):
        vendor, product = extract_from_cpe(cpe)
        if vendor and product:
            return vendor.lower(), product.lower()
    # Second pass: accept partial matches (vendor only)
    for cpe in (cpe_names or []):
        vendor, product = extract_from_cpe(cpe)
        if vendor:
            return vendor.lower(), (product.lower() if product else None)
    return None, None


def extract_from_affected_products(affected_products: list) -> Tuple[Optional[str], Optional[str]]:
    """Extract vendor/product from affected_products list.

    Format is typically "Vendor Product" strings.
    """
    for entry in (affected_products or []):
        if not entry or not isinstance(entry, str):
            continue
        parts = entry.strip().split(None, 1)
        if len(parts) >= 2:
            return parts[0].lower(), parts[1].lower()
        elif len(parts) == 1 and parts[0]:
            return parts[0].lower(), None
    return None, None


def extract_from_redhat_raw(raw_json: dict) -> Tuple[Optional[str], Optional[str]]:
    """Extract product from RedHat raw_json data."""
    if not raw_json:
        return "redhat", None

    # Try affected_release for product names
    affected_releases = raw_json.get("affected_release", [])
    if isinstance(affected_releases, list):
        for release in affected_releases:
            if isinstance(release, dict):
                product_name = release.get("product_name", "")
                if product_name:
                    return "redhat", product_name.lower()

    # Try affected_packages for package names
    packages = raw_json.get("affected_packages", [])
    if isinstance(packages, list) and packages:
        pkg = packages[0]
        if isinstance(pkg, str):
            match = re.match(r'^([a-zA-Z][a-zA-Z0-9_+-]*?)(?:-\d)', pkg)
            if match:
                return "redhat", match.group(1).lower()

    # Try bugzilla_description
    bugzilla_desc = raw_json.get("bugzilla_description", "")
    if bugzilla_desc:
        match = re.match(r'CVE-\d{4}-\d+\s+(.+?):\s', bugzilla_desc)
        if match:
            return "redhat", match.group(1).strip().lower()

    return "redhat", None


def extract_from_nvd_raw(raw_json: dict) -> Tuple[Optional[str], Optional[str]]:
    """Try to extract vendor/product from NVD raw_json when CPE configs are missing."""
    if not raw_json:
        return None, None

    # Try configurations block
    configurations = raw_json.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                if cpe:
                    vendor, product = extract_from_cpe(cpe)
                    if vendor:
                        return vendor.lower(), product.lower() if product else None

    return None, None


def extract_from_mitre_raw(raw_json: dict) -> Tuple[Optional[str], Optional[str]]:
    """Try to extract vendor/product from MITRE raw_json."""
    if not raw_json:
        return None, None

    containers = raw_json.get("containers", {})
    cna = containers.get("cna", {})
    affected = cna.get("affected", [])

    for aff in affected:
        v = aff.get("vendor", "")
        p = aff.get("product", "")
        if v:
            return v.lower(), p.lower() if p else None
    return None, None


# ── Domains to skip when mining reference URLs for vendor info ───────────
# These are hosting/advisory platforms, not vendor sites.
_REFERENCE_SKIP_DOMAINS = {
    "nvd.nist.gov", "cve.org", "cve.mitre.org", "www.cve.org",
    "vuldb.com", "exploit-db.com", "www.exploit-db.com",
    "packetstormsecurity.com", "seclists.org", "www.openwall.com",
    "securityfocus.com", "bugzilla.redhat.com", "access.redhat.com",
    "security.gentoo.org", "lists.debian.org", "www.debian.org",
    "ubuntu.com", "usn.ubuntu.com", "bugs.launchpad.net",
    "www.securitytracker.com", "securitytracker.com",
    "exchange.xforce.ibmcloud.com", "www.kb.cert.org",
    "tools.cisco.com", "sec.cloudapps.cisco.com",
    "msrc.microsoft.com", "portal.msrc.microsoft.com",
    "support.apple.com", "www.zerodayinitiative.com",
    "www.wordfence.com", "www.patchstack.com",
    "plugins.trac.wordpress.org", "wordpress.org",
    "web.archive.org", "archive.org",
}


def extract_from_references(raw_json: dict) -> Tuple[Optional[str], Optional[str]]:
    """Extract vendor/product from CVE reference URLs.

    Mines GitHub/GitLab repo URLs from the references array.

    Important: GitHub repo owner is often a personal username (e.g. "shirshaw64p"),
    NOT the vendor. We only use the repo name as the product and leave vendor
    for other methods to fill in (description parsing, vendor inference, etc.).

    Exception: when repo owner matches a known organization/vendor name we use it.
    """
    if not raw_json:
        return None, None

    references = raw_json.get("references", [])
    if not references:
        return None, None

    github_candidates = []
    gitlab_candidates = []

    for ref in references:
        url = ref.get("url", "") if isinstance(ref, dict) else ""
        if not url:
            continue

        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            path = parsed.path.strip("/")
        except Exception:
            continue

        # Skip advisory/aggregator sites
        if host in _REFERENCE_SKIP_DOMAINS:
            continue

        path_parts = [p for p in path.split("/") if p]

        # GitHub: github.com/{owner}/{repo}/...
        if host in ("github.com", "www.github.com") and len(path_parts) >= 2:
            owner = path_parts[0].lower()
            repo = path_parts[1].lower()
            # Skip GitHub meta pages and "security-advisories" subpath
            if owner in ("advisories", "github", "actions", "features", "topics"):
                continue
            # Skip advisory-only paths (owner's security fork, not the real project)
            if repo == "security-advisories":
                continue
            github_candidates.append((owner, repo))

        # GitLab: gitlab.com/{owner}/{repo}/...
        elif host in ("gitlab.com", "www.gitlab.com") and len(path_parts) >= 2:
            owner = path_parts[0].lower()
            repo = path_parts[1].lower()
            if owner in ("explore", "help", "gitlab-org"):
                continue
            gitlab_candidates.append((owner, repo))

    # Use repo name as product. For vendor, only use owner if it matches
    # a known vendor or looks like an organization (matches the repo name).
    # Generic repo names (cms, app, api, etc.) use the owner as product instead.
    _GENERIC_REPO_NAMES = {
        "cms", "app", "api", "web", "server", "client", "core", "sdk",
        "backend", "frontend", "platform", "service", "plugin", "module",
        "security-advisories", "advisories", "security",
    }

    all_candidates = github_candidates + gitlab_candidates
    for owner, repo in all_candidates:
        repo = re.sub(r'\.git$', '', repo)
        if not repo or len(repo) > 50:
            continue

        # If repo name is too generic (e.g. "cms", "app"), use owner as the product
        if repo in _GENERIC_REPO_NAMES:
            return owner, owner

        # If owner matches repo name (e.g. umbraco/Umbraco-CMS), owner is the vendor
        repo_base = re.sub(r'[-_].*$', '', repo)  # "umbraco-cms" → "umbraco"
        if owner == repo_base or owner == repo:
            return owner, repo

        # If owner is a known CNA vendor, use it
        if owner in CNA_VENDOR_MAP.values():
            return owner, repo

        # Otherwise, only return the product — don't guess vendor from username
        return None, repo

    return None, None


def _clean_product_name(name: str) -> Optional[str]:
    """Clean up extracted product names — strip noise, limit length."""
    if not name:
        return None
    name = name.strip().rstrip('.,;:')
    # Strip leading "the "
    if name.lower().startswith("the "):
        name = name[4:]
    # Strip trailing version-like suffixes (must have dot or 'v' prefix to avoid stripping
    # single digits that are part of the product name, e.g. "Contact Form 7")
    name = re.sub(r'\s+v\d+[\d.]*\s*$', '', name)       # v1.2.3
    name = re.sub(r'\s+\d+\.\d[\d.]*\s*$', '', name)    # 10.3.1 (must have dot)
    # Strip trailing "(also known as ...)"
    name = re.sub(r'\s*\(also known as[^)]*\)\s*$', '', name, flags=re.IGNORECASE)
    # Strip trailing "is a/an ..." sentences captured by greedy patterns
    name = re.sub(r'\s+is\s+(?:a|an)\s+.*$', '', name, flags=re.IGNORECASE)
    # Strip trailing ": from ..." or ". from ..." version range fragments
    name = re.sub(r'\s*[:.]?\s+from\s+\d.*$', '', name, flags=re.IGNORECASE)
    # Strip trailing "before ..." version references
    name = re.sub(r'\s+before\s+(?:version\s+)?\d.*$', '', name, flags=re.IGNORECASE)
    # Strip trailing "through ..." version references
    name = re.sub(r'\s+through\s+\d.*$', '', name, flags=re.IGNORECASE)
    name = name.strip().rstrip('.,;:')
    if not name or len(name) > 80 or len(name) < 2:
        return None
    return name.lower()


def extract_from_description(description: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract vendor/product from CVE description text using common patterns.

    NVD descriptions follow predictable patterns. This handles the most common ones
    found in CVEs that are "Awaiting Analysis" (no CPE data yet).
    """
    if not description:
        return None, None

    desc = description.strip()

    # ── Rejected CVEs ────────────────────────────────────────────────────────
    if desc.startswith("Rejected reason:") or "DO NOT USE THIS CANDIDATE NUMBER" in desc:
        return "[rejected]", "[rejected]"

    # ── WordPress plugin pattern (very common — Wordfence/Patchstack) ────────
    m = re.match(
        r'The\s+(.+?)\s+plugin\s+for\s+WordPress\b',
        desc, re.IGNORECASE,
    )
    if m:
        return "wordpress", _clean_product_name(m.group(1))

    # "The {Product} theme for WordPress..."
    m = re.match(
        r'The\s+(.+?)\s+theme\s+for\s+WordPress\b',
        desc, re.IGNORECASE,
    )
    if m:
        return "wordpress", _clean_product_name(m.group(1))

    # ── "This issue affects {Product}: from/through" (Patchstack/USOM style) ─
    # Only capture the product name BEFORE the colon, not the version range
    m = re.search(
        r'This\s+issue\s+affects\s+([^:,]+?)(?:\s*:\s*(?:from|through|before)|\s*,\s)',
        desc, re.IGNORECASE,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    # ── "{Product} is a/an ..." at start of description ─────────────────────
    # Only captures the product name (before "is a/an"), NOT the description after it
    # e.g. "pyLoad is a free..." → product = "pyload"
    # e.g. "Umbraco is an ASP.NET CMS..." → product = "umbraco"
    m = re.match(
        r'^([A-Za-z][A-Za-z0-9._/-]{0,50})\s+is\s+(?:a\s+|an\s+)',
        desc,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    # ── "The {Vendor} {Product} server/portal/... is vulnerable" ──────────
    # e.g. "The HCL BigFix Inventory server is vulnerable to path traversal"
    # Must come BEFORE the generic "is vulnerable" pattern below.
    m = re.match(
        r'The\s+([A-Z][A-Za-z]+)\s+(.+?)\s+(?:server|portal|platform|application|service|component|module|interface|system|client|agent|manager|daemon)\s+(?:is|was|has|allows|does|can)',
        desc, re.IGNORECASE,
    )
    if m:
        vendor = m.group(1).strip().lower()
        product = _clean_product_name(m.group(2))
        if vendor and product:
            return vendor, product

    # Broader: "{Product} is {adjective}-based/powered/..." (no article)
    m = re.match(
        r'^([A-Za-z][A-Za-z0-9._/ -]{1,50}?)\s+is\s+(?:vulnerable|based|designed|built|used|intended)',
        desc, re.IGNORECASE,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    # ── "{product} in {Product} before {version}" ───────────────────────────
    # e.g. "ssh in OpenSSH before 10.1 allows..."
    m = re.match(
        r'^[a-z][a-zA-Z0-9._-]*\s+in\s+([A-Z][A-Za-z0-9._/ -]{1,50}?)\s+before\s',
        desc,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    # ── "vulnerability exists in {Vendor} {Product}" ────────────────────────
    m = re.search(
        r'vulnerability\s+exists\s+in\s+([A-Z][A-Za-z]+)\s+([A-Z][A-Za-z0-9._/ -]+?)[\s,.]',
        desc,
    )
    if m:
        vendor = m.group(1).strip().lower()
        product = _clean_product_name(m.group(2))
        if vendor and product:
            return vendor, product

    # ── "{Vendor} {Product} versions ..." ───────────────────────────────────
    # e.g. "QiAnXin TianQing Management Center versions up to..."
    m = re.match(
        r'^([A-Z][A-Za-z]+)\s+(.+?)\s+versions?\s+',
        desc,
    )
    if m:
        vendor = m.group(1).strip().lower()
        product = _clean_product_name(m.group(2))
        if vendor and product:
            return vendor, product

    # ── "{Product} (also known as ...) versions ..." ────────────────────────
    # e.g. "Lavasoft Web Companion (also known as Ad-Aware) versions 8.9..."
    m = re.match(
        r'^([A-Z][A-Za-z0-9\s._-]+?)(?:\s*\([^)]*\))?\s+versions?\s+',
        desc,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    # ── "A vulnerability in {Product} of/from/by {Vendor}" ──────────────────
    m = re.match(
        r'(?:A|An)\s+.{0,80}?vulnerability\s+(?:in|of)\s+(?:the\s+)?(.+?)\s+(?:of|from|by)\s+([A-Z][A-Za-z0-9._/ -]+?)[\s,.]',
        desc, re.IGNORECASE,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        vendor_name = m.group(2).strip().rstrip('.').lower()
        if vendor_name and product_name and len(vendor_name) < 50:
            return vendor_name, product_name

    # ── "...was found in the {Product} of {Vendor}" ─────────────────────────
    m = re.search(
        r'was\s+found\s+in\s+(?:the\s+)?(.+?)\s+of\s+([A-Z][A-Za-z0-9._/ -]+?)[\s,.]',
        desc, re.IGNORECASE,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        vendor_name = m.group(2).strip().rstrip('.').lower()
        if vendor_name and product_name and len(vendor_name) < 50:
            return vendor_name, product_name

    # ── "{Product} before {version}" at start ───────────────────────────────
    m = re.match(
        r'^([A-Z][A-Za-z0-9\s._/-]{1,60}?)\s+before\s+(?:version\s+)?[\d.]+',
        desc,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    # ── "An issue was discovered in {Product} {version}" ────────────────────
    m = re.match(
        r'An\s+issue\s+(?:was|has been)\s+discovered\s+in\s+(.+?)\s+[\d.]+',
        desc, re.IGNORECASE,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    # ── "{Vendor} {Product} {version} has/contains/allows" ──────────────────
    m = re.match(
        r'^([A-Z][A-Za-z]+)\s+([A-Z][A-Za-z0-9._/-]+)\s+[\d.]+.*?\s+(?:has|contains|allows|is vulnerable)',
        desc,
    )
    if m:
        return m.group(1).strip().lower(), m.group(2).strip().lower()

    # ── "The {Product} for/app before/through" ──────────────────────────────
    m = re.match(
        r'The\s+(.+?)\s+(?:for|app\s+for)\s+(.+?)\s+(?:app\s+)?(?:before|through|up to)',
        desc, re.IGNORECASE,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    # ── "A flaw was found in {Product}" ─────────────────────────────────────
    m = re.search(
        r'(?:A\s+)?flaw\s+was\s+found\s+in\s+(?:the\s+)?(.+?)[\s,.](?:that|which|where|allowing|\s+A\s)',
        desc, re.IGNORECASE,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    # ── "vulnerability in {Vendor} {Product}." or "in {Product} allows" ─────
    # Tighter version: requires product to start with uppercase or be multi-word
    m = re.search(
        r'vulnerability\s+in\s+([A-Z][A-Za-z0-9]+(?:\s+[A-Z][A-Za-z0-9._/-]+)?)\s*[.,]',
        desc,
    )
    if m:
        extracted = m.group(1).strip()
        parts = extracted.split(None, 1)
        if len(parts) == 2:
            return parts[0].lower(), parts[1].lower()
        elif len(parts) == 1:
            product_name = _clean_product_name(parts[0])
            if product_name:
                return None, product_name

    # ── "vulnerability in {Product} allows" — broader fallback ──────────────
    m = re.search(
        r'vulnerability\s+in\s+(?:the\s+)?(.+?)\s+allows\s',
        desc, re.IGNORECASE,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name and len(product_name) < 60:
            return None, product_name

    # ── "In {Product}, ..." at start ────────────────────────────────────────
    m = re.match(
        r'^In\s+([A-Z][A-Za-z0-9\s._/-]{1,60}?),\s',
        desc,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    # ── "{Product} {version} and earlier/prior" ─────────────────────────────
    m = re.match(
        r'^([A-Z][A-Za-z0-9\s._/-]{1,50}?)\s+[\d.]+\s+(?:and\s+)?(?:earlier|prior)',
        desc,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    # ── "{Product} {version} and later/newer" ───────────────────────────────
    m = re.match(
        r'^([A-Z][A-Za-z0-9\s._/-]{1,50}?)\s+[\d.]+\s+(?:and\s+)?(?:later|newer)',
        desc,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    # ── "{Product} provides/contains/includes" at start ─────────────────────
    # e.g. "passport-wsfed-saml2 provides passport strategy..."
    m = re.match(
        r'^([A-Za-z][A-Za-z0-9._-]{2,50})\s+(?:provides|contains|includes|implements)\s',
        desc,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    # ── "...in {Product} in versions from" ──────────────────────────────────
    # e.g. "Edito CMS (Content Management System) in versions from 3.5..."
    m = re.search(
        r'(?:^|\s)([A-Z][A-Za-z0-9\s._/-]+?)(?:\s*\([^)]*\))?\s+in\s+versions?\s',
        desc,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    # ── VulDB: "A vulnerability was detected/found in {Vendor} {Product} up to/through" ─
    m = re.match(
        r'A\s+vulnerability\s+was\s+(?:detected|found)\s+in\s+(.+?)\s+(?:up\s+to|through|before)\s',
        desc, re.IGNORECASE,
    )
    if m:
        extracted = m.group(1).strip()
        parts = extracted.split(None, 1)
        if len(parts) == 2:
            return parts[0].lower(), _clean_product_name(parts[1])
        elif len(parts) == 1:
            return None, _clean_product_name(parts[0])

    # ── "{Product} has a vulnerability" ─────────────────────────────────────
    # e.g. "OpenPLC_V3 has a vulnerability in the enipThread function..."
    m = re.match(
        r'^([A-Za-z][A-Za-z0-9._-]{2,40})\s+has\s+(?:a\s+)?(?:vulnerability|a\s+code|a\s+path)',
        desc, re.IGNORECASE,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    # ── "in {Vendor} {Product} {version}" ───────────────────────────────────
    # e.g. "in TIBCO JasperReports Server 8.0.4 and 8.2.0 allows"
    m = re.search(
        r'in\s+([A-Z][A-Za-z]+)\s+([A-Z][A-Za-z0-9\s._/-]+?)\s+[\d.]+',
        desc,
    )
    if m:
        vendor = m.group(1).strip().lower()
        product = _clean_product_name(m.group(2))
        if vendor and product and len(vendor) > 1:
            return vendor, product

    # ── "in the {Product} portal/server/..." ────────────────────────────────
    # e.g. "in the SonicOS SSLVPN portal allows..."
    m = re.search(
        r'in\s+the\s+([A-Z][A-Za-z0-9\s._/-]+?)\s+(?:portal|server|platform|application|service|interface|system|component)',
        desc,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    return None, None


def extract_from_source_identifier(source_identifier: str) -> Tuple[Optional[str], Optional[str]]:
    """Map NVD sourceIdentifier (CNA email) to vendor.

    Only maps CNAs that report their OWN products.
    Third-party reporters (GitHub, CISA, VulnCheck, etc.) are in CNA_ECOSYSTEM_MAP
    with value=None and are explicitly skipped — they'd produce false vendor matches.
    """
    if not source_identifier or "@" not in source_identifier:
        return None, None

    domain = source_identifier.split("@", 1)[1].lower()

    def _lookup(d: str) -> Tuple[Optional[str], Optional[str]]:
        # Check own-product vendor map first
        if d in CNA_VENDOR_MAP:
            return CNA_VENDOR_MAP[d], None
        # Check ecosystem map — only return if value is not None
        # (None means "known third-party reporter, skip entirely")
        if d in CNA_ECOSYSTEM_MAP:
            eco = CNA_ECOSYSTEM_MAP[d]
            if eco is not None:
                return eco, None
            return None, None  # Explicitly skip third-party reporters
        return None, None

    # Direct domain match
    v, p = _lookup(domain)
    if v is not None:
        return v, p
    # If domain is in ecosystem map with None, it was explicitly skipped
    if domain in CNA_ECOSYSTEM_MAP:
        return None, None

    # Try parent domain (e.g. "ch.abb.com" → "abb.com", "psirt.hcl.com" → "hcl.com")
    parts = domain.split(".")
    if len(parts) > 2:
        parent_domain = ".".join(parts[-2:])
        v, p = _lookup(parent_domain)
        if v is not None:
            return v, p
        if parent_domain in CNA_ECOSYSTEM_MAP:
            return None, None

    return None, None


def extract_vendor_product(
    vendor: Optional[str],
    product: Optional[str],
    cpe_names: list = None,
    affected_products: list = None,
    raw_json: dict = None,
    source: str = None,
    sources: list = None,
    description: str = None,
) -> Tuple[Optional[str], Optional[str]]:
    """Master extraction function — tries every available avenue.

    Returns (vendor, product) using the best available data.
    Preserves existing values if already set.
    """
    # Already have both — nothing to do
    if vendor and product:
        return vendor, product

    # 1. Try CPE names (most reliable — structured data)
    if not (vendor and product) and cpe_names:
        cpe_v, cpe_p = extract_from_cpe_list(cpe_names)
        if cpe_v and not vendor:
            vendor = cpe_v
        if cpe_p and not product:
            product = cpe_p

    if vendor and product:
        return vendor, product

    # 2. Try affected_products list
    if not (vendor and product) and affected_products:
        ap_v, ap_p = extract_from_affected_products(affected_products)
        if ap_v and not vendor:
            vendor = ap_v
        if ap_p and not product:
            product = ap_p

    if vendor and product:
        return vendor, product

    # 3. Try source-specific raw_json parsing
    if not (vendor and product) and raw_json:
        primary_source = source or (sources[0] if sources else None)

        if primary_source == "REDHAT":
            rh_v, rh_p = extract_from_redhat_raw(raw_json)
            if rh_v and not vendor:
                vendor = rh_v
            if rh_p and not product:
                product = rh_p
        elif primary_source == "NVD":
            nvd_v, nvd_p = extract_from_nvd_raw(raw_json)
            if nvd_v and not vendor:
                vendor = nvd_v
            if nvd_p and not product:
                product = nvd_p
        elif primary_source == "MITRE":
            m_v, m_p = extract_from_mitre_raw(raw_json)
            if m_v and not vendor:
                vendor = m_v
            if m_p and not product:
                product = m_p

    if vendor and product:
        return vendor, product

    # 4. Try reference URL mining (GitHub/GitLab repo URLs)
    if not (vendor and product) and raw_json:
        ref_v, ref_p = extract_from_references(raw_json)
        if ref_v and not vendor:
            vendor = ref_v
        if ref_p and not product:
            product = ref_p

    if vendor and product:
        return vendor, product

    # 5. Try description text parsing
    desc_text = description
    if not desc_text and raw_json:
        # Get description from raw_json if not passed directly
        descriptions = raw_json.get("descriptions", [])
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break
        if not desc_text and descriptions:
            desc_text = descriptions[0].get("value", "")

    if not (vendor and product) and desc_text:
        desc_v, desc_p = extract_from_description(desc_text)
        if desc_v and not vendor:
            vendor = desc_v
        if desc_p and not product:
            product = desc_p

    if vendor and product:
        return vendor, product

    # 6. Try sourceIdentifier (CNA email → vendor, own-product CNAs only)
    if not vendor and raw_json:
        src_id = raw_json.get("sourceIdentifier", "")
        si_v, si_p = extract_from_source_identifier(src_id)
        if si_v and not vendor:
            vendor = si_v
        if si_p and not product:
            product = si_p

    # 7. Infer vendor from product when we have product but no vendor
    if product and not vendor:
        vendor = _infer_vendor_from_product(product)

    return vendor, product


    # ── 4-Tier Pipeline (Golden List + LLM integration) ────────────────────────

# In-memory cache of the Golden List for fast lookups during pipeline runs.
# Populated by load_golden_list() — call once at start or when cache expires.
_golden_vendor_map: dict = {}    # vendor_name → vendor_id
_golden_product_map: dict = {}   # (vendor_id, product_name) → product_id
_golden_loaded: bool = False


def load_golden_list_sync():
    """Load the Golden List from the database into memory (sync, for Celery workers).

    Uses psycopg2 (sync driver) since this runs in Celery context.
    Safe to call multiple times — only loads once unless force_reload=True.
    """
    global _golden_vendor_map, _golden_product_map, _golden_loaded

    if _golden_loaded:
        return

    try:
        import psycopg2
        from app.config import settings

        conn = psycopg2.connect(settings.sync_database_url)
        cur = conn.cursor()

        cur.execute("SELECT id, name FROM vendors")
        _golden_vendor_map = {row[1]: row[0] for row in cur.fetchall()}

        cur.execute("SELECT id, name, vendor_id FROM products")
        _golden_product_map = {(row[2], row[1]): row[0] for row in cur.fetchall()}

        cur.close()
        conn.close()

        _golden_loaded = True
        logger.info(
            f"Golden List loaded: {len(_golden_vendor_map)} vendors, "
            f"{len(_golden_product_map)} products"
        )
    except Exception as e:
        logger.warning(f"Could not load Golden List: {e}")


async def load_golden_list_async(session):
    """Load the Golden List from the database into memory (async, for FastAPI).

    Call from request handlers or pipeline code that has an async session.
    """
    global _golden_vendor_map, _golden_product_map, _golden_loaded

    if _golden_loaded:
        return

    try:
        from sqlalchemy import select
        from app.models.vendor_product import Vendor, Product

        vendor_rows = (await session.execute(select(Vendor.id, Vendor.name))).all()
        _golden_vendor_map = {row[1]: row[0] for row in vendor_rows}

        product_rows = (await session.execute(
            select(Product.id, Product.name, Product.vendor_id)
        )).all()
        _golden_product_map = {(row[2], row[1]): row[0] for row in product_rows}

        _golden_loaded = True
        logger.info(
            f"Golden List loaded (async): {len(_golden_vendor_map)} vendors, "
            f"{len(_golden_product_map)} products"
        )
    except Exception as e:
        logger.warning(f"Could not load Golden List (async): {e}")


def lookup_golden_list(vendor: str, product: str = None):
    """Look up vendor/product against the Golden List.

    Returns (vendor_id, product_id, matched) — matched=True if found in Golden List.
    """
    if not _golden_loaded or not vendor:
        return None, None, False

    vendor_lower = vendor.lower()
    vid = _golden_vendor_map.get(vendor_lower)
    if not vid:
        return None, None, False

    pid = None
    if product:
        pid = _golden_product_map.get((vid, product.lower()))

    return vid, pid, True


def extract_vendor_product_tiered(
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    cpe_names: list = None,
    affected_products: list = None,
    raw_json: dict = None,
    source: str = None,
    sources: list = None,
    description: str = None,
) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int], Optional[str]]:
    """4-Tier extraction pipeline returning (vendor, product, vendor_id, product_id, method).

    Tiers:
    1. Direct CPE Match — from the CVE record's cpe_names field
    2. DB Lookup — check extracted strings against the Golden List
    3. Heuristic/Regex — existing logic from extract_vendor_product()
    4. LLM Inference — handled externally (async), not called here

    This function is synchronous and covers Tiers 1-3.
    Tier 4 (LLM) must be called separately via llm_extraction_service.extract_with_llm().

    Returns:
        (vendor_str, product_str, vendor_id, product_id, extraction_method)
    """
    vendor_id = None
    product_id = None
    method = None

    # Tier 1: Direct CPE Match
    if cpe_names:
        cpe_v, cpe_p = extract_from_cpe_list(cpe_names)
        if cpe_v:
            if not vendor:
                vendor = cpe_v
            if cpe_p and not product:
                product = cpe_p
            method = "cpe_match"

            # Try to link to Golden List immediately
            vid, pid, matched = lookup_golden_list(vendor, product)
            if matched:
                vendor_id = vid
                product_id = pid
                return vendor, product, vendor_id, product_id, method

    # Tier 2: Golden List DB Lookup with existing vendor/product strings
    if vendor and _golden_loaded:
        vid, pid, matched = lookup_golden_list(vendor, product)
        if matched:
            vendor_id = vid
            product_id = pid
            if not method:
                method = "db_lookup"
            return vendor, product, vendor_id, product_id, method

    # Tier 3: Full heuristic extraction (existing logic)
    heur_vendor, heur_product = extract_vendor_product(
        vendor=vendor,
        product=product,
        cpe_names=cpe_names,
        affected_products=affected_products,
        raw_json=raw_json,
        source=source,
        sources=sources,
        description=description,
    )

    if heur_vendor:
        vendor = heur_vendor
    if heur_product:
        product = heur_product

    if not method and (heur_vendor or heur_product):
        method = "heuristic"

    # Try Golden List lookup with heuristic results
    if vendor and _golden_loaded:
        vid, pid, matched = lookup_golden_list(vendor, product)
        if matched:
            vendor_id = vid
            product_id = pid

    return vendor, product, vendor_id, product_id, method


    # Additional vendor names commonly seen as first-word prefixes in product names
# that aren't in CNA_VENDOR_MAP (because they don't have a CNA email).
_EXTRA_KNOWN_VENDORS = {
    "jetbrains", "zoho", "trendmicro", "broadcom", "citrix", "mcafee",
    "symantec", "kaspersky", "autodesk", "bentley", "dassault",
    "honeywell", "ge", "emerson", "yokogawa", "mitsubishi",
    "schneider", "phoenix", "pilz", "codesys", "wago", "beckhoff",
    "aveva", "inductive", "ignition", "kepware", "opc",
}


def _infer_vendor_from_product(product: str) -> str:
    """Infer vendor from product name when vendor is missing.

    Rules:
    - Multi-word product where first word is a known vendor:
      "jetbrains datalore" → vendor = "jetbrains"
    - Single-word product or no recognized vendor prefix:
      vendor = product (e.g. "statamic" → vendor = "statamic")
    """
    if not product:
        return product

    # Skip rejected markers
    if product.startswith("["):
        return product

    parts = product.strip().split()

    if len(parts) >= 2:
        first_word = parts[0].lower()
        # Check if the first word is a known vendor
        known_vendors = set(CNA_VENDOR_MAP.values()) | _EXTRA_KNOWN_VENDORS
        if first_word in known_vendors:
            return first_word

    # Default: vendor = product (for single-word or unknown multi-word)
    # For multi-word like "contact form 7", the whole thing is the product
    # and the vendor is the product name too
    return product
