"""Vendor/product extraction utilities.

Extracts vendor and product from multiple data sources within a CVE record,
used both during ingestion and for backfilling existing records.

Extraction priority:
1. CPE names (most reliable — structured data)
2. Affected products list
3. Source-specific raw_json parsing
4. Description text parsing (pattern-based)
5. sourceIdentifier (CNA email domain mapping)
"""

from __future__ import annotations

import logging
import re
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


# ── CNA email → vendor mapping ──────────────────────────────────────────────
# Maps sourceIdentifier email domains to known vendors.
# Only includes CNAs that report their OWN products (not third-party reporters).
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
    "cert.pl": "cert_pl",
    "cert.vde.com": "cert_vde",
    "hcl.com": "hcl",
    "psirt@hcl.com": "hcl",
    "vulncheck.com": "vulncheck",
    "tenable.com": "tenable",
    "rapid7.com": "rapid7",
    "cisa.gov": "cisa",
    "github.com": "github",
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

# CNAs that are third-party reporters — sourceIdentifier tells us the ecosystem, not the vendor
CNA_ECOSYSTEM_MAP = {
    "wordfence.com": "wordpress",
    "patchstack.com": "wordpress",
    "wpscan.com": "wordpress",
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


def _clean_product_name(name: str) -> Optional[str]:
    """Clean up extracted product names — strip noise, limit length."""
    if not name:
        return None
    name = name.strip().rstrip('.,;:')
    # Strip leading "the "
    if name.lower().startswith("the "):
        name = name[4:]
    # Strip trailing version-like suffixes
    name = re.sub(r'\s+v?\d+[\d.]*\s*$', '', name)
    # Strip trailing "(also known as ...)"
    name = re.sub(r'\s*\(also known as[^)]*\)\s*$', '', name, flags=re.IGNORECASE)
    name = name.strip()
    if not name or len(name) > 100 or len(name) < 2:
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
    m = re.search(
        r'This\s+issue\s+affects\s+(.+?):\s+(?:from|through|before)',
        desc, re.IGNORECASE,
    )
    if m:
        product_name = _clean_product_name(m.group(1))
        if product_name:
            return None, product_name

    # ── "{Product} is a/an ..." at start of description ─────────────────────
    # e.g. "pyLoad is a free and open-source download manager..."
    # e.g. "ZenUML is JavaScript-based diagramming tool..."
    # e.g. "quic-go is an implementation of the QUIC protocol..."
    # e.g. "Webhood is a self-hosted URL scanner..."
    # e.g. "DocsGPT is a GPT-powered chat for documentation..."
    m = re.match(
        r'^([A-Za-z][A-Za-z0-9._/ -]{1,50}?)\s+is\s+(?:a\s+|an\s+)',
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

    Only maps CNAs that report their own products.
    Third-party reporters (Wordfence, Patchstack) return ecosystem hint instead.
    """
    if not source_identifier or "@" not in source_identifier:
        return None, None

    domain = source_identifier.split("@", 1)[1].lower()

    # Direct domain match
    if domain in CNA_VENDOR_MAP:
        return CNA_VENDOR_MAP[domain], None

    # Ecosystem hint
    if domain in CNA_ECOSYSTEM_MAP:
        return CNA_ECOSYSTEM_MAP[domain], None

    # Try parent domain (e.g. "ch.abb.com" → "abb.com", "psirt.hcl.com" → "hcl.com")
    parts = domain.split(".")
    if len(parts) > 2:
        parent_domain = ".".join(parts[-2:])
        if parent_domain in CNA_VENDOR_MAP:
            return CNA_VENDOR_MAP[parent_domain], None
        if parent_domain in CNA_ECOSYSTEM_MAP:
            return CNA_ECOSYSTEM_MAP[parent_domain], None

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

    # 4. Try description text parsing
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

    # 5. Try sourceIdentifier (CNA email → vendor)
    if not vendor and raw_json:
        src_id = raw_json.get("sourceIdentifier", "")
        si_v, si_p = extract_from_source_identifier(src_id)
        if si_v and not vendor:
            vendor = si_v
        if si_p and not product:
            product = si_p

    return vendor, product
