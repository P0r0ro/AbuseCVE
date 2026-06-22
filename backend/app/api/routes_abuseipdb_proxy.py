"""AbuseIPDB API proxy — server-side relay for Abusef.

Bypasses unreliable public CORS proxies (codetabs, corsproxy.io,
allorigins, thingproxy) that Abusef previously chained from the
browser. Also keeps the AbuseIPDB API key out of third-party logs:
the key was leaking into codetabs / Cloudflare request logs every
time the browser fell through the fallback chain.

Endpoint: GET /api/abuseipdb-proxy?ip=<ipv4-or-v6>[&maxAgeInDays=90]
Headers:
    x-apikey   — AbuseIPDB key (required). NEVER sent via query string.
    Accept     — passed through; defaults to application/json.

Response: AbuseIPDB's JSON body verbatim, plus the following headers
forwarded so Abusef's quota-refresh logic keeps working:
    x-ratelimit-remaining
    x-ratelimit-limit
    x-ratelimit-reset

This route is exempt from the RBAC middleware (see main.py
``public_prefixes``) because Abusef runs outside the AbuseCVE login
flow. The proxy still validates the target so it can't be used as an
open relay.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/abuseipdb-proxy", tags=["AbuseIPDB Proxy"])

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

# Reasonable v4/v6 sanity check — full validation happens on AbuseIPDB's
# side. This is only to refuse obvious garbage / SSRF attempts at our edge.
_IPV4 = r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
_IPV6 = r"[0-9a-fA-F:]+(?:%[0-9a-zA-Z]+)?"
_IP_RE = re.compile(rf"^(?:{_IPV4}|{_IPV6})$")

_FORWARD_HEADERS = (
    "x-ratelimit-remaining",
    "x-ratelimit-limit",
    "x-ratelimit-reset",
    "retry-after",
)

_client = httpx.AsyncClient(
    timeout=httpx.Timeout(connect=10, read=20, write=10, pool=10),
    follow_redirects=False,
)


@router.get("")
async def abuseipdb_proxy(
    request: Request,
    ip: str = Query(..., alias="ip", description="IPv4 or IPv6 address to query"),
    maxAgeInDays: int = Query(90, ge=1, le=365),
    verbose: bool = Query(True, description="Include reports in the response"),
):
    if not _IP_RE.match(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")

    api_key = request.headers.get("x-apikey", "").strip()
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing x-apikey header")

    accept = request.headers.get("accept", "application/json")

    params = {"ipAddress": ip, "maxAgeInDays": str(maxAgeInDays)}
    if verbose:
        # AbuseIPDB accepts the bare ``verbose`` flag — emulate the
        # original browser request shape.
        params["verbose"] = ""

    try:
        upstream = await _client.get(
            ABUSEIPDB_CHECK_URL,
            params=params,
            headers={
                "Key": api_key,
                "Accept": accept,
            },
        )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="AbuseIPDB request timed out")
    except httpx.RequestError as exc:
        logger.error("AbuseIPDB proxy request failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"Proxy request failed: {exc}")

    # Forward quota headers so the existing UI quota tracker keeps working.
    response_headers = {"Cache-Control": "no-store, max-age=0"}
    for h in _FORWARD_HEADERS:
        value = upstream.headers.get(h)
        if value is not None:
            response_headers[h] = value
    # Make sure the browser can read them via JS (CORS exposure).
    response_headers["Access-Control-Expose-Headers"] = ", ".join(_FORWARD_HEADERS)

    try:
        body = upstream.json()
    except ValueError:
        body = {"raw": upstream.text[:2000]}

    return JSONResponse(
        content=body,
        status_code=upstream.status_code,
        headers=response_headers,
    )
