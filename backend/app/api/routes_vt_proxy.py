"""VirusTotal API proxy — server-side relay.

Bypasses corporate firewall / SSL-intercept issues by fetching VT
from the backend container rather than the analyst's browser.

Endpoint: GET /api/vt-proxy?url=<encoded VT v3 URL>
Forwards ``x-apikey`` and ``Accept`` headers from the client request.
"""

from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/vt-proxy", tags=["VT Proxy"])

# Reusable async client with sensible timeouts.
_client = httpx.AsyncClient(
    timeout=httpx.Timeout(connect=10, read=25, write=10, pool=10),
    follow_redirects=True,
)


@router.get("")
async def vt_proxy(request: Request, url: str = ""):
    """Relay a VirusTotal v3 API call server-side.

    Query params:
        url  — full VT API URL, e.g. https://www.virustotal.com/api/v3/files/<hash>

    Headers forwarded from the client:
        x-apikey, Accept
    """
    if not url:
        raise HTTPException(status_code=400, detail="Missing target URL")

    # Only allow proxying to VirusTotal domains.
    if not url.startswith("https://www.virustotal.com/"):
        raise HTTPException(
            status_code=400,
            detail="Only VirusTotal URLs are permitted",
        )

    api_key = request.headers.get("x-apikey", "")
    accept = request.headers.get("accept", "application/json")

    try:
        vt_resp = await _client.get(
            url,
            headers={
                "x-apikey": api_key,
                "Accept": accept,
            },
        )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="VirusTotal request timed out")
    except httpx.RequestError as exc:
        logger.error("VT proxy request failed: %s", exc)
        raise HTTPException(
            status_code=502,
            detail=f"Proxy request failed: {exc}",
        )

    return JSONResponse(
        content=vt_resp.json(),
        status_code=vt_resp.status_code,
        headers={"Cache-Control": "no-store, max-age=0"},
    )
