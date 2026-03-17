"""LLM-based vendor/product extraction service.

Final fallback in the 4-tier extraction pipeline. Uses Groq (Llama 3.1 70B)
or Google Gemini Free Tier to infer vendor and product from CVE descriptions
when all structured/heuristic methods fail.

Uses few-shot prompting for consistent, structured output.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Optional, Tuple

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# ── Few-Shot Prompt Template ─────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are a cybersecurity expert specializing in CVE analysis and Common Platform Enumeration (CPE).

Your task: Given a CVE description, extract the **vendor** and **product** names.

Rules:
1. Return ONLY valid JSON: {"vendor": "name", "product": "name"}
2. Use lowercase, CPE-normalized names (underscores for spaces, e.g. "palo_alto_networks")
3. If the CVE is about a WordPress plugin, vendor is "wordpress" and product is the plugin name
4. If you cannot determine vendor or product, use null for that field
5. Never guess — if the description is too vague, return nulls
6. For rejected/reserved CVEs, return {"vendor": null, "product": null}
7. Do NOT include version numbers in the product name
8. Common vendor normalizations: "Cisco Systems" → "cisco", "Microsoft Corporation" → "microsoft"
"""

_FEW_SHOT_EXAMPLES = [
    {
        "description": "A vulnerability in the web-based management interface of Cisco IOS XE Software could allow an authenticated, remote attacker to execute arbitrary commands.",
        "answer": '{"vendor": "cisco", "product": "ios_xe"}'
    },
    {
        "description": "The Contact Form 7 plugin for WordPress is vulnerable to Cross-Site Scripting (XSS) in all versions up to 5.8.3.",
        "answer": '{"vendor": "wordpress", "product": "contact_form_7"}'
    },
    {
        "description": "An issue was discovered in GitLab CE/EE affecting all versions starting from 16.0 prior to 16.11.6. A stored XSS vulnerability exists in the markdown editor.",
        "answer": '{"vendor": "gitlab", "product": "gitlab"}'
    },
    {
        "description": "pyLoad is a free and open-source Download Manager. A cross-site scripting vulnerability was found in pyLoad versions prior to 0.5.0b3.dev85.",
        "answer": '{"vendor": "pyload", "product": "pyload"}'
    },
    {
        "description": "Rejected reason: This candidate is a duplicate of another CVE.",
        "answer": '{"vendor": null, "product": null}'
    },
    {
        "description": "A vulnerability in Palo Alto Networks PAN-OS software enables an authenticated admin to upload a compromised software image.",
        "answer": '{"vendor": "paloaltonetworks", "product": "pan-os"}'
    },
]


def _build_prompt(description: str) -> str:
    """Build the few-shot prompt for LLM extraction."""
    examples = "\n\n".join(
        f'Description: "{ex["description"]}"\nAnswer: {ex["answer"]}'
        for ex in _FEW_SHOT_EXAMPLES
    )
    return f"""{examples}

Description: "{description}"
Answer:"""


@dataclass
class LLMExtractionResult:
    """Result from LLM vendor/product extraction."""
    vendor: Optional[str]
    product: Optional[str]
    provider: Optional[str]  # "groq" or "gemini"
    status: str  # "success", "no_keys", "api_error", "parse_error"
    error: Optional[str] = None


def _parse_llm_response(text: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse LLM response JSON to extract vendor/product.

    Handles common LLM quirks: markdown code fences, extra text around JSON.
    """
    if not text:
        return None, None

    # Strip markdown code fences
    text = re.sub(r'```(?:json)?\s*', '', text).strip().rstrip('`')

    # Find JSON object in the response
    match = re.search(r'\{[^}]+\}', text)
    if not match:
        return None, None

    try:
        data = json.loads(match.group(0))
        vendor = data.get("vendor")
        product = data.get("product")

        # Normalize: lowercase, strip whitespace
        if vendor:
            vendor = vendor.strip().lower()
            if vendor in ("null", "none", "n/a", "unknown", ""):
                vendor = None
        if product:
            product = product.strip().lower()
            if product in ("null", "none", "n/a", "unknown", ""):
                product = None

        return vendor, product
    except (json.JSONDecodeError, AttributeError):
        return None, None


async def _call_groq(description: str) -> LLMExtractionResult:
    """Call Groq API (Llama 3.1 70B) for vendor/product extraction."""
    api_key = settings.groq_api_key
    if not api_key:
        return LLMExtractionResult(None, None, "groq", "no_keys", "GROQ_API_KEY not configured")

    prompt = _build_prompt(description)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "llama-3.3-70b-versatile",
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.1,
                    "max_tokens": 100,
                },
            )
            resp.raise_for_status()
            data = resp.json()

            content = data["choices"][0]["message"]["content"]
            vendor, product = _parse_llm_response(content)

            if vendor or product:
                return LLMExtractionResult(vendor, product, "groq", "success")
            return LLMExtractionResult(None, None, "groq", "parse_error", f"Could not parse: {content[:200]}")

    except httpx.HTTPStatusError as e:
        body = e.response.text[:300] if e.response else ""
        logger.warning(f"Groq API error: HTTP {e.response.status_code} — {body}")
        return LLMExtractionResult(None, None, "groq", "api_error", f"HTTP {e.response.status_code}: {body}")
    except Exception as e:
        return LLMExtractionResult(None, None, "groq", "api_error", f"{type(e).__name__}: {str(e)[:200]}")


async def _call_gemini(description: str) -> LLMExtractionResult:
    """Call Google Gemini Free Tier for vendor/product extraction."""
    api_key = settings.gemini_api_key
    if not api_key:
        return LLMExtractionResult(None, None, "gemini", "no_keys", "GEMINI_API_KEY not configured")

    prompt = _SYSTEM_PROMPT + "\n\n" + _build_prompt(description)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.1,
                        "maxOutputTokens": 100,
                    },
                },
            )
            resp.raise_for_status()
            data = resp.json()

            content = data["candidates"][0]["content"]["parts"][0]["text"]
            vendor, product = _parse_llm_response(content)

            if vendor or product:
                return LLMExtractionResult(vendor, product, "gemini", "success")
            return LLMExtractionResult(None, None, "gemini", "parse_error", f"Could not parse: {content[:200]}")

    except httpx.HTTPStatusError as e:
        body = e.response.text[:300] if e.response else ""
        logger.warning(f"Gemini API error: HTTP {e.response.status_code} — {body}")
        return LLMExtractionResult(None, None, "gemini", "api_error", f"HTTP {e.response.status_code}: {body}")
    except Exception as e:
        return LLMExtractionResult(None, None, "gemini", "api_error", f"{type(e).__name__}: {str(e)[:200]}")


async def extract_with_llm(description: str) -> LLMExtractionResult:
    """Try LLM extraction — Groq first, then Gemini as fallback.

    Returns the first successful result. If both fail, returns the last error.
    """
    if not description or len(description) < 20:
        return LLMExtractionResult(None, None, None, "no_keys", "Description too short for LLM")

    # Skip rejected/reserved CVEs
    if description.startswith("Rejected reason:") or "DO NOT USE THIS CANDIDATE" in description:
        return LLMExtractionResult(None, None, None, "success", "Rejected CVE, skipped")

    # Try Groq first (faster, free tier generous)
    if settings.groq_api_key:
        result = await _call_groq(description)
        if result.status == "success":
            logger.debug(f"LLM extraction (Groq): vendor={result.vendor}, product={result.product}")
            return result
        logger.debug(f"Groq failed: {result.error}")

    # Fallback to Gemini
    if settings.gemini_api_key:
        result = await _call_gemini(description)
        if result.status == "success":
            logger.debug(f"LLM extraction (Gemini): vendor={result.vendor}, product={result.product}")
            return result
        logger.debug(f"Gemini failed: {result.error}")

    # Neither key configured or both failed
    if not settings.groq_api_key and not settings.gemini_api_key:
        return LLMExtractionResult(None, None, None, "no_keys", "No LLM API keys configured (GROQ_API_KEY or GEMINI_API_KEY)")

    return LLMExtractionResult(None, None, None, "api_error", "All LLM providers failed")


def check_llm_keys_status() -> dict:
    """Check which LLM keys are configured (without exposing them)."""
    return {
        "groq": bool(settings.groq_api_key),
        "gemini": bool(settings.gemini_api_key),
        "any_configured": bool(settings.groq_api_key or settings.gemini_api_key),
    }
