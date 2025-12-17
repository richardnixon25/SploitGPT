"""Shodan search tool for SploitGPT."""

import asyncio
import logging
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx

from . import register_tool

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _load_embedded_queries() -> list[str]:
    """Load embedded Shodan dorks/queries from bundled knowledge sources."""
    base = Path(__file__).resolve().parent.parent
    sources = [
        base / "knowledge" / "sources" / "shodan_dorks.md",
        base / "knowledge" / "sources" / "awesome_shodan_queries.md",
    ]

    queries: list[str] = []
    seen: set[str] = set()

    for path in sources:
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        in_block = False
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("```"):
                in_block = not in_block
                continue
            if not line:
                continue
            if in_block:
                # Raw dork list in code blocks.
                val = line
            else:
                # Bullet format: - **Title** — `query`
                match = re.findall(r"`([^`]+)`", line)
                if match:
                    val = match[0]
                else:
                    continue

            val_norm = val.strip()
            if val_norm and val_norm not in seen:
                seen.add(val_norm)
                queries.append(val_norm)

    return queries


def _suggest_queries(user_query: str, limit: int = 5) -> list[str]:
    """Suggest locally-embedded queries that overlap with the user input."""
    tokens = [t for t in re.split(r"\s+", user_query.lower()) if t]
    if not tokens:
        return []

    scored: list[tuple[int, int, str]] = []
    for q in _load_embedded_queries():
        q_lower = q.lower()
        score = sum(1 for t in tokens if t in q_lower)
        if score > 0:
            scored.append((score, -len(q), q))

    scored.sort(reverse=True)
    return [q for _, __, q in scored[:limit]]


def _get_client(timeout: float = 30.0) -> httpx.AsyncClient:
    """Factory for the HTTP client (patched in tests)."""
    return httpx.AsyncClient(timeout=timeout)


def _coerce_str(value: Any) -> str:
    """Return a safe string representation, ignoring non-scalar types."""
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def _format_banner(raw: Any, max_lines: int = 8, max_line_len: int = 160) -> str:
    if raw is None:
        return ""
    text = _coerce_str(raw)
    if not text:
        return ""
    lines = text.splitlines()
    formatted: list[str] = []
    for line in lines[:max_lines]:
        formatted.append(_coerce_str(line)[:max_line_len])
    if len(lines) > max_lines or any(len(line) > max_line_len for line in lines):
        formatted.append("...truncated...")
    return "\n".join(formatted).strip()


def _format_match(match: dict[str, Any]) -> str:
    """Format a single Shodan match for LLM consumption."""
    ip = _coerce_str(match.get("ip_str")) or "unknown"
    port = _coerce_str(match.get("port")) or "?"
    org = _coerce_str(match.get("org")) or _coerce_str(match.get("isp"))
    hostnames_list = match.get("hostnames") or []
    if isinstance(hostnames_list, (list, tuple)):
        hostnames = ", ".join(_coerce_str(h) for h in hostnames_list if _coerce_str(h))
    else:
        hostnames = _coerce_str(hostnames_list)
    location = match.get("location") or {}
    city = _coerce_str(location.get("city"))
    country = _coerce_str(location.get("country_name"))
    product = _coerce_str(match.get("product")) or _coerce_str(match.get("_shodan", {}).get("module", ""))

    banner = _format_banner(match.get("data"))

    vulns: list[str] = []
    if isinstance(match.get("vulns"), dict):
        vulns = list(match["vulns"].keys())[:10]

    lines = [f"- {ip}:{port}"]
    if hostnames:
        lines.append(f"  hostnames: {hostnames}")
    if org:
        lines.append(f"  org: {org}")
    if city or country:
        lines.append(f"  location: {city}, {country}".rstrip(", "))
    if product:
        lines.append(f"  service: {product}")
    if vulns:
        lines.append(f"  vulns: {', '.join(vulns)}")
    if banner:
        lines.append("  banner:\n    " + banner.replace("\n", "\n    "))

    return "\n".join(lines)


@register_tool("shodan_search")
async def shodan_search(
    query: str,
    limit: int = 5,
) -> str:
    """
    Search Shodan for exposed services, banners, and potential vulnerabilities.
    
    Requires SHODAN_API_KEY in the environment.
    
    Args:
        query: Shodan query (e.g., 'apache country:US port:80')
        limit: Maximum results to return (default 5, max 20)
        
    Returns:
        Formatted Shodan results
    """
    query = query.strip()
    if not query:
        return "Error: No query provided."

    limit = max(1, min(limit, 20))

    suggestions = _suggest_queries(query, limit=5)

    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return (
            "Error: SHODAN_API_KEY environment variable is not set.\n"
            "Add SHODAN_API_KEY=your_key to .env to enable this tool."
        )

    max_attempts = 3
    backoff = 1.0
    last_error: str | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            async with _get_client(timeout=30.0) as client:
                resp = await client.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": api_key, "query": query},
                )
            status = resp.status_code
            retry_after = resp.headers.get("Retry-After")
            payload: dict[str, Any] = {}
            try:
                payload = resp.json() if resp.content else {}
            except Exception:
                payload = {}

            if status == 429:
                last_error = payload.get("error") or "Shodan rate limited (HTTP 429)."
                if attempt < max_attempts:
                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue
                detail = f"{last_error} Try again later."
                if retry_after:
                    detail += f" Retry-After: {retry_after}s."
                return f"Error: {detail}"

            if status == 401 or status == 403:
                return "Error: Shodan rejected the request. Check SHODAN_API_KEY."
            if status == 402:
                return "Error: Shodan plan limit reached (status 402)."
            if status >= 400:
                api_error = payload.get("error")
                if api_error:
                    return f"Error: Shodan returned {status}: {api_error}"
                return f"Error: Shodan returned HTTP {status}."

            if isinstance(payload, dict) and payload.get("error"):
                return f"Error: Shodan API error: {payload['error']}"

            data = payload
            break

        except httpx.TimeoutException:
            last_error = "timeout"
            if attempt < max_attempts:
                await asyncio.sleep(backoff)
                backoff *= 2
                continue
            return "Error: Shodan search timed out."
        except httpx.RequestError as e:
            last_error = str(e)
            logger.debug("Shodan network error: %s", e, exc_info=True)
            if attempt < max_attempts:
                await asyncio.sleep(backoff)
                backoff *= 2
                continue
            return "Error: Shodan network error. Please check connectivity."
        except Exception as e:
            logger.exception("Shodan search failed")
            return f"Error: Shodan search failed: {e}"
    else:
        return f"Error: Shodan search failed after retries ({last_error})."

    matches = data.get("matches") or []
    total = data.get("total", 0)

    results: list[str] = []
    if suggestions:
        results.append("Suggested local queries (offline):")
        results.extend([f"- {s}" for s in suggestions])
        results.append("")

    results.append(f"Shodan search: {query}")
    results.append(f"Total reported: {total}")
    if not matches:
        return "\n".join(results + ["No results found."])

    for match in matches[:limit]:
        results.append(_format_match(match))

    if total > limit:
        results.append(f"(Showing top {limit} of {total} results)")

    return "\n".join(results)
