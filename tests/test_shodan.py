import json
from collections.abc import Iterable

import httpx
import pytest

from sploitgpt.tools import shodan


class FakeResponse:
    def __init__(self, status_code: int, json_data: dict | None = None, headers: dict | None = None):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.headers = headers or {}
        self.content = json.dumps(self._json_data).encode() if self._json_data else b""

    def json(self) -> dict:
        return self._json_data


class FakeClient:
    def __init__(self, responses: Iterable[FakeResponse] | None = None, exc: Exception | None = None):
        # Keep shared reference so retries consume in order across client instances.
        if isinstance(responses, list):
            self._responses = responses
        else:
            self._responses = list(responses or [])
        self._exc = exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return False

    async def get(self, *_, **__):
        if self._exc:
            exc, self._exc = self._exc, None
            raise exc
        if not self._responses:
            raise AssertionError("No response configured")
        return self._responses.pop(0)


@pytest.fixture(autouse=True)
def shodan_key(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "test-key")


@pytest.fixture
def fast_sleep(monkeypatch):
    async def _sleep(_delay):
        return None

    monkeypatch.setattr(shodan.asyncio, "sleep", _sleep)


@pytest.mark.asyncio
async def test_shodan_success(monkeypatch):
    matches = [{
        "ip_str": "1.2.3.4",
        "port": 80,
        "hostnames": ["example.com"],
        "location": {"city": "Testville", "country_name": "US"},
        "data": "Banner line 1\nBanner line 2"
    }]
    monkeypatch.setattr(
        shodan,
        "_get_client",
        lambda timeout=30.0: FakeClient([FakeResponse(200, {"total": 1, "matches": matches})])
    )

    result = await shodan.shodan_search("apache")
    assert "Shodan search: apache" in result
    assert "1.2.3.4:80" in result
    assert "Banner line 1" in result


@pytest.mark.asyncio
async def test_shodan_handles_401(monkeypatch):
    monkeypatch.setattr(
        shodan,
        "_get_client",
        lambda timeout=30.0: FakeClient([FakeResponse(401, {"error": "Invalid key"})])
    )
    result = await shodan.shodan_search("test")
    assert "Shodan rejected" in result


@pytest.mark.asyncio
async def test_shodan_retries_429(monkeypatch, fast_sleep):
    responses = [
        FakeResponse(429, {"error": "Rate limit"}),
        FakeResponse(200, {"total": 0, "matches": []}),
    ]
    monkeypatch.setattr(shodan, "_get_client", lambda timeout=30.0: FakeClient(responses))

    result = await shodan.shodan_search("port:22", limit=1)
    assert "No results" in result  # succeeded after retry


@pytest.mark.asyncio
async def test_shodan_timeout(monkeypatch, fast_sleep):
    request = httpx.Request("GET", "https://api.shodan.io/shodan/host/search")
    exc = httpx.TimeoutException("timeout", request=request)
    monkeypatch.setattr(shodan, "_get_client", lambda timeout=30.0: FakeClient(exc=exc))

    result = await shodan.shodan_search("apache")
    assert "timed out" in result


@pytest.mark.asyncio
async def test_shodan_api_error_payload(monkeypatch):
    monkeypatch.setattr(
        shodan,
        "_get_client",
        lambda timeout=30.0: FakeClient([FakeResponse(200, {"error": "Bad query"})])
    )
    result = await shodan.shodan_search("apache")
    assert "API error" in result
