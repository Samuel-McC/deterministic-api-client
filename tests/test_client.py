import requests
import pytest

from deterministic_api_client.client import DeterministicApiClient, RetryableHttpError, NonRetryableHttpError


class FakeResp:
    def __init__(self, status_code: int, text: str = "", headers=None, json_obj=None):
        self.status_code = status_code
        self.text = text
        self._json_obj = json_obj
        self.headers = headers or {"Content-Type": "application/json"}

    def json(self):
        if self._json_obj is None:
            raise ValueError("no json")
        return self._json_obj


def test_retries_on_429_then_succeeds(monkeypatch):
    client = DeterministicApiClient("https://example.com", timeout_seconds=1)

    calls = {"n": 0}

    def fake_request(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return FakeResp(429, text="rate limited")
        return FakeResp(200, text="ok", json_obj={"ok": True})

    monkeypatch.setattr(client.session, "request", fake_request)

    resp = client.request("GET", "/anything")
    assert resp.status_code == 200
    assert calls["n"] == 2

def test_post_timeout_without_idempotency_does_not_retry(monkeypatch):
    client = DeterministicApiClient("https://example.com", timeout_seconds=1)

    calls = {"n": 0}

    def fake_request(*args, **kwargs):
        calls["n"] += 1
        raise requests.Timeout("network timeout")

    monkeypatch.setattr(client.session, "request", fake_request)

    with pytest.raises(NonRetryableHttpError):
        client.request("POST", "/pay_bonus", json_body={"amount": 100})

    # Must only attempt once
    assert calls["n"] == 1
