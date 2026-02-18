from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from logger import get_logger, new_correlation_id

log = get_logger("deterministic_client")


class RetryableHttpError(Exception):
    pass


class NonRetryableHttpError(Exception):
    pass


@dataclass(frozen=True)
class ApiResponse:
    status_code: int
    headers: Dict[str, str]
    json: Optional[Dict[str, Any]]
    text: str


class DeterministicApiClient:
    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 10.0,
        user_agent: str = "deterministic-api-client/0.1",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

    def _full_url(self, path: str) -> str:
        path = path if path.startswith("/") else f"/{path}"
        return f"{self.base_url}{path}"

    @retry(
        reraise=True,
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=8),
        retry=retry_if_exception_type(RetryableHttpError),
    )
    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> ApiResponse:
        cid = correlation_id or new_correlation_id()
        url = self._full_url(path)

        merged_headers: Dict[str, str] = {}
        if headers:
            merged_headers.update(headers)

        merged_headers["X-Correlation-Id"] = cid
        if idempotency_key:
            merged_headers["Idempotency-Key"] = idempotency_key

        try:
            log.info("http_request", extra={"cid": cid, "method": method, "url": url})

            resp = self.session.request(
                method=method.upper(),
                url=url,
                headers=merged_headers,
                json=json_body,
                timeout=self.timeout_seconds,
            )

        except (requests.Timeout, requests.ConnectionError) as e:
            log.info("http_retryable_exception", extra={"cid": cid, "err": str(e)})
            raise RetryableHttpError(str(e)) from e

        if resp.status_code in (429, 502, 503, 504):
            log.info("http_retryable_status", extra={"cid": cid, "status": resp.status_code})
            raise RetryableHttpError(f"Retryable status: {resp.status_code}")

        if 500 <= resp.status_code <= 599:
            if method.upper() in ("POST", "PUT", "PATCH") and not idempotency_key:
                raise NonRetryableHttpError(
                    f"Server error {resp.status_code} on write without idempotency key"
                )
            raise RetryableHttpError(f"Server error: {resp.status_code}")

        if 400 <= resp.status_code <= 499:
            raise NonRetryableHttpError(
                f"Client error: {resp.status_code} {resp.text[:200]}"
            )

        parsed_json: Optional[Dict[str, Any]] = None
        try:
            if resp.headers.get("Content-Type", "").startswith("application/json"):
                parsed_json = resp.json()
        except Exception:
            parsed_json = None

        return ApiResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            json=parsed_json,
            text=resp.text,
        )
