from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type,RetryCallState

from .logger import get_logger, new_correlation_id


log = get_logger("deterministic_client")

def _log_retry(retry_state: RetryCallState) -> None:
    # Called by tenacity before sleeping between retries
    try:
        cid = retry_state.kwargs.get("correlation_id") or "unknown"
    except Exception:
        cid = "unknown"

    attempt = retry_state.attempt_number
    exc = retry_state.outcome.exception() if retry_state.outcome else None
    err = str(exc) if exc else "unknown"

    log.info(
        "http_retry_attempt",
        extra={"cid": cid, "attempt": attempt, "error": err},
    )


class RetryableHttpError(Exception):
    """Raised for errors we want to retry safely (timeouts, 429, transient 5xx)."""


class NonRetryableHttpError(Exception):
    """Raised for errors we should not retry (most 4xx, unsafe retries)."""


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
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=0.5, min=0.5, max=4),
    retry=retry_if_exception_type(RetryableHttpError),
    before_sleep=_log_retry,
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
        """
        Deterministic request wrapper:
        - Correlation ID for tracing
        - Optional Idempotency-Key for safe retries on writes
        - Retries only when logically safe
        """
        cid = correlation_id or new_correlation_id()
        url = self._full_url(path)

        merged_headers: Dict[str, str] = {}
        if headers:
            merged_headers.update(headers)

        merged_headers["X-Correlation-Id"] = cid
        if idempotency_key:
            merged_headers["Idempotency-Key"] = idempotency_key

        is_write = method.upper() in ("POST", "PUT", "PATCH")

        try:
            log.info("http_request", extra={"cid": cid, "method": method.upper(), "url": url})

            resp = self.session.request(
                method=method.upper(),
                url=url,
                headers=merged_headers,
                json=json_body,
                timeout=self.timeout_seconds,
            )

        except (requests.Timeout, requests.ConnectionError) as e:
            # Critical rule: never retry an unsafe write without idempotency
            if is_write and not idempotency_key:
                log.info("http_non_retryable_timeout_write", extra={"cid": cid, "err": str(e)})
                raise NonRetryableHttpError("Timeout on write without idempotency key") from e

            log.info("http_retryable_exception", extra={"cid": cid, "err": str(e)})
            raise RetryableHttpError(str(e)) from e

        # Retryable statuses
        if resp.status_code in (429, 502, 503, 504):
            log.info("http_retryable_status", extra={"cid": cid, "status": resp.status_code})
            raise RetryableHttpError(f"Retryable status: {resp.status_code}")

        # 5xx handling (retry only if safe)
        if 500 <= resp.status_code <= 599:
            if is_write and not idempotency_key:
                raise NonRetryableHttpError(
                    f"Server error {resp.status_code} on write without idempotency key"
                )
            log.info("http_retryable_5xx", extra={"cid": cid, "status": resp.status_code})
            raise RetryableHttpError(f"Server error: {resp.status_code}")

        # Non-retryable client errors (most 4xx)
        if 400 <= resp.status_code <= 499:
            raise NonRetryableHttpError(
                f"Client error: {resp.status_code} {resp.text[:200]}"
            )

        # Parse JSON if present
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
