"""
Google BatchExecute protocol client.

This implements the same protocol used by Google's internal web services
(NotebookLM, Flow, ImageFX, etc.) to make RPC-style calls over HTTP.
Reverse-engineered from tmc/nlm's Go implementation and adapted for Python.

The protocol works as follows:
1. RPCs are encoded as nested JSON arrays
2. Sent as form-encoded POST to /_/<AppName>/data/batchexecute
3. Responses come back in a chunked format with )]}\' prefix
4. Each response chunk is a JSON array with wrb.fr markers
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import requests

logger = logging.getLogger("gflow.batchexecute")


class BatchExecuteError(Exception):
    """Error from a BatchExecute request."""

    def __init__(self, message: str, status_code: int = 0, response: requests.Response | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response

    @property
    def is_unauthorized(self) -> bool:
        return self.status_code == 401


@dataclass
class RPC:
    """A single RPC call to be executed via BatchExecute."""

    id: str  # RPC endpoint ID (e.g., "xYz123")
    args: list[Any] = field(default_factory=list)
    index: str = "generic"
    url_params: dict[str, str] = field(default_factory=dict)


@dataclass
class Response:
    """A decoded RPC response."""

    id: str = ""
    index: int = 0
    data: Any = None
    raw: str = ""
    error: str = ""


class ReqIDGenerator:
    """Generates incrementing request IDs matching Google's format."""

    def __init__(self):
        self._base = 1_500_000_000 + random.randint(0, 100_000_000)
        self._seq = 0

    def next(self) -> str:
        reqid = self._base + (self._seq * 100_000)
        self._seq += 1
        return str(reqid)


def _generate_sapisidhash(sapisid: str, origin: str) -> str:
    """Generate SAPISIDHASH authorization header value."""
    timestamp = int(time.time())
    data = f"{timestamp} {sapisid} {origin}"
    hash_val = hashlib.sha1(data.encode()).hexdigest()
    return f"SAPISIDHASH {timestamp}_{hash_val}"


def _extract_sapisid(cookies: str) -> str | None:
    """Extract SAPISID value from a cookie string."""
    for part in cookies.split(";"):
        part = part.strip()
        if part.startswith("SAPISID="):
            return part[len("SAPISID="):]
    return None


class BatchExecuteClient:
    """
    Client for Google's BatchExecute protocol.

    This is the core transport layer — it handles encoding RPCs into the
    batchexecute wire format, sending them, and decoding responses.
    Mirrors the architecture of tmc/nlm's internal/batchexecute package.
    """

    # Retryable HTTP status codes
    RETRYABLE_STATUSES = {429, 500, 502, 503, 504}

    def __init__(
        self,
        host: str,
        app: str,
        auth_token: str,
        cookies: str,
        *,
        headers: dict[str, str] | None = None,
        url_params: dict[str, str] | None = None,
        debug: bool = False,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        retry_max_delay: float = 10.0,
        timeout: float = 60.0,
    ):
        self.host = host
        self.app = app
        self.auth_token = auth_token
        self.cookies = cookies
        self.headers = headers or {}
        self.url_params = url_params or {}
        self.debug = debug
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.retry_max_delay = retry_max_delay
        self.timeout = timeout

        self._session = requests.Session()
        self._reqid = ReqIDGenerator()

    def do(self, rpc: RPC) -> Response:
        """Execute a single RPC call."""
        return self.execute([rpc])

    def execute(self, rpcs: list[RPC]) -> Response:
        """
        Execute one or more RPCs via the BatchExecute protocol.

        Encodes the RPCs, sends them as a form POST, and decodes the response.
        Includes retry logic for transient failures.
        """
        # Build URL
        base_url = f"https://{self.host}/_/{self.app}/data/batchexecute"
        params = {
            "rpcids": rpcs[0].id,
            "_reqid": self._reqid.next(),
        }
        params.update(self.url_params)
        if rpcs[0].url_params:
            params.update(rpcs[0].url_params)

        url = f"{base_url}?{urllib.parse.urlencode(params)}"

        if self.debug:
            logger.info("BatchExecute URL: %s", url)

        # Build request body
        envelope = [self._build_rpc_data(rpc) for rpc in rpcs]
        req_body = json.dumps([envelope])

        form_body = urllib.parse.urlencode({
            "f.req": req_body,
            "at": self.auth_token,
        })

        if self.debug:
            logger.info("Request body (decoded): %s", req_body)

        # Build headers
        req_headers = {
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "Cookie": self.cookies,
            "Origin": f"https://{self.host}",
            "Referer": f"https://{self.host}/",
        }
        req_headers.update(self.headers)

        # Add SAPISIDHASH if available
        sapisid = _extract_sapisid(self.cookies)
        if sapisid:
            origin = f"https://{self.host}"
            req_headers["Authorization"] = _generate_sapisidhash(sapisid, origin)

        # Execute with retries
        last_err = None
        resp = None

        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                delay = min(self.retry_delay * (2 ** (attempt - 1)), self.retry_max_delay)
                if self.debug:
                    logger.info("Retrying (attempt %d/%d) after %.1fs...", attempt, self.max_retries, delay)
                time.sleep(delay)

            try:
                resp = self._session.post(
                    url,
                    data=form_body,
                    headers=req_headers,
                    timeout=self.timeout,
                )
            except requests.RequestException as e:
                last_err = e
                if attempt < self.max_retries and self._is_retryable_error(e):
                    continue
                raise BatchExecuteError(f"Request failed: {e}") from e

            if resp.status_code in self.RETRYABLE_STATUSES and attempt < self.max_retries:
                last_err = BatchExecuteError(f"Server returned {resp.status_code}", resp.status_code, resp)
                continue
            break

        if resp is None:
            raise BatchExecuteError(f"All retry attempts failed: {last_err}")

        if self.debug:
            logger.info("Response status: %d", resp.status_code)
            logger.info("Response body (first 500 chars): %s", resp.text[:500])

        if resp.status_code != 200:
            raise BatchExecuteError(
                f"Request failed with status {resp.status_code}",
                resp.status_code,
                resp,
            )

        # Decode response
        responses = self._decode_response(resp.text)
        if not responses:
            raise BatchExecuteError("No valid responses found in batchexecute response")

        return responses[0]

    @staticmethod
    def _build_rpc_data(rpc: RPC) -> list:
        """Encode a single RPC into the batchexecute wire format."""
        args_json = json.dumps(rpc.args)
        return [rpc.id, args_json, None, "generic"]

    @staticmethod
    def _is_retryable_error(err: Exception) -> bool:
        """Check if a request exception is retryable."""
        retryable_patterns = [
            "ConnectionError", "Timeout", "ConnectionReset",
            "ConnectionRefused", "BrokenPipe",
        ]
        err_str = str(type(err).__name__) + str(err)
        return any(p.lower() in err_str.lower() for p in retryable_patterns)

    def _decode_response(self, raw: str) -> list[Response]:
        """
        Decode a batchexecute response.

        Google's batchexecute responses use a special format:
        - Prefixed with )]}' to prevent JSON hijacking
        - May be chunked (line with byte count, then that many bytes of JSON)
        - Each chunk contains arrays with "wrb.fr" markers
        - Data is often multi-layer JSON-encoded (string within string)
        """
        # Strip the anti-XSSI prefix
        raw = raw.strip()
        if raw.startswith(")]}'"):
            raw = raw[4:].strip()

        if not raw:
            raise BatchExecuteError("Empty response after stripping prefix")

        # Try chunked format first (starts with a digit = byte count)
        if raw[0].isdigit():
            return self._decode_chunked(raw)

        # Try plain JSON array format
        return self._decode_json_array(raw)

    def _decode_chunked(self, raw: str) -> list[Response]:
        """Decode the chunked batchexecute response format."""
        results: list[Response] = []
        pos = 0

        while pos < len(raw):
            # Skip whitespace
            while pos < len(raw) and raw[pos] in " \t\r\n":
                pos += 1
            if pos >= len(raw):
                break

            # Read chunk size
            nl_idx = raw.find("\n", pos)
            if nl_idx < 0:
                break

            try:
                chunk_size = int(raw[pos:nl_idx].strip())
            except ValueError:
                break

            pos = nl_idx + 1
            chunk = raw[pos : pos + chunk_size]
            pos += chunk_size

            # Parse chunk as JSON
            try:
                data = json.loads(chunk)
            except json.JSONDecodeError:
                continue

            if not isinstance(data, list):
                continue

            for rpc_data in data:
                resp = self._parse_rpc_entry(rpc_data)
                if resp:
                    results.append(resp)

        return results

    def _decode_json_array(self, raw: str) -> list[Response]:
        """Decode a plain JSON array batchexecute response."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise BatchExecuteError(f"Failed to decode response JSON: {e}") from e

        results: list[Response] = []

        if isinstance(data, list):
            for entry in data:
                resp = self._parse_rpc_entry(entry)
                if resp:
                    results.append(resp)

        return results

    @staticmethod
    def _parse_rpc_entry(rpc_data: Any) -> Response | None:
        """Parse a single wrb.fr RPC entry from the response."""
        if not isinstance(rpc_data, list) or len(rpc_data) < 7:
            return None

        if rpc_data[0] != "wrb.fr":
            return None

        rpc_id = rpc_data[1] if isinstance(rpc_data[1], str) else ""
        resp = Response(id=rpc_id)

        # Extract data — position 2 is primary, position 5 is fallback
        raw_data = rpc_data[2]
        if raw_data is None and len(rpc_data) > 5:
            raw_data = rpc_data[5]

        if raw_data is not None:
            resp.raw = raw_data if isinstance(raw_data, str) else json.dumps(raw_data)
            resp.data = _unwrap_json(raw_data)

        # Parse index
        idx = rpc_data[6] if len(rpc_data) > 6 else "generic"
        if idx == "generic":
            resp.index = 0
        elif isinstance(idx, str):
            try:
                resp.index = int(idx)
            except ValueError:
                resp.index = 0

        return resp


def _unwrap_json(value: Any, max_depth: int = 3) -> Any:
    """
    Unwrap multi-layer JSON encoding that Google uses.

    Google often JSON-encodes data multiple times, so a response might be:
    '"[\\"hello\\"]"' -> '["hello"]' -> ["hello"]
    """
    if not isinstance(value, str):
        return value

    current = value
    for _ in range(max_depth):
        current = current.strip()
        if not current:
            return current

        # If it looks like JSON, try to parse it
        if current[0] in "[{":
            try:
                return json.loads(current)
            except json.JSONDecodeError:
                return current

        # If it's a JSON string that might contain JSON inside
        if current[0] == '"':
            try:
                inner = json.loads(current)
                if isinstance(inner, str):
                    current = inner
                    continue
                return inner
            except json.JSONDecodeError:
                return current

        # Try parsing as-is
        try:
            return json.loads(current)
        except json.JSONDecodeError:
            return current

    return current
