"""
reCAPTCHA Enterprise token provider for Google Flow.

Flow requires a reCAPTCHA Enterprise v3 token with every generation request.
reCAPTCHA Enterprise v3 uses deep behavioral scoring — it tracks mouse movements,
browsing history, interaction patterns, and more. No automated/headless browser
can pass this scoring, regardless of how well it's disguised.

This module connects to the Chrome browser that was kept alive after `gflow auth`.
Since that browser has genuine user interaction (the user logged in manually),
reCAPTCHA Enterprise gives it a good score and accepts the tokens.

The connection is via Chrome DevTools Protocol (CDP) over WebSocket to the
--remote-debugging-port that was set during `gflow auth`.

Site key (from Flow network traffic):
  6LdsFiUsAAAAAIjVDZcuLhaHiDn5nnHVXVRQGeMV
"""

from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.error
from typing import Optional

logger = logging.getLogger("gflow.recaptcha")

# reCAPTCHA Enterprise site key for labs.google
RECAPTCHA_SITE_KEY = "6LdsFiUsAAAAAIjVDZcuLhaHiDn5nnHVXVRQGeMV"

# Flow URL to load for reCAPTCHA context
FLOW_URL = "https://labs.google/fx/tools/flow"


class RecaptchaProvider:
    """
    Provides fresh reCAPTCHA Enterprise tokens by connecting to the
    Chrome browser that was kept alive from `gflow auth`.

    This avoids launching any new browser — it reuses the authenticated
    session where the user already interacted, which is the only way
    to get valid reCAPTCHA Enterprise v3 tokens.
    """

    def __init__(self, cookies: str = "", debug: bool = False):
        self.debug = debug
        self._cookies = cookies
        self._ws = None
        self._msg_id: int = 0
        self._ready = False

    def get_token(self, action: str = "IMAGE_GENERATION") -> str:
        """
        Get a fresh reCAPTCHA Enterprise token.

        Args:
            action: The reCAPTCHA action string. Flow uses:
                    - "IMAGE_GENERATION" for image generation
                    - "VIDEO_GENERATION" for video generation

        Returns:
            A reCAPTCHA token string

        Raises:
            RecaptchaError if token cannot be obtained
        """
        if not self._ready:
            self._connect()

        return self._execute_recaptcha(action)

    def _connect(self) -> None:
        """Connect to the existing auth Chrome browser via CDP, launching one if needed."""
        from gflow.auth.browser_auth import get_saved_cdp_port

        port = get_saved_cdp_port()
        if not port:
            logger.info("No Chrome session found — auto-launching auth browser...")
            port = self._auto_launch_chrome()
            if not port:
                raise RecaptchaError(
                    "No Chrome browser session found and auto-launch failed.\n"
                    "Run 'gflow auth' first — it opens a Chrome window that stays\n"
                    "open for reCAPTCHA. Don't close it until you're done generating."
                )

        if self.debug:
            logger.info("Connecting to auth Chrome on port %d...", port)

        # Find a page target on the Flow domain
        ws_url = self._find_flow_tab(port)
        if not ws_url:
            # No Flow tab found — try to find any page tab and navigate it
            ws_url = self._find_any_tab(port)
            if not ws_url:
                raise RecaptchaError(
                    "Chrome is running but has no usable tabs.\n"
                    "Run 'gflow auth' again to set up a fresh session."
                )
            # Connect and navigate to Flow
            self._connect_ws(ws_url)
            self._cdp_send("Page.enable")
            self._cdp_navigate(FLOW_URL)
        else:
            self._connect_ws(ws_url)

        # Wait for reCAPTCHA to be available
        self._wait_for_recaptcha()
        self._ready = True

        if self.debug:
            logger.info("Connected to auth Chrome, reCAPTCHA ready")

    def _auto_launch_chrome(self) -> int | None:
        """Auto-launch Chrome with CDP for reCAPTCHA, reusing saved cookies."""
        import os
        import platform
        import subprocess
        from gflow.auth.browser_auth import (
            _get_chrome_path, _find_free_port, save_cdp_port,
            _wait_for_cdp_page, ENV_DIR,
        )

        try:
            chrome_path = _get_chrome_path()
        except Exception:
            return None

        cdp_port = _find_free_port()
        profile_dir = str(ENV_DIR / "chrome-profile")

        args = [
            chrome_path,
            f"--remote-debugging-port={cdp_port}",
            "--remote-allow-origins=*",
            f"--user-data-dir={profile_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            FLOW_URL,
        ]

        if self.debug:
            logger.info("Auto-launching Chrome on CDP port %d", cdp_port)

        creation_flags = 0
        if platform.system() == "Windows":
            creation_flags = (
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
            )

        try:
            subprocess.Popen(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creation_flags if platform.system() == "Windows" else 0,
                start_new_session=(platform.system() != "Windows"),
            )
        except Exception as e:
            logger.warning("Failed to launch Chrome: %s", e)
            return None

        # Wait for CDP to become available
        try:
            _wait_for_cdp_page(cdp_port, timeout=30)
        except Exception:
            logger.warning("Chrome launched but CDP not available")
            return None

        save_cdp_port(cdp_port)

        # Give the page time to fully load reCAPTCHA scripts
        import time as _time
        _time.sleep(5)

        return cdp_port

    def _find_flow_tab(self, port: int) -> str | None:
        """Find a tab that's already on labs.google/fx."""
        try:
            url = f"http://127.0.0.1:{port}/json/list"
            resp = urllib.request.urlopen(url, timeout=5)
            targets = json.loads(resp.read().decode())

            for target in targets:
                if target.get("type") == "page":
                    page_url = target.get("url", "")
                    if "labs.google/fx" in page_url:
                        return target.get("webSocketDebuggerUrl", "")
        except Exception as e:
            if self.debug:
                logger.warning("Failed to list tabs: %s", e)
        return None

    def _find_any_tab(self, port: int) -> str | None:
        """Find any page tab we can use."""
        try:
            url = f"http://127.0.0.1:{port}/json/list"
            resp = urllib.request.urlopen(url, timeout=5)
            targets = json.loads(resp.read().decode())

            for target in targets:
                if target.get("type") == "page":
                    return target.get("webSocketDebuggerUrl", "")
        except Exception:
            pass
        return None

    def _connect_ws(self, ws_url: str) -> None:
        """Connect to a CDP WebSocket endpoint."""
        import websocket

        try:
            self._ws = websocket.create_connection(ws_url, timeout=30)
        except Exception as e:
            raise RecaptchaError(
                f"Failed to connect to Chrome: {e}\n"
                "The auth browser may have been closed. Run 'gflow auth' again."
            )

    def _cdp_send(self, method: str, params: dict | None = None) -> dict:
        """Send a CDP command and wait for the result."""
        self._msg_id += 1
        msg = {"id": self._msg_id, "method": method}
        if params:
            msg["params"] = params

        self._ws.send(json.dumps(msg))

        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                self._ws.settimeout(5)
                raw = self._ws.recv()
                data = json.loads(raw)
                if data.get("id") == self._msg_id:
                    if "error" in data:
                        raise RecaptchaError(f"CDP error: {data['error']}")
                    return data.get("result", {})
            except RecaptchaError:
                raise
            except Exception as e:
                if "timed out" in str(e).lower() or "timeout" in str(e).lower():
                    continue
                raise

        raise RecaptchaError("CDP command timed out")

    def _cdp_navigate(self, url: str) -> None:
        """Navigate to a URL and wait for it to load."""
        self._cdp_send("Page.navigate", {"url": url})

        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                self._ws.settimeout(2)
                raw = self._ws.recv()
                data = json.loads(raw)
                method = data.get("method", "")
                if method in ("Page.loadEventFired", "Page.frameStoppedLoading"):
                    return
            except Exception:
                continue

        if self.debug:
            logger.info("Navigation wait timed out, continuing...")

    def _cdp_evaluate(self, expression: str):
        """Evaluate JS expression in the page and return the result."""
        result = self._cdp_send("Runtime.evaluate", {
            "expression": expression,
            "awaitPromise": True,
            "returnByValue": True,
        })
        inner = result.get("result", {})
        if inner.get("subtype") == "error":
            raise RecaptchaError(f"JS error: {inner.get('description', 'unknown')}")
        return inner.get("value")

    def _wait_for_recaptcha(self, timeout: int = 30) -> None:
        """Wait for reCAPTCHA Enterprise to load on the page."""
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                ready = self._cdp_evaluate(
                    "typeof grecaptcha !== 'undefined' && "
                    "typeof grecaptcha.enterprise !== 'undefined' && "
                    "typeof grecaptcha.enterprise.execute === 'function'"
                )
                if ready:
                    if self.debug:
                        logger.info("reCAPTCHA Enterprise loaded")
                    return
            except RecaptchaError:
                pass
            time.sleep(1)

        raise RecaptchaError(
            "reCAPTCHA Enterprise did not load within 30s.\n"
            "The auth browser may have navigated away from Flow.\n"
            "Run 'gflow auth' again."
        )

    def _execute_recaptcha(self, action: str = "IMAGE_GENERATION") -> str:
        """Execute reCAPTCHA and get a token."""
        try:
            token = self._cdp_evaluate(
                f"grecaptcha.enterprise.execute('{RECAPTCHA_SITE_KEY}', {{action: '{action}'}})"
            )

            if not token or not isinstance(token, str):
                raise RecaptchaError(f"reCAPTCHA returned invalid token: {token}")

            if len(token) < 100:
                raise RecaptchaError(f"reCAPTCHA token too short ({len(token)} chars)")

            if self.debug:
                logger.info("Got reCAPTCHA token: %s... (%d chars)", token[:30], len(token))

            return token

        except RecaptchaError:
            raise
        except Exception as e:
            raise RecaptchaError(f"Failed to execute reCAPTCHA: {e}")

    def close(self) -> None:
        """Close the WebSocket connection (does NOT close Chrome)."""
        if self._ws:
            try:
                self._ws.close()
            except Exception:
                pass
            self._ws = None
        self._ready = False

    def __del__(self):
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class RecaptchaError(Exception):
    """Raised when reCAPTCHA token cannot be obtained."""
    pass
