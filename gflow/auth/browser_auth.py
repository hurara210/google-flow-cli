"""
Browser-based authentication for Google Flow.

Opens a real Chrome window (via subprocess, NOT Selenium) and lets the user
log in to their Google account. Cookies are extracted via Chrome DevTools
Protocol (CDP). The cookies are used to call the session endpoint
(labs.google/fx/api/auth/session) to get fresh OAuth2 access_tokens.

IMPORTANT: We intentionally avoid Selenium/chromedriver because reCAPTCHA
Enterprise v3 detects chromedriver artifacts and permanently taints the
browser session with a low trust score. By launching Chrome directly via
subprocess with --remote-debugging-port, the browser is completely clean.

After authentication, Chrome stays alive so that reCAPTCHA Enterprise tokens
can be obtained from the same session via CDP.

Architecture:
  1. subprocess launches Chrome with --remote-debugging-port
  2. CDP WebSocket connection extracts cookies
  3. Cookies saved to ~/.gflow/env; CDP port saved to ~/.gflow/cdp-port
  4. Chrome stays alive for reCAPTCHA token generation
  5. At runtime, cookies -> /fx/api/auth/session -> fresh access_token
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import requests

logger = logging.getLogger("gflow.auth")

FLOW_HOST = "labs.google"
FLOW_URL = "https://labs.google/fx/tools/flow"
SESSION_URL = "https://labs.google/fx/api/auth/session"
ENV_DIR = Path.home() / ".gflow"
ENV_FILE = ENV_DIR / "env"
CDP_PORT_FILE = ENV_DIR / "cdp-port"


@dataclass
class AuthData:
    """Authentication credentials for Google Flow."""

    cookies: str  # Full cookie string (Google session cookies)
    token: str = ""  # OAuth2 access_token (refreshed from session endpoint)
    expires: str = ""  # Token expiry time

    @property
    def is_valid(self) -> bool:
        return bool(self.cookies)


def refresh_access_token(cookies: str, debug: bool = False) -> dict:
    """
    Call the session endpoint to get a fresh access_token.
    """
    headers = {
        "Origin": "https://labs.google",
        "Referer": "https://labs.google/fx/tools/image-fx",
        "Cookie": cookies,
    }

    if debug:
        logger.info("Refreshing access token from %s", SESSION_URL)

    # Route through residential proxy if configured (cookies are tied to proxy IP)
    proxies = None
    try:
        from gflow.api.client import get_active_proxy
        proxy_url = get_active_proxy()
        if proxy_url:
            proxies = {"https": proxy_url, "http": proxy_url}
    except Exception:
        pass

    resp = requests.get(SESSION_URL, headers=headers, timeout=30, proxies=proxies)

    if resp.status_code == 401:
        raise AuthError(
            "Session expired. Run: gflow auth --clear && gflow auth"
        )
    if resp.status_code != 200:
        raise AuthError(
            f"Session endpoint returned {resp.status_code}: {resp.text[:300]}"
        )

    data = resp.json()

    access_token = data.get("access_token", "")
    if not access_token:
        raise AuthError(
            "Session endpoint returned no access_token. "
            "Cookies may be expired. Run: gflow auth --clear && gflow auth"
        )

    if debug:
        user = data.get("user", {})
        logger.info(
            "Got access_token: %s... (expires: %s, user: %s)",
            access_token[:20],
            data.get("expires", "?"),
            user.get("email", "?"),
        )

    return {
        "access_token": access_token,
        "expires": data.get("expires", ""),
        "user": data.get("user", {}),
    }


# ------------------------------------------------------------------
# Chrome binary discovery
# ------------------------------------------------------------------

def _find_chrome() -> str:
    """Find the Chrome binary on the current system."""
    system = platform.system()

    if system == "Windows":
        candidates = [
            os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
        ]
    elif system == "Darwin":
        candidates = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        ]
    else:
        candidates = [
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
        ]

    for path in candidates:
        if os.path.isfile(path):
            return path

    chrome_in_path = shutil.which("chrome") or shutil.which("google-chrome") or shutil.which("chromium")
    if chrome_in_path:
        return chrome_in_path

    raise AuthError(
        "Chrome not found. Install Google Chrome or set CHROME_PATH env var."
    )


def _get_chrome_path() -> str:
    """Get Chrome binary path, allowing env var override."""
    env_path = os.environ.get("CHROME_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path
    return _find_chrome()


def _find_free_port() -> int:
    """Find a free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ------------------------------------------------------------------
# CDP port persistence
# ------------------------------------------------------------------

def get_saved_cdp_port() -> int | None:
    """Get the saved CDP port from a previous auth session."""
    if not CDP_PORT_FILE.exists():
        return None
    try:
        port = int(CDP_PORT_FILE.read_text().strip())
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex(("127.0.0.1", port))
            if result == 0:
                return port
    except (ValueError, OSError):
        pass
    return None


def save_cdp_port(port: int) -> None:
    """Save the CDP debugging port for reuse."""
    ENV_DIR.mkdir(parents=True, exist_ok=True)
    CDP_PORT_FILE.write_text(str(port))


def clear_cdp_port() -> None:
    """Remove the saved CDP port file."""
    if CDP_PORT_FILE.exists():
        CDP_PORT_FILE.unlink()


# ------------------------------------------------------------------
# CDP helpers (no Selenium — pure WebSocket)
# ------------------------------------------------------------------

class _CDPConnection:
    """Lightweight CDP WebSocket connection for cookie extraction."""

    def __init__(self, ws_url: str):
        import websocket
        self._ws = websocket.create_connection(ws_url, timeout=30)
        self._msg_id = 0

    def send(self, method: str, params: dict | None = None) -> dict:
        """Send CDP command, return result."""
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
                        raise AuthError(f"CDP error: {data['error']}")
                    return data.get("result", {})
            except AuthError:
                raise
            except Exception as e:
                if "timed out" in str(e).lower() or "timeout" in str(e).lower():
                    continue
                raise
        raise AuthError("CDP command timed out")

    def close(self):
        try:
            self._ws.close()
        except Exception:
            pass


def _wait_for_cdp_page(port: int, timeout: int = 30) -> str:
    """Wait for a page-level CDP WebSocket URL."""
    import urllib.request
    import urllib.error

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            url = f"http://127.0.0.1:{port}/json/list"
            resp = urllib.request.urlopen(url, timeout=2)
            targets = json.loads(resp.read().decode())
            for target in targets:
                if target.get("type") == "page":
                    ws_url = target.get("webSocketDebuggerUrl", "")
                    if ws_url:
                        return ws_url
        except (urllib.error.URLError, ConnectionRefusedError, OSError, json.JSONDecodeError):
            pass
        time.sleep(0.5)
    raise AuthError(f"Chrome CDP not available after {timeout}s on port {port}")


def _get_all_cookies_cdp(cdp: _CDPConnection) -> list[dict]:
    """Get all cookies via CDP Network.getAllCookies."""
    result = cdp.send("Network.getAllCookies")
    return result.get("cookies", [])


def _get_current_url_cdp(cdp: _CDPConnection) -> str:
    """Get the current page URL via CDP."""
    try:
        result = cdp.send("Runtime.evaluate", {
            "expression": "window.location.href",
            "returnByValue": True,
        })
        return result.get("result", {}).get("value", "")
    except Exception:
        return ""


# ------------------------------------------------------------------
# Main auth class
# ------------------------------------------------------------------

class BrowserAuth:
    """
    Handles browser-based authentication for Google Flow.

    Launches Chrome directly (no Selenium/chromedriver!) via subprocess,
    with --remote-debugging-port for CDP access. User logs in manually,
    cookies are extracted via CDP.

    Chrome stays alive after auth for reCAPTCHA token generation.
    """

    def __init__(self, debug: bool = False):
        self.debug = debug

    def get_auth(self, profile: str | None = None, interactive: bool = True) -> AuthData:
        """
        Get authentication credentials.

        Order:
        1. Environment variables (GFLOW_COOKIES)
        2. Saved credentials in ~/.gflow/env
        3. Browser login (if interactive=True)
        """
        cookies = os.environ.get("GFLOW_COOKIES", "")
        if cookies:
            if self.debug:
                logger.info("Using cookies from environment variables")
            return AuthData(cookies=cookies)

        auth = load_env()
        if auth and auth.is_valid:
            if self.debug:
                logger.info("Using saved cookies from %s", ENV_FILE)
            return auth

        if interactive:
            auth = self._login_with_browser(profile)
            if auth and auth.is_valid:
                save_env(auth)
                return auth

        raise AuthError(
            "Could not authenticate. Try one of:\n"
            "  1. Run 'gflow auth' to log in via browser\n"
            "  2. Set GFLOW_COOKIES environment variable"
        )

    def _login_with_browser(self, profile: str | None = None) -> AuthData | None:
        """
        Launch Chrome directly (no Selenium!), navigate to Flow, wait for
        the user to log in, extract cookies via CDP.

        Chrome stays alive after auth for reCAPTCHA.
        """
        # Kill any previously running auth Chrome
        kill_auth_browser()

        print()
        print("=" * 60)
        print("  Google Flow Authentication")
        print("=" * 60)
        print()
        print("  A Chrome window will open.")
        print("  1. Log in with your Google account")
        print("  2. Wait until the Flow page loads")
        print("  3. Come back here - cookies will be captured")
        print()
        print("  The browser will stay open for image/video generation.")
        print("  Run 'gflow close' when you're done to close it.")
        print()
        print("  Timeout: 5 minutes")
        print()

        chrome_path = _get_chrome_path()
        cdp_port = _find_free_port()

        profile_dir = str(ENV_DIR / "chrome-profile")

        # Build Chrome args — NO chromedriver, NO Selenium
        args = [
            chrome_path,
            f"--remote-debugging-port={cdp_port}",
            "--remote-allow-origins=*",
            f"--user-data-dir={profile_dir}",
            "--no-first-run",
            "--no-default-browser-check",
        ]

        if profile:
            args.append(f"--profile-directory={profile}")

        # Route Chrome through residential proxy if configured
        try:
            from gflow.auth.proxy_ext import get_chrome_proxy_args
            proxy_args = get_chrome_proxy_args()
            if proxy_args:
                args.extend(proxy_args)
                print("  Using residential proxy for browser")
        except Exception:
            pass

        # Start with the Flow URL
        args.append(FLOW_URL)

        if self.debug:
            logger.info("Launching Chrome: %s", " ".join(args[:3]))
            logger.info("CDP port: %d", cdp_port)

        # Launch Chrome as a detached process (survives after Python exits)
        creation_flags = 0
        if platform.system() == "Windows":
            creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS

        try:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creation_flags if platform.system() == "Windows" else 0,
                start_new_session=(platform.system() != "Windows"),
            )
        except FileNotFoundError:
            raise AuthError(f"Chrome not found at: {chrome_path}")
        except Exception as e:
            raise AuthError(f"Failed to launch Chrome: {e}")

        print("  Browser opened. Waiting for login...")

        # Connect via CDP
        try:
            ws_url = _wait_for_cdp_page(cdp_port, timeout=30)
        except AuthError:
            print("\n  Could not connect to Chrome. Make sure Chrome is not already running")
            print("  with this profile. Try: gflow auth --clear")
            return None

        cdp = _CDPConnection(ws_url)

        try:
            cdp.send("Network.enable")

            # Poll for authentication (up to 5 minutes)
            for attempt in range(60):
                time.sleep(5)

                current_url = _get_current_url_cdp(cdp)
                if self.debug:
                    logger.info("Poll %d/60 - URL: %s", attempt + 1, current_url)

                # If still on a login/accounts page, keep waiting
                if "accounts.google" in current_url or "signin" in current_url.lower():
                    if attempt % 6 == 0:
                        print(f"  Waiting for login... ({(attempt + 1) * 5}s)")
                    continue

                # Get all cookies
                all_cookies = _get_all_cookies_cdp(cdp)

                # Check for Google auth cookies
                cookie_names = {c["name"] for c in all_cookies}
                has_google_auth = bool(
                    {"SID", "HSID", "SSID", "__Secure-1PSID", "SAPISID"}.intersection(cookie_names)
                )

                if self.debug:
                    logger.info("Cookies: %d total, auth=%s", len(all_cookies), has_google_auth)

                if not has_google_auth:
                    if attempt % 6 == 0:
                        print(f"  On Flow page but no auth cookies yet... ({(attempt + 1) * 5}s)")
                    continue

                # Build cookie string
                cookie_str = "; ".join(
                    f'{c["name"]}={c["value"]}' for c in all_cookies
                )

                # Verify cookies work
                try:
                    session_data = refresh_access_token(cookie_str, debug=self.debug)
                    user = session_data.get("user", {})

                    # Save CDP port for reCAPTCHA
                    save_cdp_port(cdp_port)

                    # Make sure we're on the Flow page (reCAPTCHA needs it)
                    if "flow" not in current_url.lower():
                        cdp.send("Page.enable")
                        cdp.send("Page.navigate", {"url": FLOW_URL})
                        time.sleep(3)

                    print()
                    print("  Authentication successful!")
                    print(f"  User: {user.get('name', 'Unknown')} ({user.get('email', '')})")
                    print(f"  Token: {session_data['access_token'][:20]}...")
                    print(f"  Cookies: {len(all_cookies)} captured")
                    print(f"  Saved to: {ENV_FILE}")
                    print()
                    print("  Chrome stays open for reCAPTCHA. Run 'gflow close' when done.")
                    print()

                    return AuthData(
                        cookies=cookie_str,
                        token=session_data["access_token"],
                        expires=session_data.get("expires", ""),
                    )
                except AuthError as e:
                    logger.warning("Session endpoint failed: %s", e)
                    if attempt % 6 == 0:
                        print(f"  Got cookies but session not ready... ({(attempt + 1) * 5}s)")
                        print(f"    Reason: {e}")
                    continue

            print()
            print("  Timed out waiting for authentication.")
            print("  Make sure you log in to your Google account in the browser.")
            return None

        except Exception as e:
            logger.error("Auth error: %s", e)
            if self.debug:
                import traceback
                traceback.print_exc()
            print(f"\n  Error: {e}")
            return None

        finally:
            cdp.close()


def refresh_cookies_from_cdp() -> AuthData | None:
    """
    Silently re-extract cookies from the already-running Chrome CDP session.

    Inspired by notebooklm-mcp-cli's approach: instead of forcing the user
    to re-login when cookies rotate, just pull fresh cookies from the Chrome
    instance that's already authenticated and running.

    Google rotates some cookies on every request, but Chrome handles this
    transparently. By re-reading via CDP, we get the latest values without
    any user interaction.

    Returns:
        AuthData with fresh cookies, or None if Chrome isn't running.
    """
    port = get_saved_cdp_port()
    if not port:
        return None

    try:
        ws_url = _wait_for_cdp_page(port, timeout=5)
    except AuthError:
        return None

    cdp = _CDPConnection(ws_url)
    try:
        cdp.send("Network.enable")
        all_cookies = _get_all_cookies_cdp(cdp)

        if not all_cookies:
            return None

        # Verify Google auth cookies are still present
        cookie_names = {c["name"] for c in all_cookies}
        has_google_auth = bool(
            {"SID", "HSID", "SSID", "__Secure-1PSID", "SAPISID"}.intersection(cookie_names)
        )

        if not has_google_auth:
            logger.warning("CDP cookie refresh: Chrome running but no Google auth cookies")
            return None

        cookie_str = "; ".join(f'{c["name"]}={c["value"]}' for c in all_cookies)

        # Verify the cookies actually work before returning them
        try:
            session_data = refresh_access_token(cookie_str, debug=False)
            if session_data.get("access_token"):
                logger.info(
                    "Silent CDP cookie refresh successful (%d cookies)",
                    len(all_cookies),
                )
                auth = AuthData(
                    cookies=cookie_str,
                    token=session_data["access_token"],
                    expires=session_data.get("expires", ""),
                )
                # Persist refreshed cookies so next startup uses them
                save_env(auth)
                return auth
        except AuthError:
            logger.warning("CDP cookie refresh: cookies extracted but session endpoint rejected them")
            return None

    except Exception as e:
        logger.warning("CDP cookie refresh failed: %s", e)
        return None
    finally:
        cdp.close()


def kill_auth_browser() -> None:
    """Kill the Chrome browser that was kept alive for reCAPTCHA."""
    port = get_saved_cdp_port()
    if not port:
        clear_cdp_port()
        return

    try:
        import urllib.request
        url = f"http://127.0.0.1:{port}/json/version"
        resp = urllib.request.urlopen(url, timeout=2)
        data = json.loads(resp.read().decode())
        ws_url = data.get("webSocketDebuggerUrl", "")

        if ws_url:
            import websocket
            ws = websocket.create_connection(ws_url, timeout=5)
            ws.send(json.dumps({"id": 1, "method": "Browser.close"}))
            ws.close()
    except Exception:
        pass

    clear_cdp_port()


class AuthError(Exception):
    """Raised when authentication fails."""
    pass


# ------------------------------------------------------------------
# Persistence helpers
# ------------------------------------------------------------------

def save_env(auth: AuthData) -> None:
    """Save authentication credentials to ~/.gflow/env."""
    ENV_DIR.mkdir(parents=True, exist_ok=True)
    ENV_FILE.write_text(
        f"GFLOW_COOKIES={auth.cookies}\n",
    )
    try:
        ENV_FILE.chmod(0o600)
    except OSError:
        pass


def load_env() -> AuthData | None:
    """Load authentication credentials from ~/.gflow/env."""
    if not ENV_FILE.exists():
        return None

    cookies = ""
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if line.startswith("GFLOW_COOKIES="):
            cookies = line[len("GFLOW_COOKIES="):]

    if cookies:
        return AuthData(cookies=cookies)
    return None


def clear_env() -> None:
    """Remove saved authentication credentials."""
    kill_auth_browser()

    if ENV_FILE.exists():
        ENV_FILE.unlink()
    profile_dir = ENV_DIR / "chrome-profile"
    if profile_dir.exists():
        import shutil
        try:
            shutil.rmtree(profile_dir)
        except OSError:
            pass
