"""
Google Flow API client.

Reverse-engineered from network traffic captured by `gflow sniff`.

Endpoints:
  - Project creation:  labs.google/fx/api/trpc/project.createProject
  - Image generation:  aisandbox-pa.googleapis.com/v1/projects/{pid}/flowMedia:batchGenerateImages
  - Video generation:  aisandbox-pa.googleapis.com/v1/video:batchAsyncGenerateVideoText
  - Video status:      aisandbox-pa.googleapis.com/v1/video:batchCheckAsyncVideoGenerationStatus
  - Media URLs:        labs.google/fx/api/trpc/media.getMediaUrlRedirect
  - Session/auth:      labs.google/fx/api/auth/session

Auth:
  - labs.google requests: Cookie header
  - aisandbox-pa requests: Bearer token only (no cookies!)
"""

from __future__ import annotations

import base64
import json
import logging
import os
import random
import time
import urllib.request
import urllib.error
import uuid
from pathlib import Path
from typing import Any

import requests

from gflow.api.models import (
    Asset,
    AssetType,
    ExtendVideoRequest,
    GenerateImageRequest,
    GenerateVideoRequest,
)
from gflow.auth.browser_auth import refresh_access_token, refresh_cookies_from_cdp, AuthError
from gflow.auth.recaptcha import RecaptchaProvider, RecaptchaError

logger = logging.getLogger("gflow.api")

# Actual API endpoints (from network capture)
SANDBOX_BASE = "https://aisandbox-pa.googleapis.com"
LABS_BASE = "https://labs.google/fx/api"

# Internal model names (discovered from sniff)
IMAGE_MODEL = "NARWHAL"  # Imagen 4 internal name
VIDEO_MODEL = "veo_3_1_t2v_fast_ultra"  # Veo 3.1 fast/ultra
TOOL_NAME = "PINHOLE"  # Flow's internal tool name

# Aspect ratio mapping
IMAGE_ASPECT_MAP = {
    "square": "IMAGE_ASPECT_RATIO_SQUARE",
    "1:1": "IMAGE_ASPECT_RATIO_SQUARE",
    "portrait": "IMAGE_ASPECT_RATIO_PORTRAIT",
    "9:16": "IMAGE_ASPECT_RATIO_PORTRAIT",
    "landscape": "IMAGE_ASPECT_RATIO_LANDSCAPE",
    "16:9": "IMAGE_ASPECT_RATIO_LANDSCAPE",
    "4:3": "IMAGE_ASPECT_RATIO_LANDSCAPE_FOUR_THREE",
}

VIDEO_ASPECT_MAP = {
    "square": "VIDEO_ASPECT_RATIO_SQUARE",
    "1:1": "VIDEO_ASPECT_RATIO_SQUARE",
    "portrait": "VIDEO_ASPECT_RATIO_PORTRAIT",
    "9:16": "VIDEO_ASPECT_RATIO_PORTRAIT",
    "landscape": "VIDEO_ASPECT_RATIO_LANDSCAPE",
    "16:9": "VIDEO_ASPECT_RATIO_LANDSCAPE",
}

# Extend model names include the aspect ratio + quality suffix
# Ultra plan uses _ultra suffix (matches base VIDEO_MODEL pattern)
EXTEND_MODEL_MAP = {
    "landscape": "veo_3_1_extend_fast_landscape_ultra",
    "16:9": "veo_3_1_extend_fast_landscape_ultra",
    "portrait": "veo_3_1_extend_fast_portrait_ultra",
    "9:16": "veo_3_1_extend_fast_portrait_ultra",
    "square": "veo_3_1_extend_fast_square_ultra",
    "1:1": "veo_3_1_extend_fast_square_ultra",
}


def _load_proxies() -> list[str]:
    """Load residential proxy list from ~/.gflow/proxies.txt.

    File format: one proxy per line as user:pass@host:port
    Lines starting with # are ignored. Empty lines are ignored.

    Returns list of proxy URLs formatted as http://user:pass@host:port
    Proxies are NOT shuffled — the first working proxy is used for the
    entire session (sticky IP).  Only rotates on failure.
    """
    proxy_file = Path.home() / ".gflow" / "proxies.txt"
    if not proxy_file.exists():
        return []

    proxies = []
    for line in proxy_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Normalize to full URL
        if not line.startswith("http"):
            line = f"http://{line}"
        proxies.append(line)

    if proxies:
        logger.info("Loaded %d residential proxies (sticky session)", len(proxies))

    return proxies


def get_active_proxy() -> str | None:
    """Return the currently active proxy URL for external use (e.g. Chrome launch).

    Returns None if no proxies are configured.
    """
    proxy_file = Path.home() / ".gflow" / "proxies.txt"
    if not proxy_file.exists():
        return None

    for line in proxy_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("http"):
            line = f"http://{line}"
        return line  # Return first proxy (sticky)

    return None


def parse_proxy_url(proxy_url: str) -> dict:
    """Parse proxy URL into components for Chrome extension.

    Returns dict with host, port, username, password.
    """
    from urllib.parse import urlparse
    p = urlparse(proxy_url)
    return {
        "host": p.hostname or "",
        "port": p.port or 8080,
        "username": p.username or "",
        "password": p.password or "",
        "scheme": p.scheme or "http",
    }


class FlowClient:
    """
    Client for Google Flow's internal APIs.

    Flow requires:
    1. A project (created per session via trpc)
    2. Bearer auth for aisandbox-pa.googleapis.com
    3. Cookie auth for labs.google
    """

    def __init__(self, cookies: str, *, debug: bool = False):
        self.debug = debug or os.environ.get("GFLOW_DEBUG") == "true"
        self.cookies = cookies
        self._access_token: str = ""
        self._project_id: str = ""
        self._workflow_id: str = ""
        self._primary_media_id: str = ""  # from workflow metadata — used for extend
        self._session_id: str = f";{int(time.time() * 1000)}"
        # Maps operation names to media names (they differ!)
        self._op_to_media: dict[str, str] = {}

        # Load residential proxy list from ~/.gflow/env
        self._proxies = _load_proxies()
        self._proxy_index = 0

        # Separate sessions for different hosts
        self._sandbox_session = requests.Session()
        self._labs_session = requests.Session()

        # Apply proxy to BOTH sessions when configured.
        # Chrome auth goes through the proxy, so cookies are tied to that IP.
        # All API calls must use the same IP to avoid auth mismatches.
        if self._proxies:
            proxy_url = self._pick_proxy()
            proxy_dict = {"https": proxy_url, "http": proxy_url}
            self._sandbox_session.proxies = proxy_dict
            self._labs_session.proxies = proxy_dict
            if self.debug:
                masked = proxy_url.split("@")[-1] if "@" in proxy_url else proxy_url
                logger.info("Using residential proxy: %s", masked)

        # reCAPTCHA Enterprise token provider (lazy-initialized)
        self._recaptcha: RecaptchaProvider | None = None

    def _pick_proxy(self) -> str:
        """Pick a proxy from the list (round-robin)."""
        if not self._proxies:
            return ""
        proxy = self._proxies[self._proxy_index % len(self._proxies)]
        self._proxy_index += 1
        return proxy

    def _rotate_proxy(self) -> None:
        """Switch both sessions to the next proxy in the list."""
        if not self._proxies or len(self._proxies) < 2:
            return
        proxy_url = self._pick_proxy()
        proxy_dict = {"https": proxy_url, "http": proxy_url}
        self._sandbox_session.proxies = proxy_dict
        self._labs_session.proxies = proxy_dict
        masked = proxy_url.split("@")[-1] if "@" in proxy_url else proxy_url
        logger.info("Rotated to proxy: %s", masked)

    # ------------------------------------------------------------------
    # Token & Project Management
    # ------------------------------------------------------------------

    def _ensure_token(self) -> None:
        """Ensure we have a valid access token."""
        if not self._access_token:
            self._refresh_token()

    def _refresh_token(self) -> None:
        """Get a fresh access token from the session endpoint.

        Three-tier recovery strategy (inspired by notebooklm-py and
        notebooklm-mcp-cli):

        1. Try existing cookies (fast path — works most of the time)
        2. Silent CDP cookie refresh from running Chrome (no user interaction)
        3. Full browser re-authentication (last resort — requires user login)
        """
        # Tier 1: Try existing cookies
        try:
            data = refresh_access_token(self.cookies, debug=self.debug)
            self._apply_token(data)
            return
        except AuthError as original_err:
            logger.info("Tier 1 failed (existing cookies expired)")

        # Tier 2: Silent CDP cookie refresh — re-extract cookies from the
        # Chrome instance that's already running (Google rotates cookies
        # but Chrome tracks them automatically)
        logger.info("Trying silent CDP cookie refresh (no user interaction)...")
        refreshed = refresh_cookies_from_cdp()
        if refreshed and refreshed.is_valid:
            self.cookies = refreshed.cookies
            try:
                data = refresh_access_token(self.cookies, debug=self.debug)
                self._apply_token(data)
                logger.info("Tier 2 succeeded — cookies silently refreshed from Chrome")
                return
            except AuthError:
                logger.warning("Tier 2 failed — CDP cookies didn't work either")

        # Tier 3: Full browser re-authentication (user interaction required)
        logger.info("Falling back to full browser re-authentication...")
        new_cookies = self._re_authenticate()
        if not new_cookies:
            raise original_err
        data = refresh_access_token(self.cookies, debug=self.debug)
        self._apply_token(data)

    def _apply_token(self, data: dict) -> None:
        """Apply a fresh access token and update session headers."""
        self._access_token = data["access_token"]

        # Update sandbox session (Bearer only, no cookies)
        self._sandbox_session.headers.update({
            "Authorization": f"Bearer {self._access_token}",
            "Origin": "https://labs.google",
            "Referer": "https://labs.google/",
            "Content-Type": "text/plain;charset=UTF-8",
        })

        # Update labs session (cookies, no Bearer for trpc)
        self._labs_session.headers.update({
            "Cookie": self.cookies,
            "Origin": "https://labs.google",
            "Referer": "https://labs.google/fx/tools/flow",
            "Content-Type": "application/json",
        })

        if self.debug:
            logger.info("Token refreshed: %s...", self._access_token[:20])

    def _re_authenticate(self) -> str | None:
        """Re-authenticate via browser and update cookies in-place (Tier 3 — last resort)."""
        try:
            from gflow.auth import BrowserAuth, save_env
            browser_auth = BrowserAuth(debug=self.debug)
            auth = browser_auth.get_auth(interactive=True)
            save_env(auth)
            self.cookies = auth.cookies
            return self.cookies
        except Exception as e:
            logger.warning("Auto re-authentication failed: %s", e)
            return None

    def _get_recaptcha_token(self, action: str = "IMAGE_GENERATION") -> str:
        """Get a fresh reCAPTCHA Enterprise token.

        Args:
            action: reCAPTCHA action — "IMAGE_GENERATION" or "VIDEO_GENERATION"
        """
        if self._recaptcha is None:
            self._recaptcha = RecaptchaProvider(cookies=self.cookies, debug=self.debug)

        try:
            return self._recaptcha.get_token(action=action)
        except RecaptchaError as e:
            raise FlowAPIError(
                f"reCAPTCHA failed: {e}\n"
                "Make sure you're authenticated: gflow auth"
            )

    def _build_client_context(self, project_id: str, recaptcha_token: str) -> dict:
        """Build the clientContext dict used in all generation requests."""
        return {
            "recaptchaContext": {
                "token": recaptcha_token,
                "applicationType": "RECAPTCHA_APPLICATION_TYPE_WEB",
            },
            "projectId": project_id,
            "tool": TOOL_NAME,
            "userPaygateTier": "PAYGATE_TIER_TWO",
            "sessionId": self._session_id,
        }

    def _with_recaptcha_retry(self, fn, max_retries: int = 3):
        """Wrap a generation call with reCAPTCHA retry on 403.

        Enhanced retry strategy inspired by notebooklm-py:
        - Attempt 1: Retry with fresh reCAPTCHA token
        - Attempt 2: Also try silent CDP cookie refresh (cookies may have rotated)
        - Attempt 3: Full reconnect with extended warm-up

        Args:
            fn: A callable that takes no args and performs the generation request.
                It will be called repeatedly with fresh reCAPTCHA tokens on failure.
            max_retries: Maximum number of retry attempts.

        Returns:
            Whatever fn() returns on success.
        """
        import time as _time

        for attempt in range(max_retries):
            try:
                return fn()
            except FlowRecaptchaError as e:
                if attempt < max_retries - 1:
                    wait = 5 * (attempt + 1)
                    logger.warning(
                        "reCAPTCHA failed (attempt %d/%d), retrying in %ds with fresh token...",
                        attempt + 1, max_retries, wait
                    )

                    # On second attempt, also try refreshing cookies silently
                    # (Google may have rotated session cookies, causing the
                    # access token to be rejected alongside the reCAPTCHA token)
                    if attempt >= 1:
                        logger.info("Also attempting silent CDP cookie refresh...")
                        refreshed = refresh_cookies_from_cdp()
                        if refreshed and refreshed.is_valid:
                            self.cookies = refreshed.cookies
                            self._access_token = ""  # Force token refresh
                            self._refresh_token()
                            logger.info("Cookies silently refreshed during reCAPTCHA retry")

                    # Force reconnect to get a fresh reCAPTCHA token
                    if self._recaptcha:
                        self._recaptcha.close()
                        self._recaptcha = None
                    _time.sleep(wait)
                else:
                    raise FlowAPIError(
                        f"reCAPTCHA evaluation failed after {max_retries} attempts.\n"
                        f"Last error: {e}\n"
                        "Try: gflow auth --clear && gflow auth\n"
                        "Then interact with the Flow page for a minute before generating."
                    )

    def _ensure_project(self) -> str:
        """Create a project if we don't have one, or return existing."""
        if self._project_id:
            return self._project_id

        self._ensure_token()

        # Create a new project via trpc
        url = f"{LABS_BASE}/trpc/project.createProject"
        payload = {
            "json": {
                "projectTitle": "Untitled project",
                "toolName": TOOL_NAME,
            }
        }

        if self.debug:
            logger.info("Creating project: %s", json.dumps(payload))

        # Retry with proxy rotation on connection errors
        resp = None
        for attempt in range(3):
            try:
                resp = self._labs_session.post(url, json=payload, timeout=30)
                break
            except (requests.exceptions.ConnectionError, requests.exceptions.ProxyError,
                    requests.exceptions.ReadTimeout) as e:
                if attempt < 2:
                    logger.warning("Project creation connection failed (attempt %d/3): %s",
                                   attempt + 1, str(e)[:120])
                    self._rotate_proxy()
                    time.sleep(3)
                else:
                    raise

        # If cookies are stale, re-auth and retry once
        if resp.status_code == 401:
            logger.info("Project creation got 401 — re-authenticating...")
            if self._re_authenticate():
                self._refresh_token()
                resp = self._labs_session.post(url, json=payload, timeout=30)

        # If still 401, try via Chrome CDP (datacenter IPs get blocked on direct HTTP)
        if resp.status_code == 401:
            logger.info("Direct HTTP still 401 — trying via Chrome browser (CDP)...")
            data = self._create_project_via_cdp(payload)
            if data:
                json_data = data.get("result", {}).get("data", {}).get("json", {})
                project_id = (
                    json_data.get("result", {}).get("projectId", "")
                    or json_data.get("projectId", "")
                )
                if project_id:
                    self._project_id = project_id
                    if self.debug:
                        logger.info("Created project via CDP: %s", project_id)
                    return project_id

        if resp.status_code != 200:
            raise FlowAPIError(f"Failed to create project: {resp.status_code} {resp.text[:300]}")

        data = resp.json()
        # Extract project ID from response
        # Response format: {"result":{"data":{"json":{"result":{"projectId":"..."},"status":200}}}}
        json_data = data.get("result", {}).get("data", {}).get("json", {})
        project_id = (
            json_data.get("result", {}).get("projectId", "")
            or json_data.get("projectId", "")
        )

        if not project_id:
            if self.debug:
                logger.info("Project response: %s", json.dumps(data, indent=2)[:500])
            raise FlowAPIError(f"Could not extract project ID from response: {json.dumps(data)[:300]}")

        self._project_id = project_id
        if self.debug:
            logger.info("Created project: %s", project_id)

        return project_id

    def _create_project_via_cdp(self, payload: dict) -> dict | None:
        """Create a project by running fetch() inside the Chrome browser via CDP.

        Key requirements for this to work:
        1. The Chrome tab MUST be on labs.google — the browser enforces Origin
           based on the current page, and custom Origin headers in fetch() are
           silently ignored. If the tab is on chrome://newtab, the Origin will
           be wrong and Google rejects with 401.
        2. Don't set custom Origin/Referer headers — let the browser set them
           from the page context (that's the whole point of using CDP).
        3. Check for error responses properly (trpc returns {"error":{...}} dicts).
        """
        try:
            ws, port = self._get_cdp_websocket()
            if not ws:
                logger.warning("No CDP WebSocket available for project creation")
                return None

            # CRITICAL: Ensure the tab is on labs.google/fx
            # Browser sets Origin from the current page — if the tab navigated
            # away (login redirect, error, etc.), the Origin will be wrong and
            # Google returns 401. Navigate there first.
            current_url = self._cdp_evaluate(ws, "window.location.href", timeout=5)
            if not current_url or "labs.google/fx" not in str(current_url):
                logger.info("CDP tab not on Flow page (url=%s), navigating...", current_url)
                # Navigate to Flow — this sets the correct Origin for fetch()
                nav_js = """
                    new Promise((resolve) => {
                        window.location.href = 'https://labs.google/fx/tools/flow';
                        // Wait for navigation to complete
                        setTimeout(() => resolve('navigated'), 5000);
                    })
                """
                self._cdp_evaluate(ws, nav_js, timeout=15)
                # Re-verify we're on the right page
                time.sleep(3)
                current_url = self._cdp_evaluate(ws, "window.location.href", timeout=5)
                if not current_url or "labs.google" not in str(current_url):
                    logger.warning("CDP: could not navigate to Flow page (url=%s)", current_url)
                    ws.close()
                    return None
                logger.info("CDP tab now on: %s", current_url)

            # Build the fetch call — NO custom Origin/Referer headers!
            # The browser sets these automatically from the page context.
            payload_json = json.dumps(payload)
            # Escape for embedding in JS template literal
            payload_escaped = payload_json.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${")

            js_code = f"""
                fetch('https://labs.google/fx/api/trpc/project.createProject', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json'
                    }},
                    credentials: 'same-origin',
                    body: `{payload_escaped}`
                }})
                .then(async r => {{
                    const text = await r.text();
                    return JSON.stringify({{status: r.status, body: text}});
                }})
                .catch(e => JSON.stringify({{status: 0, body: '', error: e.message}}))
            """

            value = self._cdp_evaluate(ws, js_code, timeout=30)
            ws.close()

            if not value or not isinstance(value, str):
                logger.warning("CDP project creation: no response")
                return None

            try:
                wrapper = json.loads(value)
            except json.JSONDecodeError:
                logger.warning("CDP project creation: invalid JSON response")
                return None

            status = wrapper.get("status", 0)
            body_str = wrapper.get("body", "")
            error = wrapper.get("error", "")

            if error:
                logger.warning("CDP fetch error: %s", error)
                return None

            if status != 200:
                logger.warning("CDP project creation returned HTTP %d: %s", status, body_str[:300])
                return None

            # Parse the actual response body
            try:
                parsed = json.loads(body_str)
                logger.info("Project created via Chrome CDP successfully")
                return parsed
            except json.JSONDecodeError:
                logger.warning("CDP project creation: response body not JSON: %s", body_str[:200])
                return None

        except Exception as e:
            logger.warning("CDP project creation failed: %s", e)
            return None

    def _ensure_workflow(self) -> str:
        """Ensure we have a workflow ID for the current project.

        Workflows are used by Flow to group related media (e.g. a video
        and its extensions).  The extend endpoint requires a valid
        workflowId in the request metadata.
        """
        if self._workflow_id:
            return self._workflow_id

        self._ensure_token()
        project_id = self._ensure_project()

        # Create a new workflow via POST to flowWorkflows
        url = f"{SANDBOX_BASE}/v1/flowWorkflows"
        workflow_name = str(uuid.uuid4())
        payload = {
            "workflow": {
                "name": workflow_name,
                "projectId": project_id,
                "metadata": {
                    "displayName": "gflow video",
                },
            },
        }

        if self.debug:
            logger.info("Creating workflow: %s", json.dumps(payload))

        resp = self._sandbox_request("POST", url, json_payload=payload)

        if resp.status_code >= 400:
            # If POST fails, just use the UUID we generated — the video
            # generation response will create the workflow implicitly.
            logger.warning("Workflow creation returned %s — using generated ID", resp.status_code)
            self._workflow_id = workflow_name
            return self._workflow_id

        data = resp.json()
        # Extract workflow ID from response
        wf_id = data.get("name", "") or data.get("workflowId", "") or workflow_name
        self._workflow_id = wf_id
        if self.debug:
            logger.info("Created workflow: %s", wf_id)

        return self._workflow_id

    def update_workflow(
        self,
        workflow_id: str,
        display_name: str = "",
        primary_media_id: str = "",
    ) -> None:
        """Update a workflow via PATCH /v1/flowWorkflows/{id}.

        The Flow UI calls this after every video generation and after
        each extend completes.  It updates:
        - ``displayName`` — human-readable title (after initial generation)
        - ``primaryMediaId`` — the ID the extend endpoint uses to locate the
          source video (after every extend, so subsequent extends can chain)
        """
        self._ensure_token()
        project_id = self._ensure_project()

        url = f"{SANDBOX_BASE}/v1/flowWorkflows/{workflow_id}"

        metadata: dict[str, str] = {}
        masks: list[str] = []

        if display_name:
            metadata["displayName"] = display_name
            masks.append("metadata.displayName")
        if primary_media_id:
            metadata["primaryMediaId"] = primary_media_id
            masks.append("metadata.primaryMediaId")

        if not masks:
            return  # nothing to update

        payload = {
            "workflow": {
                "name": workflow_id,
                "projectId": project_id,
                "metadata": metadata,
            },
            "updateMask": ",".join(masks),
        }

        if self.debug:
            logger.info("Updating workflow %s: %s", workflow_id, json.dumps(payload))

        try:
            self._sandbox_request("PATCH", url, json_payload=payload)
        except FlowAPIError as e:
            logger.warning("Workflow update failed (non-fatal): %s", e)

    # ------------------------------------------------------------------
    # Image Generation
    # ------------------------------------------------------------------

    def generate_image(self, req: GenerateImageRequest) -> list[Asset]:
        """
        Generate images using Imagen 4 (NARWHAL).

        POST /v1/projects/{pid}/flowMedia:batchGenerateImages
        """
        self._ensure_token()
        project_id = self._ensure_project()

        url = f"{SANDBOX_BASE}/v1/projects/{project_id}/flowMedia:batchGenerateImages"
        aspect = IMAGE_ASPECT_MAP.get(req.aspect_ratio.lower(), "IMAGE_ASPECT_RATIO_LANDSCAPE")
        seed = req.seed if req.seed is not None else random.randint(10000, 99999)

        def _do_generate():
            recaptcha_token = self._get_recaptcha_token()
            client_ctx = self._build_client_context(project_id, recaptcha_token)
            batch_id = str(uuid.uuid4())

            payload = {
                "clientContext": client_ctx,
                "mediaGenerationContext": {"batchId": batch_id},
                "useNewMedia": True,
                "requests": [],
            }
            for i in range(req.num_images):
                img_req = {
                    "clientContext": client_ctx,
                    "imageModelName": IMAGE_MODEL,
                    "imageAspectRatio": aspect,
                    "structuredPrompt": {
                        "parts": [{"text": req.prompt}],
                    },
                    "seed": seed + i,
                    "imageInputs": [],
                }
                payload["requests"].append(img_req)

            if self.debug:
                safe = json.dumps(payload, indent=2)[:1000]
                logger.info("Image request to %s:\n%s", url, safe)

            resp = self._sandbox_request("POST", url, json_payload=payload)
            data = resp.json()

            if self.debug:
                safe = json.dumps(data, indent=2)[:1000]
                logger.info("Image response:\n%s", safe)

            return self._parse_image_response(data, req.prompt)

        return self._with_recaptcha_retry(_do_generate)

    # ------------------------------------------------------------------
    # Video Generation (async)
    # ------------------------------------------------------------------

    def generate_video(self, req: GenerateVideoRequest) -> list[Asset]:
        """
        Generate a video using Veo 3.1 (async).

        POST /v1/video:batchAsyncGenerateVideoText
        """
        self._ensure_token()
        project_id = self._ensure_project()

        url = f"{SANDBOX_BASE}/v1/video:batchAsyncGenerateVideoText"
        aspect = VIDEO_ASPECT_MAP.get(req.aspect_ratio.lower(), "VIDEO_ASPECT_RATIO_LANDSCAPE")
        seed = req.seed if req.seed is not None else random.randint(10000, 99999)
        batch_id = str(uuid.uuid4())

        def _do_generate():
            nonlocal batch_id
            batch_id = str(uuid.uuid4())  # Fresh batch ID on each retry
            recaptcha_token = self._get_recaptcha_token(action="VIDEO_GENERATION")
            client_ctx = self._build_client_context(project_id, recaptcha_token)

            payload = {
                "mediaGenerationContext": {"batchId": batch_id},
                "clientContext": client_ctx,
                "requests": [{
                    "aspectRatio": aspect,
                    "seed": seed,
                    "textInput": {
                        "structuredPrompt": {
                            "parts": [{"text": req.prompt}],
                        },
                    },
                    "videoModelKey": VIDEO_MODEL,
                    "metadata": {},
                }],
                "useV2ModelConfig": True,
            }

            if self.debug:
                safe = json.dumps(payload, indent=2)[:1000]
                logger.info("Video request to %s:\n%s", url, safe)

            return self._sandbox_request("POST", url, json_payload=payload)

        resp = self._with_recaptcha_retry(_do_generate)
        data = resp.json()

        if self.debug:
            safe = json.dumps(data, indent=2)[:2000]
            logger.info("Video response:\n%s", safe)

        # Store workflow ID and primaryMediaId from response (needed for extend)
        workflows = data.get("workflows", [])
        if workflows and isinstance(workflows, list):
            wf = workflows[0]
            wf_id = wf.get("name", "") or wf.get("id", "") or wf.get("workflowId", "")
            if wf_id:
                self._workflow_id = wf_id
                logger.info("Stored workflow ID from video response: %s", wf_id)

            # primaryMediaId is the ID the extend endpoint uses to find the source video.
            # This is NOT the same as media[].name or operations[].operation.name.
            primary = wf.get("metadata", {}).get("primaryMediaId", "")
            if primary:
                self._primary_media_id = primary
                logger.info("Stored primaryMediaId from workflow: %s", primary)

        if self.debug:
            ops = data.get("operations", [])
            medias = data.get("media", [])
            op_id = ops[0].get("operation", {}).get("name", "") if ops else "NONE"
            media_id = medias[0].get("name", "") if medias else "NONE"
            logger.info("Video IDs — operation: %s, media: %s, primaryMedia: %s",
                        op_id, media_id, self._primary_media_id)

        return self._parse_video_response(data, req.prompt, batch_id)

    # ------------------------------------------------------------------
    # Video Extend (async)
    # ------------------------------------------------------------------

    def extend_video(self, req: ExtendVideoRequest) -> list[Asset]:
        """
        Extend a video using Veo 3.1 extend.

        POST /v1/video:batchAsyncGenerateVideoExtendVideo

        Takes an existing video's media ID and generates a continuation
        based on the extend prompt.  Requires a valid workflowId in
        metadata — obtained from the base video generation response or
        created explicitly.
        """
        self._ensure_token()
        project_id = self._ensure_project()

        # Resolve workflow ID — priority: explicit > stored > create new
        workflow_id = req.workflow_id or self._workflow_id
        if not workflow_id:
            workflow_id = self._ensure_workflow()

        url = f"{SANDBOX_BASE}/v1/video:batchAsyncGenerateVideoExtendVideo"
        aspect = VIDEO_ASPECT_MAP.get(req.aspect_ratio.lower(), "VIDEO_ASPECT_RATIO_LANDSCAPE")
        extend_model = EXTEND_MODEL_MAP.get(req.aspect_ratio.lower(), "veo_3_1_extend_fast_landscape")
        seed = req.seed if req.seed is not None else random.randint(10000, 99999)
        batch_id = str(uuid.uuid4())

        def _do_extend():
            nonlocal batch_id
            batch_id = str(uuid.uuid4())
            recaptcha_token = self._get_recaptcha_token(action="VIDEO_GENERATION")
            client_ctx = self._build_client_context(project_id, recaptcha_token)

            payload = {
                "mediaGenerationContext": {"batchId": batch_id},
                "clientContext": client_ctx,
                "requests": [{
                    "aspectRatio": aspect,
                    "seed": seed,
                    "textInput": {
                        "structuredPrompt": {
                            "parts": [{"text": req.prompt}],
                        },
                    },
                    "videoModelKey": extend_model,
                    "metadata": {
                        "workflowId": workflow_id,
                    },
                    "videoInput": {
                        "mediaId": req.media_id,
                    },
                }],
                "useV2ModelConfig": True,
            }

            if self.debug:
                safe = json.dumps(payload, indent=2)[:1000]
                logger.info("Extend request to %s:\n%s", url, safe)

            return self._sandbox_request("POST", url, json_payload=payload)

        resp = self._with_recaptcha_retry(_do_extend)
        data = resp.json()

        if self.debug:
            safe = json.dumps(data, indent=2)[:1000]
            logger.info("Extend response:\n%s", safe)

        return self._parse_video_response(data, req.prompt, batch_id)

    def check_video_status(self, operation_names: list[str]) -> dict:
        """
        Check status of async video generation.

        POST /v1/video:batchCheckAsyncVideoGenerationStatus

        Real payload format (from network sniff):
          {"media": [{"name": "uuid", "projectId": "uuid"}]}
        """
        self._ensure_token()

        url = f"{SANDBOX_BASE}/v1/video:batchCheckAsyncVideoGenerationStatus"

        # Build the real payload format — each media item needs name + projectId
        media_items = []
        for op_name in operation_names:
            media_items.append({
                "name": op_name,
                "projectId": self._project_id,
            })

        payload = {"media": media_items}

        if self.debug:
            logger.info("Video status check payload: %s", json.dumps(payload))

        resp = self._sandbox_request("POST", url, json_payload=payload)
        return resp.json()

    def get_flow_media(self, media_name: str) -> dict:
        """
        Get full media details including fifeUrl for download.

        GET /v1/flowMedia/{name}

        The status check endpoint does NOT return fifeUrl — only this
        endpoint does.  Call it after status shows SUCCESSFUL.
        """
        self._ensure_token()
        url = f"{SANDBOX_BASE}/v1/flowMedia/{media_name}"

        if self.debug:
            logger.info("Fetching media details: %s", url)

        resp = self._sandbox_request("GET", url)
        return resp.json()

    # Successful status values (Flow uses SUCCESSFUL, not COMPLETE)
    _VIDEO_DONE_STATUSES = {
        "MEDIA_GENERATION_STATUS_SUCCESSFUL",
        "MEDIA_GENERATION_STATUS_COMPLETE",   # keep as fallback
    }
    _VIDEO_FAIL_STATUSES = {
        "MEDIA_GENERATION_STATUS_FAILED",
    }

    def wait_for_video(self, operation_names: list[str], timeout: int = 300) -> list[Asset]:
        """Poll video status until complete or timeout.

        Flow for video:
        1. Poll batchCheckAsyncVideoGenerationStatus until
           mediaGenerationStatus == MEDIA_GENERATION_STATUS_SUCCESSFUL
        2. Fetch GET /v1/flowMedia/{name} to get the fifeUrl
        3. Return assets with download URLs
        """
        start = time.time()
        poll_interval = 10  # seconds

        while time.time() - start < timeout:
            data = self.check_video_status(operation_names)

            if self.debug:
                logger.info("Video status: %s", json.dumps(data, indent=2)[:2000])

            all_done = True
            completed_names: list[str] = []

            # Primary format: media[].mediaMetadata.mediaStatus.mediaGenerationStatus
            media_list = data.get("media", [])
            for media_item in media_list:
                media_name = media_item.get("name", "")
                status_info = (
                    media_item.get("mediaMetadata", {})
                    .get("mediaStatus", {})
                    .get("mediaGenerationStatus", "")
                )

                if self.debug:
                    logger.info("  Media %s status: %s", media_name[:8], status_info)

                if status_info in self._VIDEO_FAIL_STATUSES:
                    media_status = media_item.get("mediaMetadata", {}).get("mediaStatus", {})
                    failure_reason = (
                        media_status.get("failureReason", "")
                        or media_status.get("errorMessage", "")
                        or media_status.get("reason", "")
                        or json.dumps(media_status)[:200]
                    )
                    raise FlowAPIError(f"Video generation failed: {failure_reason}")

                if status_info in self._VIDEO_DONE_STATUSES:
                    completed_names.append(media_name)
                else:
                    all_done = False

            if all_done and completed_names:
                # All done — now fetch full media details to get fifeUrl
                assets = []
                for name in completed_names:
                    try:
                        media_detail = self.get_flow_media(name)
                        vid_data = (
                            media_detail.get("video", {})
                            .get("generatedVideo", {})
                        )
                        fife_url = vid_data.get("fifeUrl", "")

                        if self.debug:
                            logger.info("  Media %s fifeUrl: %s", name[:8],
                                        fife_url[:80] if fife_url else "NONE")

                        asset = Asset(
                            id=name,
                            name=f"video-{name[:8]}",
                            asset_type=AssetType.VIDEO,
                            url=fife_url,
                            raw=vid_data,
                        )
                        assets.append(asset)
                    except FlowAPIError as e:
                        logger.warning("Failed to get media detail for %s: %s", name, e)
                        # Still create an asset without URL — save_video will try redirect
                        asset = Asset(
                            id=name,
                            name=f"video-{name[:8]}",
                            asset_type=AssetType.VIDEO,
                            raw={},
                        )
                        assets.append(asset)

                return assets

            elapsed = int(time.time() - start)
            if self.debug:
                logger.info("Video still rendering... (%ds / %ds)", elapsed, timeout)

            time.sleep(poll_interval)

        raise FlowAPIError(f"Video generation timed out after {timeout}s")

    # ------------------------------------------------------------------
    # Media URL (get download link for generated content)
    # ------------------------------------------------------------------

    def get_media_url(self, media_name: str) -> str:
        """
        Get a signed download URL for a media item.

        GET labs.google/fx/api/trpc/media.getMediaUrlRedirect?name={uuid}
        """
        self._ensure_token()
        url = f"{LABS_BASE}/trpc/media.getMediaUrlRedirect"
        resp = self._labs_session.get(
            url, params={"name": media_name}, timeout=30, allow_redirects=False
        )

        # This endpoint typically redirects to GCS
        if resp.status_code in (301, 302, 307, 308):
            return resp.headers.get("Location", "")

        # Or returns JSON with the URL
        if resp.status_code == 200:
            data = resp.json()
            return (
                data.get("result", {})
                .get("data", {})
                .get("json", {})
                .get("url", "")
            ) or resp.url

        raise FlowAPIError(f"Failed to get media URL: {resp.status_code}")

    # ------------------------------------------------------------------
    # Download / Save
    # ------------------------------------------------------------------

    def save_image(self, asset: Asset, output_path: str | Path) -> Path:
        """Save a generated image to disk."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Try base64 data first
        encoded = asset.raw.get("encodedImage", "")
        if encoded:
            img_bytes = base64.b64decode(encoded)
            output_path.write_bytes(img_bytes)
            return output_path

        # Try fifeUrl (signed GCS URL from Flow response)
        fife_url = asset.raw.get("fifeUrl", "") or asset.url
        if fife_url:
            return self.download_asset(fife_url, output_path)

        # Try media URL redirect endpoint
        media_id = asset.raw.get("mediaGenerationId", "") or asset.id
        if media_id:
            try:
                url = self.get_media_url(media_id)
                if url:
                    return self.download_asset(url, output_path)
            except FlowAPIError:
                pass

        raise FlowAPIError(f"Asset {asset.id} has no downloadable content")

    def save_video(self, asset: Asset, output_path: str | Path) -> Path:
        """Save a generated video to disk."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Try fifeUrl (signed GCS URL from Flow response)
        fife_url = asset.raw.get("fifeUrl", "") or asset.url
        if fife_url:
            return self.download_asset(fife_url, output_path)

        # Try media URL redirect endpoint
        media_id = asset.raw.get("mediaGenerationId", "") or asset.id
        if media_id:
            try:
                url = self.get_media_url(media_id)
                if url:
                    return self.download_asset(url, output_path)
            except FlowAPIError:
                pass

        raise FlowAPIError(f"Video asset {asset.id} has no downloadable content")

    def download_asset(self, url: str, output_path: str | Path) -> Path:
        """Download content from a URL."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        resp = requests.get(url, stream=True, timeout=120)
        resp.raise_for_status()

        with open(output_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)

        return output_path

    # ------------------------------------------------------------------
    # Account Info
    # ------------------------------------------------------------------

    def get_user_info(self) -> dict:
        """Get current user info."""
        data = refresh_access_token(self.cookies, debug=self.debug)
        return data.get("user", {})

    # ------------------------------------------------------------------
    # Raw request (for discovery)
    # ------------------------------------------------------------------

    def raw_request(self, method: str, path: str, payload: dict | None = None) -> Any:
        """Make a raw API request for endpoint discovery."""
        self._ensure_token()

        if path.startswith("http"):
            url = path
        elif path.startswith("/"):
            url = f"{SANDBOX_BASE}{path}"
        else:
            url = f"{SANDBOX_BASE}/{path}"

        if "labs.google" in url:
            resp = self._labs_session.request(method, url, json=payload, timeout=30)
        else:
            resp = self._sandbox_request(method, url, json_payload=payload)

        return resp.json()

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    def _cdp_evaluate(self, ws, expression: str, timeout: int = 60) -> str | None:
        """Evaluate a JS expression inside Chrome via an open CDP WebSocket.

        Returns the string value, or None on failure.
        """
        msg_id = int(time.time() * 1000) % 1_000_000  # Unique-ish ID
        ws.send(json.dumps({
            "id": msg_id,
            "method": "Runtime.evaluate",
            "params": {
                "expression": expression,
                "awaitPromise": True,
                "returnByValue": True,
            }
        }))

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                ws.settimeout(10)
                raw = ws.recv()
                data = json.loads(raw)
                if data.get("id") == msg_id:
                    result = data.get("result", {}).get("result", {})
                    return result.get("value")
            except Exception:
                continue
        return None

    def _get_cdp_websocket(self):
        """Get a CDP WebSocket connection to a usable Chrome tab.

        Returns (websocket, port) tuple, or (None, None) if unavailable.
        """
        from gflow.auth.browser_auth import get_saved_cdp_port
        import websocket

        port = get_saved_cdp_port()
        if not port:
            return None, None

        tab_url = f"http://127.0.0.1:{port}/json/list"
        resp = urllib.request.urlopen(tab_url, timeout=5)
        targets = json.loads(resp.read().decode())

        ws_url = None
        # Prefer a tab on labs.google
        for target in targets:
            if target.get("type") == "page" and "labs.google" in target.get("url", ""):
                ws_url = target.get("webSocketDebuggerUrl", "")
                break
        # Fall back to any page tab
        if not ws_url:
            for target in targets:
                if target.get("type") == "page":
                    ws_url = target.get("webSocketDebuggerUrl", "")
                    break
        if not ws_url:
            return None, None

        ws = websocket.create_connection(ws_url, timeout=60)
        return ws, port

    def _get_token_via_cdp(self, ws) -> str | None:
        """Get a fresh access token by calling the session endpoint FROM WITHIN Chrome.

        This ensures the token is bound to Chrome's proxy exit IP, not Python's.
        Critical on VPS/proxy setups where the two IPs differ.

        Requires: tab must be on labs.google (call _ensure_cdp_on_flow_page first).
        """
        js_code = """
            fetch('https://labs.google/fx/api/auth/session', {
                method: 'GET',
                credentials: 'same-origin'
            })
            .then(r => r.json())
            .then(data => JSON.stringify(data))
            .catch(e => JSON.stringify({error: e.message}))
        """

        value = self._cdp_evaluate(ws, js_code, timeout=30)
        if not value or not isinstance(value, str):
            return None

        try:
            data = json.loads(value)
            if "error" in data and isinstance(data["error"], str):
                logger.warning("CDP session endpoint error: %s", data["error"])
                return None
            token = data.get("access_token", "")
            if token:
                if self.debug:
                    user = data.get("user", {})
                    logger.info("Got access token via CDP: %s... (user: %s)",
                                token[:20], user.get("email", "?"))
                return token
            return None
        except json.JSONDecodeError:
            return None

    def _ensure_cdp_on_flow_page(self, ws) -> bool:
        """Ensure the CDP tab is on labs.google/fx so fetch() has correct Origin.

        Browsers silently ignore custom Origin headers in fetch() — the Origin
        is always set from the current page. If the tab isn't on labs.google,
        same-origin requests to labs.google will fail and cross-origin requests
        to aisandbox-pa won't have the right Origin/Referer.

        Returns True if the tab is (or was navigated to) the Flow page.
        """
        current_url = self._cdp_evaluate(ws, "window.location.href", timeout=5)
        if current_url and "labs.google" in str(current_url):
            return True

        logger.info("CDP tab not on Flow page (url=%s), navigating...", current_url)
        nav_js = """
            new Promise((resolve) => {
                window.location.href = 'https://labs.google/fx/tools/flow';
                setTimeout(() => resolve('navigated'), 5000);
            })
        """
        self._cdp_evaluate(ws, nav_js, timeout=15)
        time.sleep(3)

        current_url = self._cdp_evaluate(ws, "window.location.href", timeout=5)
        if current_url and "labs.google" in str(current_url):
            logger.info("CDP tab now on: %s", current_url)
            return True

        logger.warning("CDP: could not navigate to Flow page (url=%s)", current_url)
        return False

    def _request_via_cdp(self, method: str, url: str, json_payload: dict | None = None) -> dict | None:
        """Execute an API request entirely through Chrome's browser context via CDP.

        Three-step process:
        1. Ensure the tab is on labs.google/fx (so Origin is correct)
        2. Get a fresh access token from the session endpoint INSIDE Chrome
           (so the token is bound to Chrome's proxy exit IP)
        3. Make the actual API request INSIDE Chrome with that token

        This ensures complete IP consistency: auth, token, and API request
        all go through Chrome's proxy extension → same exit IP.

        Returns parsed JSON response, or None if CDP is unavailable.
        """
        try:
            ws, port = self._get_cdp_websocket()
            if not ws:
                return None

            # Step 1: Ensure we're on the Flow page (correct Origin for fetch)
            if not self._ensure_cdp_on_flow_page(ws):
                ws.close()
                return None

            # Step 2: Get a fresh access token from WITHIN Chrome
            # (bound to Chrome's proxy IP, not Python's)
            cdp_token = self._get_token_via_cdp(ws)
            if not cdp_token:
                logger.warning("CDP: could not get access token from session endpoint")
                ws.close()
                return None

            logger.info("CDP: got fresh access token bound to Chrome's IP")

            # Step 3: Make the actual API request with Chrome-obtained token
            body_str = json.dumps(json_payload) if json_payload else ""
            body_escaped = body_str.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${")

            headers_obj = {
                "Content-Type": "text/plain;charset=UTF-8",
                "Authorization": f"Bearer {cdp_token}",
            }
            headers_json = json.dumps(headers_obj)

            js_code = f"""
                fetch('{url}', {{
                    method: '{method}',
                    headers: {headers_json},
                    body: `{body_escaped}`,
                    credentials: 'include'
                }})
                .then(async r => {{
                    const text = await r.text();
                    return JSON.stringify({{status: r.status, body: text}});
                }})
                .catch(e => JSON.stringify({{status: 0, body: '', error: e.message}}))
            """

            value = self._cdp_evaluate(ws, js_code, timeout=60)
            ws.close()

            if not value or not isinstance(value, str):
                return None

            try:
                wrapper = json.loads(value)
            except json.JSONDecodeError:
                logger.warning("CDP response not JSON: %s", str(value)[:200])
                return None

            status = wrapper.get("status", 0)
            body_str = wrapper.get("body", "")
            error = wrapper.get("error", "")

            if error:
                logger.warning("CDP fetch error: %s", error)
                return None

            if status != 200:
                logger.warning("CDP sandbox request returned HTTP %d: %s", status, body_str[:300])
                return None

            try:
                return json.loads(body_str)
            except json.JSONDecodeError:
                logger.warning("CDP response body not JSON: %s", body_str[:200])
                return None

        except Exception as e:
            logger.warning("CDP request failed: %s", e)
            return None

    def _sandbox_request(self, method: str, url: str, json_payload: dict | None = None) -> requests.Response:
        """Make an authenticated request to aisandbox-pa.googleapis.com.

        On proxy setups, falls back to Chrome CDP routing when direct HTTP
        gets 401 (IP mismatch between Python requests and Chrome's proxy).
        """
        import time as _time

        if self.debug:
            logger.info("%s %s", method, url)

        # aisandbox-pa uses text/plain;charset=UTF-8 with JSON body
        kwargs: dict[str, Any] = {"timeout": 120}
        if json_payload is not None:
            kwargs["data"] = json.dumps(json_payload)

        # Retry on transient connection errors (ConnectionResetError, etc.)
        max_retries = 3
        resp = None
        for attempt in range(max_retries):
            try:
                resp = self._sandbox_session.request(method, url, **kwargs)
                break
            except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError,
                    requests.exceptions.ProxyError) as e:
                if attempt < max_retries - 1:
                    wait = 5 * (attempt + 1)
                    logger.warning("Connection error on %s %s (attempt %d/%d), retrying in %ds: %s", method, url, attempt + 1, max_retries, wait, e)
                    self._rotate_proxy()  # Try next proxy on connection failure
                    _time.sleep(wait)
                else:
                    raise

        if resp.status_code == 401:
            if self.debug:
                logger.info("Got 401, refreshing token...")
            self._refresh_token()
            # Also try rotating proxy on 401 — datacenter IPs get blocked
            if self._proxies:
                self._rotate_proxy()
            resp = self._sandbox_session.request(method, url, **kwargs)

        # If still 401 and we have a proxy setup, the issue is likely IP mismatch:
        # Python requests exits through a different proxy IP than Chrome.
        # Route through Chrome CDP instead (same IP as auth session).
        if resp.status_code == 401 and self._proxies:
            logger.info("Direct HTTP still 401 with proxies — trying via Chrome CDP (same IP as auth)...")
            cdp_result = self._request_via_cdp(method, url, json_payload)
            if cdp_result is not None:
                logger.info("CDP sandbox request succeeded — proxy IP mismatch confirmed")
                # Wrap in a fake Response so callers can use .json() / .status_code
                fake_resp = requests.Response()
                fake_resp.status_code = 200
                fake_resp._content = json.dumps(cdp_result).encode("utf-8")
                fake_resp.encoding = "utf-8"
                return fake_resp

        if resp.status_code == 401:
            raise FlowAPIError("Auth expired. Run: gflow auth --clear\nthen: gflow auth")
        if resp.status_code == 403:
            resp_text = resp.text[:500]
            # reCAPTCHA failures are retryable — score can vary between evaluations
            if "recaptcha" in resp_text.lower() or "reCAPTCHA" in resp_text:
                raise FlowRecaptchaError(
                    f"Permission denied (403): {resp_text}"
                )
            raise FlowAPIError(
                f"Permission denied (403): {resp_text}"
            )
        if resp.status_code >= 400:
            raise FlowAPIError(f"API error {resp.status_code}: {resp.text[:500]}")

        return resp

    # ------------------------------------------------------------------
    # Response Parsers
    # ------------------------------------------------------------------

    def _parse_image_response(self, data: dict, prompt: str) -> list[Asset]:
        """Parse flowMedia:batchGenerateImages response.

        Real response format:
        {
          "media": [{
            "name": "uuid",
            "image": {
              "generatedImage": {
                "seed": 12345,
                "mediaGenerationId": "...",
                "prompt": "...",
                "modelNameType": "NARWHAL",
                "fifeUrl": "https://storage.googleapis.com/...",
                ...
              }
            }
          }]
        }
        """
        assets = []

        # Primary format: media[].image.generatedImage (real Flow response)
        for i, media_item in enumerate(data.get("media", [])):
            media_name = media_item.get("name", f"img-{i}")
            img_data = media_item.get("image", {}).get("generatedImage", {})
            if img_data:
                url = img_data.get("fifeUrl", "")
                asset = Asset(
                    id=img_data.get("mediaGenerationId", media_name),
                    name=media_name,
                    asset_type=AssetType.IMAGE,
                    url=url,
                    prompt=img_data.get("prompt", prompt),
                    model=img_data.get("modelNameType", IMAGE_MODEL),
                    raw=img_data,
                )
                assets.append(asset)

        # Fallback: responses[].generatedImages[] (older format)
        if not assets:
            for resp_item in data.get("responses", data.get("imagePanels", [])):
                images = resp_item.get("generatedImages", resp_item.get("images", []))
                for i, img in enumerate(images):
                    asset = Asset(
                        id=img.get("mediaGenerationId", img.get("name", f"img-{i}")),
                        name=f"image-{i}",
                        asset_type=AssetType.IMAGE,
                        prompt=img.get("prompt", prompt),
                        model=img.get("modelNameType", IMAGE_MODEL),
                        raw=img,
                    )
                    assets.append(asset)

        # Fallback: flat generatedImages[]
        if not assets:
            for i, img in enumerate(data.get("generatedImages", [])):
                asset = Asset(
                    id=img.get("mediaGenerationId", f"img-{i}"),
                    name=f"image-{i}",
                    asset_type=AssetType.IMAGE,
                    prompt=prompt,
                    model=IMAGE_MODEL,
                    raw=img,
                )
                assets.append(asset)

        if not assets and "error" in data:
            raise FlowAPIError(f"Image generation failed: {data['error']}")

        return assets

    def _parse_video_response(self, data: dict, prompt: str, batch_id: str = "") -> list[Asset]:
        """Parse batchAsyncGenerateVideoText response.

        Real response format:
        {
          "operations": [{
            "operation": {"name": "uuid"},
            "sceneId": "",
            "status": "MEDIA_GENERATION_STATUS_PENDING"
          }],
          "media": [{"name": "uuid", ...}],
          "workflows": [...]
        }
        """
        assets = []

        # Extract workflow ID and primaryMediaId from response (for extend continuity)
        workflow_id = ""
        workflows = data.get("workflows", [])
        if workflows and isinstance(workflows, list):
            wf = workflows[0]
            workflow_id = wf.get("id", "") or wf.get("workflowId", "")
            # Update primaryMediaId for chaining extends
            primary = wf.get("metadata", {}).get("primaryMediaId", "")
            if primary:
                self._primary_media_id = primary

        # Extract media names from media[] array (these are the actual resource IDs
        # needed for extend, as opposed to operation names which are for status polling)
        media_names = []
        for m in data.get("media", []):
            mname = m.get("name", "")
            if mname:
                media_names.append(mname)

        for i, op in enumerate(data.get("operations", [])):
            # Real format: operations[].operation.name
            op_inner = op.get("operation", {})
            op_name = op_inner.get("name", "") or op.get("name", op.get("operationName", ""))
            status = op.get("status", "")

            if op_name:
                raw = dict(op)
                if workflow_id:
                    raw["_workflow_id"] = workflow_id

                # The status-check endpoint needs the MEDIA name, not the
                # operation name.  For base video generation both are the same
                # UUID, but for extend they differ (operation is a hex hash,
                # media is a UUID).  Always prefer the media name as the
                # canonical ID used for polling and subsequent operations.
                asset_id = op_name  # fallback
                if i < len(media_names):
                    raw["_media_name"] = media_names[i]
                    self._op_to_media[op_name] = media_names[i]
                    asset_id = media_names[i]

                asset = Asset(
                    id=asset_id,
                    name=f"video-{asset_id[:8]}",
                    asset_type=AssetType.VIDEO,
                    prompt=prompt,
                    raw=raw,
                )
                assets.append(asset)

        if not assets and "error" in data:
            raise FlowAPIError(f"Video generation failed: {data['error']}")

        return assets

    def get_media_name_for_op(self, op_name: str) -> str:
        """Look up the actual media resource name for an operation name.

        The video generation response has both operations[] and media[] arrays
        with different UUIDs. Operations are for status polling; media names
        are the actual resource IDs needed for extend/download.
        """
        return self._op_to_media.get(op_name, op_name)

    def get_primary_media_id(self) -> str:
        """Return the primaryMediaId from the last workflow response.

        This is the ID the extend endpoint uses to locate the source video.
        It comes from workflows[].metadata.primaryMediaId in generation
        and extend responses, and is distinct from both the operation name
        and the media[].name.
        """
        return self._primary_media_id


    def close(self) -> None:
        """Clean up resources (headless browser, etc.)."""
        if getattr(self, '_recaptcha', None):
            self._recaptcha.close()
            self._recaptcha = None

    def __del__(self):
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class FlowAPIError(Exception):
    """Raised when a Flow API operation fails."""
    pass


class FlowRecaptchaError(FlowAPIError):
    """Raised when reCAPTCHA evaluation fails (403). Retryable with a fresh token."""
    pass
