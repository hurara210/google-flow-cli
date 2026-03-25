"""
gflow CLI — Command-line interface to Google Flow.

Uses Google's Imagen 4 and Veo 3.1 via the reverse-engineered
aisandbox-pa.googleapis.com endpoints with cookie-based auth.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from gflow import __version__
from gflow.auth import BrowserAuth, AuthData, load_env, save_env, refresh_access_token, kill_auth_browser
from gflow.auth.browser_auth import clear_env, AuthError
from gflow.api.client import FlowClient, FlowAPIError
from gflow.api.models import (
    AssetType,
    ExtendVideoRequest,
    GenerateImageRequest,
    GenerateVideoRequest,
)

console = Console()
logger = logging.getLogger("gflow")


def _get_client(debug: bool = False) -> FlowClient:
    """Create an authenticated FlowClient."""
    auth = load_env()
    if not auth or not auth.is_valid:
        console.print("[red]Not authenticated. Run 'gflow auth' first.[/red]")
        sys.exit(1)

    return FlowClient(
        cookies=auth.cookies,
        debug=debug,
    )


# =============================================================
# Root CLI group
# =============================================================

@click.group()
@click.version_option(version=__version__, prog_name="gflow")
@click.option("--debug", is_flag=True, help="Enable debug output")
@click.pass_context
def cli(ctx: click.Context, debug: bool):
    """gflow - CLI for Google Flow (AI image & video generation)."""
    ctx.ensure_object(dict)
    ctx.obj["debug"] = debug

    if debug:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)


# =============================================================
# Auth
# =============================================================

@cli.command()
@click.option("--profile", default=None, help="Chrome profile directory")
@click.option("--clear", "do_clear", is_flag=True, help="Clear saved credentials")
@click.option("--status", "show_status", is_flag=True, help="Show auth status")
@click.pass_context
def auth(ctx: click.Context, profile, do_clear, show_status):
    """Authenticate with Google Flow via browser login."""
    debug = ctx.obj["debug"]

    if do_clear:
        clear_env()
        console.print("[green]Credentials cleared.[/green]")
        return

    if show_status:
        data = load_env()
        if data and data.is_valid:
            try:
                session = refresh_access_token(data.cookies, debug=debug)
                user = session.get("user", {})
                console.print(f"[green]Authenticated[/green] as {user.get('name', '?')} ({user.get('email', '?')})")
                console.print(f"Token: {session['access_token'][:25]}...")
                console.print(f"Expires: {session.get('expires', '?')}")
            except AuthError as e:
                console.print(f"[yellow]Cookies saved but session expired:[/yellow] {e}")
                console.print("Run 'gflow auth --clear && gflow auth' to re-authenticate.")
        else:
            console.print("[yellow]Not authenticated.[/yellow] Run 'gflow auth' to log in.")
        return

    browser_auth = BrowserAuth(debug=debug)
    try:
        data = browser_auth.get_auth(profile=profile, interactive=True)
        save_env(data)
        console.print("[green]Authentication successful![/green]")
        console.print("Credentials saved to ~/.gflow/env")
    except AuthError as e:
        console.print(f"[red]Authentication failed:[/red] {e}")
        sys.exit(1)


# =============================================================
# Close background Chrome
# =============================================================

@cli.command("close")
@click.pass_context
def close_browser(ctx):
    """Close the Chrome browser that was kept alive for reCAPTCHA.

    \b
    After 'gflow auth', Chrome stays open so that image/video generation
    can obtain reCAPTCHA tokens. Run this command when you're done.
    """
    kill_auth_browser()
    console.print("[green]Chrome session closed.[/green]")


# =============================================================
# Image generation
# =============================================================

@cli.command("generate-image")
@click.argument("prompt")
@click.option("--aspect-ratio", default="landscape",
              type=click.Choice(["square", "portrait", "landscape", "4:3", "1:1", "16:9", "9:16"]),
              help="Image aspect ratio")
@click.option("--seed", default=None, type=int, help="Random seed for reproducibility")
@click.option("--num", default=1, type=click.IntRange(1, 8), help="Number of images (1-8)")
@click.option("-o", "--output", default=None, help="Output file path (auto-named if omitted)")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def generate_image(ctx, prompt, aspect_ratio, seed, num, output, as_json):
    """Generate images from a text prompt using Imagen 4.

    \b
    Examples:
        gflow generate-image "a cat astronaut floating in space"
        gflow generate-image "sunset over mountains" --aspect-ratio landscape --num 4
        gflow generate-image "logo design" --aspect-ratio square -o logo.png
    """
    client = _get_client(ctx.obj["debug"])

    req = GenerateImageRequest(
        prompt=prompt,
        aspect_ratio=aspect_ratio,
        seed=seed,
        num_images=num,
    )

    try:
        console.print("[dim]Connecting to auth browser for reCAPTCHA...[/dim]")
        assets = client.generate_image(req)
    except FlowAPIError as e:
        console.print(f"[red]Error:[/red] {e}")
        client.close()
        sys.exit(1)

    if not assets:
        console.print("[yellow]No images generated.[/yellow]")
        client.close()
        sys.exit(1)

    # Save images to disk
    saved_files = []
    for i, asset in enumerate(assets):
        if output and len(assets) == 1:
            filepath = output
        elif output:
            p = Path(output)
            filepath = str(p.parent / f"{p.stem}-{i}{p.suffix}")
        else:
            filepath = f"gflow-image-{i}.png"

        try:
            path = client.save_image(asset, filepath)
            saved_files.append(str(path))
            console.print(f"[green]Saved:[/green] {path}")
        except FlowAPIError as e:
            console.print(f"[yellow]Could not save image {i}:[/yellow] {e}")

    client.close()

    if as_json:
        result = []
        for asset in assets:
            d = asset.model_dump()
            if "encodedImage" in d.get("raw", {}):
                enc = d["raw"]["encodedImage"]
                d["raw"]["encodedImage"] = f"<{len(enc)} chars base64>"
            result.append(d)
        click.echo(json.dumps({"images": result, "saved_files": saved_files}, indent=2))
    else:
        console.print(f"\n[bold]Generated {len(assets)} image(s)[/bold] for: {prompt}")


# =============================================================
# Video generation
# =============================================================

@cli.command("generate-video")
@click.argument("prompt")
@click.option("--aspect-ratio", default="landscape",
              type=click.Choice(["square", "portrait", "landscape", "16:9", "9:16", "1:1"]))
@click.option("--seed", default=None, type=int)
@click.option("--wait/--no-wait", default=True, help="Wait for video to finish rendering")
@click.option("--timeout", default=300, type=int, help="Max wait seconds (default: 300)")
@click.option("-o", "--output", default=None, help="Output file path")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def generate_video(ctx, prompt, aspect_ratio, seed, wait, timeout, output, as_json):
    """Generate a video from a text prompt using Veo 3.1.

    \b
    Video generation is async — it takes 1-3 minutes.
    By default, gflow will poll until the video is ready.

    \b
    Examples:
        gflow generate-video "a timelapse of a flower blooming"
        gflow generate-video "drone flyover of a city" --aspect-ratio landscape
        gflow generate-video "ocean waves" -o waves.mp4
        gflow generate-video "cat walking" --no-wait  # just submit, don't wait
    """
    client = _get_client(ctx.obj["debug"])

    req = GenerateVideoRequest(
        prompt=prompt,
        aspect_ratio=aspect_ratio,
        seed=seed,
    )

    try:
        with console.status("[bold green]Submitting video generation (Veo 3.1)..."):
            assets = client.generate_video(req)
    except FlowAPIError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if not assets:
        console.print("[yellow]No video operation returned.[/yellow]")
        sys.exit(1)

    # Get operation names for polling
    op_names = [a.id for a in assets if a.id]
    console.print(f"[bold]Video submitted.[/bold] Operations: {len(op_names)}")

    if wait and op_names:
        try:
            with console.status("[bold green]Rendering video (this takes 1-3 minutes)..."):
                final_assets = client.wait_for_video(op_names, timeout=timeout)
        except FlowAPIError as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)

        for i, asset in enumerate(final_assets):
            out = output or f"gflow-video-{i}.mp4"
            try:
                path = client.save_video(asset, out)
                console.print(f"[green]Saved:[/green] {path}")
            except Exception as e:
                console.print(f"[yellow]Download failed:[/yellow] {e}")
                if asset.url:
                    console.print(f"Video URL: {asset.url}")

        if as_json:
            click.echo(json.dumps([a.model_dump() for a in final_assets], indent=2, default=str))
        else:
            console.print(f"\n[bold]Video rendered[/bold] for: {prompt}")
    else:
        for op in op_names:
            console.print(f"  Operation: {op}")
        console.print("Run with --wait or use 'gflow wait <op-name>' to check status.")

        if as_json:
            click.echo(json.dumps([a.model_dump() for a in assets], indent=2, default=str))


# =============================================================
# Video extend
# =============================================================

@cli.command("extend-video")
@click.argument("media_id")
@click.argument("prompt")
@click.option("--aspect-ratio", default="landscape",
              type=click.Choice(["square", "portrait", "landscape", "16:9", "9:16", "1:1"]))
@click.option("--seed", default=None, type=int)
@click.option("--wait/--no-wait", default=True, help="Wait for video to finish rendering")
@click.option("--timeout", default=300, type=int, help="Max wait seconds (default: 300)")
@click.option("-o", "--output", default=None, help="Output file path")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def extend_video(ctx, media_id, prompt, aspect_ratio, seed, wait, timeout, output, as_json):
    """Extend an existing video with a continuation prompt.

    \b
    MEDIA_ID is the media name/ID of the video to extend.
    You can get it from generate-video --json output.

    \b
    Examples:
        gflow extend-video abc123-def456 "the cat jumps onto a couch"
        gflow extend-video abc123 "camera pans left" -o extended.mp4
    """
    client = _get_client(ctx.obj["debug"])

    req = ExtendVideoRequest(
        prompt=prompt,
        media_id=media_id,
        aspect_ratio=aspect_ratio,
        seed=seed,
    )

    try:
        with console.status("[bold green]Submitting video extend (Veo 3.1)..."):
            assets = client.extend_video(req)
    except FlowAPIError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if not assets:
        console.print("[yellow]No video operation returned.[/yellow]")
        sys.exit(1)

    op_names = [a.id for a in assets if a.id]
    console.print(f"[bold]Extend submitted.[/bold] Operations: {len(op_names)}")

    if wait and op_names:
        try:
            with console.status("[bold green]Rendering extended video (this takes 1-3 minutes)..."):
                final_assets = client.wait_for_video(op_names, timeout=timeout)
        except FlowAPIError as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)

        for i, asset in enumerate(final_assets):
            out = output or f"gflow-extend-{i}.mp4"
            try:
                path = client.save_video(asset, out)
                console.print(f"[green]Saved:[/green] {path}")
            except Exception as e:
                console.print(f"[yellow]Download failed:[/yellow] {e}")
                if asset.url:
                    console.print(f"Video URL: {asset.url}")

        if as_json:
            click.echo(json.dumps([a.model_dump() for a in final_assets], indent=2, default=str))
        else:
            console.print(f"\n[bold]Extended video rendered.[/bold]")
            # Print the new media ID for chaining
            for asset in final_assets:
                console.print(f"  New media ID: {asset.id}")
    else:
        for op in op_names:
            console.print(f"  Operation: {op}")

        if as_json:
            click.echo(json.dumps([a.model_dump() for a in assets], indent=2, default=str))


# =============================================================
# Long video (auto-extend loop)
# =============================================================

@cli.command("long-video")
@click.argument("prompt")
@click.option("--extend-prompt", "-e", multiple=True,
              help="Prompt(s) for each extension. Can specify multiple times. If fewer than --extensions, last prompt is reused.")
@click.option("--extensions", "-n", default=4, type=click.IntRange(1, 50),
              help="Number of times to extend (default: 4, each ~8s = ~40s total)")
@click.option("--aspect-ratio", default="landscape",
              type=click.Choice(["square", "portrait", "landscape", "16:9", "9:16", "1:1"]))
@click.option("--seed", default=None, type=int)
@click.option("--timeout", default=300, type=int, help="Max wait per segment (default: 300)")
@click.option("-o", "--output-dir", default=".", help="Output directory for segments")
@click.option("--prefix", default="gflow-long", help="Filename prefix for segments")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def long_video(ctx, prompt, extend_prompt, extensions, aspect_ratio, seed,
               timeout, output_dir, prefix, as_json):
    """Generate a long video by auto-extending multiple times.

    \b
    First generates a base video from PROMPT, then extends it
    N times (default 4). Each Veo 3.1 segment is ~8 seconds,
    so 4 extensions = ~40 seconds total.

    \b
    Use -e to specify different prompts for each extension,
    or leave blank to auto-continue with the original prompt.

    \b
    Examples:
        gflow long-video "a cat exploring a garden" -n 6
        gflow long-video "drone flying over city" -e "camera dives down" -e "flies through streets"
        gflow long-video "ocean waves" -n 10 -o ./my-video --prefix ocean
    """
    import time as _time

    client = _get_client(ctx.obj["debug"])
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_assets = []
    segment_paths = []

    # ---- Step 1: Generate base video ----
    console.print(f"\n[bold]Step 1/{extensions + 1}:[/bold] Generating base video...")

    req = GenerateVideoRequest(
        prompt=prompt,
        aspect_ratio=aspect_ratio,
        seed=seed,
    )

    try:
        with console.status("[bold green]Submitting base video..."):
            assets = client.generate_video(req)
    except FlowAPIError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if not assets:
        console.print("[red]No video operation returned.[/red]")
        sys.exit(1)

    op_names = [a.id for a in assets if a.id]
    try:
        with console.status("[bold green]Rendering base video (1-3 min)..."):
            final_assets = client.wait_for_video(op_names, timeout=timeout)
    except FlowAPIError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if not final_assets:
        console.print("[red]Base video failed.[/red]")
        sys.exit(1)

    base_asset = final_assets[0]
    all_assets.append(base_asset)

    # Save base segment
    seg_path = out_dir / f"{prefix}-seg0.mp4"
    try:
        path = client.save_video(base_asset, seg_path)
        segment_paths.append(path)
        console.print(f"  [green]Segment 0 saved:[/green] {path}")
    except Exception as e:
        console.print(f"  [yellow]Download failed:[/yellow] {e}")

    # Use primaryMediaId from workflow (this is what extend needs to find the source video)
    current_media_id = client.get_primary_media_id() or client.get_media_name_for_op(base_asset.id)
    workflow_id = client._workflow_id or ""
    console.print(f"  Media ID (primaryMedia): {current_media_id}")

    # Finalize the workflow (PATCH displayName) — the Flow UI does this
    # after every generation and it may be needed for extend to find the media
    if workflow_id:
        prompt_short = prompt[:30].replace('"', '')
        client.update_workflow(workflow_id, display_name=prompt_short)

    # ---- Step 2+: Extend loop ----
    for i in range(extensions):
        step = i + 2
        console.print(f"\n[bold]Step {step}/{extensions + 1}:[/bold] Extending video (segment {i + 1})...")

        # Pick the extend prompt
        if extend_prompt and i < len(extend_prompt):
            ext_prompt = extend_prompt[i]
        elif extend_prompt:
            ext_prompt = extend_prompt[-1]  # Reuse last prompt
        else:
            ext_prompt = prompt  # Reuse original prompt

        ext_req = ExtendVideoRequest(
            prompt=ext_prompt,
            media_id=current_media_id,
            aspect_ratio=aspect_ratio,
            workflow_id=workflow_id,
            seed=(seed + i + 1) if seed is not None else None,
        )

        # Retry extend up to 3 times (reCAPTCHA can fail intermittently)
        ext_assets = None
        for attempt in range(3):
            try:
                if attempt > 0:
                    console.print(f"  [yellow]Retry {attempt}/2 after {5 * attempt}s...[/yellow]")
                    _time.sleep(5 * attempt)
                with console.status(f"[bold green]Submitting extend ({ext_prompt[:40]})..."):
                    ext_assets = client.extend_video(ext_req)
                break  # success
            except FlowAPIError as e:
                err_str = str(e)
                if "reCAPTCHA" in err_str and attempt < 2:
                    continue  # retry reCAPTCHA failures
                elif "generation failed" in err_str.lower() and attempt < 2:
                    continue  # retry transient generation failures
                console.print(f"[red]Error on extension {i + 1}:[/red] {e}")
                ext_assets = None
                break

        if ext_assets is None:
            break

        if not ext_assets:
            console.print(f"[yellow]No operation returned for extension {i + 1}.[/yellow]")
            break

        ext_op_names = [a.id for a in ext_assets if a.id]
        try:
            with console.status(f"[bold green]Rendering segment {i + 1} (1-3 min)..."):
                ext_final = client.wait_for_video(ext_op_names, timeout=timeout)
        except FlowAPIError as e:
            console.print(f"[red]Error rendering extension {i + 1}:[/red] {e}")
            break

        if not ext_final:
            console.print(f"[yellow]Extension {i + 1} returned no assets.[/yellow]")
            break

        ext_asset = ext_final[0]
        all_assets.append(ext_asset)

        # Save segment
        seg_path = out_dir / f"{prefix}-seg{i + 1}.mp4"
        try:
            path = client.save_video(ext_asset, seg_path)
            segment_paths.append(path)
            console.print(f"  [green]Segment {i + 1} saved:[/green] {path}")
        except Exception as e:
            console.print(f"  [yellow]Download failed:[/yellow] {e}")

        # After extend completes, the new media name becomes the primaryMediaId
        # for the next extend.  The Flow UI PATCHes the workflow to register this.
        new_media_name = client.get_media_name_for_op(ext_asset.id) or ext_asset.id
        if client._workflow_id:
            workflow_id = client._workflow_id
        # PATCH workflow to update primaryMediaId (required for chaining extends)
        if workflow_id and new_media_name:
            client.update_workflow(workflow_id, primary_media_id=new_media_name)
        # Now read back the current primaryMediaId for next iteration
        current_media_id = new_media_name
        console.print(f"  Media ID (primaryMedia): {current_media_id}")

    # ---- Summary ----
    console.print(f"\n[bold green]Done![/bold green] Generated {len(all_assets)} segments.")
    for p in segment_paths:
        console.print(f"  {p}")

    if as_json:
        click.echo(json.dumps([a.model_dump() for a in all_assets], indent=2, default=str))


# =============================================================
# Caption (image-to-text)
# =============================================================

@cli.command("caption")
@click.argument("image_path", type=click.Path(exists=True))
@click.option("--count", default=1, type=click.IntRange(1, 5), help="Number of captions to generate")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def caption_image(ctx, image_path, count, as_json):
    """Generate a caption/description from an image file.

    \b
    Examples:
        gflow caption photo.png
        gflow caption my-image.jpg --count 3
    """
    client = _get_client(ctx.obj["debug"])

    try:
        with console.status("[bold green]Generating caption..."):
            captions = client.caption_image(image_path, count=count)
    except FlowAPIError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if as_json:
        click.echo(json.dumps({"captions": captions}, indent=2))
    else:
        for i, cap in enumerate(captions):
            console.print(f"[bold]Caption {i+1}:[/bold] {cap}")


# =============================================================
# Fetch media by ID
# =============================================================

@cli.command("fetch")
@click.argument("media_id")
@click.option("-o", "--output", default=None, help="Save to file")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def fetch_media(ctx, media_id, output, as_json):
    """Fetch a previously generated image/video by its media ID.

    \b
    Example:
        gflow fetch <media-id> -o fetched-image.png
    """
    client = _get_client(ctx.obj["debug"])

    try:
        asset = client.fetch_media(media_id)
    except FlowAPIError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if output and asset.raw.get("encodedImage"):
        import base64
        img_bytes = base64.b64decode(asset.raw["encodedImage"])
        Path(output).write_bytes(img_bytes)
        console.print(f"[green]Saved:[/green] {output}")
    elif output and asset.url:
        path = client.download_asset(asset.url, output)
        console.print(f"[green]Saved:[/green] {path}")

    if as_json:
        d = asset.model_dump()
        if "encodedImage" in d.get("raw", {}):
            d["raw"]["encodedImage"] = f"<{len(d['raw']['encodedImage'])} chars>"
        click.echo(json.dumps(d, indent=2, default=str))
    else:
        console.print(f"[bold]Media:[/bold] {asset.id}")
        console.print(f"  Type: {asset.asset_type.value}")
        console.print(f"  Prompt: {asset.prompt}")
        console.print(f"  Model: {asset.model}")


# =============================================================
# User info
# =============================================================

@cli.command("whoami")
@click.pass_context
def whoami(ctx):
    """Show the currently authenticated user."""
    client = _get_client(ctx.obj["debug"])

    try:
        user = client.get_user_info()
    except (FlowAPIError, AuthError) as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    console.print(f"[bold]{user.get('name', 'Unknown')}[/bold]")
    console.print(f"  Email: {user.get('email', '?')}")
    if user.get("image"):
        console.print(f"  Avatar: {user['image']}")


# =============================================================
# Raw request (discovery mode)
# =============================================================

@cli.command("raw")
@click.argument("method", type=click.Choice(["GET", "POST"], case_sensitive=False))
@click.argument("path")
@click.option("--data", "payload", default=None, help="JSON payload for POST")
@click.pass_context
def raw_request(ctx, method, path, payload):
    """Make a raw API request (for endpoint discovery).

    \b
    Examples:
        gflow raw GET https://labs.google/fx/api/auth/session
        gflow raw POST /v1:runImageFx --data '{"userInput":{"prompts":["test"]}}'
    """
    client = _get_client(ctx.obj["debug"])

    parsed_payload = None
    if payload:
        try:
            parsed_payload = json.loads(payload)
        except json.JSONDecodeError as e:
            console.print(f"[red]Invalid JSON:[/red] {e}")
            sys.exit(1)

    try:
        result = client.raw_request(method.upper(), path, parsed_payload)
        click.echo(json.dumps(result, indent=2, default=str))
    except FlowAPIError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


# =============================================================
# Network sniffer (discover what APIs Flow actually uses)
# =============================================================

@cli.command("sniff")
@click.option("--duration", default=120, type=int, help="How many seconds to capture (default: 120)")
@click.option("-o", "--output", default="gflow-network-capture.json", help="Output file for captured requests")
@click.pass_context
def sniff_network(ctx, duration, output):
    """Sniff Flow's network traffic to discover real API endpoints.

    \b
    Opens Flow in a browser and captures all API requests while you
    interact with it. Generate an image or video in the browser, then
    come back here to see exactly what API calls Flow made.

    \b
    Steps:
        1. Run: gflow sniff
        2. In the browser, generate an image or video
        3. Wait for it to finish, then press Ctrl+C or let the timer expire
        4. Check the output file for captured API calls
    """
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
    from gflow.auth.browser_auth import ENV_DIR, FLOW_URL

    print()
    print("=" * 60)
    print("  Google Flow Network Sniffer")
    print("=" * 60)
    print()
    print("  A browser will open with Flow loaded.")
    print("  Perform any action (generate image, video, etc.)")
    print(f"  Network traffic will be captured for {duration}s.")
    print()
    print("  Press Ctrl+C to stop early.")
    print()

    chrome_options = Options()
    chrome_options.add_argument("--no-first-run")
    chrome_options.add_argument("--no-default-browser-check")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_experimental_option("useAutomationExtension", False)

    # Reuse the persistent profile (already logged in)
    profile_dir = str(ENV_DIR / "chrome-profile")
    chrome_options.add_argument(f"--user-data-dir={profile_dir}")

    # Enable performance logging for network capture
    chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})

    driver = None
    captured_requests = []

    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)

        # Enable CDP network domain
        driver.execute_cdp_cmd("Network.enable", {})

        driver.get(FLOW_URL)
        print("  Browser opened. Perform your actions now...")
        print()

        import time as _time
        start = _time.time()
        request_bodies = {}

        try:
            while _time.time() - start < duration:
                _time.sleep(2)

                try:
                    logs = driver.get_log("performance")
                except Exception:
                    logs = []

                for entry in logs:
                    try:
                        msg = json.loads(entry["message"])["message"]
                        method = msg.get("method", "")
                        params = msg.get("params", {})

                        if method == "Network.requestWillBeSent":
                            request = params.get("request", {})
                            url = request.get("url", "")
                            http_method = request.get("method", "")
                            headers = request.get("headers", {})
                            post_data = request.get("postData", "")
                            request_id = params.get("requestId", "")

                            if any(ext in url for ext in [".js", ".css", ".png", ".jpg", ".svg", ".woff", ".ico"]):
                                continue
                            if any(h in url for h in ["google-analytics", "doubleclick", "googletagmanager", "play.google.com/log"]):
                                continue

                            req_data = {
                                "requestId": request_id,
                                "method": http_method,
                                "url": url,
                                "headers": dict(headers),
                            }

                            if post_data:
                                req_data["postData"] = post_data
                                if "batchexecute" in url:
                                    req_data["type"] = "batchexecute"
                                elif "aisandbox" in url or "runImageFx" in url or "runVideoFx" in url:
                                    req_data["type"] = "ai_sandbox"
                                    try:
                                        req_data["payload"] = json.loads(post_data)
                                    except Exception:
                                        pass
                                elif "/api/" in url:
                                    req_data["type"] = "labs_api"
                                    try:
                                        req_data["payload"] = json.loads(post_data)
                                    except Exception:
                                        pass

                            if request_id:
                                request_bodies[request_id] = req_data

                            captured_requests.append(req_data)

                            if any(kw in url for kw in [
                                "batchexecute", "aisandbox", "runImageFx", "runVideoFx",
                                "googleapis", "/api/", "trpc",
                            ]):
                                elapsed = _time.time() - start
                                console.print(f"  [{elapsed:.0f}s] [cyan]{http_method}[/cyan] {url[:100]}")

                        elif method == "Network.responseReceived":
                            request_id = params.get("requestId", "")
                            response = params.get("response", {})
                            if request_id in request_bodies:
                                request_bodies[request_id]["response_status"] = response.get("status")

                    except (json.JSONDecodeError, KeyError):
                        continue

        except KeyboardInterrupt:
            print("\n  Stopped by user.")

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass

    # Filter interesting requests
    interesting = [r for r in captured_requests if any(
        kw in r.get("url", "") for kw in [
            "batchexecute", "aisandbox", "runImageFx", "runVideoFx",
            "googleapis.com/v", "/api/", "trpc", "labs.google/fx",
        ]
    )]

    output_data = {
        "total_requests": len(captured_requests),
        "interesting_requests": len(interesting),
        "interesting": interesting,
        "all_requests": captured_requests,
    }

    Path(output).write_text(json.dumps(output_data, indent=2, default=str))
    console.print(f"\n[green]Saved {len(captured_requests)} requests ({len(interesting)} interesting) to {output}[/green]")

    if interesting:
        print()
        table = Table(title="Interesting API Calls Found")
        table.add_column("Method", style="cyan", width=6)
        table.add_column("URL", style="white", max_width=80)
        table.add_column("Type", style="magenta")

        for r in interesting[:20]:
            table.add_row(
                r.get("method", "?"),
                r.get("url", "")[:80],
                r.get("type", ""),
            )
        console.print(table)
    else:
        console.print("[yellow]No interesting API calls captured.[/yellow]")


# =============================================================
# Entry point
# =============================================================

if __name__ == "__main__":
    cli()
