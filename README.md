# gflow — CLI for Google Flow

A command-line interface to [Google Flow](https://flow.google) (AI image & video generation), built using the same reverse-engineering approach as [tmc/nlm](https://github.com/tmc/nlm) for NotebookLM.

Lets AI agents and scripts generate images/videos via Google Flow without the GUI.

## Architecture

```
┌────────────────────────────────────┐
│  CLI Layer (click)                 │  gflow/cli/main.py
│  generate-image, generate-video,   │
│  list, download, collections, raw  │
├────────────────────────────────────┤
│  API Client (FlowClient)          │  gflow/api/client.py
│  High-level ops, polling, parsing  │
├────────────────────────────────────┤
│  BatchExecute Protocol            │  gflow/batchexecute/client.py
│  RPC encoding, SAPISIDHASH,       │
│  chunked response decoding         │
├────────────────────────────────────┤
│  Browser Auth                     │  gflow/auth/browser_auth.py
│  Cookie extraction from Chrome,    │
│  Selenium interactive login        │
└────────────────────────────────────┘
```

This is the same layered architecture as `tmc/nlm`:
- **Auth** extracts Google cookies from your browser (browser_cookie3 or Selenium)
- **BatchExecute** encodes RPCs into Google's wire format and decodes responses
- **API Client** wraps BatchExecute with typed methods for each Flow feature
- **CLI** exposes everything as clean subcommands

## Install

```bash
pip install -e .
```

Or with optional Selenium support for interactive login:
```bash
pip install -e ".[dev]"
pip install selenium
```

## Quick Start

```bash
# 1. Authenticate (extracts cookies from your Chrome browser)
gflow auth

# 2. Generate an image
gflow generate-image "a cat astronaut floating in space"

# 3. Generate a video
gflow generate-video "a timelapse of a flower blooming"

# 4. List your assets
gflow list

# 5. Download an asset
gflow download <asset-id> -o output.png
```

## Setup: Discovering RPC IDs

Google Flow uses the same BatchExecute protocol as NotebookLM, but with different RPC endpoint IDs. You need to discover these by inspecting network traffic:

1. Open [flow.google](https://flow.google) in Chrome
2. Open DevTools → Network tab
3. Filter requests by `batchexecute`
4. Perform an action (e.g., generate an image)
5. In the request payload, find the `rpcids` parameter — that's the RPC ID
6. Update `gflow/api/rpc_ids.py` with the real ID

Check which IDs are configured:
```bash
gflow rpc-ids
```

Use raw mode to test discovered IDs:
```bash
gflow raw "xYz123" --args '["my prompt", "16:9"]'
```

## Commands

| Command | Description |
|---------|-------------|
| `gflow auth` | Authenticate with Google Flow |
| `gflow auth --status` | Check auth status |
| `gflow auth --clear` | Clear saved credentials |
| `gflow generate-image PROMPT` | Generate images (Imagen 4) |
| `gflow generate-video PROMPT` | Generate videos (Veo 3.1) |
| `gflow list` | List assets in your library |
| `gflow get ASSET_ID` | Get asset details |
| `gflow download ASSET_ID` | Download an asset |
| `gflow delete ASSET_ID` | Delete an asset |
| `gflow collections list` | List collections |
| `gflow collections create NAME` | Create a collection |
| `gflow collections add COL_ID ASSET_ID` | Add asset to collection |
| `gflow raw RPC_ID` | Execute raw RPC (discovery mode) |
| `gflow rpc-ids` | Show configured RPC IDs |

All commands support `--json` for machine-readable output (ideal for scripts/agents).

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GFLOW_AUTH_TOKEN` | Auth token (overrides saved credentials) |
| `GFLOW_COOKIES` | Cookie string (overrides saved credentials) |
| `GFLOW_CHROME_PATH` | Path to Chrome executable |
| `GFLOW_DEBUG` | Set to `true` for debug output |

## For AI Agents / Scripts

Every command supports `--json` output:

```bash
# Generate and get JSON response
gflow generate-image "a logo" --json | jq '.[0].url'

# List assets as JSON for processing
gflow list --type image --json | jq '.[].id'

# Pipeline: generate, wait, download
ASSET_ID=$(gflow generate-video "ocean waves" --json | jq -r '.[0].id')
gflow download "$ASSET_ID" -o waves.mp4
```

## How It Works (Same as tmc/nlm)

1. **Browser Auth**: Extracts Google cookies from Chrome/Brave/Edge profiles using `browser_cookie3`, then fetches the XSRF token from the Flow page HTML
2. **BatchExecute Protocol**: Encodes RPC calls into Google's `batchexecute` wire format — form-encoded POST with nested JSON arrays, SAPISIDHASH authorization header
3. **Response Decoding**: Parses Google's chunked response format (byte-count prefixed JSON chunks with `wrb.fr` markers and multi-layer JSON encoding)
4. **Retry Logic**: Exponential backoff for transient errors (429, 500, 502, 503, 504)

## Project Structure

```
gflow-py/
├── pyproject.toml              # Package config & dependencies
├── README.md
├── gflow/
│   ├── __init__.py
│   ├── auth/
│   │   ├── __init__.py
│   │   └── browser_auth.py     # Cookie extraction & Selenium login
│   ├── batchexecute/
│   │   ├── __init__.py
│   │   └── client.py           # Google BatchExecute protocol
│   ├── api/
│   │   ├── __init__.py
│   │   ├── client.py           # FlowClient (high-level API)
│   │   ├── models.py           # Pydantic models (Asset, Collection, etc.)
│   │   └── rpc_ids.py          # RPC endpoint IDs (fill these in!)
│   └── cli/
│       ├── __init__.py
│       └── main.py             # Click CLI commands
└── tests/
    ├── __init__.py
    └── test_batchexecute.py    # Unit tests
```

## License

MIT
