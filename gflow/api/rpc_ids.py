"""
RPC endpoint IDs for Google Flow.

These IDs are used in the BatchExecute protocol to identify which
server-side method to call. They must be discovered by inspecting
network traffic when using flow.google in a browser.

HOW TO DISCOVER THESE IDs:
1. Open flow.google in Chrome
2. Open DevTools > Network tab
3. Filter by "batchexecute"
4. Perform an action (e.g., generate an image)
5. Look at the request payload for the "rpcids" parameter
6. The value is the RPC ID for that action

The IDs below are PLACEHOLDERS. Replace them with the real values
you discover from network inspection. The format is typically
a short alphanumeric string like "xYz123" or "AbCdEf".

tmc/nlm uses the same approach — their RPC IDs were reverse-engineered
from NotebookLM's web traffic.
"""

# =============================================================
# IMPORTANT: These are PLACEHOLDER IDs.
# You MUST replace them with real IDs from network inspection.
# =============================================================

# --- Image Generation ---
GENERATE_IMAGE = "PLACEHOLDER_GENERATE_IMAGE"
# Generates images using Imagen 4

# --- Video Generation ---
GENERATE_VIDEO = "PLACEHOLDER_GENERATE_VIDEO"
# Generates videos using Veo 3.1

# --- Asset Management ---
LIST_ASSETS = "PLACEHOLDER_LIST_ASSETS"
# Lists all assets in the user's library

GET_ASSET = "PLACEHOLDER_GET_ASSET"
# Gets details for a single asset

DELETE_ASSET = "PLACEHOLDER_DELETE_ASSET"
# Deletes an asset

# --- Collections ---
LIST_COLLECTIONS = "PLACEHOLDER_LIST_COLLECTIONS"
CREATE_COLLECTION = "PLACEHOLDER_CREATE_COLLECTION"
ADD_TO_COLLECTION = "PLACEHOLDER_ADD_TO_COLLECTION"
REMOVE_FROM_COLLECTION = "PLACEHOLDER_REMOVE_FROM_COLLECTION"
DELETE_COLLECTION = "PLACEHOLDER_DELETE_COLLECTION"

# --- Editing ---
EDIT_IMAGE = "PLACEHOLDER_EDIT_IMAGE"
# Lasso tool / inpainting edits

EXTEND_VIDEO = "PLACEHOLDER_EXTEND_VIDEO"
# Extend a video clip

FRAMES_TO_VIDEO = "PLACEHOLDER_FRAMES_TO_VIDEO"
# Create video bridging two images

# --- Account ---
GET_ACCOUNT = "PLACEHOLDER_GET_ACCOUNT"
# Get account info and quota

# --- App Config ---
GET_APP_CONFIG = "PLACEHOLDER_GET_APP_CONFIG"
# Loaded during initial page load, contains feature flags and model info

# =============================================================
# Discovery helper
# =============================================================

# Mapping of friendly names to RPC IDs for CLI discovery mode
ALL_RPC_IDS = {
    "generate_image": GENERATE_IMAGE,
    "generate_video": GENERATE_VIDEO,
    "list_assets": LIST_ASSETS,
    "get_asset": GET_ASSET,
    "delete_asset": DELETE_ASSET,
    "list_collections": LIST_COLLECTIONS,
    "create_collection": CREATE_COLLECTION,
    "add_to_collection": ADD_TO_COLLECTION,
    "remove_from_collection": REMOVE_FROM_COLLECTION,
    "delete_collection": DELETE_COLLECTION,
    "edit_image": EDIT_IMAGE,
    "extend_video": EXTEND_VIDEO,
    "frames_to_video": FRAMES_TO_VIDEO,
    "get_account": GET_ACCOUNT,
    "get_app_config": GET_APP_CONFIG,
}


def is_placeholder(rpc_id: str) -> bool:
    """Check if an RPC ID is still a placeholder."""
    return rpc_id.startswith("PLACEHOLDER_")
