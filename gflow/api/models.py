"""
Data models for Google Flow API.

These models represent the request/response structures for Flow's
image and video generation endpoints, based on the reverse-engineered
aisandbox-pa.googleapis.com API.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AssetType(str, Enum):
    """Type of generated asset."""
    IMAGE = "image"
    VIDEO = "video"
    UNKNOWN = "unknown"


class Asset(BaseModel):
    """A generated image or video asset from Google Flow."""
    id: str = ""
    name: str = ""
    asset_type: AssetType = AssetType.UNKNOWN
    prompt: str = ""
    url: str = ""  # CDN URL (for videos)
    width: int = 0
    height: int = 0
    duration_seconds: float = 0.0  # For videos
    model: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)  # Raw API response


class GenerateImageRequest(BaseModel):
    """Request to generate images using Imagen 4."""
    prompt: str
    aspect_ratio: str = "landscape"  # square, portrait, landscape, 4:3
    seed: int | None = None
    num_images: int = 1  # Number of images to generate (1-8)


class GenerateVideoRequest(BaseModel):
    """Request to generate a video using Veo 3.1."""
    prompt: str
    aspect_ratio: str = "landscape"
    duration: str = "short"  # "short", "medium", "long"
    seed: int | None = None


class ExtendVideoRequest(BaseModel):
    """Request to extend a video using Veo 3.1 extend.

    Takes an existing video's media ID and generates a continuation.
    """
    prompt: str  # Describe what happens next
    media_id: str  # Media ID of the video to extend
    aspect_ratio: str = "landscape"
    workflow_id: str = ""  # Flow workflow ID (optional, for project continuity)
    seed: int | None = None
