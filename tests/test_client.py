"""Tests for the Flow API client."""

import json
from unittest.mock import patch, MagicMock

import pytest

from gflow.api.client import (
    FlowClient, FlowAPIError,
    IMAGE_ASPECT_MAP, VIDEO_ASPECT_MAP,
    IMAGE_MODEL, VIDEO_MODEL, TOOL_NAME,
)
from gflow.api.models import Asset, AssetType, GenerateImageRequest, GenerateVideoRequest


class TestConstants:
    """Test internal constants match what we discovered."""

    def test_image_model(self):
        assert IMAGE_MODEL == "NARWHAL"

    def test_video_model(self):
        assert VIDEO_MODEL == "veo_3_1_t2v_fast_ultra"

    def test_tool_name(self):
        assert TOOL_NAME == "PINHOLE"


class TestAspectRatioMapping:
    """Test the CLI-friendly aspect ratio mapping."""

    def test_image_square(self):
        assert IMAGE_ASPECT_MAP["square"] == "IMAGE_ASPECT_RATIO_SQUARE"
        assert IMAGE_ASPECT_MAP["1:1"] == "IMAGE_ASPECT_RATIO_SQUARE"

    def test_image_portrait(self):
        assert IMAGE_ASPECT_MAP["portrait"] == "IMAGE_ASPECT_RATIO_PORTRAIT"

    def test_image_landscape(self):
        assert IMAGE_ASPECT_MAP["landscape"] == "IMAGE_ASPECT_RATIO_LANDSCAPE"

    def test_video_landscape(self):
        assert VIDEO_ASPECT_MAP["landscape"] == "VIDEO_ASPECT_RATIO_LANDSCAPE"

    def test_video_portrait(self):
        assert VIDEO_ASPECT_MAP["portrait"] == "VIDEO_ASPECT_RATIO_PORTRAIT"


class TestParseImageResponse:
    """Test image response parsing."""

    def setup_method(self):
        self.client = FlowClient.__new__(FlowClient)
        self.client.debug = False

    def test_parses_responses_format(self):
        data = {
            "responses": [{
                "generatedImages": [
                    {
                        "encodedImage": "abc123base64",
                        "mediaGenerationId": "media-001",
                        "prompt": "a cat",
                        "modelNameType": "NARWHAL",
                    },
                ]
            }]
        }
        assets = self.client._parse_image_response(data, "a cat")
        assert len(assets) == 1
        assert assets[0].id == "media-001"
        assert assets[0].asset_type == AssetType.IMAGE
        assert assets[0].raw["encodedImage"] == "abc123base64"

    def test_parses_flat_format(self):
        data = {
            "generatedImages": [
                {"mediaGenerationId": "flat-001", "encodedImage": "xyz"},
            ]
        }
        assets = self.client._parse_image_response(data, "test")
        assert len(assets) == 1
        assert assets[0].id == "flat-001"

    def test_error_response(self):
        data = {"error": {"message": "bad prompt"}}
        with pytest.raises(FlowAPIError, match="Image generation failed"):
            self.client._parse_image_response(data, "test")


class TestParseVideoResponse:
    """Test video response parsing."""

    def setup_method(self):
        self.client = FlowClient.__new__(FlowClient)
        self.client.debug = False

    def test_parses_operations(self):
        data = {
            "operations": [
                {"name": "operations/video-abc123", "done": False},
            ]
        }
        assets = self.client._parse_video_response(data, "a sunset")
        assert len(assets) == 1
        assert assets[0].id == "operations/video-abc123"
        assert assets[0].asset_type == AssetType.VIDEO

    def test_error_response(self):
        data = {"error": {"message": "video failed"}}
        with pytest.raises(FlowAPIError, match="Video generation failed"):
            self.client._parse_video_response(data, "test")


class TestClientInit:
    """Test client initialization."""

    def test_creates_with_cookies(self):
        client = FlowClient(cookies="SID=abc; HSID=def")
        assert client.cookies == "SID=abc; HSID=def"
        assert client._access_token == ""
        assert client._project_id == ""

    def test_session_id_format(self):
        client = FlowClient(cookies="test")
        assert client._session_id.startswith(";")
        assert len(client._session_id) > 5


class TestImagePayload:
    """Test that generate_image builds correct payload."""

    @patch.object(FlowClient, '_get_recaptcha_token', return_value="fake-recaptcha-token")
    @patch.object(FlowClient, '_sandbox_request')
    @patch.object(FlowClient, '_ensure_project', return_value="proj-123")
    @patch.object(FlowClient, '_ensure_token')
    def test_payload_structure(self, mock_token, mock_proj, mock_request, mock_captcha):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"responses": [{"generatedImages": []}]}
        mock_request.return_value = mock_resp

        client = FlowClient(cookies="test")
        req = GenerateImageRequest(prompt="a cat in space", num_images=2, seed=42)
        client.generate_image(req)

        call_args = mock_request.call_args
        assert call_args[0][0] == "POST"
        assert "proj-123/flowMedia:batchGenerateImages" in call_args[0][1]

        payload = call_args[1]["json_payload"]
        assert payload["clientContext"]["projectId"] == "proj-123"
        assert payload["clientContext"]["tool"] == "PINHOLE"
        assert payload["clientContext"]["recaptchaContext"]["token"] == "fake-recaptcha-token"
        assert payload["useNewMedia"] is True
        assert len(payload["requests"]) == 2
        assert payload["requests"][0]["imageModelName"] == "NARWHAL"
        assert payload["requests"][0]["structuredPrompt"]["parts"][0]["text"] == "a cat in space"
        assert payload["requests"][0]["seed"] == 42
        assert payload["requests"][0]["imageAspectRatio"] == "IMAGE_ASPECT_RATIO_LANDSCAPE"
        assert payload["requests"][0]["imageInputs"] == []


class TestVideoPayload:
    """Test that generate_video builds correct payload."""

    @patch.object(FlowClient, '_get_recaptcha_token', return_value="fake-recaptcha-token")
    @patch.object(FlowClient, '_sandbox_request')
    @patch.object(FlowClient, '_ensure_project', return_value="proj-456")
    @patch.object(FlowClient, '_ensure_token')
    def test_payload_structure(self, mock_token, mock_proj, mock_request, mock_captcha):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"operations": [{"name": "op/1"}]}
        mock_request.return_value = mock_resp

        client = FlowClient(cookies="test")
        req = GenerateVideoRequest(prompt="a sunset", seed=100)
        client.generate_video(req)

        call_args = mock_request.call_args
        assert call_args[0][0] == "POST"
        assert "video:batchAsyncGenerateVideoText" in call_args[0][1]

        payload = call_args[1]["json_payload"]
        assert payload["clientContext"]["projectId"] == "proj-456"
        assert payload["clientContext"]["tool"] == "PINHOLE"
        assert payload["clientContext"]["recaptchaContext"]["token"] == "fake-recaptcha-token"
        assert payload["useV2ModelConfig"] is True
        assert len(payload["requests"]) == 1
        assert payload["requests"][0]["videoModelKey"] == "veo_3_1_t2v_fast_ultra"
        assert payload["requests"][0]["textInput"]["structuredPrompt"]["parts"][0]["text"] == "a sunset"
        assert payload["requests"][0]["aspectRatio"] == "VIDEO_ASPECT_RATIO_LANDSCAPE"
