"""Tests for the BatchExecute protocol client."""

import json
import pytest

from gflow.batchexecute.client import (
    BatchExecuteClient,
    RPC,
    Response,
    _unwrap_json,
    _extract_sapisid,
    _generate_sapisidhash,
    ReqIDGenerator,
)


class TestReqIDGenerator:
    def test_generates_incrementing_ids(self):
        gen = ReqIDGenerator()
        id1 = int(gen.next())
        id2 = int(gen.next())
        assert id2 > id1
        assert id2 - id1 == 100_000

    def test_base_is_in_expected_range(self):
        gen = ReqIDGenerator()
        val = int(gen.next())
        assert 1_500_000_000 <= val <= 1_700_000_000


class TestExtractSAPISID:
    def test_extracts_sapisid(self):
        cookies = "SID=abc; HSID=def; SAPISID=my_sapisid_value; SSID=ghi"
        assert _extract_sapisid(cookies) == "my_sapisid_value"

    def test_returns_none_when_missing(self):
        cookies = "SID=abc; HSID=def"
        assert _extract_sapisid(cookies) is None

    def test_empty_cookies(self):
        assert _extract_sapisid("") is None


class TestGenerateSAPISIDHASH:
    def test_format(self):
        result = _generate_sapisidhash("test_sapisid", "https://flow.google")
        assert result.startswith("SAPISIDHASH ")
        parts = result.split(" ")[1].split("_")
        assert len(parts) == 2
        # First part is timestamp, second is hex hash
        assert parts[0].isdigit()
        assert all(c in "0123456789abcdef" for c in parts[1])


class TestUnwrapJSON:
    def test_plain_string(self):
        assert _unwrap_json("hello") == "hello"

    def test_json_array(self):
        result = _unwrap_json('[1, 2, 3]')
        assert result == [1, 2, 3]

    def test_json_object(self):
        result = _unwrap_json('{"key": "value"}')
        assert result == {"key": "value"}

    def test_double_encoded(self):
        inner = json.dumps([1, 2, 3])
        outer = json.dumps(inner)
        result = _unwrap_json(outer)
        assert result == [1, 2, 3]

    def test_non_json(self):
        result = _unwrap_json("not json at all")
        assert result == "not json at all"


class TestBuildRPCData:
    def test_basic_rpc(self):
        rpc = RPC(id="test123", args=["hello", 42])
        data = BatchExecuteClient._build_rpc_data(rpc)
        assert data[0] == "test123"
        assert json.loads(data[1]) == ["hello", 42]
        assert data[2] is None
        assert data[3] == "generic"


class TestDecodeResponse:
    def _make_client(self):
        return BatchExecuteClient(
            host="test.example.com",
            app="TestApp",
            auth_token="token",
            cookies="",
        )

    def test_chunked_response(self):
        # Simulate a chunked batchexecute response
        chunk_data = json.dumps([
            ["wrb.fr", "rpc123", '["result_data"]', None, None, None, "generic"]
        ])
        prefix = ")]}\'"
        raw = "{}\n\n{}\n{}".format(prefix, len(chunk_data), chunk_data)

        client = self._make_client()
        responses = client._decode_response(raw)

        assert len(responses) == 1
        assert responses[0].id == "rpc123"

    def test_empty_response_raises(self):
        client = self._make_client()
        with pytest.raises(Exception):
            client._decode_response(")]}'")
