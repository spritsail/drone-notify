import asyncio
from typing import Any

import aiohttp
import pytest
from http_message_signatures.algorithms import HMAC_SHA256

from drone_notify.http_signature import (
    HTTPSignature,
    KeyResolver,
    Signer,
    verify_signature,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            'keyId="foo",algorithm="hmac-sha256",signature="c2lnbmF0dXJl",headers="one two three"',
            HTTPSignature(
                keyid="foo",
                algorithm="hmac-sha256",
                signature=b"signature",
                headers=["one", "two", "three"],
            ),
        ),
        (
            'keyId="foo",algorithm="hmac-sha256",signature="c2lnbmF0dXJl"',
            ValueError({"headers"}),
        ),
    ],
)
def test_parse_http_signature(value: str, expected: HTTPSignature | Exception) -> None:
    if isinstance(expected, Exception):
        with pytest.raises(type(expected)) as exc:
            HTTPSignature.parse(value)
        assert type(exc.value) == type(expected) and exc.value.args == expected.args
    else:
        assert HTTPSignature.parse(value) == expected


async def handler(_: aiohttp.web.Request) -> aiohttp.web.Response:
    return aiohttp.web.Response(body=b"OK")


@pytest.mark.parametrize(
    "headers,signer,expected_status",
    [
        # Valid HTTP signature with all required components
        (
            {
                "Signature": (
                    'keyId="foo",algorithm="hmac-sha256",'
                    'signature="o8c0qNYaEw1e459ACtXZ2R/8WwQqfcjMUjlwpyp5HYg=",'
                    'headers="date digest"'
                ),
                "Digest": "blahblah",
                "Date": "Wed, 1 Jan 2020 12:00:00 UTC",
                "ignoreme": "this header is ignored",
            },
            Signer(KeyResolver({"foo": b"Ssstv1tPfr2ekmIcMIngEXC1sjTz0MV1"}), {HMAC_SHA256}),
            200,
        ),
        # Missing signature header
        (
            {
                "Date": "Wed, 1 Jan 2020 12:00:00 UTC",
                "Digest": "blahblah",
            },
            Signer(KeyResolver({"foo": b"Ssstv1tPfr2ekmIcMIngEXC1sjTz0MV1"}), {HMAC_SHA256}),
            401,
        ),
    ],
)
@pytest.mark.asyncio
async def test_verifier_middleware(
    headers: dict[str, str], signer: Signer, expected_status: int, aiohttp_client: Any
) -> None:
    app = aiohttp.web.Application()
    app.middlewares.append(verify_signature(signer))
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.get("/", headers=headers)
    assert resp.status == expected_status
