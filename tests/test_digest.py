import hashlib
from typing import Any

import aiohttp.web
import pytest
from multidict import MultiDict

import drone_notify.digest
from drone_notify.digest import DigestFunc, DigestVerifier


@pytest.mark.parametrize(
    "computed,algorithm,data,expected",
    [
        (
            b"\xff._\xd8\xc5\x8e\xd0\x95Zh9\t\x1eb\xd6\x18",
            hashlib.md5,
            (
                b"\xa7|\xaae=\xe7PZ\xd9w\x82\x89h\xee\x89-\xdb\xab\x84\xfaI\xaf\x07k\x85\xf2m\x88"
                b"\x8c\xa5\x7f\x98"
            ),
            True,
        ),
        (
            b"\x83H\xb4\x9c\x04\xa3(P\x9a\xf7\x916\xa4\xbf\x02\xb0\xdbb\xbf\xc1",
            hashlib.sha1,
            (
                b"\xf0\x8c+\x1c_\xab\x9aaV\xbe\xe3\xab\xfd\xae\xbel\xed\xfcI\xe2\xf1%\x85\x96p\xe2"
                b"\xaa\xfef\xab\x8b\x01"
            ),
            True,
        ),
        (
            (
                b"\xfaY0\x80\xd7o\xfe\xfd\xab\x98h\xb3\x91\x85\xae\x93\nvp\xf5:V\x87\xfe3\n\xe94"
                b"\x13_\x93\xa3"
            ),
            hashlib.sha256,
            (
                b"+\x9cmk\xa3\xb2\xa5M\x9a\xb8\x9e\x94\xdf\xb3Z\xdd\xa3\xbf\xd0\x0f\xae\xdaJ\xe2"
                b"\x8c~\xe0\xe2\xf4\n\xad\xae"
            ),
            True,
        ),
        (
            (
                b"\x1d\xaf\n\x98\x1c\xc4W\xe0]u\x8b|YV\x02\xf5\x92Y\xc3\xb0\xbf\x07\xc9\x97\x08e"
                b"\xe9RL\xac\xd4\xb0\xae\xd7\x12\xe58Q><\x95\x95\x9eB\x98\xd01\n+{^\xd6\x94\xb2"
                b"\xcb\xa8z\x9c\xac!:OV\xd1"
            ),
            hashlib.sha512,
            b"\xc4\xacw\xfb\xdeT\x11\xdcBH\x9d6f\x18\xb4\xe7\xc6\xf18^\xf8@Ko\x8d>\x16g\xd3\xc3f:",
            True,
        ),
    ],
)
def test_compare_digest(
    computed: bytes,
    algorithm: DigestFunc,
    data: bytes,
    expected: bool,
) -> None:
    assert drone_notify.digest.compare(computed, algorithm, data) == expected


LOREM_IPSUM = (
    b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut"
    b" labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco "
    b"laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in "
    b"voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat "
    b"cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
)
LOREM_IPSUM_DIGESTS = {
    "md5": "24m7XOq4f5wPzCqzbBicLA==",
    "sha1": "zTazcHWKJZs0hFCEpsw4Rzy5Xic=",
    "sha256": "LYwvbZeMohcStfbeNsnTH6jpak+l2P+LAYjfuefBcbs=",
    "sha512": (
        "i6dgysKcsrLOZoWOrRaRdAV6oSmMzVgVFObbbe4yhSgO5uOlTJMZBx3IFl/wYdd3gxANRJyTf/H7TNG7UWppuQ=="
    ),
}


async def handler(_: aiohttp.web.Request) -> aiohttp.web.Response:
    return aiohttp.web.Response(body=b"OK")


@pytest.mark.parametrize(
    "require,algorithms,body,headers,expected_status",
    [
        # Digests not required and not supplied. Middleware should let it through
        (
            False,
            None,
            (
                b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor "
                b"incididunt ut labore et dolore magna aliqua."
            ),
            [],
            200,
        ),
        # Single header test. Digest matches and should verify
        (
            True,
            None,
            LOREM_IPSUM,
            ["md5=" + LOREM_IPSUM_DIGESTS["md5"]],
            200,
        ),
        # Multiple valid digests in one header
        (
            True,
            {"sha256": hashlib.sha256},
            LOREM_IPSUM,
            ["md5=" + LOREM_IPSUM_DIGESTS["md5"] + ",sha256=" + LOREM_IPSUM_DIGESTS["sha256"]],
            200,
        ),
        # Digests required but not supplied
        (
            True,
            None,
            LOREM_IPSUM,
            [],
            401,
        ),
        # Digests not required but are incorrectly supplied. Middleware should block the request
        (
            False,
            None,
            LOREM_IPSUM,
            ["sha1=definitely invalid"],
            401,
        ),
        # Digests not required but are supplied without a value. Middleware should block the request
        (
            False,
            {"sha256": hashlib.sha256},
            LOREM_IPSUM,
            ["sha256"],
            401,
        ),
        # Multiple header test. Digest of all headers match and should verify
        (
            True,
            None,
            LOREM_IPSUM,
            [f"{algo}={digest}" for algo, digest in LOREM_IPSUM_DIGESTS.items()],
            200,
        ),
        # Multiple header test. Digest of second header matches and should verify (first is bogus)
        (
            True,
            None,
            LOREM_IPSUM,
            [
                "this=is=a=bogus=digest",
                "sha1=" + LOREM_IPSUM_DIGESTS["sha1"],
            ],
            200,
        ),
        # Multiple header test. First is valid but unsupported, second is supported but invalid
        (
            True,
            {"sha256": hashlib.sha256},
            LOREM_IPSUM,
            [
                "md5=" + LOREM_IPSUM_DIGESTS["md5"],
                "sha256=this is not a valid digest",
            ],
            401,
        ),
    ],
)
@pytest.mark.asyncio
async def test_verifier_middleware(
    require: bool,
    algorithms: dict[str, DigestFunc] | None,
    body: bytes | None,
    headers: list[str],
    expected_status: int,
    aiohttp_client: Any,
) -> None:
    verifier = DigestVerifier(require=require, supported_algorithms=algorithms)
    app = aiohttp.web.Application()
    app.middlewares.append(verifier.verify_digest_headers)
    app.router.add_route("GET", "/", handler)
    client = await aiohttp_client(app)
    resp = await client.get(
        "/",
        data=body,
        headers=MultiDict([("Digest", h) for h in headers]),
    )
    assert resp.status == expected_status
