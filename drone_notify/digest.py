"""
A module for verifying HTTP 'Digest' header(s)
"""

import base64
import binascii
import functools
import hashlib
import logging
from collections.abc import Callable
from typing import Union

import aiohttp.web
from aiohttp.typedefs import Handler
from aiohttp.web import HTTPUnauthorized, Request, StreamResponse

log = logging.getLogger(__name__)

DigestFunc = Callable[[bytes], Union[bytes, "hashlib._Hash"]]

# https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-digest-headers#name-establish-the-hash-algorith
# Permitted digest algorithms values include: sha-256 and sha-512, id-sha-256, id-sha-512
# Deprecated algorithms values include: md5, sha, unixsum, unixcksum, adler32, crc32c.
DIGEST_ALGORITHMS: dict[str, DigestFunc] = {
    "sha256": hashlib.sha256,
    "sha-256": hashlib.sha256,
    "sha512": hashlib.sha512,
    "sha-512": hashlib.sha512,
    # Deprecated
    "md5": hashlib.md5,
    "sha": hashlib.sha1,
    "sha1": hashlib.sha1,
}


def compare(value: bytes, algorithm: DigestFunc, tohash: bytes) -> bool:
    """
    Verify a digest by computing and comparing against the input data
    """
    hashed = algorithm(tohash)
    if not isinstance(hashed, bytes):
        hashed = hashed.digest()

    return value == hashed


@aiohttp.web.middleware
class DigestVerifier:
    """
    HTTP 'Digest' verification module with aiohttp middleware
    """

    def __init__(
        self,
        require: bool,
        supported_algorithms: dict[str, DigestFunc] | None = None,
    ):
        self.require = require
        self.algos = supported_algorithms if supported_algorithms is not None else DIGEST_ALGORITHMS

    async def __call__(self, request: Request, handler: Handler) -> StreamResponse:
        """
        aiohttp middleware to verify HTTP 'Digest' header(s)
        """
        verified_digests = 0
        if "digest" in request.headers:
            body = await request.read()

            # Split ["a=1,b=2", "c=3"] into ['a=1', 'b=2', 'c=3']
            digests: list[str] = functools.reduce(
                lambda l, h: l + h.split(","),
                request.headers.getall("digest"),
                [],
            )

            for digest in set(digests):
                try:
                    algo, val = digest.split("=", 1)
                except ValueError as exc:
                    log.debug("Digest header parse error", exc_info=exc)
                    # If somehow the caller sends `Digest: sha256` or some
                    # other supported algorithm, we should detect that and
                    # complain.
                    algo = digest
                    val = ""

                algo = algo.lower()
                if algo not in self.algos:
                    continue

                try:
                    decoded = base64.b64decode(val, validate=True)
                except binascii.Error:
                    # If decoding fails, we still try to verify in case it's an
                    # algorithm we support but the digest is just broken so we
                    # can reject the request
                    decoded = b""

                if not compare(decoded, self.algos[algo], body):
                    # Failed to verify
                    return HTTPUnauthorized(reason="Invalid digest")

                log.debug("Verified digest header: %s", digest)
                verified_digests += 1

        if self.require and verified_digests < 1:
            return HTTPUnauthorized(reason="Missing supported digest")

        return await handler(request)
