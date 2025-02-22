"""
A module for veriying HTTP 'Signature' headers

Note: This module implements an earlier draft RFC instead of the final spec, as
that is what Drone implements:
https://docs.drone.io/extensions/secret/#authorization
https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12
"""

import base64
import logging
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, fields

import aiohttp.web
import http_sfv.dictionary
import http_sfv.util
from aiohttp.typedefs import Handler, Middleware
from aiohttp.web import HTTPUnauthorized, Request, StreamResponse
from http_message_signatures.algorithms import HMAC_SHA256  # type: ignore[attr-defined]
from http_message_signatures.signatures import (  # type: ignore[attr-defined]
    HTTPSignatureAlgorithm,
    HTTPSignatureKeyResolver,
)
from multidict import CIMultiDict

log = logging.getLogger(__name__)

# Required to parse keys with uppercase chars in, like `keyId`
# https://github.com/mnot/http_sfv/commit/0fede94081e2ba1beb443fb34de77d0b4ed2bb02
http_sfv.util.COMPAT = True

# Smallest set of headers that must be covered by the signature to consider the
# request authenticated.
REQUIRED_HEADERS = {"signature", "date", "digest"}


@dataclass
class HTTPSignature:
    """
    Represent (and parse) a HTTP Signature header into its constituent parts
    """

    keyid: str
    algorithm: str
    signature: bytes
    headers: list[str]

    def __init__(
        self,
        keyid: str,
        algorithm: str,
        signature: str | bytes,
        headers: str | list[str],
    ):
        self.keyid = keyid
        self.algorithm = algorithm
        self.signature = base64.b64decode(signature) if isinstance(signature, str) else signature
        self.headers = headers.split() if isinstance(headers, str) else headers

    @classmethod
    def parse(cls, header: str | bytes) -> "HTTPSignature":
        """
        Parses a 'Signature' header value and returns a representative
        HTTPSignature object
        """
        if isinstance(header, str):
            header = header.encode()

        sd = http_sfv.dictionary.Dictionary()
        sd.parse(header)

        if missing := set(map(lambda f: f.name, fields(cls))) - sd.keys():
            raise ValueError(missing)

        return HTTPSignature(**{k: v.value for k, v in sd.items()})

    def __iter__(self) -> Iterator[tuple[str, str | bytes | list[str]]]:
        yield "keyId", self.keyid
        yield "algorithm", self.algorithm
        yield "signature", self.signature
        yield "headers", self.headers

    def __str__(self) -> str:
        sig_b64 = base64.b64encode(self.signature).decode()
        header_str = " ".join(self.headers)
        return (
            f'keyId="{self.keyid}",algorithm="{self.algorithm}",'
            f'signature="{sig_b64}",headers="{header_str}"'
        )


class KeyResolver(HTTPSignatureKeyResolver):
    """
    KeyResolver is a simple key store that can handle both symmetric and
    asymmetric keys.
    Symmetric keys are stored as a single `bytes` value.
    Asymmetric keys are stored as a tuple of (public: bytes, private: bytes)
    """

    def __init__(self, keys: dict[str, bytes | tuple[bytes, bytes]]):
        self.keys = keys

    def resolve_public_key(self, key_id: str) -> bytes:
        key = self.keys[key_id]
        return key if isinstance(key, bytes) else key[0]

    def resolve_private_key(self, key_id: str) -> bytes:
        key = self.keys[key_id]
        return key if isinstance(key, bytes) else key[1]


class Signer:
    """
    Sign and verify HTTP header signatures
    """

    def __init__(
        self,
        key_resolver: HTTPSignatureKeyResolver,
        algorithms: set[type[HTTPSignatureAlgorithm]],
        required_headers: set[str] | None = None,
    ):
        self.key_resolver = key_resolver
        self.algorithms = algorithms
        self.required_headers = (
            REQUIRED_HEADERS if required_headers is None else set(map(str.lower, required_headers))
        )

    def _algorithm(self, algorithm_id: str) -> type[HTTPSignatureAlgorithm] | None:
        return next(
            (a for a in self.algorithms if algorithm_id == a.algorithm_id),
            None,
        )

    @classmethod
    def header_payload(cls, headers: Mapping[str, str]) -> bytes:
        """
        Generate the canonical header data form for signing and verifying
        """
        return "\n".join(f"{k.lower()}: {headers[k]}" for k in headers).encode()

    def sign(
        self,
        headers: dict[str, str],
        algorithm: str | type[HTTPSignatureAlgorithm],
        keyid: str | None = None,
    ) -> HTTPSignature:
        """
        Generate a HTTP signature header for a set of headers
        """
        if isinstance(algorithm, str):
            if (maybealgo := self._algorithm(algorithm)) is None:
                raise KeyError(algorithm)
            algorithm = maybealgo

        if keyid is None:
            raise ValueError("keyid is None but required to sign")
        key = self.key_resolver.resolve_private_key(keyid)
        signer = algorithm(private_key=key)

        sig = signer.sign(self.header_payload(headers))
        return HTTPSignature(keyid, signer.algorithm_id, sig, list(headers.keys()))

    def verify(self, headers: Mapping[str, str]) -> bool:
        """
        Verify a HTTP header signature. Returns true if it is valid
        """
        if missing := self.required_headers - set(map(str.lower, headers)):
            log.debug("Missing required headers: %s", ", ".join(missing))
            return False

        # Ensure we can access the header keys via their lowercase names
        headers = CIMultiDict(headers)
        try:
            signature = HTTPSignature.parse(headers["signature"])
        except (KeyError, ValueError) as exc:
            log.debug("Invalid signature header: %s", headers["signature"], exc_info=exc)
            return False

        try:
            key = self.key_resolver.resolve_public_key(signature.keyid)
            if not key:
                log.debug("Signed with unresolvable key: %s", signature.keyid)
        except Exception as exc:  # pylint: disable=broad-except
            key = None
            log.debug("Signed with unresolvable key: %s", signature.keyid, exc_info=exc)

        if not key:
            return False

        # Find the algorithm constructor as specified in the Signature header
        algorithm = next(
            (a for a in self.algorithms if signature.algorithm == a.algorithm_id),
            None,
        )
        if algorithm is None:
            log.debug("Invalid algorithm: %s", signature.algorithm)
            return False

        try:
            # Construct the verify payload in the order specified in the signature
            toverify = self.header_payload({k: headers[k] for k in signature.headers})
            verifier = algorithm(public_key=key)
            verifier.verify(signature=signature.signature, message=toverify)
        except Exception as exc:  # pylint: disable=broad-except
            log.debug("Failed to verify signature", exc_info=exc)
            return False

        return True


def verify_drone_signature(secret: bytes) -> Middleware:
    """
    Produce a aiohttp middleware to verify Drone HTTP header signatures
    """
    # Drone signs using hmac-sha256 with a key named 'hmac-key'
    signer = Signer(key_resolver=KeyResolver({"hmac-key": secret}), algorithms={HMAC_SHA256})
    return verify_signature(signer)


def verify_signature(signer: Signer) -> Middleware:
    """
    Produce a aiohttp middleware to verify HTTP header signatures
    """

    @aiohttp.web.middleware
    async def func(request: Request, handler: Handler) -> StreamResponse:
        if not signer.verify(request.headers):
            log.warning("Failed to verify request signature from %s", request.remote)
            return HTTPUnauthorized(reason="Invalid signature")

        return await handler(request)

    return func
