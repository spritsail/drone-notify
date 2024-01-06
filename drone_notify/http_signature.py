import re
import hmac
import hashlib
import os
import base64
from aiohttp import web

# Implementation based on suggestion by drone
#
# https://docs.drone.io/extensions/secret/#authorization
# https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-10
#
# Since drone uses only hmac for encryption and we don't need RSA or anything
# else, this is a stripped down version of the specs. This basically covers
# only the essential verification of the hmac signature in the header.
# See section-3.1.3 of the specs for more details


def parse_headers_from_sig(sig: dict, req: web.Request) -> str:
    headers = []
    for name in sig['headers'].split():
        if name not in req.headers:
            raise web.HTTPBadRequest(reason=f"Header {name} not found in req")
        headers.append(f"{name}: {req.headers[name]}")
    return "\n".join(headers)


def parse_sig_from_request(req: web.Request) -> dict:
    regex = re.compile(r'(\w+)="([^"]*)"')
    parts = req.headers.get('signature', '').split(',')
    result = {}
    for entry in parts:
        matches = regex.match(entry.strip())
        if matches:
            result[matches.group(1)] = matches.group(2)
    return result


def calc_sig_str_from_request(key: str, req: web.Request) -> str:
    hash = hmac.new(key.encode(), digestmod=hashlib.sha256)
    sig = parse_sig_from_request(req)
    headers = parse_headers_from_sig(sig, req)
    hash.update(headers.encode())
    return base64.b64encode(hash.digest()).decode()


def is_request_valid(req: web.Request, secret: str) -> bool:
    computed_sig = calc_sig_str_from_request(secret, req).encode()
    request_sig = parse_sig_from_request(req).get('signature', '').encode()
    return hmac.compare_digest(request_sig, computed_sig)