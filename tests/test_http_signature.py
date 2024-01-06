import sys
from pathlib import Path
from aiohttp import web, hdrs
from unittest import mock
from datetime import datetime
import hmac
import hashlib
import base64
import asyncio
import os

sys.path.append(str(Path(__file__).resolve().parent.parent))

from drone_notify import http_signature


def sig_header(signature: str, headers: str) -> str:
    values = [
        'keyId="hmac-key"',
        'algorithm="hmac-sha256"',
        'signature="{}"'.format(signature),
        'headers="{}"'.format(headers)
    ]

    return ', '.join(values)


async def test_request_validation():
    # Generate date and signature
    date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    secret = '48df35f0d73819a3c674404f';
    hash1 = 'XXXXXXX'.encode();
    hash2 = hmac.new(secret.encode(), digestmod=hashlib.sha256)
    hash2.update(f'date: {date}'.encode())

    hash_invalid_str = base64.b64encode(hash1).decode()
    hash_valid_str = base64.b64encode(hash2.digest()).decode()

    # create valid and invalid headers for the mocked request
    headers_valid = {
        'signature': sig_header(hash_valid_str, 'date'),
        'date': date
    }

    headers_invalid =  {
        'signature': sig_header(hash_invalid_str, 'date'),
        'date': date
    }

    # test a valid request against valid and invalid secrets
    with mock.patch('aiohttp.web.Request') as mock_request:
        mock_request.headers = headers_valid

        is_valid = http_signature.is_request_valid(mock_request, secret)
        is_valid_1 = http_signature.is_request_valid(mock_request, secret + '1')
        is_valid_2 = http_signature.is_request_valid(mock_request, 'XXXX')

        assert is_valid, "The secret is not valid, but it should be"
        assert not is_valid_1, "The secret matched, but shouldn't have"
        assert not is_valid_2, "The secret matched, but shouldn't have"

    # test an invalid request against a valid secret
    with mock.patch('aiohttp.web.Request') as mock_request:
        mock_request.headers = headers_invalid

        is_valid = http_signature.is_request_valid(mock_request, secret)

        assert not is_valid, "The secret matched, but shouldn't have"


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(test_request_validation())