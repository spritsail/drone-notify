#!/usr/bin/python3

import requests
import base64
import hmac
import hashlib

url = "http://localhost:1337/hook"

def send_post_request(secret):
    signature = base64.b64encode(
        hmac.new(secret.encode(), digestmod=hashlib.sha256).digest()
    ).decode()

    headers = {
        "signature": ", ".join([
            'keyId="hmac-key"',
            'algorithm="hmac-sha256"',
            'signature="{}"'.format(signature),
            'headers="{}"'.format("")
        ])
    }

    data = {
        "event": "build",
        "build": {
            "status": "success",
            "number": 0,
            "event": "build",
            "started": False,
            "finished": True,
            "link": "https://test.com/",
            "author_login": "XXXX",
            "message": "XXX",
            "target": "prod",
            "after": "XXX",
        },
        "system": {
            "link": "https://drone.company.com"
        },
        "repo": {
            "slug": "/test",
        }
    }
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        print(f"Status Code: {response.status_code}")
        print("Response:", response.text)
        print("Request was successful.")
    except requests.exceptions.HTTPError as err:
        print(f"Error: {err}")
        print(f"Response Content: {response.text}")
    except Exception as err:
        print(f"An error occurred: {err}")

    return response.status_code

assert send_post_request('test') == 200, "Test request failed: Status is not OK"