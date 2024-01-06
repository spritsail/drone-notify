#!/usr/bin/python3

# pylint: disable=missing-function-docstring
import asyncio
import configparser
import importlib.metadata
import ipaddress
import logging
import os
import socket
import sys
from . import http_signature
from html import escape
from typing import Any

import aiohttp
from aiohttp import web

log = logging.getLogger(__name__)

VERSION = importlib.metadata.version(__package__ or __name__)

DRONE_SECRET = os.environ.get('DRONE_SECRET')

VALID_BUILD_STATES = (
    "success",
    "failure",
    "error",
    "killed",
)

BUILD_STATUS_EMOJI = {
    "success": "✅",
    "failure": "❌",
    "error": "💢",
    "killed": "☠️",
    "running": "▶️",
    "skipped": "🚫",
    "pending": "⏳",
}


def format_duration(start: int | float, end: int | float) -> str:
    minutes, seconds = divmod((int(end) - int(start)), 60)
    datestr = f"{minutes:02}m{seconds:02}s"
    return datestr


async def send_telegram_msg(chatid: str, message: str) -> None:
    postdata = {
        "parse_mode": "html",
        "disable_web_page_preview": "true",
        "chat_id": chatid,
        "text": message,
    }

    async with aiohttp.ClientSession() as session:
        respbody: str | None = None
        try:
            async with session.post(
                f"https://api.telegram.org/bot{ttoken}/sendmessage",
                json=postdata,
                timeout=60,
            ) as resp:
                if not resp.ok:
                    respbody = await resp.text()
                resp.raise_for_status()
        except aiohttp.ClientResponseError:
            log.exception("Failed to send notification for %s: %s", postdata, respbody)


async def do_notify(build: dict[Any, Any]) -> None:
    if "[NOTIFY SKIP]" in build["build"]["message"] or "[SKIP NOTIFY]" in build["build"]["message"]:
        log.debug("Skipping build as flags set")
        return

    is_pr = ""
    if build["build"]["event"] == "pull_request":
        # This isn't pretty, but it works.
        is_pr = f"#{escape(build['build']['ref'].split('/')[2])} → "

    multi_stage = ""

    if "stages" in build["build"]:
        if len(build["build"]["stages"]) > 1:
            for stage in build["build"]["stages"]:
                multi_stage += "• {stage_name}     <b>{stage_state}</b> in {time} {emoji}\n".format(
                    stage_name=escape(stage["name"]),
                    stage_state=escape(stage["status"]),
                    time=format_duration(stage["started"], stage["stopped"]),
                    emoji=BUILD_STATUS_EMOJI.get(stage["status"], "❔"),
                )
            multi_stage += "\n"

    drone_link = "{}/{}/{}".format(
        build["system"]["link"], build["repo"]["slug"], build["build"]["number"]
    )

    try:
        commit_firstline, commit_rest = build["build"]["message"].split("\n", 1)
        commit_rest = "-----\n" + commit_rest.strip()
    except ValueError:
        commit_firstline = build["build"]["message"]
        commit_rest = ""

    notifytmpl = (
        "<b>{repo} [{PR}{branch}]</b> #{number}: <b>{status}</b> in {time}\n"
        + "<a href='{drone_link}'>{drone_link}</a>\n"
        + "{multi_stage}<a href='{git_link}'>#{commit:7.7}</a> ({committer}): "
        + "<i>{commit_firstline}</i>\n{commit_rest}"
    )

    notifymsg = notifytmpl.format(
        PR=is_pr,
        branch=escape(build["build"]["target"]),
        commit=escape(build["build"]["after"]),
        commit_firstline=escape(commit_firstline),
        commit_rest=escape(commit_rest),
        committer=escape(build["build"]["author_login"]),
        drone_link=escape(drone_link),
        git_link=escape(build["build"]["link"]),
        multi_stage=multi_stage,
        number=build["build"]["number"],
        repo=escape(build["repo"]["slug"]),
        status=escape(build["build"]["status"]).upper(),
        time=format_duration(build["build"]["started"], build["build"]["finished"]),
    )

    log.info(
        "Sending Telegram notification(s) for %s #%d",
        build["repo"]["slug"],
        build["build"]["number"],
    )

    tchat = config["channels"].get(build["repo"]["slug"], default_channel)

    senders = []
    # Send normal telegram notification
    senders.append(send_telegram_msg(tchat, notifymsg))

    # If theres a failure channel defined & the build has failed, notify that too
    if build["build"]["status"] != "success" and failure_channel is not None:
        senders.append(send_telegram_msg(failure_channel, notifymsg))

    await asyncio.gather(*senders)


async def hook(request: web.Request) -> web.Response:
    if not http_signature.is_request_valid(request, DRONE_SECRET):
        return web.HTTPUnauthorized()

    data = await request.json()
    log.debug("Received a post from %s: %s", request.remote, data)
    if data["event"] == "build":
        log.debug(
            "%s - Successfully parsed a webook for %s #%d (%s)",
            request.remote,
            data["repo"]["slug"],
            data["build"]["number"],
            data["build"]["status"],
        )

        if data["build"]["status"] in VALID_BUILD_STATES:
            await do_notify(data)
            log.debug("Returning %s to %s", data["build"]["status"], request.remote)
            return web.Response(body=data["build"]["status"])

    # Default to blackholing it. Om nom nom.
    log.debug("Not a valid build state, accepting & taking no action")
    return web.Response(body=b"accepted")


async def main() -> None:
    log.info("Started Drone Notify v%s. Default Notification Channel: %s", VERSION, default_channel)
    log.debug("Debug logging is enabled - prepare for logspam")

    host = ipaddress.ip_address(config["main"].get("host", "::"))
    port = int(config["main"].get("port", "5000"))
    hostport = ("[%s]:%d" if host.version == 6 else "%s:%d") % (host, port)
    log.info("Listening on %s", hostport)

    handler = web.Application()
    handler.add_routes([web.post("/hook", hook)])

    runner = web.AppRunner(handler)
    await runner.setup()

    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.bind((str(host), port))
    site = web.SockSite(runner, sock)
    await site.start()
    # I'm astounded that there doesn't seem to be a better way to wait than this?
    while True:
        await asyncio.sleep(1**63)


if __name__ == "__main__":
    # Configure stdout logging
    logging.basicConfig(
        level=logging.INFO,
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        format="[%(asctime)s] %(levelname)s - %(message)s",
        stream=sys.stdout,
    )

    # TODO: Add some sanity checks to make sure the file exists, is readable
    # and contains everything we need.
    cfg_path: str = sys.argv[1] if len(sys.argv) > 1 else "notify.conf"

    config = configparser.ConfigParser()
    config.read(cfg_path)

    ttoken = config["main"]["token"]
    default_channel = config["channels"]["default"]

    if config.has_option("main", "debug"):
        if config["main"].getboolean("debug"):
            log.setLevel(logging.DEBUG)

    # If a failure channel exists, assign it to a var
    failure_channel: str | None = None

    if config.has_option("channels", "failure"):
        failure_channel = config["channels"]["failure"]

    if not ttoken:
        log.error("Required variable `main.token' empty or unset")
        sys.exit(1)
    elif not default_channel:
        log.error("Required value `channels.default' empty or unset")
        sys.exit(1)

    asyncio.get_event_loop().run_until_complete(main())
