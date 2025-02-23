#!/usr/bin/python3

"""
drone-notify - A webhook and notification sidecar daemon for Harness Drone
Receives build webhook events from Drone and fires off notifications when
builds complete, with support for multi-stage builds and pull-requests
"""

import asyncio
import configparser
import html
import importlib.metadata
import ipaddress
import logging
import signal
import socket
import sys

import aiohttp
from aiohttp import web
from aiohttp.typedefs import Middleware

from drone_notify.digest import DigestVerifier
from drone_notify.drone import WebhookEvent, WebhookRequest
from drone_notify.http_signature import verify_drone_signature

log = logging.getLogger(__name__)

VERSION = importlib.metadata.version(__package__ or __name__)

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
    """
    Produce a formatted duration in the form 12m34s given a start and end time
    """
    minutes, seconds = divmod((int(end) - int(start)), 60)
    datestr = f"{minutes:02}m{seconds:02}s"
    return datestr


async def send_telegram_msg(chatid: str, message: str, parse_mode: str = "html") -> None:
    """
    Send a formatted message to a Telegram chat
    """
    postdata = {
        "parse_mode": parse_mode,
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
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                if not resp.ok:
                    respbody = await resp.text()
                resp.raise_for_status()
        except aiohttp.ClientResponseError:
            log.exception("Failed to send notification for %s: %s", postdata, respbody)


async def do_notify(event: WebhookRequest) -> None:
    """
    Generate a formatted notification message and send it
    """
    if event.build is None or event.repo is None or event.system is None:
        # Satisfy type checkers. We already checked these
        return

    if "[NOTIFY SKIP]" in event.build.message or "[SKIP NOTIFY]" in event.build.message:
        log.debug("Skipping build as flags set")
        return

    is_pr = ""
    if event.build.event == "pull_request":
        # This isn't pretty, but it works.
        is_pr = f"#{html.escape(event.build.ref.split('/', 3)[2])} → "

    multi_stage = ""

    if event.build.stages is not None and len(event.build.stages) > 1:
        for stage in event.build.stages:
            stage_name = html.escape(stage.name)
            stage_state = html.escape(stage.status)
            time = format_duration(stage.started, stage.stopped)
            emoji = BUILD_STATUS_EMOJI.get(stage.status, "❔")
            multi_stage += f"• {stage_name}     <b>{stage_state}</b> in {time} {emoji}\n"

        multi_stage += "\n"

    drone_link = f"{event.system.link}/{event.repo.slug}/{event.build.number}"

    try:
        commit_firstline, commit_rest = event.build.message.split("\n", 1)
        commit_rest = "-----\n" + commit_rest.strip()
    except ValueError:
        commit_firstline = event.build.message
        commit_rest = ""

    notifytmpl = (
        "<b>{repo} [{PR}{branch}]</b> #{number}: <b>{status}</b> in {time}\n"
        + "<a href='{drone_link}'>{drone_link}</a>\n"
        + "{multi_stage}<a href='{git_link}'>#{commit:7.7}</a> ({committer}): "
        + "<i>{commit_firstline}</i>\n{commit_rest}"
    )

    notifymsg = notifytmpl.format(
        PR=is_pr,
        branch=html.escape(event.build.target),
        commit=html.escape(event.build.after),
        commit_firstline=html.escape(commit_firstline),
        commit_rest=html.escape(commit_rest),
        committer=html.escape(event.build.author_login),
        drone_link=html.escape(drone_link),
        git_link=html.escape(event.build.link),
        multi_stage=multi_stage,
        number=event.build.number,
        repo=html.escape(event.repo.slug),
        status=html.escape(event.build.status).upper(),
        time=format_duration(event.build.started, event.build.finished),
    )

    log.info(
        "Sending Telegram notification(s) for %s #%d",
        event.repo.slug,
        event.build.number,
    )

    tchat = config["channels"].get(event.repo.slug, default_channel)

    senders = []
    # Send normal telegram notification
    senders.append(send_telegram_msg(tchat, notifymsg))

    # If theres a failure channel defined & the build has failed, notify that too
    if event.build.status != "success" and failure_channel is not None:
        senders.append(send_telegram_msg(failure_channel, notifymsg))

    await asyncio.gather(*senders)


async def hook(request: web.Request) -> web.StreamResponse:
    """
    Handle incoming webhooks from (hopefully) Drone
    """
    data = await request.json()
    log.debug("Received a webhook request from %s: %s", request.remote, data)
    event = WebhookRequest.from_dict(data)
    if event.event is WebhookEvent.BUILD:
        log.debug(
            "%s - Successfully parsed a webook for %s #%d (%s)",
            request.remote,
            event.repo.slug,
            event.build.number,
            event.build.status,
        )

        if event.build.status in VALID_BUILD_STATES:
            await do_notify(event)
            log.debug("Returning %s to %s", event.build.status, request.remote)
            return web.Response(body=event.build.status)

    # Default to blackholing it. Om nom nom.
    log.debug("Not a valid build state, accepting & taking no action")
    return web.Response(body=b"accepted")


async def startup() -> None:
    """
    drone-notify entrypoint
    """
    log.info("Started Drone Notify v%s. Default Notification Channel: %s", VERSION, default_channel)
    log.debug("Debug logging is enabled - prepare for logspam")

    host = ipaddress.ip_address(config["main"].get("host", "::"))
    port = int(config["main"].get("port", "5000"))
    hostport = ("[%s]:%d" if host.version == 6 else "%s:%d") % (host, port)

    middlewares: list[Middleware] = []

    if "secret" in config["main"]:
        log.debug("Enabled webhook signature verification")
        middlewares.append(verify_drone_signature(config["main"]["secret"].encode()))

    # Drone adds the `Digest:` header to all of it's requests
    middlewares.append(DigestVerifier(require=True).verify_digest_headers)

    handler = web.Application(middlewares=middlewares)
    handler.add_routes([web.post("/hook", hook)])

    runner = web.AppRunner(handler)
    await runner.setup()

    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.bind((str(host), port))
    site = web.SockSite(runner, sock)
    await site.start()
    log.info("Listening on %s", hostport)


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

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.add_signal_handler(signal.SIGTERM, loop.stop)
        loop.add_signal_handler(signal.SIGINT, loop.stop)
        loop.run_until_complete(startup())
        loop.run_forever()
    except KeyboardInterrupt:
        log.info("Caught ^C, stopping")
        loop.stop()
    except Exception as e:  # pylint: disable=broad-except
        log.exception("Caught exception, stopping: %s", e)
        loop.stop()
        sys.exit(1)
