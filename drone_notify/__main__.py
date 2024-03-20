#!/usr/bin/python3

"""
drone-notify - A webhook and notification sidecar daemon for Harness Drone
Receives build webhook events from Drone and fires off notifications when
builds complete, with support for multi-stage builds and pull-requests
"""

import asyncio
import functools
import importlib.metadata
import ipaddress
import logging
import os.path
import signal
import socket
import sys
from html import escape

import aiohttp
from aiohttp import web

from drone_notify.config import Config, load_toml_file
from drone_notify.digest import DigestVerifier
from drone_notify.drone import WebhookEvent, WebhookRequest
from drone_notify.http_signature import verify_drone_signature
from drone_notify.notify import repo_match
from drone_notify.types import Middleware

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


async def send_telegram_msg(
    bot_token: str, chatid: str, message: str, parse_mode: str = "html"
) -> None:
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
                f"https://api.telegram.org/bot{bot_token}/sendmessage",
                json=postdata,
                timeout=60,
            ) as resp:
                if not resp.ok:
                    respbody = await resp.text()
                resp.raise_for_status()
        except aiohttp.ClientResponseError:
            log.exception("Failed to send notification for %s: %s", postdata, respbody)


def generate_msg(event: WebhookRequest) -> str:
    """
    Generate a HTML formatted notification message from Webhook event data
    """
    is_pr = ""
    if event.build.event == "pull_request":
        # This isn't pretty, but it works.
        is_pr = f"#{escape(event.build.ref.split('/', 3)[2])} → "

    multi_stage = ""

    if event.build.stages is not None and len(event.build.stages) > 1:
        for stage in event.build.stages:
            stage_name = escape(stage.name)
            stage_state = escape(stage.status)
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

    return (
        "<b>{repo} [{is_pr}{branch}]</b> #{number}: <b>{status}</b> in {time}\n"
        + "<a href='{drone_link}'>{drone_link}</a>\n"
        + "{multi_stage}<a href='{git_link}'>#{commit:7.7}</a> ({committer}): "
        + "<i>{commit_firstline}</i>\n{commit_rest}"
    ).format(
        is_pr=is_pr,
        branch=escape(event.build.target),
        commit=escape(event.build.after),
        commit_firstline=escape(commit_firstline),
        commit_rest=escape(commit_rest),
        committer=escape(event.build.author_login),
        drone_link=escape(drone_link),
        git_link=escape(event.build.link),
        multi_stage=multi_stage,
        number=event.build.number,
        repo=escape(event.repo.slug),
        status=escape(event.build.status).upper(),
        time=format_duration(event.build.started, event.build.finished),
    )


async def do_notify(config: Config, event: WebhookRequest) -> None:
    """
    Dispatch notifications to all notifiers
    """
    if event.build is None or event.repo is None or event.system is None:
        # Satisfy type checkers. We already checked these
        return

    if "[NOTIFY SKIP]" in event.build.message or "[SKIP NOTIFY]" in event.build.message:
        log.debug("Skipping notification as commit message requested it")
        return

    message = generate_msg(event)

    senders = []
    for name, notif in config.notifier.items():
        if notif.status is not None and event.build.status not in notif.status:
            log.debug(
                "Notifier '%s' isn't used for builds with status %s", name, event.build.status
            )
            continue

        # Skip if notifier disallows repo
        if notif.repos is not None and not repo_match(name, event.repo.slug, notif.repos):
            continue

        # Elaborate hack to extract the bot token from the config
        bot_token = getattr(getattr(config, notif.kind), "bot")[notif.bot].bot_token

        log.info(
            "Sending Telegram notification for %s #%d with notifier '%s' to channel %s",
            event.repo.slug,
            event.build.number,
            name,
            notif.channel,
        )
        senders.append(send_telegram_msg(bot_token, notif.channel, message))

    if not senders:
        log.info("No matching notifiers for %s #%d", event.repo.slug, event.build.number)
        return

    await asyncio.gather(*senders)


async def hook(config: Config, request: web.Request) -> web.StreamResponse:
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
            await do_notify(config, event)
            log.debug("Returning %s to %s", event.build.status, request.remote)
            return web.Response(body=event.build.status)

    # Default to blackholing it. Om nom nom.
    log.debug("Not a valid build state, accepting & taking no action")
    return web.Response(body=b"accepted")


async def startup(config: Config) -> None:
    """
    drone-notify entrypoint
    """
    log.info("Started Drone Notify v%s. Loaded %d notifiers", VERSION, len(config.notifier))
    log.debug("Debug logging is enabled - prepare for logspam")

    host = ipaddress.ip_address(config.main.host)
    port = config.main.port
    hostport = ("[%s]:%d" if host.version == 6 else "%s:%d") % (host, port)

    middlewares: list[Middleware] = []

    if config.main.secret is not None:
        log.debug("Enabled webhook signature verification")
        middlewares.append(verify_drone_signature(config.main.secret.encode()))

    # Drone adds the `Digest:` header to all of it's requests
    middlewares.append(DigestVerifier(require=True).verify_digest_headers)

    handler = web.Application(middlewares=middlewares)
    handler.add_routes([web.post("/hook", functools.partial(hook, config))])

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

    if len(sys.argv) > 1:
        cfg_path = sys.argv[1]
    elif os.path.isfile("notify.toml"):
        cfg_path = "notify.toml"
    else:
        log.warning("Falling back to old config filename 'notify.conf'")
        log.warning(
            "Configuration has migrated to TOML format. Please update your configuration file"
        )
        cfg_path = "notify.conf"

    cfg = load_toml_file(cfg_path)

    if cfg.main.debug:
        log.setLevel(logging.DEBUG)

    try:
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGTERM, loop.stop)
        loop.add_signal_handler(signal.SIGINT, loop.stop)
        loop.run_until_complete(startup(cfg))
        loop.run_forever()
    except KeyboardInterrupt:
        log.info("Caught ^C, stopping")
        loop.stop()
    except Exception as e:  # pylint: disable=broad-except
        log.info("Caught exception, stopping: %s", e)
        loop.stop()
        sys.exit(1)
