#!/usr/bin/python3

"""
drone-notify - A webhook and notification sidecar daemon for Harness Drone
Receives build webhook events from Drone and fires off notifications when
builds complete, with support for multi-stage builds and pull-requests
"""

import asyncio
import html
import importlib.metadata
import ipaddress
import logging
import os.path
import socket
import sys

from aiohttp import web
from aiohttp.typedefs import Middleware

from drone_notify.config import Config, load_toml_file
from drone_notify.digest import DigestVerifier
from drone_notify.drone import Build, Repo, WebhookEvent, WebhookRequest
from drone_notify.http_signature import verify_drone_signature
from drone_notify.notify import Bot, Notifier, load_notifiers

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


def generate_msg(event: WebhookRequest) -> str:
    """
    Generate a HTML formatted notification message from Webhook event data
    """
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
            multi_stage += f"• {stage_name}     <b>{stage_state}</b> in {time} {emoji}<br/>"

        multi_stage += "<br/>"

    drone_link = f"{event.system.link}/{event.repo.slug}/{event.build.number}"

    if "\n" in event.build.message:
        msg_lines = event.build.message.split("\n")
        msg_firstline = html.escape(msg_lines.pop(0))
        msg_rest = "<br/>-----" + "<br/>".join(map(lambda l: html.escape(l.strip()), msg_lines))
    else:
        msg_firstline = html.escape(event.build.message)
        msg_rest = ""

    return (
        "<b>{repo} [{is_pr}{branch}]</b> #{number}: <b>{status}</b> in {time}<br/>"
        + "<a href='{drone_link}'>{drone_link}</a><br/>"
        + "{multi_stage}<a href='{git_link}'>#{commit:7.7}</a> ({committer}): "
        + "<i>{msg_firstline}</i>{msg_rest}"
    ).format(
        is_pr=is_pr,
        branch=html.escape(event.build.target),
        commit=html.escape(event.build.after),
        msg_firstline=msg_firstline,
        msg_rest=msg_rest,
        committer=html.escape(event.build.author_login),
        drone_link=html.escape(drone_link),
        git_link=html.escape(event.build.link),
        multi_stage=multi_stage,
        number=event.build.number,
        repo=html.escape(event.repo.slug),
        status=html.escape(event.build.status).upper(),
        time=format_duration(event.build.started, event.build.finished),
    )


async def send_to(notifier: Notifier, message: str, repo: Repo, build: Build) -> None:
    """
    Send a notification message to a given notifier
    """
    try:
        await notifier.send(message)
        log.info(
            "Sent %s notification for %s #%d to %s with %s",
            notifier.kind.capitalize(),
            repo.slug,
            build.number,
            notifier,
            notifier.bot,
        )
    except Exception as exc:  # pylint: disable=broad-except
        log.exception("Failed to send notification: %s", exc)


class DroneNotifier:
    """
    A Drone Notifier
    """

    bots: list[Bot] | None
    notifiers: list[Notifier] | None
    site: web.SockSite | None

    def __init__(self, config: Config) -> None:
        self.config = config

    async def hook(self, request: web.Request) -> web.StreamResponse:
        """
        Handle incoming webhooks from (hopefully) Drone
        """
        assert self.notifiers is not None

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
                await self.do_notify(event)
                return web.Response(body=event.build.status)

        # Default to blackholing it. Om nom nom.
        log.debug("Not a valid build state, accepting & taking no action")
        return web.Response(body=b"accepted")

    async def start(self) -> None:
        """Start the drone notifier"""
        log.info(
            "Started Drone Notify v%s. Loaded %d notifiers", VERSION, len(self.config.notifier)
        )
        log.debug("Debug logging is enabled - prepare for logspam")

        self.bots, self.notifiers = load_notifiers(self.config)
        await asyncio.gather(*[bot.start() for bot in self.bots])

        host = ipaddress.ip_address(self.config.main.host)
        port = self.config.main.port
        hostport = ("[%s]:%d" if host.version == 6 else "%s:%d") % (host, port)

        middlewares: list[Middleware] = []

        if self.config.main.secret is not None:
            log.debug("Enabled webhook signature verification")
            middlewares.append(verify_drone_signature(self.config.main.secret.encode()))

        # Drone adds the `Digest:` header to all of it's requests
        middlewares.append(DigestVerifier(require=True))

        handler = web.Application(middlewares=middlewares)
        handler.add_routes([web.post("/hook", self.hook)])

        runner = web.AppRunner(handler)
        await runner.setup()

        log.info("Listening on %s", hostport)
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.bind((str(host), port))
        self.site = web.SockSite(runner, sock)
        await self.site.start()

    async def stop(self) -> None:
        """Stop the drone notifier"""
        log.info("Stopping...")
        if self.site is not None:
            await self.site.stop()
        if self.bots is not None:
            await asyncio.gather(*[bot.stop() for bot in self.bots])

    async def do_notify(self, event: WebhookRequest) -> None:
        """Dispatch notifications to all notifiers"""
        if self.notifiers is None:
            return

        if event.build is None or event.repo is None or event.system is None:
            # Satisfy type checkers. We already checked these
            return

        if "[NOTIFY SKIP]" in event.build.message or "[SKIP NOTIFY]" in event.build.message:
            log.debug("Skipping notification as commit message requested it")
            return

        filtered = list(filter(lambda n: n.should_notify(event.build, event.repo), self.notifiers))
        if not filtered:
            log.info("No matching notifiers for %s #%d", event.repo.slug, event.build.number)
            return

        message = generate_msg(event)
        await asyncio.gather(
            *(map(lambda n: send_to(n, message, event.repo, event.build), filtered))
        )


if __name__ == "__main__":
    # Configure stdout logging
    logging.basicConfig(
        level=logging.INFO,
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        format="[%(asctime)s] [%(name)s] %(levelname)s - %(message)s",
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
        dn = DroneNotifier(cfg)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(dn.start())
        loop.run_forever()
    except KeyboardInterrupt:
        log.info("Caught ^C, stopping")
        loop.run_until_complete(dn.stop())
        loop.stop()
    except Exception as exc:  # pylint: disable=broad-except
        log.exception("Caught exception, stopping: %s", exc)
        loop.run_until_complete(dn.stop())
        loop.stop()
        sys.exit(1)
