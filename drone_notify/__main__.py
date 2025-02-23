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

from aiohttp import web
from aiohttp.typedefs import Middleware

from drone_notify.config import NotifierConfig
from drone_notify.digest import DigestVerifier
from drone_notify.drone import WebhookEvent, WebhookRequest
from drone_notify.http_signature import verify_drone_signature
from drone_notify.notify import telegram
from drone_notify.notify.types import Bot, Notifier

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


class DroneNotifier:
    """
    Drone Notifier main application logic
    """

    site: web.SockSite | None

    def __init__(
        self,
        host: str,
        port: int,
        bots: list[Bot],
        notifiers: list[Notifier[NotifierConfig]],
        *,
        webhook_secret: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.bots = bots
        self.notifiers = notifiers
        self.webhook_secret = webhook_secret

        self.site = None

    async def start(self) -> None:
        """
        drone-notify entrypoint
        """
        log.info("Started Drone Notify v%s", VERSION)
        log.debug("Debug logging is enabled - prepare for logspam")

        await asyncio.gather(*[bot.start() for bot in self.bots])

        host = ipaddress.ip_address(self.host)
        hostport = ("[%s]:%d" if host.version == 6 else "%s:%d") % (host, self.port)

        # Drone adds the `Digest:` header to all of it's requests
        middlewares: list[Middleware] = [DigestVerifier(require=True)]

        if self.webhook_secret is not None:
            log.debug("Enabled webhook signature verification")
            middlewares.append(verify_drone_signature(self.webhook_secret.encode()))

        handler = web.Application(middlewares=middlewares)
        handler.add_routes([web.post("/hook", self.hook)])

        runner = web.AppRunner(handler)
        await runner.setup()

        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        self.site = web.SockSite(runner, sock)
        await self.site.start()
        log.info("Listening on %s", hostport)

    async def stop(self) -> None:
        """
        Shut down the notification agent
        """
        log.info("Stopping...")
        if self.site is not None:
            await self.site.stop()
        if self.bots is not None:
            await asyncio.gather(*[bot.stop() for bot in self.bots])

    async def do_notify(self, event: WebhookRequest) -> None:
        """
        Dispatch notifications to all notifiers
        """
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
        await asyncio.gather(*(map(lambda n: n.send(message), filtered)))

    async def hook(self, request: web.Request) -> web.StreamResponse:
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
                await self.do_notify(event)
                log.debug("Returning %s to %s", event.build.status, request.remote)
                return web.Response(body=event.build.status)

        # Default to blackholing it. Om nom nom.
        log.debug("Not a valid build state, accepting & taking no action")
        return web.Response(body=b"accepted")


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

    if config.has_option("main", "debug"):
        if config["main"].getboolean("debug"):
            log.setLevel(logging.DEBUG)

    if not config.has_option("main", "token"):
        log.error("Required variable `main.token' empty or unset")
        sys.exit(1)
    elif not config.has_option("channels", "default"):
        log.error("Required value `channels.default' empty or unset")
        sys.exit(1)

    host = config["main"].get("host", "::")
    port = int(config["main"].get("port", "5000"))

    botconfig = telegram.TelegramBotConfig(bot_token=config["main"]["token"])
    tgbot = telegram.TelegramBot("bot", botconfig)
    bots: list[Bot] = [tgbot]

    # Use the default notifier for all repos, except those explicitly overriden by other notifiers
    default_repos = list(map(lambda r: "!" + r, config["channels"].keys() - {"default", "failure"}))
    channels: list[Notifier[NotifierConfig]] = [
        telegram.TelegramNotifier(
            "default",
            tgbot,
            telegram.TelegramNotifyConfig(
                repos=default_repos,
                status=["success"],
                chat_id=config["channels"]["default"],
            ),
        )
    ]
    if config.has_option("channels", "failure"):
        failconfig = telegram.TelegramNotifyConfig(
            repos=default_repos,
            status=["failure", "error", "killed"],
            chat_id=config["channels"]["failure"],
        )
        channels.append(telegram.TelegramNotifier("failure", tgbot, failconfig))
    for repo, chat_id in config["channels"].items():
        if repo in {"default", "failure"}:
            continue
        channelconfig = telegram.TelegramNotifyConfig(
            repos=[repo], status=["success"], chat_id=chat_id
        )
        channels.append(telegram.TelegramNotifier(repo, tgbot, channelconfig))

    dn = DroneNotifier(host, port, bots, channels, webhook_secret=config.get("main", "secret"))
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.add_signal_handler(signal.SIGTERM, loop.stop)
        loop.add_signal_handler(signal.SIGINT, loop.stop)
        loop.run_until_complete(dn.start())
        loop.run_forever()
    except KeyboardInterrupt:
        log.info("Caught ^C, stopping")
        loop.run_until_complete(dn.stop())
        loop.stop()
    except Exception as e:  # pylint: disable=broad-except
        log.exception("Caught exception, stopping: %s", e)
        loop.run_until_complete(dn.stop())
        loop.stop()
        sys.exit(1)
