#!/usr/bin/python3

# pylint: disable=missing-function-docstring
import configparser
import importlib.metadata
import ipaddress
import json
import logging
import sys
from html import escape
from typing import Any

import requests
from bottle import post, request, run

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
    minutes, seconds = divmod((int(end) - int(start)), 60)
    datestr = f"{minutes:02}m{seconds:02}s"
    return datestr


def send_telegram_msg(chatid: str, message: str) -> None:
    postdata = {
        "parse_mode": "html",
        "disable_web_page_preview": "true",
        "chat_id": chatid,
        "text": message,
    }

    log.debug("Sending following data to the Telegram API: %s", json.dumps(postdata))

    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{ttoken}/sendmessage",
            json=postdata,
            timeout=60,
        )
        resp.raise_for_status()
    except requests.exceptions.HTTPError as err:
        log.error("Failed to send notification for %s", json.dumps(postdata))
        log.error(err)
    except Exception as err:  # pylint: disable=broad-except
        log.error("Error: Failed to send Telegram notification: %s", err)


def do_notify(build: dict[Any, Any]) -> None:
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

    # Send normal telegram notification
    send_telegram_msg(tchat, notifymsg)

    # If theres a failure channel defined & the build has failed, notify that too
    if build["build"]["status"] != "success" and failure_channel is not None:
        send_telegram_msg(failure_channel, notifymsg)


@post("/hook")
def webhook() -> Any:
    log.debug("Received a post from %s: %s", request.remote_addr, request.json)
    if request.json["event"] == "build":
        log.debug(
            "%s - Successfully parsed a webook for %s #%d (%s)",
            request.remote_addr,
            request.json["repo"]["slug"],
            request.json["build"]["number"],
            request.json["build"]["status"],
        )

        if request.json["build"]["status"] in VALID_BUILD_STATES:
            do_notify(request.json)
            log.debug("Returning %s to %s", request.json["build"]["status"], request.remote_addr)
            return escape(request.json["build"]["status"])

    # Default to blackholing it. Om nom nom.
    log.debug("Not a valid build state, accepting & taking no action")
    return "accepted"


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

    log.info("Started Drone Notify v%s. Default Notification Channel: %s", VERSION, default_channel)
    log.debug("Debug logging is enabled - prepare for logspam")

    host = ipaddress.ip_address(config["main"].get("host", "::"))
    port = int(config["main"].get("port", "5000"))
    hostport = ("[%s]:%d" if host.version == 6 else "%s:%d") % (host, port)
    log.info("Listening on %s", hostport)
    run(host=str(host), port=port, quiet=True)
