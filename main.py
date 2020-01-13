#!/usr/bin/python3

from bottle import run, post, request
import datetime
import logging
import json
import os
import requests

def getDate():
    return datetime.datetime.now().strftime("%c")

def doNotify(success, build):

    status = ("SUCCESS" if success else "FAILURE")

    minutes,seconds=divmod(int(build["build"]["finished"]) - int(build["build"]["started"]), 60)
    datestr = "{:02}m{:02}s".format(minutes, seconds)

    drone_link = "{}/{}/{}".format(build["system"]["link"], build["repo"]["slug"], build["build"]["number"])

    try:
        commit_firstline, commit_rest = build["build"]["message"].split("\n", 1)
        commit_rest = "-----\n" + commit_rest.strip()
    except ValueError:
        commit_firstline = build["build"]["message"]
        commit_rest = ""

    # TODO: Add PR functionality
    notifymsg="<b>{repo} [{branch}]</b> #{number}: <b>{status}</b> in {time}\n<a href='{drone_link}'>{drone_link}</a>\n<a href='{git_link}'>#{commit:7.7}</a> ({committer}): <i>{commit_firstline}</i>\n{commit_rest}".format(
                    repo=build["repo"]["slug"], branch=build["build"]["target"], number=build["build"]["number"], status=status, time=datestr, drone_link=drone_link,
                    git_link=build["build"]["link"], commit=build["build"]["after"], committer=build["build"]["author_login"], commit_firstline=commit_firstline, commit_rest=commit_rest)

    postdata = {
            "parse_mode": "html",
            "disable_web_page_preview": "true",
            "chat_id": tchat,
            "text": notifymsg
    }

    try:
        r = requests.post("https://api.telegram.org/bot{}/sendmessage".format(ttoken), json=postdata)
        if (r.status_code == 200):
            print("[{}] - Sent Webhook for repo {}".format(getDate(), build["repo"]["slug"]))
        else:
            print(r.text)
    except:
         print("Warning: Telegram notify error!")

@post('/hook')
def webhook():
    json = request.json
    if (json['event'] == 'build'):
        print("[{}] - {} - Got a webook for {} build {} ({})".format(getDate(), request.remote_addr, json['repo']['slug'], json['build']['number'], json['build']['status']))
        if (json["build"]["status"] == "success"):
            doNotify(True, json)
            return "success"
        elif (json["build"]["status"] == "failure"):
            doNotify(False, json)
            return "failure"

    # Default to blackholing it. Om nom nom.
    return "accepted"

if __name__ == '__main__':
    ttoken = os.environ.get('TELEGRAM_TOKEN')
    tchat = os.environ.get('TELEGRAM_CHAT')
    if (not ttoken and not tchat):
        print("Env Var not set")
        exit()
    print("[{}] - Started Drone Notify. Notification Channel: {}".format(getDate(), tchat))
    run(host='0.0.0.0', port=5000, quiet=True)
