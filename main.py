#!/usr/bin/python3

from flask import Flask, request, abort
import sys
import logging
import json
import configparser
import requests

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

def doNotify(success, build):

    status = ("SUCCESS" if success else "FAILURE")

    minutes,seconds=divmod(int(build["build"]["updated"]) - int(build["build"]["started"]), 60)
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
        print(r.text)
    except:
        print("Warning: Telegram notify error!")

@app.route('/hook', methods=['POST'])
def webhook():
    if request.method == 'POST':
        json = request.json
        if (json['event'] == 'build') and (json['action'] == 'updated'):
            print("{} - Got a webook for {} build {}".format(request.remote_addr, json['repo']['slug'], json['repo']['build']['number']))
            success = True
            for stage in json['build']['stages']:
                for step in stage['steps']:
                    status = step['status']
                    if status == 'failure':
                        doNotify(False, json)
                        return 'epicfail', 200
                    if status != 'success':
                        success = False

            if success:
                # All the steps are called success. nice.
                doNotify(True, json)
                return 'winrar', 200
            else:
                # Not a success or a failure, so still going or cancelled. No notify.
                return 'mmmkay', 200
        # Default to blackholing it. Om nom nom.
        return '', 200
    else:
        abort(400)

if __name__ == '__main__':
    config = configparser.ConfigParser()
    try:
        cfg_path = sys.argv[1]
    except IndexError:
        cfg_path = "./drone.cfg"
    config.read(cfg_path)
    ttoken = config['Telegram']['token']
    tchat =  config['Telegram']['chatid']
    app.run()
