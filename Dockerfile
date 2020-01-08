FROM spritsail/alpine:3.11

ARG NOTIFY_VER=1.0

LABEL maintainer="Adam Dodman <dronenotify@adam-ant.co.uk>" \
      org.label-schema.vendor="Adam Dodman" \
      org.label-schema.name="Drone Notify" \
      org.label-schema.url="https://github.com/Adam-Ant/DroneWebhookNotify" \
      org.label-schema.description="Turn Drone global webhooks into Telegram notifications" \
      org.label-schema.version=${NOTIFY_VER}

COPY requirements.txt main.py /app/

RUN apk add --no-cache py3-pip \
 && pip3 install -r requirements.txt

VOLUME ["/config"]

TCMD ["/usr/bin/python3", "/app/main.py", "/config/drone.cfg"]
