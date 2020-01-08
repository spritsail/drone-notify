FROM spritsail/alpine:3.11

ARG NOTIFY_VER=1.0

WORKDIR /app

COPY requirements.txt main.py /app/

RUN apk add --no-cache py3-pip \
 && pip3 install -r requirements.txt

VOLUME ["/config"]

CMD ["/usr/bin/python3", "/app/main.py", "/config/drone.cfg"]
