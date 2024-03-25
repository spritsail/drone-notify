FROM spritsail/alpine:3.19

ARG NOTIFY_VER=1.5

LABEL maintainer="Adam Dodman <dronenotify@spritsail.io>" \
      org.label-schema.vendor="Spritsail" \
      org.label-schema.name="Drone Notify" \
      org.label-schema.url="https://github.com/spritsail/drone-notify" \
      org.label-schema.description="Turn Drone global webhooks into Telegram notifications" \
      org.label-schema.version=${NOTIFY_VER}

# Note 'rw' is required because setuptools is bad
# https://github.com/pypa/pip/issues/3930
# https://github.com/pypa/setuptools/issues/3237
RUN --mount=type=bind,target=/src,rw \
    apk add --no-cache --virtual .build-deps \
        cmake \
        gcc \
        g++ \
        make \
        musl-dev \
        python3-dev \
        && \
    apk add --no-cache py3-pip && \
    pip install --break-system-packages /src && \
    apk del .build-deps

WORKDIR /config
VOLUME ["/config"]

CMD ["/usr/bin/python3", "-m", "drone_notify"]
