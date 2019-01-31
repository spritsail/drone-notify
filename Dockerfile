ARG JO_VER=1.2
ARG NOTIFY_VER=1.0

FROM alpine:3.9 as builder

ARG JO_VER

ENV CFLAGS="-Os -pipe -fstack-protector-strong" \
    LDFLAGS="-Wl,-O1,--sort-common -Wl,-s"

WORKDIR /tmp

RUN apk add --no-cache libc-dev gcc make \
 && wget -O- https://github.com/jpmens/jo/releases/download/v1.1/jo-1.1.tar.gz | \
        tar xz --strip-components=1 \
 && ./configure \
 && make all \
 && make check

# =============

FROM spritsail/alpine:3.9

ARG JO_VER
ARG NOTIFY_VER
ARG VCS_REF

LABEL maintainer="Spritsail <notify@spritsail.io>" \
      org.label-schema.vendor="Spritsail" \
      org.label-schema.name="notify" \
      org.label-schema.description="A Drone CI plugin for sending webhook notifications" \
      org.label-schema.version=${VCS_REF} \
      io.spritsail.version.jo=${JO_VER} \
      io.spritsail.version.notify=${NOTIFY_VER}

COPY --from=builder /tmp/jo /usr/bin/jo
ADD *.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/*.sh && \
    apk --no-cache add jq curl

CMD [ "/usr/local/bin/notify.sh" ]
