FROM golang:alpine AS build

WORKDIR /build
RUN apk add --no-cache gcc musl-dev sqlite-dev

COPY go.mod go.sum .
RUN go mod download

COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    go build -tags "libsqlite3 goolm" -trimpath

# ~~~~~~~~~~~~~~~~~~~~~~~~

FROM spritsail/alpine:3.22

ARG NOTIFY_VER=2.0

LABEL maintainer="Joe Groocock <dronenotify@spritsail.io>" \
      org.label-schema.vendor="Spritsail" \
      org.label-schema.name="Drone Notify" \
      org.label-schema.url="https://github.com/spritsail/drone-notify" \
      org.label-schema.description="Turn Drone global webhooks into Matrix notifications" \
      org.label-schema.version=${NOTIFY_VER}

WORKDIR /config
VOLUME ["/config"]

RUN apk add --no-cache sqlite-libs
COPY --from=build /build/drone-notify /usr/bin/drone-notify
ENTRYPOINT ["drone-notify"]
CMD ["/config/notify.toml"]
