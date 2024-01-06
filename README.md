[hub]: https://hub.docker.com/r/spritsail/drone-notify
[git]: https://github.com/spritsail/drone-notify
[drone]: https://drone.spritsail.io/spritsail/drone-notify
[mbdg]: https://microbadger.com/images/spritsail/drone-notify

# [spritsail/drone-notify][hub]

[![Layers](https://images.microbadger.com/badges/image/spritsail/drone-notify.svg)][mbdg]
[![Latest Version](https://images.microbadger.com/badges/version/spritsail/drone-notify.svg)][hub]
[![Git Commit](https://images.microbadger.com/badges/commit/spritsail/drone-notify.svg)][git]
[![Docker Pulls](https://img.shields.io/docker/pulls/spritsail/drone-notify.svg)][hub]
[![Docker Stars](https://img.shields.io/docker/stars/spritsail/drone-notify.svg)][hub]
[![Build Status](https://drone.spritsail.io/api/badges/spritsail/drone-notify/status.svg)][drone]
[![Last Build](https://api.spritsail.io/badge/lastbuild/spritsail/drone-notify:latest)][drone]

This script sets up a webhook listener for Drone's global webhooks. It then sends a notification to a Telegram channel every time a build passes or fails.

## Getting Started

Run the docker container with a config file (notify.conf) mounted to /config/notify.conf. Configure the required parameters. At the bare minimum a Telegram bot token (`main.token`) and default channel (`channels.default`) will need to be added.

An example config file can be found in `notify.conf.example`

Then run the container:

```shell
docker run -d \
    --name=drone-notify \
    --restart=always \
    -e DRONE_SECRET=testing \
    -v path/to/notify.conf:/config/notify.conf \
    spritsail/drone-notify
```

## YAML Configuration
```yaml
drone:
    image: drone/drone:2
    ...
    environment:
        ...
        - DRONE_WEBHOOK_ENDPOINT=http://127.0.01:5000/
        - DRONE_WEBHOOK_SECRET=YOUR_SECRET
webook:
    image: spritsail/drone-notify:1.3
    ports:
        - 5000:5000
    volumes:
        - /opt/drone/notify.conf:/config/notify.conf
    environment:
        - DRONE_SECRET=YOUR_SECRET
```

## Test locally
These steps help to simulate the request coming from drone on a specific event

1. First build a local dev image
```sh
docker build -t drone-notify .
```

2. Then start this image with with the script `start_test_server` from `root`:
```sh
./scripts/start_test_server.sh
```

3. Trigger a request to the server with the `mock_drone_request` script
```sh
./scripts/mock_drone_request.py
```