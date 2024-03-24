[hub]: https://hub.docker.com/r/spritsail/drone-notify
[git]: https://github.com/spritsail/drone-notify
[drone]: https://drone.spritsail.io/spritsail/drone-notify

# [spritsail/drone-notify][hub]

[![Latest Version](https://img.shields.io/docker/v/spritsail/drone-notify)][git]
[![Image Size](https://img.shields.io/docker/image-size/spritsail/drone-notify)][hub]
[![Docker Pulls](https://img.shields.io/docker/pulls/spritsail/drone-notify.svg)][hub]
[![Docker Stars](https://img.shields.io/docker/stars/spritsail/drone-notify.svg)][hub]
[![Build Status](https://drone.spritsail.io/api/badges/spritsail/drone-notify/status.svg)][drone]

This script sets up a webhook listener for Drone's global webhooks. It then sends notification(s) to Telegram every time a build passes or fails.

## Getting Started

Run the docker container with a config file (notify.toml) mounted to /config/notify.toml. Configure the required parameters. At the bare minimum a Telegram bot (`[telegram.bot."my bot name"]`) and at least one notifier (`[notifier."my notifier"]`) referencing that bot (`bot = "my bot name"`) will need to be added.

An example config file can be found in `notify.toml.example`

Then run the container:

```shell
docker run -d \
    --name=drone-notify \
    --restart=always \
    -v path/to/notify.toml:/config/notify.toml \
    spritsail/drone-notify
```

## Docker Compose Configuration
```yaml
services:
  drone:
    image: drone/drone:2
    ...
    environment:
      ...
      - DRONE_WEBHOOK_ENDPOINT=http://notify:5000
      - DRONE_WEBHOOK_SECRET=YOUR_SECRET

  notify:
    image: spritsail/drone-notify:1.5
    volumes:
      - path/to/notify.toml:/config/notify.toml
```
