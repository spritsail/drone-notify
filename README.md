[hub]: https://hub.docker.com/r/spritsail/notify
[git]: https://github.com/spritsail/drone-notify
[drone]: https://drone.spritsail.io/spritsail/notify
[mbdg]: https://microbadger.com/images/spritsail/notify

# [spritsail/notify][hub]
[![Layers](https://images.microbadger.com/badges/image/spritsail/notify.svg)][mbdg]
[![Latest Version](https://images.microbadger.com/badges/version/spritsail/notify.svg)][hub]
[![Git Commit](https://images.microbadger.com/badges/commit/spritsail/notify.svg)][git]
[![Docker Stars](https://img.shields.io/docker/stars/spritsail/notify.svg)][hub]
[![Docker Pulls](https://img.shields.io/docker/pulls/spritsail/notify.svg)][hub]
[![Build Status](https://drone.spritsail.io/api/badges/spritsail/drone-notify/status.svg)][drone]

A plugin for [Drone CI](https://github.com/drone/drone) to send simple JSON notifications of build status. This image is desingned to work in tandem with [spritsail/webhook](https://github.com/spritsail/webhook).

## Supported tags and respective `Dockerfile` links

`latest` - [(Dockerfile)](https://github.com/spritsail/drone-notify/blob/master/Dockerfile)

## Configuration

An example configuration of how the plugin should be configured:
```yaml
pipeline:
  notify:
    image: spritsail/notify
    when: { status: [ success, failure ] }
    secrets: [ webhook_url, notify_token ]
```

### Available options
- `webhook_url`   full URL of webhook endpoint. Can be a secret or a value. _required_
- `notify_token`  the `Authorization` header value _optional_
- `method`        request method. _default `POST`_
- `curl_opts`     additional options to pass to curl. _optional_
