# Drone Webhook Notify

This script sets up a webhook listener for Drone's global webhooks. It then sends a notification to a Telegram channel every time a build passes or fails.

## Running

Run the docker container with a config file (notify.conf) mounted to /config/notify.conf

An example config file can be found in `notify.conf.example`
