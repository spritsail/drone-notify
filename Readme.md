# Drone Webhook Notify

This script sets up a webhook listener for Drone's global webhooks. It then sends a notification to a Telegram channel every time a build passes or fails.

## Running

Run the docker container with the following environment variables set:
 * `TELEGRAM_TOKEN` = Bot Token
 * `TELEGRAM_CHAT` = Chat ID

