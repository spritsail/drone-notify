"""
Telegram Bot and Notifier implementations for sending notifications to Telegram
chats, users and channels
"""

import logging
from typing import Any

import aiohttp

from drone_notify.config import TelegramBotConfig, TelegramNotifyConfig
from drone_notify.notify.types import Bot, Notifier, NotifyException

log = logging.getLogger(__name__)


class TelegramBot(Bot):
    """
    Communicate with the Telegram API as Telegram Bot account
    """

    bot_token: str
    session: aiohttp.ClientSession | None

    def __init__(self, name: str, cfg: TelegramBotConfig) -> None:
        self.bot_token = cfg.bot_token
        self.session = None
        super().__init__(name, cfg)

    async def request(self, what: str, payload: Any = None) -> dict[str, Any]:
        """
        Make a bot POST request to the Telegram API
        """
        if self.session is None:
            await self.start()
        assert self.session is not None

        async with self.session.post(f"/bot{self.bot_token}/{what}", json=payload) as resp:
            data = await resp.json()
            if data["ok"] is not True:
                # FIXME: Raise Telegram API exceptions to the caller
                raise NotifyException(data["description"])
            ret: dict[str, Any] = data["result"]
            return ret

    async def start(self) -> None:
        """
        Start up the bot
        """
        self.session = aiohttp.ClientSession(
            base_url="https://api.telegram.org/",
            headers={"Content-Type": "application/json"},
            timeout=aiohttp.ClientTimeout(60),
            raise_for_status=True,
        )
        resp = await self.request("getMe")
        log.info("Initialised Telegram bot %s (@%s)", resp["first_name"], resp["username"])

    async def stop(self) -> None:
        """
        Shut down the bot
        """
        if self.session is not None:
            await self.session.close()
            self.session = None


class TelegramNotifier(Notifier):
    """
    Send a notification to Telegram using a TelegramBot
    """

    bot: TelegramBot
    chat_id: str

    def __init__(self, name: str, bot: TelegramBot, cfg: TelegramNotifyConfig) -> None:
        if not isinstance(bot, TelegramBot):
            raise TypeError("TelegramNotifier only works with TelegramBot bots")

        self.chat_id = cfg.chat_id
        super().__init__(name, bot, cfg)

    async def send(self, message: str) -> None:
        """
        Send a formatted message to a Telegram chat
        """
        await self.bot.request(
            "sendmessage",
            payload={
                "parse_mode": "html",
                "disable_web_page_preview": "true",
                "chat_id": self.chat_id,
                "text": message,
            },
        )
