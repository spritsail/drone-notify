"""
Telegram Bot and Notifier implementations for sending notifications to Telegram
chats, users and channels
"""

import logging
from typing import Any

import aiohttp

from drone_notify.config import BotConfig, NotifierConfig
from drone_notify.notify.types import Bot, Notifier, NotifyException

log = logging.getLogger(__name__)


class TelegramBotConfig(BotConfig):
    """
    A Bot object for sending messages to Telegram as a bot user
    """

    bot_token: str


class TelegramNotifyConfig(NotifierConfig):
    """
    A Telegram notifier type that uses a bot to notify a Telegram chat
    """

    chat_id: str


class TelegramBot(Bot):
    """
    Communicate with the Telegram API as Telegram Bot account
    """

    bot_token: str
    session: aiohttp.ClientSession | None

    def __init__(self, name: str, config: TelegramBotConfig) -> None:
        super().__init__(name)
        self.bot_token = config.bot_token
        self.session = None

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
        self.botname = resp["first_name"]
        self.username = resp["username"]
        log.info("Initialised Telegram bot %s (@%s)", self.botname, self.username)

    async def stop(self) -> None:
        """
        Shut down the bot
        """
        if self.session is not None:
            log.info("Stopping Telegram http clientsession")
            await self.session.close()
            self.session = None


class TelegramNotifier(Notifier[TelegramNotifyConfig]):
    """
    Send a notification to Telegram using a TelegramBot
    """

    bot: TelegramBot
    chat_id: str

    def __init__(self, name: str, bot: TelegramBot, config: TelegramNotifyConfig) -> None:
        if not isinstance(bot, TelegramBot):
            raise TypeError("TelegramNotifier only works with TelegramBot bots")

        super().__init__(name, config)
        self.bot = bot
        self.chat_id = config.chat_id

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
                "text": message.replace("<br/>", "\n"),
            },
        )
