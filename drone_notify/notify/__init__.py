"""
Notifications
"""

import logging
from collections.abc import Mapping
from fnmatch import fnmatchcase

from drone_notify.config import Config
from drone_notify.notify.types import Bot, Notifier, NotifyException, Registry

from .telegram import TelegramBot, TelegramNotifier

log = logging.getLogger(__name__)


BotRegistry = Registry[str, Bot]()
NotifierRegistry = Registry[str, Notifier]()

BotRegistry.register("telegram", TelegramBot)
NotifierRegistry.register("telegram", TelegramNotifier)


def load_notifiers(cfg: Config) -> tuple[list[Bot], list[Notifier]]:
    """
    Instantiate all notifiers and their associated bot objects
    """
    allnotifs: list[Notifier] = []
    bot_map: dict[str, Bot] = {}

    for name, notifcfg in cfg.notifier.items():
        if notifcfg.bot not in bot_map:
            botcfg = cfg.bot[notifcfg.bot]
            newbot = BotRegistry[botcfg.kind]
            bot_map[notifcfg.bot] = newbot(notifcfg.bot, botcfg)

        bot = bot_map[notifcfg.bot]
        notifier = NotifierRegistry[notifcfg.kind](name, bot, notifcfg)
        allnotifs.append(notifier)

    return list(bot_map.values()), allnotifs


__all__ = (
    "Bot",
    "BotRegistry",
    "Notifier",
    "NotifierRegistry",
    "NotifyException",
    "load_notifiers",
)