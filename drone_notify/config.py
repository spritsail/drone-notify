"""
Configuration parsing, validation and representation for drone-notify
configuration data.
"""

import logging
import os
import tomllib
from typing import Annotated, Literal

from mautrix.types import RoomID, UserID
from pydantic import BaseModel, ConfigDict, Field, model_validator

log = logging.getLogger(__name__)


class StrictModel(BaseModel):
    """
     pydantic model that enables strict model configuration
    This should be used as the base class for all configuration classes
    """

    model_config = ConfigDict(strict=True, extra="forbid")


class BotConfig(StrictModel):
    """
    An abstract bot type with no special service-specific behaviours
    """

    kind: str


class NotifierConfig(StrictModel):
    """
    An abstract notifier type with no special service-specific behaviours
    """

    kind: str
    bot: str
    status: list[str] | None = None
    repos: list[str] | None = None


class TelegramBotConfig(BotConfig):
    """
    A Bot object for sending messages to Telegram as a bot user
    """

    kind: Literal["telegram"]
    bot_token: str


class TelegramNotifyConfig(NotifierConfig):
    """
    A Telegram notifier type that uses a bot to notify a Telegram chat
    """

    kind: Literal["telegram"]
    chat_id: str


class MatrixBotConfig(BaseBotConfig):
    """
    A Bot object for sending messages to Matrix as a user
    """

    kind: Literal["matrix"]
    mxid: UserID
    access_token: str
    db_path: str


class MatrixNotifyConfig(BaseNotifierConfig):
    """
    A Matrix notifier type that uses a bot to notify a Matrix room
    """

    kind: Literal["matrix"]
    room_id: RoomID


class Main(StrictModel):
    """
    Main application-level configuration options
    """

    host: str = Field(default="::")
    port: int = Field(default=5000)
    secret: str | None = None
    debug: bool = False


class Config(StrictModel):
    """
    Top-level application configuration
    """

    main: Main
    bot: dict[str, Annotated[TelegramBotConfig | MatrixBotConfig, Field(discriminator="kind")]]
    notifier: dict[
        str, Annotated[TelegramNotifyConfig | MatrixNotifyConfig, Field(discriminator="kind")]
    ]

    @model_validator(mode="after")
    def match_notifiers(self) -> "Config":
        """
        Validates that each notifier references a defined bot object
        """
        for name, notif in self.notifier.items():
            if notif.bot not in self.bot:
                raise ValueError(
                    f"Notifier '{name}' references undefined {notif.kind} bot '{notif.bot}'"
                )

        for name in self.bot:
            if all(n.bot != name for n in self.notifier.values()):
                log.warning("Bot '%s' defined but not used by any notifiers", name)

        return self


def load_toml_file(path: str | bytes | os.PathLike[str]) -> Config:
    """
    Loads a Config object from an ini file given a path
    """
    with open(path, "rb") as fp:
        return Config(**tomllib.load(fp))
