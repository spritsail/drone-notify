"""
Configuration parsing, validation and representation for drone-notify
configuration data.
"""

import os
import tomllib
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    """
    Base pydantic model that enables strict model configuration
    This should be used as the base class for all configuration classes
    """

    model_config = ConfigDict(strict=True, extra="forbid")


class BaseNotifier(StrictModel):
    """
    An abstract notifier type with no special service-specific behaviours
    """

    kind: str
    status: list[str] | None = None
    repos: list[str] | None = None


class TelegramNotifier(BaseNotifier):
    """
    A Telegram notifier type that uses a bot to notify a Telegram channel
    """

    kind: Literal["telegram"]
    bot: str
    channel: str


class TelegramBot(StrictModel):
    """
    A Bot object for sending messages to Telegram as a bot user
    """

    bot_token: str


class Telegram(StrictModel):
    """
    Container for one or more Telegram bot definitions
    """

    bot: dict[str, TelegramBot]


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
    notifier: dict[str, Annotated[TelegramNotifier, Field(discriminator="kind")]]
    telegram: Telegram | None

    @model_validator(mode="after")
    def match_notifiers(self) -> "Config":
        """
        Validates that each notifier references a defined bot object
        """
        for name, notif in self.notifier.items():
            bots: dict[str, Any] = getattr(getattr(self, notif.kind), "bot")
            if notif.bot not in bots:
                raise ValueError(
                    f"Notifier '{name}' references undefined {notif.kind} bot '{notif.bot}'"
                )

        return self


def load_toml_file(path: str | bytes | os.PathLike[str]) -> Config:
    """
    Loads a Config object from an ini file given a path
    """
    with open(path, "rb") as fp:
        return Config(**tomllib.load(fp))
