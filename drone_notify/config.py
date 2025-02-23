"""
Configuration representation for drone-notify configuration data.
"""

from dataclasses import dataclass


@dataclass
class BotConfig:
    """
    An abstract bot type with no special service-specific behaviours
    """


@dataclass
class NotifierConfig:
    """
    An abstract notifier type with no special service-specific behaviours
    """

    status: list[str] | None = None
    repos: list[str] | None = None
