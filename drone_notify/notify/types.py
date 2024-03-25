"""
Notifier base types
"""

import logging
from abc import ABC, abstractmethod
from fnmatch import fnmatchcase
from typing import Generic, TypeVar

from drone_notify import drone
from drone_notify.config import BaseBotConfig, BaseNotifierConfig

log = logging.getLogger(__name__)


def repo_match(notif: str, repo: str, repos: list[str]) -> bool:
    """
    Determine whether a repo matches a list of repo matchers.

    'repos' should be a list of strings that are one of:
    - An explicit match - returns True
    - A glob that matches the repo - returns True
    - One of the above rules prefixed with a '!', which negates the rule.
      Any matches to a negated rule returns False
    """
    if len(repos) == 0:
        return True

    # Split matchers and rejectors into two lists
    accept: list[str] = []
    reject: list[str] = []
    for r in repos:
        (reject if r.startswith("!") else accept).append(r)

    # Skip this notifier if there were any explicit rejections
    match = next((pat for pat in reject if fnmatchcase(repo, pat[1:])), None)
    if match is not None:
        log.debug("Notifier '%s' rejected for repo '%s' by rule '%s'", notif, repo, match)
        return False

    # Skip this notifier if there were no explicit matches
    match = next((pat for pat in accept if fnmatchcase(repo, pat)), None)
    if match is None:
        log.debug("Notifier '%s' skipped for repo '%s' as it isn't allowlisted", notif, repo)
        return False

    log.debug("Notifier '%s' accepted for repo '%s' by rule '%s'", notif, repo, match)
    return True


class Bot(ABC):
    """
    Represents a notifier bot
    """

    @abstractmethod
    def __init__(self, name: str, cfg: BaseBotConfig):
        self.name = name
        self.kind = cfg.kind

    def __str__(self) -> str:
        return self.name

    @abstractmethod
    async def start(self) -> None:
        """Start the bot"""

    @abstractmethod
    async def stop(self) -> None:
        """Stop the bot"""


class Notifier(ABC):
    """
    Represents a notifier, that sends, er, notifications
    """

    repos: list[str] | None
    status: list[str] | None

    @abstractmethod
    def __init__(self, name: str, bot: Bot, cfg: BaseNotifierConfig):
        self.name = name
        self.kind = cfg.kind
        self.bot = bot
        self.repos = cfg.repos
        self.status = cfg.status

    def __str__(self) -> str:
        return self.name

    @abstractmethod
    async def send(self, message: str) -> None:
        """Send a message to the notifier"""

    def should_notify(self, build: drone.Build, repo: drone.Repo) -> bool:
        """
        Determine whether this notifier applies to a given build/repo
        """
        if self.status is not None and build.status not in self.status:
            log.debug("Notifier '%s' isn't used for builds with status %s", self.name, build.status)
            return False

        # Skip if notifier disallows repo
        if self.repos is not None and not repo_match(self.name, repo.slug, self.repos):
            return False

        return True


class NotifyException(Exception):
    """An exception object representing a failure in sending a notification"""


# FIXME: Use python 3.12 typevar syntax when mypy supports PEP 695
# https://github.com/python/mypy/issues/15238
K = TypeVar("K")
V = TypeVar("V")


class Registry(Generic[K, V]):
    """
    A registry is an exclusive mapping of key to function or object constructor
    """

    def __init__(self) -> None:
        self.entries: dict[K, type[V]] = {}

    def get(self, key: K) -> type[V]:
        """Get the registered entry"""
        return self[key]

    def register(self, key: K, value: type[V]) -> None:
        """Register a new entry"""
        self[key] = value

    def __getitem__(self, key: K) -> type[V]:
        return self.entries[key]

    def __setitem__(self, key: K, value: type[V]) -> None:
        if key in self.entries:
            raise ValueError(f"Registry already has an entry for {key}")

        self.entries[key] = value
