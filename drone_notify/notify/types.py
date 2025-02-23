"""
Notifier base types
"""

import logging
from abc import ABC, abstractmethod
from fnmatch import fnmatchcase

from drone_notify import drone
from drone_notify.config import NotifierConfig

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
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    async def start(self) -> None:
        """Start the bot"""

    @abstractmethod
    async def stop(self) -> None:
        """Stop the bot"""


class Notifier[NCT: NotifierConfig](ABC):
    """
    Represents a notifier, that sends, er, notifications
    """

    repos: list[str] | None
    status: list[str] | None

    @abstractmethod
    def __init__(self, name: str, config: NCT):
        self.name = name
        self.repos = config.repos
        self.status = config.status

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
