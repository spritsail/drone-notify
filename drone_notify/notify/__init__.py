"""
Notifications
"""

import logging
from fnmatch import fnmatchcase

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
