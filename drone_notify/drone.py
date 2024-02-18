"""
Drone data types, represented as dataclasses

https://github.com/drone/drone-go/blob/master/plugin/webhook/webhook.go
https://github.com/drone/drone-go/blob/master/drone/types.go
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any

import dacite


@dataclass
class User:
    """
    User represents a user account.
    """

    id: int
    login: str
    email: str
    machine: bool
    admin: bool
    active: bool
    avatar: str
    syncing: bool
    synced: int
    created: int
    updated: int
    last_login: int


# https://github.com/harness/gitness/blob/drone/core/step.go
@dataclass
class Step:
    """
    Step represents an individual step in the stage
    """

    id: int
    step_id: int
    number: int
    name: str
    status: str
    error: str | None
    errignore: bool | None
    exit_code: int
    started: int | None
    stopped: int | None
    version: int
    depends_on: list[str] | None
    image: str | None
    detached: bool | None
    schema: str | None


# https://github.com/harness/gitness/blob/drone/core/stage.go
@dataclass
class Stage:
    """
    Stage represents a stage of build execution.
    """

    id: int
    repo_id: int
    build_id: int
    number: int
    name: str
    kind: str | None
    type: str | None
    status: str
    error: str | None
    errignore: bool
    exit_code: int
    machine: str | None
    os: str
    arch: str
    variant: str | None
    kernel: str | None
    limit: int | None
    throttle: int | None
    started: int
    stopped: int
    created: int
    updated: int
    version: int
    on_success: bool
    on_failure: bool
    depends_on: list[str] | None
    labels: dict[str, str] | None
    steps: list[Step] | None


# https://github.com/harness/gitness/blob/drone/core/build.go
@dataclass
class Build:
    """
    Build defines a build object.
    """

    id: int
    repo_id: int
    trigger: str
    number: int
    parent: int | None
    status: str
    error: str | None
    event: str
    action: str
    link: str
    timestamp: int
    title: str | None
    message: str
    before: str
    after: str
    ref: str
    source_repo: str
    source: str
    target: str
    author_login: str
    author_name: str
    author_email: str
    author_avatar: str
    sender: str
    params: dict[str, str] | None
    cron: str | None
    deploy_to: str | None
    deploy_id: int | None
    debug: bool | None
    started: int
    finished: int
    created: int
    updated: int
    version: int
    stages: list[Stage] | None


# https://github.com/harness/gitness/blob/drone/core/repo.go
@dataclass
class Repo:
    """
    Repo represents a repository.
    """

    id: int
    uid: str
    user_id: int
    namespace: str
    name: str
    slug: str
    scm: str
    git_http_url: str
    git_ssh_url: str
    link: str
    default_branch: str
    private: bool
    visibility: str
    active: bool
    config_path: str
    trusted: bool
    protected: bool
    ignore_forks: bool
    ignore_pull_requests: bool
    auto_cancel_pull_requests: bool
    auto_cancel_pushes: bool
    auto_cancel_running: bool
    timeout: int
    throttle: int | None
    counter: int
    synced: int
    created: int
    updated: int
    version: int
    build: Build | None
    archived: bool


@dataclass
class System:
    """
    System stores system information.
    """

    proto: str
    host: str
    link: str
    version: str


class WebhookEvent(Enum):
    """
    Webhook event types.
    """

    BUILD = "build"
    REPO = "repo"
    USER = "user"


class WebhookAction(Enum):
    """
    Webhook action types.
    """

    CREATED = "created"
    UPDATED = "updated"
    DELETED = "deleted"
    ENABLED = "enabled"
    DISABLED = "disabled"


@dataclass
class WebhookRequest:
    """
    WebhookRequest defines a webhook request.
    """

    event: WebhookEvent
    action: WebhookAction
    user: User | None
    repo: Repo
    build: Build
    system: System

    @classmethod
    def from_dict(cls, data: Any) -> "WebhookRequest":
        """
        Convert a dict data structure into a fully-formed WebhookRequest object
        """
        return dacite.from_dict(
            cls,
            data,
            config=dacite.Config(strict=True, cast=[WebhookEvent, WebhookAction]),
        )
