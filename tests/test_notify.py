import pytest

import drone_notify.notify


@pytest.mark.parametrize(
    "case, slug, matchers, expected",
    (
        (
            "expect match",
            "owner/repo",
            ["owner/repo"],
            True,
        ),
        (
            "glob match",
            "owner/repo",
            ["owner/*"],
            True,
        ),
        (
            "expect reject",
            "owner/repo",
            ["!owner/repo"],
            False,
        ),
        (
            "glob reject",
            "owner/repo",
            ["!owner/*"],
            False,
        ),
    ),
)
def test_repo_match(case: str, slug: str, matchers: list[str], expected: bool) -> None:
    assert (
        drone_notify.notify.repo_match(case, slug, matchers) == expected
    ), f"Repo match case {case} returned unexpected result"
