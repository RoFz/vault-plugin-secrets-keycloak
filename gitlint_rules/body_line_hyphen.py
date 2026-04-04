import re

from gitlint.rules import CommitMessageBody, LineRule, RuleViolation

FOOTER_RE = re.compile(
    r"^(BREAKING CHANGE|BREAKING-CHANGE|[A-Za-z][\w-]*):\s",
)

VALID_TYPES = (
    "feat",
    "fix",
    "chore",
    "docs",
    "style",
    "refactor",
    "perf",
    "test",
    "revert",
    "ci",
    "build",
)

BULLET_RE = re.compile(r"^- (" + "|".join(VALID_TYPES) + r"):\s")


class BodyLineHyphenPrefix(LineRule):
    """Enforce that every non-empty body line starts with '- <type>: '.

    Git trailers (e.g. BREAKING CHANGE:, Signed-off-by:) are exempt.
    """

    name = "body-line-hyphen-prefix"
    id = "UC1"
    target = CommitMessageBody

    def validate(self, line, _commit):
        if not line.strip():
            return
        if FOOTER_RE.match(line):
            return
        if not BULLET_RE.match(line):
            types = ", ".join(VALID_TYPES)
            msg = f"Body lines must match '- <type>: ...' where type is one of: {types}"
            return [RuleViolation(self.id, msg, line)]
