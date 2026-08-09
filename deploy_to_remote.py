"""Disabled legacy remote restart entry point.

Never stop remote processes by a broad name from this repository. Use the scoped
service procedure in DEPLOYMENT_RUNBOOK.md after reviewing the remote worktree.
"""

raise SystemExit(
    "Legacy remote restart is disabled. Follow DEPLOYMENT_RUNBOOK.md with an explicitly reviewed target."
)
