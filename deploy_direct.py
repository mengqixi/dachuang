"""Disabled legacy remote deployment entry point.

The former implementation embedded a server password, copied an obsolete server,
and started it without checking which project process would be affected.
"""

raise SystemExit(
    "Legacy deployment is disabled. Follow DEPLOYMENT_RUNBOOK.md with an explicitly reviewed target."
)
