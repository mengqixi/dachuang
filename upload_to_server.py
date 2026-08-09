"""Disabled legacy remote upload entry point.

The active application is app.py. Deployment must not embed credentials or
overwrite files on an unreviewed server directory.
"""

raise SystemExit(
    "Legacy upload is disabled. Follow DEPLOYMENT_RUNBOOK.md with an explicitly reviewed target."
)
