# Codex Review Checklist

Use this checklist for every Claude-generated change.

1. Does `python app.py` still start?
2. Does `/` still return the existing frontend?
3. Does `/api/system/health` still return `{code,msg,data}`?
4. Were any existing API paths removed or renamed?
5. Were existing frontend page ids or navigation entries removed?
6. Were Flask or SQLite replaced?
7. Did the change add heavy dependencies such as TensorFlow, PyTorch, Redis, MongoDB, or Java tooling?
8. Are new features behind config switches?
9. Are defaults safe and non-blocking?
10. Is placeholder functionality clearly labeled as placeholder?
11. Did docs avoid calling placeholder features complete?
12. Are secrets, keys, tokens, or passwords hardcoded?
13. Is input validation present for enabled security checks?
14. Are SQLite migrations idempotent?
15. Are errors returned in the existing `{code,msg,data}` shape when an API is involved?
16. Are tests or manual verification steps included?
17. Does the code import cleanly with `python -m py_compile`?
18. Are unrelated files left untouched?
19. Are generated files excluded from review unless intentionally changed?
20. Is the implementation small enough to review safely?
