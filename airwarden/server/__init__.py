"""Dashboard + JSON API (stdlib http.server, no framework needed).

Serves the operator console and the endpoints behind it: run a scan on a
capture, view evidence-backed verdicts, and approve/reject the proposed fixes
(which then apply in dry-run and verify). Bilingual alerts are pushed to
Telegram when configured."""
from .app import serve, AppState  # noqa: F401
