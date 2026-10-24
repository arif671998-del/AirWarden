"""Dashboard + JSON API (stdlib http.server, no framework needed).

Serves the operator console and the endpoints behind it: run a scan on a
capture, view evidence-backed verdicts, and approve/reject the proposed fixes
(which then apply in dry-run and verify). Bilingual alerts are pushed to
Telegram when configured.

Import the entry points from the submodule, e.g.
``from airwarden.server.app import serve, AppState`` — this package module is
intentionally kept import-free so ``python3 -m airwarden.server.app`` runs
without a runpy double-import warning.
"""
