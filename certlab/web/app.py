"""Flask app: serves the single-page UI and a small JSON API (localhost only)."""
from __future__ import annotations

import collections
import os
import ssl
import threading
import time

from flask import Flask, Response, abort, jsonify, request

from ..live import parse_target
from ..service import LabService
from .page import full_page

HERE = os.path.dirname(__file__)

# The page is one HTML file with inline script and style plus Google Fonts.
CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

# (requests, seconds) per client for routes that open sockets or do real work
LIMITS = {"run": (20, 60), "live": (8, 60), "analyze": (30, 60)}


class RateLimiter:
    """Small in-memory sliding window. Good enough for one process; not a security boundary."""

    def __init__(self, limits=LIMITS, clock=time.monotonic):
        self.limits, self.clock = limits, clock
        self.hits: dict[tuple[str, str], collections.deque] = {}
        self.lock = threading.Lock()

    def allow(self, bucket: str, who: str) -> tuple[bool, int]:
        n, window = self.limits[bucket]
        now = self.clock()
        with self.lock:
            q = self.hits.setdefault((bucket, who), collections.deque())
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= n:
                return False, int(window - (now - q[0])) + 1
            q.append(now)
            if len(self.hits) > 5000:          # forget idle clients
                for k in [k for k, v in self.hits.items() if not v or now - v[-1] > window]:
                    del self.hits[k]
            return True, 0


def create_app(service: LabService | None = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 128 * 1024
    svc = service or LabService()
    app.svc = svc
    app.limiter = RateLimiter()
    if os.environ.get("CERTLAB_BEHIND_PROXY"):      # one trusted reverse proxy (Render, Vercel, ...)
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    def limited(bucket):
        ok, wait = app.limiter.allow(bucket, request.remote_addr or "?")
        if not ok:
            resp = jsonify({"error": f"Too many requests. Try again in {wait} seconds."})
            resp.status_code = 429
            resp.headers["Retry-After"] = str(wait)
            return resp
        return None

    @app.after_request
    def headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if resp.mimetype == "text/html":
            resp.headers.setdefault("Content-Security-Policy", CSP)
        if request.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.get("/healthz")
    def healthz():
        return jsonify({"ok": True, "ml_ready": svc.risk is not None})

    @app.get("/")
    def index():
        return Response(full_page(), mimetype="text/html")

    @app.get("/api/state")
    def state():
        return jsonify(svc.state())

    @app.get("/api/export")
    def export():
        # every scenario run once; cached because it opens real sockets
        if not hasattr(svc, "_export"):
            svc._export = svc.export()
            svc._export["state"]["live"] = True
        return jsonify(svc._export)

    @app.get("/api/ml")
    def ml():
        if svc.metrics is None:
            abort(404, "Model not trained. Run: python -m certlab train")
        return jsonify(svc.metrics)

    @app.get("/api/pem/<name>")
    def pem(name):
        try:
            return jsonify({"pem": svc.pem(name)})
        except StopIteration:
            abort(404)

    @app.post("/api/run/<name>")
    def run(name):
        if (r := limited("run")):
            return r
        try:
            return jsonify(svc.run(name))
        except StopIteration:
            abort(404)

    @app.post("/api/live")
    def live():
        if (r := limited("live")):
            return r
        if not request.is_json:
            abort(415)
        target = str((request.get_json(silent=True) or {}).get("target", ""))
        try:
            host, port = parse_target(target)
            if port not in (443, 8443):
                raise ValueError("Live checks are limited to ports 443 and 8443.")
            return jsonify(svc.live(target))
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except (OSError, ssl.SSLError) as e:
            return jsonify({"error": f"Could not complete a TLS handshake with {target.strip()}: "
                                     f"{str(e).split('] ')[-1][:140] or type(e).__name__}"}), 502

    @app.post("/api/analyze")
    def analyze():
        if (r := limited("analyze")):
            return r
        if not request.is_json:
            abort(415)
        b = request.get_json(silent=True) or {}
        try:
            return jsonify(svc.analyze(str(b.get("pem", "")), str(b.get("host", "")),
                                       require_ct=bool(b.get("require_ct", True)),
                                       revocation_hard_fail=bool(b.get("revocation_hard_fail", True))))
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.errorhandler(404)
    @app.errorhandler(415)
    @app.errorhandler(413)
    def err(e):
        return jsonify({"error": getattr(e, "description", "error")}), e.code

    return app
