"""Flask app: serves the single-page UI and a small JSON API (localhost only)."""
from __future__ import annotations

import os
import ssl

from flask import Flask, Response, abort, jsonify, request

from ..live import parse_target
from ..service import LabService
from .page import full_page

HERE = os.path.dirname(__file__)


def create_app(service: LabService | None = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 128 * 1024
    svc = service or LabService()
    app.svc = svc

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
        try:
            return jsonify(svc.run(name))
        except StopIteration:
            abort(404)

    @app.post("/api/live")
    def live():
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
