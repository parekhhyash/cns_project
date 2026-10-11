"""Production entry point:  gunicorn certlab.web.wsgi:app"""
import logging
import threading

from .app import create_app

logging.getLogger("certlab.decision").setLevel(logging.WARNING)
app = create_app()


def _warm():
    """Run every scenario once so the first visitor does not wait for it."""
    try:
        with app.test_request_context():
            app.view_functions["export"]()
    except Exception:                      # never take the site down for a warm-up
        logging.exception("warm-up failed")


threading.Thread(target=_warm, daemon=True).start()
