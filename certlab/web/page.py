"""Loads index.html (a body fragment: title, styles, markup, script) and wraps it as a page."""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(__file__)
PREFIX = ('<!doctype html>\n<meta charset="utf-8">\n'
          '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
          '<style>:root{color-scheme:light}</style>\n')
MARKER = "/*__STATIC_DATA__*/"


def fragment() -> str:
    with open(os.path.join(HERE, "index.html"), encoding="utf-8") as f:
        return f.read()


def full_page(frag: str | None = None) -> str:
    return PREFIX + (frag if frag is not None else fragment())


def with_data(data: dict) -> str:
    """Fragment with the recorded results embedded, for the static snapshot."""
    frag = fragment()
    assert MARKER in frag, "index.html lost its data marker"
    blob = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    return frag.replace(MARKER, "window.__STATIC__=" + blob + ";")
