"""CLI:  python -m certlab demo | serve | train | export | analyze HOST:PORT | generate DIR"""
from __future__ import annotations

import argparse
import logging
import sys
import tempfile

from .analyzer import Analyzer
from .certgen import HOST, Lab
from .netlab import fetch_chain, make_analyzer, run_scenario


def cmd_demo(a):
    out = a.out or tempfile.mkdtemp(prefix="certlab_")
    lab = Lab(out)
    rows, bad = [], 0
    for sc in lab.scenarios:
        o = run_scenario(lab, sc, via_mitm=sc.name != "legitimate")
        if a.verbose:
            print(f"\n== {sc.name}: {sc.description}\n{o.verdict.report()}")
        decision = "allow" if o.verdict.allow else "block"
        ok = decision == sc.expect and all(f in o.verdict.failed for f in sc.expected_failures)
        bad += not ok
        rows.append((sc.name, o.stdlib.connected, "LEAKED" if o.naive_leaked else "ok",
                     f"{decision.upper()} ({o.verdict.score})", ",".join(o.verdict.failed) or "-",
                     "OK" if ok else "UNEXPECTED"))
    hdr = ("scenario", "stdlib-conn", "naive client", "guard decision", "failed checks", "result")
    w = [max(len(str(r[i])) for r in [hdr, *rows]) for i in range(len(hdr))]
    print("\n" + "  ".join(h.ljust(w[i]) for i, h in enumerate(hdr)))
    print("  ".join("-" * x for x in w))
    for r in rows:
        print("  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)))
    print(f"\nlab files in {out}")
    return 1 if bad else 0


def cmd_generate(a):
    lab = Lab(a.dir)
    print(f"wrote {len(lab.scenarios)} scenarios + CA material to {a.dir}")
    return 0


def cmd_analyze(a):
    host, _, port = a.target.rpartition(":")
    lab = Lab(a.lab_dir) if a.lab_dir else None
    analyzer = make_analyzer(lab) if lab else Analyzer([])
    tls, chain = fetch_chain(int(port), a.sni or host)
    tls.close()
    v = analyzer.analyze(chain, a.sni or host)
    print(v.report())
    return 0 if v.allow else 2


def cmd_train(a):
    from .ml.model import train
    train()
    return 0


def cmd_serve(a):
    from .web.app import create_app
    app = create_app()
    print(f"Cert Guard Lab running at http://{a.host}:{a.port}  (Ctrl+C to stop)")
    app.run(host=a.host, port=a.port, debug=False, threaded=True)
    return 0


def cmd_export(a):
    logging.getLogger("certlab.decision").setLevel(logging.ERROR)   # keep the export quiet
    from .service import LabService
    from .web.page import full_page, with_data
    frag = with_data(LabService().export())
    html = frag if a.fragment else full_page(frag)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"wrote {a.out} ({len(html) // 1024} KB)")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="certlab", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="run every scenario through MITM + all clients")
    d.add_argument("--out"), d.add_argument("-v", "--verbose", action="store_true")
    d.set_defaults(fn=cmd_demo)
    g = sub.add_parser("generate", help="write lab PKI + scenario certs (PEM) to DIR")
    g.add_argument("dir"), g.set_defaults(fn=cmd_generate)
    z = sub.add_parser("analyze", help="analyze the cert served at HOST:PORT")
    z.add_argument("target"), z.add_argument("--sni"), z.add_argument("--lab-dir")
    z.set_defaults(fn=cmd_analyze)
    t = sub.add_parser("train", help="generate a dataset, train and evaluate the ML risk model")
    t.set_defaults(fn=cmd_train)
    sv = sub.add_parser("serve", help="start the web UI (localhost only by default)")
    sv.add_argument("--host", default="127.0.0.1"), sv.add_argument("--port", type=int, default=5000)
    sv.set_defaults(fn=cmd_serve)
    ex = sub.add_parser("export", help="write a self-contained static HTML page with all results")
    ex.add_argument("out", nargs="?", default="cert_guard_lab.html")
    ex.add_argument("--fragment", action="store_true", help="omit doctype/meta (for embedding in a host page)")
    ex.set_defaults(fn=cmd_export)
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
