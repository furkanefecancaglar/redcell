#!/usr/bin/env python3
"""REDCELL v1 local server — serves the live console and runs real scans.

Binds to 127.0.0.1 only: the NVIDIA key stays server-side and is never sent to
the browser. This is the piece the published artifact cannot be (artifact CSP
blocks external API calls and would leak the key); run it locally instead.

    python3 server.py            # then open http://127.0.0.1:8770
    REDCELL_PORT=9000 python3 server.py
"""
import json
import os
import sys
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import redcell_engine as eng
import redcell_firewall as fw
import redcell_static as st
import nim_client


def _report_dict(r):
    return {"score": r.score, "grade": r.grade, "passed": r.passed,
            "has_critical": r.has_critical,
            "findings": [asdict(f) for f in r.findings]}

HERE = os.path.dirname(os.path.abspath(__file__))
# $PORT is honored so Heroku/Railway/Render (which inject it) work out of the box.
PORT = int(os.environ.get("REDCELL_PORT") or os.environ.get("PORT") or "8770")
# Local dev binds 127.0.0.1 (key never leaves the machine). A hosted/container
# deploy sets REDCELL_HOST=0.0.0.0 — and MUST add auth in front, since /scan holds keys.
HOST = os.environ.get("REDCELL_HOST", "127.0.0.1")


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        if self.path in ("/", "/index.html", "/console.html"):
            try:
                with open(os.path.join(HERE, "console.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                self._send(404, "console.html not found", "text/plain")
        elif self.path == "/examples":
            self._send(200, json.dumps(eng.EXAMPLES))
        elif self.path == "/health":
            self._send(200, json.dumps({
                "ok": True,
                "surfaces": {
                    "scan-config": "POST {system_prompt} → static resilience score (0 API)",
                    "firewall": "POST {input} → runtime injection verdict (0 API)",
                    "scan": "POST {system_prompt} → live adversarial engine (uses model quota)",
                },
                "target": eng.TARGET_ENGINE, "judge": eng.JUDGE_ENGINE,
                "attacks": len(eng.CORPUS), "detectors": len(st._DET), "firewall_rules": len(fw._RULES) + 1,
            }))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}")

    def do_POST(self):
        try:
            if self.path == "/scan":
                prompt = (self._body().get("system_prompt") or "").strip()
                if not prompt:
                    self._send(400, json.dumps({"error": "system_prompt required"}))
                    return
                self._send(200, json.dumps(eng.run_scan(prompt), ensure_ascii=False))  # live engine (quota)

            elif self.path == "/scan-config":
                prompt = (self._body().get("system_prompt") or "").strip()
                if not prompt:
                    self._send(400, json.dumps({"error": "system_prompt required"}))
                    return
                self._send(200, json.dumps(_report_dict(st.analyze(prompt)), ensure_ascii=False))  # static, 0 API

            elif self.path == "/firewall":
                text = self._body().get("input") or ""
                if not text:
                    self._send(400, json.dumps({"error": "input required"}))
                    return
                self._send(200, json.dumps(fw.inspect(text).to_dict(), ensure_ascii=False))  # runtime, 0 API

            else:
                self._send(404, json.dumps({"error": "not found"}))
        except Exception as e:
            self._send(500, json.dumps({"error": str(e)}))


def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"REDCELL server → http://{HOST}:{PORT}  (key source: {nim_client.KEY_SOURCE})", file=sys.stderr)
    print(f"  POST /scan-config  static resilience score   ({len(st._DET)} detectors, 0 API)", file=sys.stderr)
    print(f"  POST /firewall     runtime injection verdict  ({len(fw._RULES) + 1} rules, 0 API)", file=sys.stderr)
    print(f"  POST /scan         live adversarial engine    (target={eng.TARGET_ENGINE} judge={eng.JUDGE_ENGINE}, uses quota)", file=sys.stderr)
    print("  (127.0.0.1 only — API key never leaves this machine)  Ctrl-C to stop", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
