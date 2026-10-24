"""Token-protected loopback dashboard. Not an Internet-facing server."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
from importlib.resources import files
import json
from pathlib import Path
import secrets
from urllib.parse import parse_qs, urlsplit

import duckdb

from .exports import render_export, select_findings
from .model import InputError
from .queries import Filters, evidence, overview, timeline

FILTER_NAMES = {"account", "principal", "region", "source", "started_at", "ended_at"}
STATIC = {"/": ("dashboard.html", "text/html"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css")}


def _arguments(query, allowed):
    values = parse_qs(query, keep_blank_values=True, strict_parsing=True, max_num_fields=20)
    if set(values) - allowed or any(len(v) != 1 for v in values.values()):
        raise InputError("invalid_query_parameters")
    return {key: value[0] for key, value in values.items()}


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def log_message(self, *_):
        pass  # Do not log request paths, filters, actor identifiers or access tokens.

    def _send(self, status, content, content_type="application/json; charset=utf-8", *, filename=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        if filename is not None:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        try:
            self.wfile.write(content)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass

    def _json(self, status, value):
        self._send(status, json.dumps(value, ensure_ascii=True).encode())

    def do_POST(self): self._json(405, {"error": "read_only_service"})
    do_PUT = do_POST
    do_DELETE = do_POST
    do_PATCH = do_POST
    do_OPTIONS = do_POST

    def do_GET(self):
        expected_host = f"127.0.0.1:{self.server.server_port}"
        if self.headers.get_all("Host", []) != [expected_host]:
            return self._json(403, {"error": "invalid_host"})
        origin = self.headers.get_all("Origin", [])
        if origin and origin != ["http://" + expected_host]:
            return self._json(403, {"error": "invalid_origin"})
        if len(self.path) > 8192:
            return self._json(414, {"error": "request_too_large"})
        try:
            target = urlsplit(self.path)
            if target.scheme or target.netloc:
                raise InputError("invalid_request_target")
            if target.path in STATIC:
                if target.query: raise InputError("unexpected_query")
                name, mime = STATIC[target.path]
                content = files("cloudtrail_triage").joinpath("static", name).read_bytes()
                return self._send(200, content, mime + "; charset=utf-8")
            if not target.path.startswith("/api/"):
                return self._json(404, {"error": "not_found"})
            tokens = self.headers.get_all("X-Triage-Token", [])
            if len(tokens) != 1 or not hmac.compare_digest(tokens[0].encode(), self.server.token.encode()):
                return self._json(403, {"error": "access_token_required"})
            database = self.server.database
            if target.path == "/api/overview":
                _arguments(target.query, set())
                return self._json(200, overview(database))
            if target.path == "/api/findings":
                args = _arguments(target.query, {"account", "principal", "started_at", "ended_at", "rule", "severity"})
                rule, severity = args.pop("rule", None), args.pop("severity", None)
                return self._json(200, {"findings": select_findings(database, Filters(**args), rule=rule, severity=severity)})
            if target.path == "/api/timeline":
                args = _arguments(target.query, FILTER_NAMES | {"limit", "offset"})
                limit, offset = int(args.pop("limit", "100")), int(args.pop("offset", "0"))
                return self._json(200, timeline(database, Filters(**args), limit=limit, offset=offset))
            if target.path == "/api/evidence":
                args = _arguments(target.query, {"id", "limit", "offset"})
                return self._json(200, evidence(database, args.get("id"), limit=int(args.get("limit", "100")), offset=int(args.get("offset", "0"))))
            if target.path == "/api/export":
                args = _arguments(target.query, FILTER_NAMES | {"kind", "format", "id", "rule", "severity"})
                settings = {"kind": args.pop("kind", "events"), "output_format": args.pop("format", "json"),
                    "finding_id": args.pop("id", None), "rule": args.pop("rule", None), "severity": args.pop("severity", None)}
                export = render_export(database, filters=Filters(**args), **settings)
                return self._send(200, export.content, export.content_type, filename=export.filename)
            return self._json(404, {"error": "not_found"})
        except InputError as error:
            return self._json(404 if error.code == "finding_not_found" else 400, {"error": error.code})
        except (ValueError, UnicodeError):
            return self._json(400, {"error": "invalid_query_parameters"})
        except (OSError, duckdb.Error):
            return self._json(503, {"error": "local_data_unavailable"})


def create_dashboard(database: Path, port=8765):
    if type(port) is not int or not 0 <= port <= 65535:
        raise InputError("invalid_port")
    overview(database)  # Validate before listening.
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    server.database = database
    server.token = secrets.token_urlsafe(32)
    return server


def serve(database: Path, port=8765):
    server = create_dashboard(database, port)
    print(f"Open http://127.0.0.1:{server.server_port}/#{server.token}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
