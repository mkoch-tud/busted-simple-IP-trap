#!/usr/bin/env python3
"""Serve a small page that records and displays each visitor's IP address."""

from __future__ import annotations

import argparse
import html
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_LOG_FILE = BASE_DIR / "visitors.log"
PAGE_TEMPLATE = (BASE_DIR / "index.html").read_text(encoding="utf-8")


def configure_logger(log_file: Path) -> logging.Logger:
    logger = logging.getLogger("visitors")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s IP=%(message)s"))
    logger.addHandler(handler)
    return logger


class TrapHandler(BaseHTTPRequestHandler):
    visitor_logger: logging.Logger

    def do_GET(self) -> None:
        request_path = self.path.split("?", 1)[0]

        if request_path == "/healthz":
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Nginx overwrites X-Real-IP with the address of its network peer. The
        # app container is not published, so public traffic can only arrive
        # through that trusted proxy.
        client_ip = self.headers.get("X-Real-IP") or self.client_address[0]
        identifier = unquote(request_path.lstrip("/"))
        self.visitor_logger.info(
            "%s IDENTIFIER=%s", client_ip, json.dumps(identifier, ensure_ascii=True)
        )

        identifier_block = ""
        if identifier:
            identifier_block = (
                '<p class="identifier">Identifier: '
                f"<code>{html.escape(identifier)}</code></p>"
            )

        page = PAGE_TEMPLATE.replace("{{IP_ADDRESS}}", html.escape(client_ip))
        page = page.replace("{{IDENTIFIER_BLOCK}}", identifier_block)
        body = page.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        # Keep the console quiet; visits are recorded in visitors.log instead.
        return


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0", help="address to listen on")
    parser.add_argument("--port", type=int, default=8000, help="port to listen on")
    parser.add_argument(
        "--log-file", type=Path, default=DEFAULT_LOG_FILE, help="visitor log path"
    )
    args = parser.parse_args()

    TrapHandler.visitor_logger = configure_logger(args.log_file)
    server = ThreadingHTTPServer((args.host, args.port), TrapHandler)
    print(f"Listening on http://{args.host}:{args.port}")
    print(f"Logging visitor IPs to {args.log_file}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
