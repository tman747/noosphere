from __future__ import annotations

import argparse
import http.server
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

SCHEMA: Final[str] = "noos/wwm-public-static-host/v1"
SHARE_BYTES: Final[int] = 1_047_552
MAX_MANIFEST_BYTES: Final[int] = 1 * 1024 * 1024
MAX_INVENTORY_BYTES: Final[int] = 8 * 1024 * 1024
LOOPBACK_NAMES: Final[set[str]] = {"127.0.0.1", "::1", "localhost"}
SHARE_ROUTE = re.compile(r"^/shares/([0-9]{6})/([0-9]{2})\.share$")
RANGE_HEADER = re.compile(r"^bytes=([0-9]*)-([0-9]*)$")
HOST_MANIFEST_PATH: Final[str] = "/.well-known/noos/wwm-web-capacity-v1.json"
INVENTORY_PATH: Final[str] = "/inventory-v1.json"


class StaticHostError(RuntimeError):
    pass


@dataclass(frozen=True)
class StaticHostConfig:
    listen_host: str
    listen_port: int
    bundle_root: Path
    canonical_origin: str
    share_count: int
    share_bytes: int
    expires_at: int


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def parse_listen(value: str) -> tuple[str, int]:
    host, separator, raw_port = value.rpartition(":")
    if not separator or host not in LOOPBACK_NAMES:
        raise StaticHostError("listen address must be loopback host:port")
    try:
        port = int(raw_port)
    except ValueError as error:
        raise StaticHostError("listen port must be an integer") from error
    if not 1 <= port <= 65535:
        raise StaticHostError("listen port must be within 1..65535")
    return host, port


def validate_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.port not in {None, 443}
    ):
        raise StaticHostError("origin must be an exact HTTPS origin without a path")
    return f"https://{parsed.hostname.lower()}"


def read_json(path: Path, maximum: int, label: str) -> dict[str, object]:
    if not path.is_file():
        raise StaticHostError(f"{label} is missing: {path}")
    if path.stat().st_size > maximum:
        raise StaticHostError(f"{label} exceeds its byte bound")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError) as error:
        raise StaticHostError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise StaticHostError(f"{label} must be a JSON object")
    return value


def load_config(args: argparse.Namespace) -> StaticHostConfig:
    listen_host, listen_port = parse_listen(args.listen)
    root = args.bundle_root.resolve(strict=True)
    if not root.is_dir():
        raise StaticHostError("bundle root must be a directory")
    origin = validate_origin(args.origin)
    manifest = read_json(root / HOST_MANIFEST_PATH.lstrip("/"), MAX_MANIFEST_BYTES, "host manifest")
    inventory = read_json(root / INVENTORY_PATH.lstrip("/"), MAX_INVENTORY_BYTES, "inventory")
    if manifest.get("canonical_origin") != origin or inventory.get("canonical_origin") != origin:
        raise StaticHostError("bundle canonical origin does not match --origin")
    manifest_inventory = manifest.get("inventory")
    if not isinstance(manifest_inventory, dict) or manifest_inventory.get("url") != origin + INVENTORY_PATH:
        raise StaticHostError("host manifest inventory URL is invalid")
    rows = inventory.get("rows")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 5_448:
        raise StaticHostError("inventory must contain 1..=5448 rows")
    coordinates: set[tuple[int, int]] = set()
    total_bytes = 0
    for row in rows:
        if not isinstance(row, dict):
            raise StaticHostError("inventory row must be an object")
        stripe = row.get("stripe")
        position = row.get("position")
        byte_count = row.get("bytes")
        if (
            not isinstance(stripe, int)
            or isinstance(stripe, bool)
            or not 0 <= stripe < 1_000_000
            or not isinstance(position, int)
            or isinstance(position, bool)
            or not 0 <= position <= 11
            or byte_count != SHARE_BYTES
        ):
            raise StaticHostError("inventory row coordinate or byte count is invalid")
        coordinate = (stripe, position)
        if coordinate in coordinates:
            raise StaticHostError("inventory contains a duplicate coordinate")
        coordinates.add(coordinate)
        route = f"/shares/{stripe:06}/{position:02}.share"
        if row.get("url") != origin + route:
            raise StaticHostError("inventory row URL does not match its coordinate")
        share_path = root / route.lstrip("/")
        if not share_path.is_file() or share_path.stat().st_size != SHARE_BYTES:
            raise StaticHostError(f"inventory share is missing or malformed: {route}")
        total_bytes += SHARE_BYTES
    expires_at = manifest.get("expires_at")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at <= 0:
        raise StaticHostError("host manifest expiry is invalid")
    for legal_name in ("LICENSE.txt", "NOTICE.txt"):
        if not (root / legal_name).is_file():
            raise StaticHostError(f"bundle legal file is missing: {legal_name}")
    return StaticHostConfig(
        listen_host=listen_host,
        listen_port=listen_port,
        bundle_root=root,
        canonical_origin=origin,
        share_count=len(rows),
        share_bytes=total_bytes,
        expires_at=expires_at,
    )


def parse_range(value: str, size: int) -> tuple[int, int] | None:
    match = RANGE_HEADER.fullmatch(value)
    if match is None or (not match.group(1) and not match.group(2)):
        return None
    if not match.group(1):
        suffix = int(match.group(2))
        if suffix <= 0:
            return None
        return max(0, size - suffix), size - 1
    start = int(match.group(1))
    end = size - 1 if not match.group(2) else min(int(match.group(2)), size - 1)
    if start >= size or end < start:
        return None
    return start, end


class StaticBundleHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mindchain-wwm-static-host/1"

    @property
    def config(self) -> StaticHostConfig:
        config = getattr(self.server, "static_host_config", None)
        if not isinstance(config, StaticHostConfig):
            raise StaticHostError("static host server is missing its configuration")
        return config

    def log_message(self, format: str, *args: object) -> None:
        print(f"static-host {self.client_address[0]} {format % args}", flush=True)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._common_headers("no-store")
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Accept, Range")
        self.send_header("Access-Control-Max-Age", "86400")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch(send_body=True)

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch(send_body=False)

    def do_POST(self) -> None:  # noqa: N802
        self._reject_write()

    def do_PUT(self) -> None:  # noqa: N802
        self._reject_write()

    def do_PATCH(self) -> None:  # noqa: N802
        self._reject_write()

    def do_DELETE(self) -> None:  # noqa: N802
        self._reject_write()

    def _reject_write(self) -> None:
        self.close_connection = True
        self._json_error(405, "METHOD_NOT_ALLOWED", "static artifact host is read-only")

    def _dispatch(self, *, send_body: bool) -> None:
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment:
            self._json_error(400, "INVALID_PATH", "query strings are not accepted")
            return
        if parsed.path == "/healthz":
            self._health(send_body)
            return
        fixed = {
            HOST_MANIFEST_PATH: (HOST_MANIFEST_PATH.lstrip("/"), "application/json", "public, max-age=60, must-revalidate"),
            INVENTORY_PATH: (INVENTORY_PATH.lstrip("/"), "application/json", "public, max-age=0, no-cache, must-revalidate"),
            "/LICENSE.txt": ("LICENSE.txt", "text/plain; charset=utf-8", "public, max-age=31536000, immutable"),
            "/NOTICE.txt": ("NOTICE.txt", "text/plain; charset=utf-8", "public, max-age=31536000, immutable"),
        }.get(parsed.path)
        if fixed is not None:
            if self.headers.get("Range") is not None:
                self._range_error(0)
                return
            self._serve_file(self.config.bundle_root / fixed[0], fixed[1], fixed[2], send_body, None)
            return
        match = SHARE_ROUTE.fullmatch(parsed.path)
        if match is None:
            self._json_error(404, "NOT_FOUND", "resource not found")
            return
        candidate = (self.config.bundle_root / parsed.path.lstrip("/")).resolve()
        if self.config.bundle_root not in candidate.parents or not candidate.is_file() or candidate.stat().st_size != SHARE_BYTES:
            self._json_error(404, "NOT_FOUND", "resource not found")
            return
        byte_range = None
        if range_header := self.headers.get("Range"):
            byte_range = parse_range(range_header, SHARE_BYTES)
            if byte_range is None:
                self._range_error(SHARE_BYTES)
                return
        self._serve_file(
            candidate,
            "application/octet-stream",
            "public, max-age=31536000, immutable, no-transform",
            send_body,
            byte_range,
        )

    def _health(self, send_body: bool) -> None:
        body = canonical_json(
            {
                "schema": SCHEMA,
                "status": "ok",
                "environment": "public-testnet",
                "production": False,
                "production_custody": False,
                "rewards": False,
                "canonical_origin": self.config.canonical_origin,
                "share_count": self.config.share_count,
                "share_bytes": self.config.share_bytes,
                "expires_at": self.config.expires_at,
            }
        )
        self._reply(200, "application/json; charset=utf-8", "no-store", len(body), send_body, body=body)

    def _serve_file(
        self,
        path: Path,
        content_type: str,
        cache_control: str,
        send_body: bool,
        byte_range: tuple[int, int] | None,
    ) -> None:
        size = path.stat().st_size
        start, end = (0, size - 1) if byte_range is None else byte_range
        status = 200 if byte_range is None else 206
        length = end - start + 1
        self.send_response(status)
        self._common_headers(cache_control)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        if path.suffix == ".share":
            self.send_header("Accept-Ranges", "bytes")
        if byte_range is not None:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.end_headers()
        if not send_body:
            return
        remaining = length
        with path.open("rb") as source:
            source.seek(start)
            while remaining:
                chunk = source.read(min(64 * 1024, remaining))
                if not chunk:
                    raise StaticHostError("immutable bundle file ended unexpectedly")
                self.wfile.write(chunk)
                remaining -= len(chunk)

    def _common_headers(self, cache_control: str) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", cache_control)
        self.send_header("Cross-Origin-Resource-Policy", "cross-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")

    def _range_error(self, size: int) -> None:
        body = canonical_json({"schema": SCHEMA, "status": "error", "error": {"code": "RANGE_NOT_SATISFIABLE"}})
        self.send_response(416)
        self._common_headers("no-store")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Range", f"bytes */{size}")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json_error(self, status: int, code: str, message: str) -> None:
        body = canonical_json(
            {
                "schema": SCHEMA,
                "status": "error",
                "production": False,
                "error": {"code": code, "message": message},
            }
        )
        self._reply(
            status,
            "application/json; charset=utf-8",
            "no-store",
            len(body),
            self.command != "HEAD",
            body=body,
        )

    def _reply(
        self,
        status: int,
        content_type: str,
        cache_control: str,
        content_length: int,
        send_body: bool,
        *,
        body: bytes,
    ) -> None:
        self.send_response(status)
        self._common_headers(cache_control)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(content_length))
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if send_body:
            self.wfile.write(body)


class StaticHostServer(http.server.HTTPServer):
    allow_reuse_address = True

    def __init__(self, config: StaticHostConfig):
        super().__init__((config.listen_host, config.listen_port), StaticBundleHandler)
        self.static_host_config = config


def serve(config: StaticHostConfig) -> None:
    server = StaticHostServer(config)
    print(
        json.dumps(
            {
                "schema": SCHEMA,
                "event": "ready",
                "listen": f"{config.listen_host}:{config.listen_port}",
                "canonical_origin": config.canonical_origin,
                "share_count": config.share_count,
                "share_bytes": config.share_bytes,
                "production": False,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bounded read-only static host for a verified WWM web bundle")
    parser.add_argument("--listen", default="127.0.0.1:29681")
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--origin", required=True)
    return parser.parse_args()


def main() -> int:
    try:
        serve(load_config(parse_args()))
        return 0
    except (OSError, StaticHostError, UnicodeError) as error:
        print(f"static artifact host failed: {error}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
