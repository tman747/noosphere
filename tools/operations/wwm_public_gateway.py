from __future__ import annotations

import argparse
import http.server
import json
import mimetypes
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.operations.wwm_wallet_gateway import (  # noqa: E402
    MAX_BODY_BYTES,
    WalletError,
    WalletReply,
    WalletService,
)
from tools.operations.wwm_public_inference import (  # noqa: E402
    InferenceError,
    InferenceReply,
    InferenceService,
    LiveStateProvider,
    OfflineTokenizer,
    WorkerdExecutor,
)

SCHEMA: Final[str] = "noos/wwm-public-testnet-gateway/v1"
MAX_UPSTREAM_BYTES: Final[int] = 2 * 1024 * 1024
MAX_STATIC_BYTES: Final[int] = 8 * 1024 * 1024
UPSTREAM_SELECTION_TTL_SECONDS: Final[float] = 5.0
RECORD_ROUTE = re.compile(r"^/api/wwm-record/([a-z0-9-]{1,64})/([0-9a-f]{64})$")
LOOPBACK_NAMES: Final[set[str]] = {"127.0.0.1", "::1", "localhost"}
NEURAL_EXPLORER_BROWSER_ORIGINS: Final[frozenset[str]] = frozenset({
    "https://wwm-rpc.mindchain.network",
})
NEURAL_EXPLORER_CONNECT_ORIGINS: Final[frozenset[str]] = frozenset({
    "https://wwm-seed.mindchain.network",
    "https://wwm-seed-2.mindchain.network",
    "https://mindchain-seed-3.eastus.cloudapp.azure.com",
})


class GatewayError(RuntimeError):
    pass


@dataclass(frozen=True)
class GatewayConfig:
    listen_host: str
    listen_port: int
    node_rpc: str
    node_token: str
    site_root: Path
    allowed_origins: frozenset[str]
    connect_origins: frozenset[str]
    fallback_node_rpc: str | None = None
    fallback_node_token: str | None = None
    monitor_url: str | None = None
    wallet_service: WalletService | None = None
    inference_service: InferenceService | None = None


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def parse_listen(value: str) -> tuple[str, int]:
    host, separator, raw_port = value.rpartition(":")
    if not separator or host not in LOOPBACK_NAMES:
        raise GatewayError("listen address must be loopback host:port")
    try:
        port = int(raw_port)
    except ValueError as error:
        raise GatewayError("listen port must be an integer") from error
    if not 1 <= port <= 65535:
        raise GatewayError("listen port must be within 1..65535")
    return host, port


def validate_node_rpc(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "http" or parsed.hostname not in LOOPBACK_NAMES or parsed.username or parsed.password:
        raise GatewayError("node RPC must be an unauthenticated loopback HTTP origin")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.port is None:
        raise GatewayError("node RPC must be an exact loopback HTTP origin")
    return value.rstrip("/")


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
        raise GatewayError("allowed origins must be exact HTTPS origins without paths")
    return f"https://{parsed.hostname.lower()}"


def load_config(args: argparse.Namespace) -> GatewayConfig:
    def load_token(path: Path, label: str) -> str:
        token_path = path.resolve(strict=True)
        value = token_path.read_text(encoding="ascii").strip()
        if len(value) < 32 or any(character.isspace() for character in value):
            raise GatewayError(f"{label} token file contains an invalid token")
        return value

    listen_host, listen_port = parse_listen(args.listen)
    token = load_token(args.node_token_file, "node")
    site_root = args.site_root.resolve(strict=True)
    if not site_root.is_dir():
        raise GatewayError("site root must be a directory")
    allowed_origins = frozenset(
        {validate_origin(value) for value in args.allow_origin}
        | NEURAL_EXPLORER_BROWSER_ORIGINS
    )
    connect_origins = frozenset(
        {validate_origin(value) for value in args.connect_origin}
        | NEURAL_EXPLORER_CONNECT_ORIGINS
    )
    node_rpc = validate_node_rpc(args.node_rpc)
    fallback_rpc_arg = getattr(args, "fallback_node_rpc", None)
    fallback_token_path = getattr(args, "fallback_node_token_file", None)
    if (fallback_rpc_arg is None) != (fallback_token_path is None):
        raise GatewayError("fallback node RPC and token file must be configured together")
    fallback_node_rpc = None
    fallback_node_token = None
    if fallback_rpc_arg is not None and fallback_token_path is not None:
        fallback_node_rpc = validate_node_rpc(fallback_rpc_arg)
        fallback_node_token = load_token(fallback_token_path, "fallback node")
    monitor_arg = getattr(args, "monitor_url", None)
    monitor_url = validate_node_rpc(monitor_arg) if monitor_arg is not None else None

    wallet_service = None
    wallet_root = getattr(args, "wallet_root", None)
    if wallet_root is not None:
        try:
            wallet_service = WalletService(
                api_base=args.wallet_api_base,
                node_rpc=fallback_node_rpc or node_rpc,
                node_token=fallback_node_token or token,
                cli_path=args.wallet_cli,
                wallet_root=wallet_root,
                faucet_db=args.wallet_faucet_db,
            )
        except WalletError as error:
            raise GatewayError(error.message) from error

    inference_service = None
    inference_secrets_path = getattr(args, "inference_secrets", None)
    if inference_secrets_path is not None:
        if monitor_url is None:
            raise GatewayError("public inference requires the signed monitor")
        try:
            secret_path = inference_secrets_path.resolve(strict=True)
            secrets_value = json.loads(secret_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise GatewayError("public inference secrets file is unavailable or malformed") from error
        if not isinstance(secrets_value, dict) or secrets_value.get("schema") != "noos/wwm-public-inference-secrets/v1":
            raise GatewayError("public inference secrets file has the wrong schema")
        worker_token = secrets_value.get("worker_token")
        signing_seed_hex = secrets_value.get("signing_seed_hex")
        if (
            not isinstance(worker_token, str)
            or len(worker_token) < 32
            or any(character.isspace() for character in worker_token)
            or not isinstance(signing_seed_hex, str)
            or re.fullmatch(r"[0-9a-f]{64}", signing_seed_hex) is None
        ):
            raise GatewayError("public inference secrets are invalid")
        node_sources = [(node_rpc, token)]
        if fallback_node_rpc is not None and fallback_node_token is not None:
            node_sources.append((fallback_node_rpc, fallback_node_token))
        try:
            tokenizer = OfflineTokenizer(
                executable=getattr(
                    args,
                    "inference_tokenizer",
                    Path("D:/noosphere-artifacts/runtime/hip-run/llama-tokenize.exe"),
                ),
                model=getattr(
                    args,
                    "inference_model",
                    Path("D:/noosphere-artifacts/demo-disposable/model/Bonsai-27B-Q1_0.gguf"),
                ),
                expected_executable_sha256=getattr(
                    args,
                    "inference_tokenizer_sha256",
                    "2685f72d8b2c27c72c116d2c6af9bb180adb4bf2f4fc9adee052dbcfe7f266f4",
                ),
            )
            inference_service = InferenceService(
                database=getattr(
                    args,
                    "inference_database",
                    Path("C:/mindchain/wwm-testnet/inference/public-inference.sqlite3"),
                ),
                signing_seed=bytes.fromhex(signing_seed_hex),
                provider=LiveStateProvider(
                    node_sources=node_sources,
                    monitor_url=monitor_url,
                ),
                executor=WorkerdExecutor(
                    origin=getattr(args, "inference_worker_origin", "http://127.0.0.1:29807"),
                    token=worker_token,
                    tokenizer=tokenizer,
                ),
            )
        except InferenceError as error:
            raise GatewayError(error.message) from error
    return GatewayConfig(
        listen_host=listen_host,
        listen_port=listen_port,
        node_rpc=node_rpc,
        node_token=token,
        site_root=site_root,
        allowed_origins=allowed_origins,
        connect_origins=connect_origins,
        fallback_node_rpc=fallback_node_rpc,
        fallback_node_token=fallback_node_token,
        monitor_url=monitor_url,
        wallet_service=wallet_service,
        inference_service=inference_service,
    )


def read_bounded(response: object, maximum: int) -> bytes:
    reader = getattr(response, "read", None)
    if not callable(reader):
        raise GatewayError("upstream response is unreadable")
    body = reader(maximum + 1)
    if len(body) > maximum:
        raise GatewayError("upstream response exceeded the public gateway bound")
    return body


def fetch_node(
    node_rpc: str,
    node_token: str,
    upstream_path: str,
    user_agent: str,
) -> tuple[int, str, bytes]:
    request = urllib.request.Request(
        node_rpc + upstream_path,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {node_token}",
            "User-Agent": user_agent,
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return (
                int(response.status),
                response.headers.get_content_type(),
                read_bounded(response, MAX_UPSTREAM_BYTES),
            )
    except urllib.error.HTTPError as error:
        return (
            int(error.code),
            error.headers.get_content_type(),
            read_bounded(error, MAX_UPSTREAM_BYTES),
        )

def fetch_public_json(
    origin: str,
    upstream_path: str,
    user_agent: str,
) -> tuple[int, str, bytes]:
    request = urllib.request.Request(
        origin + upstream_path,
        headers={
            "Accept": "application/json",
            "User-Agent": user_agent,
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return (
                int(response.status),
                response.headers.get_content_type(),
                read_bounded(response, MAX_UPSTREAM_BYTES),
            )
    except urllib.error.HTTPError as error:
        return (
            int(error.code),
            error.headers.get_content_type(),
            read_bounded(error, MAX_UPSTREAM_BYTES),
        )


def canonical_uint(value: object, label: str) -> int:
    if isinstance(value, bool):
        raise GatewayError(f"{label} must be an unsigned integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.isascii() and value.isdigit():
        parsed = int(value)
    else:
        raise GatewayError(f"{label} must be an unsigned integer")
    if not 0 <= parsed <= (1 << 64) - 1:
        raise GatewayError(f"{label} is outside uint64")
    return parsed


def node_status_view(
    node_rpc: str,
    node_token: str,
    user_agent: str,
) -> tuple[str, str, int, str, int]:
    status, content_type, body = fetch_node(node_rpc, node_token, "/status", user_agent)
    if status != 200 or content_type != "application/json":
        raise GatewayError("node status response is unavailable")
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise GatewayError("node status response is malformed")
    unsafe_head = parsed.get("unsafe_head")
    finalized = parsed.get("finalized")
    chain_id = parsed.get("chain_id")
    genesis_hash = parsed.get("genesis_hash")
    finalized_hash = finalized.get("hash") if isinstance(finalized, dict) else None
    if (
        not isinstance(unsafe_head, dict)
        or not isinstance(finalized, dict)
        or not isinstance(chain_id, str)
        or not isinstance(genesis_hash, str)
        or not isinstance(finalized_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", chain_id) is None
        or re.fullmatch(r"[0-9a-f]{64}", genesis_hash) is None
        or re.fullmatch(r"[0-9a-f]{64}", finalized_hash) is None
    ):
        raise GatewayError("node status identity or checkpoints are malformed")
    return (
        chain_id,
        genesis_hash,
        canonical_uint(finalized.get("epoch"), "finalized epoch"),
        finalized_hash,
        canonical_uint(unsafe_head.get("height"), "unsafe head height"),
    )




class PublicGatewayHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mindchain-wwm-public-testnet/1"

    @property
    def config(self) -> GatewayConfig:
        config = getattr(self.server, "gateway_config", None)
        if not isinstance(config, GatewayConfig):
            raise GatewayError("gateway server is missing its configuration")
        return config

    def log_message(self, format: str, *args: object) -> None:
        print(f"gateway {self.client_address[0]} {format % args}", flush=True)

    def do_OPTIONS(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        wallet_post = (
            self.config.wallet_service is not None
            and not parsed.query
            and self.config.wallet_service.is_post_route(parsed.path)
        )
        inference_post = (
            self.config.inference_service is not None
            and not parsed.query
            and self.config.inference_service.is_post_route(parsed.path)
        )
        writable = wallet_post or inference_post
        allowed_methods = {"GET", "HEAD", "POST"} if writable else {"GET", "HEAD"}
        requested_method = self.headers.get("Access-Control-Request-Method")
        if requested_method not in {None, *allowed_methods}:
            self._json_error(405, "METHOD_NOT_ALLOWED", "method is not available on this public testnet route")
            return
        if not self._origin_allowed():
            self._json_error(403, "ORIGIN_NOT_ALLOWED", "browser origin is not authorized")
            return
        rendered_methods = "GET, HEAD, POST, OPTIONS" if writable else "GET, HEAD, OPTIONS"
        self.send_response(204)
        self._security_headers("no-store")
        self.send_header("Allow", rendered_methods)
        self.send_header("Access-Control-Allow-Methods", rendered_methods)
        self.send_header("Access-Control-Allow-Headers", "Accept, Content-Type, Idempotency-Key, Last-Event-ID")
        self.send_header("Access-Control-Max-Age", "300")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch(send_body=False)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch(send_body=True)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        inference = self.config.inference_service
        if inference is not None and not parsed.query and inference.is_post_route(parsed.path):
            self._inference_post()
            return
        self._wallet_post()

    def do_PUT(self) -> None:  # noqa: N802
        self._reject_write()

    def do_PATCH(self) -> None:  # noqa: N802
        self._reject_write()

    def do_DELETE(self) -> None:  # noqa: N802
        self._reject_write()

    def do_CONNECT(self) -> None:  # noqa: N802
        self._reject_write()

    def do_TRACE(self) -> None:  # noqa: N802
        self._reject_write()

    def _reject_write(self) -> None:
        self.close_connection = True
        self._json_error(405, "METHOD_NOT_ALLOWED", "public testnet gateway is read-only")

    def _dispatch(self, *, send_body: bool) -> None:
        if not self._origin_allowed():
            self._json_error(403, "ORIGIN_NOT_ALLOWED", "browser origin is not authorized")
            return
        parsed = urlsplit(self.path)
        inference = self.config.inference_service
        if inference is not None and inference.is_get_route(parsed.path):
            if inference.is_stream_route(parsed.path):
                if not send_body:
                    self._json_error(405, "METHOD_NOT_ALLOWED", "SSE streams require GET")
                else:
                    self._inference_stream(parsed.path, parsed.query)
                return
            try:
                reply = inference.get(
                    parsed.path,
                    parsed.query,
                    self.headers.get("CF-Connecting-IP") or self.client_address[0],
                )
                self._inference_json(reply, send_body)
            except InferenceError as error:
                self._inference_error(error, send_body)
            return
        wallet = self.config.wallet_service
        if wallet is not None and wallet.is_get_route(parsed.path):
            try:
                reply = wallet.get(parsed.path, parsed.query)
                self._wallet_json(reply, send_body)
            except WalletError as error:
                self._wallet_error(error, send_body)
            return
        if parsed.path == "/wallet" or parsed.path.startswith("/wallet/"):
            if parsed.query or parsed.fragment:
                self._json_error(400, "INVALID_PATH", "query strings are not accepted")
                return
            if wallet is None:
                self._json_error(404, "NOT_FOUND", "resource not found")
                return
            self._wallet_static(parsed.path, send_body)
            return
        if parsed.query or parsed.fragment:
            self._json_error(400, "INVALID_PATH", "query strings are not accepted")
            return
        if parsed.path == "/healthz":
            self._health(send_body)
            return
        if parsed.path == "/api/network-status":
            self._monitor_status(send_body)
            return
        if parsed.path == "/api/status":
            self._proxy("/status", send_body)
            return
        if parsed.path == "/api/model-resolution/bonsai-q1":
            self._proxy("/model-resolution/bonsai-q1", send_body)
            return
        record = RECORD_ROUTE.fullmatch(parsed.path)
        if record:
            self._proxy(f"/wwm-record/{record.group(1)}/{record.group(2)}", send_body)
            return
        self._static(parsed.path, send_body)

    def _inference_post(self) -> None:
        if not self._origin_allowed():
            self._json_error(403, "ORIGIN_NOT_ALLOWED", "browser origin is not authorized")
            return
        parsed = urlsplit(self.path)
        inference = self.config.inference_service
        if (
            inference is None
            or parsed.query
            or parsed.fragment
            or not inference.is_post_route(parsed.path)
        ):
            self._reject_write()
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            self._inference_error(
                InferenceError(413, "INVALID_BODY_SIZE", "Request body must be between 1 and 65536 bytes."),
                True,
            )
            return
        if self.headers.get_content_type() != "application/json":
            self._inference_error(
                InferenceError(415, "UNSUPPORTED_MEDIA_TYPE", "Inference requests require application/json."),
                True,
            )
            return
        try:
            body = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._inference_error(
                InferenceError(400, "MALFORMED_JSON", "Request body is not valid JSON."),
                True,
            )
            return
        if not isinstance(body, dict):
            self._inference_error(
                InferenceError(400, "MALFORMED_JSON", "Request body must be a JSON object."),
                True,
            )
            return
        client = self.headers.get("CF-Connecting-IP") or self.client_address[0]
        try:
            self._inference_json(
                inference.post(
                    parsed.path,
                    body,
                    client,
                    self.headers.get("Idempotency-Key"),
                ),
                True,
            )
        except InferenceError as error:
            self._inference_error(error, True)

    def _inference_stream(self, path: str, query: str) -> None:
        inference = self.config.inference_service
        if inference is None:
            self._json_error(404, "NOT_FOUND", "resource not found")
            return
        if query:
            self._inference_error(
                InferenceError(400, "INVALID_QUERY", "Public inference streams do not accept query strings."),
                True,
            )
            return
        last_event_id = self.headers.get("Last-Event-ID")
        try:
            inference.validate_stream(path, last_event_id)
        except InferenceError as error:
            self._inference_error(error, True)
            return
        server = self.server
        if not isinstance(server, GatewayServer):
            self._inference_error(
                InferenceError(503, "GATEWAY_UNAVAILABLE", "Public inference gateway is unavailable."),
                True,
            )
            return
        if not server.inference_stream_slots.acquire(blocking=False):
            self._inference_error(
                InferenceError(429, "STREAM_CAPACITY_FULL", "Public inference stream capacity is full.", retry_after=15),
                True,
            )
            return
        try:
            self.close_connection = True
            self.send_response(200)
            self._security_headers("no-store")
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            try:
                for payload in inference.stream(path, last_event_id):
                    if payload is None:
                        body = b": keepalive\n\n"
                    else:
                        encoded = canonical_json(payload).rstrip(b"\n")
                        body = (
                            f"id: {payload['id']}\nevent: {payload['type']}\ndata: ".encode("ascii")
                            + encoded
                            + b"\n\n"
                        )
                    self.wfile.write(body)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, InferenceError, OSError):
                return
        finally:
            server.inference_stream_slots.release()

    def _wallet_post(self) -> None:
        if not self._origin_allowed():
            self._json_error(403, "ORIGIN_NOT_ALLOWED", "browser origin is not authorized")
            return
        parsed = urlsplit(self.path)
        wallet = self.config.wallet_service
        if (
            wallet is None
            or parsed.query
            or parsed.fragment
            or not wallet.is_post_route(parsed.path)
        ):
            self._reject_write()
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            self._wallet_error(
                WalletError(413, "INVALID_BODY_SIZE", "Request body must be between 1 and 65536 bytes."),
                True,
            )
            return
        if self.headers.get_content_type() != "application/json":
            self._wallet_error(
                WalletError(415, "UNSUPPORTED_MEDIA_TYPE", "Wallet requests require application/json."),
                True,
            )
            return
        try:
            body = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._wallet_error(WalletError(400, "MALFORMED_JSON", "Request body is not valid JSON."), True)
            return
        if not isinstance(body, dict):
            self._wallet_error(WalletError(400, "MALFORMED_JSON", "Request body must be a JSON object."), True)
            return
        client = self.headers.get("CF-Connecting-IP") or self.client_address[0]
        try:
            self._wallet_json(wallet.post(parsed.path, body, client), True)
        except WalletError as error:
            self._wallet_error(error, True)

    def _wallet_static(self, request_path: str, send_body: bool) -> None:
        wallet = self.config.wallet_service
        if wallet is None:
            self._json_error(404, "NOT_FOUND", "resource not found")
            return
        relative = "index.html" if request_path in {"/wallet", "/wallet/"} else request_path.removeprefix("/wallet/")
        self._serve_static_file(wallet.wallet_root, relative, send_body)

    def _wallet_json(self, reply: WalletReply, send_body: bool) -> None:
        body = canonical_json(reply.value)
        self.send_response(reply.status)
        self._security_headers("no-store")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        if reply.retry_after is not None:
            self.send_header("Retry-After", str(reply.retry_after))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def _wallet_error(self, error: WalletError, send_body: bool) -> None:
        self._wallet_json(
            WalletReply(
                error.status,
                {
                    "schema": "noos/public-testnet-wallet-error/v1",
                    "error": error.message,
                    "code": error.code,
                    "production": False,
                },
                retry_after=error.retry_after,
            ),
            send_body,
        )

    def _inference_json(self, reply: InferenceReply, send_body: bool) -> None:
        body = canonical_json(reply.value)
        self.send_response(reply.status)
        self._security_headers("no-store")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        if reply.retry_after is not None:
            self.send_header("Retry-After", str(reply.retry_after))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def _inference_error(self, error: InferenceError, send_body: bool) -> None:
        self._inference_json(
            InferenceReply(
                error.status,
                {
                    "schema": "noos/wwm-error/v2",
                    "code": error.code,
                    "message": error.message,
                    "production": False,
                    "promotion_effect": "NONE",
                },
                retry_after=error.retry_after,
            ),
            send_body,
        )

    def _serve_static_file(self, root: Path, relative: str, send_body: bool) -> None:
        candidate = (root / relative).resolve()
        if root not in candidate.parents or not candidate.is_file():
            self._json_error(404, "NOT_FOUND", "resource not found")
            return
        size = candidate.stat().st_size
        if size > MAX_STATIC_BYTES:
            self._json_error(413, "STATIC_RESOURCE_TOO_LARGE", "resource exceeds gateway bound")
            return
        body = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        cache = "no-store" if candidate.suffix.lower() in {".html", ".json", ".webmanifest"} else "public, max-age=300"
        self._reply(200, content_type, body, cache, send_body)

    def _origin_allowed(self) -> bool:
        origin = self.headers.get("Origin")
        return origin is None or origin in self.config.allowed_origins

    def _monitor_status(self, send_body: bool) -> None:
        monitor_url = self.config.monitor_url
        if monitor_url is None:
            self._json_error(503, "MONITOR_UNAVAILABLE", "signed network status is unavailable")
            return
        try:
            status, content_type, body = fetch_public_json(
                monitor_url,
                "/status.json",
                self.server_version,
            )
        except (GatewayError, OSError, urllib.error.URLError):
            self._json_error(503, "MONITOR_UNAVAILABLE", "signed network status is unavailable")
            return
        if content_type != "application/json":
            self._json_error(502, "INVALID_UPSTREAM", "monitor returned a non-JSON response")
            return
        self._reply(status, "application/json; charset=utf-8", body, "no-store", send_body)

    def _health(self, send_body: bool) -> None:
        try:
            status, _, upstream, node_source = self._fetch("/status")
            parsed = json.loads(upstream)
            if status != 200 or not isinstance(parsed, dict):
                raise GatewayError("node status response is invalid")
            body = canonical_json(
                {
                    "schema": SCHEMA,
                    "status": "ok",
                    "environment": "public-testnet",
                    "production": False,
                    "promotion_effect": "NONE",
                    "chain_id": parsed.get("chain_id"),
                    "genesis_hash": parsed.get("genesis_hash"),
                    "unsafe_head": parsed.get("unsafe_head"),
                    "finalized": parsed.get("finalized"),
                    "node_source": node_source,
                }
            )
            self._reply(200, "application/json; charset=utf-8", body, "no-store", send_body)
        except (GatewayError, OSError, ValueError, urllib.error.URLError):
            self._json_error(503, "NODE_UNAVAILABLE", "public testnet node is unavailable")

    def _fetch(self, upstream_path: str) -> tuple[int, str, bytes, str]:
        server = self.server
        if not isinstance(server, GatewayServer):
            raise GatewayError("gateway server is unavailable")
        last_error: Exception | None = None
        for node_source, node_rpc, node_token in server.upstream_order(self.server_version):
            try:
                status, content_type, body = fetch_node(
                    node_rpc,
                    node_token,
                    upstream_path,
                    self.server_version,
                )
                return status, content_type, body, node_source
            except (OSError, urllib.error.URLError) as error:
                last_error = error
        if last_error is not None:
            raise last_error
        raise GatewayError("no node RPC upstream is configured")

    def _proxy(self, upstream_path: str, send_body: bool) -> None:
        try:
            status, content_type, body, _ = self._fetch(upstream_path)
        except (GatewayError, OSError, urllib.error.URLError):
            self._json_error(503, "NODE_UNAVAILABLE", "public testnet node is unavailable")
            return
        if content_type != "application/json":
            self._json_error(502, "INVALID_UPSTREAM", "node returned a non-JSON response")
            return
        self._reply(status, "application/json; charset=utf-8", body, "no-store", send_body)

    def _static(self, request_path: str, send_body: bool) -> None:
        relative = "query.html" if request_path == "/" else request_path.lstrip("/")
        self._serve_static_file(self.config.site_root, relative, send_body)

    def _security_headers(self, cache_control: str) -> None:
        self.send_header("Cache-Control", cache_control)
        connect_sources = " ".join(["'self'", *sorted(self.config.connect_origins)])
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            f"form-action 'self'; connect-src {connect_sources}; img-src 'self' data:; "
            "script-src 'self'; style-src 'self'; worker-src 'self'",
        )
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-site")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        origin = self.headers.get("Origin")
        if origin in self.config.allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _reply(
        self,
        status: int,
        content_type: str,
        body: bytes,
        cache_control: str,
        send_body: bool,
    ) -> None:
        self.send_response(status)
        self._security_headers(cache_control)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def _json_error(self, status: int, code: str, message: str) -> None:
        body = canonical_json(
            {
                "schema": SCHEMA,
                "status": "error",
                "production": False,
                "promotion_effect": "NONE",
                "error": {"code": code, "message": message},
            }
        )
        self._reply(status, "application/json; charset=utf-8", body, "no-store", self.command != "HEAD")


class GatewayServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, config: GatewayConfig):
        super().__init__((config.listen_host, config.listen_port), PublicGatewayHandler)
        self.gateway_config = config
        self._selection_lock = threading.Lock()
        self._selection_expires_at = 0.0
        self._preferred_source = "primary"
        self.inference_stream_slots = threading.BoundedSemaphore(16)

    def server_close(self) -> None:
        inference = self.gateway_config.inference_service
        if inference is not None:
            inference.close()
        super().server_close()

    @staticmethod
    def _status_or_none(
        upstream: tuple[str, str, str],
        user_agent: str,
    ) -> tuple[str, str, int, str, int] | None:
        _, node_rpc, node_token = upstream
        try:
            return node_status_view(node_rpc, node_token, user_agent)
        except (GatewayError, OSError, ValueError, urllib.error.URLError):
            return None

    def upstream_order(self, user_agent: str) -> tuple[tuple[str, str, str], ...]:
        primary = ("primary", self.gateway_config.node_rpc, self.gateway_config.node_token)
        fallback_rpc = self.gateway_config.fallback_node_rpc
        fallback_token = self.gateway_config.fallback_node_token
        if fallback_rpc is None or fallback_token is None:
            return (primary,)
        fallback = ("fallback", fallback_rpc, fallback_token)

        with self._selection_lock:
            now = time.monotonic()
            if now >= self._selection_expires_at:
                primary_status = self._status_or_none(primary, user_agent)
                fallback_status = self._status_or_none(fallback, user_agent)
                if primary_status is None:
                    self._preferred_source = "fallback" if fallback_status is not None else "primary"
                elif fallback_status is None:
                    self._preferred_source = "primary"
                elif (
                    primary_status[:2] != fallback_status[:2]
                    or primary_status[2:4] != fallback_status[2:4]
                    or primary_status[4] < fallback_status[4]
                ):
                    self._preferred_source = "fallback"
                else:
                    self._preferred_source = "primary"
                self._selection_expires_at = now + UPSTREAM_SELECTION_TTL_SECONDS
            if self._preferred_source == "fallback":
                return fallback, primary
            return primary, fallback


def serve(config: GatewayConfig) -> None:
    server = GatewayServer(config)
    print(
        json.dumps(
            {
                "schema": SCHEMA,
                "event": "ready",
                "listen": f"{config.listen_host}:{config.listen_port}",
                "node_rpc": config.node_rpc,
                "fallback_node_rpc": config.fallback_node_rpc,
                "site_root": str(config.site_root),
                "wallet_enabled": config.wallet_service is not None,
                "inference_enabled": config.inference_service is not None,
                "production": False,
                "promotion_effect": "NONE",
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
    parser = argparse.ArgumentParser(description="Public WWM gateway with scoped valueless-testnet wallet relay")
    parser.add_argument("--listen", default="127.0.0.1:29680")
    parser.add_argument("--node-rpc", default="http://127.0.0.1:29652")
    parser.add_argument("--node-token-file", type=Path, required=True)
    parser.add_argument("--fallback-node-rpc")
    parser.add_argument("--fallback-node-token-file", type=Path)
    parser.add_argument("--monitor-url", default="http://127.0.0.1:29901")
    parser.add_argument("--site-root", type=Path, required=True)
    parser.add_argument("--allow-origin", action="append", default=[])
    parser.add_argument("--connect-origin", action="append", default=[])
    parser.add_argument(
        "--wallet-api-base",
        default="https://wwm-seed-2.mindchain.network",
    )
    parser.add_argument(
        "--wallet-cli",
        type=Path,
        default=Path("C:/mindchain/wwm-testnet/bin/noos-cli.exe"),
    )
    parser.add_argument(
        "--wallet-root",
        type=Path,
        default=PROJECT_ROOT / "apps" / "mind-market" / "wallet",
    )
    parser.add_argument(
        "--wallet-faucet-db",
        type=Path,
        default=Path("C:/mindchain/wwm-testnet/wallet/faucet.sqlite3"),
    )
    parser.add_argument(
        "--inference-secrets",
        type=Path,
        default=Path("C:/mindchain/wwm-testnet/secrets/public-inference.json"),
    )
    parser.add_argument(
        "--inference-database",
        type=Path,
        default=Path("C:/mindchain/wwm-testnet/inference/public-inference.sqlite3"),
    )
    parser.add_argument("--inference-worker-origin", default="http://127.0.0.1:29807")
    parser.add_argument(
        "--inference-tokenizer",
        type=Path,
        default=Path("D:/noosphere-artifacts/runtime/hip-run/llama-tokenize.exe"),
    )
    parser.add_argument(
        "--inference-model",
        type=Path,
        default=Path("D:/noosphere-artifacts/demo-disposable/model/Bonsai-27B-Q1_0.gguf"),
    )
    parser.add_argument(
        "--inference-tokenizer-sha256",
        default="2685f72d8b2c27c72c116d2c6af9bb180adb4bf2f4fc9adee052dbcfe7f266f4",
    )
    return parser.parse_args()


def main() -> int:
    try:
        serve(load_config(parse_args()))
        return 0
    except (GatewayError, OSError, UnicodeError) as error:
        print(f"public gateway failed: {error}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
