#!/usr/bin/env python3
"""Local World Wide Mind static server plus MindLink persistence API."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sqlite3
import tempfile
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


REQUIRED_FIELDS = (
    "mindlink_version",
    "id",
    "type",
    "title",
    "language",
    "content",
    "authority",
    "provenance",
    "rights",
    "relations",
    "challenge",
    "moderation",
    "state",
    "created_at",
    "updated_at",
    "content_hash",
)
VALID_TYPES = {
    "claim",
    "question",
    "evidence",
    "correction",
    "translation",
    "memory",
    "model",
    "agent",
    "capability",
    "tool",
    "request",
    "result",
    "challenge",
    "collection",
    "community",
    "contribution",
}
VALID_VISIBILITY = {"only_me", "link", "public"}
VALID_STATES = {"public", "unlisted", "private_draft", "research", "horizon", "building"}
VALID_AI_REUSE = {"deny", "conditional", "allow"}
VALID_CHALLENGE = {"unchallenged", "disputed", "corrected", "withdrawn"}
VALID_MODERATION = {
    "not_reported",
    "reported_pending_review",
    "reviewed_kept",
    "reviewed_changed",
    "withdrawn",
}
VALID_RELATION_FEEDBACK = {
    "unreviewed",
    "user_marked_not_related",
    "user_requested_map_review",
    "user_wants_to_add_evidence",
}
PRIVATE_SKIP_REASON = "private_draft_not_indexed"
CONTROL_HASH_PREFIX = "mindchain-control-v0:"
MAX_REQUEST_BYTES = 1_000_000


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def non_empty_string(value: Any, maximum: int | None = None) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    return maximum is None or len(value) <= maximum


def validate_mindlink(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["mindlink_must_be_object"]

    missing = [field for field in REQUIRED_FIELDS if field not in value]
    errors.extend(f"missing_{field}" for field in missing)
    if missing:
        return errors

    if value.get("mindlink_version") != "0.1":
        errors.append("invalid_version")
    if not non_empty_string(value.get("id")):
        errors.append("invalid_id")
    if value.get("type") not in VALID_TYPES:
        errors.append("invalid_type")
    if not non_empty_string(value.get("title"), 180):
        errors.append("invalid_title")
    if not non_empty_string(value.get("language"), 16):
        errors.append("invalid_language")
    if value.get("state") not in VALID_STATES:
        errors.append("invalid_state")
    if not non_empty_string(value.get("created_at")):
        errors.append("invalid_created_at")
    if not non_empty_string(value.get("updated_at")):
        errors.append("invalid_updated_at")
    if not non_empty_string(value.get("content_hash"), 256) or len(str(value.get("content_hash"))) < 8:
        errors.append("invalid_content_hash")

    content = value.get("content")
    if not isinstance(content, dict):
        errors.append("invalid_content")
    else:
        if not non_empty_string(content.get("original_text"), 1200):
            errors.append("invalid_original_text")
        if not non_empty_string(content.get("summary"), 1200):
            errors.append("invalid_summary")

    authority = value.get("authority")
    if not isinstance(authority, dict):
        errors.append("invalid_authority")
    elif not non_empty_string(authority.get("contributor"), 160):
        errors.append("invalid_contributor")

    provenance = value.get("provenance")
    if not isinstance(provenance, dict):
        errors.append("invalid_provenance")
    else:
        for key in ("sources", "derived_from"):
            field = provenance.get(key)
            if not isinstance(field, list) or any(not isinstance(item, str) for item in field):
                errors.append(f"invalid_{key}")

    rights = value.get("rights")
    if not isinstance(rights, dict):
        errors.append("invalid_rights")
    else:
        visibility = rights.get("visibility")
        if visibility not in VALID_VISIBILITY:
            errors.append("invalid_visibility")
        if rights.get("ai_training") not in VALID_AI_REUSE:
            errors.append("invalid_ai_training")
        if rights.get("commercial_use") not in VALID_AI_REUSE:
            errors.append("invalid_commercial_use")
        if not non_empty_string(rights.get("license"), 120):
            errors.append("invalid_license")
        if visibility == "only_me" and value.get("state") != "private_draft":
            errors.append("private_visibility_must_be_private_draft")
        if visibility == "link" and value.get("state") not in {"unlisted", "private_draft"}:
            errors.append("link_visibility_must_be_unlisted")
        if visibility == "public" and value.get("state") != "public":
            errors.append("public_visibility_must_be_public")

    relations = value.get("relations")
    if not isinstance(relations, dict):
        errors.append("invalid_relations")
    else:
        related = relations.get("related")
        if not isinstance(related, list):
            errors.append("invalid_related")
        else:
            for index, relation in enumerate(related):
                if not isinstance(relation, dict):
                    errors.append(f"invalid_relation_{index}")
                    continue
                if not non_empty_string(relation.get("id")):
                    errors.append(f"invalid_relation_{index}_id")
                if not non_empty_string(relation.get("title"), 180):
                    errors.append(f"invalid_relation_{index}_title")
                if not non_empty_string(relation.get("reason"), 320):
                    errors.append(f"invalid_relation_{index}_reason")
                if relation.get("feedback") not in VALID_RELATION_FEEDBACK:
                    errors.append(f"invalid_relation_{index}_feedback")
        for key in ("supports", "contradicts", "translates", "extends"):
            field = relations.get(key)
            if not isinstance(field, list) or any(not isinstance(item, str) for item in field):
                errors.append(f"invalid_{key}")

    challenge = value.get("challenge")
    if not isinstance(challenge, dict) or challenge.get("status") not in VALID_CHALLENGE:
        errors.append("invalid_challenge")
    moderation = value.get("moderation")
    if not isinstance(moderation, dict) or moderation.get("status") not in VALID_MODERATION:
        errors.append("invalid_moderation")

    return errors


def should_index(mindlink: dict[str, Any]) -> bool:
    rights = mindlink.get("rights") if isinstance(mindlink, dict) else None
    visibility = rights.get("visibility") if isinstance(rights, dict) else None
    return visibility != "only_me" and mindlink.get("state") != "private_draft"


def hash_control_token(token: str) -> str:
    return hashlib.sha256(f"{CONTROL_HASH_PREFIX}{token}".encode("utf-8")).hexdigest()


def valid_control_token(token: Any) -> bool:
    return isinstance(token, str) and token.startswith("control_") and len(token) >= 40


def extract_mindlink_payload(payload: Any) -> tuple[Any, str | None]:
    if isinstance(payload, dict) and "mindlink" in payload:
        control_token = payload.get("control_token")
        return payload.get("mindlink"), control_token if isinstance(control_token, str) else None
    return payload, None


def control_matches(stored_hash: str | None, token: str | None) -> bool:
    if not stored_hash:
        return True
    if not valid_control_token(token):
        return False
    return hmac.compare_digest(stored_hash, hash_control_token(token))

class WorldWideMindStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS mindlinks (
                    id TEXT PRIMARY KEY,
                    visibility TEXT NOT NULL,
                    state TEXT NOT NULL,
                    title TEXT NOT NULL,
                    moderation_status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    body TEXT NOT NULL,
                    control_hash TEXT
                )
                """
            )
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(mindlinks)").fetchall()}
            if "control_hash" not in columns:
                connection.execute("ALTER TABLE mindlinks ADD COLUMN control_hash TEXT")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_mindlinks_visibility ON mindlinks(visibility)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_mindlinks_updated_at ON mindlinks(updated_at)")

    def save_mindlink(self, mindlink: dict[str, Any], control_token: str | None = None) -> dict[str, Any]:
        errors = validate_mindlink(mindlink)
        if errors:
            return {"ok": False, "stored": False, "status": "unprocessable", "errors": errors}
        if not should_index(mindlink):
            try:
                removed = self.remove_mindlink(mindlink["id"], control_token)
            except PermissionError:
                return {"ok": False, "stored": False, "status": "forbidden", "errors": ["invalid_control_token"]}
            return {
                "ok": True,
                "stored": False,
                "removed": removed,
                "reason": PRIVATE_SKIP_REASON,
                "mindlink": mindlink,
            }

        existing = self.get_record(mindlink["id"])
        existing_control_hash = existing["control_hash"] if existing else None
        if existing_control_hash and not control_matches(existing_control_hash, control_token):
            return {"ok": False, "stored": False, "status": "forbidden", "errors": ["invalid_control_token"]}
        if not existing_control_hash and not valid_control_token(control_token):
            return {"ok": False, "stored": False, "status": "unprocessable", "errors": ["missing_control_token"]}

        rights = mindlink["rights"]
        moderation = mindlink["moderation"]
        control_hash = existing_control_hash or hash_control_token(control_token or "")
        body = json.dumps(mindlink, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO mindlinks (
                    id, visibility, state, title, moderation_status,
                    created_at, updated_at, content_hash, body, control_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    visibility=excluded.visibility,
                    state=excluded.state,
                    title=excluded.title,
                    moderation_status=excluded.moderation_status,
                    updated_at=excluded.updated_at,
                    content_hash=excluded.content_hash,
                    body=excluded.body,
                    control_hash=COALESCE(mindlinks.control_hash, excluded.control_hash)
                """,
                (
                    mindlink["id"],
                    rights["visibility"],
                    mindlink["state"],
                    mindlink["title"],
                    moderation["status"],
                    mindlink["created_at"],
                    mindlink["updated_at"],
                    mindlink["content_hash"],
                    body,
                    control_hash,
                ),
            )
        return {"ok": True, "stored": True, "mindlink": mindlink}

    def remove_mindlink(self, mindlink_id: str, control_token: str | None = None) -> bool:
        record = self.get_record(mindlink_id)
        if record is None:
            return False
        if not control_matches(record["control_hash"], control_token):
            raise PermissionError("invalid_control_token")
        with self.connect() as connection:
            cursor = connection.execute("DELETE FROM mindlinks WHERE id = ?", (mindlink_id,))
        return cursor.rowcount > 0

    def list_mindlinks(self, visibility: str | None = None) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[str] = []
        if visibility in {"public", "link"}:
            clauses.append("visibility = ?")
            params.append(visibility)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as connection:
            rows = connection.execute(
                f"SELECT body FROM mindlinks{where} ORDER BY updated_at DESC, id ASC",
                params,
            ).fetchall()
        return [json.loads(row["body"]) for row in rows]

    def get_record(self, mindlink_id: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(
                "SELECT body, control_hash FROM mindlinks WHERE id = ?",
                (mindlink_id,),
            ).fetchone()

    def count_mindlinks(self) -> int:
        with self.connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM mindlinks").fetchone()
        return int(row["count"])

    def get_mindlink(self, mindlink_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT body FROM mindlinks WHERE id = ?", (mindlink_id,)).fetchone()
        return json.loads(row["body"]) if row else None

    def update_mindlink_body(self, mindlink: dict[str, Any]) -> None:
        rights = mindlink["rights"]
        moderation = mindlink["moderation"]
        body = json.dumps(mindlink, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE mindlinks
                SET visibility = ?, state = ?, title = ?, moderation_status = ?,
                    updated_at = ?, content_hash = ?, body = ?
                WHERE id = ?
                """,
                (
                    rights["visibility"],
                    mindlink["state"],
                    mindlink["title"],
                    moderation["status"],
                    mindlink["updated_at"],
                    mindlink["content_hash"],
                    body,
                    mindlink["id"],
                ),
            )

    def report_mindlink(self, mindlink_id: str) -> dict[str, Any] | None:
        mindlink = self.get_mindlink(mindlink_id)
        if mindlink is None:
            return None
        mindlink["moderation"]["status"] = "reported_pending_review"
        mindlink["updated_at"] = now_iso()
        self.update_mindlink_body(mindlink)
        return mindlink

    def record_relation_feedback(self, mindlink_id: str, relation_id: str, feedback: str) -> dict[str, Any] | None:
        if feedback not in VALID_RELATION_FEEDBACK - {"unreviewed"}:
            raise ValueError("invalid_relation_feedback")
        mindlink = self.get_mindlink(mindlink_id)
        if mindlink is None:
            return None
        related = mindlink.get("relations", {}).get("related", [])
        for relation in related:
            if relation.get("id") == relation_id:
                relation["feedback"] = feedback
                mindlink["updated_at"] = now_iso()
                self.update_mindlink_body(mindlink)
                return mindlink
        raise KeyError("relation_not_found")


class WorldWideMindRequestHandler(SimpleHTTPRequestHandler):
    server_version = "WorldWideMindServer/0.1"

    def __init__(self, *args: Any, directory: str, store: WorldWideMindStore, **kwargs: Any):
        self.store = store
        self.site_dir = Path(directory).resolve()
        self.repo_dir = self.site_dir.parent
        super().__init__(*args, directory=directory, **kwargs)

    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        if self.path.startswith("/api/"):
            super().log_message(format, *args)

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def translate_path(self, path: str) -> str:
        parsed_path = unquote(urlparse(path).path)
        public_roots = ("/apps/", "/explorer/", "/protocol/", "/release/")
        if any(parsed_path.startswith(prefix) for prefix in public_roots):
            candidate = (self.repo_dir / parsed_path.lstrip("/")).resolve()
            try:
                candidate.relative_to(self.repo_dir)
            except ValueError:
                return str(self.site_dir / "__not_found__")
            return str(candidate)
        return super().translate_path(path)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/connect":
            try:
                manifest = json.loads((self.site_dir / "connect-manifest.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self.send_json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"ok": False, "errors": ["connect_manifest_unavailable"]},
                )
                return
            self.send_json(HTTPStatus.OK, manifest)
            return
        if parsed.path == "/api/health":
            self.send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "schema": "mindchain/world-wide-mind-server/v0",
                    "mindlinks": self.store.count_mindlinks(),
                    "private_policy": PRIVATE_SKIP_REASON,
                },
            )
            return
        if parsed.path == "/api/mindlinks":
            query = parse_qs(parsed.query)
            visibility = query.get("visibility", [None])[0]
            if visibility not in {None, "all", "public", "link"}:
                self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "errors": ["invalid_visibility_filter"]})
                return
            items = self.store.list_mindlinks(None if visibility in {None, "all"} else visibility)
            self.send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "schema": "mindchain/mindlink-index/v0",
                    "count": len(items),
                    "mindlinks": items,
                },
            )
            return
        if parsed.path.startswith("/api/mindlinks/"):
            mindlink_id = unquote(parsed.path.removeprefix("/api/mindlinks/").strip("/"))
            item = self.store.get_mindlink(mindlink_id)
            if item is None:
                self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "errors": ["mindlink_not_found"]})
                return
            self.send_json(HTTPStatus.OK, {"ok": True, "mindlink": item})
            return
        super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/mindlinks":
            payload = self.read_json_body()
            if payload is None:
                return
            mindlink, control_token = extract_mindlink_payload(payload)
            result = self.store.save_mindlink(mindlink, control_token)
            if not result["ok"]:
                status = HTTPStatus.FORBIDDEN if result.get("status") == "forbidden" else HTTPStatus.UNPROCESSABLE_ENTITY
                self.send_json(status, result)
                return
            self.send_json(HTTPStatus.CREATED if result["stored"] else HTTPStatus.ACCEPTED, result)
            return

        if parsed.path.startswith("/api/mindlinks/") and parsed.path.endswith("/report"):
            mindlink_id = unquote(parsed.path.removeprefix("/api/mindlinks/")[: -len("/report")].strip("/"))
            updated = self.store.report_mindlink(mindlink_id)
            if updated is None:
                self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "errors": ["mindlink_not_found"]})
                return
            self.send_json(HTTPStatus.OK, {"ok": True, "mindlink": updated})
            return

        if parsed.path.startswith("/api/mindlinks/") and parsed.path.endswith("/relation-feedback"):
            mindlink_id = unquote(parsed.path.removeprefix("/api/mindlinks/")[: -len("/relation-feedback")].strip("/"))
            payload = self.read_json_body()
            if payload is None:
                return
            try:
                updated = self.store.record_relation_feedback(
                    mindlink_id,
                    str(payload.get("relation_id", "")),
                    str(payload.get("feedback", "")),
                )
            except KeyError as error:
                self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "errors": [str(error)]})
                return
            except ValueError as error:
                self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "errors": [str(error)]})
                return
            if updated is None:
                self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "errors": ["mindlink_not_found"]})
                return
            self.send_json(HTTPStatus.OK, {"ok": True, "mindlink": updated})
            return

        self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "errors": ["api_route_not_found"]})

    def read_json_body(self) -> Any | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "errors": ["invalid_content_length"]})
            return None
        if length <= 0:
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "errors": ["empty_body"]})
            return None
        if length > MAX_REQUEST_BYTES:
            self.send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"ok": False, "errors": ["body_too_large"]})
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "errors": ["invalid_json"]})
            return None

    def send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def make_handler(site_dir: Path, store: WorldWideMindStore) -> type[WorldWideMindRequestHandler]:
    class Handler(WorldWideMindRequestHandler):
        def __init__(self, *args: Any, **kwargs: Any):
            super().__init__(*args, directory=str(site_dir), store=store, **kwargs)

    return Handler


def serve(host: str, port: int, site_dir: Path, data_dir: Path) -> ThreadingHTTPServer:
    store = WorldWideMindStore(data_dir / "mindlinks.sqlite3")
    handler = make_handler(site_dir, store)
    return ThreadingHTTPServer((host, port), handler)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--site-dir", type=Path, default=Path(__file__).resolve().parent.parent / "site")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path(tempfile.gettempdir()) / "noosphere-world-wide-mind",
        help="Directory for the local SQLite MindLink index.",
    )
    args = parser.parse_args()
    site_dir = args.site_dir.resolve()
    if not site_dir.exists():
        raise SystemExit(f"site directory does not exist: {site_dir}")
    httpd = serve(args.host, args.port, site_dir, args.data_dir.resolve())
    print(f"World Wide Mind server on http://{args.host}:{args.port}/")
    print(f"MindLink API data: {args.data_dir.resolve()}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
