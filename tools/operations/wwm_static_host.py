#!/usr/bin/env python3
"""Prepare owner authorization and register a deployed WWM static host safely."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SCHEMA = "noos/wwm-web-capacity/v1"
MEDIA_TYPE = "application/vnd.noos.wwm-web-capacity.v1+json"
REGISTER_PATH = "/api/wwm-web-capacity/v1/hosts"
MAX_RESPONSE_BYTES = 64 * 1024
INVENTORY_CACHE_CONTROL = "public, max-age=0, no-cache, must-revalidate"
MANIFEST_CACHE_MAX_AGE_SECONDS = 60


def cache_control_directives(value: str) -> dict[str, str | None]:
    directives: dict[str, str | None] = {}
    for raw_directive in value.split(","):
        directive = raw_directive.strip().lower()
        if not directive:
            continue
        name, separator, argument = directive.partition("=")
        if name in directives:
            raise StaticHostError(f"duplicate Cache-Control directive: {name}")
        directives[name] = argument if separator else None
    return directives


def validate_recipe_cache_controls(
    *,
    manifest: str,
    inventory: str,
    license_and_notice: str,
    shares: str,
) -> None:
    parsed = {
        "manifest": cache_control_directives(manifest),
        "inventory": cache_control_directives(inventory),
        "license_and_notice": cache_control_directives(license_and_notice),
        "shares": cache_control_directives(shares),
    }
    manifest_max_age = parsed["manifest"].get("max-age")
    if (
        "must-revalidate" not in parsed["manifest"]
        or manifest_max_age is None
        or not manifest_max_age.isdecimal()
        or int(manifest_max_age) > MANIFEST_CACHE_MAX_AGE_SECONDS
        or "immutable" in parsed["manifest"]
        or "no-store" in parsed["manifest"]
    ):
        raise StaticHostError("manifest cache policy must revalidate within 60 seconds")
    inventory_directives = parsed["inventory"]
    if (
        inventory_directives.get("max-age") != "0"
        or "no-cache" not in inventory_directives
        or "must-revalidate" not in inventory_directives
        or "immutable" in inventory_directives
        or "no-store" in inventory_directives
    ):
        raise StaticHostError(
            "inventory cache policy must be public, storable, and revalidated on every use"
        )
    for label in ("license_and_notice", "shares"):
        directives = parsed[label]
        if (
            "public" not in directives
            or "immutable" not in directives
            or directives.get("max-age") != "31536000"
            or "no-cache" in directives
            or "no-store" in directives
        ):
            raise StaticHostError(f"{label} cache policy must remain one-year immutable")


class StaticHostError(RuntimeError):
    """A deployment input or coordinator response violated the contract."""


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        raise StaticHostError(f"redirect response is forbidden: status={code} target={newurl}")


def canonical_origin(value: str, *, allow_http_loopback: bool = False) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise StaticHostError(f"invalid origin: {error}") from error
    if parsed.username is not None or parsed.password is not None:
        raise StaticHostError("origin must not contain credentials")
    if parsed.path or parsed.query or parsed.fragment or not parsed.hostname:
        raise StaticHostError("origin must contain only scheme and authority")
    host = parsed.hostname
    try:
        host.encode("ascii")
    except UnicodeEncodeError as error:
        raise StaticHostError("origin host must use canonical ASCII/IDNA form") from error
    host = host.lower()
    loopback = host == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if parsed.scheme != "https" and not (
        allow_http_loopback and parsed.scheme == "http" and loopback
    ):
        raise StaticHostError("origin must use HTTPS")
    if (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80):
        raise StaticHostError("origin must omit its default port")
    authority = f"[{host}]" if ":" in host else host
    canonical = f"{parsed.scheme}://{authority}"
    if port is not None:
        canonical = f"{canonical}:{port}"
    if value != canonical or len(value) > 253:
        raise StaticHostError("origin must be canonical lowercase with no trailing slash")
    return canonical


def bounded_text(value: str, label: str) -> str:
    if not value or len(value.encode("utf-8")) > 128:
        raise StaticHostError(f"{label} must contain 1..=128 UTF-8 bytes")
    return value


def source_record(origin: str, provider: str, region: str, control_cluster: str) -> dict[str, str]:
    return {
        "origin": canonical_origin(origin),
        "provider": bounded_text(provider, "provider"),
        "region": bounded_text(region, "region"),
        "control_cluster": bounded_text(control_cluster, "control_cluster"),
    }


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def write_new_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as error:
        raise StaticHostError(f"refusing to overwrite existing output: {path}") from error


def is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def validate_registration_response(
    value: Any,
    *,
    host_origin: str,
    now: int,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StaticHostError("coordinator registration response must be a JSON object")
    required = {
        "schema",
        "record_kind",
        "host_id",
        "canonical_origin",
        "participant_class",
        "admission_class",
        "inventory_root",
        "verified_rows",
        "expires_at",
        "production_custody",
        "rewards",
    }
    if set(value) != required:
        raise StaticHostError("coordinator registration response has unexpected fields")
    if (
        value["schema"] != SCHEMA
        or value["record_kind"] != "HOST_REGISTRATION_RESPONSE"
        or value["canonical_origin"] != host_origin
        or value["participant_class"] != "STATIC_HOST_SEEDER"
        or value["admission_class"] != "StatelessReissueable"
        or value["production_custody"] is not False
        or value["rewards"] is not False
        or not is_hex(value["host_id"], 64)
        or not is_hex(value["inventory_root"], 64)
        or not isinstance(value["verified_rows"], int)
        or isinstance(value["verified_rows"], bool)
        or not 1 <= value["verified_rows"] <= 5_448
        or not isinstance(value["expires_at"], int)
        or isinstance(value["expires_at"], bool)
        or value["expires_at"] <= now
    ):
        raise StaticHostError("coordinator registration response violates the static host contract")
    return value


def register_host(
    coordinator_origin: str,
    request_origin: str,
    host_origin: str,
    *,
    timeout_seconds: float,
    allow_http_loopback: bool = False,
) -> dict[str, Any]:
    coordinator = canonical_origin(
        coordinator_origin,
        allow_http_loopback=allow_http_loopback,
    )
    request_origin = canonical_origin(request_origin)
    host_origin = canonical_origin(host_origin)
    if not 0.1 <= timeout_seconds <= 120:
        raise StaticHostError("timeout must be within 0.1..=120 seconds")
    payload = canonical_json(
        {
            "schema": SCHEMA,
            "record_kind": "HOST_REGISTRATION_REQUEST",
            "canonical_origin": host_origin,
        }
    )
    request = urllib.request.Request(
        f"{coordinator}{REGISTER_PATH}",
        data=payload,
        method="POST",
        headers={
            "Accept": MEDIA_TYPE,
            "Content-Type": "application/json",
            "Origin": request_origin,
            "User-Agent": "noos-wwm-static-host-operator/1",
        },
    )
    opener = urllib.request.build_opener(RejectRedirects())
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            status = response.status
            content_type = response.headers.get_content_type()
            cors_origin = response.headers.get("Access-Control-Allow-Origin")
            cache_control = response.headers.get("Cache-Control", "")
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except StaticHostError:
        raise
    except urllib.error.HTTPError as error:
        detail = error.read(MAX_RESPONSE_BYTES).decode("utf-8", errors="replace")
        raise StaticHostError(f"coordinator rejected registration: status={error.code} body={detail}") from error
    except urllib.error.URLError as error:
        raise StaticHostError(f"coordinator registration request failed: {error.reason}") from error
    if status != 201:
        raise StaticHostError(f"coordinator returned unexpected status {status}")
    if content_type != MEDIA_TYPE:
        raise StaticHostError(f"coordinator returned unexpected content type {content_type}")
    if cors_origin != request_origin:
        raise StaticHostError("coordinator did not return the exact registered request origin")
    if "no-store" not in {item.strip() for item in cache_control.split(",")}:
        raise StaticHostError("coordinator registration response is not marked no-store")
    if len(body) > MAX_RESPONSE_BYTES:
        raise StaticHostError("coordinator registration response exceeds 64 KiB")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StaticHostError(f"coordinator returned invalid JSON: {error}") from error
    verified = validate_registration_response(value, host_origin=host_origin, now=int(time.time()))
    return {
        "schema": "noos/wwm-web-static-host-registration-command/v1",
        "coordinator_origin": coordinator,
        "request_origin": request_origin,
        "host_origin": host_origin,
        "redirects_followed": False,
        "credentials_sent": False,
        "coordinator_verification": verified,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare and verify an owner-authorized WWM static host"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    source = subparsers.add_parser(
        "source-record",
        help="render one exact source_allowlist record without editing coordinator config",
    )
    source.add_argument("--origin", required=True)
    source.add_argument("--provider", required=True)
    source.add_argument("--region", required=True)
    source.add_argument("--control-cluster", required=True)
    source.add_argument("--output", type=Path)

    register = subparsers.add_parser(
        "register",
        help="ask the coordinator to verify and register an already authorized host",
    )
    register.add_argument("--coordinator-origin", required=True)
    register.add_argument("--request-origin", required=True)
    register.add_argument("--host-origin", required=True)
    register.add_argument("--timeout-seconds", type=float, default=15.0)
    register.add_argument(
        "--allow-http-loopback",
        action="store_true",
        help="local fixtures only; relaxes coordinator transport, never request or host Origin",
    )
    register.add_argument("--output", type=Path)
    return parser


def emit(value: Any, output: Path | None) -> None:
    if output is not None:
        write_new_json(output, value)
    print(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "source-record":
            value = source_record(
                args.origin,
                args.provider,
                args.region,
                args.control_cluster,
            )
        elif args.command == "register":
            value = register_host(
                args.coordinator_origin,
                args.request_origin,
                args.host_origin,
                timeout_seconds=args.timeout_seconds,
                allow_http_loopback=args.allow_http_loopback,
            )
        else:
            raise StaticHostError(f"unsupported command {args.command}")
        emit(value, args.output)
        return 0
    except StaticHostError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
