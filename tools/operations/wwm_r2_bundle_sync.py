from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

MAX_OBJECTS: Final[int] = 5_500
MAX_BUNDLE_BYTES: Final[int] = 6 * 1024 * 1024 * 1024
SHARE_BYTES: Final[int] = 1_047_552
EXPECTED_BUCKET: Final[str] = "mindchain-wwm-artifacts-pilot"


class SyncError(RuntimeError):
    pass


@dataclass(frozen=True)
class ObjectSpec:
    key: str
    path: Path
    size: int
    sha256: str
    content_type: str
    cache_control: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def fixed_object(root: Path, key: str, content_type: str, cache_control: str) -> ObjectSpec:
    path = (root / key).resolve(strict=True)
    if root not in path.parents or not path.is_file() or path.is_symlink():
        raise SyncError(f"bundle object is not a regular in-root file: {key}")
    size = path.stat().st_size
    return ObjectSpec(key, path, size, sha256_file(path), content_type, cache_control)


def load_bundle(root_value: Path) -> list[ObjectSpec]:
    root = root_value.resolve(strict=True)
    if not root.is_dir():
        raise SyncError("bundle root must be a directory")
    objects = [
        fixed_object(
            root,
            ".well-known/noos/wwm-web-capacity-v1.json",
            "application/json",
            "public, max-age=60, must-revalidate",
        ),
        fixed_object(
            root,
            "inventory-v1.json",
            "application/json",
            "public, max-age=0, no-cache, must-revalidate",
        ),
        fixed_object(root, "LICENSE.txt", "text/plain; charset=utf-8", "public, max-age=31536000, immutable"),
        fixed_object(root, "NOTICE.txt", "text/plain; charset=utf-8", "public, max-age=31536000, immutable"),
    ]
    inventory = json.loads((root / "inventory-v1.json").read_bytes())
    rows = inventory.get("rows") if isinstance(inventory, dict) else None
    if not isinstance(rows, list) or not 1 <= len(rows) <= 5_448:
        raise SyncError("inventory rows are missing or out of bounds")
    coordinates: set[tuple[int, int]] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise SyncError("inventory row must be an object")
        stripe = row.get("stripe")
        position = row.get("position")
        size = row.get("bytes")
        transport_sha256 = row.get("transport_sha256")
        if (
            not isinstance(stripe, int)
            or isinstance(stripe, bool)
            or not 0 <= stripe < 1_000_000
            or not isinstance(position, int)
            or isinstance(position, bool)
            or not 0 <= position <= 11
            or size != SHARE_BYTES
            or not isinstance(transport_sha256, str)
            or len(transport_sha256) != 64
            or any(character not in "0123456789abcdef" for character in transport_sha256)
        ):
            raise SyncError("inventory row has invalid coordinate, length, or transport digest")
        coordinate = (stripe, position)
        if coordinate in coordinates:
            raise SyncError("inventory contains a duplicate coordinate")
        coordinates.add(coordinate)
        key = f"shares/{stripe:06}/{position:02}.share"
        path = (root / key).resolve(strict=True)
        if root not in path.parents or not path.is_file() or path.is_symlink() or path.stat().st_size != SHARE_BYTES:
            raise SyncError(f"inventory share is missing or malformed: {key}")
        objects.append(
            ObjectSpec(
                key,
                path,
                SHARE_BYTES,
                transport_sha256,
                "application/octet-stream",
                "public, max-age=31536000, immutable, no-transform",
            )
        )
    if len(objects) > MAX_OBJECTS:
        raise SyncError("bundle exceeds object count bound")
    total_bytes = sum(item.size for item in objects)
    if total_bytes > MAX_BUNDLE_BYTES:
        raise SyncError("bundle exceeds byte bound")
    return objects


def load_credentials(path: Path) -> dict[str, str]:
    document = json.loads(path.resolve(strict=True).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise SyncError("credential file must contain a JSON object")
    required = ("access_key_id", "secret_access_key", "s3_endpoint", "bucket")
    if any(not isinstance(document.get(key), str) or not document[key].strip() for key in required):
        raise SyncError("credential file is missing a required string")
    if document["bucket"] != EXPECTED_BUCKET:
        raise SyncError("credential bucket does not match the dedicated pilot bucket")
    if not document["s3_endpoint"].startswith("https://"):
        raise SyncError("R2 endpoint must be HTTPS")
    return {key: document[key] for key in required}


def head(client: object, bucket: str, item: ObjectSpec) -> str:
    try:
        response = client.head_object(Bucket=bucket, Key=item.key)
    except Exception as error:  # botocore is an optional runtime dependency
        code = getattr(error, "response", {}).get("Error", {}).get("Code")
        if code in {"404", "NoSuchKey", "NotFound"}:
            return "missing"
        raise SyncError(f"head failed for {item.key}: {code or type(error).__name__}") from error
    metadata = response.get("Metadata") or {}
    if (
        response.get("ContentLength") != item.size
        or metadata.get("sha256") != item.sha256
        or response.get("CacheControl") != item.cache_control
        or response.get("ContentType") != item.content_type
    ):
        raise SyncError(f"immutable remote object conflicts with local bundle: {item.key}")
    return "present"


def sync_one(client: object, bucket: str, item: ObjectSpec) -> str:
    if head(client, bucket, item) == "present":
        return "skipped"
    with item.path.open("rb") as body:
        try:
            client.put_object(
                Bucket=bucket,
                Key=item.key,
                Body=body,
                ContentLength=item.size,
                ContentType=item.content_type,
                CacheControl=item.cache_control,
                Metadata={"sha256": item.sha256},
            )
        except Exception as error:
            code = getattr(error, "response", {}).get("Error", {}).get("Code")
            raise SyncError(f"upload failed for {item.key}: {code or type(error).__name__}") from error
    if head(client, bucket, item) != "present":
        raise SyncError(f"uploaded object could not be verified: {item.key}")
    return "uploaded"


def run(args: argparse.Namespace) -> dict[str, object]:
    try:
        import boto3
        from botocore.config import Config
    except ImportError as error:
        raise SyncError("boto3 is required in the isolated uploader environment") from error
    credentials = load_credentials(args.credentials)
    objects = load_bundle(args.bundle_root)
    if not 1 <= args.workers <= 16:
        raise SyncError("workers must be within 1..16")
    client = boto3.client(
        "s3",
        endpoint_url=credentials["s3_endpoint"],
        aws_access_key_id=credentials["access_key_id"],
        aws_secret_access_key=credentials["secret_access_key"],
        region_name="auto",
        config=Config(
            signature_version="s3v4",
            max_pool_connections=args.workers,
            retries={"max_attempts": 8, "mode": "adaptive"},
        ),
    )
    bucket = credentials["bucket"]
    started = int(time.time())
    counts = {"uploaded": 0, "skipped": 0}
    uploaded_bytes = 0
    lock = threading.Lock()

    def one(item: ObjectSpec) -> tuple[str, int]:
        outcome = sync_one(client, bucket, item)
        return outcome, item.size if outcome == "uploaded" else 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(one, item): item.key for item in objects}
        try:
            for index, future in enumerate(concurrent.futures.as_completed(futures), start=1):
                outcome, byte_count = future.result()
                with lock:
                    counts[outcome] += 1
                    uploaded_bytes += byte_count
                if index % 100 == 0 or index == len(objects):
                    print(
                        json.dumps(
                            {
                                "event": "progress",
                                "completed": index,
                                "total": len(objects),
                                "uploaded": counts["uploaded"],
                                "skipped": counts["skipped"],
                            },
                            sort_keys=True,
                        ),
                        flush=True,
                    )
        except Exception:
            for future in futures:
                future.cancel()
            raise
    report = {
        "schema": "noos/wwm-r2-static-bundle-sync/v1",
        "environment": "public-testnet",
        "production": False,
        "production_custody": False,
        "rewards": False,
        "bucket": bucket,
        "object_count": len(objects),
        "bundle_bytes": sum(item.size for item in objects),
        "uploaded_objects": counts["uploaded"],
        "skipped_objects": counts["skipped"],
        "uploaded_bytes": uploaded_bytes,
        "started_at": started,
        "completed_at": int(time.time()),
        "verdict": "PASS",
    }
    report_path = args.report.resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    if report_path.exists():
        raise SyncError("report path already exists")
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Idempotently sync a verified WWM static bundle to a private R2 bucket")
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=8)
    return parser.parse_args()


def main() -> int:
    try:
        print(json.dumps(run(parse_args()), sort_keys=True), flush=True)
        return 0
    except (OSError, SyncError, ValueError) as error:
        print(f"R2 bundle sync failed: {error}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
