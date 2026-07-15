from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.operations import wwm_r2_bundle_sync as sync


class MissingObject(RuntimeError):
    response = {"Error": {"Code": "404"}}


class FakeS3Client:
    def __init__(self) -> None:
        self.objects: dict[str, dict[str, object]] = {}
        self.put_calls = 0

    def head_object(self, *, Bucket: str, Key: str) -> dict[str, object]:
        del Bucket
        try:
            stored = self.objects[Key]
        except KeyError as error:
            raise MissingObject(Key) from error
        return {
            "ContentLength": len(stored["body"]),
            "ContentType": stored["content_type"],
            "CacheControl": stored["cache_control"],
            "Metadata": stored["metadata"],
        }

    def put_object(
        self,
        *,
        Bucket: str,
        Key: str,
        Body: object,
        ContentLength: int,
        ContentType: str,
        CacheControl: str,
        Metadata: dict[str, str],
    ) -> None:
        del Bucket
        payload = Body.read()
        if len(payload) != ContentLength:
            raise AssertionError("declared content length did not match upload body")
        self.put_calls += 1
        self.objects[Key] = {
            "body": payload,
            "content_type": ContentType,
            "cache_control": CacheControl,
            "metadata": dict(Metadata),
        }


class R2BundleSyncTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / ".well-known" / "noos").mkdir(parents=True)
        (self.root / "shares" / "000000").mkdir(parents=True)
        (self.root / ".well-known" / "noos" / "wwm-web-capacity-v1.json").write_text(
            '{"schema":"fixture"}\n', encoding="utf-8"
        )
        (self.root / "LICENSE.txt").write_text("Apache-2.0\n", encoding="utf-8")
        (self.root / "NOTICE.txt").write_text("fixture\n", encoding="utf-8")
        self.share = b"x" * sync.SHARE_BYTES
        self.share_digest = hashlib.sha256(self.share).hexdigest()
        (self.root / "shares" / "000000" / "00.share").write_bytes(self.share)
        self.inventory = {
            "rows": [
                {
                    "stripe": 0,
                    "position": 0,
                    "bytes": sync.SHARE_BYTES,
                    "transport_sha256": self.share_digest,
                }
            ]
        }
        self.write_inventory()

    def write_inventory(self) -> None:
        (self.root / "inventory-v1.json").write_text(
            json.dumps(self.inventory, sort_keys=True) + "\n", encoding="utf-8"
        )

    def test_bundle_inventory_drives_bounded_object_specs(self) -> None:
        objects = sync.load_bundle(self.root)
        self.assertEqual(len(objects), 5)
        share = next(item for item in objects if item.key.endswith(".share"))
        self.assertEqual(share.size, sync.SHARE_BYTES)
        self.assertEqual(share.sha256, self.share_digest)
        self.assertEqual(share.content_type, "application/octet-stream")
        self.assertEqual(share.cache_control, "public, max-age=31536000, immutable, no-transform")

    def test_sync_is_idempotent_and_rejects_immutable_conflicts(self) -> None:
        item = next(item for item in sync.load_bundle(self.root) if item.key.endswith(".share"))
        client = FakeS3Client()

        self.assertEqual(sync.sync_one(client, sync.EXPECTED_BUCKET, item), "uploaded")
        self.assertEqual(sync.sync_one(client, sync.EXPECTED_BUCKET, item), "skipped")
        self.assertEqual(client.put_calls, 1)
        client.objects[item.key]["cache_control"] = "no-store"
        with self.assertRaisesRegex(sync.SyncError, "immutable remote object conflicts"):
            sync.sync_one(client, sync.EXPECTED_BUCKET, item)

    def test_invalid_inventory_digest_is_rejected_before_upload(self) -> None:
        self.inventory["rows"][0]["transport_sha256"] = "not-a-digest"
        self.write_inventory()
        with self.assertRaisesRegex(sync.SyncError, "invalid coordinate, length, or transport digest"):
            sync.load_bundle(self.root)


if __name__ == "__main__":
    unittest.main()
