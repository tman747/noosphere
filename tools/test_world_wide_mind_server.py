import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import world_wide_mind_server


class WorldWideMindServerTests(unittest.TestCase):
    def sample_mindlink(self, visibility="public"):
        state = "public" if visibility == "public" else "unlisted" if visibility == "link" else "private_draft"
        return {
            "mindlink_version": "0.1",
            "id": f"https://mindchain.network/test/{visibility}",
            "type": "claim",
            "title": f"Sample {visibility} MindLink",
            "language": "en",
            "content": {
                "original_text": "Local archives should preserve community corrections.",
                "summary": "Local archives should preserve community corrections.",
            },
            "authority": {"contributor": "anonymous", "community": None},
            "provenance": {"sources": [], "derived_from": []},
            "rights": {
                "visibility": visibility,
                "ai_training": "deny",
                "commercial_use": "deny",
                "license": "conservative-default",
                "cultural_authority": None,
            },
            "relations": {
                "related": [
                    {
                        "id": "community-controlled-archives",
                        "title": "Community-controlled archives",
                        "reason": "Connected because both concern local knowledge authority.",
                        "feedback": "unreviewed",
                    }
                ],
                "supports": [],
                "contradicts": [],
                "translates": [],
                "extends": [],
            },
            "challenge": {"status": "unchallenged"},
            "moderation": {"status": "not_reported"},
            "state": state,
            "created_at": "2026-07-13T00:00:00.000Z",
            "updated_at": "2026-07-13T00:00:00.000Z",
            "content_hash": "1234567890abcdef",
        }

    def test_public_and_link_mindlinks_are_indexed(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = world_wide_mind_server.WorldWideMindStore(Path(tmp) / "mindlinks.sqlite3")
            public_result = store.save_mindlink(self.sample_mindlink("public"))
            link_result = store.save_mindlink(self.sample_mindlink("link"))
            self.assertTrue(public_result["stored"])
            self.assertTrue(link_result["stored"])
            self.assertEqual(len(store.list_mindlinks()), 2)
            self.assertEqual(len(store.list_mindlinks("public")), 1)
            self.assertEqual(store.list_mindlinks("public")[0]["rights"]["visibility"], "public")

    def test_private_drafts_are_not_persisted_to_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = world_wide_mind_server.WorldWideMindStore(Path(tmp) / "mindlinks.sqlite3")
            result = store.save_mindlink(self.sample_mindlink("only_me"))
            self.assertTrue(result["ok"])
            self.assertFalse(result["stored"])
            self.assertFalse(result["removed"])
            self.assertEqual(result["reason"], "private_draft_not_indexed")
            self.assertEqual(store.list_mindlinks(), [])

    def test_private_update_removes_previously_indexed_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = world_wide_mind_server.WorldWideMindStore(Path(tmp) / "mindlinks.sqlite3")
            public = self.sample_mindlink("public")
            private = self.sample_mindlink("only_me")
            private["id"] = public["id"]
            store.save_mindlink(public)
            result = store.save_mindlink(private)
            self.assertFalse(result["stored"])
            self.assertTrue(result["removed"])
            self.assertEqual(store.list_mindlinks(), [])

    def test_report_and_relation_feedback_update_stored_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = world_wide_mind_server.WorldWideMindStore(Path(tmp) / "mindlinks.sqlite3")
            mindlink = self.sample_mindlink("public")
            store.save_mindlink(mindlink)
            reported = store.report_mindlink(mindlink["id"])
            self.assertEqual(reported["moderation"]["status"], "reported_pending_review")
            updated = store.record_relation_feedback(
                mindlink["id"],
                "community-controlled-archives",
                "user_requested_map_review",
            )
            self.assertEqual(updated["relations"]["related"][0]["feedback"], "user_requested_map_review")

    def test_http_api_persists_public_and_skips_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "site").mkdir()
            (root / "site" / "index.html").write_text("<h1>World Wide Mind</h1>", encoding="utf-8")
            server = world_wide_mind_server.serve(
                "127.0.0.1",
                0,
                root / "site",
                root / "data",
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                public = self.post_json(f"{base}/api/mindlinks", self.sample_mindlink("public"))
                private = self.post_json(f"{base}/api/mindlinks", self.sample_mindlink("only_me"))
                index = self.get_json(f"{base}/api/mindlinks")
                self.assertTrue(public["stored"])
                self.assertFalse(private["stored"])
                self.assertEqual(index["count"], 1)
                self.assertEqual(index["mindlinks"][0]["rights"]["visibility"], "public")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def post_json(self, url, payload):
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)

    def get_json(self, url):
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)


if __name__ == "__main__":
    unittest.main()
