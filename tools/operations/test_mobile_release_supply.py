from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.operations import mobile_release_supply as supply


class MobileReleaseSupplyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.revision = "71" * 20
        self.inputs = self.make_inputs()

    def subject(self, root: Path, relative: str, content: bytes) -> dict[str, object]:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return {
            "path": f"wallet/mobile/{relative}",
            "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }

    def binding(self, label: str, platform: str, *, variant: bytes = b"") -> Path:
        root = self.root / label
        root.mkdir(exist_ok=True)
        if platform == "android":
            rows = [
                self.subject(root, "android/core/src/main/java/core.kt", b"kotlin" + variant),
                self.subject(root, "android/core/src/main/jniLibs/arm64/libwallet.so", b"so"),
                self.subject(root, "android/app/build/outputs/apk/release/app.apk", b"apk"),
                self.subject(root, "android/core/build/outputs/aar/core.aar", b"aar"),
            ]
        else:
            rows = [
                self.subject(root, "ios/CoreBindings/Core.swift", b"swift"),
                self.subject(root, "ios/CoreBindings/Core.h", b"header"),
                self.subject(root, "ios/Artifacts/Core.xcframework/ios/libwallet.a", b"archive"),
            ]
        manifest = {
            "schema": "noos/mobile-wallet-bindings/v2",
            "platform": platform,
            "profile": "release",
            "crate": "noos-wallet-sdk",
            "crate_version": "0.1.0",
            "source_revision": self.revision,
            "release_version": f"0.1.0+git.{self.revision}",
            "files": rows,
        }
        path = root / f"{platform}-bindings.manifest.json"
        path.write_bytes(supply.canonical_json(manifest) + b"\n")
        return root

    def make_inputs(self) -> dict[str, Path]:
        android_linux = self.binding("android-linux", "android")
        android_windows = self.binding("android-windows", "android", variant=b"-windows")
        ios = self.binding("ios", "ios")
        native_windows = self.root / "native-windows"
        native_windows.mkdir(exist_ok=True)
        (native_windows / "bin").mkdir(exist_ok=True)
        (native_windows / "bin" / "noosd.exe").write_bytes(b"windows")
        native_macos = self.root / "native-macos"
        native_macos.mkdir(exist_ok=True)
        (native_macos / "bin").mkdir(exist_ok=True)
        (native_macos / "bin" / "noosd").write_bytes(b"macos")
        return {
            "android-linux": android_linux,
            "android-windows": android_windows,
            "ios": ios,
            "native-windows": native_windows,
            "native-macos": native_macos,
        }

    def test_seals_exact_subjects_and_records_unnormalized_differences(self) -> None:
        output = self.root / "release"
        document = supply.seal(self.inputs, output, self.revision)
        body = supply.verify(output / "subject-manifest.json", output / "SHA256SUMS")
        self.assertEqual(body["manifest_id"], document["body"]["manifest_id"])
        comparison = body["android_cross_builder_comparison"]
        self.assertFalse(comparison["all_subjects_equal"])
        self.assertFalse(comparison["independent_builders"])
        self.assertFalse(comparison["normalized"])
        self.assertEqual(set(body["binding_manifests"]), {"android-linux", "android-windows", "ios"})

    def test_rejects_missing_manifested_subject_and_wrong_revision(self) -> None:
        missing = self.inputs["ios"] / "ios" / "CoreBindings" / "Core.h"
        missing.unlink()
        with self.assertRaisesRegex(supply.SupplyError, "manifested subject"):
            supply.seal(self.inputs, self.root / "missing", self.revision)

        self.inputs = self.make_inputs()
        manifest_path = self.inputs["android-linux"] / "android-bindings.manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["source_revision"] = "aa" * 20
        manifest_path.write_bytes(supply.canonical_json(manifest) + b"\n")
        with self.assertRaisesRegex(supply.SupplyError, "identity"):
            supply.seal(self.inputs, self.root / "wrong", self.revision)

    def test_checksum_verifier_rejects_tampering(self) -> None:
        output = self.root / "release-tamper"
        supply.seal(self.inputs, output, self.revision)
        sums = output / "SHA256SUMS"
        sums.write_text(sums.read_text().replace("  ", " ", 1), encoding="ascii")
        with self.assertRaisesRegex(supply.SupplyError, "does not exactly cover"):
            supply.verify(output / "subject-manifest.json", sums)

        document = json.loads((output / "subject-manifest.json").read_text())
        tampered = copy.deepcopy(document)
        tampered["body"]["production"] = True
        (output / "subject-manifest.json").write_bytes(supply.canonical_json(tampered) + b"\n")
        with self.assertRaisesRegex(supply.SupplyError, "identity|assurance boundary"):
            supply.verify(output / "subject-manifest.json", output / "SHA256SUMS")


if __name__ == "__main__":
    unittest.main()
