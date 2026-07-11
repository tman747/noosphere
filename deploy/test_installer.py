import base64, hashlib, json, platform, shutil, tempfile, unittest, zipfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import installer

class InstallerContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name); self.install = self.root / "install"; self.state = self.root / "state"
        self.install.mkdir(); (self.install / "version").write_text("prior", "utf-8")
        self.identity = {"chain_id":"a"*64,"genesis_hash":"b"*64,"api_version":"v1"}
        self.key = Ed25519PrivateKey.generate(); self.public = self.key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    def tearDown(self): self.temp.cleanup()
    def build(self, corrupt=False):
        payload = self.root / "payload"; payload.mkdir(exist_ok=True)
        descriptor = payload / "descriptor.json"; descriptor.write_text(json.dumps(self.identity, sort_keys=True), "utf-8")
        genesis = payload / "genesis.bin"; genesis.write_bytes(b"NOOS genesis")
        (payload / "version").write_text("new", "utf-8")
        artifact = self.root / "artifact.zip"
        with zipfile.ZipFile(artifact,"w") as archive:
            for entry in payload.iterdir(): archive.write(entry, entry.name)
        sha=lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
        manifest={"app":"noosd","chain_id":self.identity["chain_id"],"genesis_hash":self.identity["genesis_hash"],"api_version":"v1","platform":platform.system().lower(),"arch":platform.machine().lower().replace("amd64","x86_64").replace("arm64","aarch64"),"version":"0.1.0","artifact_sha256":sha(artifact),"descriptor_sha256":sha(descriptor),"genesis_sha256":sha(genesis)}
        manifest["signature"] = base64.b64encode(self.key.sign(installer._canonical(manifest))).decode()
        path=self.root/"manifest.json"; path.write_text(json.dumps(manifest),"utf-8")
        if corrupt: artifact.write_bytes(artifact.read_bytes()[:-5])
        return path,artifact
    def assert_prior(self): self.assertEqual((self.install/"version").read_text("utf-8"),"prior")
    def test_corrupt_artifact_preserves_prior(self):
        manifest,artifact=self.build(corrupt=True)
        with self.assertRaisesRegex(installer.InstallError,"bad_checksum"): installer.install(manifest,artifact,self.install,self.state,self.public,self.identity)
        self.assert_prior()
    def test_bad_identity_preserves_prior(self):
        manifest,artifact=self.build(); wrong={**self.identity,"chain_id":"c"*64}
        with self.assertRaisesRegex(installer.InstallError,"wrong_protocol_identity"): installer.install(manifest,artifact,self.install,self.state,self.public,wrong)
        self.assert_prior()
    def test_interruption_after_prior_move_rolls_back(self):
        manifest,artifact=self.build()
        def interrupt(stage):
            if stage=="prior_moved": raise RuntimeError("simulated interruption")
        with self.assertRaisesRegex(RuntimeError,"simulated interruption"): installer.install(manifest,artifact,self.install,self.state,self.public,self.identity,interrupt)
        self.assert_prior()
    def test_bad_signature_preserves_prior(self):
        manifest,artifact=self.build(); data=json.loads(manifest.read_text()); data["signature"]=base64.b64encode(b"x"*64).decode(); manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(installer.InstallError,"bad_signature"): installer.install(manifest,artifact,self.install,self.state,self.public,self.identity)
        self.assert_prior()

if __name__ == "__main__": unittest.main()
