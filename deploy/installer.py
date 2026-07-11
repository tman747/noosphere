"""Signed, identity-bound MindChain artifact installer with atomic rollback."""
from __future__ import annotations
import base64, hashlib, json, os, platform, shutil, tempfile
from pathlib import Path
from typing import Callable

class InstallError(RuntimeError): pass

def _canonical(manifest: dict) -> bytes:
    unsigned = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()

def verify_ed25519(manifest: dict, public_key_pem: bytes) -> None:
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        signature = base64.b64decode(manifest["signature"], validate=True)
        load_pem_public_key(public_key_pem).verify(signature, _canonical(manifest))
    except Exception as exc:
        raise InstallError("bad_signature") from exc

def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _inside(child: Path, parent: Path) -> bool:
    try: child.resolve().relative_to(parent.resolve()); return True
    except ValueError: return False

def install(manifest_path: Path, artifact_path: Path, install_root: Path, state_root: Path,
            public_key_pem: bytes, expected_identity: dict,
            interrupt: Callable[[str], None] = lambda _: None) -> None:
    """Validate completely in staging, then replace; callback exists for crash tests."""
    if _inside(state_root, install_root) or _inside(install_root, state_root):
        raise InstallError("state_and_install_roots_must_be_separate")
    try: manifest = json.loads(manifest_path.read_text("utf-8"))
    except Exception as exc: raise InstallError("invalid_manifest") from exc
    required = {"app","chain_id","genesis_hash","api_version","platform","arch","version","artifact_sha256","descriptor_sha256","genesis_sha256","signature"}
    if set(manifest) != required: raise InstallError("invalid_manifest")
    verify_ed25519(manifest, public_key_pem)
    if any(manifest.get(k) != expected_identity.get(k) for k in ("chain_id","genesis_hash","api_version")):
        raise InstallError("wrong_protocol_identity")
    machine = platform.machine().lower().replace("amd64", "x86_64").replace("arm64", "aarch64")
    system = platform.system().lower()
    if manifest["platform"] != system or manifest["arch"] != machine: raise InstallError("unsupported_architecture")
    if _sha256(artifact_path) != manifest["artifact_sha256"]: raise InstallError("bad_checksum")

    install_root = install_root.resolve(); install_root.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{install_root.name}.stage-", dir=install_root.parent))
    backup = install_root.with_name(f".{install_root.name}.prior")
    journal = install_root.with_name(f".{install_root.name}.installing")
    swapped = False
    try:
        shutil.unpack_archive(str(artifact_path), stage)
        descriptor = stage / "descriptor.json"; genesis = stage / "genesis.bin"
        if not descriptor.is_file() or not genesis.is_file(): raise InstallError("artifact_missing_identity_files")
        if _sha256(descriptor) != manifest["descriptor_sha256"] or _sha256(genesis) != manifest["genesis_sha256"]: raise InstallError("bad_genesis_or_descriptor")
        try: staged_identity = json.loads(descriptor.read_text("utf-8"))
        except Exception as exc: raise InstallError("bad_descriptor") from exc
        if any(staged_identity.get(k) != expected_identity.get(k) for k in ("chain_id","genesis_hash","api_version")): raise InstallError("wrong_protocol_identity")
        (stage / "install-manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2), "utf-8")
        interrupt("staged")
        if backup.exists(): shutil.rmtree(backup)
        journal.write_text(json.dumps({"install":str(install_root),"backup":str(backup)}), "utf-8")
        if install_root.exists(): os.replace(install_root, backup)
        interrupt("prior_moved")
        os.replace(stage, install_root); swapped = True
        interrupt("new_installed")
        journal.unlink(missing_ok=True)
        if backup.exists(): shutil.rmtree(backup)
    except BaseException:
        if swapped and install_root.exists(): shutil.rmtree(install_root)
        if backup.exists(): os.replace(backup, install_root)
        journal.unlink(missing_ok=True)
        if stage.exists(): shutil.rmtree(stage)
        raise

def recover(install_root: Path) -> None:
    """Restore the prior generation after an externally interrupted atomic swap."""
    install_root = install_root.resolve(); backup = install_root.with_name(f".{install_root.name}.prior"); journal = install_root.with_name(f".{install_root.name}.installing")
    if not journal.exists(): return
    if backup.exists():
        if install_root.exists(): shutil.rmtree(install_root)
        os.replace(backup, install_root)
    journal.unlink(missing_ok=True)
