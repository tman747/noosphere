#!/usr/bin/env python3
"""Build and compare release artifacts without post-build normalization.

Production mode fails before building unless the raw reproducibility policy is
SIGNED and has valid detached Ed25519 signatures for every required role.
`--smoke` exists only to prove the local two-clean-directory comparison path;
its report is permanently labelled non-release evidence.
"""
from __future__ import annotations
import argparse, base64, hashlib, json, os, shutil, subprocess, sys, tempfile
try:
 import tomllib
except ModuleNotFoundError:
 import tomli as tomllib
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
POLICY=ROOT/"protocol/release/repro-policy-v1.toml"
SIGS=ROOT/"protocol/release/repro-policy-v1.signatures.json"

def sha(path:Path)->str:
 h=hashlib.sha256()
 with path.open("rb") as f:
  for chunk in iter(lambda:f.read(1<<20),b""): h.update(chunk)
 return h.hexdigest()

def verify_policy()->tuple[dict,list[str]]:
 raw=POLICY.read_bytes(); policy=tomllib.loads(raw.decode("utf-8")); errors=[]
 if policy.get("state")!="SIGNED": errors.append("policy state is not SIGNED")
 if policy.get("post_build_normalization")!="forbidden": errors.append("post-build normalization must be forbidden")
 if not SIGS.exists(): errors.append("detached signature record missing"); return policy,errors
 try:
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
  records=json.loads(SIGS.read_text("utf-8")); roles=set()
  for rec in records.get("signatures",[]):
   key=Ed25519PublicKey.from_public_bytes(base64.b64decode(rec["public_key_base64"],validate=True))
   key.verify(base64.b64decode(rec["signature_base64"],validate=True),raw); roles.add(rec["role"])
  for role in policy["signature_policy"]["required_roles"]:
   if role not in roles: errors.append(f"missing valid signature role {role}")
 except Exception as exc: errors.append(f"signature verification failed: {exc}")
 return policy,errors

def det_env(prefix:str,target:Path)->dict:
 """Deterministic build environment shared by the clean repro builders and
 the release-artifact build: locked target dir, SOURCE_DATE_EPOCH, path
 remapping, no debuginfo, reproducible MSVC link flags (Windows only)."""
 env=os.environ.copy(); env["CARGO_TARGET_DIR"]=str(target); env["SOURCE_DATE_EPOCH"]="1"
 prior=env.get("RUSTFLAGS",""); flags=f" --remap-path-prefix={prefix}=/noos-clean-builder -C debuginfo=0"
 if os.name=="nt": flags+=" -C link-arg=/Brepro -C link-arg=/PDBALTPATH:noos-transition.pdb"
 env["RUSTFLAGS"]=(prior+flags).strip()
 return env

EXT=".exe" if os.name=="nt" else ""

def build_release_artifacts(out:Path,target:Path)->dict[str,str]:
 """Build the release binary set with the exact deterministic flags of the
 clean-directory repro builders, into a persistent target dir. Returns
 {artifact_name: sha256}. Used by tools/gates/generate_release.py."""
 out.mkdir(parents=True,exist_ok=True); env=det_env(str(target),target)
 subprocess.run(["cargo","build","--locked","--release","-p","noos-lumen","--bin","noos-transition"],cwd=ROOT,env=env,check=True)
 shutil.copy2(target/"release"/("noos-transition"+EXT),out/("noos-transition-rust"+EXT))
 for name,pkg in (("noos-transition-go","./cmd/noos-transition"),("noos-verify","./cmd/noos-verify")):
  # `go build` skips rewriting an output whose embedded build ID still
  # matches (an appended-byte tamper would survive); force a fresh write.
  (out/(name+EXT)).unlink(missing_ok=True)
  subprocess.run(["go","build","-trimpath","-buildvcs=false","-o",str(out/(name+EXT)),pkg],cwd=ROOT/"go",check=True)
 return {p.name:sha(p) for p in sorted(out.iterdir()) if p.is_file()}

def build(builder:str,out:Path)->dict[str,str]:
 out.mkdir(parents=True); target=out/"cargo-target"; env=det_env(str(out),target)
 subprocess.run(["cargo","build","--locked","--release","-p","noos-lumen","--bin","noos-transition"],cwd=ROOT,env=env,check=True)
 rust=target/"release"/("noos-transition"+EXT); shutil.copy2(rust,out/("noos-transition-rust"+EXT))
 subprocess.run(["go","build","-trimpath","-buildvcs=false","-o",str(out/("noos-transition-go"+EXT)),"./cmd/noos-transition"],cwd=ROOT/"go",check=True)
 artifacts={p.name:sha(p) for p in sorted(out.iterdir()) if p.is_file()}
 (out/"artifact-hashes.json").write_text(json.dumps(artifacts,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8",newline="\n")
 artifacts["artifact-hashes.json"]=sha(out/"artifact-hashes.json")
 return artifacts

def main()->int:
 p=argparse.ArgumentParser();p.add_argument("--builders",required=True);p.add_argument("--locked",action="store_true");p.add_argument("--frozen",action="store_true");p.add_argument("--smoke",action="store_true");p.add_argument("--out",default="release/repro-report.json");a=p.parse_args()
 if not a.locked or not a.frozen: p.error("--locked and --frozen are mandatory")
 policy,errors=verify_policy()
 if errors and not a.smoke:
  print("RESULT repro_build=BLOCKED reason="+"; ".join(errors),file=sys.stderr);return 2
 requested=[x.strip() for x in a.builders.split(",") if x.strip()]; local=[x for x in requested if x.startswith("windows-x86_64-")]
 external=[x for x in requested if not x.startswith("windows-x86_64-")]
 if len(local)<2: print("two Windows x86_64 builders required",file=sys.stderr);return 2
 report={"schema":"noos/repro-report/v1","created":datetime.now(timezone.utc).isoformat(),"policy_sha256":sha(POLICY),"policy_signature_errors":errors,"smoke_only":a.smoke,"builders":{},"comparisons":[],"external_blocked":external}
 with tempfile.TemporaryDirectory(prefix="noos-repro-") as d:
  base=Path(d); built=[]
  for ident in local:
   hashes=build(ident,base/ident);report["builders"][ident]={"platform":"windows-x86_64","hashes":hashes,"clean_target":True};built.append((ident,hashes))
  reference=built[0]
  for ident,hashes in built[1:]:
   equal=reference[1]==hashes;report["comparisons"].append({"a":reference[0],"b":ident,"law":"raw_bytes","equal":equal})
 out=ROOT/a.out;out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8",newline="\n")
 mismatch=any(not x["equal"] for x in report["comparisons"])
 if mismatch: verdict="FAIL"
 elif errors: verdict="SMOKE_PASS_UNSIGNED_POLICY"
 elif external: verdict="EXTERNAL_BLOCKED"
 else: verdict="PASS"
 print(f"RESULT repro_build={verdict} local_builders={len(local)} external_blocked={len(external)} report={out.relative_to(ROOT)}")
 return 1 if mismatch else 0
if __name__=="__main__":raise SystemExit(main())
