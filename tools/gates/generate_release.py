#!/usr/bin/env python3
"""Build release binaries and generate checksums, CycloneDX SBOM, in-toto
provenance, and a release manifest.

Artifacts are REAL: noos-transition (Rust + independent Go) and noos-verify
are built through the tools/gates/repro_build.py deterministic machinery.
The SBOM enumerates every locked package from Cargo.lock (workspace crates
flagged); provenance binds every artifact hash to the git head revision and
the lockfile digests. Generated metadata records blockers; it never turns
unavailable external builders, ceremony values, policy signatures, or human
signatures into PASS.
"""
from __future__ import annotations
import argparse, hashlib, json, platform, subprocess, sys
try:
 import tomllib
except ModuleNotFoundError:
 import tomli as tomllib
from datetime import date, datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"tools/gates"))
import repro_build
def sha(p:Path)->str:return hashlib.sha256(p.read_bytes()).hexdigest()
def version(cmd):
 try:return subprocess.run(cmd,cwd=ROOT,text=True,capture_output=True,check=True).stdout.splitlines()[0]
 except Exception:return "UNAVAILABLE"
def cargo_lock_packages()->list[dict]:
 """Stdlib-only Cargo.lock reader: [[package]] rows with name/version/source.
 Workspace (path) crates carry no `source` key in the lockfile."""
 pkgs=[];cur=None
 for line in (ROOT/"Cargo.lock").read_text("utf-8").splitlines():
  line=line.strip()
  if line=="[[package]]":cur={};pkgs.append(cur);continue
  if line.startswith("["):cur=None;continue
  if cur is None or " = " not in line:continue
  key,_,val=line.partition(" = ")
  if key in ("name","version","source") and val.startswith('"') and val.endswith('"'):cur[key]=val[1:-1]
 bad=[p for p in pkgs if "name" not in p or "version" not in p]
 if bad:raise SystemExit(f"Cargo.lock parse failed: incomplete package rows {bad}")
 return sorted(pkgs,key=lambda p:(p["name"],p["version"]))
def deterministic_serial(payload:bytes)->str:
 h=hashlib.sha256(payload).hexdigest()
 return f"urn:uuid:{h[0:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"
def main()->int:
 p=argparse.ArgumentParser()
 p.add_argument("--artifacts",default="release/artifacts");p.add_argument("--out",default="release/manifest.json")
 p.add_argument("--version",default="0.1.0-dev")
 p.add_argument("--skip-build",action="store_true",help="hash existing release/artifacts without rebuilding")
 a=p.parse_args()
 ad=ROOT/a.artifacts;ad.mkdir(parents=True,exist_ok=True)
 if not a.skip_build:
  repro_build.build_release_artifacts(ad,ROOT/"target/noos-release")
 files=sorted(x for x in ad.rglob("*") if x.is_file())
 hashes={x.relative_to(ROOT).as_posix():sha(x) for x in files}
 rel=ROOT/"release";rel.mkdir(exist_ok=True)
 checks=rel/"SHA256SUMS";checks.write_text("".join(f"{v}  {k}\n" for k,v in sorted(hashes.items())),encoding="ascii",newline="\n")
 # CycloneDX 1.5: artifact files (hashed) + every locked crate from Cargo.lock.
 components=[{"type":"file","name":k,"version":a.version,"hashes":[{"alg":"SHA-256","content":v}]} for k,v in sorted(hashes.items())]
 for pkg in cargo_lock_packages():
  components.append({"type":"library","name":pkg["name"],"version":pkg["version"],
   "purl":f"pkg:cargo/{pkg['name']}@{pkg['version']}",
   "properties":[{"name":"noos:workspace","value":"true" if "source" not in pkg else "false"}]})
 comp_bytes=json.dumps(components,sort_keys=True,separators=(",",":")).encode()
 sbom={"bomFormat":"CycloneDX","specVersion":"1.5","serialNumber":deterministic_serial(comp_bytes),"version":1,"components":components}
 sbom_path=rel/"sbom.cdx.json";sbom_path.write_text(json.dumps(sbom,indent=2,sort_keys=True)+"\n",encoding="utf-8",newline="\n")
 repo_rev=version(["git","rev-parse","HEAD"])
 subjects=[{"name":k,"digest":{"sha256":v}} for k,v in sorted(hashes.items())]
 provenance={"_type":"https://in-toto.io/Statement/v1","subject":subjects,"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"buildType":"https://mindchain.network/noos/repro-build/v1","externalParameters":{"locked":True,"frozen":True},"internalParameters":{"post_build_normalization":"forbidden"},"resolvedDependencies":[{"uri":"git+file://noosphere","digest":{"gitCommit":repo_rev}},{"uri":"Cargo.lock","digest":{"sha256":sha(ROOT/'Cargo.lock')}},{"uri":"go.sum","digest":{"sha256":sha(ROOT/'go/go.sum')}}]},"runDetails":{"builder":{"id":"windows-single-host-clean-target-smoke"},"metadata":{"invocationId":"local-release-generation"}}}}
 prov_path=rel/"provenance.intoto.jsonl";prov_path.write_text(json.dumps(provenance,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8",newline="\n")
 policy=tomllib.loads((ROOT/"protocol/release/repro-policy-v1.toml").read_text("utf-8")); blockers=[]
 if policy.get("state")!="SIGNED":blockers.append({"code":"UNSIGNED_REPRO_POLICY","status":"EXTERNAL_BLOCKED"})
 blockers += [{"code":"INDEPENDENT_BUILDER_REQUIRED","target":x,"status":"EXTERNAL_BLOCKED"} for x in ("linux-x86_64","linux-aarch64")]
 blockers += [{"code":"GENESIS_CEREMONY_REQUIRED","status":"EXTERNAL_BLOCKED"},{"code":"HUMAN_RELEASE_SIGNATURES_REQUIRED","status":"EXTERNAL_BLOCKED"}]
 manifest={"schema_version":1,"manifest_kind":"noosphere-release-manifest","release":{"version":a.version,"channel":"devnet","date":str(date.today()),"protocol_version":"v1","api_version":"v1"},"source":{"repo_revision":repo_rev,"spec_revision":sha(ROOT/"protocol/spec/constants-v1.toml")},"identity":{"chain_id":"EXTERNAL_BLOCKED_QUIET_WEEK","genesis_hash":"EXTERNAL_BLOCKED_CEREMONY","is_test_network":True},"toolchain_locks":{"rustc":version(["rustc","--version"]),"go":version(["go","version"]),"python":sys.version.split()[0],"cargo_lock_hash":sha(ROOT/"Cargo.lock"),"go_sum_hash":sha(ROOT/"go/go.sum"),"repro_policy_hash":sha(ROOT/"protocol/release/repro-policy-v1.toml")},"artifact_hashes":hashes,"checksums":{"path":"release/SHA256SUMS","sha256":sha(checks)},"sbom":{"format":"CycloneDX-1.5","path":"release/sbom.cdx.json","sha256":sha(sbom_path)},"provenance":{"format":"SLSA-v1/in-toto","path":"release/provenance.intoto.jsonl","sha256":sha(prov_path)},"gate_verdicts":[],"unresolved_findings":blockers,"signatures":[],"generated_at":datetime.now(timezone.utc).isoformat(),"host":platform.platform()}
 out=ROOT/a.out;out.write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n",encoding="utf-8",newline="\n");print(f"RESULT release_manifest_generation=PASS artifacts={len(files)} blockers={len(blockers)} out={out.relative_to(ROOT)}");return 0
if __name__=="__main__":raise SystemExit(main())
