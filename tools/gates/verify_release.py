#!/usr/bin/env python3
"""Fail-closed verifier for NOOSPHERE release supply-chain manifests."""
from __future__ import annotations
import argparse, hashlib, json, re, sys
try:
 import tomllib
except ModuleNotFoundError:
 import tomli as tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; HEX=re.compile(r"^[0-9a-f]{64}$")
def sha(p:Path)->str:return hashlib.sha256(p.read_bytes()).hexdigest()
def safe(rel:str)->Path:
 p=(ROOT/rel).resolve()
 if ROOT.resolve() not in p.parents and p!=ROOT.resolve():raise ValueError(f"path escapes repository: {rel}")
 return p
def verify_signatures(manifest:dict,errors:list[str],blocked:list[str],keyring=None,*,test_mode:bool=False):
 sigs=manifest.get("signatures",[]);required=("release-owner","independent-build-reviewer");roles={}
 unsigned=dict(manifest);unsigned["signatures"]=[]
 payload=json.dumps(unsigned,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
 if not sigs:
  for role in required:blocked.append(f"missing manifest signature role {role}")
  return
 if keyring is None:
  errors.append("signed release manifest requires externally supplied pinned role keyring")
  return
 message=b"NOOS/RELEASE/MANIFEST/V2\x00"+payload
 for rec in sigs:
  if not isinstance(rec,dict) or set(rec)!={"role","key_id","signature_ed25519_hex"}:
   errors.append("manifest signature has unknown/embedded-key fields");continue
  role=rec.get("role")
  if role in roles or role not in required:errors.append(f"manifest signature duplicate/unknown role {role}");continue
  pinned=keyring.get(role)
  if pinned is None or rec.get("key_id")!=pinned.key_id:errors.append(f"manifest signature role/key mismatch {role}");continue
  try:pinned.public.verify(bytes.fromhex(rec["signature_ed25519_hex"]),message);roles[role]=rec
  except Exception as exc:errors.append(f"manifest signature invalid for {role}: {exc}")
 for role in required:
  if role not in roles:errors.append(f"missing manifest signature role {role}")
def main()->int:
 p=argparse.ArgumentParser();p.add_argument("manifest");p.add_argument("--allow-external-blocked",action="store_true");p.add_argument("--keyring");p.add_argument("--final-freeze");p.add_argument("--final-freeze-signatures");a=p.parse_args();mp=safe(a.manifest)
 try:m=json.loads(mp.read_text("utf-8"))
 except Exception as exc:print(f"manifest parse failed: {exc}",file=sys.stderr);return 1
 errors=[];blocked=[];keyring=None
 supplied=[a.keyring,a.final_freeze,a.final_freeze_signatures]
 if any(supplied) and not all(supplied):errors.append("--keyring, --final-freeze, and --final-freeze-signatures must be supplied together")
 elif all(supplied):
  try:
   gt=ROOT/"tools/genesis"
   if str(gt) not in sys.path:sys.path.insert(0,str(gt))
   from production_authorization import DOMAIN_FINAL_FREEZE,FINAL_ROLES,canonical_json,file_sha256,load_keyring,read_json,verify_detached_signatures
   kp=safe(a.keyring);fp=safe(a.final_freeze);sp=safe(a.final_freeze_signatures)
   keyring,keyring_doc=load_keyring(kp)
   freeze=read_json(fp);revision=m.get("source",{}).get("repo_revision")
   if keyring_doc.get("exact_revision")!=revision or freeze.get("exact_revision")!=revision:raise ValueError("release/keyring/final-freeze revision mismatch")
   if freeze.get("role_keyring_sha256")!=file_sha256(kp):raise ValueError("final freeze does not pin supplied role keyring bytes")
   if freeze.get("chain_id")!=m.get("identity",{}).get("chain_id") or freeze.get("genesis_hash")!=m.get("identity",{}).get("genesis_hash"):raise ValueError("release/final-freeze identity mismatch")
   verify_detached_signatures(canonical_json(freeze),read_json(sp),DOMAIN_FINAL_FREEZE,revision,FINAL_ROLES,keyring)
  except Exception as exc:errors.append(f"trusted release keyring/final-freeze verification failed: {exc}")
 if m.get("schema_version")!=1 or m.get("manifest_kind")!="noosphere-release-manifest":errors.append("wrong manifest schema/kind")
 for section in ("release","source","identity","toolchain_locks","artifact_hashes","checksums","sbom","provenance","gate_verdicts","unresolved_findings","signatures"):
  if section not in m:errors.append(f"missing section {section}")
 for rel,digest in m.get("artifact_hashes",{}).items():
  try:path=safe(rel)
  except ValueError as exc:errors.append(str(exc));continue
  if not HEX.fullmatch(str(digest)):errors.append(f"invalid sha256 {rel}")
  elif not path.is_file():errors.append(f"missing artifact {rel}")
  elif sha(path)!=digest:errors.append(f"artifact checksum mismatch {rel}")
 for section in ("checksums","sbom","provenance"):
  rec=m.get(section,{})
  try:path=safe(rec.get("path",""))
  except ValueError as exc:errors.append(str(exc));continue
  if not path.is_file() or sha(path)!=rec.get("sha256"):errors.append(f"{section} file/hash invalid")
 # Every checksum line must be exact and refer to a manifested artifact.
 cp=m.get("checksums",{}).get("path")
 if cp and safe(cp).is_file():
  seen={}
  for line in safe(cp).read_text("ascii").splitlines():
   parts=line.split("  ",1)
   if len(parts)!=2 or not HEX.fullmatch(parts[0]):errors.append("malformed SHA256SUMS line");continue
   seen[parts[1]]=parts[0]
  if seen!=m.get("artifact_hashes",{}):errors.append("SHA256SUMS does not exactly match artifact_hashes")
 # SBOM and provenance must cover exactly the artifacts, not merely exist;
 # the SBOM's library components must exactly enumerate Cargo.lock, with
 # every workspace (path) crate flagged; provenance must bind the git head
 # revision and the live lockfile digests.
 try:
  sb=json.loads(safe(m["sbom"]["path"]).read_text("utf-8"))
  sbset={c["name"]:c["hashes"][0]["content"] for c in sb["components"] if c.get("type")=="file"}
  if sbset!=m.get("artifact_hashes",{}):errors.append("SBOM file subjects do not exactly match artifacts")
  libs={(c["name"],c.get("version")):c for c in sb["components"] if c.get("type")=="library"}
  lock={};cur=None
  for line in (ROOT/"Cargo.lock").read_text("utf-8").splitlines():
   line=line.strip()
   if line=="[[package]]":cur={};continue
   if line.startswith("["):cur=None;continue
   if cur is None or " = " not in line:continue
   key,_,val=line.partition(" = ")
   if key in ("name","version","source") and val.startswith('"'):cur[key]=val[1:-1]
   if "name" in cur and "version" in cur:lock.setdefault((cur["name"],cur["version"]),cur)
  if set(libs)!=set(lock):errors.append("SBOM libraries do not exactly enumerate Cargo.lock packages")
  else:
   for key,c in libs.items():
    ws=next((p["value"] for p in c.get("properties",[]) if p.get("name")=="noos:workspace"),None)
    if ws!=("true" if "source" not in lock[key] else "false"):errors.append(f"SBOM workspace flag wrong for crate {key[0]}")
  pr=json.loads(safe(m["provenance"]["path"]).read_text("utf-8"));pset={s["name"]:s["digest"]["sha256"] for s in pr["subject"]}
  if pset!=m.get("artifact_hashes",{}):errors.append("provenance subjects do not exactly match artifacts")
  deps={d["uri"]:d["digest"] for d in pr["predicate"]["buildDefinition"]["resolvedDependencies"]}
  if deps.get("git+file://noosphere",{}).get("gitCommit")!=m.get("source",{}).get("repo_revision"):errors.append("provenance git revision does not bind manifest source revision")
  if deps.get("Cargo.lock",{}).get("sha256")!=sha(ROOT/"Cargo.lock"):errors.append("provenance Cargo.lock digest stale")
  if deps.get("go.sum",{}).get("sha256")!=sha(ROOT/"go/go.sum"):errors.append("provenance go.sum digest stale")
 except Exception as exc:errors.append(f"SBOM/provenance parse failed: {exc}")
 policy=tomllib.loads((ROOT/"protocol/release/repro-policy-v1.toml").read_text("utf-8"))
 if policy.get("state")!="SIGNED":blocked.append("UNSIGNED_REPRO_POLICY")
 if m.get("toolchain_locks",{}).get("repro_policy_hash")!=sha(ROOT/"protocol/release/repro-policy-v1.toml"):errors.append("repro policy hash mismatch")
 for finding in m.get("unresolved_findings",[]):
  if finding.get("status") in ("OPEN","EXTERNAL_BLOCKED"):blocked.append(finding.get("code") or finding.get("finding_id","UNKNOWN"))
 ident=m.get("identity",{})
 for key in ("chain_id","genesis_hash"):
  if not HEX.fullmatch(str(ident.get(key,""))):blocked.append(f"INVALID_OR_UNFROZEN_{key.upper()}")
 verify_signatures(m,errors,blocked,keyring)
 for v in m.get("gate_verdicts",[]):
  if v.get("verdict")!="PASS":blocked.append(f"GATE_{v.get('gate','UNKNOWN')}_{v.get('verdict','MISSING')}")
 if errors:
  print("RESULT verify_release=FAIL errors="+"; ".join(errors),file=sys.stderr);return 1
 if blocked:
  print("RESULT verify_release=EXTERNAL_BLOCKED blockers="+",".join(sorted(set(blocked))))
  return 0 if a.allow_external_blocked else 2
 print("RESULT verify_release=PASS artifacts="+str(len(m["artifact_hashes"])))
 return 0
if __name__=="__main__":raise SystemExit(main())
