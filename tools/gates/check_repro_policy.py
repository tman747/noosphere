#!/usr/bin/env python3
"""Validate reproducibility policy, release manifest schema/template, and instances.

Uses only Python stdlib. On Python 3.11+ it uses tomllib; older supported
interpreters use the strict minimal TOML subset parser below. Passing the
contract gate does not make an unsigned policy release-ready:
--require-signed enforces that boundary.
"""
from __future__ import annotations
import argparse, copy, hashlib, json, re, sys
from pathlib import Path
try:
 import tomllib
except ImportError:
 tomllib=None
HASH=re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDER=re.compile(r"^(PENDING|OWNER_BLOCKED)(_[A-Z0-9_]+)?$")
PLATFORMS={"windows-x86_64","linux-x86_64","linux-aarch64"}
RAW_CLASSES={"unsigned_binary","library","data","schema","api_schema_or_vector","telemetry_schema_or_vector","conformance_vector","genesis","archive"}
MANIFEST_TOP={"schema_version","manifest_kind","_comment","release","source","identity","clients","verifiers","toolchain_locks","schema_roots","artifact_hashes","gate_verdicts","unresolved_findings","signatures","evidence_appendix"}
SCHEMA_ROOTS={"claim_registry_root","crypto_domains_root","constants_root","openapi_v1_root","api_vectors_root","telemetry_v1_root","telemetry_fixtures_root","conformance_vector_root","genesis_vector_root"}

def parse_toml_subset(text):
 """Parse the closed TOML subset used by the frozen policy, without packages."""
 root={}; current=root
 def value(raw):
  raw=raw.strip()
  if raw=="true": return True
  if raw=="false": return False
  if re.fullmatch(r"-?[0-9]+",raw): return int(raw)
  try:return json.loads(raw)
  except json.JSONDecodeError as exc:raise ValueError(f"unsupported TOML value {raw!r}: {exc}")
 for lineno,raw in enumerate(text.splitlines(),1):
  line=raw.strip()
  if not line or line.startswith("#"):continue
  if line.startswith("[[") and line.endswith("]]"):
   parts=line[2:-2].strip().split("."); parent=root
   for p in parts[:-1]:parent=parent.setdefault(p,{})
   arr=parent.setdefault(parts[-1],[])
   if not isinstance(arr,list):raise ValueError(f"line {lineno}: table/array collision")
   current={};arr.append(current);continue
  if line.startswith("[") and line.endswith("]"):
   parts=line[1:-1].strip().split(".");current=root
   for p in parts:
    nxt=current.setdefault(p,{})
    if not isinstance(nxt,dict):raise ValueError(f"line {lineno}: table collision")
    current=nxt
   continue
  if "=" not in line:raise ValueError(f"line {lineno}: expected key = value")
  key,raw_value=line.split("=",1);key=key.strip()
  if not re.fullmatch(r"[A-Za-z0-9_-]+",key) or key in current:raise ValueError(f"line {lineno}: invalid or duplicate key {key!r}")
  current[key]=value(raw_value)
 return root

def load_policy(path):
 try:
  text=path.read_text(encoding="utf-8")
  return tomllib.loads(text) if tomllib is not None else parse_toml_subset(text)
 except (OSError, ValueError) as exc:raise ValueError(f"{path}: TOML parse failed: {exc}")
def load_json(path):
 try:return json.loads(path.read_text(encoding="utf-8"))
 except (OSError,json.JSONDecodeError) as exc:raise ValueError(f"{path}: JSON parse failed: {exc}")
def hashish(v,allow_placeholder):return isinstance(v,str) and (bool(HASH.fullmatch(v)) or (allow_placeholder and bool(PLACEHOLDER.fullmatch(v))))

def validate_policy(p):
 e=[]
 if p.get("policy_version")!=1 or p.get("policy_id")!="NOOS-REPRO-V1":e.append("policy identity invalid")
 if p.get("default_comparison")!="raw_bytes" or p.get("unlisted_artifact_comparison")!="raw_bytes":e.append("unlisted artifacts must default to raw_bytes")
 if p.get("post_build_normalization")!="forbidden":e.append("post-build normalization must be forbidden")
 if p.get("hash_algorithm")!="sha256":e.append("comparison witness must be sha256")
 if p.get("require_two_independent_builders") is not True:e.append("two independent builders not required")
 if set(p.get("builder_independence_fields",[]))!={"operator","host","toolchain_installation"}:e.append("builder independence fields drifted")
 if set(p.get("required_platforms",[]))!=PLATFORMS:e.append("required platform set incomplete")
 sig=p.get("signature_policy",{})
 if sig.get("required_before_build") is not True or set(sig.get("required_roles",[]))!={"release-owner","independent-build-reviewer"} or sig.get("unsigned_or_pending_state_blocks_release") is not True:e.append("signature policy incomplete")
 signed=p.get("comparison",{}).get("signed_installer",{})
 if signed.get("law")!="signed_installer_payload":e.append("signed installer law invalid")
 if set(signed.get("allowed_platform_envelope_fields",[]))!={"platform_signature","timestamp_envelope"}:e.append("signed installer variance is not closed")
 if not signed.get("extractor") or not signed.get("extractor_version") or not signed.get("extractor_sha256"):e.append("pinned extractor incomplete")
 forbidden=set(signed.get("forbidden_variance",[]))
 if not {"unsigned_payload","entry_path","entry_order","compression_method","permissions","embedded_manifest","chain_id","genesis_hash","api_version","artifact_version"}<=forbidden:e.append("installer deterministic container law incomplete")
 rules=p.get("artifact_rules",[]); patterns=[]; classes=set()
 for r in rules:
  pattern=r.get("pattern");cls=r.get("class");comparison=r.get("comparison");patterns.append(pattern);classes.add(cls)
  if cls in RAW_CLASSES and comparison!="raw_bytes":e.append(f"{pattern}: unsigned class {cls} must use raw_bytes")
  if cls=="signed_installer" and comparison!="signed_installer_payload":e.append(f"{pattern}: signed installer law mismatch")
 if len(patterns)!=len(set(patterns)):e.append("duplicate artifact rule")
 if not RAW_CLASSES<=classes:e.append(f"raw artifact class coverage incomplete: {sorted(RAW_CLASSES-classes)}")
 if "signed_installer" not in classes:e.append("no signed installer rules")
 return e

def validate_manifest(m,instance=False):
 e=[];allow=not instance
 if set(m)!=MANIFEST_TOP:e.append(f"manifest top-level mismatch missing={sorted(MANIFEST_TOP-set(m))} extra={sorted(set(m)-MANIFEST_TOP)}")
 if m.get("schema_version")!=1 or m.get("manifest_kind")!="noosphere-release-manifest":e.append("manifest identity invalid")
 release=m.get("release",{})
 if release.get("protocol_version")!="v1" or release.get("api_version")!="v1" or release.get("channel") not in {"devnet","testnet","beta","stable"}:e.append("release identity/version invalid")
 ident=m.get("identity",{})
 for k in ("parameter_manifest_hash","chain_id","dkg_root","genesis_hash"):
  if not hashish(ident.get(k),allow):e.append(f"identity.{k}: invalid hash")
 anchor=ident.get("bitcoin_anchor",{})
 if not isinstance(anchor.get("height"),int) or anchor.get("height",-1)<0 or not hashish(anchor.get("block_hash_internal_order"),allow):e.append("bitcoin anchor invalid")
 locks=m.get("toolchain_locks",{})
 if locks.get("repro_policy")!="protocol/release/repro-policy-v1.toml" or not hashish(locks.get("repro_policy_hash"),allow):e.append("repro policy binding invalid")
 builders=locks.get("builders",[]);platforms=set();operators=[];ids=[]
 for b in builders:
  ids.append(b.get("id"));operators.append(b.get("independent_operator"));platforms.update(b.get("platforms",[]))
 if len(builders)<2 or platforms!=PLATFORMS or len(set(operators))!=len(operators):e.append("independent builder/platform coverage invalid")
 if instance and len(set(ids))!=len(ids):e.append("instance builder ids not unique")
 roots=m.get("schema_roots",{})
 if set(roots)!=SCHEMA_ROOTS:e.append("schema root set incomplete")
 for k,v in roots.items():
  if not hashish(v,allow):e.append(f"schema_roots.{k}: invalid hash")
 for k,v in m.get("artifact_hashes",{}).items():
  if not k or not hashish(v,allow):e.append(f"artifact hash invalid: {k}")
 if not isinstance(m.get("clients"),list) or len(m.get("clients",[]))<2:e.append("two client families required")
 if not isinstance(m.get("verifiers"),list) or not m.get("verifiers"):e.append("verifier revisions required")
 if not isinstance(m.get("gate_verdicts"),list) or not m.get("gate_verdicts"):e.append("gate verdicts required")
 appendix=m.get("evidence_appendix",{})
 if not isinstance(appendix.get("entries"),list):e.append("append-only evidence entries required")
 if instance:
  def walk(x,path=""):
   if isinstance(x,dict):
    for k,v in x.items():yield from walk(v,f"{path}.{k}" if path else k)
   elif isinstance(x,list):
    for i,v in enumerate(x):yield from walk(v,f"{path}[{i}]")
   elif isinstance(x,str) and (x.startswith("PENDING") or x.startswith("OWNER_BLOCKED") or x in {"EXAMPLE-REPLACE-ME","0.0.0"}):yield path
  placeholders=list(walk(m))
  if placeholders:e.append("instance contains placeholders: "+", ".join(placeholders[:8]))
 return e

def set_path(obj,path,value):
 parts=path.split(".");cur=obj
 for p in parts[:-1]:cur=cur[p]
 cur[parts[-1]]=value

def vector_accept(case,policy,manifest):
 kind=case["kind"]
 if kind=="policy":return not validate_policy(policy)
 if kind=="manifest_template":return not validate_manifest(manifest,False)
 if kind=="policy_mutation":
  p=copy.deepcopy(policy);set_path(p,case["path"],case["value"]);return not validate_policy(p)
 if kind=="policy_rule_mutation":
  p=copy.deepcopy(policy)
  for r in p["artifact_rules"]:
   if r["pattern"]==case["pattern"]:r["comparison"]=case["comparison"]
  return not validate_policy(p)
 if kind=="release_readiness":return case.get("policy_state")=="SIGNED" and not validate_policy(policy)
 if kind=="manifest_instance":return not validate_manifest(manifest,True)
 return False

def main(argv=None):
 ap=argparse.ArgumentParser();ap.add_argument("--root");ap.add_argument("--instance");ap.add_argument("--require-signed",action="store_true");args=ap.parse_args(argv)
 root=Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[2]
 errors=[]
 try:
  policy=load_policy(root/"protocol/release/repro-policy-v1.toml");manifest=load_json(root/"protocol/release/manifest-template.json");schema=load_json(root/"protocol/release/manifest-schema-v1.json");vectors=load_json(root/"protocol/release/vectors/repro-policy-v1.json")
  toolchains=load_json(root/"protocol/release/repro-toolchains-v1.json");attestation_schema=load_json(root/"protocol/release/repro-build-attestation-schema-v1.json");signature_schema=load_json(root/"protocol/release/detached-signature-schema-v1.json");trust_template=load_json(root/"protocol/release/trusted-repro-builders-template.json")
 except ValueError as exc:print(f"ERROR: {exc}");return 1
 errors+=validate_policy(policy);errors+=validate_manifest(manifest,False)
 policy_hash=hashlib.sha256((root/"protocol/release/repro-policy-v1.toml").read_bytes()).hexdigest()
 if manifest.get("toolchain_locks",{}).get("repro_policy_hash")!=policy_hash:errors.append("manifest repro_policy_hash does not bind policy bytes")
 if toolchains.get("schema")!="noos/repro-toolchains/v1" or set(toolchains.get("targets",{}))!=PLATFORMS:errors.append("repro toolchain target lock invalid")
 denv=toolchains.get("deterministic_environment",{})
 if denv.get("dependencies_offline_during_build") is not True or denv.get("cargo_locked") is not True or denv.get("go_mod")!="readonly" or denv.get("post_build_normalization")!="forbidden" or denv.get("source_date_epoch")!="git_commit_timestamp":errors.append("deterministic/offline toolchain environment incomplete")
 rust_lock=load_policy(root/"rust-toolchain.toml")
 if toolchains.get("toolchains",{}).get("rustc",{}).get("channel")!=rust_lock.get("toolchain",{}).get("channel"):errors.append("Rust repro toolchain does not bind rust-toolchain.toml")
 go_match=re.search(r"(?m)^go ([0-9]+\.[0-9]+)$",(root/"go/go.mod").read_text("utf-8"))
 go_version=toolchains.get("toolchains",{}).get("go",{}).get("version","")
 if not go_match or not go_version.startswith(go_match.group(1)+"."):errors.append("Go repro toolchain does not bind go.mod language version")
 att_props=attestation_schema.get("properties",{})
 if attestation_schema.get("additionalProperties") is not False or set(attestation_schema.get("required",[]))!={"schema","builder","build","artifact_hashes"} or set(att_props.get("build",{}).get("properties",{}).get("target",{}).get("enum",[]))!=PLATFORMS:errors.append("external build attestation schema is not closed and target-complete")
 sig_props=signature_schema.get("properties",{})
 if signature_schema.get("additionalProperties") is not False or sig_props.get("algorithm",{}).get("const")!="ed25519":errors.append("detached signature schema invalid")
 builders=trust_template.get("builders",[])
 if trust_template.get("schema")!="noos/trusted-repro-builders/v1" or len(builders)!=2 or any(b.get("test_only") is not False or b.get("external_to_release_owner") is not True or b.get("public_key_base64")!="EXTERNAL_INPUT_REQUIRED" for b in builders):errors.append("trusted external builder template must remain placeholder-only")
 try:api_roots=load_json(root/"protocol/api/contract-root-v1.json");telemetry_roots=load_json(root/"protocol/telemetry/contract-root-v1.json")
 except ValueError as exc:errors.append(str(exc));api_roots={};telemetry_roots={}
 bindings=manifest.get("schema_roots",{})
 expected_bindings={"openapi_v1_root":api_roots.get("files",{}).get("protocol/api/openapi-v1.yaml"),"api_vectors_root":api_roots.get("vector_root"),"telemetry_v1_root":telemetry_roots.get("files",{}).get("protocol/telemetry/telemetry-v1.yaml"),"telemetry_fixtures_root":telemetry_roots.get("fixture_root")}
 for key,value in expected_bindings.items():
  if bindings.get(key)!=value:errors.append(f"manifest {key} does not bind frozen contract")
 if set(schema.get("required",[])) != MANIFEST_TOP-{"_comment"}:errors.append("manifest schema required fields drift from validator")
 if schema.get("additionalProperties") is not False:errors.append("manifest schema must close top-level properties")
 for c in vectors.get("cases",[]):
  actual=vector_accept(c,policy,manifest);expected=c.get("valid") is True
  if actual!=expected:errors.append(f"vector {c.get('id')}: got {actual}, expected {expected}")
 if args.require_signed and policy.get("state")!="SIGNED":errors.append("policy is not SIGNED; release build blocked")
 if args.instance:
  try:instance=load_json(Path(args.instance));errors+=validate_manifest(instance,True)
  except ValueError as exc:errors.append(str(exc))
 if errors:
  for e in errors:print(f"ERROR: {e}")
  print(f"Repro policy gate: FAIL ({len(errors)} error(s))");return 1
 print("Repro policy gate: PASS (policy + schema + template + mutation vectors; unsigned state still blocks release builds)");return 0
if __name__=="__main__":raise SystemExit(main())
