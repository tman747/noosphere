#!/usr/bin/env python3
"""Validate the frozen API v1 contract and conformance vectors using stdlib only.

The .yaml document is deliberately JSON-form YAML 1.2, so validation never
silently depends on PyYAML or another optional package.
"""
from __future__ import annotations
import base64, hashlib, json, re, sys
from pathlib import Path

HASH = re.compile(r"^[0-9a-f]{64}$")
DEC = re.compile(r"^(0|[1-9][0-9]*)$")
CURSOR = re.compile(r"^[A-Za-z0-9_-]+$")
U64_MAX = 2**64 - 1
U128_MAX = 2**128 - 1
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
REQUIRED_ROUTES = {
 "/api/status", "/api/v1/blocks", "/api/v1/blocks/{hash_or_height}",
 "/api/v1/transactions/{txid}", "/api/v1/notes/{noteid}",
 "/api/v1/addresses/{address}/notes", "/api/v1/addresses/{address}/balance",
 "/api/v1/addresses/{address}/history", "/api/v1/nodes", "/api/v1/workers",
 "/api/v1/objects/{objectid}", "/api/v1/models", "/api/v1/jobs",
 "/api/v1/jobs/{jobid}/chunks", "/api/v1/receipts/{receiptid}",
 "/api/v1/disputes/{disputeid}", "/api/v1/evidence/{mechanism_id}",
 "/api/v1/transactions"
}
LIST_ROUTES = {"/api/v1/blocks","/api/v1/addresses/{address}/notes","/api/v1/addresses/{address}/history","/api/v1/nodes","/api/v1/workers","/api/v1/models","/api/v1/jobs","/api/v1/jobs/{jobid}/chunks"}
FEATURE_ROUTES = {"/api/v1/workers","/api/v1/models","/api/v1/jobs","/api/v1/jobs/{jobid}/chunks","/api/v1/disputes/{disputeid}"}


def load_json_yaml(path: Path):
 try: return json.loads(path.read_text(encoding="utf-8"))
 except (OSError, json.JSONDecodeError) as exc: raise ValueError(f"{path}: JSON-form YAML parse failed: {exc}")

def polymod(values):
 chk=1
 for value in values:
  top=chk>>25; chk=(chk&0x1ffffff)<<5 ^ value
  for i,g in enumerate((0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3)):
   if (top>>i)&1: chk ^= g
 return chk

def valid_address(s):
 if not isinstance(s,str) or s != s.lower() or not s.startswith("noos1") or len(s)>90: return False
 pos=s.rfind("1"); data=s[pos+1:]
 if pos<1 or len(data)<6 or any(c not in CHARSET for c in data): return False
 exp=[ord(c)>>5 for c in s[:pos]]+[0]+[ord(c)&31 for c in s[:pos]]
 vals=[CHARSET.index(c) for c in data]
 if polymod(exp+vals) != 0x2bc830a3: return False
 payload=vals[:-6]; acc=bits=0; out=[]
 for v in payload:
  acc=(acc<<5)|v; bits+=5
  if bits>=8: bits-=8; out.append((acc>>bits)&255)
 if bits and ((acc << (8-bits)) & 255): return False
 return len(out)==34 and out[0]==1

def dec(v, maximum): return isinstance(v,str) and bool(DEC.fullmatch(v)) and int(v)<=maximum

def coordinate(v): return isinstance(v,dict) and set(v)=={"height","hash","index"} and dec(v["height"],U64_MAX) and bool(HASH.fullmatch(v["hash"])) and dec(v["index"],U64_MAX)

def transaction(v):
 if not isinstance(v,dict): return False
 base={"txid","wtxid","state","fee","resource_counters"}
 if not base <= set(v) or not HASH.fullmatch(str(v["txid"])) or not HASH.fullmatch(str(v["wtxid"])) or not dec(v["fee"],U128_MAX) or not isinstance(v["resource_counters"],dict): return False
 if any(not dec(x,U64_MAX) for x in v["resource_counters"].values()): return False
 law={"MEMPOOL":set(),"INCLUDED":{"inclusion"},"JUSTIFIED":{"inclusion","justification"},"FINALIZED":{"inclusion","justification","finalization"},"REVERTED":{"inclusion"},"REJECTED":{"rejection_code"}}
 state=v["state"]
 if state not in law: return False
 coord_names={"inclusion","justification","finalization"}; present=coord_names & set(v)
 if present != (law[state] & coord_names): return False
 if any(not coordinate(v[n]) for n in present): return False
 if state=="REJECTED" and not isinstance(v.get("rejection_code"),str): return False
 if state!="REJECTED" and "rejection_code" in v: return False
 return set(v) <= base|coord_names|{"rejection_code"}

def error_envelope(v,status):
 allowed={"code","message","request_id","details","mechanism_id","evidence_ref"}
 if not isinstance(v,dict) or set(v)-allowed or not {"code","message","request_id","details"}<=set(v): return False
 if v["code"]=="feature_disabled": return status==409 and {"mechanism_id","evidence_ref"}<=set(v)
 return True

def vector_accept(case):
 k=case["kind"]; v=case.get("value")
 if k=="hash32": return isinstance(v,str) and bool(HASH.fullmatch(v))
 if k=="address": return valid_address(v)
 if k=="u64": return dec(v,U64_MAX)
 if k=="u128": return dec(v,U128_MAX)
 if k=="cursor":
  if not isinstance(v,str) or not CURSOR.fullmatch(v) or "=" in v: return False
  try: base64.urlsafe_b64decode(v+"="*((4-len(v)%4)%4)); return True
  except Exception: return False
 if k=="cursor_binding": return case.get("cursor_query_sha256")==case.get("request_query_sha256")
 if k=="limit": return isinstance(v,int) and not isinstance(v,bool) and 1<=v<=200
 if k=="transaction": return transaction(v)
 if k=="error": return error_envelope(v,case.get("status"))
 if k=="page": return isinstance(v,dict) and set(v)=={"items","next_cursor"} and isinstance(v["items"],list) and len(v["items"])<=200 and (v["next_cursor"] is None or vector_accept({"kind":"cursor","value":v["next_cursor"]}))
 if k=="page_count": return isinstance(v,int) and v<=200
 if k=="media": return case.get("content_type")=="application/json"
 if k=="accept": return case.get("accept") in {"application/json","application/vnd.noos.v1+json"}
 if k=="request_size": return case.get("bytes",10**9)<=1048576
 if k=="submission_envelope_size": return case.get("bytes",10**9)<=1048576
 if k=="submission_semantics":
  inp=case.get("input")
  if not isinstance(inp,dict) or set(inp)!={"exact_node_envelope","fresh_node_identity","node_accepted"}: return False
  if any(not isinstance(inp[key],bool) for key in inp) or not inp["exact_node_envelope"] or not inp["fresh_node_identity"]: return False
  if inp["node_accepted"]: return case.get("expected_status")==202 and "expected_error" not in case
  return case.get("expected_status")==409 and case.get("expected_error")=="node_refused"
 if k=="status":
  req={"chain_id","genesis_hash","protocol_version","api_version","release_version","unsafe_head","justified","finalized","freshness_ms","evidence_registry_root"}
  if not isinstance(v,dict) or set(v)!=req or v["protocol_version"]!="v1" or v["api_version"]!="v1": return False
  return HASH.fullmatch(v["chain_id"]) is not None and HASH.fullmatch(v["genesis_hash"]) is not None and HASH.fullmatch(v["evidence_registry_root"]) is not None and dec(v["freshness_ms"],U64_MAX) and all(isinstance(v[n],dict) and set(v[n])=={"height","hash","state_root"} and dec(v[n]["height"],U64_MAX) and HASH.fullmatch(v[n]["hash"]) and HASH.fullmatch(v[n]["state_root"]) for n in ("unsafe_head","justified","finalized"))
 return False

def walk_refs(node,refs):
 if isinstance(node,dict):
  if "$ref" in node: refs.append(node["$ref"])
  for v in node.values(): walk_refs(v,refs)
 elif isinstance(node,list):
  for v in node: walk_refs(v,refs)

def resolve(doc,ref):
 if not ref.startswith("#/"): return False
 cur=doc
 for p in ref[2:].split("/"):
  if not isinstance(cur,dict) or p not in cur: return False
  cur=cur[p]
 return True

def frozen_root(root, paths):
 h=hashlib.sha256()
 for rel in sorted(paths):
  h.update(rel.encode("utf-8")); h.update(b"\0")
  h.update(hashlib.sha256((root/rel).read_bytes()).digest())
 return h.hexdigest()

def validate(root):
 errors=[]; spec_path=root/"protocol/api/openapi-v1.yaml"
 try: spec=load_json_yaml(spec_path)
 except ValueError as exc: return [str(exc)]
 try: roots=json.loads((root/"protocol/api/contract-root-v1.json").read_text(encoding="utf-8"))
 except (OSError,json.JSONDecodeError) as exc: errors.append(f"API root manifest parse failed: {exc}"); roots={}
 expected_files={"protocol/api/openapi-v1.yaml","protocol/api/vectors/positive.json","protocol/api/vectors/negative.json"}
 if set(roots.get("files",{}))!=expected_files: errors.append("API root manifest file set mismatch")
 for rel,digest in roots.get("files",{}).items():
  try: actual=hashlib.sha256((root/rel).read_bytes()).hexdigest()
  except OSError as exc: errors.append(f"{rel}: hash read failed: {exc}"); continue
  if digest!=actual: errors.append(f"{rel}: frozen hash mismatch")
 if roots.get("vector_root")!=frozen_root(root,expected_files-{"protocol/api/openapi-v1.yaml"}): errors.append("API vector root mismatch")
 if roots.get("contract_root")!=frozen_root(root,expected_files): errors.append("API contract root mismatch")
 if spec.get("openapi")!="3.1.0": errors.append("OpenAPI version must be 3.1.0")
 paths=spec.get("paths",{})
 if set(paths)!=REQUIRED_ROUTES: errors.append(f"route set mismatch missing={sorted(REQUIRED_ROUTES-set(paths))} extra={sorted(set(paths)-REQUIRED_ROUTES)}")
 contract=spec.get("x-noos-contract",{}); pagination=contract.get("pagination",{}); limits=contract.get("limits",{})
 if pagination.get("limit_default")!=50 or pagination.get("limit_min")!=1 or pagination.get("limit_max")!=200: errors.append("pagination bounds/default changed")
 if limits != {"max_request_bytes":1048576,"max_submission_envelope_bytes":1048576,"max_operator_response_bytes":65536,"max_page_limit":200}: errors.append("size/page limits changed")
 neg=contract.get("negotiation",{})
 if neg.get("unsupported_request_status")!=415 or neg.get("unacceptable_response_status")!=406: errors.append("media negotiation status law missing")
 registry=contract.get("error_registry",{})
 if registry.get("feature_disabled",{}).get("status")!=409: errors.append("feature_disabled registry status must be 409")
 for route in LIST_ROUTES:
  op=paths.get(route,{}).get("get",{}); names={p.get("$ref","").split("/")[-1] for p in op.get("parameters",[])}
  if not op.get("x-stable-sort"): errors.append(f"{route}: stable sort absent")
  if not {"Limit","Cursor"}<=names: errors.append(f"{route}: limit/cursor absent")
  response_200=op.get("responses",{}).get("200",{}); response=response_200.get("$ref","")
  if response.endswith("/GenericPage") or not (response.endswith("Page") or response_200.get("content")): errors.append(f"{route}: response body is not a route-specific typed page")
 for route in FEATURE_ROUTES:
  if "409" not in paths.get(route,{}).get("get",{}).get("responses",{}): errors.append(f"{route}: feature 409 absent")
 post=paths.get("/api/v1/transactions",{}).get("post",{})
 if set(post.get("responses",{}))!={"202","400","409","413","415","422","429","503"}: errors.append("transaction status semantics incomplete")
 schemas=spec.get("components",{}).get("schemas",{})
 error_codes=set(schemas.get("Error",{}).get("properties",{}).get("code",{}).get("enum",[]))
 if set(registry)!=error_codes: errors.append(f"error registry/schema mismatch registry_only={sorted(set(registry)-error_codes)} schema_only={sorted(error_codes-set(registry))}")
 for name in ("Status","Block","Transaction","SubmitTransactionRequest","SubmitTransactionResponse","Note","Balance","HistoryEvent","LedgerObject","Node","Worker","Model","Job","Chunk","Receipt","Dispute","Evidence","Error"):
  if schemas.get(name,{}).get("additionalProperties") is not False: errors.append(f"schema {name} must reject additional properties")
 refs=[]; walk_refs(spec,refs)
 for ref in refs:
  if not resolve(spec,ref): errors.append(f"unresolved reference {ref}")
 for file,expected in (("positive.json",True),("negative.json",False)):
  try: vectors=json.loads((root/"protocol/api/vectors"/file).read_text(encoding="utf-8"))
  except Exception as exc: errors.append(f"{file}: parse failed: {exc}"); continue
  ids=set()
  for c in vectors.get("cases",[]):
   if c.get("id") in ids: errors.append(f"{file}: duplicate id {c.get('id')}")
   ids.add(c.get("id")); actual=vector_accept(c)
   if c.get("valid") is not expected: errors.append(f"{file}:{c.get('id')}: declared validity wrong")
   if actual is not expected: errors.append(f"{file}:{c.get('id')}: validator returned {actual}, expected {expected}")
 return errors

def main(argv):
 root=Path(argv[1]).resolve() if len(argv)>1 else Path(__file__).resolve().parents[2]
 errors=validate(root)
 if errors:
  for e in errors: print(f"ERROR: {e}")
  print(f"API contract gate: FAIL ({len(errors)} error(s))"); return 1
 print("API contract gate: PASS (OpenAPI + positive/negative vectors; stdlib JSON-form YAML parser)"); return 0
if __name__=="__main__": raise SystemExit(main(sys.argv))
