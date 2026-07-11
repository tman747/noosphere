#!/usr/bin/env python3
"""Validate telemetry-v1 and end-to-end failure fixtures with Python stdlib."""
from __future__ import annotations
import hashlib, json, math, re, sys
from pathlib import Path

FIELDS={"name","type","unit","buckets","help","producer","labels","cardinality_ceiling","scrape_interval_seconds","freshness_deadline_seconds","aggregation","window","unknown_semantics","recording_rule","recording_expression","alert","alert_expression","severity","for","dashboard","release_gates"}
STAGES={"emitter","scrape","parser","recording_rule","alert","dashboard","release_gate"}
INJECTIONS={"absent","stale","malformed","reset","cardinality_overflow"}
GATES={"G0","G1","G2","G3","G4","G5"}
NAME=re.compile(r"^noos_[a-z0-9_]+$")

def load(path):
 try:return json.loads(path.read_text(encoding="utf-8"))
 except (OSError,json.JSONDecodeError) as exc:raise ValueError(f"{path}: JSON-form YAML/JSON parse failed: {exc}")

def frozen_root(root, paths):
 h=hashlib.sha256()
 for rel in sorted(paths):
  h.update(rel.encode("utf-8")); h.update(b"\0")
  h.update(hashlib.sha256((root/rel).read_bytes()).digest())
 return h.hexdigest()

def validate(root):
 errors=[]
 try:spec=load(root/"protocol/telemetry/telemetry-v1.yaml")
 except ValueError as exc:return [str(exc)]
 try:roots=load(root/"protocol/telemetry/contract-root-v1.json")
 except ValueError as exc:errors.append(str(exc));roots={}
 expected_files={"protocol/telemetry/telemetry-v1.yaml","protocol/telemetry/fixtures/all-metrics-v1.json","protocol/telemetry/fixtures/pipeline-v1.json"}
 if set(roots.get("files",{}))!=expected_files:errors.append("telemetry root manifest file set mismatch")
 for rel,digest in roots.get("files",{}).items():
  try:actual=hashlib.sha256((root/rel).read_bytes()).hexdigest()
  except OSError as exc:errors.append(f"{rel}: hash read failed: {exc}");continue
  if digest!=actual:errors.append(f"{rel}: frozen hash mismatch")
 fixture_files=expected_files-{"protocol/telemetry/telemetry-v1.yaml"}
 if roots.get("fixture_root")!=frozen_root(root,fixture_files):errors.append("telemetry fixture root mismatch")
 if roots.get("contract_root")!=frozen_root(root,expected_files):errors.append("telemetry contract root mismatch")
 if spec.get("schema_version")!=1 or spec.get("namespace")!="noos":errors.append("schema identity must be telemetry v1/noos")
 semantics=spec.get("global_semantics",{})
 for key in ("absent","stale","malformed","counter_reset","cardinality_overflow","gate_policy","prohibited_labels"):
  if key not in semantics:errors.append(f"global semantics missing {key}")
 if semantics.get("unknown_value")!="UNKNOWN" or semantics.get("unknown_is_never_zero_or_healthy") is not True:errors.append("UNKNOWN must be explicit and never zero/healthy")
 prohibited=set(semantics.get("prohibited_labels",[])); metrics=spec.get("metrics",[]); names=[]; rules=set(); alerts=set(); dashboards=set(spec.get("dashboards",[]))
 for i,m in enumerate(metrics):
  ident=m.get("name",f"row-{i}"); names.append(ident)
  missing=FIELDS-set(m)
  if missing:errors.append(f"{ident}: missing fields {sorted(missing)}")
  if not isinstance(ident,str) or not NAME.fullmatch(ident):errors.append(f"{ident}: noncanonical metric name")
  if m.get("type") not in {"counter","gauge","histogram"}:errors.append(f"{ident}: invalid type")
  if m.get("type")=="counter" and not ident.endswith("_total"):errors.append(f"{ident}: counter must end _total")
  buckets=m.get("buckets")
  if m.get("type")=="histogram":
   if not isinstance(buckets,list) or not buckets or any(not isinstance(x,(int,float)) or isinstance(x,bool) or not math.isfinite(x) for x in buckets) or buckets!=sorted(set(buckets)):errors.append(f"{ident}: buckets must be finite, unique, increasing")
  elif buckets!=[]:errors.append(f"{ident}: non-histogram buckets must be []")
  labels=m.get("labels")
  if not isinstance(labels,dict):errors.append(f"{ident}: labels must be object");labels={}
  if prohibited & set(labels):errors.append(f"{ident}: prohibited labels {sorted(prohibited&set(labels))}")
  product=1
  for label,values in labels.items():
   if not isinstance(values,list) or not values or len(values)!=len(set(values)) or any(not isinstance(v,str) or not v for v in values):errors.append(f"{ident}: label {label} needs nonempty unique enum")
   else:product*=len(values)
  ceiling=m.get("cardinality_ceiling")
  if not isinstance(ceiling,int) or isinstance(ceiling,bool) or ceiling<product or ceiling<1:errors.append(f"{ident}: cardinality ceiling below enumerated product {product}")
  scrape=m.get("scrape_interval_seconds");fresh=m.get("freshness_deadline_seconds")
  if not isinstance(scrape,int) or not isinstance(fresh,int) or scrape<=0 or fresh<2*scrape:errors.append(f"{ident}: freshness must be at least two scrape intervals")
  if "UNKNOWN" not in str(m.get("unknown_semantics")):errors.append(f"{ident}: UNKNOWN semantics absent")
  if "unknown(" not in str(m.get("alert_expression")):errors.append(f"{ident}: alert must fire on UNKNOWN")
  if m.get("severity") not in {"warning","critical"}:errors.append(f"{ident}: invalid severity")
  if not isinstance(m.get("release_gates"),list) or not m["release_gates"] or not set(m["release_gates"])<=GATES:errors.append(f"{ident}: invalid release gates")
  if m.get("dashboard") not in dashboards:errors.append(f"{ident}: unknown dashboard")
  rule=m.get("recording_rule");alert=m.get("alert")
  if rule in rules:errors.append(f"{ident}: duplicate recording rule {rule}")
  if alert in alerts:errors.append(f"{ident}: duplicate alert {alert}")
  rules.add(rule);alerts.add(alert)
 if len(names)!=len(set(names)):errors.append("duplicate metric name")
 required_fragments=("p2p_peers","consensus_stall","finality_lag","queue_depth","mempool","freshness","identity_match","replica_divergence","rpc_requests","faucet_requests","tls_certificate","descriptor_drift","genesis_drift","download_bytes","version_skew","witness_stake","control_cluster_concentration","ecosystem_concentration","nel_correctness","nel_token_latency","nel_da_retrieval","nel_dispute_rounds","nel_dispute_bytes","nel_dispute_duration","nel_diversity","nel_finality_state_jobs","nel_finality_state_age","nel_verifier_backlog","nel_bond_value_exposure")
 for frag in required_fragments:
  if not any(frag in n for n in names):errors.append(f"mandated metric family missing: {frag}")
 try:coverage=load(root/"protocol/telemetry/fixtures/all-metrics-v1.json")
 except ValueError as exc:errors.append(str(exc));coverage={}
 families=coverage.get("families",[])
 if set(families)!=set(names):errors.append(f"all-metrics fixture mismatch missing={sorted(set(names)-set(families))} extra={sorted(set(families)-set(names))}")
 if len(families)!=len(set(families)):errors.append("all-metrics fixture has duplicates")
 try:pipeline=load(root/"protocol/telemetry/fixtures/pipeline-v1.json")
 except ValueError as exc:errors.append(str(exc));pipeline={}
 if set(pipeline.get("pipeline",[]))!={"emitter","scrape","parser","recording_rule","alert","dashboard","release_gate"}:errors.append("pipeline stage declaration incomplete")
 seen=set()
 for c in pipeline.get("cases",[]):
  cid=c.get("id","unnamed");inj=c.get("injection")
  if c.get("metric") not in set(names):errors.append(f"{cid}: unknown metric")
  if not STAGES<=set(c):errors.append(f"{cid}: missing pipeline stages {sorted(STAGES-set(c))}")
  if inj in INJECTIONS:
   seen.add(inj)
   if c.get("parser",{}).get("status") not in {"UNKNOWN","RESET"}:errors.append(f"{cid}: failure parser not UNKNOWN/RESET")
   if c.get("recording_rule",{}).get("value")!="UNKNOWN":errors.append(f"{cid}: failure recording rule not UNKNOWN")
   if c.get("alert",{}).get("state")!="FIRING" or c.get("dashboard",{}).get("state")!="UNKNOWN" or c.get("release_gate",{}).get("state")!="BLOCKED":errors.append(f"{cid}: failure did not alert/UNKNOWN/block")
 if seen!=INJECTIONS:errors.append(f"failure injections incomplete missing={sorted(INJECTIONS-seen)}")
 return errors

def main(argv):
 root=Path(argv[1]).resolve() if len(argv)>1 else Path(__file__).resolve().parents[2]
 errors=validate(root)
 if errors:
  for e in errors:print(f"ERROR: {e}")
  print(f"Telemetry contract gate: FAIL ({len(errors)} error(s))");return 1
 print("Telemetry contract gate: PASS (all metric rows + emitter/scrape/parser/rule/alert/dashboard/gate fixtures)");return 0
if __name__=="__main__":raise SystemExit(main(sys.argv))
