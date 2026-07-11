#!/usr/bin/env python3
"""Fail-closed gate for protocol/genesis/mainnet-parameters.template.toml.

The template is honest scaffolding: every owner decision is an explicit
"OWNER_BLOCKED" placeholder. This gate REFUSES to let placeholder values be
presented as real mainnet parameters:

* default run on the template → RESULT=OWNER_BLOCKED (exit 2; 0 with
  --allow-owner-blocked) listing every blocked field;
* a file claiming readiness (owner_signed = true or is_template = false)
  while placeholders remain, signatures are missing, fixtures appear, or a
  radical control is enabled → RESULT=FAIL (exit 1);
* --self-test exercises the falsifiers.
"""
from __future__ import annotations
import argparse, sys, tempfile
from pathlib import Path
try:
 import tomllib
except ModuleNotFoundError:
 import tomli as tomllib
ROOT=Path(__file__).resolve().parents[2]
TEMPLATE=ROOT/"protocol/genesis/mainnet-parameters.template.toml"
PLACEHOLDER="OWNER_BLOCKED"
# Every field the owner must supply; absence is as dishonest as a fake value.
REQUIRED_OWNER_FIELDS=[
 ("","chain_name"),
 ("consensus","max_future_drift_ms"),
 ("witness_ring","min_bond_micro_noos"),
 ("emission","max_supply_micro_noos"),("emission","emission_terminal_height"),
 ("emission","emission_table_root"),("emission","recipient_share_ground_bp"),
 ("emission","recipient_share_witness_bp"),("emission","recipient_share_treasury_bp"),
 ("emission","rounding_rule_id"),("emission","fee_disposition_id"),
 ("allocations","allocations_root"),
 ("commitments","claim_registry_root"),("commitments","conformance_vector_root"),
 ("commitments","software_manifest_root"),
 ("dkg","participants"),("dkg","threshold"),
 ("authorization","exact_revision"),("authorization","role_keyring_path"),
 ("authorization","signed_repro_policy_record_path"),
 ("signatures","record_path"),
]
ZERO_CONTROLS={"work_loom_credit_enabled":False,"work_loom_weight_cap":0,
 "witness_proofpower_bonus_enabled":False,"neural_lane_enabled":False,
 "reflex_lane_enabled":False,"umbra_suite_enabled":False,"dream_lane_enabled":False,
 "class_gate_irreversible_budget":0}

def walk(doc:dict,section:str,key:str):
 node=doc if not section else doc.get(section,{})
 return node.get(key) if isinstance(node,dict) else None

def check(path:Path)->tuple[list[str],list[str]]:
 """Returns (errors, owner_blocked_fields)."""
 errors=[];blocked=[]
 try:doc=tomllib.loads(path.read_text("utf-8"))
 except Exception as exc:return [f"parse failed: {exc}"],[]
 if doc.get("is_test_network") is not False:errors.append("mainnet file must declare is_test_network = false")
 claims_real=bool(doc.get("owner_signed")) or doc.get("is_template") is False
 for section,key in REQUIRED_OWNER_FIELDS:
  value=walk(doc,section,key);field=f"{section+'.' if section else ''}{key}"
  if value is None:errors.append(f"missing owner field {field}")
  elif value==PLACEHOLDER:blocked.append(field)
 if claims_real and blocked:
  errors.append("file claims owner_signed/non-template but still contains OWNER_BLOCKED placeholders: "+", ".join(sorted(blocked)))
 if claims_real:
  record=walk(doc,"signatures","record_path")
  if record in (None,PLACEHOLDER) or not (ROOT/str(record)).is_file():
   errors.append("owner_signed file lacks a resolvable detached signature record")
 # Fixture and control laws hold for template and real file alike.
 def scan_fixtures(node,prefix=""):
  if isinstance(node,dict):
   for key,value in node.items():
    if key=="is_test_fixture" and value:errors.append(f"is_test_fixture material at {prefix or '<root>'}: refused off test networks")
    scan_fixtures(value,f"{prefix}.{key}" if prefix else key)
 scan_fixtures(doc)
 if "faucet" in doc:errors.append("mainnet file must not carry a faucet section (test fixture)")
 controls=doc.get("controls",{})
 for key,expected in ZERO_CONTROLS.items():
  if controls.get(key)!=expected:errors.append(f"genesis control {key} must be {expected!r} on every network")
 # Shares must sum to 10000 once real.
 shares=[walk(doc,"emission",k) for k in ("recipient_share_ground_bp","recipient_share_witness_bp","recipient_share_treasury_bp")]
 if all(isinstance(s,int) for s in shares) and sum(shares)!=10000:errors.append("recipient shares must sum to 10000 bp")
 return errors,sorted(blocked)

def self_test()->int:
 errors,blocked=check(TEMPLATE)
 assert not errors,f"pristine template must have no structural errors: {errors}"
 assert len(blocked)==len(REQUIRED_OWNER_FIELDS),f"every owner field must be blocked: {blocked}"
 text=TEMPLATE.read_text("utf-8")
 with tempfile.TemporaryDirectory() as tmp:
  # Falsifier 1: claiming owner_signed with placeholders present must FAIL.
  dishonest=Path(tmp)/"signed-with-placeholders.toml"
  dishonest.write_text(text.replace("owner_signed = false","owner_signed = true"),"utf-8")
  errors,_=check(dishonest)
  assert any("still contains OWNER_BLOCKED" in e for e in errors),"placeholder-as-real must be refused"
  # Falsifier 2: filling values but skipping the signature record must FAIL.
  filled=text.replace("owner_signed = false","owner_signed = true")
  filled=filled.replace('"OWNER_BLOCKED"','"deadbeef"')
  filled=filled.replace('max_future_drift_ms = "deadbeef"','max_future_drift_ms = 12000')
  unsigned=Path(tmp)/"filled-unsigned.toml"
  unsigned.write_text(filled,"utf-8")
  errors,blocked=check(unsigned)
  assert not blocked,"no placeholders should remain in the filled file"
  assert any("signature record" in e for e in errors),"filled file without signatures must be refused"
  # Falsifier 3: a radical control flipped on must FAIL.
  hot=Path(tmp)/"control-on.toml"
  hot.write_text(text.replace("neural_lane_enabled = false","neural_lane_enabled = true"),"utf-8")
  errors,_=check(hot)
  assert any("neural_lane_enabled" in e for e in errors),"enabled radical control must be refused"
  # Falsifier 4: fixture material must FAIL.
  fixture=Path(tmp)/"fixture.toml"
  fixture.write_text(text+"\n[faucet]\nenabled = true\nis_test_fixture = true\n","utf-8")
  errors,_=check(fixture)
  assert any("faucet" in e for e in errors) and any("is_test_fixture" in e for e in errors),"fixtures must be refused"
 print("RESULT check_mainnet_template_self_test=PASS falsifiers=4")
 return 0

def main()->int:
 p=argparse.ArgumentParser()
 p.add_argument("path",nargs="?",default=str(TEMPLATE))
 p.add_argument("--allow-owner-blocked",action="store_true")
 p.add_argument("--self-test",action="store_true")
 a=p.parse_args()
 if a.self_test:return self_test()
 errors,blocked=check(Path(a.path))
 if errors:
  print("RESULT check_mainnet_template=FAIL errors="+"; ".join(errors),file=sys.stderr);return 1
 if blocked:
  print("RESULT check_mainnet_template=OWNER_BLOCKED fields="+",".join(blocked))
  return 0 if a.allow_owner_blocked else 2
 print("RESULT check_mainnet_template=PASS")
 return 0
if __name__=="__main__":raise SystemExit(main())
