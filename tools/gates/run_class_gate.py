#!/usr/bin/env python3
import argparse
from experimental_gate import cargo_test, emit, evidence_check
p=argparse.ArgumentParser(); p.add_argument('--version',type=int,required=True); p.add_argument('--irreversible-budget',type=int,required=True); p.add_argument('--reorg-revocation-matrix',action='store_true',required=True); a=p.parse_args()
if a.version != 2 or a.irreversible_budget != 0: raise SystemExit('only preregistered v2 with zero irreversible budget is valid')
local=cargo_test(['noos-agent-class','noos-contracts'])
checks=[evidence_check('claim-implementation','implementation',True,local),evidence_check('claim-falsifiers','falsifier',True,local)]
emit(gate='class-gate-v2',claims=['A-CLASS-GATE.v2','I-AGENT'],result='PASSED',expected='PASSED',checks=checks,sources=['crates/noos-agent-class/Cargo.toml','crates/noos-agent-class/src/lib.rs','crates/noos-contracts/Cargo.toml','crates/noos-contracts/src/router.rs','protocol/spec/constants-v1.toml'])
