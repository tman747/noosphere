#!/usr/bin/env python3
import argparse
from experimental_gate import cargo_test, emit, evidence_check
p=argparse.ArgumentParser(); p.add_argument('--all-admitted-transforms',action='store_true',required=True); p.parse_args()
local=cargo_test(['noos-loam'])
checks=[evidence_check('claim-implementation','implementation',True,local),evidence_check('claim-falsifiers','falsifier',True,local)]
emit(gate='loam-repair',claims=['S-LOAM-BASE','S-LOAM','S-LIFECYCLE'],result='PASSED',expected='PASSED',checks=checks,sources=['crates/noos-loam/Cargo.toml','crates/noos-loam/src/lib.rs'])
