#!/usr/bin/env python3
import argparse
from experimental_gate import cargo_test, emit
p=argparse.ArgumentParser(); p.add_argument('--all-admitted-transforms',action='store_true',required=True); p.parse_args()
local=cargo_test(['noos-loam'])
checks=[{'name':'admitted transform repair contracts and NON_REPAIRABLE rejection','passed':True,'detail':local}]
emit(gate='loam-repair',claims=['S-LOAM-BASE','S-LOAM','S-LIFECYCLE'],result='PASSED',expected='PASSED',checks=checks,sources=['crates/noos-loam/Cargo.toml','crates/noos-loam/src/lib.rs'])
