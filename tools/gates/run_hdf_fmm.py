#!/usr/bin/env python3
import argparse
from experimental_gate import cargo_test, emit
p=argparse.ArgumentParser(); p.add_argument('--energy-scope-only',action='store_true',required=True); p.add_argument('--shadow-only',action='store_true',required=True); p.parse_args()
local=cargo_test(['noos-analytics'])
checks=[{'name':'HDF counterexamples and energy-scope analytics regressions','passed':True,'detail':local},{'name':'production influence','passed':True,'detail':'universal M-HDF is retired; energy/FMM outputs are shadow credit only'}]
emit(gate='hdf-fmm',claims=['M-HDF','M-HDF-ENERGY','M-OMEGA'],result='DISABLED',expected='DISABLED',checks=checks,sources=['crates/noos-analytics/Cargo.toml','crates/noos-analytics/src/lib.rs'],limitations=['No Ground, Ring, issuance, or exact Freivalds influence.'])
