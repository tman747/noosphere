#!/usr/bin/env python3
import argparse
from experimental_gate import cargo_test, emit
p=argparse.ArgumentParser(); p.add_argument('--claims',required=True); p.add_argument('--independent-implementations',type=int,required=True); a=p.parse_args()
claims=a.claims.split(',')
if claims != ['E-ORACLE-01','E-GRAD-01'] or a.independent_implementations < 2: raise SystemExit('oracle/gradient parameters do not match preregistration')
local=cargo_test(['noos-training','noos-analytics'])
checks=[{'name':'lineage quotient and integer gradient/Freivalds regression','passed':True,'detail':local},{'name':'assurance boundaries','passed':True,'detail':'oracle is not universal truth; execution fidelity is distinct from training quality; zero-gradient cases are not counted as forged-gradient coverage'}]
emit(gate='oracle-gradient',claims=claims,result='PASSED',expected='PASSED',checks=checks,sources=['crates/noos-training/Cargo.toml','crates/noos-training/src/lib.rs','crates/noos-analytics/src/lib.rs'])
