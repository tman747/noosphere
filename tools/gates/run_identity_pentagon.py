#!/usr/bin/env python3
import argparse
from experimental_gate import cargo_test, emit, evidence_check
p=argparse.ArgumentParser(); p.add_argument('--claims',required=True); p.add_argument('--model',required=True); p.add_argument('--chunk',type=int,required=True); p.add_argument('--orderings',type=int,required=True); p.add_argument('--shadow-only',action='store_true',required=True); a=p.parse_args()
claims=a.claims.split(',')
if claims != ['E-IDENT-01','E-IDENT-02','E-IDENT-03'] or a.chunk != 32 or a.orderings < 100000: raise SystemExit('identity gate parameters do not match preregistration')
local=cargo_test(['noos-analytics','noos-training'])
checks=[evidence_check('local-precursor','falsifier',True,local),evidence_check('real-campaign-threshold','external_requirement',False,'no registered real 0.5B witness corpus with measured five-path marginal cost, 15/15 mutations, and two-epoch live lane-disable evidence')]
emit(gate='identity-pentagon',claims=claims+['I-PENTAGON'],result='EXTERNAL_BLOCKED',expected='EXTERNAL_BLOCKED',checks=checks,sources=['crates/noos-analytics/src/lib.rs','crates/noos-training/src/lib.rs'],limitations=['I-PENTAGON remains shadow-only.'])
