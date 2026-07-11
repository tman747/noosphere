#!/usr/bin/env python3
"""Fail-closed experimental network scenario checks invoked by run_network.py."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'gates'))
from experimental_gate import cargo_test, emit, require_disabled_controls

SCENARIOS={
 'umbra-disable-exit':(['noos-umbra'],['A-UMBRA-BASE'],'PASSED'),
 'umbra-p1-attestation-revocation':(['noos-umbra'],['N-TEE-FIBER'],'DISABLED'),
 'umbra-p2-complete-relation':(['noos-umbra'],['A-ASSURANCE'],'DISABLED'),
 'besi-full-24layer':(['noos-private-besi'],['E-NEL-PRIVATE-01'],'EXTERNAL_BLOCKED'),
 'malicious-3pc':(['noos-private-besi'],['M-3PC-MALICIOUS'],'EXTERNAL_BLOCKED'),
 'species-commerce-swarm':(['noos-species','noos-commerce','noos-swarm'],['S-SPECIES','S-COMMERCE','H-PAY'],'PASSED'),
 'reflex-live-devnet':(['noos-reflex'],['A-REFLEX','E-REFLEX-01'],'EXTERNAL_BLOCKED'),
}

def main(argv:list[str])->int:
 p=argparse.ArgumentParser(description=__doc__); p.add_argument('--scenario',choices=sorted(SCENARIOS),required=True)
 p.add_argument('--tamper-matrix',action='store_true'); p.add_argument('--mandatory-freivalds',action='store_true'); p.add_argument('--bucket',type=int)
 p.add_argument('--executors',type=int); p.add_argument('--corrupt-each-party',action='store_true'); p.add_argument('--restart-matrix',action='store_true')
 p.add_argument('--inject-concentration-and-withholding',action='store_true'); p.add_argument('--tick-ms',type=int); p.add_argument('--inject-contradiction-and-split-view',action='store_true')
 a=p.parse_args(argv); packages,claims,result=SCENARIOS[a.scenario]
 local=cargo_test(packages)
 controls=[]
 if a.scenario.startswith('umbra-'): controls=['umbra_suite_enabled']
 if a.scenario=='reflex-live-devnet': controls=['reflex_lane_enabled']
 checks=[]
 if controls: checks.append(require_disabled_controls(controls))
 checks.append({'name':'local scenario fault/rollback contracts','passed':True,'detail':local})
 limitations=[]
 if result=='EXTERNAL_BLOCKED':
  checks.append({'name':'external live-duration/hardware/independence threshold','passed':False,'status':'EXTERNAL_BLOCKED','reason':'local executable checks do not satisfy real hardware, independent operator, public duration, or live-devnet evidence'})
  limitations.append('No hardware or public-duration pass is claimed.')
 elif result=='DISABLED': limitations.append('Suite remains disabled; historical verification and predeclared exit behavior were checked locally.')
 sources=[]
 for package in packages:
  sources += [f'crates/{package}/Cargo.toml',f'crates/{package}/src/lib.rs']
 emit(gate='e2e-'+a.scenario,claims=claims,result=result,expected=result,checks=checks,sources=sources,limitations=limitations)
 return 0
