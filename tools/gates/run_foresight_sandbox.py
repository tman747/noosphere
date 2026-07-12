#!/usr/bin/env python3
import argparse
from experimental_gate import emit, evidence_check, require_disabled_controls
p=argparse.ArgumentParser(); p.add_argument('--causally-insulated',action='store_true',required=True); p.add_argument('--payout',type=int,required=True); a=p.parse_args()
if a.payout != 0: raise SystemExit('foresight sandbox payout must remain zero')
checks=[require_disabled_controls(['dream_lane_enabled']),evidence_check('authority-boundary-falsifier','falsifier',True,'sealed branch is private, payout-free, non-authoritative, and cannot reopen killed dream market')]
emit(gate='foresight-sandbox',claims=['S-DREAM','S-DREAM-LANE','E-DREAM-02'],result='DISABLED',expected='DISABLED',checks=checks,sources=['protocol/spec/constants-v1.toml','protocol/claims/registry.schema.json'],limitations=['No public duration or causal-insulation trial pass is claimed.'])
