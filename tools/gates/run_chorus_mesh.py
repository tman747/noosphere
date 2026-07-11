#!/usr/bin/env python3
import argparse
from experimental_gate import cargo_test, emit
p=argparse.ArgumentParser(); p.add_argument('--devices',type=int,required=True); p.add_argument('--simulations',type=int,required=True); a=p.parse_args()
local=cargo_test(['noos-chorus'])
checks=[{'name':'local lineage/failure-domain falsifiers','passed':True,'detail':local},{'name':'consenting heterogeneous physical mesh','passed':False,'status':'EXTERNAL_BLOCKED','requested_devices':a.devices,'requested_simulations':a.simulations,'reason':'requested counts do not constitute evidence and no immutable 1,000-device consenting deployment corpus is registered'}]
emit(gate='chorus-mesh',claims=['S-CHORUS','E-HEARTH-07','E-HEARTH-08'],result='EXTERNAL_BLOCKED',expected='EXTERNAL_BLOCKED',checks=checks,sources=['crates/noos-chorus/Cargo.toml','crates/noos-chorus/src/lib.rs'],limitations=['Chorus remains non-slashable advisory availability.'])
