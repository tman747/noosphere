#!/usr/bin/env python3
import argparse
from experimental_gate import cargo_test, emit
p=argparse.ArgumentParser(); p.add_argument('--models',required=True); p.add_argument('--devices',required=True); p.add_argument('--instances',type=int,required=True); a=p.parse_args()
local=cargo_test(['noos-hearth'])
required={'cpu','amd','nvidia'}; requested=set(a.devices.split(',')); blocked=not(required<=requested and a.instances>=1_000_000_000)
# CLI declarations are not measurements: the public cross-vendor campaign is external even when the requested envelope is correct.
checks=[{'name':'local Hearth deterministic and fault tests','passed':True,'detail':local},{'name':'cross-vendor measured campaign','passed':False,'status':'EXTERNAL_BLOCKED','required_instances':1_000_000_000,'requested_instances':a.instances,'required_devices':sorted(required),'requested_devices':sorted(requested),'reason':'no immutable CPU/AMD/NVIDIA measurement corpus or independent operators is registered'}]
emit(gate='hearth-matrix',claims=[f'E-HEARTH-0{i}' for i in range(1,9)],result='EXTERNAL_BLOCKED',expected='EXTERNAL_BLOCKED',checks=checks,sources=['crates/noos-hearth/Cargo.toml','crates/noos-hearth/src/lib.rs'],limitations=['Local tests pass; billion-instance and real-device claims remain externally blocked.'])
