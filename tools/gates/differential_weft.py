#!/usr/bin/env python3
"""Independent Rust/Go Weft compiler differential and source laboratory."""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, random, shutil, subprocess, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
CORPUS=ROOT/'grain'/'corpus'/'weft'

def build(work:pathlib.Path)->tuple[pathlib.Path,pathlib.Path]:
    rust_target=work/'rust-target'; go_bin=work/('weftref.exe' if os.name=='nt' else 'weftref')
    subprocess.run(['cargo','build','-p','noos-weftc','--target-dir',str(rust_target)],cwd=ROOT,check=True,stdout=subprocess.DEVNULL)
    subprocess.run(['go','build','-o',str(go_bin),'./cmd/weftref'],cwd=ROOT/'go',check=True)
    rust=rust_target/'debug'/('weftc.exe' if os.name=='nt' else 'weftc')
    if not rust.is_file() or not go_bin.is_file(): raise RuntimeError('isolated build did not produce both executables')
    return rust,go_bin

def run_one(exe:pathlib.Path,source:str)->tuple[int,dict|None,str]:
    p=subprocess.run([str(exe),'--json'],input=source,text=True,capture_output=True)
    try: obj=json.loads(p.stdout) if p.returncode==0 else None
    except json.JSONDecodeError as e: raise RuntimeError(f'{exe} emitted non-JSON: {e}') from e
    return p.returncode,obj,p.stderr

def get(obj:dict,key:str):
    camel=''.join(x.title() for x in key.split('_'))
    return obj.get(key,obj.get(camel,obj.get(camel.replace('Id','ID'))))
def comparable(obj:dict)->tuple:
    units=get(obj,'units'); out=[]
    for u in units:
        out.append((get(u,'name'),get(u,'grain_formula_hex'),get(u,'formula_id')))
    return get(obj,'source_root'),tuple(out)
def diagnostic_code(stderr:str)->str:
    return stderr.split(':',1)[0].strip()
def generated(seed:int,count:int):
    r=random.Random(seed)
    forms=(
      lambda n:f'fn f(x: u64) -> u64 ! {{}} cost 256 dec 0 {{ x + {n%16} }}',
      lambda n:f'fn f(x: u64) -> Bool ! {{}} cost 64 dec 0 {{ x == {n%31} }}',
      lambda n:f'fn f(c: Bool, x: u64) -> u64 ! {{}} cost 64 dec 0 {{ if c {{ x }} else {{ {n%31} }} }}',
      lambda n:f'fn f(x: u64) -> (u64, u64) ! {{}} cost 64 dec 0 {{ (x, {n%31}) }}',
    )
    for _ in range(count):
        n=r.getrandbits(32);yield forms[n%len(forms)](n)

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument('--cases',type=int,default=1000);ap.add_argument('--seed',type=int,default=20260711);ap.add_argument('--keep-builds',action='store_true');a=ap.parse_args()
    work=pathlib.Path(tempfile.mkdtemp(prefix='weft-diff-'))
    try:
      rust,go=build(work); sources=[p.read_text(encoding='utf-8') for p in sorted(CORPUS.glob('*.weft'))]; sources.extend(generated(a.seed,min(a.cases,4096)))
      cache={};digest=hashlib.sha256()
      for source in sources:
        if source in cache: continue
        rr,ro,re=run_one(rust,source);gr,goj,ge=run_one(go,source)
        if rr or gr: raise AssertionError(f'valid source rejected rust={rr}:{re} go={gr}:{ge}')
        rc,gc=comparable(ro),comparable(goj)
        if rc!=gc: raise AssertionError(f'elaboration divergence for {source!r}\nrust={rc}\ngo={gc}')
        cache[source]=rc;digest.update(repr(rc).encode())
      # 100k-scale deterministic smoke uses independently established unique outputs.
      checked=0
      for source in generated(a.seed,a.cases):
        if source not in cache:
          rr,ro,re=run_one(rust,source);gr,goj,ge=run_one(go,source)
          if rr or gr or comparable(ro)!=comparable(goj): raise AssertionError(f'generated divergence: {re} {ge}')
          cache[source]=comparable(ro)
        digest.update(repr(cache[source]).encode());checked+=1
      invalid=[('fn f(x: lin Hash) -> () ! {} { () }','E-LIN-001'),('fn f(x: lin Hash) -> () ! {} { let a = consume(x); consume(x) }','E-LIN-002'),('fn f(x: u64) -> u64 ! {} { missing }','E-TYPE-001'),('fn f(x: u64) -> Rand256<h> ! {} { beacon(x) }','E-EFFECT-002'),('fn f(x: u64) -> u64 ! {} { x + }','E-PARSE-001')]
      for source,want in invalid:
        rr,_,re=run_one(rust,source);gr,_,ge=run_one(go,source)
        if rr==0 or gr==0: raise AssertionError('invalid source accepted')
        # Independent span offsets/messages may differ; stable rejection class is law.
        if diagnostic_code(re)!=want or diagnostic_code(ge)!=want: raise AssertionError(f'diagnostic divergence want={want} rust={re} go={ge}')
      print(json.dumps({'gate':'E-WEFT-01','status':'PASS','cases':checked,'unique_cases':len(cache),'corpus_files':len(list(CORPUS.glob('*.weft'))),'digest':digest.hexdigest(),'isolated_builds':True},sort_keys=True));return 0
    finally:
      if a.keep_builds: print(f'build_dir={work}',file=sys.stderr)
      else: shutil.rmtree(work,ignore_errors=True)
if __name__=='__main__': raise SystemExit(main())
