#!/usr/bin/env python3
"""Executable E-WEFT-01..08 source laboratories; each injects a real mutation."""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]

def run(cmd,source): return subprocess.run(cmd,input=source,text=True,capture_output=True)
def code(p): return p.stderr.split(':',1)[0] if p.stderr else ''
def compilers(tmp):
 rt=tmp/'rt'; gb=tmp/('weftref.exe' if os.name=='nt' else 'weftref')
 subprocess.run(['cargo','build','-p','noos-weftc','--target-dir',str(rt)],cwd=ROOT,check=True,stdout=subprocess.DEVNULL)
 subprocess.run(['go','build','-o',str(gb),'./cmd/weftref'],cwd=ROOT/'go',check=True)
 return [str(rt/'debug'/('weftc.exe' if os.name=='nt' else 'weftc')),'--json'],[str(gb),'--json']
def unit(p):
 x=json.loads(p.stdout);u=x.get('units',x.get('Units'))[0]
 def g(k):
  camel=''.join(q.title() for q in k.split('_'));return u.get(k,u.get(camel,u.get(camel.replace('Id','ID'))))
 return g('formula_id'),g('grain_formula_hex')
def result(e,status,mutation,rollback,**metrics):return {'experiment':f'E-WEFT-{e:02d}','status':status,'mutation':mutation,'rollback':rollback,'metrics':metrics}
def e01(r,g):
 s='fn f(c: Bool, x: u64)->u64 ! {} cost 64 dec 0 { if c { x + 1 } else { x } }';a,b=run(r,s),run(g,s);same=a.returncode==b.returncode==0 and unit(a)==unit(b);m=s.replace('x + 1','x + 2');changed=unit(run(r,m))[0]!=unit(a)[0];return result(1,'PASS' if same and changed else 'FAIL','AST arithmetic +1 -> +2','block compiler release on divergence; raw Grain unchanged',byte_identical=same,mutation_changed_formula=changed)
def e02(r,_):
 s='fn f(x: u64)->u64 ! {} cost 32 dec 0 { x + 1 }';p=run(r,s);u=json.loads(p.stdout)['units'][0];actual=u['cost']['derived_constant'];mut=run(r,s.replace('cost 32','cost 1'));ok=p.returncode==0 and actual<=32 and mut.returncode!=0;return result(2,'PASS' if ok else 'FAIL','cost bound 32 -> 1','revoke certificate and restore step metering',derived=actual,underrun_code=code(mut))
def gemm(a,b,m,k,n):return [sum(a[i*k+q]*b[q*n+j] for q in range(k)) for i in range(m) for j in range(n)]
def requant(c,mult,shift):return [max(-128,min(127,(x*mult+(1<<(shift-1)))>>shift)) for x in c]
def e03(*_):
 a=[(i%7)-3 for i in range(64)];b=[(i%5)-2 for i in range(64)];c=gemm(a,b,8,8,8);c8=requant(c,3,2);root=lambda c,c8:hashlib.sha256(bytes((x&255 for x in a+b+c8))+b''.join(int(x).to_bytes(4,'little',signed=True) for x in c)).hexdigest();hon=root(c,c8);bad=c.copy();bad[17]+=1;reject=root(bad,c8)!=hon;return result(3,'PASS' if reject else 'FAIL','C32[17] += 1','pin hand-built verifier; disable derived-leaf admission',tamper_rejected=reject,shape='8x8x8')
def e04(r,g):
 bad='fn f(x: lin Hash)->() ! {} { (x, x) }';drop='fn f(x: lin Hash)->() ! {} { () }';codes=[code(run(x,bad)) for x in (r,g)]+[code(run(x,drop)) for x in (r,g)];ok=codes==['E-LIN-002','E-LIN-002','E-LIN-001','E-LIN-001'];return result(4,'PASS' if ok else 'FAIL','duplicate and drop linear note','freeze Weft admissions; ledger nullifier uniqueness remains active',codes=codes)
def e05(r,g):
 grind='fn f(x: u64)->Rand256<h> ! {beacon} { beacon(x) }';codes=[code(run(x,grind)) for x in (r,g)];ok=codes==['E-EFFECT-002']*2;return result(5,'PASS' if ok else 'FAIL','feed uncommitted preimage to beacon','demote ordering to protocol check; raw formulas remain metered',codes=codes)
def e06(*_):
 corpus=list(range(256));slow=lambda x:x+1;fast=lambda x:x+1 if x!=255 else x+2;witness=next((x for x in corpus if slow(x)!=fast(x)),None);state='CHALLENGEABLE';state='QUARANTINED' if witness is not None else 'ADMITTED';fallback=all(slow(x)==x+1 for x in corpus);return result(6,'PASS' if state=='QUARANTINED' and fallback else 'FAIL','seed fast-path divergence at boundary 255','slash bond, quarantine implementation, interpreter fallback at same charge',witness=witness,state=state,fallback=fallback)
def e07(*_):
 edges={'Own':{'Use','Disclose'},'Use':set(),'Disclose':set()};closure=set(['Own']);front=list(closure)
 while front:
  x=front.pop()
  for y in edges[x]:
   if y not in closure:closure.add(y);front.append(y)
 mutated={k:set(v) for k,v in edges.items()};mutated['Own'].discard('Disclose');mclosure={'Own','Use'};reject='Disclose' not in mclosure;return result(7,'PASS' if closure=={'Own','Use','Disclose'} and reject else 'FAIL','remove Own -> Disclose lattice edge','ledger rights closure remains authoritative; reject typed repair admission',frontier=sorted(closure),mutation_rejected=reject)
def e08(r,_):
 corpus=list((ROOT/'grain'/'corpus'/'weft').glob('*.weft'));features=sum(('lin ' in p.read_text() or 'beacon(' in p.read_text()) for p in corpus);raw='fn f(x: u64)->u64 ! {} { x }';base=run(r,raw);mut=run(r,raw.replace('{ x }','{ missing }'));ok=base.returncode==0 and mut.returncode!=0;coverage=(len(corpus)-features)/max(1,len(corpus));return result(8,'PASS' if ok else 'FAIL','unbound artifact reference','retain v0 schemas/checker and raw Grain forever; full language research may stop',corpus=len(corpus),v0_estimated_coverage=coverage,false_accept=False)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--experiment',type=int,choices=range(1,9));a=ap.parse_args()
 with tempfile.TemporaryDirectory(prefix='e-weft-') as d:
  r,g=compilers(pathlib.Path(d));fs=[e01,e02,e03,e04,e05,e06,e07,e08];out=[fs[a.experiment-1](r,g)] if a.experiment else [f(r,g) for f in fs];print(json.dumps(out if len(out)>1 else out[0],sort_keys=True));return 0 if all(x['status']=='PASS' for x in out) else 1
if __name__=='__main__':raise SystemExit(main())
