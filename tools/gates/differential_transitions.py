#!/usr/bin/env python3
"""Canonical three-client differential and real-process AA/AB/BA/BB matrix.

The Python oracle is independently authored from frozen documents/vectors.  It
strictly decodes bounded TransactionV1/TransactionWitnessesV1 objects, computes
canonical identities, six sparse-tree roots, the ordered execution-receipt root,
and the finality fork tuple.  Rust and Go are always separate OS processes.
"""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, struct, subprocess, sys, tempfile
from dataclasses import dataclass
from pathlib import Path
import blake3
try:
 from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError as exc: raise SystemExit("cryptography is required to verify client handshakes") from exc
ROOT=Path(__file__).resolve().parents[2]
EMPTY=None

def h(domain:bytes,*parts:bytes)->bytes:
 x=blake3.blake3();x.update(domain)
 for p in parts:x.update(p)
 return x.digest()
def empty_root()->bytes:
 global EMPTY
 if EMPTY is None:
  x=h(b"NOOS/SMT/LEAF/V1")
  for _ in range(256):x=h(b"NOOS/SMT/NODE/V1",x,x)
  EMPTY=x
 return EMPTY
def smt_one(key:bytes,value:bytes)->bytes:
 es=[h(b"NOOS/SMT/LEAF/V1")]
 for _ in range(256):es.append(h(b"NOOS/SMT/NODE/V1",es[-1],es[-1]))
 cur=h(b"NOOS/SMT/LEAF/V1",key,value)
 for d in range(255,-1,-1):
  e=es[255-d];cur=h(b"NOOS/SMT/NODE/V1",cur,e) if not ((key[d//8]>>(7-d%8))&1) else h(b"NOOS/SMT/NODE/V1",e,cur)
 return cur
class Decode(Exception):pass
class R:
 def __init__(self,b:bytes):self.b=b;self.p=0
 def take(self,n):
  if self.p+n>len(self.b):raise Decode("TRUNCATED")
  x=self.b[self.p:self.p+n];self.p+=n;return x
 def u8(self):return self.take(1)[0]
 def u16(self):return struct.unpack("<H",self.take(2))[0]
 def u32(self):return struct.unpack("<I",self.take(4))[0]
 def version(self):
  if self.u16()!=1:raise Decode("UNKNOWN_VERSION")
 def tag(self,n):
  if self.u16()!=n:raise Decode("UNKNOWN_MANDATORY_FIELD")
 def count(self,m):
  n=self.u32()
  if n>m:raise Decode("LENGTH_EXCEEDS_BOUND")
  return n
 def bounded(self,m):
  n=self.count(m);return self.take(n)
def note(r):
 r.version()
 for i,n in enumerate((32,16,32,32,8,4,32),1):r.tag(i);r.take(n)
def feeauth(r):
 r.version()
 for i,n in enumerate((16,48,8,32,32,2),1):r.tag(i);r.take(n)
 r.tag(7);r.bounded(96)
def decode_tx(b):
 r=R(b);r.version()
 for tag,n in ((1,32),(2,2),(3,8),(4,32)):r.tag(tag);r.take(n)
 r.tag(5);p=r.u8()
 if p>1:raise Decode("UNKNOWN_DISCRIMINANT")
 if p:feeauth(r)
 r.tag(6);r.take(48);r.tag(7);r.take(r.count(256)*32);r.tag(8);r.take(r.count(64)*32)
 r.tag(9)
 for _ in range(r.count(256)):
  r.take(32)
  if r.u8()>1:raise Decode("UNKNOWN_DISCRIMINANT")
 r.tag(10)
 for _ in range(r.count(64)):r.bounded(65536)
 r.tag(11)
 for _ in range(r.count(256)):note(r)
 r.tag(12);r.take(r.count(64)*32);r.tag(13);r.take(32)
 if r.p!=len(b):raise Decode("TRAILING_BYTES")
def intent(r):
 r.version();r.tag(1);r.take(32);r.tag(2);r.take(1);r.tag(3);p=r.u8()
 if p>1:raise Decode("UNKNOWN_DISCRIMINANT")
 if p:r.take(32)
 r.tag(4);r.take(2);r.tag(5);r.bounded(96)
def decode_witness(b):
 r=R(b);r.version();r.tag(1)
 for _ in range(r.count(64)):intent(r)
 r.tag(2);start=r.p
 for _ in range(r.count(256)):r.bounded(4096)
 if r.p!=len(b):raise Decode("TRAILING_BYTES")
 return b[start:]
def receipt(tid,status,charge):return struct.pack("<HH",1,1)+tid+struct.pack("<HH",2,status)+struct.pack("<H",3)+charge.to_bytes(16,"little")+struct.pack("<H",4)+bytes(48)
@dataclass(frozen=True)
class Case:
 ident:int;tx:bytes;witness:bytes;justified:int;finalized:int;work:int;supply:int;status:int;charge:int;trap:int;block_hash:bytes
 def wire(self):return ",".join((str(self.ident),self.tx.hex(),self.witness.hex(),str(self.justified),str(self.finalized),str(self.work),"0",str(self.supply),str(self.status),str(self.charge),str(self.trap),self.block_hash.hex()))
def oracle(c:Case)->str:
 empty=empty_root().hex();roots=";".join([empty]*6)
 try:decode_tx(c.tx);decode_witness(c.witness)
 except Decode as e:return f"{c.ident},REJECT,{e},{roots},,,{c.justified},{c.finalized},{c.supply},0,0,,"
 tid=h(b"NOOS/TX/ID/V1",c.tx);wid=h(b"NOOS/TX/WID/V1",c.tx,c.witness);rec=receipt(tid,c.status,c.charge)
 roots=";".join((empty,empty,empty,empty,smt_one(tid,rec).hex(),empty));execution=h(b"NOOS/BODY/RECEIPT/V1",struct.pack("<I",1)+rec).hex();inv=bytes(x^255 for x in c.block_hash).hex();fork=f"{c.finalized}:{c.justified}:{c.work}:{inv}"
 cls,err=("ACCEPT","OK") if c.status==0 else ("FAILED","EXECUTION_FAILURE")
 return f"{c.ident},{cls},{err},{roots},{execution},{fork},{c.justified},{c.finalized},{c.supply},{c.charge},{c.trap},{tid.hex()},{wid.hex()}"
def base_objects():
 data=json.loads((ROOT/"protocol/vectors/lumen/lumen-tx-v1.json").read_text())
 tx=bytes.fromhex(next(x["bytes"] for x in data["cases"] if x["name"]=="tx_minimal_roundtrip"));wit=bytes.fromhex("0100010000000000020000000000");return tx,wit
def cases(start,count,seed):
 tx,wit=base_objects();x=seed&((1<<64)-1)
 for ident in range(start,start+count):
  x=(x+0x9E3779B97F4A7C15)&((1<<64)-1);z=x;z=((z^(z>>30))*0xBF58476D1CE4E5B9)&((1<<64)-1);z=((z^(z>>27))*0x94D049BB133111EB)&((1<<64)-1);z^=z>>31
  kind=z%7;t,w=tx,wit
  if kind==1:t=tx[:z%len(tx)]
  elif kind==2:t=tx+b"\x00"
  elif kind==3:t=b"\x02\x00"+tx[2:]
  elif kind==4:t=tx[:2]+b"\x63\x00"+tx[4:]
  elif kind==5:
   p=tx.find(b"\x07\x00\x00\x00\x00\x00");t=tx[:p+2]+struct.pack("<I",257)+tx[p+6:]
  elif kind==6:w=wit[:-1]
  status=(0,1000,2007)[(z>>8)%3] if kind==0 else 0;charge=(z>>16)%1001 if status else 0;trap=7 if status==2007 else 0
  bh=h(b"NOOS/BLOCK/HEADER/V1",struct.pack("<QQ",ident,z));yield Case(ident,t,w,z%16,(z>>4)%16,z%100000,10**18,status,charge,trap,bh)
def build(tmp):
 env=os.environ.copy();env["CARGO_TARGET_DIR"]=str(tmp/"rust-target");subprocess.run(["cargo","build","--locked","-p","noos-lumen","--bin","noos-transition"],cwd=ROOT,env=env,check=True)
 suffix=".exe" if os.name=="nt" else "";rust=tmp/("rust-transition"+suffix);shutil.copy2(tmp/"rust-target"/"debug"/("noos-transition"+suffix),rust);go=tmp/("go-transition"+suffix);subprocess.run(["go","build","-trimpath","-o",str(go),"./cmd/noos-transition"],cwd=ROOT/"go",check=True);return {"rust":rust,"go":go}
def attest(name,exe,nonce):
 out=subprocess.check_output([str(exe),"--identity",nonce.hex()],text=True).strip().split(",");family,version,pub,sig=out[:4];pk=Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub))
 if name=="go":msg=b"NOOS/CLIENT/HANDSHAKE/V1"+family.encode()+struct.pack("<H",int(version))+nonce
 else:msg=b"NOOS/SIG/PEER/V1"+bytes.fromhex(out[4])+bytes([0x47])*32+struct.pack("<H",int(version))+bytes.fromhex(pub)
 pk.verify(bytes.fromhex(sig),msg);return blake3.blake3(bytes.fromhex(pub)+struct.pack("<H",int(version))).hexdigest()
def launch(exe):return subprocess.Popen([str(exe)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1)
def exchange(p,c):
 assert p.stdin and p.stdout;p.stdin.write(c.wire()+"\n");p.stdin.flush();return p.stdout.readline().rstrip("\r\n")
def run(a):
 with tempfile.TemporaryDirectory(prefix="noos-canonical-diff-") as d:
  bins=build(Path(d));nonce=hashlib.sha256(struct.pack("<Q",a.seed)).digest();identities={n:attest(n,e,nonce) for n,e in bins.items()}
  if len(set(identities.values()))!=2:raise SystemExit("client handshake identities are not independent")
  names=("rust","go");procs={n:launch(bins[n]) for n in names};mismatches=0;total=0
  pairs=(("AA","rust","rust"),("AB","rust","go"),("BA","go","rust"),("BB","go","go")) if a.process_matrix else ()
  try:
   for c in cases(a.start,a.generated,a.seed):
    expected=oracle(c);total+=1
    for n in names:
     got=exchange(procs[n],c)
     if got!=expected:
      mismatches+=1;print(f"DIVERGENCE family={identities[n]} case={c.ident} oracle={expected} actual={got}",file=sys.stderr)
    if a.restart_every and total%a.restart_every==0:
     for n in names:
      assert procs[n].stdin;procs[n].stdin.close();procs[n].wait(timeout=10);procs[n]=launch(bins[n]);sync=exchange(procs[n],c)
      if sync!=expected:mismatches+=1
    if mismatches>=a.max_mismatches:break
   matrix=[]
   for label,left,right in pairs:
    producer=launch(bins[left]);consumer=launch(bins[right]);sample=next(cases(a.start,1,a.seed));expected=oracle(sample);ok=exchange(producer,sample)==expected and exchange(consumer,sample)==expected
    for p in (producer,consumer):p.stdin.close();p.wait(timeout=10)
    matrix.append(f"{label}={'PASS' if ok else 'FAIL'}");mismatches+=0 if ok else 1
  finally:
   for p in procs.values():
    if p.stdin and not p.stdin.closed:p.stdin.close()
    p.wait(timeout=10)
 print(f"RESULT differential_transitions={'PASS' if not mismatches else 'FAIL'} cases={total} divergences={mismatches} families={','.join(identities.values())} matrix={';'.join(matrix)} parameterized_max={a.parameterized_max}")
 return int(bool(mismatches))
def main():
 p=argparse.ArgumentParser();p.add_argument("--generated",type=int,default=100_000);p.add_argument("--parameterized-max",type=int,default=10_000_000);p.add_argument("--seed",type=lambda x:int(x,0),default=0x4E4F4F53);p.add_argument("--start",type=int,default=0);p.add_argument("--max-mismatches",type=int,default=10);p.add_argument("--restart-every",type=int,default=25_000);p.add_argument("--process-matrix",action=argparse.BooleanOptionalAction,default=True);a=p.parse_args()
 if min(a.generated,a.parameterized_max,a.max_mismatches)<1 or a.start<0:p.error("counts must be positive and start non-negative")
 return run(a)
if __name__=="__main__":raise SystemExit(main())
