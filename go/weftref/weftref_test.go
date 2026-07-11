package weftref

import "testing"

func TestCompileKnownFormula(t *testing.T){c,ds:=Compile("fn inc(x: u64) -> u64 ! {} cost 20 dec 0 { x + 1 }");if len(ds)!=0{t.Fatal(ds)};if len(c.Units)!=1||c.Units[0].FormulaID!="bc5afc24d46851a39b739c059b7b248929c96813b5e9637375bbcc8addfa2a99"{t.Fatalf("unexpected unit: %+v",c.Units)}}
func TestStableDiagnostics(t *testing.T){_,ds:=Compile("fn f(x: lin Hash) -> () ! {} { () }");if len(ds)==0||ds[0].Code!="E-LIN-001"{t.Fatalf("diagnostics=%v",ds)}}
func TestSpanAdmissionMutations(t *testing.T){a:=make([]int8,16);b:=make([]int8,16);for i:=range a{a[i]=1;b[i]=2};c,err:=GEMMI8(a,b,4,4,4);if err!=nil{t.Fatal(err)};c8,err:=RequantW8A8(c,1,1);if err!=nil{t.Fatal(err)};cert,err:=DeriveSpan(a,b,4,4,4,1,1,[2]uint32{7,9});if err!=nil{t.Fatal(err)};if err=AdmitSpan(cert,a,b,c,c8);err!=nil{t.Fatal(err)};c[0]++;if err=AdmitSpan(cert,a,b,c,c8);err==nil{t.Fatal("tampered C32 admitted")};cert.Reps=1;if err=AdmitSpan(cert,a,b,c,c8);err==nil{t.Fatal("weak soundness admitted")}}
