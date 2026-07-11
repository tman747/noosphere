package main

import (
 "bufio"
 "encoding/json"
 "fmt"
 "io"
 "os"
 "github.com/mindchain/noosphere/go/weftref"
)
func emit(source string)bool{c,ds:=weftref.Compile(source);if len(ds)>0{for _,d:=range ds{fmt.Fprintln(os.Stderr,d.Error())};return false};if err:=json.NewEncoder(os.Stdout).Encode(c);err!=nil{fmt.Fprintln(os.Stderr,"E-EMIT-001:",err);return false};return true}
func main(){if len(os.Args)>1&&os.Args[1]=="--ndjson"{s:=bufio.NewScanner(os.Stdin);s.Buffer(make([]byte,4096),1<<20);for s.Scan(){if !emit(s.Text()){os.Exit(1)}};if err:=s.Err();err!=nil{fmt.Fprintln(os.Stderr,"E-IO-001:",err);os.Exit(2)};return};source,err:=io.ReadAll(os.Stdin);if len(os.Args)>1&&os.Args[1]!="--json"{source,err=os.ReadFile(os.Args[1])};if err!=nil{fmt.Fprintln(os.Stderr,"E-IO-001:",err);os.Exit(2)};if !emit(string(source)){os.Exit(1)}}
