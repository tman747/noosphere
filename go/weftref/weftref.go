// Package weftref is an independently authored Weft parser, checker, and Grain elaborator.
// It is based only on the frozen language and Grain specifications. It shares no parser,
// runtime, FFI, generated code, or compiler implementation with the Rust compiler.
package weftref

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lukechampine.com/blake3"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

type Diagnostic struct {
	Code    string `json:"code"`
	Start   int    `json:"start"`
	End     int    `json:"end"`
	Message string `json:"message"`
}

func (d Diagnostic) Error() string {
	return fmt.Sprintf("%s:%d-%d: %s", d.Code, d.Start, d.End, d.Message)
}

type token struct {
	k, s       string
	start, end int
}

func scan(src string) ([]token, *Diagnostic) {
	var t []token
	for i := 0; i < len(src); {
		if unicode.IsSpace(rune(src[i])) {
			i++
			continue
		}
		if i+1 < len(src) && src[i:i+2] == "--" {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}
		st := i
		if unicode.IsLetter(rune(src[i])) || src[i] == '_' {
			i++
			for i < len(src) && (unicode.IsLetter(rune(src[i])) || unicode.IsDigit(rune(src[i])) || src[i] == '_') {
				i++
			}
			t = append(t, token{"id", src[st:i], st, i})
			continue
		}
		if unicode.IsDigit(rune(src[i])) {
			i++
			for i < len(src) && unicode.IsDigit(rune(src[i])) {
				i++
			}
			t = append(t, token{"num", src[st:i], st, i})
			continue
		}
		if i+1 < len(src) {
			x := src[i : i+2]
			if x == "->" || x == "==" || x == "<<" || x == ">>" {
				t = append(t, token{x, x, st, i + 2})
				i += 2
				continue
			}
		}
		if strings.ContainsRune("(){}[]<>,:;!+*-=&.@", rune(src[i])) {
			x := src[i : i+1]
			t = append(t, token{x, x, st, i + 1})
			i++
			continue
		}
		d := Diagnostic{"E-LEX-001", st, st + 1, "unexpected source byte"}
		return nil, &d
	}
	t = append(t, token{"eof", "", len(src), len(src)})
	return t, nil
}

type Type struct {
	Name   string
	Linear bool
	Rights []string
	Args   []Type
}

func (x Type) Canonical() string {
	n := x.Name
	if len(x.Args) > 0 {
		a := make([]string, len(x.Args))
		for i := range x.Args {
			a[i] = x.Args[i].Canonical()
		}
		n += "<" + strings.Join(a, ",") + ">"
	}
	if x.Linear {
		n = "lin " + n
	}
	if len(x.Rights) > 0 {
		r := append([]string(nil), x.Rights...)
		sort.Strings(r)
		n += " & rights {" + strings.Join(r, ",") + "}"
	}
	return n
}

type Expr struct {
	Kind, Name string
	Value      uint64
	Bool       bool
	Op         string
	Kids       []*Expr
	Start, End int
}
type Param struct {
	Name string
	Type Type
}
type Function struct {
	Name    string
	Sizes   []string
	Params  []Param
	Ret     Type
	Effects []string
	Cost    string
	Dec     string
	Body    *Expr
}
type Program struct{ Functions []Function }
type parser struct {
	t []token
	i int
}

func (p *parser) cur() token  { return p.t[p.i] }
func (p *parser) bump() token { x := p.cur(); p.i++; return x }
func (p *parser) sym(s string) bool {
	if p.cur().k == s {
		p.i++
		return true
	}
	return false
}
func (p *parser) kw(s string) bool {
	if p.cur().k == "id" && p.cur().s == s {
		p.i++
		return true
	}
	return false
}
func (p *parser) diag(msg string) *Diagnostic {
	x := p.cur()
	return &Diagnostic{"E-PARSE-001", x.start, x.end, msg}
}
func (p *parser) need(s string) *Diagnostic {
	if !p.sym(s) {
		return p.diag("expected '" + s + "'")
	}
	return nil
}
func (p *parser) id() (string, *Diagnostic) {
	x := p.bump()
	if x.k != "id" {
		return "", &Diagnostic{"E-PARSE-001", x.start, x.end, "expected identifier"}
	}
	return x.s, nil
}
func Parse(src string) (Program, []Diagnostic) {
	t, d := scan(src)
	if d != nil {
		return Program{}, []Diagnostic{*d}
	}
	p := parser{t: t}
	var out Program
	for p.cur().k != "eof" {
		f, e := p.fn()
		if e != nil {
			return Program{}, []Diagnostic{*e}
		}
		out.Functions = append(out.Functions, f)
	}
	if len(out.Functions) == 0 {
		return Program{}, []Diagnostic{{"E-PARSE-001", 0, 0, "source contains no functions"}}
	}
	return out, nil
}
func (p *parser) fn() (Function, *Diagnostic) {
	if !p.kw("fn") {
		return Function{}, p.diag("expected 'fn'")
	}
	name, e := p.id()
	if e != nil {
		return Function{}, e
	}
	f := Function{Name: name}
	if p.sym("<") {
		for {
			n, e := p.id()
			if e != nil {
				return f, e
			}
			if p.sym(":") {
				if !p.kw("Size") {
					return f, p.diag("size parameter must have kind Size")
				}
			}
			f.Sizes = append(f.Sizes, n)
			if p.sym(">") {
				break
			}
			if e = p.need(","); e != nil {
				return f, e
			}
		}
	}
	if e = p.need("("); e != nil {
		return f, e
	}
	if !p.sym(")") {
		for {
			n, e := p.id()
			if e != nil {
				return f, e
			}
			if e = p.need(":"); e != nil {
				return f, e
			}
			ty, e := p.ty()
			if e != nil {
				return f, e
			}
			f.Params = append(f.Params, Param{n, ty})
			if p.sym(")") {
				break
			}
			if e = p.need(","); e != nil {
				return f, e
			}
		}
	}
	if e = p.need("->"); e != nil {
		return f, e
	}
	f.Ret, e = p.ty()
	if e != nil {
		return f, e
	}
	if p.sym("!") {
		if e = p.need("{"); e != nil {
			return f, e
		}
		if !p.sym("}") {
			for {
				x, e := p.id()
				if e != nil {
					return f, e
				}
				f.Effects = append(f.Effects, x)
				if p.sym("}") {
					break
				}
				if e = p.need(","); e != nil {
					return f, e
				}
			}
		}
	}
	sort.Strings(f.Effects)
	if p.kw("cost") {
		f.Cost = p.size()
	}
	if p.kw("dec") {
		f.Dec = p.size()
	}
	if e = p.need("{"); e != nil {
		return f, e
	}
	f.Body, e = p.expr(0)
	if e != nil {
		return f, e
	}
	if e = p.need("}"); e != nil {
		return f, e
	}
	return f, nil
}
func (p *parser) size() string {
	x := p.bump()
	if x.k != "id" && x.k != "num" {
		return "?"
	}
	s := x.s
	for p.cur().k == "+" || p.cur().k == "*" {
		o := p.bump().s
		y := p.bump()
		s = "(" + s + o + y.s + ")"
	}
	return s
}
func (p *parser) ty() (Type, *Diagnostic) {
	lin := p.kw("lin")
	if p.sym("(") {
		if p.sym(")") {
			return Type{Name: "()", Linear: lin}, nil
		}
		var a []Type
		for {
			x, e := p.ty()
			if e != nil {
				return Type{}, e
			}
			a = append(a, x)
			if p.sym(")") {
				break
			}
			if e = p.need(","); e != nil {
				return Type{}, e
			}
		}
		return Type{Name: "(" + joinTypes(a) + ")", Linear: lin}, nil
	}
	n, e := p.id()
	if e != nil {
		return Type{}, e
	}
	if n == "Tensor" {
		if e = p.need("<"); e != nil {
			return Type{}, e
		}
		element, d := p.ty()
		if d != nil {
			return Type{}, d
		}
		if e = p.need(","); e != nil {
			return Type{}, e
		}
		if e = p.need("["); e != nil {
			return Type{}, e
		}
		var dimensions []string
		for !p.sym("]") {
			dimensions = append(dimensions, p.size())
			if p.sym("]") {
				break
			}
			if e = p.need(","); e != nil {
				return Type{}, e
			}
		}
		if e = p.need(","); e != nil {
			return Type{}, e
		}
		if e = p.need("@"); e != nil {
			return Type{}, e
		}
		profile, d := p.id()
		if d != nil {
			return Type{}, d
		}
		if p.sym(".") {
			suffix, d := p.id()
			if d != nil {
				return Type{}, d
			}
			profile += "." + suffix
		}
		if e = p.need(">"); e != nil {
			return Type{}, e
		}
		return Type{Name: "Tensor<" + element.Canonical() + ",[" + strings.Join(dimensions, ",") + "],@" + profile + ">", Linear: lin}, nil
	}
	x := Type{Name: n, Linear: lin}
	if p.sym("<") {
		for {
			if p.cur().k == "num" || p.cur().k == "id" {
				z := p.bump().s
				x.Args = append(x.Args, Type{Name: z})
			} else {
				z, e := p.ty()
				if e != nil {
					return x, e
				}
				x.Args = append(x.Args, z)
			}
			if p.sym(">") {
				break
			}
			if e = p.need(","); e != nil {
				return x, e
			}
		}
	}
	if p.sym("&") {
		if !p.kw("rights") {
			return x, p.diag("expected rights row")
		}
		if e = p.need("{"); e != nil {
			return x, e
		}
		for !p.sym("}") {
			r, e := p.id()
			if e != nil {
				return x, e
			}
			x.Rights = append(x.Rights, r)
			if p.sym("}") {
				break
			}
			if e = p.need(","); e != nil {
				return x, e
			}
		}
	}
	return x, nil
}
func joinTypes(a []Type) string {
	v := make([]string, len(a))
	for i := range a {
		v[i] = a[i].Canonical()
	}
	return strings.Join(v, ",")
}
func (p *parser) expr(min int) (*Expr, *Diagnostic) {
	st := p.cur().start
	var x *Expr
	if p.kw("let") {
		n, e := p.id()
		if e != nil {
			return nil, e
		}
		if e = p.need("="); e != nil {
			return nil, e
		}
		a, e := p.expr(0)
		if e != nil {
			return nil, e
		}
		if e = p.need(";"); e != nil {
			return nil, e
		}
		b, e := p.expr(0)
		if e != nil {
			return nil, e
		}
		x = &Expr{Kind: "let", Name: n, Kids: []*Expr{a, b}, Start: st, End: b.End}
	} else if p.kw("if") {
		c, e := p.expr(0)
		if e != nil {
			return nil, e
		}
		if e = p.need("{"); e != nil {
			return nil, e
		}
		a, e := p.expr(0)
		if e != nil {
			return nil, e
		}
		if e = p.need("}"); e != nil {
			return nil, e
		}
		if !p.kw("else") {
			return nil, p.diag("if requires else")
		}
		if e = p.need("{"); e != nil {
			return nil, e
		}
		b, e := p.expr(0)
		if e != nil {
			return nil, e
		}
		if e = p.need("}"); e != nil {
			return nil, e
		}
		x = &Expr{Kind: "if", Kids: []*Expr{c, a, b}, Start: st, End: p.cur().start}
	} else if p.sym("(") {
		if p.sym(")") {
			x = &Expr{Kind: "tuple", Start: st, End: p.cur().start}
		} else {
			a, e := p.expr(0)
			if e != nil {
				return nil, e
			}
			if p.sym(",") {
				v := []*Expr{a}
				for {
					z, e := p.expr(0)
					if e != nil {
						return nil, e
					}
					v = append(v, z)
					if p.sym(")") {
						break
					}
					if e = p.need(","); e != nil {
						return nil, e
					}
				}
				x = &Expr{Kind: "tuple", Kids: v, Start: st, End: p.cur().start}
			} else {
				if e = p.need(")"); e != nil {
					return nil, e
				}
				x = a
			}
		}
	} else {
		z := p.bump()
		switch z.k {
		case "num":
			v, _ := strconv.ParseUint(z.s, 10, 64)
			x = &Expr{Kind: "int", Value: v, Start: z.start, End: z.end}
		case "id":
			if z.s == "true" || z.s == "false" {
				x = &Expr{Kind: "bool", Bool: z.s == "true", Start: z.start, End: z.end}
			} else {
				x = &Expr{Kind: "var", Name: z.s, Start: z.start, End: z.end}
			}
		default:
			return nil, &Diagnostic{"E-PARSE-001", z.start, z.end, "expected expression"}
		}
	}
	for {
		if p.sym("(") {
			if x.Kind != "var" {
				return nil, p.diag("only named calls are supported")
			}
			var a []*Expr
			if !p.sym(")") {
				for {
					z, e := p.expr(0)
					if e != nil {
						return nil, e
					}
					a = append(a, z)
					if p.sym(")") {
						break
					}
					if e = p.need(","); e != nil {
						return nil, e
					}
				}
			}
			x = &Expr{Kind: "call", Name: x.Name, Kids: a, Start: st, End: p.cur().start}
			continue
		}
		prec := map[string]int{"==": 5, "<": 5, "<<": 8, ">>": 8, "+": 10, "-": 10, "*": 20, "@": 20}[p.cur().k]
		if prec == 0 || prec < min {
			break
		}
		o := p.bump().k
		y, e := p.expr(prec + 1)
		if e != nil {
			return nil, e
		}
		x = &Expr{Kind: "binary", Op: o, Kids: []*Expr{x, y}, Start: st, End: y.End}
	}
	return x, nil
}

type checkInfo struct {
	ty      Type
	effects map[string]bool
	used    map[string]bool
	cost    uint64
}

func validateType(t Type) *Diagnostic {
	if strings.HasPrefix(t.Name, "Tensor<") &&
		!strings.HasSuffix(t.Name, ",@W8A8v1>") &&
		!strings.HasSuffix(t.Name, ",@W8A8v1.accum>") {
		return &Diagnostic{"E-PROFILE-002", 0, 0, "unknown numeric profile"}
	}
	for _, arg := range t.Args {
		if d := validateType(arg); d != nil {
			return d
		}
	}
	return nil
}

func Check(p Program) []Diagnostic {
	seen := map[string]bool{}
	fn := map[string]Function{}
	var ds []Diagnostic
	for _, f := range p.Functions {
		if seen[f.Name] {
			ds = append(ds, Diagnostic{"E-TYPE-012", 0, 0, "duplicate function"})
		}
		seen[f.Name] = true
		fn[f.Name] = f
	}
	for _, f := range p.Functions {
		env := map[string]Type{}
		for _, x := range f.Params {
			if d := validateType(x.Type); d != nil {
				ds = append(ds, *d)
			}
			env[x.Name] = x.Type
		}
		if d := validateType(f.Ret); d != nil {
			ds = append(ds, *d)
		}
		i, d := infer(f.Body, env, fn)
		if d != nil {
			ds = append(ds, *d)
			continue
		}
		for _, x := range f.Params {
			if x.Type.Linear && !i.used[x.Name] {
				ds = append(ds, Diagnostic{"E-LIN-001", f.Body.Start, f.Body.End, "linear parameter is not consumed"})
			}
		}
		decl := map[string]bool{}
		for _, x := range f.Effects {
			decl[x] = true
		}
		for x := range i.effects {
			if !decl[x] {
				ds = append(ds, Diagnostic{"E-EFFECT-001", f.Body.Start, f.Body.End, "inferred effects exceed declared row"})
				break
			}
		}
	}
	return ds
}
func infer(e *Expr, env map[string]Type, fns map[string]Function) (checkInfo, *Diagnostic) {
	bad := func(code, msg string) *Diagnostic { return &Diagnostic{code, e.Start, e.End, msg} }
	z := checkInfo{effects: map[string]bool{}, used: map[string]bool{}}
	switch e.Kind {
	case "int":
		z.ty = Type{Name: "u64"}
		z.cost = 1
	case "bool":
		z.ty = Type{Name: "Bool"}
		z.cost = 1
	case "var":
		t, ok := env[e.Name]
		if !ok {
			return z, bad("E-TYPE-001", "unbound name")
		}
		z.ty = t
		z.cost = 2
		if t.Linear {
			z.used[e.Name] = true
		}
	case "tuple":
		z.ty = Type{Name: "()"}
		z.cost = 4
		for _, x := range e.Kids {
			i, d := infer(x, env, fns)
			if d != nil {
				return z, d
			}
			if overlap(z.used, i.used) {
				return z, bad("E-LIN-002", "linear value used more than once")
			}
			mergeInfo(&z, i)
		}
	case "binary":
		a, d := infer(e.Kids[0], env, fns)
		if d != nil {
			return z, d
		}
		b, d := infer(e.Kids[1], env, fns)
		if d != nil {
			return z, d
		}
		if overlap(a.used, b.used) {
			return z, bad("E-LIN-002", "linear value used twice")
		}
		z = a
		mergeInfo(&z, b)
		z.cost += 4
		if e.Op == "==" || e.Op == "<" {
			z.ty = Type{Name: "Bool"}
		} else if e.Op == "@" {
			if !strings.HasPrefix(a.ty.Name, "Tensor<i8,") || !strings.HasPrefix(b.ty.Name, "Tensor<i8,") {
				return z, bad("E-PROFILE-001", "matmul requires compatible i8 tensors under one numeric profile")
			}
			z.ty = Type{Name: strings.Replace(a.ty.Name, "Tensor<i8,", "Tensor<i32,", 1)}
		}
	case "if":
		c, d := infer(e.Kids[0], env, fns)
		if d != nil {
			return z, d
		}
		a, d := infer(e.Kids[1], env, fns)
		if d != nil {
			return z, d
		}
		b, d := infer(e.Kids[2], env, fns)
		if d != nil {
			return z, d
		}
		if !sameSet(a.used, b.used) {
			return z, bad("E-LIN-003", "if branches consume different linear resources")
		}
		z = c
		mergeInfo(&z, a)
		for q := range b.effects {
			z.effects[q] = true
		}
		z.cost = c.cost + max(a.cost, b.cost) + 3
		z.ty = a.ty
	case "let":
		a, d := infer(e.Kids[0], env, fns)
		if d != nil {
			return z, d
		}
		en := cloneEnv(env)
		en[e.Name] = a.ty
		b, d := infer(e.Kids[1], en, fns)
		if d != nil {
			return z, d
		}
		if a.ty.Linear && !b.used[e.Name] {
			return z, bad("E-LIN-001", "linear binding is not consumed")
		}
		delete(b.used, e.Name)
		// Any linear resource used by both the bound value and the body
		// (beyond the binding itself) is a double use.
		if overlap(a.used, b.used) {
			return z, bad("E-LIN-002", "linear value used more than once")
		}
		z = a
		mergeInfo(&z, b)
		z.ty = b.ty
		z.cost += 3
	case "call":
		for _, x := range e.Kids {
			i, d := infer(x, env, fns)
			if d != nil {
				return z, d
			}
			if overlap(z.used, i.used) {
				return z, bad("E-LIN-002", "linear argument reused")
			}
			mergeInfo(&z, i)
		}
		z.cost += 8
		switch e.Name {
		case "consume":
			if len(e.Kids) != 1 {
				return z, bad("E-LIN-004", "consume arity")
			}
			z.ty = Type{Name: "()"}
		case "commit":
			z.effects["commit"] = true
			z.ty = Type{Name: "Committed"}
		case "beacon":
			if len(e.Kids) != 1 {
				return z, bad("E-TYPE-007", "beacon takes one argument")
			}
			arg, d := infer(e.Kids[0], env, fns)
			if d != nil {
				return z, d
			}
			if arg.ty.Name != "Committed" {
				return z, bad("E-EFFECT-002", "beacon requires a Committed token")
			}
			z.effects["beacon"] = true
			z.ty = Type{Name: "Rand256"}
		default:
			f, ok := fns[e.Name]
			if !ok {
				return z, bad("E-TYPE-008", "unknown function")
			}
			z.ty = f.Ret
			for _, q := range f.Effects {
				z.effects[q] = true
			}
		}
	}
	return z, nil
}
func mergeInfo(a *checkInfo, b checkInfo) {
	for k := range b.used {
		a.used[k] = true
	}
	for k := range b.effects {
		a.effects[k] = true
	}
	a.cost += b.cost
}
func overlap(a, b map[string]bool) bool {
	for k := range a {
		if b[k] {
			return true
		}
	}
	return false
}
func sameSet(a, b map[string]bool) bool { return len(a) == len(b) && !overlapDiff(a, b) }
func overlapDiff(a, b map[string]bool) bool {
	for k := range a {
		if !b[k] {
			return true
		}
	}
	return false
}
func cloneEnv(a map[string]Type) map[string]Type {
	b := map[string]Type{}
	for k, v := range a {
		b[k] = v
	}
	return b
}
func max(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

type noun struct {
	atom uint64
	h, t *noun
}

func A(v uint64) *noun                  { return &noun{atom: v} }
func C(h, t *noun) *noun                { return &noun{h: h, t: t} }
func op(n uint64, x *noun) *noun        { return C(A(n), x) }
func pair(a, b *noun) *noun             { return C(a, b) }
func q(x *noun) *noun                   { return op(1, x) }
func slot(a uint64) *noun               { return op(0, A(a)) }
func op2(n uint64, a, b *noun) *noun    { return op(n, pair(a, b)) }
func op3(n uint64, a, b, c *noun) *noun { return op(n, pair(a, pair(b, c))) }
func enc(n *noun) []byte {
	if n.h != nil {
		return append(append([]byte{1}, enc(n.h)...), enc(n.t)...)
	}
	var p []byte
	v := n.atom
	for v > 0 {
		p = append(p, byte(v))
		v >>= 8
	}
	o := []byte{0, byte(len(p)), 0, 0, 0}
	return append(o, p...)
}
func listData(x []*noun) *noun {
	n := A(0)
	for i := len(x) - 1; i >= 0; i-- {
		n = C(x[i], n)
	}
	return n
}
func consFormula(x []*noun) *noun {
	n := q(A(0))
	for i := len(x) - 1; i >= 0; i-- {
		n = C(x[i], n)
	}
	return n
}
func parmAxis(i int) uint64 { return (uint64(1) << uint(i+3)) - 2 }
func armAxis(i int) uint64  { return (uint64(3) << uint(i+1)) - 2 }
func lower(e *Expr, params map[string]uint64, arms map[string]uint64) (*noun, *Diagnostic) {
	bad := func(msg string) (*noun, *Diagnostic) { return nil, &Diagnostic{"E-LOWER-003", e.Start, e.End, msg} }
	switch e.Kind {
	case "var":
		return slot(params[e.Name]), nil
	case "int":
		return q(A(e.Value)), nil
	case "bool":
		// Loobean (grain spec §9 ops 5/6): TRUE is atom 0, FALSE is atom 1,
		// matching equal's result and if's dispatch law.
		if e.Bool {
			return q(A(0)), nil
		}
		return q(A(1)), nil
	case "tuple":
		var x []*noun
		for _, k := range e.Kids {
			n, d := lower(k, params, arms)
			if d != nil {
				return nil, d
			}
			x = append(x, n)
		}
		return consFormula(x), nil
	case "binary":
		a, d := lower(e.Kids[0], params, arms)
		if d != nil {
			return nil, d
		}
		if e.Op == "==" {
			b, d := lower(e.Kids[1], params, arms)
			if d != nil {
				return nil, d
			}
			return op2(5, a, b), nil
		}
		if e.Op == "+" && e.Kids[1].Kind == "int" {
			if e.Kids[1].Value > 4096 {
				return bad("literal addition unroll exceeds 4096")
			}
			for i := uint64(0); i < e.Kids[1].Value; i++ {
				a = op(4, a)
			}
			return a, nil
		}
		return bad("operator has no exact Grain v1 lowering")
	case "if":
		a, d := lower(e.Kids[0], params, arms)
		if d != nil {
			return nil, d
		}
		b, d := lower(e.Kids[1], params, arms)
		if d != nil {
			return nil, d
		}
		c, d := lower(e.Kids[2], params, arms)
		if d != nil {
			return nil, d
		}
		return op3(6, a, b, c), nil
	case "let":
		v, d := lower(e.Kids[0], params, arms)
		if d != nil {
			return nil, d
		}
		p := map[string]uint64{}
		for k, a := range params {
			p[k] = a*2 + 2
		}
		p[e.Name] = 2
		b, d := lower(e.Kids[1], p, arms)
		if d != nil {
			return nil, d
		}
		return op2(8, v, b), nil
	case "call":
		if e.Name == "consume" {
			return q(A(0)), nil
		}
		var fs []*noun
		for _, x := range e.Kids {
			n, d := lower(x, params, arms)
			if d != nil {
				return nil, d
			}
			fs = append(fs, n)
		}
		args := consFormula(fs)
		if e.Name == "commit" || e.Name == "beacon" || e.Name == "declassify" {
			return op2(11, q(A(1)), args), nil
		}
		core := pair(slot(6), slot(2))
		return op2(8, args, op(9, pair(A(arms[e.Name]), core))), nil
	}
	return bad("unsupported expression")
}

type CostDerivation struct {
	Declared        string `json:"declared"`
	DerivedConstant uint64 `json:"derived_constant"`
	BranchLaw       string `json:"branch_law"`
	CallCharge      uint64 `json:"call_charge"`
}
type SizeBound struct {
	Variable string `json:"variable"`
	Maximum  uint64 `json:"maximum"`
}
type LoweringManifest struct {
	Target, Hash     string
	TranscriptLayout *string `json:"transcript_layout"`
	JournalSchema    *string `json:"journal_schema"`
}
type MeaningContract struct {
	FormulaID                             string `json:"formula_id"`
	GrainVersion                          uint32 `json:"grain_version"`
	CompilerID, SourceRoot, TypeSignature string
	NumericProfiles                       []string `json:"numeric_profiles"`
	CostCertificate                       string   `json:"cost_certificate"`
	Effects, Rights                       []string
	SizeBounds                            []SizeBound `json:"size_bounds"`
	Lowerings                             []LoweringManifest
}
type Unit struct {
	Name, GrainFormulaHex, FormulaID string
	MeaningContract                  MeaningContract `json:"meaning_contract"`
	Cost                             CostDerivation
	Obligations                      []string
}
type Compilation struct {
	Schema, SourceRoot, CompilerID string
	Units                          []Unit
}

func dh(domain string, b []byte) string {
	h := blake3.New(32, nil)
	h.Write([]byte(domain))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
func canonical(p Program) string {
	var b strings.Builder
	for _, f := range p.Functions {
		b.WriteString("fn " + f.Name + "<" + strings.Join(f.Sizes, ",") + ">(")
		for i, x := range f.Params {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(x.Name + ":" + x.Type.Canonical())
		}
		b.WriteString(")->" + f.Ret.Canonical() + "!" + strings.Join(f.Effects, ","))
		if f.Cost != "" {
			b.WriteString(" cost " + f.Cost)
		}
		if f.Dec != "" {
			b.WriteString(" dec " + f.Dec)
		}
		b.WriteByte('{')
		canonExpr(&b, f.Body)
		b.WriteByte('}')
	}
	return b.String()
}
func canonExpr(b *strings.Builder, e *Expr) {
	switch e.Kind {
	case "var":
		b.WriteString(e.Name)
	case "int":
		b.WriteString(strconv.FormatUint(e.Value, 10))
	case "bool":
		b.WriteString(strconv.FormatBool(e.Bool))
	case "tuple":
		b.WriteByte('(')
		for i, x := range e.Kids {
			if i > 0 {
				b.WriteByte(',')
			}
			canonExpr(b, x)
		}
		b.WriteByte(')')
	case "binary":
		b.WriteByte('(')
		canonExpr(b, e.Kids[0])
		b.WriteString(e.Op)
		canonExpr(b, e.Kids[1])
		b.WriteByte(')')
	case "if":
		b.WriteString("if ")
		canonExpr(b, e.Kids[0])
		b.WriteByte('{')
		canonExpr(b, e.Kids[1])
		b.WriteString("}else{")
		canonExpr(b, e.Kids[2])
		b.WriteByte('}')
	case "let":
		b.WriteString("let " + e.Name + "=")
		canonExpr(b, e.Kids[0])
		b.WriteByte(';')
		canonExpr(b, e.Kids[1])
	case "call":
		b.WriteString(e.Name + "(")
		for i, x := range e.Kids {
			if i > 0 {
				b.WriteByte(',')
			}
			canonExpr(b, x)
		}
		b.WriteByte(')')
	}
}
func Compile(src string) (Compilation, []Diagnostic) {
	p, ds := Parse(src)
	if len(ds) > 0 {
		return Compilation{}, ds
	}
	if ds = Check(p); len(ds) > 0 {
		return Compilation{}, ds
	}
	root := dh("NOOS/WEFT/SOURCE/V1", []byte(canonical(p)))
	cid := dh("NOOS/WEFT/COMPILER/V1", []byte("go-weftref/v1;grain=1;go=1.25"))
	arms := map[string]uint64{}
	for i, f := range p.Functions {
		arms[f.Name] = armAxis(i)
	}
	var bodies []*noun
	for _, f := range p.Functions {
		pm := map[string]uint64{}
		for i, x := range f.Params {
			pm[x.Name] = parmAxis(i)
		}
		n, d := lower(f.Body, pm, arms)
		if d != nil {
			return Compilation{}, []Diagnostic{*d}
		}
		bodies = append(bodies, n)
	}
	battery := listData(bodies)
	out := Compilation{Schema: "WeftCompilation/v1", SourceRoot: root, CompilerID: cid, Units: []Unit{}}
	for i, f := range p.Functions {
		formula := op(9, pair(A(armAxis(i)), pair(q(battery), slot(1))))
		fb := enc(formula)
		fid := dh("NOOS/WEFT/FORMULA/V1", fb)
		cost := CostDerivation{f.Cost, deriveCost(f.Body), "if=max(then,else)+condition+3", 8}
		if cost.Declared == "" {
			cost.Declared = strconv.FormatUint(cost.DerivedConstant, 10)
		}
		cb, _ := json.Marshal(cost)
		mc := MeaningContract{FormulaID: fid, GrainVersion: 1, CompilerID: cid, SourceRoot: root, TypeSignature: signature(f), CostCertificate: dh("NOOS/WEFT/COST/V1", cb), Effects: append([]string{}, f.Effects...), NumericProfiles: []string{}, Rights: []string{}, SizeBounds: []SizeBound{}, Lowerings: []LoweringManifest{{Target: "grain-v1", Hash: fid}}}
		for _, s := range f.Sizes {
			mc.SizeBounds = append(mc.SizeBounds, SizeBound{s, 65535})
		}
		out.Units = append(out.Units, Unit{Name: f.Name, GrainFormulaHex: hex.EncodeToString(fb), FormulaID: fid, MeaningContract: mc, Cost: cost, Obligations: []string{}})
	}
	return out, nil
}
func deriveCost(e *Expr) uint64 {
	switch e.Kind {
	case "int", "bool":
		return 1
	case "var":
		return 2
	case "tuple":
		n := uint64(4)
		for _, x := range e.Kids {
			n += deriveCost(x)
		}
		return n
	case "binary":
		return deriveCost(e.Kids[0]) + deriveCost(e.Kids[1]) + 4
	case "if":
		return deriveCost(e.Kids[0]) + max(deriveCost(e.Kids[1]), deriveCost(e.Kids[2])) + 3
	case "let":
		return deriveCost(e.Kids[0]) + deriveCost(e.Kids[1]) + 3
	case "call":
		n := uint64(12)
		for _, x := range e.Kids {
			n += deriveCost(x)
		}
		return n
	}
	return 0
}
func signature(f Function) string {
	var a []string
	for _, p := range f.Params {
		a = append(a, p.Type.Canonical())
	}
	return "fn(" + strings.Join(a, ",") + ")->" + f.Ret.Canonical() + " !{" + strings.Join(f.Effects, ",") + "}"
}

// GEMMI8, RequantW8A8, and AdmitSpan are the deliberately slow independent certificate path.
func GEMMI8(a, b []int8, m, k, n int) ([]int32, error) {
	if m <= 0 || k <= 0 || n <= 0 || m > 65535 || k > 65535 || n > 65535 || len(a) != m*k || len(b) != k*n {
		return nil, fmt.Errorf("shape")
	}
	c := make([]int32, m*n)
	for i := 0; i < m; i++ {
		for j := 0; j < n; j++ {
			var x int64
			for q := 0; q < k; q++ {
				x += int64(a[i*k+q]) * int64(b[q*n+j])
			}
			if x < -2147483648 || x > 2147483647 {
				return nil, fmt.Errorf("accum overflow")
			}
			c[i*n+j] = int32(x)
		}
	}
	return c, nil
}
func RequantW8A8(c []int32, mult uint32, shift uint8) ([]int8, error) {
	if mult == 0 || shift == 0 || shift > 31 {
		return nil, fmt.Errorf("profile")
	}
	o := make([]int8, len(c))
	r := int64(1) << uint(shift-1)
	for i, x := range c {
		q := (int64(x)*int64(mult) + r) >> uint(shift)
		if q < -128 {
			q = -128
		}
		if q > 127 {
			q = 127
		}
		o[i] = int8(q)
	}
	return o, nil
}

type SpanCertificate struct {
	M, K, N       uint16
	Reps, RBits   uint8
	Commitment    string
	Challenge     [2]uint32
	Projections   []uint64
	C32Hash       string
	C8Hash        string
	Mult          uint32
	Shift         uint8
}

func append16(b []byte, v uint16) []byte { return append(b, byte(v), byte(v>>8)) }
func append32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}
func c32Bytes(v []int32) []byte {
	b := make([]byte, 0, len(v)*4)
	for _, x := range v {
		b = append32(b, uint32(x))
	}
	return b
}
func i8Bytes(v []int8) []byte {
	b := make([]byte, len(v))
	for i, x := range v {
		b[i] = byte(x)
	}
	return b
}

func DeriveSpan(a, b []int8, m, k, n uint16, mult uint32, shift uint8, challenge [2]uint32) (SpanCertificate, error) {
	c, err := GEMMI8(a, b, int(m), int(k), int(n))
	if err != nil {
		return SpanCertificate{}, err
	}
	c8, err := RequantW8A8(c, mult, shift)
	if err != nil {
		return SpanCertificate{}, err
	}
	transcript := append(i8Bytes(a), i8Bytes(b)...)
	transcript = append(transcript, c32Bytes(c)...)
	transcript = append(transcript, i8Bytes(c8)...)
	transcript = append16(transcript, m)
	transcript = append16(transcript, k)
	transcript = append16(transcript, n)
	transcript = append32(transcript, mult)
	transcript = append(transcript, shift)
	projections := make([]uint64, 2)
	for rep, r := range challenge {
		for i, x := range c {
			rot := (r << uint(i%32)) | (r >> uint((32-i%32)%32))
			projections[rep] += uint64(int64(x)) * uint64(rot)
		}
	}
	return SpanCertificate{
		M: m, K: k, N: n, Reps: 2, RBits: 32,
		Commitment: dh("NOOS/WEFT/W8A8/COMMIT/V1", transcript),
		Challenge: challenge, Projections: projections,
		C32Hash: dh("NOOS/WEFT/W8A8/C32/V1", c32Bytes(c)),
		C8Hash: dh("NOOS/WEFT/W8A8/C8/V1", i8Bytes(c8)),
		Mult: mult, Shift: shift,
	}, nil
}

func AdmitSpan(cert SpanCertificate, a, b []int8, claimedC []int32, claimedC8 []int8) error {
	if cert.Reps != 2 || cert.RBits != 32 {
		return fmt.Errorf("soundness")
	}
	fresh, err := DeriveSpan(a, b, cert.M, cert.K, cert.N, cert.Mult, cert.Shift, cert.Challenge)
	if err != nil {
		return err
	}
	if fresh.Commitment != cert.Commitment {
		return fmt.Errorf("commitment")
	}
	if len(fresh.Projections) != len(cert.Projections) {
		return fmt.Errorf("projection")
	}
	for i := range fresh.Projections {
		if fresh.Projections[i] != cert.Projections[i] {
			return fmt.Errorf("projection")
		}
	}
	if fresh.C32Hash != dh("NOOS/WEFT/W8A8/C32/V1", c32Bytes(claimedC)) ||
		fresh.C8Hash != dh("NOOS/WEFT/W8A8/C8/V1", i8Bytes(claimedC8)) {
		return fmt.Errorf("output")
	}
	return nil
}
