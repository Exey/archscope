// mutability.go is Code Structure's 🧊 Mutability subcard — ideas from three Go
// linters, run lexically (no type checker) and extended to other languages:
//
//	constlint   — `// +const` on a struct field forbids assigning it outside a
//	              constructor; `// +const:[a,b]` above a func makes those
//	              parameters read-only inside it.      → mut-const-field, mut-const-param
//	go-immutable / funky — package-level variables treated as read-only: any
//	              function that reassigns one, writes into its map/slice/field or
//	              appends to it mutates shared state; funky also reports every
//	              reassignment of a local after its declaration.
//	                                                   → mut-global, mut-reassign
//	TS/JS  `let` that is never reassigned (prefer const).   → mut-prefer-const
//	Python `global` + assignment, module-level collections mutated inside
//	       functions, class-level mutable attributes shared by every instance.
//	                                  → mut-py-global, mut-py-module-state, mut-py-class-attr
//
// Mutation in itself isn't wrong, so findings are MEDIUM/LOW and mut-reassign is
// Advisory: shown in the card, but never a review item or a score input (it fires
// on every `x = …` after a declaration — funky's whole point, and far too much
// for a merge-request review).
package constructs

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/security"
)

var (
	reMutAssignOps = `(?:=[^=]|\+=|-=|\*=|/=|%=|\|=|&=|\^=|<<=|>>=|\+\+|--)`
	reGoVarOne     = regexp.MustCompile(`^var\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\b(.*)$`)
	reGoVarBlock   = regexp.MustCompile(`^var\s*\(\s*$`)
	reGoVarEntry   = regexp.MustCompile(`^\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\b(.*)$`)
	reGoFieldLine  = regexp.MustCompile(`^\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+\S`)
	reGoStructOpen = regexp.MustCompile(`^type\s+(\w+)\s+struct\s*\{`)
	// a constlint marker is a comment that *starts* with +const (`// +const`, `// +const:[a,b]`)
	reGoConstMark  = regexp.MustCompile(`//\s*\+const\b(?::\[([^\]]*)\])?\s*$`)
	reGoIdentTok   = regexp.MustCompile(`[A-Za-z_]\w*`)
	goCtorPrefixes = []string{"New", "new", "Create", "Make", "Build", "Init", "init", "Load", "From", "Parse"}
	goSyncInit     = regexp.MustCompile(`\b(?:sync|atomic)\.|\bnew\((?:sync|atomic)\.|\bMutex\b|\bOnce\b|\bWaitGroup\b`)
	reTSLetDecl    = regexp.MustCompile(`\blet\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*[^=]`)
	rePyGlobalStmt = regexp.MustCompile(`^global\s+(.+)$`)
	rePyModuleColl = regexp.MustCompile(`^([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*(?:\[|\{|(?:list|dict|set|defaultdict|OrderedDict|deque|Counter)\s*\()`)
	rePyClassColl  = regexp.MustCompile(`^([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*(?:\[|\{|(?:list|dict|set|defaultdict|OrderedDict|deque|Counter)\s*\()`)
)

func isGoCtor(name string) bool {
	for _, p := range goCtorPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// goPackage is one directory's Go files, read once.
type goPackage struct {
	dir   string
	files []*goMutFile
}

type goMutFile struct {
	path     string
	stripped []string
	raw      []string
	funcs    []csFuncRange
	depth    []int // brace depth at the start of each line
}

type goGlobal struct {
	name string
	file *goMutFile
	line int
}

type constField struct {
	name, strct string
	file        *goMutFile
	line        int
}

// scanGoMutability runs the Go mutability rules across the platform's packages.
func scanGoMutability(files []*parser.ParsedFile, cache *sourceCache) []CSIssue {
	pkgs := map[string]*goPackage{}
	var order []string
	for _, f := range files {
		if ext(f.FilePath) != ".go" || security.IsTestOrBenchPath(f.FilePath) || isConstructDetectorFile(f.FilePath) {
			continue
		}
		stripped, raw := cache.lines(f.FilePath), cache.rawLines(f.FilePath)
		if stripped == nil || raw == nil || isGeneratedHeader(raw) {
			continue
		}
		mf := &goMutFile{path: f.FilePath, stripped: stripped, raw: raw, funcs: csFuncRanges(stripped)}
		d, depth := 0, make([]int, len(stripped))
		for i, l := range stripped {
			depth[i] = d
			d += strings.Count(l, "{") - strings.Count(l, "}")
		}
		mf.depth = depth
		dir := filepath.Dir(f.FilePath)
		if pkgs[dir] == nil {
			pkgs[dir] = &goPackage{dir: dir}
			order = append(order, dir)
		}
		pkgs[dir].files = append(pkgs[dir].files, mf)
	}
	sort.Strings(order)
	var out []CSIssue
	for _, dir := range order {
		p := pkgs[dir]
		out = append(out, p.globalMutations()...)
		out = append(out, p.constFieldAssignments()...)
		for _, mf := range p.files {
			out = append(out, mf.constParams()...)
			out = append(out, mf.reassignments()...)
		}
	}
	sup := map[string]*security.Suppressor{}
	kept := out[:0]
	for _, is := range out {
		s, ok := sup[is.FilePath]
		if !ok {
			s = security.NewSuppressor(cache.rawLines(is.FilePath))
			sup[is.FilePath] = s
		}
		if !s.Suppressed(is.Line, is.RuleID) {
			kept = append(kept, is)
		}
	}
	return kept
}

func (mf *goMutFile) issue(line int, sev security.Severity, id, rule, detail, msg string, advisory bool) CSIssue {
	snip := strings.TrimSpace(mf.raw[line])
	if len(snip) > 100 {
		snip = snip[:100] + "…"
	}
	return CSIssue{RuleID: id, Rule: rule, Message: msg, Detail: detail, Severity: sev, FilePath: mf.path, Line: line + 1, Snippet: snip, Advisory: advisory}
}

// enclosing returns the function range containing line i, if any.
func (mf *goMutFile) enclosing(i int) (csFuncRange, bool) {
	for _, fr := range mf.funcs {
		if fr.start <= i && i <= fr.end {
			return fr, true
		}
	}
	return csFuncRange{}, false
}

// globals lists this file's package-level `var` names (const are immutable by definition).
func (mf *goMutFile) globals() []goGlobal {
	var out []goGlobal
	inBlock := false
	for i, l := range mf.stripped {
		t := strings.TrimRight(l, " \t")
		switch {
		case inBlock:
			if strings.TrimSpace(t) == ")" {
				inBlock = false
				continue
			}
			if g := reGoVarEntry.FindStringSubmatch(t); g != nil && mf.depth[i] == 0 && !goSyncInit.MatchString(g[2]) {
				for _, n := range splitNames(g[1]) {
					if n != "_" {
						out = append(out, goGlobal{n, mf, i})
					}
				}
			}
		case mf.depth[i] == 0 && reGoVarBlock.MatchString(t):
			inBlock = true
		case mf.depth[i] == 0:
			if g := reGoVarOne.FindStringSubmatch(t); g != nil && !goSyncInit.MatchString(g[2]) {
				for _, n := range splitNames(g[1]) {
					if n != "_" {
						out = append(out, goGlobal{n, mf, i})
					}
				}
			}
		}
	}
	return out
}

// shadows reports whether fr declares name itself (parameter, :=, var), so a
// write to it is local, not to the package variable.
func (mf *goMutFile) shadows(fr csFuncRange, name string) bool {
	q := regexp.QuoteMeta(name)
	decl := regexp.MustCompile(`(?:\b` + q + `\s*(?:,\s*\w+\s*)*:=|,\s*` + q + `\s*:=|\bvar\s+` + q + `\b)`)
	sig := mf.stripped[fr.start]
	if open := strings.Index(sig, "("); open >= 0 {
		// parameters: `name Type` / `name, other Type` inside the signature's parens
		hdr := sig[open:]
		if regexp.MustCompile(`[(,]\s*`+q+`\s+[\w*\[\]]`).MatchString(hdr) || regexp.MustCompile(`[(,]\s*`+q+`\s*,`).MatchString(hdr) {
			return true
		}
	}
	for i := fr.start; i <= fr.end && i < len(mf.stripped); i++ {
		if decl.MatchString(mf.stripped[i]) {
			return true
		}
	}
	return false
}

// globalMutations finds writes to package-level variables from inside functions.
func (p *goPackage) globalMutations() []CSIssue {
	var globals []goGlobal
	declLine := map[string]bool{}
	for _, mf := range p.files {
		for _, g := range mf.globals() {
			globals = append(globals, g)
			declLine[fmt.Sprintf("%s:%d", g.file.path, g.line)] = true
		}
	}
	if len(globals) == 0 {
		return nil
	}
	var out []CSIssue
	for _, g := range globals {
		q := regexp.QuoteMeta(g.name)
		write := regexp.MustCompile(`(?:^|[^\w.])` + q + `\s*(?:\[[^\]\n]*\]\s*)*(?:\.\w+\s*(?:\[[^\]\n]*\]\s*)*)*` + reMutAssignOps)
		call := regexp.MustCompile(`\b(?:delete|clear)\(\s*` + q + `\b`)
		for _, mf := range p.files {
			reported := map[string]bool{}
			for i, l := range mf.stripped {
				fr, in := mf.enclosing(i)
				if !in || i == fr.start || fr.name == "init" || fr.name == "TestMain" {
					continue
				}
				hit := false
				if loc := write.FindStringIndex(l); loc != nil {
					seg := l[loc[0]:loc[1]]
					hit = !strings.Contains(seg, ":=") && !(strings.HasSuffix(seg, "=") && strings.Contains(l[loc[0]:], "==") && !strings.Contains(seg, "="))
				}
				if !hit && call.MatchString(l) {
					hit = true
				}
				if !hit || reported[fr.name] || mf.shadows(fr, g.name) {
					continue
				}
				reported[fr.name] = true
				out = append(out, mf.issue(i, security.SevMedium, "mut-global", "Package-level variable mutated", fr.name+" → "+g.name,
					"A function changes a package-level variable (assigns it, writes into its map/slice/field, or appends to it), so every caller shares and races on that state. Pass the value in, return the new one, or guard it with a mutex and keep it unexported.", false))
			}
		}
	}
	return out
}

// constFieldAssignments finds assignments to `// +const` struct fields outside constructors.
func (p *goPackage) constFieldAssignments() []CSIssue {
	fields := map[string]constField{}
	for _, mf := range p.files {
		inStruct, name := false, ""
		structDepth := 0
		for i, l := range mf.stripped {
			if g := reGoStructOpen.FindStringSubmatch(l); g != nil && mf.depth[i] == 0 {
				inStruct, name, structDepth = true, g[1], mf.depth[i]
				continue
			}
			if !inStruct {
				continue
			}
			if mf.depth[i] <= structDepth && strings.Contains(l, "}") {
				inStruct = false
				continue
			}
			g := reGoFieldLine.FindStringSubmatch(l)
			if g == nil {
				continue
			}
			marked := reGoConstMark.MatchString(mf.raw[i]) // inline `// +const`
			for j := i - 1; !marked && j >= 0; j-- {       // doc comment block directly above
				t := strings.TrimSpace(mf.raw[j])
				if !strings.HasPrefix(t, "//") {
					break
				}
				if m := reGoConstMark.FindStringSubmatch(t); m != nil && m[1] == "" {
					marked = true
				}
			}
			if marked {
				for _, n := range splitNames(g[1]) {
					fields[n] = constField{name: n, strct: name, file: mf, line: i}
				}
			}
		}
	}
	if len(fields) == 0 {
		return nil
	}
	var out []CSIssue
	for _, cf := range fields {
		write := regexp.MustCompile(`\.` + regexp.QuoteMeta(cf.name) + `\s*(?:\[[^\]\n]*\]\s*)*` + reMutAssignOps)
		for _, mf := range p.files {
			for i, l := range mf.stripped {
				if !write.MatchString(l) {
					continue
				}
				fr, in := mf.enclosing(i)
				if in && isGoCtor(fr.name) {
					continue
				}
				out = append(out, mf.issue(i, security.SevMedium, "mut-const-field", "Assignment to a `+const` field", cf.strct+"."+cf.name,
					"This field is marked `// +const` (constlint): it may be set when the value is constructed but not changed afterwards. Build a new value instead of mutating it, or drop the marker if it is really mutable.", false))
			}
		}
	}
	return out
}

// constParams enforces `// +const:[a,b]` above a func: those parameters are read-only inside it.
func (mf *goMutFile) constParams() []CSIssue {
	var out []CSIssue
	for _, fr := range mf.funcs {
		var params []string
		for j := fr.start - 1; j >= 0; j-- {
			t := strings.TrimSpace(mf.raw[j])
			if !strings.HasPrefix(t, "//") {
				break
			}
			if m := reGoConstMark.FindStringSubmatch(t); m != nil && m[1] != "" {
				params = append(params, splitNames(m[1])...)
			}
		}
		for _, name := range params {
			q := regexp.QuoteMeta(name)
			write := regexp.MustCompile(`(?:^|[^\w.])` + q + `\s*(?:\[[^\]\n]*\]\s*)*(?:\.\w+\s*(?:\[[^\]\n]*\]\s*)*)*` + reMutAssignOps)
			for i := fr.start + 1; i <= fr.end && i < len(mf.stripped); i++ {
				if loc := write.FindStringIndex(mf.stripped[i]); loc != nil && !strings.Contains(mf.stripped[i][loc[0]:loc[1]], ":=") {
					out = append(out, mf.issue(i, security.SevMedium, "mut-const-param", "Assignment to a `+const` parameter", fr.name+"("+name+")",
						"The function is annotated `// +const:["+name+"]` (constlint): the parameter must not be modified inside it. Copy it first, or remove the annotation.", false))
					break
				}
			}
		}
	}
	return out
}

// reassignments is funky's check: a local assigned a new value after its declaration.
func (mf *goMutFile) reassignments() []CSIssue {
	var out []CSIssue
	for _, fr := range mf.funcs {
		declared := map[string]int{}
		reported := map[string]bool{}
		reDecl := regexp.MustCompile(`^\s*(?:var\s+)?([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::=|\s+[\w*\[\]]+\s*(?:=|$))`)
		reAssign := regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*=[^=]`)
		for i := fr.start + 1; i <= fr.end && i < len(mf.stripped); i++ {
			l := mf.stripped[i]
			if g := reDecl.FindStringSubmatch(l); g != nil && (strings.Contains(l, ":=") || strings.HasPrefix(strings.TrimSpace(l), "var ")) {
				for _, n := range splitNames(g[1]) {
					if _, ok := declared[n]; !ok {
						declared[n] = i
					}
				}
				continue
			}
			if g := reAssign.FindStringSubmatch(l); g != nil {
				n := g[1]
				if _, ok := declared[n]; !ok || reported[n] || n == "err" || n == "ok" || n == "_" || n == "ctx" || n == "i" || n == "j" || n == "k" {
					continue
				}
				reported[n] = true
				out = append(out, mf.issue(i, security.SevLow, "mut-reassign", "Variable reassigned", fr.name+": "+n,
					"funky's mutation check: the variable gets a new value after it was declared. Often fine; where it is easy, prefer building the value once (a helper function or an if/switch expression) so readers don't have to track its changes.", true))
			}
		}
	}
	return out
}

// scanTSMutability: `let` that is never reassigned.
func scanTSMutability(filePath string, m maskedFile) []CSIssue {
	if !isJSFamily(ext(filePath)) {
		return nil
	}
	f := m.flat()
	blocks := blockRanges(f.code)
	var out []CSIssue
	for _, dm := range reTSLetDecl.FindAllStringSubmatchIndex(f.code, -1) {
		pre := strings.TrimRight(f.code[max0(dm[0]-6):dm[0]], " \t")
		if strings.HasSuffix(pre, "(") || strings.HasSuffix(pre, "for") || strings.HasSuffix(pre, ",") {
			continue // for (let …), multi-declarations: leave alone
		}
		name := f.code[dm[2]:dm[3]]
		lo, hi := scopeAround(blocks, dm[0], len(f.code))
		scope := f.code[dm[1]:hi]
		_ = lo
		q := regexp.QuoteMeta(name)
		reassign := regexp.MustCompile(`(?:^|[^\w$.])` + q + `\s*(?:=[^=>]|\+=|-=|\*=|/=|%=|\*\*=|\|\|=|&&=|\?\?=|<<=|>>=|>>>=|&=|\|=|\^=|\+\+|--)|(?:\+\+|--)\s*` + q + `\b|\b(?:in|of)\s+` + q + `\b|[\[{,]\s*` + q + `\s*[,\]}]\s*=[^=]|\.{3}` + q + `\s*\]\s*=`)
		if reassign.MatchString(scope) {
			continue
		}
		li := f.line(dm[0])
		snip := strings.TrimSpace(m.raw[li])
		if len(snip) > 100 {
			snip = snip[:100] + "…"
		}
		out = append(out, CSIssue{RuleID: "mut-prefer-const", Rule: "`let` that is never reassigned", Detail: name, Severity: security.SevLow,
			Message:  "The binding is never reassigned, so `const` states that and lets readers (and the compiler) rely on it.",
			FilePath: filePath, Line: li + 1, Snippet: snip})
	}
	return out
}

// scanPyMutability: shared mutable state in Python.
func scanPyMutability(filePath string, m maskedFile) []CSIssue {
	code := m.code
	starts := pyLogicalStarts(code)
	funcs, classes := pyParse(m)
	var out []CSIssue
	add := func(li int, sev security.Severity, id, rule, detail, msg string) {
		snip := strings.TrimSpace(m.raw[li])
		if len(snip) > 100 {
			snip = snip[:100] + "…"
		}
		out = append(out, CSIssue{RuleID: id, Rule: rule, Message: msg, Detail: detail, Severity: sev, FilePath: filePath, Line: li + 1, Snippet: snip})
	}

	// module-level mutable collections
	moduleColl := map[string]int{}
	for i := 0; i < len(code); i++ {
		if starts[i] && pyIndent(code[i]) == 0 {
			if g := rePyModuleColl.FindStringSubmatch(strings.TrimSpace(code[i])); g != nil {
				moduleColl[g[1]] = i
			}
		}
	}
	for _, f := range funcs {
		body := f.bodyStart
		end := min(f.end, len(code)-1)
		globals := map[string]bool{}
		for i := body; i <= end; i++ {
			if !starts[i] {
				continue
			}
			t := strings.TrimSpace(code[i])
			if g := rePyGlobalStmt.FindStringSubmatch(t); g != nil {
				for _, n := range splitNames(g[1]) {
					globals[n] = true
				}
			}
		}
		for n := range globals {
			q := regexp.QuoteMeta(n)
			write := regexp.MustCompile(`^\s*` + q + `\s*(?::[^=]+)?(?:=[^=]|\+=|-=|\*=|/=)`)
			for i := body; i <= end; i++ {
				if write.MatchString(code[i]) {
					add(f.start, security.SevMedium, "mut-py-global", "`global` variable reassigned", f.name+" → "+n,
						"The function rebinds a module-level name through `global`, so behaviour depends on hidden shared state and on call order. Return the new value, or hold the state in an object that is passed in.")
					break
				}
			}
		}
		for name := range moduleColl {
			if globals[name] || pyShadowed(m, f, name) {
				continue
			}
			q := regexp.QuoteMeta(name)
			mut := regexp.MustCompile(`(?:^|[^\w.])` + q + `\s*(?:\.\s*(?:append|extend|insert|add|update|pop|popitem|remove|discard|clear|setdefault|sort|reverse)\s*\(|\[[^\]]*\]\s*(?:=[^=]|\+=|-=)|\s*\+=)`)
			for i := body; i <= end; i++ {
				if mut.MatchString(code[i]) {
					add(i, security.SevMedium, "mut-py-module-state", "Module-level collection mutated", f.name+" → "+name,
						"A function mutates a list/dict/set defined at module level, so every caller (and every thread) shares it. Pass the collection in, or wrap the state in a class/closure with a lock.")
					break
				}
			}
		}
	}

	// class-level mutable attributes
	for _, c := range classes {
		for i := c.start + 1; i <= c.end && i < len(code); i++ {
			if !starts[i] || pyIndent(code[i]) != c.indent+pyBodyIndent(code, c) {
				continue
			}
			t := strings.TrimSpace(code[i])
			if g := rePyClassColl.FindStringSubmatch(t); g != nil && !strings.HasPrefix(g[1], "__") {
				if hasWordBefore(code[c.start], "Enum") || strings.Contains(code[c.start], "TypedDict") || strings.Contains(code[c.start], "NamedTuple") || strings.Contains(code[c.start], "Protocol") {
					continue
				}
				add(i, security.SevMedium, "mut-py-class-attr", "Mutable class attribute", c.name+"."+g[1],
					"A list/dict/set assigned in the class body is one object shared by every instance, so changing it through one instance changes all. Create it in __init__ (or use dataclasses.field(default_factory=…)).")
			}
		}
	}
	return out
}

// pyBodyIndent is the indentation step of the class's first body statement.
func pyBodyIndent(code []string, c pyClass) int {
	for i := c.start + 1; i < len(code) && i <= c.end; i++ {
		if strings.TrimSpace(code[i]) != "" {
			return pyIndent(code[i]) - c.indent
		}
	}
	return 4
}

func hasWordBefore(s, w string) bool { return strings.Contains(s, w) }

// pyShadowed reports whether the function binds name itself (parameter or assignment).
func pyShadowed(m maskedFile, f pyFunc, name string) bool {
	for _, p := range pyParamNames(f.params) {
		if p == name {
			return true
		}
	}
	q := regexp.QuoteMeta(name)
	re := regexp.MustCompile(`^\s*` + q + `\s*(?::[^=]+)?=[^=]|\bfor\s+` + q + `\b|\bas\s+` + q + `\b`)
	for i := f.bodyStart; i <= f.end && i < len(m.code); i++ {
		if re.MatchString(m.code[i]) {
			return true
		}
	}
	return false
}
