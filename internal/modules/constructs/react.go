// react.go is Code Structure's two React subcards, a lexical port of the
// hooks/state, performance and architecture rules of ~/react-code-audit:
//
//	⚛️ React hooks & state  — no-missing-deps, no-set-state-in-effect-loop,
//	                          no-direct-mutation, no-derived-state,
//	                          no-effect-as-handler, no-state-in-ref,
//	                          no-array-index-key
//	🧩 React components     — max-component-lines, max-props,
//	                          no-deeply-nested-jsx, no-prop-drilling
//
// Thresholds are react-code-audit's own (250 lines, 7 props, 6 JSX levels, 3
// drilled props). No AST: components and hooks come from reactparse.go, so each
// rule is a narrow pattern that prefers silence to a guess.
package constructs

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/security"
)

const (
	reactMaxComponentLines = 250
	reactMaxProps          = 7
	reactMaxJSXDepth       = 6
	reactMinDrilledProps   = 3
)

var (
	reUseState    = regexp.MustCompile(`\bconst\s*\[\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)\s*\]\s*=\s*useState\s*(?:<[^>(]*>)?\s*\(`)
	reUseReducer  = regexp.MustCompile(`\bconst\s*\[\s*([A-Za-z_$][\w$]*)\s*,\s*[A-Za-z_$][\w$]*\s*\]\s*=\s*useReducer\s*(?:<[^>(]*>)?\s*\(`)
	reUseRef      = regexp.MustCompile(`\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*useRef\b`)
	reMapIndex    = regexp.MustCompile(`\.(?:map|flatMap|forEach)\s*\(\s*(?:async\s*)?\(?\s*[\w$]+\s*,\s*([A-Za-z_$][\w$]*)\s*[,)]?[^=]*=>`)
	reKeyAttr     = regexp.MustCompile(`\bkey=\{`)
	reIdentToken  = regexp.MustCompile(`(^|[^\w$.])([A-Za-z_$][\w$]*)`)
	reCallbackDef = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)|\b([A-Za-z_$][\w$]*)\s*=>|\(([^()]*)\)\s*(?::[^=]+)?=>`)
	reDestructDef = regexp.MustCompile(`\b(?:const|let|var)\s*[\[{]([^=\]}]*)[\]}]\s*=`)
	reTriggerName = regexp.MustCompile(`^(?:should|trigger|submit|clicked|do|run|start|fetch|save|send|load|reload|refresh|retry)[A-Z_]?\w*$`)
	reStateBool   = regexp.MustCompile(`^\s*(?:true|false)\s*$`)
	reMutator     = `\s*\.\s*(?:push|pop|shift|unshift|splice|sort|reverse|fill|copyWithin)\s*\(`
	reGuardPrefix = `(?:^|[^\w$.])`
)

// reactState is one useState/useReducer value declared in a component/hook.
type reactState struct {
	name, setter, init string
	off                int
}

// scanReact runs the hooks/state and component rules on one masked JS/TS file.
func scanReact(filePath string, m maskedFile) (hooks, comps []CSIssue) {
	fe := ext(filePath)
	if !isJSFamily(fe) {
		return nil, nil
	}
	f := m.flat()
	if !strings.Contains(f.code, "use") && !strings.Contains(f.code, "<") {
		return nil, nil
	}
	mk := func(off int, sev security.Severity, group, id, rule, msg string) CSIssue {
		li := f.line(off)
		snip := strings.TrimSpace(m.raw[li])
		if len(snip) > 100 {
			snip = snip[:100] + "…"
		}
		return CSIssue{RuleID: id, Rule: rule, Message: msg, Group: group, Severity: sev, FilePath: filePath, Line: li + 1, Snippet: snip}
	}
	// the detail rides in the message's first backtick-free segment: "detail\x00message"
	addH := func(off int, sev security.Severity, id, rule, msg string) {
		is := mk(off, sev, "", id, rule, msg)
		is.Detail, is.Message = splitDetail(msg)
		hooks = append(hooks, is)
	}
	addC := func(off int, sev security.Severity, id, rule, msg string) {
		is := mk(off, sev, "", id, rule, msg)
		is.Detail, is.Message = splitDetail(msg)
		comps = append(comps, is)
	}

	funcs := findReactFuncs(f)

	// no-array-index-key: file-wide, it only needs a .map callback and a key={}.
	scanIndexKeys(f, addH)

	for _, fn := range funcs {
		states, refs := readStateAndRefs(f, fn)
		stateByName := map[string]reactState{}
		setters := map[string]bool{}
		for _, s := range states {
			stateByName[s.name] = s
			if s.setter != "" {
				setters[s.setter] = true
			}
		}
		hooksIn := hookCalls(f, fn.open, fn.close+1)

		reactHookRules(f, fn, states, stateByName, setters, refs, hooksIn, addH)

		if fn.hook {
			continue
		}
		// ---- component rules ----
		startLine, endLine := f.line(fn.declOff), f.line(fn.close)
		if lines := endLine - startLine + 1; lines > reactMaxComponentLines {
			sev := security.SevLow
			if lines > 2*reactMaxComponentLines {
				sev = security.SevMedium
			}
			addC(fn.declOff, sev, "react-max-lines", "Component is too long",
				fmt.Sprintf("%s, %d lines\x00Limit is %d lines. Split it into smaller components and hooks — long components are hard to test and re-render everything together.", fn.name, lines, reactMaxComponentLines))
		}
		if n := len(fn.props); n > reactMaxProps {
			sev := security.SevLow
			if n > reactMaxProps+5 {
				sev = security.SevMedium
			}
			addC(fn.declOff, sev, "react-max-props", "Component takes too many props",
				fmt.Sprintf("%s, %d props\x00Limit is %d props — usually a sign the component does too much; group related props into an object or split it.", fn.name, n, reactMaxProps))
		}
		tags := scanJSX(f.code, fn.open, fn.close+1)
		maxD, maxOff := 0, 0
		for _, t := range tags {
			if t.kind != 1 && t.depth > maxD {
				maxD, maxOff = t.depth, t.off
			}
		}
		if maxD > reactMaxJSXDepth {
			sev := security.SevLow
			if maxD >= reactMaxJSXDepth+4 {
				sev = security.SevMedium
			}
			addC(maxOff, sev, "react-deep-jsx", "JSX nested too deeply",
				fmt.Sprintf("%s, %d levels\x00Limit is %d levels; extract the inner branches into sub-components.", fn.name, maxD, reactMaxJSXDepth))
		}
		if drilled := drilledProps(fn, tags); len(drilled) >= reactMinDrilledProps {
			addC(fn.declOff, security.SevLow, "react-prop-drilling", "Props passed straight through",
				fmt.Sprintf("%s: %s\x00Props are passed unchanged to child components; consider Context or composition.", fn.name, strings.Join(firstN(drilled, 5), ", ")))
		}
	}
	return hooks, comps
}

// splitDetail splits "detail\x00message" into its parts ("" detail when absent).
func splitDetail(s string) (detail, msg string) {
	if i := strings.IndexByte(s, 0); i >= 0 {
		return strings.ReplaceAll(s[:i], "`", ""), s[i+1:]
	}
	return "", s
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// readStateAndRefs collects the useState/useReducer values and useRef names of fn.
func readStateAndRefs(f flatSrc, fn reactFunc) (states []reactState, refs []string) {
	region := f.code[fn.open : fn.close+1]
	for _, m := range reUseState.FindAllStringSubmatchIndex(region, -1) {
		s := reactState{name: region[m[2]:m[3]], setter: region[m[4]:m[5]], off: fn.open + m[0]}
		if cl := f.matchClose(fn.open + m[1] - 1); cl > 0 {
			s.init = strings.TrimSpace(f.text[fn.open+m[1] : cl])
		}
		states = append(states, s)
	}
	for _, m := range reUseReducer.FindAllStringSubmatchIndex(region, -1) {
		states = append(states, reactState{name: region[m[2]:m[3]], off: fn.open + m[0]})
	}
	for _, m := range reUseRef.FindAllStringSubmatch(region, -1) {
		refs = append(refs, m[1])
	}
	return states, refs
}

func reactHookRules(f flatSrc, fn reactFunc, states []reactState, stateByName map[string]reactState,
	setters map[string]bool, refs []string, calls []hookCall, add func(off int, sev security.Severity, id, rule, msg string)) {

	callsSetter := func(body string) (string, bool) {
		for s := range setters {
			if regexp.MustCompile(`\b` + regexp.QuoteMeta(s) + `\s*\(`).MatchString(body) {
				return s, true
			}
		}
		return "", false
	}
	candidates := map[string]bool{}
	for _, s := range states {
		candidates[s.name] = true
	}
	for _, p := range fn.props {
		candidates[p] = true
	}
	if fn.propsIdent != "" {
		candidates[fn.propsIdent] = true
	}
	isEffect := func(n string) bool { return n == "useEffect" || n == "useLayoutEffect" || n == "useInsertionEffect" }

	for _, h := range calls {
		loopFlagged := false
		// no-set-state-in-effect-loop
		if isEffect(h.name) && !h.hasDeps {
			if s, ok := callsSetter(h.cbCode); ok {
				add(h.off, security.SevHigh, "react-setstate-effect-loop", "setState in an effect with no dependency array",
					"`"+s+"`\x00The setter runs after every render and itself triggers a render — an infinite loop unless something guards it. Add a dependency array (or guard the update).")
				loopFlagged = true
			}
		}
		// no-missing-deps
		switch {
		case !h.hasDeps && !loopFlagged && (h.name == "useCallback" || h.name == "useMemo"):
			add(h.off, security.SevMedium, "react-missing-deps", "Memo hook without a dependency array",
				h.name+"\x00With no dependency array it recomputes on every render, so the memoisation does nothing.")
		case !h.hasDeps && !loopFlagged && isEffect(h.name):
			add(h.off, security.SevMedium, "react-missing-deps", "Effect without a dependency array",
				h.name+"\x00With no dependency array it runs after every render; list what it depends on (or `[]` to run once).")
		case h.hasDeps && h.depsLit && !h.depsSpread && !f.rawContains(f.line(h.off)-1, f.line(h.end)+1, "exhaustive-deps"):
			missing := missingDeps(h, candidates, setters)
			if len(missing) > 0 {
				sev := security.SevMedium
				if len(h.deps) == 0 {
					sev = security.SevHigh
				}
				add(h.off, sev, "react-missing-deps", "Hook uses values missing from its dependencies",
					fmt.Sprintf("%s: %s\x00The callback reads values its dependency array doesn't list, so it keeps a stale value after they change.",
						h.name, strings.Join(firstN(missing, 4), ", ")))
			}
		}
		if !isEffect(h.name) || !h.hasDeps || !h.depsLit {
			continue
		}
		// no-effect-as-handler: single boolean-looking trigger dep, guarded, reset or setter.
		if len(h.deps) == 1 && isPlainIdent(h.deps[0]) {
			d := h.deps[0]
			st, known := stateByName[d]
			boolish := known && reStateBool.MatchString(st.init) || reTriggerName.MatchString(d)
			guard := regexp.MustCompile(`\bif\s*\(\s*!?\s*` + regexp.QuoteMeta(d) + `\b|\b` + regexp.QuoteMeta(d) + `\s*&&`).MatchString(h.cbCode)
			if boolish && guard {
				reset := known && st.setter != "" && regexp.MustCompile(`\b`+regexp.QuoteMeta(st.setter)+`\s*\(\s*(?:false|true|!\s*`+regexp.QuoteMeta(d)+`)\s*\)`).MatchString(h.cbCode)
				_, anySetter := callsSetter(h.cbCode)
				if reset || (reTriggerName.MatchString(d) && anySetter) {
					add(h.off, security.SevMedium, "react-effect-as-handler", "Effect used as an event handler",
						"`"+d+"`\x00The effect waits for a flag to flip, acts, then resets it — that's an event handler in disguise. Do the work in the handler that sets the flag instead.")
					continue
				}
			}
		}
		// no-derived-state: the effect only copies values into state.
		if len(h.deps) > 0 && effectOnlySets(h.cbCode, setters) {
			add(h.off, security.SevMedium, "react-derived-state", "State derived from other values via an effect",
				"\x00The effect only copies its dependencies into state, costing an extra render. Compute the value during render (or with useMemo) instead of storing it.")
			continue
		}
	}

	// no-derived-state: useState(prop) re-synced by an effect that lists that prop.
	for _, s := range states {
		src := strings.TrimPrefix(s.init, "props.")
		if s.setter == "" || src == "" || !isPlainIdent(src) || !(inStrings(fn.props, src) || strings.HasPrefix(s.init, "props.")) {
			continue
		}
		for _, h := range calls {
			if !isEffect(h.name) || !h.depsLit {
				continue
			}
			if dependsOn(h.deps, src) && !strings.Contains(h.cbCode, "if") && regexp.MustCompile(`\b`+regexp.QuoteMeta(s.setter)+`\s*\(`).MatchString(h.cbCode) {
				add(s.off, security.SevMedium, "react-derived-state", "State initialised from a prop and re-synced in an effect",
					"`"+s.name+"` ← `"+src+"`\x00The state mirrors a prop through useState + useEffect. Use the prop directly, or key the component on it, instead of duplicating it into state.")
				break
			}
		}
	}

	// no-direct-mutation
	region := f.code[fn.open : fn.close+1]
	var attrRanges [][2]int // JSX tag interiors, where `name={name}` is an attribute, not an assignment
	for _, t := range scanJSX(f.code, fn.open, fn.close+1) {
		if t.kind != 1 {
			attrRanges = append(attrRanges, [2]int{t.off - fn.open, t.off - fn.open + 1 + len(t.name) + len(t.attrs)})
		}
	}
	inAttr := func(off int) bool {
		for _, r := range attrRanges {
			if off >= r[0] && off < r[1] {
				return true
			}
		}
		return false
	}
	for _, s := range states {
		q := regexp.QuoteMeta(s.name)
		mut := regexp.MustCompile(reGuardPrefix + q + reMutator)
		deep := regexp.MustCompile(reGuardPrefix + q + `\s*(?:(?:\.\s*[\w$]+|\[[^\]\n]*\])+)\s*(?:=[^=>]|\+=|-=|\*=|/=|\+\+|--)`)
		direct := regexp.MustCompile(reGuardPrefix + q + `\s*(?:=[^=>]|\+=|-=)`)
		for _, loc := range mut.FindAllStringIndex(region, -1) {
			add(fn.open+loc[0], security.SevHigh, "react-direct-mutation", "State mutated in place",
				"`"+s.name+"`\x00Mutating React state in place (push/splice/sort…) won't trigger a re-render and breaks memoisation. Copy first (`[...x]`, `.toSorted()`), then call the setter.")
		}
		for _, loc := range deep.FindAllStringIndex(region, -1) {
			add(fn.open+loc[0], security.SevHigh, "react-direct-mutation", "State mutated in place",
				"`"+s.name+"`\x00Assigning into state changes it without a re-render; build a new object/array and pass it to the setter.")
		}
		for _, loc := range direct.FindAllStringIndex(region, -1) {
			if declaredBefore(region, loc[0]) || inAttr(loc[0]+1) {
				continue
			}
			add(fn.open+loc[0], security.SevHigh, "react-direct-mutation", "State assigned directly",
				"`"+s.name+"`\x00Reassigning the state variable instead of calling its setter; the UI won't update.")
		}
	}

	// no-state-in-ref
	for _, r := range refs {
		pat := regexp.MustCompile(reGuardPrefix + regexp.QuoteMeta(r) + `\.current\b`)
		for _, loc := range pat.FindAllStringIndex(region, -1) {
			off := fn.open + loc[0]
			if jsxChildExpression(f, off+1) {
				add(off+1, security.SevMedium, "react-state-in-ref", "Ref value rendered in JSX",
					"`"+r+".current`\x00A ref is read while rendering, but changing a ref doesn't re-render. If the UI depends on it, keep it in useState.")
			}
		}
	}
}

func isPlainIdent(s string) bool {
	return s != "" && reJSXTagName.FindString(s) == s && !strings.ContainsAny(s, ".:-")
}

func inStrings(set []string, s string) bool {
	for _, x := range set {
		if x == s {
			return true
		}
	}
	return false
}

// dependsOn reports whether any dependency entry is, or is rooted at, name.
func dependsOn(deps []string, name string) bool {
	for _, d := range deps {
		if depRoot(d) == name {
			return true
		}
	}
	return false
}

// depRoot is the leading identifier of a dependency expression (`a.b[0]` → a).
func depRoot(d string) string {
	d = strings.TrimSpace(d)
	if i := strings.IndexAny(d, ".[?"); i >= 0 {
		d = d[:i]
	}
	return d
}

// declaredBefore reports whether the match at off is a fresh declaration
// (`let x = …`, `const x = …`) of the same name rather than a reassignment.
func declaredBefore(region string, off int) bool {
	i := off
	for i < len(region) && !isIdentByte(region[i]) {
		i++ // skip the prefix char the regexp consumed
	}
	pre := strings.TrimRight(region[:i], " \t")
	return strings.HasSuffix(pre, "const") || strings.HasSuffix(pre, "let") || strings.HasSuffix(pre, "var")
}

// missingDeps lists the state/props values the callback reads that its
// dependency array doesn't cover.
func missingDeps(h hookCall, candidates, setters map[string]bool) []string {
	declared := map[string]bool{}
	for _, m := range reCallbackDef.FindAllStringSubmatch(h.cbCode, -1) {
		for _, g := range m[1:] {
			for _, id := range reIdentToken.FindAllStringSubmatch(" "+g, -1) {
				declared[id[2]] = true
			}
		}
	}
	for _, m := range reDestructDef.FindAllStringSubmatch(h.cbCode, -1) {
		for _, id := range reIdentToken.FindAllStringSubmatch(" "+m[1], -1) {
			declared[id[2]] = true
		}
	}
	roots := map[string]bool{}
	for _, d := range h.deps {
		roots[depRoot(d)] = true
	}
	seen := map[string]bool{}
	var missing []string
	for _, loc := range reIdentToken.FindAllStringSubmatchIndex(h.cbCode, -1) {
		id := h.cbCode[loc[4]:loc[5]]
		if !candidates[id] || setters[id] || declared[id] || roots[id] || seen[id] {
			continue
		}
		rest := strings.TrimLeft(h.cbCode[loc[5]:], " \t")
		if strings.HasPrefix(rest, ":") && !strings.HasPrefix(rest, "::") {
			continue // object-literal key or label, not a read
		}
		if strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "==") && !strings.HasPrefix(rest, "=>") {
			continue // JSX attribute name (`className="…"`) or assignment, not a read
		}
		seen[id] = true
		missing = append(missing, id)
	}
	sort.Strings(missing)
	return missing
}

// effectOnlySets reports an effect callback whose statements are all setter calls.
func effectOnlySets(cb string, setters map[string]bool) bool {
	body := strings.TrimSpace(cb)
	if i := strings.Index(body, "=>"); i >= 0 {
		body = strings.TrimSpace(body[i+2:])
	} else if strings.HasPrefix(body, "function") {
		if i := strings.IndexByte(body, '{'); i >= 0 {
			body = body[i:]
		}
	}
	if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
		body = strings.TrimSpace(body[1 : len(body)-1])
	}
	if body == "" {
		return false
	}
	n := 0
	for _, st := range strings.FieldsFunc(body, func(r rune) bool { return r == ';' || r == '\n' }) {
		st = strings.TrimSpace(st)
		if st == "" {
			continue
		}
		id := reJSXTagName.FindString(st)
		if id == "" || !setters[id] || !strings.HasPrefix(strings.TrimSpace(st[len(id):]), "(") {
			return false
		}
		n++
	}
	return n > 0
}

// scanIndexKeys flags key={index} inside .map callbacks.
func scanIndexKeys(f flatSrc, add func(off int, sev security.Severity, id, rule, msg string)) {
	for _, m := range reMapIndex.FindAllStringSubmatchIndex(f.code, -1) {
		idx := f.code[m[2]:m[3]]
		open := m[0] + strings.IndexByte(f.code[m[0]:], '(')
		cl := f.matchClose(open)
		if cl < 0 {
			continue
		}
		for _, k := range reKeyAttr.FindAllStringIndex(f.code[open:cl], -1) {
			bo := open + k[1] - 1
			bc := f.matchClose(bo)
			if bc < 0 || bc > cl {
				continue
			}
			if isIndexKeyExpr(strings.TrimSpace(f.text[bo+1:bc]), idx) {
				add(bo, security.SevMedium, "react-index-key", "Array index used as a React key",
					"key={"+idx+"}\x00Position-based keys make React reuse DOM and state by position, so inserting, removing or reordering items shows the wrong state. Use a stable id from the item.")
			}
		}
	}
}

var reIndexTemplate = regexp.MustCompile("^`[^`$]*\\$\\{\\s*([A-Za-z_$][\\w$]*)\\s*\\}[^`$]*`$")

func isIndexKeyExpr(expr, idx string) bool {
	if expr == idx || expr == "String("+idx+")" || expr == idx+".toString()" {
		return true
	}
	if m := reIndexTemplate.FindStringSubmatch(expr); m != nil && m[1] == idx {
		return true
	}
	return false
}

// jsxChildExpression reports whether the identifier at off sits inside a JSX
// `{…}` container — a child expression or a non-handler attribute — rather than
// in an event handler or ordinary code.
func jsxChildExpression(f flatSrc, off int) bool {
	depth := 0
	for i := off; i >= 0; i-- {
		switch f.code[i] {
		case '}':
			depth++
		case '{':
			if depth > 0 {
				depth--
				continue
			}
			inside := f.code[i+1 : off]
			if strings.Contains(inside, "=>") || strings.Contains(inside, "function") {
				return false
			}
			j := i - 1
			for j >= 0 && (f.code[j] == ' ' || f.code[j] == '\t' || f.code[j] == '\n') {
				j--
			}
			if j < 0 {
				return false
			}
			switch f.code[j] {
			case '>':
				return j == 0 || f.code[j-1] != '=' // {expr} as a child (but not an arrow body `=> {`)
			case '=': // attr={expr}
				k := j - 1
				for k >= 0 && (isIdentByte(f.code[k]) || f.code[k] == '-') {
					k--
				}
				attr := f.code[k+1 : j]
				return attr != "" && attr != "ref" && attr != "key" && !strings.HasPrefix(attr, "on")
			}
			return false
		case ';':
			if depth == 0 {
				return false // reached a statement boundary outside any JSX container
			}
		}
	}
	return false
}

// drilledProps lists destructured props that are forwarded unchanged
// (`name={name}`) to custom components.
func drilledProps(fn reactFunc, tags []jsxTag) []string {
	if len(fn.props) == 0 {
		return nil
	}
	props := map[string]bool{}
	for _, p := range fn.props {
		props[p] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, t := range tags {
		if t.kind == 1 || !reCompName.MatchString(t.name) {
			continue
		}
		for _, m := range reForwardAttr.FindAllStringSubmatch(t.attrs, -1) {
			if m[1] == m[2] && props[m[1]] && !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
	}
	sort.Strings(out)
	return out
}

var reForwardAttr = regexp.MustCompile(`([A-Za-z_$][\w$]*)=\{\s*([A-Za-z_$][\w$]*)\s*\}`)
