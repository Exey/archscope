package security

import (
	"regexp"
	"strings"
)

// Suppressor reads the "I have looked at this line" comments people already
// write for other linters — `# noqa`, `# pylint: disable=…`, `# nosec`,
// `//nolint`, `// eslint-disable-next-line …`, `NOSONAR`, `@SuppressWarnings`,
// `// swiftlint:disable`, `// NOLINT` — and answers whether a finding at a line
// is covered by one. A directive with no rule list covers every rule; one with a
// list covers a rule when any listed name is the rule's ID, one of its
// aliases (pylint names, flake8 codes, go-critic and ESLint names…) or a family
// ("gosec", "bandit", "gocritic"). Ported in spirit from prospector's
// suppression.py, extended to every language ArchScope scans.
type Suppressor struct {
	spans []suppressSpan
}

type suppressSpan struct {
	from, to int // 1-based, inclusive
	all      bool
	names    map[string]bool
}

var suppressMarkers = []string{"noqa", "nosec", "nolint", "eslint-disable", "NOSONAR", "pylint:", "SuppressWarnings", "@Suppress", "swiftlint:", "NOLINT", "pylint :"}

var (
	reSupFileNoqa  = regexp.MustCompile(`(?i)#\s*(?:flake8|ruff)\s*:\s*noqa\b(?:\s*:\s*([\w\s,.-]+))?`)
	reSupPylint    = regexp.MustCompile(`(?i)#\s*pylint\s*:\s*(disable-next|disable-line|disable|skip-file)\b(?:\s*=\s*([\w\s,.-]+))?`)
	reSupNoqa      = regexp.MustCompile(`(?i)#\s*noqa\b(?:\s*:\s*([\w\s,.-]+))?`)
	reSupNosec     = regexp.MustCompile(`(?i)(?:#|//)\s*#?nosec\b(?:\s+([\w,\s]*\w))?`)
	reSupNolint    = regexp.MustCompile(`(?:#|//)\s*nolint\b(?:\s*:\s*([\w,-]+))?`)
	reSupEslint    = regexp.MustCompile(`(?://|/\*)\s*eslint-(disable-next-line|disable-line|disable|enable)\b([^*\n]*)`)
	reSupSonar     = regexp.MustCompile(`(?i)(?://|#)\s*NOSONAR\b`)
	reSupClangTidy = regexp.MustCompile(`//\s*NOLINT(NEXTLINE)?\b(?:\(([\w\s,.*-]+)\))?`)
	reSupJava      = regexp.MustCompile(`@SuppressWarnings\s*\(\s*(?:\{([^}]*)\}|("[^"]*"))|@Suppress\s*\(([^)]*)\)`)
	reSupSwiftlint = regexp.MustCompile(`//\s*swiftlint:(disable|enable)(:next|:this|:previous)?\s+([\w\s,-]+)`)
	reQuoted       = regexp.MustCompile(`"([^"]*)"`)
)

// NewSuppressor scans a file's raw lines for suppression comments. It returns nil
// (a valid, always-false Suppressor) when the file has none, so the common case
// costs one substring pass.
func NewSuppressor(raw []string) *Suppressor {
	var s *Suppressor
	for i, line := range raw {
		hit := false
		for _, m := range suppressMarkers {
			if strings.Contains(line, m) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		if s == nil {
			s = &Suppressor{}
		}
		s.parseLine(raw, i)
	}
	return s
}

// Suppressed reports whether a finding of ruleID (plus any family names such as
// "gosec"/"bandit") at 1-based line is covered by a directive.
func (s *Suppressor) Suppressed(line int, ruleID string, families ...string) bool {
	if s == nil {
		return false
	}
	for _, sp := range s.spans {
		if line < sp.from || line > sp.to {
			continue
		}
		if sp.all {
			return true
		}
		if matchesName(sp.names, ruleID) {
			return true
		}
		for _, f := range families {
			if sp.names[normName(f)] {
				return true
			}
		}
	}
	return false
}

func normName(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	n = strings.ReplaceAll(n, "_", "-")
	return n
}

// matchesName checks the rule ID and each of its aliases against the directive names.
func matchesName(names map[string]bool, ruleID string) bool {
	if names[normName(ruleID)] {
		return true
	}
	for _, a := range RuleAliases[ruleID] {
		n := normName(a)
		if names[n] {
			return true
		}
		if i := strings.LastIndexByte(n, '/'); i >= 0 && names[n[i+1:]] {
			return true
		}
	}
	return false
}

func nameSet(list string) map[string]bool {
	set := map[string]bool{}
	for _, n := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if n = normName(n); n != "" && n != "--" {
			set[n] = true
		}
	}
	return set
}

// add records a span; an empty name list (or the name "all") means every rule.
func (s *Suppressor) add(from, to int, names map[string]bool) {
	sp := suppressSpan{from: from, to: to, names: names}
	if len(names) == 0 || names["all"] {
		sp.all = true
	}
	s.spans = append(s.spans, sp)
}

// standalone reports whether the comment is the only thing on its line.
func standalone(line string, matchStart int) bool {
	return strings.TrimSpace(line[:matchStart]) == ""
}

func (s *Suppressor) parseLine(raw []string, i int) {
	line := raw[i]
	n := i + 1 // 1-based

	if g := reSupFileNoqa.FindStringSubmatchIndex(line); g != nil {
		names := map[string]bool{}
		if g[2] >= 0 {
			names = nameSet(line[g[2]:g[3]])
		}
		s.add(1, len(raw), names)
		return
	}
	if g := reSupPylint.FindStringSubmatchIndex(line); g != nil {
		kind := strings.ToLower(line[g[2]:g[3]])
		names := map[string]bool{}
		if g[4] >= 0 {
			names = nameSet(line[g[4]:g[5]])
		}
		switch {
		case kind == "skip-file":
			s.add(1, len(raw), map[string]bool{})
		case kind == "disable-next":
			s.add(n+1, n+1, names)
		case kind == "disable-line":
			s.add(n, n, names)
		case standalone(line, g[0]): // block scope: the rest of the enclosing indentation block
			s.add(n+1, blockEndByIndent(raw, i), names)
		default:
			s.add(n, n, names)
		}
		return
	}
	if g := reSupNoqa.FindStringSubmatchIndex(line); g != nil {
		names := map[string]bool{}
		if g[2] >= 0 {
			names = nameSet(line[g[2]:g[3]])
		}
		s.add(n, n, names)
	}
	if g := reSupNosec.FindStringSubmatchIndex(line); g != nil {
		names := map[string]bool{}
		if g[2] >= 0 {
			names = nameSet(line[g[2]:g[3]])
		}
		if standalone(line, g[0]) {
			s.add(n, n+1, names)
		} else {
			s.add(n, n, names)
		}
	}
	if g := reSupNolint.FindStringSubmatchIndex(line); g != nil {
		names := map[string]bool{}
		if g[2] >= 0 {
			names = nameSet(line[g[2]:g[3]])
		}
		if standalone(line, g[0]) {
			s.add(n+1, declEnd(raw, i+1), names)
		} else {
			s.add(n, n, names)
		}
	}
	if g := reSupEslint.FindStringSubmatchIndex(line); g != nil {
		kind := line[g[2]:g[3]]
		rest := line[g[4]:g[5]]
		if k := strings.Index(rest, "--"); k >= 0 {
			rest = rest[:k]
		}
		names := nameSet(rest)
		switch kind {
		case "disable-next-line":
			s.add(n+1, n+1, names)
		case "disable-line":
			s.add(n, n, names)
		case "disable":
			end := len(raw)
			for j := i + 1; j < len(raw); j++ {
				if e := reSupEslint.FindStringSubmatch(raw[j]); e != nil && e[1] == "enable" {
					end = j + 1
					break
				}
			}
			s.add(n, end, names)
		}
	}
	if reSupSonar.MatchString(line) {
		s.add(n, n, map[string]bool{})
	}
	if g := reSupClangTidy.FindStringSubmatchIndex(line); g != nil {
		names := map[string]bool{}
		if g[4] >= 0 {
			names = nameSet(line[g[4]:g[5]])
		}
		if g[2] >= 0 {
			s.add(n+1, n+1, names)
		} else {
			s.add(n, n, names)
		}
	}
	if g := reSupJava.FindStringSubmatchIndex(line); g != nil {
		names := map[string]bool{}
		body := line[g[0]:g[1]]
		for _, q := range reQuoted.FindAllStringSubmatch(body, -1) {
			names[normName(q[1])] = true
		}
		if len(names) > 0 {
			if standalone(line, g[0]) {
				s.add(n+1, declEnd(raw, i+1), names)
			} else {
				s.add(n, n, names)
			}
		}
	}
	if g := reSupSwiftlint.FindStringSubmatchIndex(line); g != nil && line[g[2]:g[3]] == "disable" {
		names := nameSet(line[g[6]:g[7]])
		switch {
		case g[4] >= 0 && line[g[4]:g[5]] == ":next":
			s.add(n+1, n+1, names)
		case g[4] >= 0 && line[g[4]:g[5]] == ":previous":
			s.add(n-1, n-1, names)
		case g[4] >= 0:
			s.add(n, n, names)
		default:
			end := len(raw)
			for j := i + 1; j < len(raw); j++ {
				if e := reSupSwiftlint.FindStringSubmatch(raw[j]); e != nil && e[1] == "enable" && e[2] == "" {
					end = j + 1
					break
				}
			}
			s.add(n, end, names)
		}
	}
}

// blockEndByIndent returns the last 1-based line of the block that a standalone
// comment at index i opens: every following line indented at least as deep (an
// indent-0 comment covers the rest of the file).
func blockEndByIndent(raw []string, i int) int {
	ind := indentOf(raw[i])
	if ind == 0 {
		return len(raw)
	}
	last := i + 1
	for j := i + 1; j < len(raw); j++ {
		if strings.TrimSpace(raw[j]) == "" {
			continue
		}
		if indentOf(raw[j]) < ind {
			break
		}
		last = j + 1
	}
	return last
}

func indentOf(l string) int {
	n := 0
	for _, c := range l {
		if c == ' ' {
			n++
		} else if c == '\t' {
			n += 4
		} else {
			break
		}
	}
	return n
}

// declEnd returns the last 1-based line of the declaration that starts at index
// i (the line after a standalone directive): through the matching closing brace
// when its header opens one, otherwise just that line.
func declEnd(raw []string, i int) int {
	if i >= len(raw) {
		return len(raw)
	}
	depth, started := 0, false
	for j := i; j < len(raw) && j < i+600; j++ {
		for _, c := range raw[j] {
			switch c {
			case '{':
				depth++
				started = true
			case '}':
				depth--
			}
		}
		if started && depth <= 0 {
			return j + 1
		}
		if !started && j >= i+1 && !strings.HasSuffix(strings.TrimSpace(raw[j-1]), ",") && !strings.HasPrefix(strings.TrimSpace(raw[j]), "{") {
			break // a one-line statement with no body
		}
	}
	return i + 1
}

// RuleAliases maps a rule ID to the names other tools call the same check, so
// `# noqa: B006` or `# pylint: disable=too-many-locals` silences ours too.
var RuleAliases = map[string][]string{
	// Python — pylint / pyflakes / flake8 / bandit
	"py-mutable-default":        {"dangerous-default-value", "W0102", "B006", "B008", "mutable-default"},
	"py-bare-except":            {"bare-except", "W0702", "E722", "B001"},
	"py-except-pass":            {"broad-except", "broad-exception-caught", "W0703", "W0718", "B110", "S110", "SIM105", "BLE001", "try-except-pass"},
	"py-raise-no-from":          {"raise-missing-from", "W0707", "B904"},
	"py-is-literal":             {"literal-comparison", "R0123", "F632"},
	"py-assert-tuple":           {"assert-on-tuple", "W0199", "F631"},
	"py-singleton-compare":      {"singleton-comparison", "C0121", "E711", "E712"},
	"py-fstring-no-placeholder": {"f-string-without-interpolation", "W1309", "F541"},
	"py-dup-dict-key":           {"duplicate-key", "W0109", "F601"},
	"py-finally-return":         {"return-in-finally", "W0150", "B012"},
	"py-lambda-loop-var":        {"cell-var-from-loop", "W0640", "B023"},
	"py-blocking-async":         {"ASYNC100", "ASYNC101", "ASYNC210", "blocking-call"},
	"py-dup-operand":            {"comparison-with-itself", "R0124", "PLR0124"},
	"py-wildcard-import":        {"wildcard-import", "W0401", "F403"},
	"py-redefined-builtin":      {"redefined-builtin", "W0622", "A001"},
	"py-self-assign":            {"self-assigning-variable", "W0127", "PLW0127"},
	"shape-returns":             {"too-many-return-statements", "R0911", "PLR0911"},
	"shape-branches":            {"too-many-branches", "R0912", "PLR0912"},
	"shape-locals":              {"too-many-locals", "R0914", "PLR0914"},
	"shape-class-attrs":         {"too-many-instance-attributes", "R0902"},
	"shape-class-methods":       {"too-many-public-methods", "R0904"},
	"shape-class-bases":         {"too-many-ancestors", "R0901"},
	"shape-module-lines":        {"too-many-lines", "C0302", "max-lines"},
	"cyclomatic":                {"cyclomatic-complexity", "C901", "too-complex", "cyclomatic-complexity", "gocyclo", "complexity", "cyclop"},
	"params":                    {"too-many-arguments", "R0913", "PLR0913", "max-params", "function-parameter-count", "funlen"},
	"nesting":                   {"nesting", "max-depth", "nestif", "R1702", "too-many-nested-blocks"},
	// Go — go-critic
	"dup-subexpr":             {"dupSubExpr", "gocritic", "SA4000"},
	"bad-cond":                {"badCond", "gocritic"},
	"off-by-one":              {"offBy1", "gocritic"},
	"http-error-no-return":    {"returnAfterHttpError", "gocritic"},
	"exit-after-defer":        {"exitAfterDefer", "gocritic", "gocritic-exitafterdefer"},
	"bad-lock":                {"badLock", "gocritic"},
	"unchecked-inline-err":    {"uncheckedInlineErr", "gocritic"},
	"case-order":              {"caseOrder", "gocritic"},
	"external-error-reassign": {"externalErrorReassign", "gocritic"},
	"sloppy-reassign":         {"sloppyReassign", "gocritic"},
	"dup-branch":              {"dupBranchBody", "gocritic", "dupl"},
	"dup-case":                {"dupCase", "gocritic"},
	"dup-clone":               {"duplicate-code", "R0801", "dupl", "jscpd", "CPD-START"},
	"strings-compare":         {"stringsCompare", "gocritic"},
	"equal-fold":              {"equalFold", "gocritic"},
	"join-small":              {"stringConcatSimplify", "gocritic"},
	"dynamic-errorf":          {"dynamicFmtString", "gocritic"},
	"index-as-contains":       {"wrapperFunc", "gocritic"},
	"perf-append-combine":     {"appendCombine", "gocritic"},
	"perf-range-append-all":   {"rangeAppendAll", "gocritic"},
	"perf-slice-clear":        {"sliceClear", "gocritic"},
	"perf-index-alloc":        {"indexAlloc", "gocritic"},
	"perf-write-byte":         {"preferWriteByte", "gocritic"},
	"perf-string-writer":      {"preferStringWriter", "gocritic"},
	"sync-map-load-delete":    {"syncMapLoadAndDelete", "gocritic"},
	"exposed-mutex":           {"exposedSyncMutex", "gocritic"},
	"once-func-misuse":        {"badSyncOnceFunc", "gocritic"},
	"http-no-body":            {"httpNoBody", "gocritic"},
	"time-expr":               {"timeExprSimplify", "gocritic"},
	"regex-must":              {"regexpMust", "gocritic"},
	"regex-simplify":          {"regexpSimplify", "gocritic"},
	"regex-bad":               {"badRegexp", "gocritic"},
	// Strings / regex
	"concat-in-loop": {"string-concatenation", "perfsprint", "S1643", "PERF401"},
	"regex-in-loop":  {"regexp-in-loop", "re-compile-in-loop"},
	// React / TS / JS — eslint
	"react-missing-deps":         {"react-hooks/exhaustive-deps", "exhaustive-deps"},
	"react-index-key":            {"react/no-array-index-key", "no-array-index-key"},
	"react-direct-mutation":      {"react/no-direct-mutation-state", "no-direct-mutation"},
	"react-setstate-effect-loop": {"react-hooks/rules-of-hooks", "no-set-state-in-effect-loop"},
	"react-max-lines":            {"max-lines-per-function", "react/max-lines", "max-lines"},
	"react-max-props":            {"react/max-props", "max-props"},
	"react-deep-jsx":             {"react/jsx-max-depth", "jsx-max-depth"},
	// Dead code
	"dead-unused-import":  {"no-unused-vars", "@typescript-eslint/no-unused-vars", "unused-imports/no-unused-imports", "unused-import", "unused", "W0611", "F401"},
	"dead-unused-var":     {"no-unused-vars", "@typescript-eslint/no-unused-vars", "unused-variable", "unused", "W0612", "F841", "ineffassign", "deadcode"},
	"dead-unreachable":    {"no-unreachable", "unreachable-code", "unreachable", "W0101"},
	"dead-commented-code": {"no-commented-out-code", "E800", "eradicate", "commented-code"},
	"dead-unused-symbol":  {"unused-function", "unused-private-member", "vulture", "deadcode", "unused", "U1000"},
	// Merge / diff markers
	"marker-conflict": {"merge-conflict"},
	// Security families: bandit codes for the Python rules
	"python.eval_exec":                 {"B307", "B102"},
	"python.unsafe_yaml":               {"B506"},
	"python.weak_crypto":               {"B303", "B324", "B304"},
	"python.weak_random":               {"B311"},
	"python.unverified_ssl":            {"B501", "B323"},
	"python.debug_mode":                {"B201"},
	"python.os_system":                 {"B605"},
	"python.shell_injection":           {"B602", "B604", "B607", "B609"},
	"python.hardcoded_credentials":     {"B105", "B106", "B107", "hardcoded-password"},
	"python.insecure_deserialization":  {"B301", "B302"},
	"python.insecure_file_permissions": {"B103"},
	"python.xxe":                       {"B313", "B314", "B315", "B316", "B317", "B318", "B319", "B320", "B405", "B406", "B407", "B408", "B410"},
	"python.sql_concat":                {"B608"},
}

// SecurityFamilies are the extra names a directive may use to silence every
// security rule of a language (`//nolint:gosec`, `# nosec`-style families).
func SecurityFamilies(languageID string) []string {
	switch languageID {
	case "go":
		return []string{"gosec", "security"}
	case "python":
		return []string{"bandit", "security"}
	case "ts", "js":
		return []string{"eslint-plugin-security", "security", "no-unsanitized"}
	}
	return []string{"security"}
}
