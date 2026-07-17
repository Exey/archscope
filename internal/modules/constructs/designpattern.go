// designpattern.go is a universal Gang-of-Four design-pattern detector,
// generalized from ArchSwiftScope's DesignPatternDetector. It works purely from
// declaration-name conventions (a type whose name ends in "Factory", "Builder",
// "Decorator", … is almost always playing that GoF role) plus a few accessor
// signals (a "shared"/"instance" member implies a Singleton). Name conventions
// are shared across Swift, Kotlin, TS, Java, C#, Python and Go, so the detector
// is language-agnostic and conservative (low false-positive) by construction.
//
// Two extensions on top of the original port:
//
//  1. Feature Flag — universal (all languages), detected from name suffixes
//     (*FeatureFlag/*FeatureToggle/*FeatureGate) and from known flagging-SDK
//     imports (LaunchDarkly, Split, Unleash, ConfigCat, Flagsmith, Statsig,
//     GrowthBook, Optimizely, Firebase Remote Config) already captured on
//     ParsedFile.Imports — no extra file read needed.
//
//  2. Swift "language feature as pattern" idioms and POSA/concurrency
//     equivalents, ported from ArchSwiftScope's DesignPatternDetector:
//     Extension, actor-as-Monitor-Object, and lazy var (Lazy Initialization)
//     are constructs Swift absorbed straight into the language — reported as
//     a distinct, muted "idiom" row (IsIdiom) so they don't inflate the
//     pattern count the way a deliberate Factory/Observer/Command choice
//     does — plus Read–Write Lock (DispatchQueue+.barrier), Double-Checked
//     Locking (os_unfair_lock + repeated nil-check), Thread Pool
//     (OperationQueue+maxConcurrentOperationCount), Fluent Interface (≥2
//     "-> Self" methods per file), Multiton (static keyed-instance
//     dictionaries), Dependency Injection (Swinject import), and Observer via
//     Combine (@Published/ObservableObject/import Combine, folded into the
//     same "Observer" match as the NC/Combine suffix signals).
package constructs

import (
	"fmt"
	"html"
	"os"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/security"
)

func init() { modules.Default.Register(DesignPatterns{}) }

// DesignPatterns is the universal design-pattern detector.
type DesignPatterns struct{}

func (DesignPatterns) ID() string                       { return "designpattern" }
func (DesignPatterns) Title() string                    { return "Design Patterns" }
func (DesignPatterns) AppliesTo(languageID string) bool { return true } // universal

// patternCategory groups GoF patterns.
type patternCategory string

const (
	creational patternCategory = "Creational"
	structural patternCategory = "Structural"
	behavioral patternCategory = "Behavioral"
	// Not a GoF category — Monitor Object, Read–Write Lock, Double-Checked
	// Locking, and Thread Pool are POSA/concurrency patterns. Filing them
	// under Behavioral would misdescribe them: they're about thread-safety,
	// not object interaction, so they get their own column (mirrors
	// ArchSwiftScope's PatternCategory.concurrency).
	concurrency patternCategory = "Concurrency"
)

// patternCategoryOrder fixes the display order.
var patternCategoryOrder = []patternCategory{creational, structural, behavioral, concurrency}

// patternCategoryIcon is the emoji shown before each category's as-sub heading.
var patternCategoryIcon = map[patternCategory]string{
	creational:  "🏭",
	structural:  "🧱",
	behavioral:  "🎭",
	concurrency: "🧵",
}

// PatternMatch is one detected pattern with its evidence.
type PatternMatch struct {
	Pattern  string
	Category patternCategory
	Count    int
	Examples []string // "TypeName (file.ext)"
	// IsIdiom marks constructs Swift built straight into the language
	// (Extension, actor-as-Monitor-Object, lazy var) — virtually every real
	// Swift codebase "has" them, so reporting them alongside a deliberate
	// Factory/Observer/Command choice would conflate "uses the language" with
	// "chose a pattern". Rendered as a distinct, muted row and excluded from
	// the summary-card pattern count.
	IsIdiom bool
}

// DesignPatternResult is the module output.
type DesignPatternResult struct {
	Matches []PatternMatch
}

// HasDetection reports whether any pattern was found.
func (r DesignPatternResult) HasDetection() bool { return len(r.Matches) > 0 }

// suffixRule maps a declaration-name suffix to a GoF pattern. kinds, when
// non-nil, restricts the match to those declaration kinds (e.g. Delegation
// only fires on a protocol/interface named "*Delegate", not a class); nil
// means "any kind isPatternTypeKind already allows".
type suffixRule struct {
	suffix   string
	pattern  string
	category patternCategory
	kinds    []parser.DeclKind
}

// kindAllowed reports whether k is permitted by a rule's kind filter.
func kindAllowed(kinds []parser.DeclKind, k parser.DeclKind) bool {
	if kinds == nil {
		return true
	}
	for _, kk := range kinds {
		if kk == k {
			return true
		}
	}
	return false
}

// suffixRules are checked against every type-like declaration name. Order does
// not matter; a name is attributed to the first rule it satisfies.
//
// Factory and Prototype are deliberately absent here: Factory needs a
// whole-codebase pass to tell Factory Method from Abstract Factory (see
// factoryLabel in Analyze), and Prototype is detected from content
// (NSCopying/copy()/clone()) rather than its name, in scanSwiftFile below.
var suffixRules = []suffixRule{
	{suffix: "Builder", pattern: "Builder", category: creational},
	{suffix: "Adapter", pattern: "Adapter", category: structural},
	{suffix: "Bridge", pattern: "Bridge", category: structural},
	{suffix: "Composite", pattern: "Composite", category: structural},
	{suffix: "Decorator", pattern: "Decorator", category: structural},
	{suffix: "Facade", pattern: "Facade", category: structural},
	{suffix: "Flyweight", pattern: "Flyweight", category: structural},
	{suffix: "Proxy", pattern: "Proxy", category: structural},
	// Cache-backed types implement caching, not GoF Flyweight (shared
	// immutable intrinsic state) — restricted to concrete kinds so a
	// CacheProtocol interface doesn't double-count with its implementation.
	{suffix: "Cache", pattern: "Caching", category: structural,
		kinds: []parser.DeclKind{parser.DeclStruct, parser.DeclClass, parser.DeclActor}},
	{suffix: "Strategy", pattern: "Strategy", category: behavioral},
	{suffix: "Observer", pattern: "Observer", category: behavioral},
	{suffix: "Listener", pattern: "Observer", category: behavioral},
	{suffix: "Subscriber", pattern: "Observer", category: behavioral},
	{suffix: "Publisher", pattern: "Observer", category: behavioral},
	// Delegation is split out from Observer: one object forwarding
	// responsibility to a single designated other is a distinct claim from
	// Observer's one-to-many broadcast, even though both ship as protocols.
	{suffix: "Delegate", pattern: "Delegation", category: behavioral,
		kinds: []parser.DeclKind{parser.DeclInterface}},
	{suffix: "Command", pattern: "Command", category: behavioral},
	{suffix: "Visitor", pattern: "Visitor", category: behavioral},
	{suffix: "Mediator", pattern: "Mediator", category: behavioral},
	// Memento restricted to class/struct, matching the reference — an enum or
	// protocol named "*Snapshot"/"*Memento" is usually a state description,
	// not the pattern's actual originator/caretaker/memento trio.
	{suffix: "Memento", pattern: "Memento", category: behavioral,
		kinds: []parser.DeclKind{parser.DeclClass, parser.DeclStruct}},
	{suffix: "Snapshot", pattern: "Memento", category: behavioral,
		kinds: []parser.DeclKind{parser.DeclClass, parser.DeclStruct}},
	{suffix: "Iterator", pattern: "Iterator", category: behavioral},
	{suffix: "Interpreter", pattern: "Interpreter", category: behavioral},
	{suffix: "Handler", pattern: "Chain of Responsibility", category: behavioral},
	// Feature Flag / Toggle — a runtime behavior switch, closely related to
	// Strategy's "select behavior at runtime" intent. Not in the GoF catalog,
	// but a real, widespread practice worth surfacing the same way.
	{suffix: "FeatureFlag", pattern: "Feature Flag", category: behavioral},
	{suffix: "FeatureToggle", pattern: "Feature Flag", category: behavioral},
	{suffix: "FeatureGate", pattern: "Feature Flag", category: behavioral},
	// Dependency Injection by explicit naming convention — the Swinject-import
	// signal below covers the case where no such type is named.
	{suffix: "ServiceLocator", pattern: "Dependency Injection", category: creational},
	{suffix: "DIContainer", pattern: "Dependency Injection", category: creational},
	{suffix: "Injector", pattern: "Dependency Injection", category: creational},
}

// nullObjectKinds restricts Null Object to concrete/enumerable kinds — an
// interface named "NullFoo" would be unusual and isn't the pattern anyway
// (Null Object is a concrete no-op stand-in, not an abstraction).
var nullObjectKinds = []parser.DeclKind{parser.DeclClass, parser.DeclStruct, parser.DeclEnum}

// hasRolePrefix reports whether name starts with prefix as a whole "word" —
// i.e. "NullUser" matches "Null" but "Nullable" does not.
func hasRolePrefix(name, prefix string) bool {
	if len(name) <= len(prefix) || !strings.HasPrefix(name, prefix) {
		return false
	}
	next := name[len(prefix)]
	return next >= 'A' && next <= 'Z'
}

// featureFlagImportNeedles are known feature-flagging SDK import markers,
// matched case-insensitively against ParsedFile.Imports — already parsed for
// every language, so this needs no extra file read and works universally.
var featureFlagImportNeedles = []string{
	"launchdarkly", "unleash", "configcat", "flagsmith", "statsig",
	"growthbook", "optimizely", "splitio", "split.io", "remoteconfig",
}

// hasFeatureFlagImport reports whether any of a file's imports names a known
// feature-flagging SDK.
func hasFeatureFlagImport(imports []string) bool {
	for _, imp := range imports {
		low := strings.ToLower(imp)
		for _, needle := range featureFlagImportNeedles {
			if strings.Contains(low, needle) {
				return true
			}
		}
	}
	return false
}

// singletonAccessors are member names that strongly imply a Singleton.
var singletonAccessors = map[string]bool{
	"shared": true, "sharedinstance": true, "instance": true,
	"default": true, "getinstance": true, "current": true,
}

// isPatternTypeKind reports whether a declaration kind can carry a pattern
// name — like isTypeKind, plus DeclService (a GoF role can be played by a
// declared service/RPC surface too).
func isPatternTypeKind(k parser.DeclKind) bool {
	switch k {
	case parser.DeclStruct, parser.DeclClass, parser.DeclInterface,
		parser.DeclEnum, parser.DeclActor, parser.DeclType, parser.DeclService:
		return true
	}
	return false
}

// ── Swift language-feature content scan ──────────────────────────────────────
//
// Ported from ArchSwiftScope's DesignPatternDetector.FileScan: several
// patterns can only be told apart by the file's raw source (a `lazy var`, a
// DispatchQueue used with `.barrier`, …), not by declaration names alone. This
// scan is Swift-only and reads each file once, bounded, with comments/string
// contents stripped so a doc comment mentioning "lazy var" in prose can't
// read as evidence.

// maxContentScanBytes bounds a single source read; a stray huge/minified file
// is skipped (treated as having none of these signals) rather than read.
const maxContentScanBytes = 2 << 20 // 2 MiB

// swiftFileScan holds the per-file content signals.
type swiftFileScan struct {
	lazyVar           bool // `lazy var ` — Lazy Initialization
	barrierQueue      bool // DispatchQueue + .barrier — Read–Write Lock
	doubleCheckedLock bool // os_unfair_lock + ≥2 "== nil" — Double-Checked Locking
	threadPool        bool // OperationQueue + maxConcurrentOperationCount>1 — Thread Pool
	fluentMethods     int  // lines with "func " and "-> Self" — Fluent Interface
	combineSignal     bool // @Published/ObservableObject/import Combine — Observer
	swinjectImport    bool // import Swinject — Dependency Injection
	multiton          bool // static var/let instances: [...] — Multiton
	prototype         bool // NSCopying conformance or copy()/clone() declaration — Prototype
}

// multitonNeedles are the declaration-style spellings of a static keyed-
// instance dictionary — Multiton's defining trait — covering both explicit
// (`: [Key: V]`) and type-inferred (`= [Key: V]()`) declaration styles.
var multitonNeedles = []string{
	"static var instances: [", "static let instances: [",
	"static var instances = [", "static let instances = [",
	"static var instances=[", "static let instances=[",
}

// scanSwiftFile reads and comment/string-strips path once and returns its
// language-feature content signals. ok is false when the file is unreadable
// or too large to scan.
func scanSwiftFile(path string) (s swiftFileScan, ok bool) {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > maxContentScanBytes {
		return s, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return s, false
	}
	var whole strings.Builder
	for _, raw := range strings.Split(string(data), "\n") {
		if security.IsComment(raw) {
			continue
		}
		line := security.StripStringsAndComments(raw)
		whole.WriteString(line)
		whole.WriteByte('\n')
		if strings.Contains(line, "lazy var ") {
			s.lazyVar = true
		}
		if strings.Contains(line, "func ") && strings.Contains(line, "-> Self") {
			s.fluentMethods++
		}
		for _, needle := range multitonNeedles {
			if strings.Contains(line, needle) {
				s.multiton = true
				break
			}
		}
		if strings.Contains(line, ": NSCopying") || strings.Contains(line, ", NSCopying") ||
			strings.Contains(line, "func copy()") || strings.Contains(line, "func clone()") {
			s.prototype = true
		}
	}
	content := whole.String()
	if strings.Contains(content, "DispatchQueue") && strings.Contains(content, ".barrier") {
		s.barrierQueue = true
	}
	// Swift's components(separatedBy:).count > 2 (the original Swift check)
	// counts N+1 for N occurrences of the separator, so "> 2 components" is
	// "≥ 2 occurrences" — strings.Count reports occurrences directly, hence > 1.
	if strings.Contains(content, "os_unfair_lock") && strings.Count(content, "== nil") > 1 {
		s.doubleCheckedLock = true
	}
	if strings.Contains(content, "OperationQueue") && strings.Contains(content, "maxConcurrentOperationCount") &&
		!strings.Contains(content, "maxConcurrentOperationCount = 1") &&
		!strings.Contains(content, "maxConcurrentOperationCount=1") {
		s.threadPool = true
	}
	if strings.Contains(content, "@Published") || strings.Contains(content, ": ObservableObject") ||
		strings.Contains(content, ", ObservableObject") || strings.Contains(content, "import Combine") {
		s.combineSignal = true
	}
	if strings.Contains(content, "import Swinject") {
		s.swinjectImport = true
	}
	return s, true
}

// ── Marker interface detection ────────────────────────────────────────────
//
// A protocol/interface declared with an empty body exists purely to tag
// conforming types (`protocol Trashable {}`) — the Marker pattern. Universal
// (not Swift-only): any language's protocol/interface with zero members
// qualifies, so this works off the shared sourceCache/typeDeclKeywords rather
// than scanSwiftFile.

// declaresProtocolLike reports whether stripped line l declares a
// protocol/interface named exactly name (identifier-boundary checked).
func declaresProtocolLike(l, name string) bool {
	for _, kw := range []string{"protocol ", "interface "} {
		idx := strings.Index(l, kw+name)
		if idx < 0 {
			continue
		}
		after := idx + len(kw) + len(name)
		if after >= len(l) || !isIdentByte(l[after]) {
			return true
		}
	}
	return false
}

// braceDelta counts the net brace-depth change contributed by s.
func braceDelta(s string) int {
	d := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			d++
		case '}':
			d--
		}
	}
	return d
}

// protocolInterior returns the content strictly between a protocol/
// interface's outermost braces (braces themselves excluded), or ok=false
// when the declaration can't be located or has no brace body.
func protocolInterior(lines []string, name string) (body string, ok bool) {
	for i, l := range lines {
		if !declaresProtocolLike(l, name) {
			continue
		}
		openIdx := strings.IndexByte(l, '{')
		if openIdx < 0 {
			return "", false
		}
		depth := 1
		first := l[openIdx+1:]
		d := braceDelta(first)
		if depth+d <= 0 {
			if closeIdx := strings.LastIndexByte(first, '}'); closeIdx >= 0 {
				first = first[:closeIdx]
			}
			return first, true
		}
		collected := []string{first}
		depth += d
		for j := i + 1; j < len(lines); j++ {
			l2 := lines[j]
			d2 := braceDelta(l2)
			if depth+d2 <= 0 {
				if closeIdx := strings.LastIndexByte(l2, '}'); closeIdx >= 0 {
					collected = append(collected, l2[:closeIdx])
				}
				return strings.Join(collected, "\n"), true
			}
			collected = append(collected, l2)
			depth += d2
		}
		return strings.Join(collected, "\n"), true
	}
	return "", false
}

// isEmptyProtocolBody reports whether body (as returned by protocolInterior)
// has no non-whitespace content — i.e. the protocol declares zero members.
func isEmptyProtocolBody(body string) bool {
	for _, raw := range strings.Split(body, "\n") {
		if strings.TrimSpace(raw) != "" {
			return false
		}
	}
	return true
}

// Analyze scans declarations across files and attributes GoF roles.
func (DesignPatterns) Analyze(files []*parser.ParsedFile) any {
	type agg struct {
		category patternCategory
		count    int
		examples []string
		isIdiom  bool
	}
	found := map[string]*agg{}
	cache := newSourceCache()

	add := func(pattern string, cat patternCategory, example string, idiom bool) {
		a := found[pattern]
		if a == nil {
			a = &agg{category: cat, isIdiom: idiom}
			found[pattern] = a
		}
		a.count++
		if len(a.examples) < 4 {
			a.examples = append(a.examples, example)
		}
	}

	// Factory Method vs. Abstract Factory needs a whole-codebase view: the
	// label depends on whether *any* Factory-suffixed declaration anywhere is
	// a protocol/interface, not just the one being visited right now.
	factoryLabel := ""
	for _, f := range files {
		for _, d := range f.Declarations {
			if !isPatternTypeKind(d.Kind) || !hasRoleSuffix(d.Name, "Factory") {
				continue
			}
			if d.Kind == parser.DeclInterface {
				factoryLabel = "Abstract Factory"
			} else if factoryLabel == "" {
				factoryLabel = "Factory Method"
			}
		}
	}

	for _, f := range files {
		fname := f.FileName()
		isSwift := f.LanguageID == "swift"
		singletonHere := false

		// Feature Flag via a known flagging-SDK import — universal, one hit
		// per file regardless of language.
		if hasFeatureFlagImport(f.Imports) {
			add("Feature Flag", behavioral, exemplar("", fname), false)
		}

		for _, d := range f.Declarations {
			// Singleton: an accessor member named shared/instance/default/…
			if !singletonHere {
				switch d.Kind {
				case parser.DeclVar, parser.DeclConst, parser.DeclFunc:
					if singletonAccessors[strings.ToLower(d.Name)] {
						add("Singleton", creational, exemplar(typeNameForFile(f), fname), false)
						singletonHere = true
					}
				}
			}

			// Swift-only per-declaration language-feature idioms: `actor` is
			// Swift's language-level monitor (compiler-enforced mutual
			// exclusion), and `extension` is Swift's built-in Extension
			// Object — adding behavior to an existing type without
			// subclassing. Both count independently of any suffix match
			// below (an actor named FooFactory is both Monitor Object and
			// Factory Method).
			if isSwift {
				switch d.Kind {
				case parser.DeclActor:
					add("Monitor Object", concurrency, exemplar(d.Name, fname), true)
				case parser.DeclExtension:
					add("Extension", structural, exemplar(d.Name, fname), true)
				}
			}

			// Marker interface: a protocol/interface declared with zero
			// members, used purely to tag conforming types. Universal (works
			// off the shared stripped-line cache, not a Swift-only scan).
			if d.Kind == parser.DeclInterface {
				if lines := cache.lines(f.FilePath); lines != nil {
					if body, ok := protocolInterior(lines, d.Name); ok && isEmptyProtocolBody(body) {
						add("Marker", structural, exemplar(d.Name, fname), false)
					}
				}
			}

			if !isPatternTypeKind(d.Kind) {
				continue
			}

			// Null Object: types prefixed Null<X> — a no-op stand-in for a real <X>.
			if kindAllowed(nullObjectKinds, d.Kind) && hasRolePrefix(d.Name, "Null") {
				add("Null Object", behavioral, exemplar(d.Name, fname), false)
			}

			// Factory Method / Abstract Factory: label decided by the
			// whole-codebase pre-pass above, since it depends on whether any
			// Factory-suffixed declaration anywhere is a protocol.
			if hasRoleSuffix(d.Name, "Factory") {
				add(factoryLabel, creational, exemplar(d.Name, fname), false)
				continue
			}

			for _, rule := range suffixRules {
				if !kindAllowed(rule.kinds, d.Kind) {
					continue
				}
				if hasRoleSuffix(d.Name, rule.suffix) {
					add(rule.pattern, rule.category, exemplar(d.Name, fname), false)
					break
				}
			}
		}

		// Swift-only per-file content scan: lazy var, GCD/OperationQueue
		// concurrency idioms, Combine/Swinject imports, and static
		// keyed-instance dictionaries — signals no declaration-name
		// convention can see. Mirrors the source-file exclusions
		// DesignPatternDetector applies to its own content scan (test dirs).
		if isSwift && strings.HasSuffix(f.FilePath, ".swift") &&
			!strings.Contains(f.FilePath, "/Tests/") && !strings.Contains(f.FilePath, "/Test/") {
			if s, ok := scanSwiftFile(f.FilePath); ok {
				if s.lazyVar {
					add("Lazy Initialization", creational, exemplar("", fname), true)
				}
				if s.barrierQueue {
					add("Read–Write Lock", concurrency, exemplar("", fname), false)
				}
				if s.doubleCheckedLock {
					add("Double-Checked Locking", concurrency, exemplar("", fname), false)
				}
				if s.threadPool {
					add("Thread Pool", concurrency, exemplar("", fname), false)
				}
				if s.fluentMethods >= 2 {
					add("Fluent Interface", structural, exemplar("", fname), false)
				}
				if s.multiton {
					add("Multiton", creational, exemplar("", fname), false)
				}
				if s.swinjectImport {
					add("Dependency Injection", creational, exemplar("", fname), false)
				}
				if s.prototype {
					add("Prototype", creational, exemplar("", fname), false)
				}
				if s.combineSignal {
					// Folded into the same "Observer" match as the NC/suffix
					// signals — Combine's @Published/ObservableObject is
					// Observer's actual mechanism in SwiftUI code, not a
					// distinct pattern.
					add("Observer", behavioral, exemplar("", fname), false)
				}
			}
		}
	}

	var matches []PatternMatch
	for pat, a := range found {
		matches = append(matches, PatternMatch{
			Pattern: pat, Category: a.category, Count: a.count, Examples: a.examples,
			IsIdiom: a.isIdiom,
		})
	}
	sort.SliceStable(matches, func(i, j int) bool {
		ci, cj := patternCategoryRank(matches[i].Category), patternCategoryRank(matches[j].Category)
		if ci != cj {
			return ci < cj
		}
		if matches[i].Count != matches[j].Count {
			return matches[i].Count > matches[j].Count
		}
		return matches[i].Pattern < matches[j].Pattern
	})
	return DesignPatternResult{Matches: matches}
}

// SummaryCards surfaces the number of distinct DELIBERATE patterns detected —
// language idioms (Extension, Monitor Object, Lazy Initialization) are
// excluded so a codebase that simply uses Swift doesn't inflate the count.
func (DesignPatterns) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(DesignPatternResult)
	if !ok || !r.HasDetection() {
		return nil
	}
	n := 0
	for _, m := range r.Matches {
		if !m.IsIdiom {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return []modules.SummaryCard{
		{Num: fmt.Sprintf("%d", n), Label: plural(n, "GoF pattern", "GoF patterns")},
	}
}

// RenderMarkdown renders detected patterns as a markdown table.
func (DesignPatterns) RenderMarkdown(res any) string {
	r, ok := res.(DesignPatternResult)
	if !ok || !r.HasDetection() {
		return ""
	}
	var b strings.Builder
	b.WriteString("| Pattern | Count | Examples |\n")
	b.WriteString("|---------|------:|---------|\n")
	for _, m := range r.Matches {
		ex := strings.Join(m.Examples, ", ")
		if len(ex) > 80 {
			ex = ex[:77] + "…"
		}
		fmt.Fprintf(&b, "| %s | %d | %s |\n", m.Pattern, m.Count, ex)
	}
	b.WriteString("\n")
	return b.String()
}

// RenderHTML renders the patterns grouped by GoF category.
func (DesignPatterns) RenderHTML(res any) string {
	r, ok := res.(DesignPatternResult)
	if !ok {
		return ""
	}
	if !r.HasDetection() {
		return `<p class="as-empty">No Gang-of-Four patterns detected from naming conventions.</p>`
	}
	byCat := map[patternCategory][]PatternMatch{}
	for _, m := range r.Matches {
		byCat[m.Category] = append(byCat[m.Category], m)
	}
	var b strings.Builder
	b.WriteString(`<div class="as-dp">`)
	for _, cat := range patternCategoryOrder {
		ms := byCat[cat]
		if len(ms) == 0 {
			continue
		}
		fmt.Fprintf(&b, `<div class="as-dp__group"><h5 class="as-sub">%s %s</h5><div class="as-dp__items">`, patternCategoryIcon[cat], html.EscapeString(string(cat)))
		for _, m := range ms {
			cls := "as-dp__item"
			suffix := ""
			if m.IsIdiom {
				cls += " as-dp__item--idiom"
				suffix = ` <span class="as-dp__idiom-badge" title="Swift built this into the language — reported for visibility, not counted as a deliberate pattern choice">language idiom</span>`
			}
			fmt.Fprintf(&b, `<div class="%s"><span class="as-dp__name">%s%s</span><span class="as-dp__count">×%d</span>`,
				cls, html.EscapeString(m.Pattern), suffix, m.Count)
			if len(m.Examples) > 0 {
				fmt.Fprintf(&b, `<span class="as-dp__ex">%s</span>`, html.EscapeString(strings.Join(m.Examples, ", ")))
			}
			b.WriteString(`</div>`)
		}
		b.WriteString(`</div></div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// ── helpers ──────────────────────────────────────────────────────────────────

// hasRoleSuffix reports whether name ends in suffix as a whole "word" — i.e.
// "UserFactory" matches "Factory" but "Factorial" does not match "Factory".
func hasRoleSuffix(name, suffix string) bool {
	if len(name) < len(suffix) || !strings.HasSuffix(name, suffix) {
		return false
	}
	if len(name) == len(suffix) {
		return true // the type is literally named "Factory" etc.
	}
	// Char immediately before the suffix must be a boundary (lower→Upper).
	prev := name[len(name)-len(suffix)-1]
	return prev >= 'a' && prev <= 'z'
}

func exemplar(typeName, file string) string {
	if typeName == "" {
		return file
	}
	return fmt.Sprintf("%s (%s)", typeName, file)
}

// typeNameForFile picks a representative type name for a Singleton example.
func typeNameForFile(f *parser.ParsedFile) string {
	for _, d := range f.Declarations {
		if isPatternTypeKind(d.Kind) {
			return d.Name
		}
	}
	return f.FileNameWithoutExt()
}

func patternCategoryRank(c patternCategory) int {
	for i, x := range patternCategoryOrder {
		if x == c {
			return i
		}
	}
	return len(patternCategoryOrder)
}
