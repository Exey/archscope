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

// suffixRule maps a declaration-name suffix to a GoF pattern.
type suffixRule struct {
	suffix   string
	pattern  string
	category patternCategory
}

// suffixRules are checked against every type-like declaration name. Order does
// not matter; a name is attributed to the first rule it satisfies.
var suffixRules = []suffixRule{
	{"Factory", "Factory Method", creational},
	{"Builder", "Builder", creational},
	{"Prototype", "Prototype", creational},
	{"Adapter", "Adapter", structural},
	{"Bridge", "Bridge", structural},
	{"Composite", "Composite", structural},
	{"Decorator", "Decorator", structural},
	{"Facade", "Facade", structural},
	{"Flyweight", "Flyweight", structural},
	{"Proxy", "Proxy", structural},
	{"Strategy", "Strategy", behavioral},
	{"Observer", "Observer", behavioral},
	{"Listener", "Observer", behavioral},
	{"Subscriber", "Observer", behavioral},
	{"Publisher", "Observer", behavioral},
	{"Command", "Command", behavioral},
	{"Visitor", "Visitor", behavioral},
	{"Mediator", "Mediator", behavioral},
	{"Memento", "Memento", behavioral},
	{"Iterator", "Iterator", behavioral},
	{"Interpreter", "Interpreter", behavioral},
	{"Handler", "Chain of Responsibility", behavioral},
	// Feature Flag / Toggle — a runtime behavior switch, closely related to
	// Strategy's "select behavior at runtime" intent. Not in the GoF catalog,
	// but a real, widespread practice worth surfacing the same way.
	{"FeatureFlag", "Feature Flag", behavioral},
	{"FeatureToggle", "Feature Flag", behavioral},
	{"FeatureGate", "Feature Flag", behavioral},
	// Dependency Injection by explicit naming convention — the Swinject-import
	// signal below covers the case where no such type is named.
	{"ServiceLocator", "Dependency Injection", creational},
	{"DIContainer", "Dependency Injection", creational},
	{"Injector", "Dependency Injection", creational},
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

// Analyze scans declarations across files and attributes GoF roles.
func (DesignPatterns) Analyze(files []*parser.ParsedFile) any {
	type agg struct {
		category patternCategory
		count    int
		examples []string
		isIdiom  bool
	}
	found := map[string]*agg{}

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

			if !isPatternTypeKind(d.Kind) {
				continue
			}
			for _, rule := range suffixRules {
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
