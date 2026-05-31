// Package designpattern is a universal Gang-of-Four design-pattern detector,
// generalized from ArchSwiftScope's DesignPatternDetector. It works purely from
// declaration-name conventions (a type whose name ends in "Factory", "Builder",
// "Decorator", … is almost always playing that GoF role) plus a few accessor
// signals (a "shared"/"instance" member implies a Singleton). Name conventions
// are shared across Swift, Kotlin, TS, Java, C#, Python and Go, so the detector
// is language-agnostic and conservative (low false-positive) by construction.
package designpattern

import (
	"fmt"
	"html"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
)

func init() { modules.Default.Register(Module{}) }

// Module is the universal design-pattern detector.
type Module struct{}

func (Module) ID() string                       { return "designpattern" }
func (Module) Title() string                    { return "Design Patterns" }
func (Module) AppliesTo(languageID string) bool { return true } // universal

// category groups GoF patterns.
type category string

const (
	creational category = "Creational"
	structural category = "Structural"
	behavioral category = "Behavioral"
)

// categoryOrder fixes the display order.
var categoryOrder = []category{creational, structural, behavioral}

// Match is one detected pattern with its evidence.
type Match struct {
	Pattern  string
	Category category
	Count    int
	Examples []string // "TypeName (file.ext)"
}

// Result is the module output.
type Result struct {
	Matches []Match
}

// HasDetection reports whether any pattern was found.
func (r Result) HasDetection() bool { return len(r.Matches) > 0 }

// suffixRule maps a declaration-name suffix to a GoF pattern.
type suffixRule struct {
	suffix   string
	pattern  string
	category category
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
}

// singletonAccessors are member names that strongly imply a Singleton.
var singletonAccessors = map[string]bool{
	"shared": true, "sharedinstance": true, "instance": true,
	"default": true, "getinstance": true, "current": true,
}

// typeKinds are the declaration kinds that can carry a pattern name.
func isTypeKind(k parser.DeclKind) bool {
	switch k {
	case parser.DeclStruct, parser.DeclClass, parser.DeclInterface,
		parser.DeclEnum, parser.DeclActor, parser.DeclType, parser.DeclService:
		return true
	}
	return false
}

// Analyze scans declarations across files and attributes GoF roles.
func (Module) Analyze(files []*parser.ParsedFile) any {
	type agg struct {
		category category
		count    int
		examples []string
	}
	found := map[string]*agg{}

	add := func(pattern string, cat category, example string) {
		a := found[pattern]
		if a == nil {
			a = &agg{category: cat}
			found[pattern] = a
		}
		a.count++
		if len(a.examples) < 4 {
			a.examples = append(a.examples, example)
		}
	}

	for _, f := range files {
		fname := f.FileName()
		singletonHere := false
		for _, d := range f.Declarations {
			// Singleton: an accessor member named shared/instance/default/…
			if !singletonHere {
				switch d.Kind {
				case parser.DeclVar, parser.DeclConst, parser.DeclFunc:
					if singletonAccessors[strings.ToLower(d.Name)] {
						add("Singleton", creational, exemplar(typeNameForFile(f), fname))
						singletonHere = true
					}
				}
			}
			if !isTypeKind(d.Kind) {
				continue
			}
			for _, rule := range suffixRules {
				if hasRoleSuffix(d.Name, rule.suffix) {
					add(rule.pattern, rule.category, exemplar(d.Name, fname))
					break
				}
			}
		}
	}

	var matches []Match
	for pat, a := range found {
		matches = append(matches, Match{
			Pattern: pat, Category: a.category, Count: a.count, Examples: a.examples,
		})
	}
	sort.SliceStable(matches, func(i, j int) bool {
		ci, cj := categoryRank(matches[i].Category), categoryRank(matches[j].Category)
		if ci != cj {
			return ci < cj
		}
		if matches[i].Count != matches[j].Count {
			return matches[i].Count > matches[j].Count
		}
		return matches[i].Pattern < matches[j].Pattern
	})
	return Result{Matches: matches}
}

// SummaryCards surfaces the number of distinct patterns detected.
func (Module) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(Result)
	if !ok || !r.HasDetection() {
		return nil
	}
	return []modules.SummaryCard{
		{Num: fmt.Sprintf("%d", len(r.Matches)), Label: plural(len(r.Matches), "GoF pattern", "GoF patterns")},
	}
}

// RenderHTML renders the patterns grouped by GoF category.
func (Module) RenderHTML(res any) string {
	r, ok := res.(Result)
	if !ok {
		return ""
	}
	if !r.HasDetection() {
		return `<p class="as-empty">No Gang-of-Four patterns detected from naming conventions.</p>`
	}
	byCat := map[category][]Match{}
	for _, m := range r.Matches {
		byCat[m.Category] = append(byCat[m.Category], m)
	}
	var b strings.Builder
	b.WriteString(`<div class="as-dp">`)
	for _, cat := range categoryOrder {
		ms := byCat[cat]
		if len(ms) == 0 {
			continue
		}
		fmt.Fprintf(&b, `<div class="as-dp__group"><h5 class="as-sub">%s</h5><div class="as-dp__items">`, html.EscapeString(string(cat)))
		for _, m := range ms {
			fmt.Fprintf(&b, `<div class="as-dp__item"><span class="as-dp__name">%s</span><span class="as-dp__count">×%d</span>`,
				html.EscapeString(m.Pattern), m.Count)
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
		if isTypeKind(d.Kind) {
			return d.Name
		}
	}
	return f.FileNameWithoutExt()
}

func categoryRank(c category) int {
	for i, x := range categoryOrder {
		if x == c {
			return i
		}
	}
	return len(categoryOrder)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
