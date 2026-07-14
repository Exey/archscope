// langrichness.go is a simple "how much of the language did this codebase
// actually use" read: each language's fixed, public reserved-keyword list is
// checked against the platform's scanned (comment/string-stripped) source,
// and the score is the percentage of that list found at least once anywhere.
// It is deliberately a simple calculation, not a sophisticated one — a
// codebase that only ever writes if/for/return/func reads as less "rich"
// than one that also reaches for select/defer/goto.
package constructs

import (
	"fmt"
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/exey/archscope/internal/modules"
	"github.com/exey/archscope/internal/parser"
)

func init() { modules.Default.Register(LanguageRichness{}) }

// languageKeywords is each language's fixed reserved-word list. ts covers
// both TypeScript and JavaScript — ArchScope parses them under one
// LanguageSpec ("ts", since one spec owns the whole TS+JS platform bucket —
// see lang/typescript.go), and the TypeScript set below is already a
// superset of JavaScript's.
var languageKeywords = map[string][]string{
	"go": {
		"break", "case", "chan", "const", "continue", "default", "defer",
		"else", "fallthrough", "for", "func", "go", "goto", "if", "import",
		"interface", "map", "package", "range", "return", "select", "struct",
		"switch", "type", "var",
	},
	"python": {
		"False", "None", "True", "and", "as", "assert", "async", "await",
		"break", "class", "continue", "def", "del", "elif", "else", "except",
		"finally", "for", "from", "global", "if", "import", "in", "is",
		"lambda", "match", "case", "nonlocal", "not", "or", "pass", "raise",
		"return", "try", "while", "with", "yield",
	},
	"java": {
		"abstract", "assert", "boolean", "break", "byte", "case", "catch",
		"char", "class", "const", "continue", "default", "do", "double",
		"else", "enum", "extends", "false", "final", "finally", "float",
		"for", "goto", "if", "implements", "import", "instanceof", "int",
		"interface", "long", "native", "new", "null", "package", "private",
		"protected", "public", "return", "short", "static", "strictfp",
		"super", "switch", "synchronized", "this", "throw", "throws",
		"transient", "true", "try", "void", "volatile", "while", "_", "var",
		"yield", "record", "sealed", "permits",
	},
	"rust": {
		"as", "async", "await", "break", "const", "continue", "crate", "dyn",
		"else", "enum", "extern", "false", "fn", "for", "if", "impl", "in",
		"let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
		"self", "Self", "static", "struct", "super", "trait", "true", "type",
		"union", "unsafe", "use", "where", "while",
	},
	"ts": {
		"any", "as", "asserts", "await", "bigint", "boolean", "break",
		"case", "catch", "class", "const", "constructor", "continue",
		"debugger", "declare", "default", "delete", "do", "else", "enum",
		"export", "extends", "false", "finally", "for", "from", "function",
		"get", "if", "implements", "import", "in", "infer", "instanceof",
		"interface", "is", "keyof", "let", "module", "namespace", "never",
		"new", "null", "number", "object", "of", "package", "private",
		"protected", "public", "readonly", "require", "return", "set",
		"static", "string", "super", "switch", "symbol", "this", "throw",
		"true", "try", "type", "typeof", "undefined", "unknown", "var",
		"void", "while", "with", "yield",
	},
	"kotlin": {
		"as", "as?", "break", "class", "continue", "do", "else", "false",
		"for", "fun", "if", "in", "!in", "interface", "is", "!is", "null",
		"object", "package", "return", "super", "this", "throw", "true",
		"try", "typealias", "val", "var", "when", "while", "by", "catch",
		"constructor", "delegate", "dynamic", "field", "file", "finally",
		"get", "import", "init", "param", "property", "receiver", "set",
		"setparam", "where", "actual", "abstract", "annotation", "companion",
		"const", "crossinline", "data", "enum", "expect", "external",
		"final", "infix", "inline", "inner", "internal", "lateinit",
		"noinline", "open", "operator", "out", "override", "private",
		"protected", "public", "reified", "sealed", "suspend", "tailrec",
		"vararg",
	},
	"swift": {
		"associatedtype", "class", "deinit", "enum", "extension",
		"fileprivate", "func", "import", "init", "inout", "internal", "let",
		"open", "operator", "private", "protocol", "public", "rethrows",
		"static", "struct", "subscript", "typealias", "var", "break", "case",
		"continue", "default", "defer", "do", "else", "fallthrough", "for",
		"guard", "if", "in", "repeat", "return", "switch", "where", "while",
		"as", "Any", "catch", "false", "is", "nil", "super", "self", "Self",
		"throw", "throws", "true", "try", "_", "associativity",
		"convenience", "dynamic", "didSet", "final", "get", "infix",
		"indirect", "lazy", "left", "mutating", "none", "nonmutating",
		"optional", "override", "postfix", "precedence", "prefix",
		"Protocol", "required", "right", "set", "Type", "unowned", "weak",
		"willSet",
	},
}

// languageLabels is the display name per languageID.
var languageLabels = map[string]string{
	"go": "Go", "python": "Python", "java": "Java", "rust": "Rust",
	"ts": "TypeScript/JavaScript", "kotlin": "Kotlin", "swift": "Swift",
}

// languageKeywordRegex is languageKeywords, precompiled once. Most keywords
// are plain identifiers (word-boundary match, so "class" in "className"
// doesn't count); a few tokens aren't valid identifiers at all (Kotlin's
// "as?", "!in", "!is") and are matched as plain literal substrings instead.
var languageKeywordRegex = buildLanguageKeywordRegex()

func buildLanguageKeywordRegex() map[string]map[string]*regexp.Regexp {
	out := make(map[string]map[string]*regexp.Regexp, len(languageKeywords))
	for lang, kws := range languageKeywords {
		m := make(map[string]*regexp.Regexp, len(kws))
		for _, kw := range kws {
			pattern := regexp.QuoteMeta(kw)
			if isIdentifierToken(kw) {
				pattern = `\b` + pattern + `\b`
			}
			m[kw] = regexp.MustCompile(pattern)
		}
		out[lang] = m
	}
	return out
}

func isIdentifierToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// LanguageRichness is the universal keyword-coverage detector.
type LanguageRichness struct{}

func (LanguageRichness) ID() string    { return "langrichness" }
func (LanguageRichness) Title() string { return "Language Richness" }

// AppliesTo runs only for languages with a known keyword list.
func (LanguageRichness) AppliesTo(languageID string) bool {
	_, ok := languageKeywords[languageID]
	return ok
}

// LangRichness is one language's keyword-coverage reading.
type LangRichness struct {
	Lang    string // languageID, e.g. "go"
	Label   string // display label, e.g. "Go"
	Found   int
	Total   int
	Percent int
}

// LanguageRichnessReport is the module output — one entry per known language
// present on the platform (almost always exactly one).
type LanguageRichnessReport struct {
	Entries []LangRichness
}

func (r LanguageRichnessReport) HasData() bool { return len(r.Entries) > 0 }

// Analyze scans each file's comment/string-stripped source for whichever of
// its language's reserved keywords appear anywhere.
func (LanguageRichness) Analyze(files []*parser.ParsedFile) any {
	cache := newSourceCache()
	byLang := map[string][]*parser.ParsedFile{}
	for _, f := range files {
		if _, ok := languageKeywords[f.LanguageID]; ok {
			byLang[f.LanguageID] = append(byLang[f.LanguageID], f)
		}
	}

	var entries []LangRichness
	for lang, fs := range byLang {
		kws := languageKeywords[lang]
		regexes := languageKeywordRegex[lang]
		found := map[string]bool{}
		for _, f := range fs {
			if len(found) == len(kws) {
				break // every keyword already seen — no need to keep scanning
			}
			lines := cache.lines(f.FilePath)
			if lines == nil {
				continue
			}
			text := strings.Join(lines, "\n")
			for _, kw := range kws {
				if found[kw] {
					continue
				}
				if regexes[kw].MatchString(text) {
					found[kw] = true
				}
			}
		}
		pct := 0
		if len(kws) > 0 {
			pct = len(found) * 100 / len(kws)
		}
		entries = append(entries, LangRichness{
			Lang: lang, Label: languageLabels[lang],
			Found: len(found), Total: len(kws), Percent: pct,
		})
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Label < entries[j].Label })
	return LanguageRichnessReport{Entries: entries}
}

// SummaryCards surfaces each language's richness percentage.
func (LanguageRichness) SummaryCards(res any) []modules.SummaryCard {
	r, ok := res.(LanguageRichnessReport)
	if !ok || !r.HasData() {
		return nil
	}
	cards := make([]modules.SummaryCard, 0, len(r.Entries))
	for _, e := range r.Entries {
		cards = append(cards, modules.SummaryCard{Num: strconv.Itoa(e.Percent) + "%", Label: e.Label + " richness"})
	}
	return cards
}

// RenderMarkdown renders each language's richness as a line.
func (LanguageRichness) RenderMarkdown(res any) string {
	r, ok := res.(LanguageRichnessReport)
	if !ok || !r.HasData() {
		return ""
	}
	var b strings.Builder
	for _, e := range r.Entries {
		fmt.Fprintf(&b, "**%s:** %d%% (%d/%d keywords used)\n\n", e.Label, e.Percent, e.Found, e.Total)
	}
	return b.String()
}

// RenderHTML renders one labelled bar per language.
func (LanguageRichness) RenderHTML(res any) string {
	r, ok := res.(LanguageRichnessReport)
	if !ok || !r.HasData() {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="as-lr">`)
	for _, e := range r.Entries {
		col := healthColor(e.Percent)
		fmt.Fprintf(&b, `<div class="as-lr__row"><div class="as-lr__label">%s <span class="as-lr__frac">(%d/%d keywords)</span></div>`+
			`<div class="as-lr__bar"><div class="as-lr__fill" style="width:%d%%;background:%s"></div></div><span class="as-lr__pct">%d%%</span></div>`,
			html.EscapeString(e.Label), e.Found, e.Total, e.Percent, col, e.Percent)
	}
	b.WriteString(`</div>`)
	return b.String()
}
