package langprofile

import (
	"regexp"
	"strings"
	"unicode"
)

// Syntax is how a language writes comments, strings and documentation — what
// every card that masks or reads source needs to know.
type Syntax struct {
	LineComment  []string  // "//", "#"
	BlockComment [2]string // "/*", "*/" ("" = none)
	DocLine      string    // doc-comment line prefix: "///", "//" (Go), "#"
	DocBlock     string    // doc-comment block opener: "/**", `"""`
	Quotes       string    // plain string delimiters: `"'` + backtick where it is a string
	RawString    string    // raw-string opener, "`" (Go) or `r"` (Python/Rust)
	TripleQuote  bool      // """ strings span lines (Python, Kotlin, Swift, Java text blocks)
	Interpolates bool      // ${…} / f"…{x}" interpolation exists
	Semicolons   bool      // statements end with ";" (a missing one is not an error)
}

// Naming is the case convention each kind of name follows, and how a name becomes public.
type Naming struct {
	Const, Func, Type string // "UPPER_SNAKE" | "camelCase" | "PascalCase" | "snake_case" | "mixed"
	Export            ExportRule
	ExportWords       []string // keywords on the declaration line that make it public (ExportKeyword)
	PrivateWords      []string // keywords that make it private (ExportDefault)
}

// ExportRule says how a language decides that a declaration is public.
type ExportRule string

const (
	ExportCapital  ExportRule = "capital"    // Go: an upper-case first letter
	ExportNoUnder  ExportRule = "no-prefix_" // Python, Dart: a leading underscore is private
	ExportKeyword  ExportRule = "keyword"    // Rust pub, TS export: public only when marked
	ExportDefault  ExportRule = "default"    // Java/Kotlin/Swift/C#: public unless marked private
	ExportEveryone ExportRule = "all"        // no visibility concept (C macros, Ruby constants)
)

// FuncConventions names functions that are not subjects of unit tests or
// documentation, and how tests of the language are named.
type FuncConventions struct {
	Ignored []string       // exact names: "main", "init"
	Pattern *regexp.Regexp // names matching it are ignored too: dunder methods, constructors
	Test    *regexp.Regexp // a test function's name
}

// Limits are the thresholds the Code Structure card reports against. The
// defaults are the card's own; a language may override one.
type Limits struct {
	MaxParams        int // 10 or more is a smell → 9
	MaxNestDepth     int
	MaxCyclomatic    int
	MaxReturns       int
	MaxBranches      int
	MaxLocals        int
	MaxModuleLines   int
	BigFunctionLines int // lines before a function is listed as long
	BigTypeLines     int
}

// DefaultLimits are the card's thresholds.
var DefaultLimits = Limits{MaxParams: 9, MaxNestDepth: 5, MaxCyclomatic: 10, MaxReturns: 6, MaxBranches: 12, MaxLocals: 15, MaxModuleLines: 1000, BigFunctionLines: 25, BigTypeLines: 300}

// ForExt returns the profile owning a lower-case extension with its dot (".go"), or nil.
func ForExt(ext string) *Profile {
	for _, pr := range profiles {
		for _, x := range pr.Exts {
			if x == ext {
				return pr
			}
		}
	}
	return nil
}

// IsCommentLine reports whether a trimmed line is only a comment in the language of ext.
func IsCommentLine(ext, trimmed string) bool {
	pr := ForExt(ext)
	if pr == nil {
		return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#")
	}
	for _, c := range pr.Syntax.LineComment {
		if strings.HasPrefix(trimmed, c) {
			return true
		}
	}
	if o := pr.Syntax.BlockComment[0]; o != "" && (strings.HasPrefix(trimmed, o) || strings.HasPrefix(trimmed, "*")) {
		return true
	}
	return false
}

// IgnoredFunc reports a function name no card should count as a subject (entry
// points, constructors, dunder methods) or one that is too short to say anything.
func IgnoredFunc(path, name string) bool {
	if len(name) <= 2 {
		return true
	}
	pr := For(path)
	if pr == nil {
		return name == "main" || name == "init"
	}
	for _, n := range pr.Funcs.Ignored {
		if n == name {
			return true
		}
	}
	return pr.Funcs.Pattern != nil && pr.Funcs.Pattern.MatchString(name)
}

// IsTestFunc reports whether name is a test function by the language's convention.
func IsTestFunc(path, name string) bool {
	pr := For(path)
	return pr != nil && pr.Funcs.Test != nil && pr.Funcs.Test.MatchString(name)
}

// Public reports whether a declaration is public, from its name and its source line.
func (n Naming) Public(name, line string) bool {
	if name == "" {
		return false
	}
	tokens := map[string]bool{}
	for _, t := range strings.FieldsFunc(line, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '.' }) {
		tokens[t] = true
	}
	hasWord := func(words []string) bool {
		for _, w := range words {
			if tokens[w] {
				return true
			}
		}
		return false
	}
	switch n.Export {
	case ExportCapital:
		return unicode.IsUpper([]rune(name)[0])
	case ExportNoUnder:
		return !strings.HasPrefix(name, "_")
	case ExportKeyword:
		return hasWord(n.ExportWords)
	case ExportDefault:
		return !hasWord(n.PrivateWords)
	}
	return true
}

func re(s string) *regexp.Regexp { return regexp.MustCompile(s) }

// syntaxByID is the data: filled into the profiles at start-up so the table in
// langprofile.go stays about files, and this one about the language itself.
var syntaxByID = map[string]struct {
	Syntax Syntax
	Naming Naming
	Funcs  FuncConventions
}{
	"go": {
		Syntax{
			LineComment:  []string{"//"},
			BlockComment: [2]string{"/*", "*/"},
			DocLine:      "//",
			Quotes:       "\"'`",
			RawString:    "`",
		},
		Naming{
			Const:  "mixed",
			Func:   "camelCase",
			Type:   "PascalCase",
			Export: ExportCapital,
		},
		FuncConventions{
			Ignored: []string{"main", "init", "TestMain"},
			Test:    re(`^(?:Test|Benchmark|Fuzz|Example)[A-Z_0-9]?`),
		},
	},
	"python": {
		Syntax{
			LineComment:  []string{"#"},
			DocBlock:     `"""`,
			Quotes:       "\"'",
			RawString:    `r"`,
			TripleQuote:  true,
			Interpolates: true,
		},
		Naming{
			Const:  "UPPER_SNAKE",
			Func:   "snake_case",
			Type:   "PascalCase",
			Export: ExportNoUnder,
		},
		FuncConventions{
			Ignored: []string{"main"},
			Pattern: re(`^__\w+__$`),
			Test:    re(`^test_?\w*`),
		},
	},
	"typescript": {
		Syntax{
			LineComment:  []string{"//"},
			BlockComment: [2]string{"/*", "*/"},
			DocBlock:     "/**",
			Quotes:       "\"'`",
			Interpolates: true,
			Semicolons:   true,
		},
		Naming{
			Const:       "mixed",
			Func:        "camelCase",
			Type:        "PascalCase",
			Export:      ExportKeyword,
			ExportWords: []string{"export"},
		},
		FuncConventions{
			Ignored: []string{"constructor", "main"},
			Test:    re(`^(?:test|it|describe)\b`),
		},
	},
	"javascript": {
		Syntax{
			LineComment:  []string{"//"},
			BlockComment: [2]string{"/*", "*/"},
			DocBlock:     "/**",
			Quotes:       "\"'`",
			Interpolates: true,
			Semicolons:   true,
		},
		Naming{
			Const:       "mixed",
			Func:        "camelCase",
			Type:        "PascalCase",
			Export:      ExportKeyword,
			ExportWords: []string{"export", "module.exports"},
		},
		FuncConventions{
			Ignored: []string{"constructor", "main"},
			Test:    re(`^(?:test|it|describe)\b`),
		},
	},
	"java": {
		Syntax{
			LineComment:  []string{"//"},
			BlockComment: [2]string{"/*", "*/"},
			DocBlock:     "/**",
			Quotes:       "\"'",
			TripleQuote:  true,
			Semicolons:   true,
		},
		Naming{
			Const:        "UPPER_SNAKE",
			Func:         "camelCase",
			Type:         "PascalCase",
			Export:       ExportDefault,
			PrivateWords: []string{"private"},
		},
		FuncConventions{
			Ignored: []string{"main"},
			Test:    re(`^test[A-Z_]?\w*`),
		},
	},
	"kotlin": {
		Syntax{
			LineComment:  []string{"//"},
			BlockComment: [2]string{"/*", "*/"},
			DocBlock:     "/**",
			Quotes:       "\"'",
			TripleQuote:  true,
			Interpolates: true,
		},
		Naming{
			Const:        "UPPER_SNAKE",
			Func:         "camelCase",
			Type:         "PascalCase",
			Export:       ExportDefault,
			PrivateWords: []string{"private", "internal"},
		},
		FuncConventions{
			Ignored: []string{"main", "<init>"},
			Test:    re(`^test\w*`),
		},
	},
	"swift": {
		Syntax{
			LineComment:  []string{"//"},
			BlockComment: [2]string{"/*", "*/"},
			DocLine:      "///",
			DocBlock:     "/**",
			Quotes:       "\"",
			TripleQuote:  true,
			Interpolates: true,
		},
		Naming{
			Const:        "camelCase",
			Func:         "camelCase",
			Type:         "PascalCase",
			Export:       ExportDefault,
			PrivateWords: []string{"private", "fileprivate"},
		},
		FuncConventions{
			Ignored: []string{"main", "init", "deinit"},
			Test:    re(`^test[A-Z_]?\w*`),
		},
	},
	"rust": {
		Syntax{
			LineComment:  []string{"//"},
			BlockComment: [2]string{"/*", "*/"},
			DocLine:      "///",
			DocBlock:     "/**",
			Quotes:       "\"",
			RawString:    `r#"`,
			Semicolons:   true,
		},
		Naming{
			Const:       "UPPER_SNAKE",
			Func:        "snake_case",
			Type:        "PascalCase",
			Export:      ExportKeyword,
			ExportWords: []string{"pub"},
		},
		FuncConventions{
			Ignored: []string{"main"},
			Test:    re(`^test_?\w*`),
		},
	},
	"csharp": {
		Syntax{
			LineComment:  []string{"//"},
			BlockComment: [2]string{"/*", "*/"},
			DocLine:      "///",
			Quotes:       "\"'",
			TripleQuote:  true,
			Interpolates: true,
			Semicolons:   true,
		},
		Naming{
			Const:       "PascalCase",
			Func:        "PascalCase",
			Type:        "PascalCase",
			Export:      ExportKeyword,
			ExportWords: []string{"public"},
		},
		FuncConventions{
			Ignored: []string{"Main"},
			Test:    re(`^Test\w*|\w+Test$`),
		},
	},
	"dart": {
		Syntax{
			LineComment:  []string{"//"},
			BlockComment: [2]string{"/*", "*/"},
			DocLine:      "///",
			Quotes:       "\"'",
			TripleQuote:  true,
			Interpolates: true,
			Semicolons:   true,
		},
		Naming{
			Const:  "camelCase",
			Func:   "camelCase",
			Type:   "PascalCase",
			Export: ExportNoUnder,
		},
		FuncConventions{
			Ignored: []string{"main"},
			Test:    re(`^test\w*`),
		},
	},
	"ruby": {
		Syntax{
			LineComment:  []string{"#"},
			BlockComment: [2]string{"=begin", "=end"},
			Quotes:       "\"'",
			Interpolates: true,
		},
		Naming{
			Const:  "UPPER_SNAKE",
			Func:   "snake_case",
			Type:   "PascalCase",
			Export: ExportEveryone,
		},
		FuncConventions{
			Ignored: []string{"initialize"},
			Test:    re(`^test_\w*`),
		},
	},
	"php": {
		Syntax{
			LineComment:  []string{"//", "#"},
			BlockComment: [2]string{"/*", "*/"},
			DocBlock:     "/**",
			Quotes:       "\"'",
			Interpolates: true,
			Semicolons:   true,
		},
		Naming{
			Const:        "UPPER_SNAKE",
			Func:         "camelCase",
			Type:         "PascalCase",
			Export:       ExportDefault,
			PrivateWords: []string{"private", "protected"},
		},
		FuncConventions{
			Ignored: []string{"__construct", "__destruct"},
			Pattern: re(`^__\w+$`),
			Test:    re(`^test[A-Z_]?\w*`),
		},
	},
	"c/c++": {
		Syntax{
			LineComment:  []string{"//"},
			BlockComment: [2]string{"/*", "*/"},
			DocBlock:     "/**",
			Quotes:       "\"'",
			Semicolons:   true,
		},
		Naming{
			Const:  "UPPER_SNAKE",
			Func:   "snake_case",
			Type:   "PascalCase",
			Export: ExportEveryone,
		},
		FuncConventions{
			Ignored: []string{"main"},
			Test:    re(`^TEST\w*|^test_\w*`),
		},
	},
}

func init() {
	for _, p := range profiles {
		d := syntaxByID[p.ID]
		p.Syntax, p.Naming, p.Funcs = d.Syntax, d.Naming, d.Funcs
		p.Limits = DefaultLimits
		p.Values = valuesByID[p.ID]
	}
}
