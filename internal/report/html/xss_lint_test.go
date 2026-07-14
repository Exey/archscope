package html_test

// xss_lint_test.go scans sections.go and graphs.go for fmt.Fprintf/Sprintf
// calls where a %s verb's argument is not wrapped in esc(). This catches
// accidental interpolation of user-controlled strings into HTML output.
//
// Safe patterns that are explicitly allowed:
//   - esc(...) — the canonical HTML escaper
//   - string literals — compile-time constants, not user data
//   - calls to known-safe functions that return CSS class names, count suffixes,
//     or pre-validated identifiers: dvoScoreClass, plural, gradeColor, passWarn,
//     vscodeHref, shortenPathFront
//   - variables whose names signal pre-built HTML fragments: *HTML, *Cell, *Attr,
//     *Class (these are assembled earlier in the same function using esc() calls)
//   - strings.Join — callers are responsible for ensuring elements are escaped
//   - map index expressions (e.g. k8sKindIcon[kind]) — values are internal emoji constants
//
// To add a new allowance: extend isSafeArg or safeCallees below, then explain why.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// safeCallees are function names whose return value is always safe to interpolate
// as %s without esc() wrapping — CSS identifiers, count suffixes, internal-only strings.
var safeCallees = map[string]bool{
	"dvoScoreClass":    true,
	"plural":           true,
	"gradeColor":       true,
	"passWarn":         true,
	"vscodeHref":       true,
	"shortenPathFront": true,
	// Formatting helpers over numbers/internal enums — never echo scanned-repo text.
	"fmtLOC":            true,
	"fmtNum":            true,
	"fmtTokens":         true,
	"moduleIcon":        true, // switches on a fixed set of internal module IDs
	"kindIcon":          true, // switches on parser.DeclKind, an internal enum
	"sevClass":          true, // switches on security.Severity, an internal enum
	"domainValueSuffix": true,
	// Pre-escape their own dynamic parts internally with esc() and return an
	// already-safe HTML fragment (verified by reading their bodies).
	"trafficProtoTag": true,
	"trafficFileLink": true,
	"declTags":        true,
}

// safeVarSuffixes are identifier-name suffixes that indicate a pre-built HTML
// fragment assembled earlier in the same function with esc() calls inside.
var safeVarSuffixes = []string{"HTML", "Cell", "Attr", "Class"}

func isSafeArg(arg ast.Expr) bool {
	switch e := arg.(type) {
	case *ast.BasicLit:
		return true // compile-time string constant
	case *ast.Ident:
		name := e.Name
		for _, suf := range safeVarSuffixes {
			if strings.HasSuffix(name, suf) {
				return true
			}
		}
		// specific well-known safe locals
		switch name {
		case "anomalyAttr", "headCount", "dotClass", "tierHTML", "hiHTML",
			"portHTML", "metricHTML", "funcCell", "typeCell", "fileCell", "meta":
			return true
		// Colors/CSS classes/labels computed from gradeColor(), fixed literals, or
		// internal constant tables (radarQuadrants, sevLabel, langspec enums) —
		// never derived from scanned-repo content. Audited call site by call site.
		case "col", "lcol", "cls", "label", "openCls", "kindCls", "bg", "fg":
			return true
		// Pre-built HTML fragments assembled earlier in the same function with
		// esc() calls inside, whose names don't match the *HTML/*Cell/*Attr/*Class
		// convention above.
		case "replicaBadge", "badge", "headBadge", "cweLink", "loc", "author",
			"chip", "specIcon":
			return true
		// Internal-only strings: dates formatted from time.Time, icon glyphs,
		// generated element IDs, module/platform names, and fixed literal
		// parameters (e.g. "warn"/"fail" severity variants, "a"/"div" tag names).
		case "dateRange", "icon", "id", "name", "variant", "mark", "tag", "attrs",
			"abbr", "heading", "anchor", "num":
			return true
		}
		return false
	case *ast.CallExpr:
		switch fn := e.Fun.(type) {
		case *ast.Ident:
			if fn.Name == "string" && len(e.Args) == 1 {
				// string(p) where p ranges over []langspec.Platform — an
				// internal enum, never scanned-repo content.
				if id, ok := e.Args[0].(*ast.Ident); ok && id.Name == "p" {
					return true
				}
			}
			return fn.Name == "esc" || safeCallees[fn.Name]
		case *ast.SelectorExpr:
			if pkg, ok := fn.X.(*ast.Ident); ok && pkg.Name == "strings" {
				switch fn.Sel.Name {
				case "Join":
					// callers build elements with esc() themselves
					return true
				case "ToUpper", "ToLower", "TrimSpace":
					// pure transforms — safe iff their own argument is safe
					for _, a := range e.Args {
						if !isSafeArg(a) {
							return false
						}
					}
					return true
				}
				return false
			}
			// Icon() methods return a fixed emoji glyph per internal enum/type,
			// by convention across this codebase (e.g. techdetect.Model.Icon()).
			if fn.Sel.Name == "Icon" {
				return true
			}
		}
		return false
	case *ast.IndexExpr:
		return true // map lookups like k8sKindIcon[kind] — internal emoji maps
	case *ast.SelectorExpr:
		// Field names that are always internal/computed regardless of receiver:
		// Icon (emoji constant), CWE (rule metadata ID assigned in Go source).
		if e.Sel.Name == "Icon" || e.Sel.Name == "CWE" {
			return true
		}
		// Qualified identifiers like ms.label (month abbreviation from time.Format).
		// Allow only fields whose struct name suggests internal/computed data.
		if recv, ok := e.X.(*ast.Ident); ok {
			switch recv.Name {
			case "ms": // monthSpec.label — "Jan", "Feb", etc.
				return true
			case "c": // column struct literal — icon and label are hardcoded strings
				if e.Sel.Name == "icon" || e.Sel.Name == "label" {
					return true
				}
			case "q", "quad": // radarQuadrants entries — color is a hex literal
				if e.Sel.Name == "color" {
					return true
				}
			case "lv": // devLevel entries (devLevels table) — color is a hex literal
				if e.Sel.Name == "color" {
					return true
				}
			case "lm": // langOrder entries — cls/label are hardcoded per-language
				if e.Sel.Name == "cls" || e.Sel.Name == "label" {
					return true
				}
			case "e": // local `entry{id string; ...}` — id is a CWE number string
				if e.Sel.Name == "id" {
					return true
				}
			}
		}
		// r.Patterns[0].Name — arch.Pattern.Name is one of a fixed set of
		// architecture-pattern labels ("MVC", "Clean Architecture", ...) assigned
		// in Go source, never derived from scanned repo content.
		if idx, ok := e.X.(*ast.IndexExpr); ok && e.Sel.Name == "Name" {
			if sel, ok := idx.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "Patterns" {
				return true
			}
		}
		return false
	case *ast.BinaryExpr:
		// String concatenations that build CSS class names from controlled parts.
		// Allow only if both sides are safe (literals or known-safe calls).
		return isSafeArg(e.X) && isSafeArg(e.Y)
	}
	return false
}

// verbArgIndices returns the positional data-arg indices (0-based into the slice
// of arguments after the format string) that correspond to %s verbs in the format.
// Other verbs (%d, %v, etc.) still consume an argument slot without being flagged.
func verbArgIndices(format string) []int {
	var sIdx []int
	argN := 0
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		i++
		if i >= len(format) || format[i] == '%' {
			continue
		}
		// skip flags
		for i < len(format) && strings.ContainsRune("-+ #0", rune(format[i])) {
			i++
		}
		// skip width digits
		for i < len(format) && format[i] >= '0' && format[i] <= '9' {
			i++
		}
		// skip precision
		if i < len(format) && format[i] == '.' {
			i++
			for i < len(format) && format[i] >= '0' && format[i] <= '9' {
				i++
			}
		}
		if i < len(format) {
			if format[i] == 's' {
				sIdx = append(sIdx, argN)
			}
			argN++ // every verb consumes one argument slot
		}
	}
	return sIdx
}

func stripQuotes(lit string) string {
	if len(lit) < 2 {
		return lit
	}
	if lit[0] == '`' && lit[len(lit)-1] == '`' {
		return lit[1 : len(lit)-1]
	}
	if (lit[0] == '"' || lit[0] == '\'') && lit[len(lit)-1] == lit[0] {
		s := lit[1 : len(lit)-1]
		// unescape \" sequences (good enough for our purposes)
		return strings.ReplaceAll(s, `\"`, `"`)
	}
	return lit
}

func TestNoUnescapedHTMLInterpolation(t *testing.T) {
	files := []string{"sections.go", "graphs.go"}

	for _, fname := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, fname, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", fname, err)
		}

		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "fmt" {
				return true
			}

			var fmtArgIdx int
			switch sel.Sel.Name {
			case "Fprintf":
				fmtArgIdx = 1 // arg 0 is the writer
			case "Sprintf":
				fmtArgIdx = 0
			default:
				return true
			}

			if fmtArgIdx >= len(call.Args) {
				return true
			}
			lit, ok := call.Args[fmtArgIdx].(*ast.BasicLit)
			if !ok {
				return true // dynamic format string — skip
			}

			fmtStr := stripQuotes(lit.Value)
			sIndices := verbArgIndices(fmtStr)
			if len(sIndices) == 0 {
				return true
			}

			dataStart := fmtArgIdx + 1
			pos := fset.Position(call.Pos())

			for _, si := range sIndices {
				argIdx := dataStart + si
				if argIdx >= len(call.Args) {
					t.Errorf("%s:%d: too few arguments for %%s at verb position %d",
						fname, pos.Line, si)
					continue
				}
				arg := call.Args[argIdx]
				if !isSafeArg(arg) {
					t.Errorf("%s:%d: %%s argument %d not wrapped in esc() — add esc() or extend isSafeArg if this is a known-safe HTML fragment",
						fname, pos.Line, si+1)
				}
			}
			return true
		})
	}
}
