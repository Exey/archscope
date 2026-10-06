// clones.go is the cross-file half of Code Structure's 👯 Duplicate code subcard
// — a port of pylint's similarity checker (R0801). Every scanned file is reduced
// to its significant lines (comments, strings' contents, blank lines, lone
// brackets and import lines dropped, whitespace collapsed); every run of
// cloneWindow of them is hashed; runs that occur in two places are extended
// line by line into maximal duplicated blocks. Works for every language because
// it needs no grammar, only the stripped lines the other scanners already read.
package constructs

import (
	"fmt"
	"sort"
	"strings"

	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/security"
)

const (
	cloneWindow   = 6   // consecutive significant lines that must match
	cloneMinChars = 110 // …and carry at least this much code between them
	cloneMaxShown = 100 // keep the longest clones only
	cloneMinLines = 15  // report a duplicated block only when it spans at least this many lines
)

// cloneFile is one file reduced to its significant lines.
type cloneFile struct {
	path   string
	lineNo []int    // original 0-based line of each significant line
	hash   []uint64 // per-line hash
	length []int    // per-line length (for the min-chars filter)
	raw    []string
}

type cloneLoc struct{ file, idx int }

var cloneNoise = map[string]bool{"{": true, "}": true, "};": true, ")": true, "});": true, "]": true, "end": true, "else": true, "else:": true, "try:": true, "try": true, "finally:": true, "pass": true, "break": true, "continue": true, "},": true, "),": true}

func cloneSignificant(line string) (string, bool) {
	t := strings.Join(strings.Fields(line), " ")
	if t == "" || cloneNoise[t] || len(t) < 3 {
		return "", false
	}
	for _, p := range []string{"import ", "from ", "#include", "#import", "use ", "using ", "package ", "@import", "require(", "export {", "export *"} {
		if strings.HasPrefix(t, p) && (p != "from " || strings.Contains(t, " import ")) {
			return "", false
		}
	}
	if strings.Trim(t, "{}()[];,") == "" {
		return "", false
	}
	return t, true
}

func fnv64(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// scanClones finds code duplicated between (or within) files.
func scanClones(files []*parser.ParsedFile, cache *sourceCache) []CSIssue {
	var cfs []*cloneFile
	for _, f := range files {
		if security.IsTestOrBenchPath(f.FilePath) || isConstructDetectorFile(f.FilePath) || isGeneratedPath(f.FilePath) {
			continue
		}
		stripped, raw := cache.lines(f.FilePath), cache.rawLines(f.FilePath)
		if stripped == nil || raw == nil || isGeneratedHeader(raw) || csStringLang(ext(f.FilePath)) == csStrNone {
			continue
		}
		cf := &cloneFile{path: f.FilePath, raw: raw}
		for i, l := range stripped {
			if t, ok := cloneSignificant(l); ok {
				cf.lineNo = append(cf.lineNo, i)
				cf.hash = append(cf.hash, fnv64(t))
				cf.length = append(cf.length, len(t))
			}
		}
		if len(cf.hash) >= cloneWindow {
			cfs = append(cfs, cf)
		}
	}
	// window hash → locations
	const mul = 1000003
	groups := map[uint64][]cloneLoc{}
	winHash := make([][]uint64, len(cfs))
	for fi, cf := range cfs {
		n := len(cf.hash) - cloneWindow + 1
		winHash[fi] = make([]uint64, n)
		for i := 0; i < n; i++ {
			var h uint64
			chars := 0
			for k := 0; k < cloneWindow; k++ {
				h = h*mul + cf.hash[i+k]
				chars += cf.length[i+k]
			}
			if chars < cloneMinChars {
				continue // too little code to call a duplicate (hash 0 = ignored)
			}
			winHash[fi][i] = h
			groups[h] = append(groups[h], cloneLoc{fi, i})
		}
	}
	covered := make([][]bool, len(cfs))
	for fi, cf := range cfs {
		covered[fi] = make([]bool, len(cf.hash))
	}
	type clone struct {
		a, b   cloneLoc
		length int // significant lines
	}
	var clones []clone
	for fi := range cfs {
		for i, h := range winHash[fi] {
			if h == 0 || covered[fi][i] {
				continue
			}
			var other *cloneLoc
			for _, l := range groups[h] {
				l := l
				if (l.file > fi || (l.file == fi && l.idx >= i+cloneWindow)) && !covered[l.file][l.idx] {
					other = &l
					break
				}
			}
			if other == nil {
				continue
			}
			k := 0
			for i+k+1 < len(winHash[fi]) && other.idx+k+1 < len(winHash[other.file]) &&
				winHash[fi][i+k+1] == winHash[other.file][other.idx+k+1] && winHash[fi][i+k+1] != 0 {
				// stay clear of overlapping with itself within one file
				if other.file == fi && i+k+1 >= other.idx {
					break
				}
				k++
			}
			for d := 0; d <= k; d++ {
				covered[fi][i+d] = true
				covered[other.file][other.idx+d] = true
			}
			clones = append(clones, clone{a: cloneLoc{fi, i}, b: *other, length: k + cloneWindow})
		}
	}
	sort.SliceStable(clones, func(i, j int) bool { return clones[i].length > clones[j].length })
	sups := map[string]*security.Suppressor{}
	var out []CSIssue
	for _, c := range clones {
		fa, fb := cfs[c.a.file], cfs[c.b.file]
		line := fa.lineNo[c.a.idx]
		endLine := fa.lineNo[c.a.idx+c.length-1]
		span := endLine - line + 1
		if span < cloneMinLines {
			continue
		}
		sev := security.SevLow
		if span >= 25 {
			sev = security.SevMedium
		}
		snip := strings.TrimSpace(fa.raw[line])
		if len(snip) > 100 {
			snip = snip[:100] + "…"
		}
		is := CSIssue{RuleID: "dup-clone", Rule: "Duplicated block", Severity: sev, FilePath: fa.path, Line: line + 1, Snippet: snip,
			Detail:  fmt.Sprintf("%d lines, also in %s:%d", span, baseName(fb.path), fb.lineNo[c.b.idx]+1),
			Message: "The same code appears in more than one place. Extract it into a shared function or module so a fix lands once — duplicated blocks drift apart and get fixed in only one copy."}
		sup, ok := sups[fa.path]
		if !ok {
			sup = security.NewSuppressor(fa.raw)
			sups[fa.path] = sup
		}
		if !sup.Suppressed(is.Line, is.RuleID) {
			out = append(out, is)
		}
		if len(out) == cloneMaxShown {
			break
		}
	}
	return out
}

// isGeneratedPath reports files that are produced, not written: ORM migrations,
// protobuf/gRPC stubs, declaration files, minified bundles, storybook stories.
func isGeneratedPath(path string) bool {
	p := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	for _, seg := range []string{"/migrations/", "/generated/", "/__generated__/", "/gen/", "/vendor/", "/node_modules/", "/third_party/"} {
		if strings.Contains(p, seg) {
			return true
		}
	}
	for _, suf := range []string{".d.ts", ".pb.go", "_pb2.py", "_pb2_grpc.py", ".pb.swift", ".min.js", ".g.dart", ".designer.cs", ".stories.tsx", ".stories.ts", ".stories.js", ".generated.ts", ".gen.go"} {
		if strings.HasSuffix(p, suf) {
			return true
		}
	}
	return false
}
