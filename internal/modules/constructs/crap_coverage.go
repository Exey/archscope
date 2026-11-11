package constructs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// crap_coverage.go reads the coverage artifacts a project's own test run already
// writes, and answers "which of this function's lines ran". Line coverage only: a
// line counts as measured when the artifact speaks of it, and as covered when it
// ran at least once. Formats: coverage.py (JSON and Cobertura XML), Go cover
// profiles, lcov, and istanbul's coverage-final.json.

var (
	coverageMu    sync.Mutex
	coveragePaths []string // --coverage files, absolute
)

// SetCoveragePaths registers the --coverage files (absolute paths).
func SetCoveragePaths(paths []string) {
	coverageMu.Lock()
	defer coverageMu.Unlock()
	coveragePaths = append([]string(nil), paths...)
}

// fileCov is one source file's measured lines: line → ran.
type fileCov struct {
	path   string // as the artifact names it, slash-separated
	lines  map[int]bool
	source string // the artifact it came from
}

func (f *fileCov) mark(line int, ran bool) {
	if line <= 0 {
		return
	}
	if cur, ok := f.lines[line]; !ok || (ran && !cur) {
		f.lines[line] = ran
	}
}

// covIndex finds a source file's coverage by path, tolerant of how artifacts spell paths.
type covIndex struct {
	byBase  map[string][]*fileCov
	sources []string
}

func newCovIndex() *covIndex { return &covIndex{byBase: map[string][]*fileCov{}} }

func (ix *covIndex) add(f *fileCov) {
	f.path = filepath.ToSlash(f.path)
	base := f.path[strings.LastIndex(f.path, "/")+1:]
	for _, e := range ix.byBase[base] { // the same file named twice (merged XML classes): fold
		if e.path == f.path && e.source == f.source {
			for l, ran := range f.lines {
				e.mark(l, ran)
			}
			return
		}
	}
	ix.byBase[base] = append(ix.byBase[base], f)
}

func commonSuffix(a, b []string) int {
	n := 0
	for i, j := len(a)-1, len(b)-1; i >= 0 && j >= 0 && a[i] == b[j]; i, j = i-1, j-1 {
		n++
	}
	return n
}

// lookup returns the coverage of the absolute file path, or nil. A file whose base
// name no other analysed file shares (baseUnique) matches on the name alone — a Go
// profile names `module/hot.go` for a file at the repository root.
func (ix *covIndex) lookup(abs string, baseUnique bool) *fileCov {
	abs = filepath.ToSlash(abs)
	parts := strings.Split(abs, "/")
	var best *fileCov
	bestN := 0
	cands := ix.byBase[parts[len(parts)-1]]
	for _, e := range cands {
		ep := strings.Split(strings.TrimPrefix(e.path, "./"), "/")
		n := commonSuffix(parts, ep)
		need := 2
		if len(ep) < need || baseUnique && len(cands) == 1 {
			need = 1
		}
		if n >= need && n > bestN {
			best, bestN = e, n
		}
	}
	return best
}

// span reports the covered and measured lines inside [from, to].
func (f *fileCov) span(from, to int) (covered, measured int) {
	for l := from; l <= to; l++ {
		if ran, ok := f.lines[l]; ok {
			measured++
			if ran {
				covered++
			}
		}
	}
	return
}

var coverageNames = map[string]bool{"coverage.xml": true, "cobertura.xml": true, "coverage.json": true, "cover.out": true, "coverage.out": true,
	"c.out": true, "cover.txt": true, "lcov.info": true, "coverage-final.json": true, "coverage.lcov": true}

var coverageSkipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true, "__pycache__": true, ".tox": true}

// findCoverageFiles looks for the usual artifacts under root, a few levels deep.
func findCoverageFiles(root string) []string {
	var out []string
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && (coverageSkipDirs[d.Name()] || strings.Count(strings.TrimPrefix(p, root), string(filepath.Separator)) > 4) {
				return filepath.SkipDir
			}
			return nil
		}
		if coverageNames[d.Name()] {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

const maxCoverageBytes = 96 << 20

// loadCoverage parses every artifact into one index and returns the artifacts' names.
func loadCoverage(files []string) (*covIndex, []string) {
	ix := newCovIndex()
	var used []string
	for _, p := range files {
		fi, err := os.Stat(p)
		if err != nil || fi.Size() > maxCoverageBytes {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var got []*fileCov
		src := filepath.Base(p)
		switch {
		case bytes.HasPrefix(bytes.TrimSpace(data), []byte("<")):
			got = parseCobertura(data, src)
		case bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")):
			got = parseCoverageJSON(data, src)
		case bytes.HasPrefix(data, []byte("mode:")):
			got = parseGoCover(data, src)
		case bytes.Contains(data, []byte("SF:")):
			got = parseLcov(data, src)
		}
		if len(got) == 0 {
			continue
		}
		for _, f := range got {
			ix.add(f)
		}
		used = append(used, src)
	}
	ix.sources = used
	return ix, used
}

// parseCoverageJSON reads coverage.py's JSON report and istanbul's coverage-final.json.
func parseCoverageJSON(data []byte, src string) []*fileCov {
	var top map[string]json.RawMessage
	if json.Unmarshal(data, &top) != nil {
		return nil
	}
	var out []*fileCov
	if raw, ok := top["files"]; ok { // coverage.py
		var files map[string]struct {
			Executed []int `json:"executed_lines"`
			Missing  []int `json:"missing_lines"`
		}
		if json.Unmarshal(raw, &files) != nil {
			return nil
		}
		for p, f := range files {
			fc := &fileCov{path: p, lines: map[int]bool{}, source: src}
			for _, l := range f.Missing {
				fc.mark(l, false)
			}
			for _, l := range f.Executed {
				fc.mark(l, true)
			}
			out = append(out, fc)
		}
		return out
	}
	for p, raw := range top { // istanbul: path → {statementMap, s}
		var f struct {
			StatementMap map[string]struct {
				Start struct {
					Line int `json:"line"`
				} `json:"start"`
			} `json:"statementMap"`
			S map[string]int `json:"s"`
		}
		if json.Unmarshal(raw, &f) != nil || f.StatementMap == nil {
			continue
		}
		fc := &fileCov{path: p, lines: map[int]bool{}, source: src}
		for id, st := range f.StatementMap {
			fc.mark(st.Start.Line, f.S[id] > 0)
		}
		out = append(out, fc)
	}
	return out
}

// parseCobertura reads Cobertura XML (coverage.py's `coverage xml`, JaCoCo converters, …).
func parseCobertura(data []byte, src string) []*fileCov {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	var out []*fileCov
	var cur *fileCov
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "class":
				cur = nil
				for _, a := range t.Attr {
					if a.Name.Local == "filename" {
						cur = &fileCov{path: a.Value, lines: map[int]bool{}, source: src}
						out = append(out, cur)
					}
				}
			case "line":
				if cur == nil {
					continue
				}
				n, hits := 0, 0
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "number":
						n, _ = strconv.Atoi(a.Value)
					case "hits":
						hits, _ = strconv.Atoi(a.Value)
					}
				}
				cur.mark(n, hits > 0)
			}
		case xml.EndElement:
			if t.Name.Local == "class" {
				cur = nil
			}
		}
	}
	return out
}

// parseGoCover reads a `go test -coverprofile` file: "file.go:10.2,12.3 1 0".
func parseGoCover(data []byte, src string) []*fileCov {
	byFile := map[string]*fileCov{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "mode:") {
			continue
		}
		colon := strings.LastIndex(line, ":")
		if colon < 0 {
			continue
		}
		f := strings.Fields(line[colon+1:])
		if len(f) != 3 {
			continue
		}
		span := strings.SplitN(f[0], ",", 2)
		if len(span) != 2 {
			continue
		}
		from, _ := strconv.Atoi(strings.SplitN(span[0], ".", 2)[0])
		to, _ := strconv.Atoi(strings.SplitN(span[1], ".", 2)[0])
		count, _ := strconv.Atoi(f[2])
		fc := byFile[line[:colon]]
		if fc == nil {
			fc = &fileCov{path: line[:colon], lines: map[int]bool{}, source: src}
			byFile[line[:colon]] = fc
		}
		for l := from; l <= to; l++ {
			fc.mark(l, count > 0)
		}
	}
	out := make([]*fileCov, 0, len(byFile))
	for _, fc := range byFile {
		out = append(out, fc)
	}
	return out
}

// parseLcov reads lcov.info: SF:path, DA:line,hits … end_of_record.
func parseLcov(data []byte, src string) []*fileCov {
	var out []*fileCov
	var cur *fileCov
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "SF:"):
			cur = &fileCov{path: line[3:], lines: map[int]bool{}, source: src}
			out = append(out, cur)
		case strings.HasPrefix(line, "DA:") && cur != nil:
			f := strings.Split(line[3:], ",")
			if len(f) >= 2 {
				n, _ := strconv.Atoi(f[0])
				hits, _ := strconv.Atoi(f[1])
				cur.mark(n, hits > 0)
			}
		case line == "end_of_record":
			cur = nil
		}
	}
	return out
}
