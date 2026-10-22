package openapi

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FileReport is the lint result of one specification file.
type FileReport struct {
	Path       string
	Version    string
	Operations int
	Findings   []Finding
	// Changes is the difference from the merge-base version (review mode only).
	Changes []Change
}

// Breaking counts the changes that break existing consumers.
func (f FileReport) Breaking() (n int) {
	for _, c := range f.Changes {
		if c.Level == lvBreaking {
			n++
		}
	}
	return
}

// Real counts the findings that are not advisory.
func (f FileReport) Real() int {
	n := 0
	for _, x := range f.Findings {
		if !x.Advisory {
			n++
		}
	}
	return n
}

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true, "target": true,
	".venv": true, "venv": true, "__pycache__": true, ".idea": true, ".vscode": true, "site-packages": true, "testdata": true, "fixtures": true}

const maxSpecBytes = 4 << 20

// Scan finds OpenAPI/Swagger documents under root (.yaml/.yml/.json) and lints
// each. only, when non-nil, restricts the scan to those absolute paths (review
// mode: just the specs the merge request changes).
func Scan(root string, exclude []string, only map[string]bool) []FileReport {
	skip := map[string]bool{}
	for _, e := range exclude {
		skip[e] = true
	}
	var out []FileReport
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && (skipDirs[d.Name()] || skip[d.Name()] || strings.HasPrefix(d.Name(), ".") && d.Name() != ".") {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yaml", ".yml", ".json":
		default:
			return nil
		}
		if only != nil && !only[path] {
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > maxSpecBytes || info.Size() < 40 {
			return nil
		}
		if !headLooksLikeSpec(path) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if rep, ok := LintFile(path, string(data)); ok {
			out = append(out, rep)
		}
		return nil
	})
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// LintFile lints src as the file at path; ok is false when it isn't a specification.
func LintFile(path, src string) (FileReport, bool) {
	d, ok := Load(src)
	if !ok {
		return FileReport{}, false
	}
	l := &linter{d: d, seen: map[string]bool{}, schemaSeen: map[*Node]bool{}}
	l.run()
	sort.SliceStable(l.out, func(i, j int) bool {
		if l.out[i].Line != l.out[j].Line {
			return l.out[i].Line < l.out[j].Line
		}
		return l.out[i].RuleID < l.out[j].RuleID
	})
	return FileReport{Path: path, Version: d.Ver, Operations: len(l.operations()), Findings: l.out}, true
}

// headLooksLikeSpec reads only the first 4 KB of a file, so scanning a repo full of
// unrelated JSON/YAML stays cheap.
func headLooksLikeSpec(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	return reSpecHead.Match(buf[:n])
}
