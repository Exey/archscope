package speccoverage

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/exey/archscope/internal/parser"
)

// ─── Project root discovery ───────────────────────────────────────────────────

// commonRoot returns the longest common directory ancestor of all file paths.
func commonRoot(files []*parser.ParsedFile) string {
	if len(files) == 0 {
		return ""
	}
	root := filepath.Dir(files[0].FilePath)
	for _, f := range files[1:] {
		dir := filepath.Dir(f.FilePath)
		for root != dir && !strings.HasPrefix(dir+string(filepath.Separator), root+string(filepath.Separator)) {
			parent := filepath.Dir(root)
			if parent == root {
				return root
			}
			root = parent
		}
	}
	return root
}

// findProjectRoot walks up from dir to the nearest directory containing a
// project-root marker (.git, go.mod, package.json, …). Falls back to dir.
func findProjectRoot(dir string) string {
	markers := []string{".git", "go.mod", "package.json", "requirements.txt", "pom.xml", "build.gradle", "Cargo.toml"}
	cur := dir
	for {
		for _, m := range markers {
			if _, err := os.Stat(filepath.Join(cur, m)); err == nil {
				return cur
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return dir // reached filesystem root
		}
		cur = parent
	}
}

// ─── Spec file scanning ───────────────────────────────────────────────────────

var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, ".git": true,
	"dist": true, "build": true, "target": true,
	"__pycache__": true, ".gradle": true, ".idea": true,
}

// specCache avoids re-walking the same project root for every platform tab.
var specCacheMu sync.Mutex
var specCache = map[string]specCacheEntry{}

type specCacheEntry struct {
	ops       []SpecOp
	fileCount int
}

// scanSpecFiles walks root up to 4 levels deep, parsing OpenAPI YAML/JSON,
// .proto, and .graphql/.gql files it finds. Results are cached by root path.
func scanSpecFiles(root string) ([]SpecOp, int) {
	specCacheMu.Lock()
	if e, ok := specCache[root]; ok {
		specCacheMu.Unlock()
		return e.ops, e.fileCount
	}
	specCacheMu.Unlock()

	var ops []SpecOp
	var fileCount int
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > 4 {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() {
				if skipDirs[name] || strings.HasPrefix(name, ".") {
					continue
				}
				walk(filepath.Join(dir, name), depth+1)
				continue
			}
			// Check filename before reading — skip non-spec files cheaply.
			nameL := strings.ToLower(name)
			if !isOpenAPIFilename(nameL) &&
				!strings.HasSuffix(nameL, ".proto") &&
				!strings.HasSuffix(nameL, ".graphql") &&
				!strings.HasSuffix(nameL, ".gql") {
				continue
			}
			abs := filepath.Join(dir, name)
			rel, _ := filepath.Rel(root, abs)
			content, err := os.ReadFile(abs)
			if err != nil {
				continue
			}
			src := string(content)
			var found []SpecOp
			switch {
			case isOpenAPIFilename(nameL):
				found = parseOpenAPI(src, rel)
			case strings.HasSuffix(nameL, ".proto"):
				found = parseProto(src, rel)
			default:
				found = parseGraphQL(src, rel)
			}
			if len(found) > 0 {
				ops = append(ops, found...)
				fileCount++
			}
		}
	}
	walk(root, 0)

	specCacheMu.Lock()
	specCache[root] = specCacheEntry{ops, fileCount}
	specCacheMu.Unlock()
	return ops, fileCount
}

func isOpenAPIFilename(name string) bool {
	for _, n := range []string{
		"openapi.yaml", "openapi.yml", "openapi.json",
		"swagger.yaml", "swagger.yml", "swagger.json",
	} {
		if name == n {
			return true
		}
	}
	return false
}

// ─── OpenAPI parsing ──────────────────────────────────────────────────────────

var httpMethods = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true,
	"patch": true, "head": true, "options": true,
}

func parseOpenAPI(content, relFile string) []SpecOp {
	if strings.HasSuffix(strings.ToLower(relFile), ".json") {
		return parseOpenAPIJSON(content, relFile)
	}
	return parseOpenAPIYAML(content, relFile)
}

// parseOpenAPIYAML uses a line-by-line state machine that tracks indentation
// to extract path entries and HTTP method keys from the `paths:` section.
func parseOpenAPIYAML(content, relFile string) []SpecOp {
	lines := strings.Split(content, "\n")

	// Confirm it's an OpenAPI/Swagger spec before parsing.
	limit := 20
	if limit > len(lines) {
		limit = len(lines)
	}
	isSpec := false
	for _, l := range lines[:limit] {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "openapi:") || strings.HasPrefix(t, "swagger:") {
			isSpec = true
			break
		}
	}
	if !isSpec {
		return nil
	}

	var ops []SpecOp
	inPaths := false
	var curPath string
	pathIndent := -1
	methIndent := -1

	for _, raw := range lines {
		t := strings.TrimSpace(raw)
		if t == "" || t == "---" || strings.HasPrefix(t, "#") {
			continue
		}
		ind := indentWidth(raw)

		if !inPaths {
			if t == "paths:" {
				inPaths = true
				pathIndent, methIndent = -1, -1
			}
			continue
		}
		// A line at indent 0 (other than `paths:`) ends the paths section.
		if ind == 0 {
			break
		}
		// Detect path-entry indent from the first line starting with '/'.
		if pathIndent < 0 && strings.HasPrefix(t, "/") && strings.HasSuffix(t, ":") {
			pathIndent = ind
		}
		// Record path entries.
		if pathIndent >= 0 && ind == pathIndent && strings.HasPrefix(t, "/") {
			p := strings.TrimSuffix(t, ":")
			if i := strings.Index(p, " #"); i >= 0 {
				p = p[:i]
			}
			curPath = strings.TrimSpace(p)
			methIndent = -1
			continue
		}
		if curPath == "" || ind <= pathIndent {
			continue
		}
		// Detect method-entry indent from the first HTTP verb seen.
		if methIndent < 0 {
			key := strings.ToLower(strings.Fields(strings.TrimSuffix(t, ":"))[0])
			if httpMethods[key] {
				methIndent = ind
			}
		}
		if methIndent >= 0 && ind == methIndent {
			key := strings.ToLower(strings.Fields(strings.TrimSuffix(t, ":"))[0])
			if httpMethods[key] {
				ops = append(ops, SpecOp{
					Method:   strings.ToUpper(key),
					Path:     curPath,
					SpecType: "OpenAPI",
					File:     relFile,
				})
			}
		}
	}
	return ops
}

var reJSONPath = regexp.MustCompile(`^\s+"(/[^"]+)"\s*:\s*\{?`)
var reJSONMethod = regexp.MustCompile(`^\s+"(get|post|put|delete|patch|head|options)"\s*:`)

// parseOpenAPIJSON uses regex scanning for JSON-format OpenAPI specs.
func parseOpenAPIJSON(content, relFile string) []SpecOp {
	if !strings.Contains(content, `"openapi"`) && !strings.Contains(content, `"swagger"`) {
		return nil
	}
	pathsIdx := strings.Index(content, `"paths"`)
	if pathsIdx < 0 {
		return nil
	}
	var ops []SpecOp
	var curPath string
	for _, l := range strings.Split(content[pathsIdx:], "\n") {
		if m := reJSONPath.FindStringSubmatch(l); m != nil {
			curPath = m[1]
			continue
		}
		if m := reJSONMethod.FindStringSubmatch(l); m != nil && curPath != "" {
			ops = append(ops, SpecOp{
				Method:   strings.ToUpper(m[1]),
				Path:     curPath,
				SpecType: "OpenAPI",
				File:     relFile,
			})
		}
	}
	return ops
}

// ─── gRPC / proto ─────────────────────────────────────────────────────────────

var reProtoRPC = regexp.MustCompile(`\brpc\s+(\w+)\s*\(`)

func parseProto(content, relFile string) []SpecOp {
	var ops []SpecOp
	for _, m := range reProtoRPC.FindAllStringSubmatch(content, -1) {
		ops = append(ops, SpecOp{
			Method:   "rpc",
			Path:     m[1],
			SpecType: "gRPC",
			File:     relFile,
		})
	}
	return ops
}

// ─── GraphQL ──────────────────────────────────────────────────────────────────

var reGQLRootType = regexp.MustCompile(`(?i)^\s*type\s+(Query|Mutation|Subscription)\s*[{(]`)
var reGQLField = regexp.MustCompile(`^\s{1,4}(\w+)\s*[:(]`)

func parseGraphQL(content, relFile string) []SpecOp {
	var ops []SpecOp
	depth := 0
	inBlock := false

	for _, raw := range strings.Split(content, "\n") {
		t := strings.TrimSpace(raw)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if !inBlock {
			if reGQLRootType.MatchString(raw) {
				inBlock = true
				depth = strings.Count(raw, "{") - strings.Count(raw, "}")
			}
			continue
		}
		depth += strings.Count(raw, "{") - strings.Count(raw, "}")
		if depth <= 0 {
			inBlock = false
			continue
		}
		if m := reGQLField.FindStringSubmatch(raw); m != nil {
			ops = append(ops, SpecOp{
				Method:   "field",
				Path:     m[1],
				SpecType: "GraphQL",
				File:     relFile,
			})
		}
	}
	return ops
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// indentWidth counts leading spaces (tabs treated as 2 spaces).
func indentWidth(s string) int {
	n := 0
	for _, c := range s {
		switch c {
		case ' ':
			n++
		case '\t':
			n += 2
		default:
			return n
		}
	}
	return n
}
