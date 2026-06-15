package speccoverage

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/exey/archscope/internal/parser"
)

// extractCodeOps reads each source file to extract HTTP route handlers, gRPC
// server method implementations, and GraphQL resolvers.
func extractCodeOps(files []*parser.ParsedFile, projRoot string) []SpecOp {
	var ops []SpecOp
	seen := map[string]bool{}
	add := func(op SpecOp) {
		if k := normKey(op); !seen[k] {
			seen[k] = true
			ops = append(ops, op)
		}
	}
	for _, f := range files {
		content, err := os.ReadFile(f.FilePath)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(projRoot, f.FilePath)
		lines := strings.Split(string(content), "\n")

		var found []SpecOp
		switch f.LanguageID {
		case "go":
			found = goRoutes(lines, rel)
		case "python":
			found = pythonRoutes(lines, rel)
		case "java", "kotlin":
			found = jvmRoutes(lines, rel)
		case "typescript":
			found = tsRoutes(lines, rel)
		}
		for _, op := range found {
			add(op)
		}
	}
	return ops
}

// ─── Go ───────────────────────────────────────────────────────────────────────

var goMethodPats = [][2]string{
	{".GET(", "GET"}, {".Get(", "GET"},
	{".POST(", "POST"}, {".Post(", "POST"},
	{".PUT(", "PUT"}, {".Put(", "PUT"},
	{".DELETE(", "DELETE"}, {".Delete(", "DELETE"},
	{".PATCH(", "PATCH"}, {".Patch(", "PATCH"},
	{".HEAD(", "HEAD"}, {".Head(", "HEAD"},
	{".OPTIONS(", "OPTIONS"}, {".Options(", "OPTIONS"},
}

// reGoGRPCImpl matches gRPC server method implementations:
// func (s *Server) GetUser(ctx context.Context, ...)
var reGoGRPCImpl = regexp.MustCompile(`\bfunc\s*\([^)]+\)\s*(\w+)\s*\(\s*\w*\s*context\.Context`)

func goRoutes(lines []string, relFile string) []SpecOp {
	var ops []SpecOp
	for _, raw := range lines {
		ln := strings.TrimSpace(raw)
		if strings.HasPrefix(ln, "//") {
			continue
		}
		// HTTP routes: .GET("/path", ...), .Post("/path", ...), etc.
		matched := false
		for _, pair := range goMethodPats {
			if sfx, ok := strAfter(ln, pair[0]); ok {
				if p := firstQStr(sfx); p != "" && strings.HasPrefix(p, "/") {
					ops = append(ops, SpecOp{Method: pair[1], Path: p, SpecType: "OpenAPI", File: relFile})
					matched = true
					break
				}
			}
		}
		if !matched {
			for _, pat := range []string{".HandleFunc(", ".Handle(", ".Route(", ".Any("} {
				if sfx, ok := strAfter(ln, pat); ok {
					if p := firstQStr(sfx); p != "" && strings.HasPrefix(p, "/") {
						ops = append(ops, SpecOp{Method: "", Path: p, SpecType: "OpenAPI", File: relFile})
						break
					}
				}
			}
		}
		// gRPC implementations: func (s *Srv) MethodName(ctx context.Context, ...)
		if m := reGoGRPCImpl.FindStringSubmatch(ln); m != nil {
			name := m[1]
			if name != "main" && !strings.HasPrefix(name, "Test") {
				ops = append(ops, SpecOp{Method: "rpc", Path: name, SpecType: "gRPC", File: relFile})
			}
		}
	}
	return ops
}

// ─── Python ───────────────────────────────────────────────────────────────────

var rePyVerb = regexp.MustCompile(`@\w+(?:\.\w+)*\.(get|post|put|delete|patch|head|options)\s*\(\s*["']([^"']+)["']`)
var rePyRoute = regexp.MustCompile(`@\w+(?:\.\w+)*\.route\s*\(\s*["']([^"']+)["']`)
var rePyMethods = regexp.MustCompile(`methods\s*=\s*\[([^\]]+)\]`)

func pythonRoutes(lines []string, relFile string) []SpecOp {
	var ops []SpecOp
	for i, raw := range lines {
		ln := strings.TrimSpace(raw)
		if strings.HasPrefix(ln, "#") {
			continue
		}
		// FastAPI/Starlette: @app.get("/path"), @router.post("/path")
		if m := rePyVerb.FindStringSubmatch(ln); m != nil {
			ops = append(ops, SpecOp{Method: strings.ToUpper(m[1]), Path: m[2], SpecType: "OpenAPI", File: relFile})
			continue
		}
		// Flask: @app.route("/path", methods=["GET", "POST"])
		if m := rePyRoute.FindStringSubmatch(ln); m != nil {
			win := ln
			for j := 1; j <= 3 && i+j < len(lines); j++ {
				win += " " + lines[i+j]
			}
			if mm := rePyMethods.FindStringSubmatch(win); mm != nil {
				for _, meth := range strings.Split(mm[1], ",") {
					meth = strings.Trim(strings.TrimSpace(meth), `"' `)
					if meth != "" {
						ops = append(ops, SpecOp{Method: strings.ToUpper(meth), Path: m[1], SpecType: "OpenAPI", File: relFile})
					}
				}
			} else {
				ops = append(ops, SpecOp{Method: "GET", Path: m[1], SpecType: "OpenAPI", File: relFile})
			}
		}
	}
	return ops
}

// ─── Java / Kotlin ────────────────────────────────────────────────────────────

var reSpringMap = regexp.MustCompile(`@(Get|Post|Put|Delete|Patch|Head|Options|Request)Mapping`)
var reSpringPath = regexp.MustCompile(`(?:value\s*=\s*)?["']([^"']+)["']`)

var springVerb = map[string]string{
	"Get": "GET", "Post": "POST", "Put": "PUT", "Delete": "DELETE",
	"Patch": "PATCH", "Head": "HEAD", "Options": "OPTIONS", "Request": "",
}

func jvmRoutes(lines []string, relFile string) []SpecOp {
	var ops []SpecOp
	for _, raw := range lines {
		ln := strings.TrimSpace(raw)
		if strings.HasPrefix(ln, "//") || strings.HasPrefix(ln, "*") {
			continue
		}
		m := reSpringMap.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		verb := springVerb[m[1]]
		if pm := reSpringPath.FindStringSubmatch(ln); pm != nil {
			if p := pm[1]; strings.HasPrefix(p, "/") {
				ops = append(ops, SpecOp{Method: verb, Path: p, SpecType: "OpenAPI", File: relFile})
			}
		}
	}
	return ops
}

// ─── TypeScript / JavaScript ──────────────────────────────────────────────────

var reTSExpress = regexp.MustCompile(`\.(get|post|put|delete|patch|head|options)\s*\(\s*["']([^"']+)["']`)
var reTSNestHTTP = regexp.MustCompile(`@(Get|Post|Put|Delete|Patch|Head|Options)\s*\(\s*["']([^"']*?)["']\s*\)`)
var reTSNestGQL = regexp.MustCompile(`@(Query|Mutation|Subscription)\s*\(`)
var reTSMethodName = regexp.MustCompile(`(?:async\s+)?(\w+)\s*\(`)

func tsRoutes(lines []string, relFile string) []SpecOp {
	var ops []SpecOp
	var pendingGQL string
	for _, raw := range lines {
		ln := strings.TrimSpace(raw)
		if strings.HasPrefix(ln, "//") {
			continue
		}
		// Express: router.get('/path', handler)
		if m := reTSExpress.FindStringSubmatch(ln); m != nil {
			if strings.HasPrefix(m[2], "/") {
				ops = append(ops, SpecOp{Method: strings.ToUpper(m[1]), Path: m[2], SpecType: "OpenAPI", File: relFile})
			}
			continue
		}
		// NestJS HTTP decorators: @Get('/path'), @Post('/path')
		if m := reTSNestHTTP.FindStringSubmatch(ln); m != nil {
			path := m[2]
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			ops = append(ops, SpecOp{Method: strings.ToUpper(m[1]), Path: path, SpecType: "OpenAPI", File: relFile})
			continue
		}
		// NestJS GraphQL decorators: @Query(), @Mutation()
		if m := reTSNestGQL.FindStringSubmatch(ln); m != nil {
			pendingGQL = m[1]
			continue
		}
		if pendingGQL != "" {
			if m := reTSMethodName.FindStringSubmatch(ln); m != nil && m[1] != "async" {
				ops = append(ops, SpecOp{Method: "field", Path: m[1], SpecType: "GraphQL", File: relFile})
				pendingGQL = ""
			}
		}
	}
	return ops
}

// ─── Normalization and string helpers ─────────────────────────────────────────

var reParam = regexp.MustCompile(`\{[^}]*\}|:[a-zA-Z_]\w*|<[^>]*>`)

// normKey returns a stable comparison key that makes spec ops and code ops
// match across different path-parameter syntaxes ({id}, :id, <id>).
// HTTP:    "get /users/{}"
// gRPC:    "rpc getuser"
// GraphQL: "field users"
func normKey(op SpecOp) string {
	path := reParam.ReplaceAllString(op.Path, "{}")
	path = strings.TrimRight(path, "/")
	if path == "" {
		path = "/"
	}
	path = strings.ToLower(path)
	m := strings.ToLower(op.Method)
	if m == "" {
		return strings.ToLower(op.SpecType) + ":" + path
	}
	return m + " " + path
}

func strAfter(s string, needles ...string) (string, bool) {
	for _, n := range needles {
		if i := strings.Index(s, n); i >= 0 {
			return s[i+len(n):], true
		}
	}
	return "", false
}

func firstQStr(s string) string {
	i := strings.IndexByte(s, '"')
	if i < 0 {
		return ""
	}
	j := i + 1
	for j < len(s) {
		if s[j] == '\\' {
			j += 2
			continue
		}
		if s[j] == '"' {
			return s[i+1 : j]
		}
		j++
	}
	return ""
}
