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
	groups := goGroupPrefixes(lines)
	var ops []SpecOp
	for _, raw := range lines {
		ln := strings.TrimSpace(raw)
		if strings.HasPrefix(ln, "//") {
			continue
		}
		// HTTP routes: .GET("/path", ...), .Post("/path", ...), etc.
		matched := false
		for _, pair := range goMethodPats {
			if idx := strings.Index(ln, pair[0]); idx >= 0 {
				sfx := ln[idx+len(pair[0]):]
				if p := firstQStr(sfx); p != "" && strings.HasPrefix(p, "/") {
					full := joinGo(groups[identBefore(ln, idx)], p)
					ops = append(ops, SpecOp{Method: pair[1], Path: full, SpecType: "OpenAPI", File: relFile})
					matched = true
					break
				}
			}
		}
		if !matched {
			for _, pat := range []string{".HandleFunc(", ".Handle(", ".Route(", ".Any("} {
				if idx := strings.Index(ln, pat); idx >= 0 {
					sfx := ln[idx+len(pat):]
					if p := firstQStr(sfx); p != "" && strings.HasPrefix(p, "/") {
						full := joinGo(groups[identBefore(ln, idx)], p)
						ops = append(ops, SpecOp{Method: "", Path: full, SpecType: "OpenAPI", File: relFile})
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

// goGroupPrefixes tracks `v := router.Group("/prefix")` assignments (gin/echo/
// chi/fiber) so routes registered on a sub-router inherit its path prefix.
// Handles one level of nesting (v2 := v1.Group("/x")).
func goGroupPrefixes(lines []string) map[string]string {
	prefixes := map[string]string{}
	for _, raw := range lines {
		ln := strings.TrimSpace(raw)
		idx := strings.Index(ln, ".Group(")
		if idx < 0 {
			continue
		}
		eq := strings.Index(ln, ":=")
		if eq < 0 {
			eq = strings.Index(ln, "=")
		}
		if eq < 0 || eq > idx {
			continue
		}
		lhs := strings.TrimSpace(ln[:eq])
		if lhs == "" || strings.ContainsAny(lhs, " \t,") {
			continue
		}
		p := firstQStr(ln[idx+len(".Group("):])
		if p == "" {
			continue
		}
		prefixes[lhs] = joinGo(prefixes[identBefore(ln, idx)], p)
	}
	return prefixes
}

// identBefore returns the identifier ending immediately before position idx.
func identBefore(s string, idx int) string {
	i := idx
	for i > 0 {
		c := s[i-1]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			i--
			continue
		}
		break
	}
	return s[i:idx]
}

// joinGo concatenates a group prefix with a route path.
func joinGo(prefix, path string) string {
	if prefix == "" {
		return path
	}
	if path == "" || path == "/" {
		return prefix
	}
	return strings.TrimRight(prefix, "/") + "/" + strings.TrimLeft(path, "/")
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
	prefix := jvmClassPrefix(lines)
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
		path := ""
		if pm := reSpringPath.FindStringSubmatch(ln); pm != nil {
			path = pm[1]
		}
		full := jvmJoinPath(prefix, path)
		// The class-level @RequestMapping is consumed as a prefix, not an op.
		if m[1] == "Request" && verb == "" && path == prefix && prefix != "" {
			continue
		}
		if full == "" || !strings.HasPrefix(full, "/") {
			continue
		}
		ops = append(ops, SpecOp{Method: verb, Path: full, SpecType: "OpenAPI", File: relFile})
	}
	return ops
}

// jvmClassPrefix returns the @RequestMapping path declared at class/interface level.
func jvmClassPrefix(lines []string) string {
	for i, raw := range lines {
		ln := strings.TrimSpace(raw)
		if !strings.HasPrefix(ln, "@RequestMapping(") {
			continue
		}
		pm := reSpringPath.FindStringSubmatch(ln)
		if pm == nil {
			continue
		}
		for j := i + 1; j < len(lines) && j <= i+6; j++ {
			t := strings.TrimSpace(lines[j])
			if t == "" || strings.HasPrefix(t, "@") || strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") {
				continue
			}
			if strings.Contains(t, " class ") || strings.Contains(t, " interface ") {
				return pm[1]
			}
			break
		}
	}
	return ""
}

// jvmJoinPath combines a class-level prefix with a method-level path.
func jvmJoinPath(prefix, path string) string {
	if prefix == "" {
		return path
	}
	if path == "" {
		return prefix
	}
	return strings.TrimRight(prefix, "/") + "/" + strings.TrimLeft(path, "/")
}

// ─── TypeScript / JavaScript ──────────────────────────────────────────────────

var reTSExpress = regexp.MustCompile(`\.(get|post|put|delete|patch|head|options)\s*\(\s*["']([^"']+)["']`)

// path argument is optional: @Get() maps to the controller root.
var reTSNestHTTP = regexp.MustCompile(`@(Get|Post|Put|Delete|Patch|Head|Options)\s*\(\s*(?:["']([^"']*?)["'])?\s*\)`)
var reTSNestGQL = regexp.MustCompile(`@(Query|Mutation|Subscription)\s*\(`)
var reTSMethodName = regexp.MustCompile(`(?:async\s+)?(\w+)\s*\(`)
var reTSController = regexp.MustCompile(`@Controller\s*\(\s*(?:["']([^"']*?)["'])?\s*\)`)

// tsControllerPrefix returns the path declared on @Controller('prefix').
// Returns "" for @Controller() / @Controller (root), and "" when no decorator
// is found (plain Express file).
func tsControllerPrefix(lines []string) string {
	for _, raw := range lines {
		ln := strings.TrimSpace(raw)
		if strings.HasPrefix(ln, "//") || strings.HasPrefix(ln, "*") {
			continue
		}
		if !strings.HasPrefix(ln, "@Controller") {
			continue
		}
		if m := reTSController.FindStringSubmatch(ln); m != nil {
			return m[1] // "" for @Controller() or @Controller('')
		}
		return "" // @Controller without parens → root prefix
	}
	return ""
}

// tsJoinPath joins a controller-level prefix with a method-level path segment.
func tsJoinPath(prefix, path string) string {
	if prefix != "" && !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	if path == "" {
		if prefix == "" {
			return "/"
		}
		return prefix
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if prefix == "" {
		return path
	}
	return strings.TrimRight(prefix, "/") + path
}

func tsRoutes(lines []string, relFile string) []SpecOp {
	prefix := tsControllerPrefix(lines)
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
		// NestJS HTTP decorators: @Get('path'), @Post('path'), or bare @Get()
		if m := reTSNestHTTP.FindStringSubmatch(ln); m != nil {
			path := tsJoinPath(prefix, m[2])
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

// normPath returns the verb-less normalized path key, used to let a catch-all
// handler (HandleFunc / @RequestMapping with no verb / .Any) cover a spec op
// on the same path regardless of HTTP method.
func normPath(op SpecOp) string {
	path := reParam.ReplaceAllString(op.Path, "{}")
	path = strings.TrimRight(path, "/")
	if path == "" {
		path = "/"
	}
	return strings.ToLower(path)
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
