package openapi

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Finding is one rule violation, pointing at a line of the spec.
type Finding struct {
	RuleID   string
	Rule     string // short human label
	Message  string // what to do
	Detail   string // what this hit is about: "POST /pets", "{petId}"
	Severity string // "HIGH" | "MEDIUM" | "LOW"
	Line     int
	Advisory bool // shown in the report, never a review issue
}

// Doc is a parsed specification.
type Doc struct {
	Root *Node
	V2   bool   // Swagger 2.0
	Ver  string // "2.0", "3.0.3", "3.1.0"
	v30  bool   // 3.0.x: $ref siblings are not allowed
}

var (
	reSpecHead = regexp.MustCompile(`(?m)^\s*["']?(?:openapi|swagger)["']?\s*:\s*["']?(?:3\.\d+(?:\.\d+)?|2\.0)["']?`)
	rePathVar  = regexp.MustCompile(`\{([^{}]*)\}`)
	methods    = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}
	unsafeM    = map[string]bool{"post": true, "put": true, "patch": true, "delete": true}
)

// LooksLikeSpec is a cheap pre-check on the file head.
func LooksLikeSpec(src string) bool {
	head := src
	if len(head) > 4096 {
		head = head[:4096]
	}
	return reSpecHead.MatchString(head) && (strings.Contains(src, "paths") || strings.Contains(src, "components") || strings.Contains(src, "definitions"))
}

// Load parses src into a Doc; ok is false when it isn't an OpenAPI/Swagger document.
func Load(src string) (*Doc, bool) {
	if !LooksLikeSpec(src) {
		return nil, false
	}
	root, err := Parse(src)
	if err != nil || root == nil || root.Kind != Map {
		return nil, false
	}
	d := &Doc{Root: root}
	if v := root.Get("swagger").Str(); v != "" {
		d.V2, d.Ver = true, v
	} else if v := root.Get("openapi").Str(); v != "" {
		d.Ver = v
		d.v30 = strings.HasPrefix(v, "3.0")
	} else {
		return nil, false
	}
	return d, true
}

// Lint runs every rule over src. ok is false for documents that aren't specs.
func Lint(src string) (findings []Finding, ok bool) {
	d, ok := Load(src)
	if !ok {
		return nil, false
	}
	l := &linter{d: d, seen: map[string]bool{}, schemaSeen: map[*Node]bool{}}
	l.run()
	sort.SliceStable(l.out, func(i, j int) bool {
		if l.out[i].Line != l.out[j].Line {
			return l.out[i].Line < l.out[j].Line
		}
		return l.out[i].RuleID < l.out[j].RuleID
	})
	return l.out, true
}

type linter struct {
	d          *Doc
	out        []Finding
	seen       map[string]bool
	schemaSeen map[*Node]bool
}

type rule struct {
	sev      string
	label    string
	msg      string
	advisory bool
}

var rules = map[string]rule{
	"oas-spec-required":           {"MEDIUM", "Required field missing", "The OpenAPI specification requires this field; tools reject or mis-read a document without it.", false},
	"oas-spec-unknown":            {"MEDIUM", "Unknown field", "This key is not part of the OpenAPI object (a typo such as `reponses` or `requestbody` is silently ignored). Fix the spelling, or prefix a custom key with `x-`.", false},
	"oas-spec-type":               {"MEDIUM", "Wrong value type", "The value has the wrong shape for this field (a list where an object belongs, a string for a boolean, …).", false},
	"oas-spec-enum":               {"MEDIUM", "Invalid value", "The value is not one of the values the OpenAPI specification allows here.", false},
	"oas-spec-response-code":      {"MEDIUM", "Invalid response code", "Response keys must be `default`, a three-digit HTTP status (`200`) or a range (`4XX`).", false},
	"oas-spec-path-key":           {"MEDIUM", "Path must start with /", "Every key under `paths` is a URL path and must begin with `/`.", false},
	"oas-schema-type":             {"MEDIUM", "Invalid schema type", "`type` must be one of string, number, integer, boolean, array, object (or null in 3.1).", false},
	"oas-schema-constraint":       {"MEDIUM", "Constraint does not apply to the type", "This keyword only constrains other types (for example `minLength` on an integer) and is ignored; fix the type or drop the keyword.", false},
	"oas-schema-range":            {"MEDIUM", "Inconsistent limits", "A minimum is above its maximum, a length/count is negative, or `multipleOf` is not positive — no value can satisfy the schema.", false},
	"oas-schema-pattern":          {"MEDIUM", "Invalid regular expression", "`pattern` must be an ECMA-262 regular expression with balanced groups and classes.", false},
	"oas-schema-value":            {"MEDIUM", "default/example does not match the type", "The value is not valid for the schema's own type; generators and mock servers will emit invalid data.", false},
	"oas-schema-required":         {"MEDIUM", "Malformed `required`", "`required` inside a schema is a list of unique property names.", false},
	"oas-schema-composition":      {"MEDIUM", "Conflicting composition", "These members of an allOf can never both hold, or a oneOf/anyOf repeats a branch.", false},
	"oas-allof-conflict":          {"MEDIUM", "allOf properties have no type in common", "The same property is declared with incompatible types in different members of an allOf, so no value can satisfy the combined schema (vacuum's allOf-conflicts rule).", false},
	"oas-schema-discriminator":    {"MEDIUM", "Broken discriminator", "A discriminator needs a `propertyName` that is a property of the schema.", false},
	"oas-schema-readwrite":        {"LOW", "readOnly and writeOnly together", "A property cannot be both read-only and write-only.", false},
	"oas-schema-exclusive":        {"MEDIUM", "exclusiveMinimum/Maximum has the wrong form", "Before OpenAPI 3.1 these are booleans next to minimum/maximum; in 3.1 they are numbers.", false},
	"oas-schema-array-items":      {"MEDIUM", "Array without items", "An array schema must say what its items are.", false},
	"oas-schema-const-enum":       {"MEDIUM", "const is not in enum", "`const` must be one of the `enum` values.", false},
	"oas-schema-missing-type":     {"LOW", "Schema without a type", "State `type` explicitly so validators and generators don't have to guess.", true},
	"oas-duplicate-key":           {"MEDIUM", "Duplicate key", "The same key appears twice in one mapping; YAML/JSON parsers keep only the last one, so the first definition is silently lost (two `paths` entries for one path are the usual case).", false},
	"oas-info-description":        {"LOW", "info.description missing", "Describe what the API is for; it is the first thing consumers read.", false},
	"oas-operation-id-missing":    {"MEDIUM", "Operation without an operationId", "Every operation needs a unique operationId — client generators and docs use it as the method name.", false},
	"oas-operation-id-duplicate":  {"MEDIUM", "Duplicate operationId", "operationIds must be unique across the whole document; generators will overwrite one operation with the other.", false},
	"oas-operation-id-chars":      {"LOW", "operationId is not URL-friendly", "Use letters, digits, `_` `-` `.` only, so the id works as a URL fragment and a method name.", false},
	"oas-operation-description":   {"LOW", "Operation without description or summary", "Say what the operation does and when it fails; undocumented endpoints are the ones consumers guess at.", false},
	"oas-operation-tags":          {"LOW", "Operation without tags", "Tags group operations in generated docs and clients.", true},
	"oas-operation-tag-undefined": {"LOW", "Operation tag not declared at the top level", "Declare the tag in the top-level `tags` list (with a description) so docs can order and explain it.", false},
	"oas-success-response":        {"MEDIUM", "Operation without a 2xx/3xx response", "Define what a successful call returns, or consumers can't generate a response type.", false},
	"oas-error-response":          {"LOW", "Operation without a 4xx response", "Document the client-error responses (400/401/403/404, plus 429 for rate-limited APIs) so callers can handle them.", true},
	"oas-body-on-get-delete":      {"MEDIUM", "GET/DELETE with a request body", "HTTP semantics give GET and DELETE bodies no meaning; proxies and clients drop them. Use query parameters or POST.", false},
	"oas-path-params":             {"MEDIUM", "Path parameter mismatch", "Every `{name}` in the path needs a matching parameter with `in: path` and `required: true`, and every `in: path` parameter must appear in the path.", false},
	"oas-path-params-empty":       {"MEDIUM", "Empty path parameter `{}`", "A path variable needs a name: `/items/{id}`.", false},
	"oas-path-query":              {"MEDIUM", "Query string in a path", "Declare query parameters under `parameters` (`in: query`), not in the path key.", false},
	"oas-path-trailing-slash":     {"LOW", "Path ends with a slash", "`/users` and `/users/` are different routes in many servers; pick one form and drop the trailing slash.", false},
	"oas-path-case":               {"LOW", "Path segment is not kebab-case", "Keep path segments lowercase with hyphens (`/order-items`), no underscores or capitals.", true},
	"oas-path-verb":               {"LOW", "HTTP verb in a path", "The method already says what happens; name the resource (`POST /orders`), not the action (`/createOrder`).", false},
	"oas-path-ambiguous":          {"MEDIUM", "Ambiguous paths", "These paths differ only by the name of a variable, so a router can't tell them apart. Keep one and a single parameter name.", false},
	"oas-parameters-duplicate":    {"MEDIUM", "Duplicate parameter", "A parameter (same name and `in`) is declared twice for one operation.", false},
	"oas-ref-unresolved":          {"MEDIUM", "Unresolved $ref", "The reference points at something that does not exist in this document; tools will fail or silently drop the schema.", false},
	"oas-ref-siblings":            {"MEDIUM", "Keywords next to $ref", "Before OpenAPI 3.1, everything beside a `$ref` is ignored. Wrap it in `allOf` or move the keywords into the referenced schema.", false},
	"oas-unused-component":        {"LOW", "Unused component", "Nothing references this component; remove it, or it will rot and mislead.", false},
	"oas-enum-duplicate":          {"MEDIUM", "Duplicate enum value", "Enum values must be unique.", false},
	"oas-enum-type":               {"LOW", "Enum value does not match the type", "Every enum value must be valid for the schema's `type`.", false},
	"oas-nullable-enum":           {"LOW", "Nullable enum without null", "A `nullable: true` enum must list `null` among its values, or null is rejected.", false},
	"oas-required-undefined":      {"LOW", "Required property is not defined", "`required` names a property that is not in `properties` (or any composed schema).", false},
	"oas-security-undefined":      {"MEDIUM", "Security requirement without a scheme", "The `security` entry names a scheme that is not defined under `securitySchemes`, so the operation is effectively unprotected.", false},
	"oas-unprotected-operation":   {"HIGH", "State-changing operation without security", "POST/PUT/PATCH/DELETE has no `security` (operation or global), so the spec says anyone may call it. Add a requirement, or `security: []` with a comment if it is deliberately public.", false},
	"oas-http-basic":              {"MEDIUM", "HTTP Basic authentication", "Basic sends the password on every request. Prefer OAuth2/OIDC or a signed token.", false},
	"oas-api-key-in-url":          {"HIGH", "Credential in the URL", "Keys, tokens and passwords in a query string end up in logs, browser history and Referer headers. Send them in a header.", false},
	"oas-oauth-flow":              {"MEDIUM", "Outdated OAuth2 flow", "The implicit and password flows are deprecated; use authorization code with PKCE (or client credentials for services).", false},
	"oas-auth-url-http":           {"MEDIUM", "Auth endpoint over plain HTTP", "OAuth/OpenID URLs must use https.", false},
	"oas-server-http":             {"MEDIUM", "Server URL uses http", "Production servers must be https; plain http exposes tokens and data.", false},
	"oas-server-style":            {"LOW", "Server URL style", "Server URLs should not end with `/` or point at example.com.", true},
	"oas-numeric-id":              {"MEDIUM", "Guessable numeric id", "Sequential integer ids in a URL invite enumeration (OWASP API1 BOLA); prefer UUIDs/opaque ids and check authorization per object.", false},
	"oas-limit-string":            {"LOW", "String without maxLength", "Unbounded strings in requests are a resource-exhaustion vector; set maxLength (or a format/enum).", true},
	"oas-limit-array":             {"LOW", "Array without maxItems", "Unbounded arrays in requests are a resource-exhaustion vector; set maxItems.", true},
	"oas-limit-integer":           {"LOW", "Integer without minimum/maximum", "Bound request integers with minimum and maximum.", true},
}

func (l *linter) add(id string, line int, detail string) {
	r, ok := rules[id]
	if !ok {
		return
	}
	key := fmt.Sprintf("%s|%d|%s", id, line, detail)
	if l.seen[key] {
		return
	}
	l.seen[key] = true
	l.out = append(l.out, Finding{RuleID: id, Rule: r.label, Message: r.msg, Detail: detail, Severity: r.sev, Line: line, Advisory: r.advisory})
}

type operation struct {
	path, method string
	item, op     *Node
	line         int // the line of the method key
}

func (o operation) name() string { return strings.ToUpper(o.method) + " " + o.path }

func (l *linter) operations() []operation {
	var ops []operation
	paths := l.d.Root.Get("paths")
	keys, vals := paths.Pairs()
	for i, p := range keys {
		item := vals[i]
		if item == nil || item.Kind != Map {
			continue
		}
		for _, m := range methods {
			if op := item.Get(m); op != nil && op.Kind == Map {
				ops = append(ops, operation{path: p, method: m, item: item, op: op, line: item.KeyLine(m)})
			}
		}
	}
	return ops
}

func (l *linter) run() {
	root := l.d.Root
	l.duplicateKeys(root)
	l.specShape()
	if root.Path("info") != nil && strings.TrimSpace(root.Path("info", "description").Str()) == "" {
		l.add("oas-info-description", root.KeyLine("info"), "")
	}
	ops := l.operations()
	l.paths(ops)
	l.operations2(ops)
	l.refs()
	l.enumsAndRequired()
	l.security(ops)
	l.servers()
	l.limits(ops)
}

func (l *linter) duplicateKeys(n *Node) {
	if n == nil {
		return
	}
	for _, d := range n.Dups {
		l.add("oas-duplicate-key", d.Line, d.Key)
	}
	for _, v := range n.Vals {
		l.duplicateKeys(v)
	}
}

// ---- paths ----

func (l *linter) paths(ops []operation) {
	paths := l.d.Root.Get("paths")
	keys, _ := paths.Pairs()
	shapes := map[string][]string{}
	for _, p := range keys {
		line := paths.KeyLine(p)
		if strings.Contains(p, "{}") {
			l.add("oas-path-params-empty", line, p)
		}
		if strings.Contains(p, "?") {
			l.add("oas-path-query", line, p)
		}
		if len(p) > 1 && strings.HasSuffix(p, "/") {
			l.add("oas-path-trailing-slash", line, p)
		}
		for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
			if seg == "" || strings.Contains(seg, "{") || strings.HasPrefix(seg, ":") {
				continue
			}
			if strings.ToLower(seg) != seg || strings.Contains(seg, "_") {
				l.add("oas-path-case", line, p)
			}
			if v := verbIn(seg); v != "" {
				l.add("oas-path-verb", line, p+" ("+v+")")
			}
		}
		shape := rePathVar.ReplaceAllString(p, "{}")
		shapes[shape] = append(shapes[shape], p)
	}
	for _, group := range shapes {
		if len(group) > 1 {
			sort.Strings(group)
			for _, p := range group[1:] {
				l.add("oas-path-ambiguous", paths.KeyLine(p), strings.Join(group, " vs "))
			}
		}
	}
	// path parameters per operation
	for _, o := range ops {
		declared := map[string]*Node{}
		var all []*Node
		for _, src := range []*Node{o.item.Get("parameters"), o.op.Get("parameters")} {
			for _, pn := range src.Items() {
				pn = l.resolve(pn)
				if pn == nil {
					continue
				}
				all = append(all, pn)
				if pn.Get("in").Str() == "path" {
					declared[pn.Get("name").Str()] = pn
				}
			}
		}
		inPath := map[string]bool{}
		for _, m := range rePathVar.FindAllStringSubmatch(o.path, -1) {
			name := m[1]
			if name == "" {
				continue
			}
			inPath[name] = true
			pn, ok := declared[name]
			switch {
			case !ok:
				l.add("oas-path-params", o.line, o.name()+": {"+name+"} is not declared")
			case !pn.Get("required").Bool():
				l.add("oas-path-params", pn.Line, o.name()+": {"+name+"} must be required: true")
			}
		}
		for name, pn := range declared {
			if !inPath[name] {
				l.add("oas-path-params", pn.Line, o.name()+": "+name+" is not in the path")
			}
		}
		seen := map[string]bool{}
		for _, pn := range all {
			k := pn.Get("in").Str() + ":" + pn.Get("name").Str()
			if pn.Get("name").Str() != "" && seen[k] {
				l.add("oas-parameters-duplicate", pn.Line, o.name()+": "+pn.Get("name").Str())
			}
			seen[k] = true
		}
	}
}

func verbIn(seg string) string {
	low := strings.ToLower(seg)
	for _, v := range []string{"get", "post", "put", "delete", "patch"} {
		if low == v || strings.HasPrefix(low, v+"-") || strings.HasPrefix(low, v+"_") || strings.HasSuffix(low, "-"+v) || strings.HasSuffix(low, "_"+v) {
			return v
		}
		if strings.HasPrefix(seg, v) && len(seg) > len(v) && seg[len(v)] >= 'A' && seg[len(v)] <= 'Z' { // getUsers
			return v
		}
	}
	return ""
}

// ---- operations ----

var reOpID = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

func (l *linter) operations2(ops []operation) {
	ids := map[string]string{}
	globalTags := map[string]bool{}
	for _, t := range l.d.Root.Get("tags").Items() {
		globalTags[t.Get("name").Str()] = true
	}
	for _, o := range ops {
		id := o.op.Get("operationId").Str()
		switch {
		case id == "":
			l.add("oas-operation-id-missing", o.line, o.name())
		default:
			if prev, dup := ids[id]; dup {
				l.add("oas-operation-id-duplicate", o.op.KeyLine("operationId"), id+" ("+prev+" and "+o.name()+")")
			} else {
				ids[id] = o.name()
			}
			if !reOpID.MatchString(id) {
				l.add("oas-operation-id-chars", o.op.KeyLine("operationId"), id)
			}
		}
		if strings.TrimSpace(o.op.Get("description").Str()) == "" && strings.TrimSpace(o.op.Get("summary").Str()) == "" {
			l.add("oas-operation-description", o.line, o.name())
		}
		tags := o.op.Get("tags").Items()
		if len(tags) == 0 {
			l.add("oas-operation-tags", o.line, o.name())
		} else if len(globalTags) > 0 {
			for _, t := range tags {
				if !globalTags[t.Str()] {
					l.add("oas-operation-tag-undefined", t.Line, o.name()+": "+t.Str())
				}
			}
		}
		l.responses(o)
		if (o.method == "get" || o.method == "delete") && (o.op.Has("requestBody") || l.hasBodyParam(o)) {
			l.add("oas-body-on-get-delete", o.op.KeyLine("requestBody"), o.name())
		}
	}
}

func (l *linter) hasBodyParam(o operation) bool {
	for _, pn := range o.op.Get("parameters").Items() {
		if pn = l.resolve(pn); pn != nil && pn.Get("in").Str() == "body" {
			return true
		}
	}
	return false
}

func (l *linter) responses(o operation) {
	resp := o.op.Get("responses")
	if resp == nil || resp.Kind != Map {
		l.add("oas-success-response", o.line, o.name())
		return
	}
	has2xx, has4xx := false, false
	for _, code := range resp.Keys {
		if strings.HasPrefix(code, "2") || strings.HasPrefix(code, "3") {
			has2xx = true
		}
		if strings.HasPrefix(code, "4") || strings.EqualFold(code, "default") {
			has4xx = true
		}
	}
	if !has2xx {
		l.add("oas-success-response", o.op.KeyLine("responses"), o.name())
	}
	if !has4xx {
		l.add("oas-error-response", o.op.KeyLine("responses"), o.name())
	}
}

// ---- references ----

func (l *linter) resolve(n *Node) *Node {
	for depth := 0; n != nil && n.Kind == Map && depth < 8; depth++ {
		ref := n.Get("$ref").Str()
		if ref == "" {
			return n
		}
		t := l.lookup(ref)
		if t == nil {
			return nil
		}
		n = t
	}
	return n
}

func (l *linter) lookup(ref string) *Node {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	n := l.d.Root
	for _, seg := range strings.Split(ref[2:], "/") {
		if u, err := url.PathUnescape(seg); err == nil {
			seg = u
		}
		seg = strings.ReplaceAll(strings.ReplaceAll(seg, "~1", "/"), "~0", "~")
		if n = n.Get(seg); n == nil {
			return nil
		}
	}
	return n
}

func (l *linter) refs() {
	used := map[string]bool{}
	var walk func(n *Node)
	walk = func(n *Node) {
		if n == nil {
			return
		}
		if n.Kind == Map {
			if ref := n.Get("$ref"); ref != nil && ref.Kind == Scalar {
				r := ref.Value
				used[r] = true
				if strings.HasPrefix(r, "#/") && l.lookup(r) == nil {
					l.add("oas-ref-unresolved", ref.Line, r)
				}
				if (l.d.v30 || l.d.V2) && len(n.Keys) > 1 {
					for i, k := range n.Keys {
						if k != "$ref" {
							l.add("oas-ref-siblings", n.KLines[i], r+" + "+k)
							break
						}
					}
				}
			}
		}
		for _, v := range n.Vals {
			walk(v)
		}
	}
	walk(l.d.Root)
	// unused components
	sections := []string{"schemas", "parameters", "responses", "requestBodies", "headers", "examples", "links", "callbacks"}
	base, prefix := l.d.Root.Get("components"), "#/components/"
	if l.d.V2 {
		for _, sec := range []string{"definitions", "parameters", "responses"} {
			c := l.d.Root.Get(sec)
			keys, _ := c.Pairs()
			for _, k := range keys {
				if !used["#/"+sec+"/"+k] {
					l.add("oas-unused-component", c.KeyLine(k), sec+"/"+k)
				}
			}
		}
		return
	}
	for _, sec := range sections {
		c := base.Get(sec)
		keys, _ := c.Pairs()
		for _, k := range keys {
			if !used[prefix+sec+"/"+k] && !strings.HasPrefix(k, "x-") {
				l.add("oas-unused-component", c.KeyLine(k), sec+"/"+k)
			}
		}
	}
}

// ---- schemas: enums and required ----

func (l *linter) enumsAndRequired() {
	var walk func(n *Node, key string)
	walk = func(n *Node, key string) {
		if n == nil {
			return
		}
		if n.Kind == Map && key != "example" && key != "examples" && key != "default" {
			if enum := n.Get("enum"); enum != nil && enum.Kind == Seq {
				seen := map[string]bool{}
				typ := n.Get("type").Str()
				hasNull := false
				for _, it := range enum.Vals {
					if it.Kind == Null || (it.Kind == Scalar && !it.Quoted && it.Value == "null") {
						hasNull = true
						continue
					}
					v := it.Str()
					if seen[v] {
						l.add("oas-enum-duplicate", it.Line, v)
					}
					seen[v] = true
					if typ != "" && !enumValueFits(typ, it) {
						l.add("oas-enum-type", it.Line, v+" is not "+typ)
					}
				}
				if n.Get("nullable").Bool() && !hasNull {
					l.add("oas-nullable-enum", n.KeyLine("enum"), "")
				}
			}
			if req := n.Get("required"); req != nil && req.Kind == Seq && n.Get("properties") != nil && !n.Has("allOf") && !n.Has("oneOf") && !n.Has("anyOf") {
				props := n.Get("properties")
				for _, r := range req.Vals {
					if !props.Has(r.Str()) {
						l.add("oas-required-undefined", r.Line, r.Str())
					}
				}
			}
		}
		for i, v := range n.Vals {
			k := ""
			if n.Kind == Map {
				k = n.Keys[i]
			}
			walk(v, k)
		}
	}
	walk(l.d.Root, "")
}

func enumValueFits(typ string, v *Node) bool {
	if v.Kind != Scalar {
		return false
	}
	switch typ {
	case "string":
		return v.Quoted || !looksNumberOrBool(v.Value)
	case "integer":
		return !v.Quoted && reInt.MatchString(v.Value)
	case "number":
		return !v.Quoted && reNum.MatchString(v.Value)
	case "boolean":
		return !v.Quoted && (v.Value == "true" || v.Value == "false")
	}
	return true
}

func looksNumberOrBool(s string) bool {
	return reNumOrBool.MatchString(s)
}

var (
	reInt       = regexp.MustCompile(`^-?\d+$`)
	reNum       = regexp.MustCompile(`^-?\d+(\.\d+)?([eE][-+]?\d+)?$`)
	reNumOrBool = regexp.MustCompile(`^(-?\d+(\.\d+)?|true|false)$`)
)

// ---- security ----

var reCredName = regexp.MustCompile(`(?i)^(api[-_]?key|apikey|access[-_]?token|token|password|passwd|secret|client[-_]?secret|auth|authorization)$`)

func (l *linter) securitySchemes() *Node {
	if l.d.V2 {
		return l.d.Root.Get("securityDefinitions")
	}
	return l.d.Root.Path("components", "securitySchemes")
}

func (l *linter) security(ops []operation) {
	schemes := l.securitySchemes()
	keys, vals := schemes.Pairs()
	for i, name := range keys {
		s := vals[i]
		typ := s.Get("type").Str()
		line := schemes.KeyLine(name)
		switch {
		case typ == "http" && strings.EqualFold(s.Get("scheme").Str(), "basic"), typ == "basic":
			l.add("oas-http-basic", line, name)
		case typ == "apiKey" && s.Get("in").Str() == "query":
			l.add("oas-api-key-in-url", line, name+" (query)")
		}
		flows := s.Get("flows")
		if l.d.V2 && typ == "oauth2" {
			if f := s.Get("flow").Str(); f == "implicit" || f == "password" {
				l.add("oas-oauth-flow", line, name+": "+f)
			}
			l.authURL(s.Get("authorizationUrl"), name)
			l.authURL(s.Get("tokenUrl"), name)
		}
		fk, fv := flows.Pairs()
		for j, fname := range fk {
			if fname == "implicit" || fname == "password" {
				l.add("oas-oauth-flow", flows.KeyLine(fname), name+": "+fname)
			}
			for _, u := range []string{"authorizationUrl", "tokenUrl", "refreshUrl"} {
				l.authURL(fv[j].Get(u), name)
			}
		}
		l.authURL(s.Get("openIdConnectUrl"), name)
	}
	globalSec := l.d.Root.Get("security")
	l.checkRequirements(globalSec, schemes)
	hasGlobal := len(globalSec.Items()) > 0
	for _, o := range ops {
		opSec := o.op.Get("security")
		l.checkRequirements(opSec, schemes)
		// Only when the spec defines security schemes at all: a document with none
		// leaves auth to a gateway, and flagging every POST there would be noise.
		if unsafeM[o.method] && !hasGlobal && opSec == nil && schemes != nil && len(schemes.Keys) > 0 {
			l.add("oas-unprotected-operation", o.line, o.name())
		}
		// credentials in the URL, numeric ids
		for _, src := range []*Node{o.item.Get("parameters"), o.op.Get("parameters")} {
			for _, pn := range src.Items() {
				pn = l.resolve(pn)
				if pn == nil {
					continue
				}
				name, in := pn.Get("name").Str(), pn.Get("in").Str()
				if in == "query" && reCredName.MatchString(name) {
					l.add("oas-api-key-in-url", pn.Line, o.name()+": "+name)
				}
				if (in == "path" || in == "query") && isIDName(name) && l.paramIsInteger(pn) {
					l.add("oas-numeric-id", pn.Line, o.name()+": "+name)
				}
			}
		}
	}
}

func (l *linter) authURL(n *Node, scheme string) {
	if v := n.Str(); strings.HasPrefix(strings.ToLower(v), "http://") {
		l.add("oas-auth-url-http", n.Line, scheme+": "+v)
	}
}

func (l *linter) checkRequirements(sec *Node, schemes *Node) {
	for _, req := range sec.Items() {
		keys, _ := req.Pairs()
		for _, name := range keys {
			if !schemes.Has(name) {
				l.add("oas-security-undefined", req.KeyLine(name), name)
			}
		}
	}
}

func isIDName(n string) bool {
	low := strings.ToLower(n)
	return low == "id" || strings.HasSuffix(low, "_id") || strings.HasSuffix(low, "-id") || (strings.HasSuffix(n, "Id") && len(n) > 2)
}

func (l *linter) paramIsInteger(pn *Node) bool {
	typ := pn.Get("type").Str()
	if s := l.resolve(pn.Get("schema")); s != nil {
		typ = s.Get("type").Str()
	}
	return typ == "integer"
}

func (l *linter) servers() {
	if l.d.V2 {
		for _, s := range l.d.Root.Get("schemes").Items() {
			if s.Str() == "http" && len(l.d.Root.Get("schemes").Items()) == 1 {
				l.add("oas-server-http", s.Line, "schemes: [http]")
			}
		}
		return
	}
	for _, s := range l.d.Root.Get("servers").Items() {
		u := s.Get("url")
		v := u.Str()
		low := strings.ToLower(v)
		if strings.HasPrefix(low, "http://") && !isLocalHost(low) {
			l.add("oas-server-http", u.Line, v)
		}
		if strings.HasSuffix(v, "/") && len(v) > 8 || strings.Contains(low, "example.com") {
			l.add("oas-server-style", u.Line, v)
		}
	}
}

func isLocalHost(u string) bool {
	for _, h := range []string{"localhost", "127.0.0.1", "0.0.0.0", "[::1]", ".local", "host.docker.internal"} {
		if strings.Contains(u, h) {
			return true
		}
	}
	return false
}

// ---- request-side limits (OWASP API4) ----

func (l *linter) limits(ops []operation) {
	for _, o := range ops {
		var roots []*Node
		for _, src := range []*Node{o.item.Get("parameters"), o.op.Get("parameters")} {
			for _, pn := range src.Items() {
				if pn = l.resolve(pn); pn != nil && (pn.Get("in").Str() == "query" || pn.Get("in").Str() == "header") {
					if s := pn.Get("schema"); s != nil {
						roots = append(roots, s)
					} else {
						roots = append(roots, pn)
					}
				}
			}
		}
		if rb := l.resolve(o.op.Get("requestBody")); rb != nil {
			ck, cv := rb.Get("content").Pairs()
			for i := range ck {
				if s := cv[i].Get("schema"); s != nil {
					roots = append(roots, s)
				}
			}
		}
		visited := map[*Node]bool{}
		for _, r := range roots {
			l.limitSchema(r, o, 0, visited)
		}
	}
}

func (l *linter) limitSchema(n *Node, o operation, depth int, visited map[*Node]bool) {
	n = l.resolve(n)
	if n == nil || n.Kind != Map || depth > 6 || visited[n] {
		return
	}
	visited[n] = true
	switch n.Get("type").Str() {
	case "string":
		if !n.Has("maxLength") && !n.Has("enum") && !n.Has("format") && !n.Has("pattern") && !n.Has("const") {
			l.add("oas-limit-string", n.Line, o.name())
		}
	case "array":
		if !n.Has("maxItems") {
			l.add("oas-limit-array", n.Line, o.name())
		}
		l.limitSchema(n.Get("items"), o, depth+1, visited)
	case "integer":
		if !(n.Has("minimum") || n.Has("exclusiveMinimum")) || !(n.Has("maximum") || n.Has("exclusiveMaximum")) {
			l.add("oas-limit-integer", n.Line, o.name())
		}
	}
	pk, pv := n.Get("properties").Pairs()
	for i := range pk {
		l.limitSchema(pv[i], o, depth+1, visited)
	}
	for _, c := range []string{"allOf", "oneOf", "anyOf"} {
		for _, s := range n.Get(c).Items() {
			l.limitSchema(s, o, depth+1, visited)
		}
	}
}
