package openapi

import (
	"regexp"
	"strings"
)

// spec.go checks a document against the *shape* of the OpenAPI object model — the
// structural half of vacuum's oas2/oas3-schema rules (which validate against the
// official JSON Schemas): required fields, unknown (usually mistyped) keys, value
// types, and the closed vocabularies (`in`, `style`, security `type`, response
// codes). It is table-driven so one walker serves Swagger 2.0, OpenAPI 3.0 and
// 3.1. Schema Objects themselves are checked in schema.go.

type fkind int

const (
	kAny    fkind = iota // anything
	kStr                 // string
	kBool                // boolean
	kNum                 // number / integer
	kMap                 // free-form mapping
	kSeq                 // free-form sequence
	kSeqStr              // sequence of strings
	kObj                 // an object of the named definition
	kMapOf               // mapping whose values are objects of the named definition
	kSeqOf               // sequence of objects of the named definition
	kSchema              // a Schema Object
	kSchemaMap
)

type fdef struct {
	kind fkind
	obj  string
	enum []string
}

type odef struct {
	fields   map[string]fdef
	required []string
	// closedExt reports that unknown keys that don't start with x- are errors
	open bool // accept any key (free-form objects)
}

func s(k fkind) fdef           { return fdef{kind: k} }
func o(name string) fdef       { return fdef{kind: kObj, obj: name} }
func mapOf(name string) fdef   { return fdef{kind: kMapOf, obj: name} }
func seqOf(name string) fdef   { return fdef{kind: kSeqOf, obj: name} }
func enum(vals ...string) fdef { return fdef{kind: kStr, enum: vals} }
func f(pairs ...any) map[string]fdef { // f("name", s(kStr), …)
	m := map[string]fdef{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i].(string)] = pairs[i+1].(fdef)
	}
	return m
}

var oas3Defs = map[string]odef{
	"Root": {fields: f("openapi", s(kStr), "info", o("Info"), "servers", seqOf("Server"), "paths", o("Paths"), "components", o("Components"),
		"security", s(kSeq), "tags", seqOf("Tag"), "externalDocs", o("ExternalDocs"), "webhooks", mapOf("PathItem"), "jsonSchemaDialect", s(kStr)),
		required: []string{"openapi", "info"}},
	"Info": {fields: f("title", s(kStr), "version", s(kStr), "summary", s(kStr), "description", s(kStr), "termsOfService", s(kStr), "contact", o("Contact"), "license", o("License")),
		required: []string{"title", "version"}},
	"Contact":        {fields: f("name", s(kStr), "url", s(kStr), "email", s(kStr))},
	"License":        {fields: f("name", s(kStr), "url", s(kStr), "identifier", s(kStr)), required: []string{"name"}},
	"Server":         {fields: f("url", s(kStr), "description", s(kStr), "variables", mapOf("ServerVariable")), required: []string{"url"}},
	"ServerVariable": {fields: f("enum", s(kSeqStr), "default", s(kStr), "description", s(kStr)), required: []string{"default"}},
	"Paths":          {open: true},
	"PathItem": {fields: f("$ref", s(kStr), "summary", s(kStr), "description", s(kStr), "get", o("Operation"), "put", o("Operation"), "post", o("Operation"),
		"delete", o("Operation"), "options", o("Operation"), "head", o("Operation"), "patch", o("Operation"), "trace", o("Operation"),
		"servers", seqOf("Server"), "parameters", seqOf("Parameter"))},
	"Operation": {fields: f("tags", s(kSeqStr), "summary", s(kStr), "description", s(kStr), "externalDocs", o("ExternalDocs"), "operationId", s(kStr),
		"parameters", seqOf("Parameter"), "requestBody", o("RequestBody"), "responses", o("Responses"), "callbacks", mapOf("Callback"),
		"deprecated", s(kBool), "security", s(kSeq), "servers", seqOf("Server")), required: []string{"responses"}},
	"Parameter": {fields: f("name", s(kStr), "in", enum("query", "header", "path", "cookie"), "description", s(kStr), "required", s(kBool), "deprecated", s(kBool),
		"allowEmptyValue", s(kBool), "style", enum("matrix", "label", "form", "simple", "spaceDelimited", "pipeDelimited", "deepObject"), "explode", s(kBool),
		"allowReserved", s(kBool), "schema", s(kSchema), "example", s(kAny), "examples", mapOf("Example"), "content", mapOf("MediaType")),
		required: []string{"name", "in"}},
	"RequestBody": {fields: f("description", s(kStr), "content", mapOf("MediaType"), "required", s(kBool)), required: []string{"content"}},
	"MediaType":   {fields: f("schema", s(kSchema), "example", s(kAny), "examples", mapOf("Example"), "encoding", mapOf("Encoding"))},
	"Encoding":    {fields: f("contentType", s(kStr), "headers", mapOf("Header"), "style", s(kStr), "explode", s(kBool), "allowReserved", s(kBool))},
	"Responses":   {open: true},
	"Response":    {fields: f("description", s(kStr), "headers", mapOf("Header"), "content", mapOf("MediaType"), "links", mapOf("Link")), required: []string{"description"}},
	"Header": {fields: f("description", s(kStr), "required", s(kBool), "deprecated", s(kBool), "allowEmptyValue", s(kBool),
		"style", enum("simple"), "explode", s(kBool), "allowReserved", s(kBool), "schema", s(kSchema), "example", s(kAny), "examples", mapOf("Example"), "content", mapOf("MediaType"))},
	"Link":     {fields: f("operationRef", s(kStr), "operationId", s(kStr), "parameters", s(kMap), "requestBody", s(kAny), "description", s(kStr), "server", o("Server"))},
	"Example":  {fields: f("summary", s(kStr), "description", s(kStr), "value", s(kAny), "externalValue", s(kStr))},
	"Callback": {open: true},
	"Components": {fields: f("schemas", fdef{kind: kSchemaMap}, "responses", mapOf("Response"), "parameters", mapOf("Parameter"), "examples", mapOf("Example"),
		"requestBodies", mapOf("RequestBody"), "headers", mapOf("Header"), "securitySchemes", mapOf("SecurityScheme"), "links", mapOf("Link"),
		"callbacks", mapOf("Callback"), "pathItems", mapOf("PathItem"))},
	"SecurityScheme": {fields: f("type", enum("apiKey", "http", "oauth2", "openIdConnect", "mutualTLS"), "description", s(kStr), "name", s(kStr),
		"in", enum("query", "header", "cookie"), "scheme", s(kStr), "bearerFormat", s(kStr), "flows", o("OAuthFlows"), "openIdConnectUrl", s(kStr)),
		required: []string{"type"}},
	"OAuthFlows":   {fields: f("implicit", o("OAuthFlow"), "password", o("OAuthFlow"), "clientCredentials", o("OAuthFlow"), "authorizationCode", o("OAuthFlow"))},
	"OAuthFlow":    {fields: f("authorizationUrl", s(kStr), "tokenUrl", s(kStr), "refreshUrl", s(kStr), "scopes", s(kMap)), required: []string{"scopes"}},
	"Tag":          {fields: f("name", s(kStr), "description", s(kStr), "externalDocs", o("ExternalDocs")), required: []string{"name"}},
	"ExternalDocs": {fields: f("description", s(kStr), "url", s(kStr)), required: []string{"url"}},
}

var oas2Defs = map[string]odef{
	"Root": {fields: f("swagger", s(kStr), "info", o("Info"), "host", s(kStr), "basePath", s(kStr), "schemes", s(kSeqStr), "consumes", s(kSeqStr), "produces", s(kSeqStr),
		"paths", o("Paths"), "definitions", fdef{kind: kSchemaMap}, "parameters", mapOf("Parameter"), "responses", mapOf("Response"),
		"securityDefinitions", mapOf("SecurityScheme"), "security", s(kSeq), "tags", seqOf("Tag"), "externalDocs", o("ExternalDocs")),
		required: []string{"swagger", "info", "paths"}},
	"Info":    oas3Defs["Info"],
	"Contact": oas3Defs["Contact"],
	"License": oas3Defs["License"],
	"Paths":   {open: true},
	"PathItem": {fields: f("$ref", s(kStr), "get", o("Operation"), "put", o("Operation"), "post", o("Operation"), "delete", o("Operation"),
		"options", o("Operation"), "head", o("Operation"), "patch", o("Operation"), "parameters", seqOf("Parameter"))},
	"Operation": {fields: f("tags", s(kSeqStr), "summary", s(kStr), "description", s(kStr), "externalDocs", o("ExternalDocs"), "operationId", s(kStr),
		"consumes", s(kSeqStr), "produces", s(kSeqStr), "parameters", seqOf("Parameter"), "responses", o("Responses"), "schemes", s(kSeqStr),
		"deprecated", s(kBool), "security", s(kSeq)), required: []string{"responses"}},
	"Parameter": {fields: f("name", s(kStr), "in", enum("query", "header", "path", "formData", "body"), "description", s(kStr), "required", s(kBool), "schema", s(kSchema),
		"type", s(kStr), "format", s(kStr), "allowEmptyValue", s(kBool), "items", s(kMap), "collectionFormat", s(kStr), "default", s(kAny), "maximum", s(kNum),
		"exclusiveMaximum", s(kBool), "minimum", s(kNum), "exclusiveMinimum", s(kBool), "maxLength", s(kNum), "minLength", s(kNum), "pattern", s(kStr),
		"maxItems", s(kNum), "minItems", s(kNum), "uniqueItems", s(kBool), "enum", s(kSeq), "multipleOf", s(kNum)), required: []string{"name", "in"}},
	"Responses": {open: true},
	"Response":  {fields: f("description", s(kStr), "schema", s(kSchema), "headers", s(kMap), "examples", s(kMap)), required: []string{"description"}},
	"SecurityScheme": {fields: f("type", enum("basic", "apiKey", "oauth2"), "description", s(kStr), "name", s(kStr), "in", enum("query", "header"),
		"flow", enum("implicit", "password", "application", "accessCode"), "authorizationUrl", s(kStr), "tokenUrl", s(kStr), "scopes", s(kMap)), required: []string{"type"}},
	"Tag":          oas3Defs["Tag"],
	"ExternalDocs": oas3Defs["ExternalDocs"],
}

var reResponseCode = regexp.MustCompile(`^(?:[1-5][0-9]{2}|[1-5]XX|default)$`)

type specWalker struct {
	l    *linter
	defs map[string]odef
	v31  bool
}

func (l *linter) specShape() {
	w := &specWalker{l: l, defs: oas3Defs, v31: strings.HasPrefix(l.d.Ver, "3.1")}
	if l.d.V2 {
		w.defs = oas2Defs
	}
	root := l.d.Root
	w.object("Root", root, "")
	if !l.d.V2 && !w.v31 && root.Get("paths") == nil {
		l.add("oas-spec-required", root.Line, "paths (required in OpenAPI 3.0)")
	}
	if w.v31 && root.Get("paths") == nil && root.Get("components") == nil && root.Get("webhooks") == nil {
		l.add("oas-spec-required", root.Line, "one of paths, components or webhooks (OpenAPI 3.1)")
	}
}

// object validates n as the named definition; n may be a $ref (then it is skipped).
func (w *specWalker) object(name string, n *Node, where string) {
	if n == nil {
		return
	}
	if n.Kind != Map {
		if n.Kind != Null {
			w.l.add("oas-spec-type", n.Line, where+" must be an object")
		}
		return
	}
	if n.Has("$ref") && name != "Root" && name != "Components" {
		return // Reference Object
	}
	def := w.defs[name]
	switch name {
	case "Paths":
		for i, k := range n.Keys {
			if !strings.HasPrefix(k, "/") && !strings.HasPrefix(k, "x-") {
				w.l.add("oas-spec-path-key", n.KLines[i], k)
				continue
			}
			w.object("PathItem", n.Vals[i], "paths."+k)
		}
		return
	case "Responses":
		for i, k := range n.Keys {
			if strings.HasPrefix(k, "x-") {
				continue
			}
			if !reResponseCode.MatchString(k) {
				w.l.add("oas-spec-response-code", n.KLines[i], k)
				continue
			}
			w.object("Response", n.Vals[i], "response "+k)
		}
		return
	case "Callback":
		for i, k := range n.Keys {
			if !strings.HasPrefix(k, "x-") {
				w.object("PathItem", n.Vals[i], "callback "+k)
			}
		}
		return
	}
	for _, req := range def.required {
		if !n.Has(req) {
			w.l.add("oas-spec-required", n.Line, name+"."+req)
		}
	}
	for i, k := range n.Keys {
		if strings.HasPrefix(k, "x-") {
			continue
		}
		fd, known := def.fields[k]
		if !known {
			if !def.open {
				w.l.add("oas-spec-unknown", n.KLines[i], name+"."+k)
			}
			continue
		}
		w.field(fd, n.Vals[i], n.KLines[i], name+"."+k)
	}
	if name == "SecurityScheme" {
		w.securityScheme(n)
	}
	if name == "Parameter" && !w.l.d.V2 && n.Has("schema") && n.Has("content") {
		w.l.add("oas-spec-type", n.KeyLine("content"), "Parameter: schema and content are mutually exclusive")
	}
}

func (w *specWalker) securityScheme(n *Node) {
	need := map[string][]string{"apiKey": {"name", "in"}, "http": {"scheme"}, "oauth2": {"flows"}, "openIdConnect": {"openIdConnectUrl"}}
	if w.l.d.V2 {
		need = map[string][]string{"apiKey": {"name", "in"}, "oauth2": {"flow", "scopes"}}
	}
	for _, r := range need[n.Get("type").Str()] {
		if !n.Has(r) {
			w.l.add("oas-spec-required", n.Line, "SecurityScheme("+n.Get("type").Str()+")."+r)
		}
	}
}

func (w *specWalker) field(fd fdef, v *Node, line int, where string) {
	if v == nil {
		return
	}
	wrong := func(want string) {
		w.l.add("oas-spec-type", line, where+" must be "+want)
	}
	switch fd.kind {
	case kStr:
		if v.Kind == Null {
			return
		}
		if v.Kind != Scalar {
			wrong("a string")
			return
		}
		if len(fd.enum) > 0 {
			ok := false
			for _, e := range fd.enum {
				if e == v.Value {
					ok = true
				}
			}
			if !ok {
				w.l.add("oas-spec-enum", line, where+": `"+v.Value+"` (allowed: "+strings.Join(fd.enum, ", ")+")")
			}
		}
	case kBool:
		if v.Kind != Scalar || v.Quoted || (v.Value != "true" && v.Value != "false") {
			if v.Kind != Null {
				wrong("a boolean")
			}
		}
	case kNum:
		if v.Kind != Scalar || v.Quoted || !reNum.MatchString(v.Value) {
			if v.Kind != Null {
				wrong("a number")
			}
		}
	case kMap:
		if v.Kind != Map && v.Kind != Null {
			wrong("an object")
		}
	case kSeq:
		if v.Kind != Seq && v.Kind != Null {
			wrong("a list")
		}
	case kSeqStr:
		if v.Kind != Seq {
			if v.Kind != Null {
				wrong("a list of strings")
			}
			return
		}
		for _, it := range v.Vals {
			if it.Kind != Scalar {
				w.l.add("oas-spec-type", it.Line, where+" must contain only strings")
				break
			}
		}
	case kObj:
		w.object(fd.obj, v, where)
	case kMapOf:
		if v.Kind != Map {
			if v.Kind != Null {
				wrong("an object")
			}
			return
		}
		for i, k := range v.Keys {
			if !strings.HasPrefix(k, "x-") {
				w.object(fd.obj, v.Vals[i], where+"."+k)
			}
		}
	case kSeqOf:
		if v.Kind != Seq {
			if v.Kind != Null {
				wrong("a list")
			}
			return
		}
		for i, it := range v.Vals {
			w.object(fd.obj, it, where+"["+itoa(i)+"]")
		}
	case kSchema:
		w.l.schemaTree(v, where)
	case kSchemaMap:
		if v.Kind == Map {
			for i, k := range v.Keys {
				if !strings.HasPrefix(k, "x-") {
					w.l.schemaTree(v.Vals[i], where+"."+k)
				}
			}
		}
	}
}
