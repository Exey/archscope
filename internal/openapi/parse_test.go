package openapi

import "testing"

const sampleYAML = `openapi: 3.0.3   # version
info:
  title: "Pets: API"
  description: >
    A long
    description
  version: '1.0'
servers:
  - url: https://api.example.com/v1
  - url: http://localhost:8080
tags: [pets, {name: store, description: "S"}]
paths:
  /pets/{petId}:
    get:
      operationId: getPet
      parameters:
        - name: petId
          in: path
          required: true
          schema: {type: integer, format: int64}
        - $ref: '#/components/parameters/Limit'
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Pet'
        default:
          description: plain
            continued here
components:
  schemas:
    Pet:
      type: object
      required:
      - id
      properties:
        id: {type: integer}
        name:
          type: string
          enum: [a, b, a]
          example: |
            line1
            line2
  parameters:
    Limit:
      name: limit
      in: query
      schema:
        type: integer
`

func TestParseYAMLStructureAndLines(t *testing.T) {
	root, err := Parse(sampleYAML)
	if err != nil {
		t.Fatal(err)
	}
	if root.Get("openapi").Str() != "3.0.3" || root.Path("info", "title").Str() != "Pets: API" {
		t.Errorf("scalars: %q %q", root.Get("openapi").Str(), root.Path("info", "title").Str())
	}
	if got := root.Path("info", "description").Str(); got != "A long description" {
		t.Errorf("folded scalar = %q", got)
	}
	if v := root.Path("info", "version"); v.Str() != "1.0" || !v.Quoted {
		t.Errorf("quoted version: %+v", v)
	}
	if n := len(root.Get("servers").Items()); n != 2 {
		t.Errorf("servers = %d", n)
	}
	tags := root.Get("tags").Items()
	if len(tags) != 2 || tags[1].Get("name").Str() != "store" {
		t.Errorf("flow tags: %+v", tags)
	}
	get := root.Path("paths", "/pets/{petId}", "get")
	if get == nil || get.Line != 15 || root.Path("paths", "/pets/{petId}").KeyLine("get") != 14 {
		t.Fatalf("get op: %+v", get)
	}
	ps := get.Get("parameters").Items()
	if len(ps) != 2 || ps[0].Get("in").Str() != "path" || ps[1].Get("$ref").Str() != "#/components/parameters/Limit" {
		t.Errorf("parameters: %+v", ps)
	}
	if ps[0].Path("schema", "format").Str() != "int64" {
		t.Error("flow map inside block map")
	}
	if d := get.Path("responses", "default", "description").Str(); d != "plain continued here" {
		t.Errorf("plain continuation = %q", d)
	}
	req := root.Path("components", "schemas", "Pet", "required").Items()
	if len(req) != 1 || req[0].Str() != "id" {
		t.Errorf("un-indented sequence under key: %+v", req)
	}
	enum := root.Path("components", "schemas", "Pet", "properties", "name", "enum").Items()
	if len(enum) != 3 {
		t.Errorf("flow seq enum = %d", len(enum))
	}
	if ex := root.Path("components", "schemas", "Pet", "properties", "name", "example").Str(); ex != "line1\nline2" {
		t.Errorf("literal block = %q", ex)
	}
	if l := root.Path("components", "parameters", "Limit").Line; l != 48 || root.Path("components", "parameters").KeyLine("Limit") != 47 {
		t.Errorf("Limit starts at line %d (key line %d)", l, root.Path("components", "parameters").KeyLine("Limit"))
	}
}

func TestParseJSONWithLines(t *testing.T) {
	src := "{\n  \"openapi\": \"3.0.0\",\n  \"paths\": {\n    \"/a\": {\n      \"get\": {\"operationId\": \"a\", \"responses\": {\"200\": {\"description\": \"ok\"}}}\n    }\n  }\n}\n"
	root, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	op := root.Path("paths", "/a", "get")
	if op == nil || op.Line != 5 || op.Get("operationId").Str() != "a" {
		t.Fatalf("op = %+v", op)
	}
	if root.Path("paths", "/a").Line != 4 {
		t.Error("line of /a")
	}
}

func TestParseDuplicateKeys(t *testing.T) {
	root, _ := Parse("paths:\n  /a:\n    get: {}\n  /b: {}\n  /a:\n    post: {}\n")
	p := root.Get("paths")
	if len(p.Dups) != 1 || p.Dups[0].Key != "/a" || p.Dups[0].Line != 5 {
		t.Errorf("dups = %+v", p.Dups)
	}
}
