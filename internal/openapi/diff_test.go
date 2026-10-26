package openapi

import (
	"strings"
	"testing"
)

const diffOld = `openapi: 3.0.3
info: {title: T, version: '1'}
paths:
  /pets:
    get:
      operationId: listPets
      parameters:
        - {name: limit, in: query, schema: {type: integer}}
        - {name: kind, in: query, schema: {type: string}}
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: array
                items: {$ref: '#/components/schemas/Pet'}
        '404': {description: nf}
    post:
      operationId: createPet
      requestBody:
        required: false
        content:
          application/json:
            schema: {$ref: '#/components/schemas/NewPet'}
      responses:
        '201': {description: c}
  /owners:
    get:
      operationId: listOwners
      responses:
        '200': {description: ok}
components:
  schemas:
    Pet:
      type: object
      required: [id, name]
      properties:
        id: {type: integer}
        name: {type: string}
        status: {type: string, enum: [a, b]}
        tag: {type: string}
    NewPet:
      type: object
      properties:
        name: {type: string, maxLength: 50}
        kind: {type: string, enum: [dog, cat, bird]}
`

const diffNew = `openapi: 3.0.3
info: {title: T, version: '1'}
paths:
  /pets:
    get:
      operationId: listPets
      parameters:
        - {name: limit, in: query, schema: {type: string}}
        - {name: kind, in: query, schema: {type: string}}
        - {name: owner, in: query, required: true, schema: {type: string}}
        - {name: page, in: query, schema: {type: integer}}
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: array
                items: {$ref: '#/components/schemas/Pet'}
    post:
      operationId: addPet
      requestBody:
        required: true
        content:
          application/json:
            schema: {$ref: '#/components/schemas/NewPet'}
      responses:
        '201': {description: c}
  /pets/{id}:
    delete:
      operationId: deletePet
      parameters:
        - {name: id, in: path, required: true, schema: {type: string}}
      responses:
        '204': {description: gone}
components:
  schemas:
    Pet:
      type: object
      required: [id]
      properties:
        id: {type: string}
        name: {type: string}
        status: {type: string, enum: [a, b, c]}
    NewPet:
      type: object
      required: [name]
      properties:
        name: {type: string, maxLength: 20}
        kind: {type: string, enum: [dog, cat]}
`

func hasChange(cs []Change, level, rule, sub string) bool {
	for _, c := range cs {
		if c.Level == level && c.Rule == rule && strings.Contains(c.Detail, sub) {
			return true
		}
	}
	return false
}

func TestDiffClassifiesChanges(t *testing.T) {
	cs, ok := Diff(diffOld, diffNew)
	if !ok {
		t.Fatal("not a spec")
	}
	for _, w := range []struct{ level, rule, sub string }{
		{lvBreaking, "Path removed", "GET /owners"},
		{lvBreaking, "Required parameter added", "`owner`"},
		{lvBreaking, "Type changed", "`integer` → `string`"},
		{lvBreaking, "Response property removed", "`tag`"},
		{lvBreaking, "Property no longer guaranteed", "`name`"},
		{lvWarning, "Response enum value added", "`c`"},
		{lvBreaking, "Request body became required", "POST /pets"},
		{lvBreaking, "Request validation tightened", "`maxLength` 50 → 20"},
		{lvBreaking, "Request enum value removed", "`bird`"},
		{lvBreaking, "Property became required", "`name`"},
		{lvWarning, "operationId changed", "createPet"},
		{lvInfo, "Optional parameter added", "`page`"},
		{lvInfo, "Operation added", "DELETE /pets/{id}"},
		{lvInfo, "Response removed", "response 404"},
	} {
		if !hasChange(cs, w.level, w.rule, w.sub) {
			t.Errorf("missing %s %q containing %q in:\n%s", w.level, w.rule, w.sub, dump(cs))
		}
	}
	if cs[0].Level != lvBreaking || cs[len(cs)-1].Level != lvInfo {
		t.Errorf("breaking changes come first, info last:\n%s", dump(cs))
	}
	for _, c := range cs {
		if c.Line <= 0 {
			t.Errorf("change without a line: %+v", c)
		}
	}
}

func dump(cs []Change) string {
	var b strings.Builder
	for _, c := range cs {
		b.WriteString("  " + c.Level + " | " + c.Rule + " | " + c.Detail + " @" + itoa(c.Line) + "\n")
	}
	return b.String()
}

func TestDiffOfIdenticalSpecsIsEmpty(t *testing.T) {
	cs, ok := Diff(diffOld, diffOld)
	if !ok || len(cs) != 0 {
		t.Errorf("identical specs differ: %v", dump(cs))
	}
}

func TestDiffIgnoresCompatibleWidening(t *testing.T) {
	old := "openapi: 3.0.3\ninfo: {title: T, version: '1'}\npaths:\n  /a:\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema:\n              type: object\n              required: [x]\n              properties:\n                x: {type: integer, maximum: 5, enum: [1, 2]}\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json:\n              schema: {type: object, required: [y], properties: {y: {type: string, nullable: true}}}\n"
	new := strings.NewReplacer("type: integer, maximum: 5, enum: [1, 2]", "type: number, maximum: 9, enum: [1, 2, 3]", "required: [x]", "required: []").Replace(old)
	cs, _ := Diff(old, new)
	for _, c := range cs {
		if c.Level != lvInfo {
			t.Errorf("a request that accepts more is not breaking: %+v", c)
		}
	}
}

func TestDiffNotASpec(t *testing.T) {
	if _, ok := Diff("a: 1\n", diffOld); ok {
		t.Error("a non-spec is not diffable")
	}
}

func TestDiffSwagger2(t *testing.T) {
	old := "swagger: '2.0'\ninfo: {title: T, version: '1'}\npaths:\n  /a:\n    get:\n      parameters:\n        - {name: q, in: query, type: string}\n      responses:\n        '200': {description: ok, schema: {type: object, properties: {id: {type: integer}, n: {type: string}}}}\n"
	new := strings.NewReplacer("{name: q, in: query, type: string}", "{name: q, in: query, type: string, required: true}", "n: {type: string}", "").Replace(old)
	cs, ok := Diff(old, new)
	if !ok {
		t.Fatal("swagger 2 should diff")
	}
	if !hasChange(cs, lvBreaking, "Parameter became required", "`q`") || !hasChange(cs, lvBreaking, "Response property removed", "`n`") {
		t.Errorf("swagger 2 changes missing:\n%s", dump(cs))
	}
}

func inlineModelSpec(model string) string {
	ep := func(path string) string {
		return "  " + path + ":\n    get:\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json:\n              schema:\n                $ref: '#/components/schemas/Resp" + strings.NewReplacer("/", "", "{", "", "}", "").Replace(path) + "'\n"
	}
	resp := func(n string) string {
		return "    Resp" + n + ":\n      type: object\n      properties:\n        model:\n" + model
	}
	return "openapi: 3.0.3\ninfo: {title: T, version: '1'}\npaths:\n" + ep("/threads") + ep("/threads/one") + ep("/threads/two") +
		"components:\n  schemas:\n" + resp("threads") + resp("threadsone") + resp("threadstwo") +
		"    Model:\n      type: object\n      required: [id]\n      properties:\n        id: {type: string}\n        title: {type: string}\n        description: {type: string}\n"
}

// An inline object that becomes allOf + $ref (and nullable) is ONE nullable
// change and ONE verified refactor — not a removed property per field per endpoint.
func TestDiffGroupsByRootCauseAndFlattensRefs(t *testing.T) {
	inline := "          type: object\n          required: [id]\n          properties:\n            id: {type: string}\n            title: {type: string}\n            description: {type: string}\n"
	wrapped := "          nullable: true\n          allOf:\n            - $ref: '#/components/schemas/Model'\n"
	cs, ok := Diff(inlineModelSpec(inline), inlineModelSpec(wrapped))
	if !ok {
		t.Fatal("not a spec")
	}
	br, _, rf, _, _ := ChangeCounts(cs)
	if br != 1 {
		t.Errorf("want exactly 1 breaking change (nullable), got %d:\n%s", br, dump(cs))
	}
	if rf == 0 {
		t.Errorf("want the inline → allOf/$ref refactor reported as verified:\n%s", dump(cs))
	}
	for _, c := range cs {
		if c.Rule == "Response property removed" || c.Rule == "Composition changed" {
			t.Errorf("false report survived flattening: %+v", c)
		}
		if c.Rule == "Now nullable" {
			if len(c.Places) != 3 || c.Question == "" {
				t.Errorf("nullable should list its 3 places and a question: %+v", c)
			}
		}
	}

	// a genuinely removed property still is breaking, once
	dropped := strings.Replace(inline, "            description: {type: string}\n", "", 1)
	cs, _ = Diff(inlineModelSpec(inline), inlineModelSpec(dropped))
	n := 0
	for _, c := range cs {
		if c.Rule == "Response property removed" {
			n++
			if len(c.Places) != 3 || !strings.Contains(c.Detail, "description") {
				t.Errorf("one removal, three places: %+v", c)
			}
		}
	}
	if n != 1 {
		t.Errorf("want 1 grouped removal, got %d:\n%s", n, dump(cs))
	}
}

func TestDiffDocsOnly(t *testing.T) {
	a := "openapi: 3.0.3\ninfo: {title: T, version: '1'}\npaths:\n  /a:\n    get:\n      summary: old\n      responses:\n        '200': {description: ok}\n"
	cs, _ := Diff(a, strings.Replace(a, "summary: old", "summary: new", 1))
	if len(cs) != 1 || cs[0].Level != lvDocs {
		t.Errorf("a summary edit is docs-only: %s", dump(cs))
	}
}
