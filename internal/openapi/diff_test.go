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
