package openapi

import "testing"

const schemaSpec = `openapi: 3.0.3
info:
  title: T
  version: '1'
  descrption: typo
paths:
  /a:
    get:
      reponses:
        '200': {description: ok}
      responses:
        '20': {description: bad code}
        '404': {content: {}}
        '200':
          description: ok
          content:
            application/json:
              schema: {$ref: '#/components/schemas/Combo'}
  bad-path: {}
components:
  schemas:
    A:
      type: object
      properties:
        id: {type: string}
        n: {type: integer, minLength: 3}
    B:
      type: object
      properties:
        id: {type: integer}
    Combo:
      allOf:
        - $ref: '#/components/schemas/A'
        - $ref: '#/components/schemas/B'
    Weird:
      type: strng
      minimum: 5
      maximum: 1
      pattern: '(abc'
      default: 12
    Arr:
      type: array
    Val: {type: string, default: 12}
    Mixed:
      allOf:
        - {type: string}
        - {type: object}
    Disc:
      type: object
      discriminator: {propertyName: kind}
      properties:
        name: {type: string}
    RW: {type: string, readOnly: true, writeOnly: true}
    Excl: {type: integer, exclusiveMinimum: 3}
    Req: {type: object, required: [a, a], properties: {a: {type: string}}}
`

func TestSpecShapeAndSchemaChecks(t *testing.T) {
	fs, ok := Lint(schemaSpec)
	if !ok {
		t.Fatal("not a spec")
	}
	got := ids(fs)
	for _, want := range []string{
		"oas-spec-unknown", "oas-spec-response-code", "oas-spec-path-key", "oas-spec-required",
		"oas-allof-conflict", "oas-schema-type", "oas-schema-constraint", "oas-schema-range", "oas-schema-pattern",
		"oas-schema-value", "oas-schema-array-items", "oas-schema-composition", "oas-schema-discriminator",
		"oas-schema-readwrite", "oas-schema-exclusive", "oas-schema-required",
	} {
		if got[want] == 0 {
			t.Errorf("missing %s; got %v", want, got)
		}
	}
	// typos name the field
	var unknown []string
	for _, f := range fs {
		if f.RuleID == "oas-spec-unknown" {
			unknown = append(unknown, f.Detail)
		}
	}
	if len(unknown) != 2 { // Info.descrption and Operation.reponses
		t.Errorf("unknown keys = %v", unknown)
	}
	for _, f := range fs {
		if f.RuleID == "oas-allof-conflict" && !(contains(f.Detail, "`id`") && contains(f.Detail, "string") && contains(f.Detail, "integer")) {
			t.Errorf("allOf conflict detail: %q", f.Detail)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool { return indexOf(s, sub) >= 0 })()
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestAllOfWithCompatibleTypesIsFine(t *testing.T) {
	spec := "openapi: 3.0.3\ninfo: {title: t, version: '1', description: d}\npaths: {}\ncomponents:\n  schemas:\n    A: {type: object, properties: {n: {type: number}, s: {type: string}}}\n    B: {type: object, properties: {n: {type: integer}, s: {type: string, nullable: true}}}\n    C:\n      allOf:\n        - {$ref: '#/components/schemas/A'}\n        - {$ref: '#/components/schemas/B'}\n"
	fs, _ := Lint(spec)
	for _, f := range fs {
		if f.RuleID == "oas-allof-conflict" || f.RuleID == "oas-schema-composition" {
			t.Errorf("number/integer overlap and nullable must not conflict: %+v", f)
		}
	}
}

func TestPatternValidity(t *testing.T) {
	for p, want := range map[string]bool{"^[a-z]+$": true, `(?=.*\d)(?=.*[a-z]).{8,}`: true, "(abc": false, "[abc": false, "*abc": false, `\d{3}-\d{4}`: true, "a|b": true, `[\])]`: true} {
		if got := patternLooksValid(p); got != want {
			t.Errorf("patternLooksValid(%q) = %v, want %v", p, got, want)
		}
	}
}
