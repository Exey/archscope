package openapi

import (
	"strings"
	"testing"
)

const badSpec = `openapi: 3.0.3
info:
  title: Pets
  version: '1'
servers:
  - url: http://api.pets.io/
tags:
  - name: pets
paths:
  /pets/{petId}:
    get:
      tags: [pets, ghost]
      operationId: getPet
      parameters:
        - name: id
          in: path
          required: true
          schema: {type: integer}
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Missing'
  /pets/{name}:
    post:
      operationId: getPet
      summary: create
      security:
        - nope: []
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required: [name, age]
              properties:
                name: {type: string}
                tags: {type: array, items: {type: string}}
                kind: {type: string, enum: [a, b, a]}
      responses:
        "201":
          description: created
  /getUsers/:
    get:
      operationId: bad id!
      description: x
      requestBody: {description: body}
      parameters:
        - name: api_key
          in: query
          schema: {type: string}
        - name: limit
          in: query
          schema: {type: integer}
      responses:
        default: {description: err}
components:
  schemas:
    Unused: {type: object}
  securitySchemes:
    basic: {type: http, scheme: basic}
    keyq: {type: apiKey, in: query, name: key}
    oauth:
      type: oauth2
      flows:
        implicit: {authorizationUrl: 'http://auth.example.com/a', scopes: {}}
`

func ids(fs []Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.RuleID]++
	}
	return m
}

func TestLintFindsReviewRelevantProblems(t *testing.T) {
	fs, ok := Lint(badSpec)
	if !ok {
		t.Fatal("not recognised as a spec")
	}
	got := ids(fs)
	for _, want := range []string{
		"oas-info-description", "oas-server-http", "oas-server-style", "oas-operation-tag-undefined",
		"oas-path-params", "oas-numeric-id", "oas-ref-unresolved", "oas-path-ambiguous",
		"oas-operation-id-duplicate", "oas-security-undefined", "oas-required-undefined", "oas-enum-duplicate",
		"oas-success-response", "oas-path-trailing-slash", "oas-path-verb", "oas-operation-id-chars",
		"oas-body-on-get-delete", "oas-api-key-in-url", "oas-unused-component", "oas-http-basic", "oas-oauth-flow", "oas-auth-url-http",
		"oas-limit-array", "oas-limit-string", "oas-limit-integer", "oas-error-response",
	} {
		if got[want] == 0 {
			t.Errorf("missing %s; got %v", want, got)
		}
	}
	// the spec has schemes, no global security, and a POST without security → HIGH
	// (the POST names an undefined scheme: reported as security-undefined, not as unprotected)
	if got["oas-unprotected-operation"] != 0 {
		t.Errorf("a POST with its own (broken) security requirement is not 'unprotected': %v", got)
	}
	for _, f := range fs {
		if f.Line <= 0 {
			t.Errorf("%s has no line", f.RuleID)
		}
		if f.RuleID == "oas-ref-unresolved" && f.Line != 25 {
			t.Errorf("unresolved ref on line %d, want 25", f.Line)
		}
	}
}

const goodSpec = `openapi: 3.0.3
info:
  title: Pets
  description: ok
  version: '1'
servers:
  - url: https://api.pets.io
  - url: http://localhost:8080
tags:
  - name: pets
    description: Pets
security:
  - bearer: []
paths:
  /pets/{petId}:
    get:
      tags: [pets]
      operationId: getPet
      summary: Get a pet
      parameters:
        - name: petId
          in: path
          required: true
          schema: {type: string, format: uuid}
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Pet'
        "404":
          description: missing
components:
  securitySchemes:
    bearer: {type: http, scheme: bearer}
  schemas:
    Pet:
      type: object
      required: [id]
      properties:
        id: {type: string}
`

func TestCleanSpecHasNoRealFindings(t *testing.T) {
	fs, ok := Lint(goodSpec)
	if !ok {
		t.Fatal("not a spec")
	}
	for _, f := range fs {
		if !f.Advisory {
			t.Errorf("unexpected %s: %s (%s) line %d", f.RuleID, f.Rule, f.Detail, f.Line)
		}
	}
}

func TestUnprotectedUnsafeOperation(t *testing.T) {
	spec := strings.Replace(goodSpec, "security:\n  - bearer: []\n", "", 1) + ""
	spec = strings.Replace(spec, "    get:\n", "    post:\n", 1)
	fs, _ := Lint(spec)
	if ids(fs)["oas-unprotected-operation"] != 1 {
		t.Errorf("POST without any security must be flagged: %v", ids(fs))
	}
	public := strings.Replace(spec, "      tags: [pets]\n", "      tags: [pets]\n      security: []\n", 1)
	if fs, _ := Lint(public); ids(fs)["oas-unprotected-operation"] != 0 {
		t.Errorf("explicit `security: []` is a deliberate public endpoint: %v", ids(fs))
	}
}

func TestNonSpecsAndSwagger2(t *testing.T) {
	if _, ok := Lint("name: ci\non: push\njobs: {}\n"); ok {
		t.Error("a CI file is not a spec")
	}
	v2 := "swagger: '2.0'\ninfo: {title: t, version: '1'}\nhost: x\nschemes: [http]\npaths:\n  /a/{id}:\n    get:\n      responses:\n        200: {description: ok}\ndefinitions:\n  U: {type: object}\n"
	fs, ok := Lint(v2)
	if !ok {
		t.Fatal("swagger 2 not recognised")
	}
	got := ids(fs)
	if got["oas-path-params"] == 0 || got["oas-unused-component"] == 0 || got["oas-server-http"] == 0 {
		t.Errorf("swagger 2: %v", got)
	}
}
