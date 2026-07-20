package lang

import "testing"

func TestExtractRustMembers(t *testing.T) {
	src := []string{
		`struct UserService {`,
		`    name: String,`,
		`    logger: Logger,`,
		`}`,
		``,
		`impl UserService {`,
		`    fn new(name: String) -> Self {`,
		`        Self { name, logger: Logger::default() }`,
		`    }`,
		``,
		`    fn greet(&self) -> String {`,
		`        format!("hi {}", self.name)`,
		`    }`,
		`}`,
		``,
		`impl UserService {`,
		`    fn attach(&mut self, logger: Logger) {`,
		`        self.logger = logger;`,
		`        let l = Logger::new();`,
		`        let _ = l;`,
		`    }`,
		`}`,
	}
	got := extractRustMembers(src)
	if len(got) != 1 {
		t.Fatalf("want 1 type, got %d: %+v", len(got), got)
	}
	tm := got[0]
	if tm.TypeName != "UserService" {
		t.Fatalf("want type UserService, got %q", tm.TypeName)
	}
	if !hasStr(tm.Fields, "name") || !hasStr(tm.Fields, "logger") {
		t.Fatalf("want fields [name logger], got %v", tm.Fields)
	}
	// "new" has no self receiver — must be excluded; greet/attach (across
	// two separate impl blocks) must both be collected under the same type.
	if len(tm.Methods) != 2 {
		t.Fatalf("want 2 methods (new excluded, greet+attach from two impl blocks), got %d: %+v", len(tm.Methods), tm.Methods)
	}
	for _, m := range tm.Methods {
		switch m.Name {
		case "greet":
			if !hasStr(m.FieldRefs, "name") {
				t.Errorf("greet(): want FieldRefs to contain \"name\", got %v", m.FieldRefs)
			}
		case "attach":
			if !hasStr(m.FieldRefs, "logger") {
				t.Errorf("attach(): want FieldRefs to contain \"logger\", got %v", m.FieldRefs)
			}
			if !hasStr(m.ParamTypes, "Logger") {
				t.Errorf("attach(): want ParamTypes to contain \"Logger\", got %v", m.ParamTypes)
			}
		default:
			t.Errorf("unexpected method %q", m.Name)
		}
	}
}
