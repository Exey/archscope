package lang

import "testing"

func TestExtractPythonMembers(t *testing.T) {
	src := []string{
		`import logging`,
		``,
		`class UserService:`,
		`    def __init__(self, logger: Logger):`,
		`        self.name = ""`,
		`        self.logger = logger`,
		``,
		`    def greet(self) -> str:`,
		`        return "hi " + self.name`,
		``,
		`    def attach(self, logger):`,
		`        self.logger = logger`,
		`        l = Logger()`,
		`        return l`,
	}
	got := extractPythonMembers(src)
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
	if len(tm.Methods) != 3 {
		t.Fatalf("want 3 methods, got %d: %+v", len(tm.Methods), tm.Methods)
	}
	for _, m := range tm.Methods {
		switch m.Name {
		case "__init__":
			if !hasStr(m.FieldRefs, "name") || !hasStr(m.FieldRefs, "logger") {
				t.Errorf("__init__(): want FieldRefs [name logger], got %v", m.FieldRefs)
			}
			if !hasStr(m.ParamTypes, "Logger") {
				t.Errorf("__init__(): want ParamTypes to contain \"Logger\", got %v", m.ParamTypes)
			}
		case "greet":
			if !hasStr(m.FieldRefs, "name") {
				t.Errorf("greet(): want FieldRefs to contain \"name\", got %v", m.FieldRefs)
			}
		case "attach":
			if !hasStr(m.FieldRefs, "logger") {
				t.Errorf("attach(): want FieldRefs to contain \"logger\", got %v", m.FieldRefs)
			}
			if !hasStr(m.ExternalRefs, "Logger") {
				t.Errorf("attach(): want ExternalRefs to contain \"Logger\" (constructor call), got %v", m.ExternalRefs)
			}
		default:
			t.Errorf("unexpected method %q", m.Name)
		}
	}
}
