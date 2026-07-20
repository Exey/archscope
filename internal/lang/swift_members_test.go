package lang

import "testing"

func TestExtractSwiftMembers(t *testing.T) {
	src := []string{
		`import Foundation`,
		``,
		`class UserService {`,
		`    private var name: String`,
		`    var logger: Logger`,
		``,
		`    func greet() -> String {`,
		`        return "hi " + self.name`,
		`    }`,
		``,
		`    func attach(logger: Logger) {`,
		`        self.logger = logger`,
		`        let l = Logger()`,
		`        _ = l`,
		`    }`,
		`}`,
	}
	got := extractSwiftMembers(src)
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
	if len(tm.Methods) != 2 {
		t.Fatalf("want 2 methods, got %d: %+v", len(tm.Methods), tm.Methods)
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
			if !hasStr(m.ExternalRefs, "Logger") {
				t.Errorf("attach(): want ExternalRefs to contain \"Logger\", got %v", m.ExternalRefs)
			}
		default:
			t.Errorf("unexpected method %q", m.Name)
		}
	}
}
