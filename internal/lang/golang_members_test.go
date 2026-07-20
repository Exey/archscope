package lang

import "testing"

func hasStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestExtractGoMembersFieldsAndRefs(t *testing.T) {
	src := []string{
		`package demo`,
		``,
		`type Logger struct{}`,
		``,
		`type Service struct {`,
		`	name string`,
		`	log  Logger`,
		`}`,
		``,
		`func (s *Service) Name() string {`,
		`	return s.name`,
		`}`,
		``,
		`func (s *Service) Log(msg string) {`,
		`	l := Logger{}`,
		`	_ = l`,
		`	_ = s.log`,
		`}`,
	}
	got := extractGoMembers("demo.go", src)
	var found bool
	for _, tm := range got {
		if tm.TypeName != "Service" {
			continue
		}
		found = true
		if !hasStr(tm.Fields, "name") || !hasStr(tm.Fields, "log") {
			t.Fatalf("want fields [name log], got %v", tm.Fields)
		}
		if len(tm.Methods) != 2 {
			t.Fatalf("want 2 methods, got %d: %+v", len(tm.Methods), tm.Methods)
		}
		for _, m := range tm.Methods {
			switch m.Name {
			case "Name":
				if !hasStr(m.FieldRefs, "name") {
					t.Errorf("Name(): want FieldRefs to contain \"name\", got %v", m.FieldRefs)
				}
			case "Log":
				if !hasStr(m.FieldRefs, "log") {
					t.Errorf("Log(): want FieldRefs to contain \"log\", got %v", m.FieldRefs)
				}
				if !hasStr(m.ExternalRefs, "Logger") {
					t.Errorf("Log(): want ExternalRefs to contain \"Logger\" (composite literal), got %v", m.ExternalRefs)
				}
				if hasStr(m.ExternalRefs, "string") {
					t.Errorf("Log(): builtin param type \"string\" should not appear in ExternalRefs (CBO), got %v", m.ExternalRefs)
				}
				if !hasStr(m.ParamTypes, "string") {
					t.Errorf("Log(): want ParamTypes to contain \"string\", got %v", m.ParamTypes)
				}
			default:
				t.Errorf("unexpected method %q", m.Name)
			}
		}
	}
	if !found {
		t.Fatalf("Service type not found in extracted members: %+v", got)
	}
}

func TestExtractGoMembersUnparsableFile(t *testing.T) {
	if got := extractGoMembers("bad.go", []string{"not valid go {{{"}); got != nil {
		t.Fatalf("want nil for an unparsable file, got %+v", got)
	}
}
