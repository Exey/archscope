package lang_test

import (
	"testing"

	_ "github.com/exey/archscope/internal/lang" // triggers all init() registrations
)

func TestCppSecurity_UnsafeStringCopy_Fires(t *testing.T) {
	lines := []string{`strcpy(dest, src);`}
	if n := javaDetect(t, "cpp.unsafe_string_copy", lines); n == 0 {
		t.Error("want finding for strcpy, got 0")
	}
}

func TestCppSecurity_FormatString_Fires(t *testing.T) {
	lines := []string{`printf(user_input);`}
	if n := javaDetect(t, "cpp.format_string", lines); n == 0 {
		t.Error("want finding for printf(var), got 0")
	}
}

func TestCppSecurity_FormatString_LiteralSafe(t *testing.T) {
	lines := []string{`printf("%s", user_input);`}
	if n := javaDetect(t, "cpp.format_string", lines); n != 0 {
		t.Errorf("want 0 findings for printf(\"%%s\", var), got %d", n)
	}
}

func TestCppSecurity_CommandInjection_Fires(t *testing.T) {
	lines := []string{`system(cmd);`}
	if n := javaDetect(t, "cpp.command_injection", lines); n == 0 {
		t.Error("want finding for system(var), got 0")
	}
}

func TestCppSecurity_CommandInjection_FixedArgSafe(t *testing.T) {
	lines := []string{`system("ls -la");`}
	if n := javaDetect(t, "cpp.command_injection", lines); n != 0 {
		t.Errorf("want 0 findings for system(\"literal\"), got %d", n)
	}
}

func TestCppSecurity_HardcodedCredential_Fires(t *testing.T) {
	lines := []string{`std::string apiKey = "sk_live_abcdef1234567890";`}
	if n := javaDetect(t, "cpp.hardcoded_credential", lines); n == 0 {
		t.Error("want finding for hardcoded apiKey, got 0")
	}
}

func TestCppSecurity_WeakRandom_Fires(t *testing.T) {
	lines := []string{`int sessionToken = rand() % 100000;`}
	if n := javaDetect(t, "cpp.weak_random", lines); n == 0 {
		t.Error("want finding for rand() assigned to sessionToken, got 0")
	}
}

func TestCppSecurity_ReinterpretCast_Fires(t *testing.T) {
	lines := []string{`auto* p = reinterpret_cast<Foo*>(raw);`}
	if n := javaDetect(t, "cpp.reinterpret_cast", lines); n == 0 {
		t.Error("want finding for reinterpret_cast, got 0")
	}
}

func TestCppSecurity_ReinterpretCast_StaticCastSafe(t *testing.T) {
	lines := []string{`auto* p = static_cast<Foo*>(raw);`}
	if n := javaDetect(t, "cpp.reinterpret_cast", lines); n != 0 {
		t.Errorf("want 0 findings for static_cast, got %d", n)
	}
}

func TestCppSecurity_RawNewDelete_Fires(t *testing.T) {
	lines := []string{`Foo* f = new Foo(1, 2);`}
	if n := javaDetect(t, "cpp.raw_new_delete", lines); n == 0 {
		t.Error("want finding for raw new, got 0")
	}
}

func TestCppSecurity_RawNewDelete_MakeUniqueSafe(t *testing.T) {
	lines := []string{`auto f = std::make_unique<Foo>(1, 2);`}
	if n := javaDetect(t, "cpp.raw_new_delete", lines); n != 0 {
		t.Errorf("want 0 findings for make_unique, got %d", n)
	}
}
