package lang_test

import (
	"testing"

	_ "github.com/exey/archscope/internal/lang" // triggers all init() registrations
)

func TestCSecurity_GetsCall_Fires(t *testing.T) {
	lines := []string{`char buf[64];`, `gets(buf);`}
	if n := javaDetect(t, "c.gets_call", lines); n == 0 {
		t.Error("want finding for gets(), got 0")
	}
}

func TestCSecurity_GetsCall_FgetsSafe(t *testing.T) {
	lines := []string{`char buf[64];`, `fgets(buf, sizeof(buf), stdin);`}
	if n := javaDetect(t, "c.gets_call", lines); n != 0 {
		t.Errorf("want 0 findings for fgets, got %d", n)
	}
}

func TestCSecurity_UnsafeStringCopy_Fires(t *testing.T) {
	lines := []string{`strcpy(dest, src);`}
	if n := javaDetect(t, "c.unsafe_string_copy", lines); n == 0 {
		t.Error("want finding for strcpy, got 0")
	}
}

func TestCSecurity_UnsafeStringCopy_StrncpySafe(t *testing.T) {
	lines := []string{`strncpy(dest, src, sizeof(dest));`}
	if n := javaDetect(t, "c.unsafe_string_copy", lines); n != 0 {
		t.Errorf("want 0 findings for strncpy, got %d", n)
	}
}

func TestCSecurity_FormatString_Fires(t *testing.T) {
	lines := []string{`printf(user_input);`}
	if n := javaDetect(t, "c.format_string", lines); n == 0 {
		t.Error("want finding for printf(var), got 0")
	}
}

func TestCSecurity_FormatString_LiteralSafe(t *testing.T) {
	lines := []string{`printf("%s", user_input);`}
	if n := javaDetect(t, "c.format_string", lines); n != 0 {
		t.Errorf("want 0 findings for printf(\"%%s\", var), got %d", n)
	}
}

func TestCSecurity_CommandInjection_Fires(t *testing.T) {
	lines := []string{`system(cmd);`}
	if n := javaDetect(t, "c.command_injection", lines); n == 0 {
		t.Error("want finding for system(var), got 0")
	}
}

func TestCSecurity_CommandInjection_FixedArgSafe(t *testing.T) {
	lines := []string{`system("ls -la");`}
	if n := javaDetect(t, "c.command_injection", lines); n != 0 {
		t.Errorf("want 0 findings for system(\"literal\"), got %d", n)
	}
}

func TestCSecurity_HardcodedCredential_Fires(t *testing.T) {
	lines := []string{`char *api_key = "sk_live_abcdef1234567890";`}
	if n := javaDetect(t, "c.hardcoded_credential", lines); n == 0 {
		t.Error("want finding for hardcoded api_key, got 0")
	}
}

func TestCSecurity_WeakRandom_Fires(t *testing.T) {
	lines := []string{`int session_token = rand() % 100000;`}
	if n := javaDetect(t, "c.weak_random", lines); n == 0 {
		t.Error("want finding for rand() assigned to session_token, got 0")
	}
}

func TestCSecurity_WeakRandom_UnrelatedRandSafe(t *testing.T) {
	lines := []string{`int dice_roll = rand() % 6;`}
	if n := javaDetect(t, "c.weak_random", lines); n != 0 {
		t.Errorf("want 0 findings for unrelated rand() use, got %d", n)
	}
}

func TestCSecurity_InsecureTempFile_Fires(t *testing.T) {
	lines := []string{`char *path = mktemp(template);`}
	if n := javaDetect(t, "c.insecure_temp_file", lines); n == 0 {
		t.Error("want finding for mktemp, got 0")
	}
}

func TestCSecurity_InsecureTempFile_MkstempSafe(t *testing.T) {
	lines := []string{`int fd = mkstemp(template);`}
	if n := javaDetect(t, "c.insecure_temp_file", lines); n != 0 {
		t.Errorf("want 0 findings for mkstemp, got %d", n)
	}
}
