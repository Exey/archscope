package constructs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"
)

func mcFile(t *testing.T, name, src string) *parser.ParsedFile {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return &parser.ParsedFile{FilePath: p, ModuleName: "m"}
}

func mcDetect(files ...*parser.ParsedFile) map[string]int {
	r := (MagicConstants{}).Analyze(files).(MagicConstantResult)
	got := map[string]int{}
	for _, m := range r.Matches {
		got[m.Name] = m.Count
	}
	return got
}

func TestNormalizedValueRadixEquivalence(t *testing.T) {
	// 0x0100_0193 == 0x1000193 == 16777619 all resolve to the same value.
	for _, lit := range []string{"0x0100_0193", "0x1000193", "16777619", "16_777_619"} {
		v, _, ok := normalizedValue(lit)
		if !ok || v != "16777619" {
			t.Errorf("normalizedValue(%q) = %q,%v; want 16777619", lit, v, ok)
		}
	}
}

func TestDetectsHighEntropyInEitherRadix(t *testing.T) {
	// FNV prime as hex, decimal, and underscored — all detected.
	got := mcDetect(
		mcFile(t, "a.go", "const p = 0x01000193\n"),
		mcFile(t, "b.go", "const p = 16777619\n"),
		mcFile(t, "c.swift", "let p = 0x0100_0193\n"),
	)
	if got["FNV-1/1a (32-bit prime)"] != 3 {
		t.Errorf("want FNV prime ×3 across radices, got %v", got)
	}
}

func TestLowEntropyRequiresHex(t *testing.T) {
	// CRC-16/CCITT 0x1021 (4129) is low-entropy: only hex spelling counts.
	hex := mcDetect(mcFile(t, "a.go", "poly := 0x1021\n"))
	if hex["CRC-16/CCITT (polynomial)"] != 1 {
		t.Errorf("hex 0x1021 should be detected, got %v", hex)
	}
	dec := mcDetect(mcFile(t, "b.go", "count := 4129\n"))
	if _, ok := dec["CRC-16/CCITT (polynomial)"]; ok {
		t.Errorf("decimal 4129 must NOT be detected (low-entropy), got %v", dec)
	}
}

func TestNumericBoundariesAndFloats(t *testing.T) {
	// A magic value embedded in a longer literal or a float must not match.
	files := []*parser.ParsedFile{
		mcFile(t, "a.go", "x := 0x010001930\n"), // trailing digit → different value
		mcFile(t, "b.go", "y := 16777619.5\n"),  // float, integer part not a literal
		mcFile(t, "c.go", "z := a16777619\n"),   // part of an identifier
	}
	if r := (MagicConstants{}).Analyze(files).(MagicConstantResult); r.HasDetection() {
		t.Errorf("boundary/float cases must not match, got %+v", r.Matches)
	}
}

func TestStringConstantDetected(t *testing.T) {
	got := mcDetect(mcFile(t, "chacha.go", "const sigma = \"expand 32-byte k\"\n"))
	if got["ChaCha20 / Salsa20 (256-bit key constant)"] != 1 {
		t.Errorf("ChaCha sigma string should be detected, got %v", got)
	}
	// The same text inside a comment must NOT count (string literals only).
	c := mcDetect(mcFile(t, "note.go", "// uses expand 32-byte k somewhere\n"))
	if len(c) > 0 {
		t.Errorf("comment mention must not match, got %v", c)
	}
}

func TestAttributesToEnclosingFunction(t *testing.T) {
	src := "package h\n" +
		"func fnv32(data []byte) uint32 {\n" +
		"    var h uint32 = 0x811c9dc5\n" +
		"    for _, b := range data {\n" +
		"        h ^= uint32(b)\n" +
		"        h *= 0x01000193\n" +
		"    }\n" +
		"    return h\n" +
		"}\n"
	r := (MagicConstants{}).Analyze([]*parser.ParsedFile{mcFile(t, "fnv.go", src)}).(MagicConstantResult)
	for _, m := range r.Matches {
		for _, o := range m.Occurrences {
			if o.Symbol != "fnv32" {
				t.Errorf("%s: want symbol fnv32, got %q", m.Name, o.Symbol)
			}
		}
	}
	if len(r.Matches) == 0 {
		t.Fatal("expected FNV constants detected")
	}
}

func TestSelfReferentialFilesExcluded(t *testing.T) {
	src := "const p = 0x01000193\n"
	for _, name := range []string{"magicconstants.go", "FooDetector.swift", "HashScanner.kt"} {
		if len(mcDetect(mcFile(t, name, src))) > 0 {
			t.Errorf("%s should be excluded from self-detection", name)
		}
	}
	// An ordinary file with the same constant IS detected.
	if len(mcDetect(mcFile(t, "hashing.go", src))) == 0 {
		t.Error("ordinary file with FNV prime should be detected")
	}
}

func TestRenderHasCategoryIconAndLink(t *testing.T) {
	src := "func crc() { var poly uint32 = 0xedb88320 }\n"
	out := (MagicConstants{}).RenderHTML((MagicConstants{}).Analyze(
		[]*parser.ParsedFile{mcFile(t, "crc.go", src)}))
	for _, want := range []string{"CRC-32", "🧮", "×1", "vscode://file"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q:\n%s", want, out)
		}
	}
}
