package scanner_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/exey/archscope/internal/config"
	_ "github.com/exey/archscope/internal/lang"
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/parser"
	"github.com/exey/archscope/internal/scanner"
)

// TestScanCCppHeaderDisambiguation exercises the full scan pipeline (not just
// the langspec.Registry unit tests) against a small C/C++/ObjC project whose
// ".h" files must be resolved by content, verifying the scanner's own peek
// path (separate code from the parser's, which reads the already-loaded
// lines) reaches the same answer.
func TestScanCCppHeaderDisambiguation(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("CMakeLists.txt", "cmake_minimum_required(VERSION 3.10)\nproject(demo)\n")
	write("src/util.h", "struct point {\n    int x;\n    int y;\n};\n\nint point_add(struct point *a, struct point *b);\n")
	write("src/util.c", "#include \"util.h\"\n\nint point_add(struct point *a, struct point *b)\n{\n    return a->x + b->x;\n}\n")
	write("src/widget.hpp", "#pragma once\nnamespace app {\nclass Widget {\npublic:\n    Widget();\n};\n}\n")
	write("src/widget.cpp", "#include \"widget.hpp\"\nnamespace app {\nWidget::Widget() {\n}\n}\n")
	write("src/greeter.h", "#import <Foundation/Foundation.h>\n@interface Greeter : NSObject\n@property (nonatomic, strong) NSString *name;\n@end\n")
	write("src/greeter.m", "#import \"greeter.h\"\n@implementation Greeter\n@end\n")

	cfg := config.Default()
	cfg.FolderAsTab = false
	res, err := scanner.Scan(root, cfg, langspec.Default)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	got := map[string]string{} // basename -> LanguageID
	for _, f := range res.Files {
		got[filepath.Base(f.Path)] = f.LanguageID
	}

	want := map[string]string{
		"util.h":     "c",
		"util.c":     "c",
		"widget.hpp": "cpp",
		"widget.cpp": "cpp",
		"greeter.h":  "objc",
		"greeter.m":  "objc",
	}
	for name, wantID := range want {
		if got[name] != wantID {
			t.Errorf("scanner LanguageID(%s) = %q, want %q", name, got[name], wantID)
		}
	}

	if g := res.Platforms[langspec.PlatformC]; g == nil || len(g.Files) != 4 {
		n := 0
		if g != nil {
			n = len(g.Files)
		}
		t.Errorf("PlatformC file count = %d, want 4 (util.h, util.c, widget.hpp, widget.cpp)", n)
	}

	// Cross-check with the parser's own (independent) resolution path: it
	// reads the file first and resolves against full content, rather than
	// the scanner's bounded peek.
	p := parser.New(langspec.Default)
	pf, err := p.Parse(filepath.Join(root, "src", "util.h"), "", "")
	if err != nil {
		t.Fatalf("parse util.h: %v", err)
	}
	if pf == nil || pf.LanguageID != "c" {
		t.Fatalf("parser LanguageID(util.h) = %+v, want c", pf)
	}
	foundStruct := false
	for _, d := range pf.Declarations {
		if d.Name == "point" && d.Kind == parser.DeclStruct {
			foundStruct = true
		}
	}
	if !foundStruct {
		t.Errorf("expected a DeclStruct %q in util.h declarations, got %+v", "point", pf.Declarations)
	}

	pf2, err := p.Parse(filepath.Join(root, "src", "widget.hpp"), "", "")
	if err != nil {
		t.Fatalf("parse widget.hpp: %v", err)
	}
	if pf2 == nil || pf2.LanguageID != "cpp" {
		t.Fatalf("parser LanguageID(widget.hpp) = %+v, want cpp", pf2)
	}
	foundClass := false
	for _, d := range pf2.Declarations {
		if d.Name == "Widget" && d.Kind == parser.DeclClass {
			foundClass = true
		}
	}
	if !foundClass {
		t.Errorf("expected a DeclClass %q in widget.hpp declarations, got %+v", "Widget", pf2.Declarations)
	}
}
