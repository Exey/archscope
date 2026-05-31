package parser_test

import (
	"path/filepath"
	"testing"

	_ "github.com/exey/archscope/internal/lang" // register languages
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/parser"
)

func TestParseGoSample(t *testing.T) {
	p := parser.New(langspec.Default)
	path := filepath.Join("..", "..", "testdata", "go-sample", "cmd", "api", "main.go")

	pf, err := p.Parse(path, "", "Go module")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pf == nil {
		t.Fatal("expected a ParsedFile, got nil (extension not registered?)")
	}

	if pf.LanguageID != "go" {
		t.Errorf("LanguageID = %q, want go", pf.LanguageID)
	}
	if pf.Platform != string(langspec.PlatformGo) {
		t.Errorf("Platform = %q, want %q", pf.Platform, langspec.PlatformGo)
	}

	// package main -> module name via hook, packageName in Extra
	if pf.ModuleName != "main" {
		t.Errorf("ModuleName = %q, want main", pf.ModuleName)
	}
	if got, _ := pf.Extra["packageName"].(string); got != "main" {
		t.Errorf(`Extra["packageName"] = %q, want main`, got)
	}

	// imports: fmt, net/http
	wantImports := map[string]bool{"fmt": true, "net/http": true}
	if len(pf.Imports) != len(wantImports) {
		t.Errorf("imports = %v, want %v", pf.Imports, wantImports)
	}
	for _, imp := range pf.Imports {
		if !wantImports[imp] {
			t.Errorf("unexpected import %q", imp)
		}
	}

	// declarations: struct Server, interface Handler, funcs run + main
	var structs, ifaces, funcs int
	for _, d := range pf.Declarations {
		switch d.Kind {
		case parser.DeclStruct:
			structs++
		case parser.DeclInterface:
			ifaces++
		case parser.DeclFunc:
			funcs++
		}
	}
	if structs != 1 {
		t.Errorf("structs = %d, want 1", structs)
	}
	if ifaces != 1 {
		t.Errorf("interfaces = %d, want 1", ifaces)
	}
	if funcs < 2 {
		t.Errorf("funcs = %d, want >= 2 (run, main)", funcs)
	}

	// doc comment attached to first declaration's description
	if pf.Description == "" {
		t.Errorf("Description empty, expected leading doc comment")
	}

	// TODO/FIXME counts
	if pf.TodoCount != 1 {
		t.Errorf("TodoCount = %d, want 1", pf.TodoCount)
	}
	if pf.FixmeCount != 1 {
		t.Errorf("FixmeCount = %d, want 1", pf.FixmeCount)
	}

	// big-function detector: run() body exceeds 25 lines
	foundBigRun := false
	for _, f := range pf.BigFunctions {
		if f.Name == "run" {
			foundBigRun = true
		}
	}
	if !foundBigRun {
		t.Errorf("expected run() in BigFunctions, got %+v", pf.BigFunctions)
	}
	if pf.LongestFunc == nil || pf.LongestFunc.Name != "run" {
		t.Errorf("LongestFunc = %+v, want run", pf.LongestFunc)
	}
}

func TestUnownedExtensionSkipped(t *testing.T) {
	p := parser.New(langspec.Default)
	pf, err := p.Parse("notes.txt", "", "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pf != nil {
		t.Errorf("expected nil for unowned extension, got %+v", pf)
	}
}
