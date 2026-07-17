package lang_test

import (
	"testing"

	_ "github.com/exey/archscope/internal/lang" // triggers all init() registrations
	"github.com/exey/archscope/internal/langspec"
)

func TestHeaderSniff_ObjCSignal(t *testing.T) {
	lines := []string{
		`#import <Foundation/Foundation.h>`,
		``,
		`@interface Person : NSObject`,
		`@property (nonatomic, strong) NSString *name;`,
		`@end`,
	}
	got := langspec.Default.ResolveShared(".h", lines)
	if got == nil || got.ID != "objc" {
		t.Fatalf("ResolveShared(.h, objc header) = %v, want objc", got)
	}
}

func TestHeaderSniff_CppSignal(t *testing.T) {
	lines := []string{
		`#pragma once`,
		`#include <string>`,
		``,
		`namespace app {`,
		`class Widget {`,
		`public:`,
		`    std::string name() const;`,
		`};`,
		`}`,
	}
	got := langspec.Default.ResolveShared(".h", lines)
	if got == nil || got.ID != "cpp" {
		t.Fatalf("ResolveShared(.h, cpp header) = %v, want cpp", got)
	}
}

func TestHeaderSniff_PlainCFallsBackToC(t *testing.T) {
	lines := []string{
		`#ifndef WIDGET_H`,
		`#define WIDGET_H`,
		``,
		`struct widget {`,
		`    int id;`,
		`    char name[64];`,
		`};`,
		``,
		`int widget_init(struct widget *w);`,
		``,
		`#endif`,
	}
	got := langspec.Default.ResolveShared(".h", lines)
	if got == nil || got.ID != "c" {
		t.Fatalf("ResolveShared(.h, plain C header) = %v, want c (default fallback)", got)
	}
}

func TestHeaderSniff_UnambiguousExtensionsUnaffected(t *testing.T) {
	cases := map[string]string{
		".c":   "c",
		".cpp": "cpp",
		".cc":  "cpp",
		".hpp": "cpp",
		".m":   "objc",
		".mm":  "objc",
	}
	for ext, wantID := range cases {
		if langspec.Default.IsShared(ext) {
			t.Errorf("%s should not be reported as shared", ext)
		}
		got := langspec.Default.Lookup(ext)
		if got == nil || got.ID != wantID {
			t.Errorf("Lookup(%s) = %v, want %s", ext, got, wantID)
		}
	}
}
