package langspec

import "testing"

func TestRegistry_ExclusiveExtension_PanicsOnClash(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("want panic when two no-Sniff specs claim the same extension")
		}
	}()
	r := NewRegistry()
	r.Register(LanguageSpec{ID: "a", Extensions: []string{"xyz"}})
	r.Register(LanguageSpec{ID: "b", Extensions: []string{"xyz"}})
}

func TestRegistry_SharedExtension_DefaultFallback(t *testing.T) {
	r := NewRegistry()
	r.Register(LanguageSpec{ID: "default", Extensions: []string{"h"}})
	r.Register(LanguageSpec{ID: "sniffed", Extensions: []string{"h"}, Sniff: func(peek []string) bool {
		for _, l := range peek {
			if l == "SIGNAL" {
				return true
			}
		}
		return false
	}})

	if !r.IsShared(".h") {
		t.Fatal("want .h to be reported as shared once two specs claim it")
	}
	if got := r.Lookup(".h"); got == nil || got.ID != "default" {
		t.Fatalf("Lookup(.h) = %v, want the no-Sniff default", got)
	}
	if got := r.ResolveShared(".h", []string{"no signal here"}); got == nil || got.ID != "default" {
		t.Fatalf("ResolveShared with no matching signal = %v, want default fallback", got)
	}
	if got := r.ResolveShared(".h", []string{"SIGNAL"}); got == nil || got.ID != "sniffed" {
		t.Fatalf("ResolveShared with matching signal = %v, want sniffed spec", got)
	}
}

func TestRegistry_SharedExtension_DefaultCanRegisterAfterSniffed(t *testing.T) {
	// Registration order shouldn't matter: whichever spec omits Sniff ends up
	// as the default, even if a Sniff-bearing spec claimed the extension first.
	r := NewRegistry()
	r.Register(LanguageSpec{ID: "sniffed", Extensions: []string{"h"}, Sniff: func([]string) bool { return false }})
	r.Register(LanguageSpec{ID: "default", Extensions: []string{"h"}})

	if got := r.Lookup(".h"); got == nil || got.ID != "default" {
		t.Fatalf("Lookup(.h) = %v, want the no-Sniff default regardless of registration order", got)
	}
}

func TestRegistry_SharedExtension_TwoDefaultsPanic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("want panic when two no-Sniff specs both claim a shared extension")
		}
	}()
	r := NewRegistry()
	r.Register(LanguageSpec{ID: "a", Extensions: []string{"h"}, Sniff: func([]string) bool { return false }})
	r.Register(LanguageSpec{ID: "b", Extensions: []string{"h"}})
	r.Register(LanguageSpec{ID: "c", Extensions: []string{"h"}})
}

func TestRegistry_UnsharedExtension_Unaffected(t *testing.T) {
	r := NewRegistry()
	r.Register(LanguageSpec{ID: "solo", Extensions: []string{"go"}, Sniff: func([]string) bool { return true }})
	if r.IsShared(".go") {
		t.Fatal("a single claimant should never be reported as shared")
	}
	if got := r.Lookup(".go"); got == nil || got.ID != "solo" {
		t.Fatalf("Lookup(.go) = %v, want solo claimant regardless of it setting Sniff", got)
	}
}
