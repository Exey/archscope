package langspec

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Compiled holds the compiled regexes for one spec's ParsePatterns.
// nil fields mean the corresponding pattern was empty (skip it).
type Compiled struct {
	ImportSingle   *regexp.Regexp
	ImportBlockBeg *regexp.Regexp
	ImportBlockEnd *regexp.Regexp
	ImportInBlock  *regexp.Regexp
	TypeDecl       *regexp.Regexp
	FuncDecl       *regexp.Regexp
	DocComment     *regexp.Regexp
}

// Registry holds registered specs keyed by ID, with an extension index and a
// per-spec compiled-pattern cache. Safe for concurrent reads after setup.
type Registry struct {
	mu       sync.RWMutex
	byID     map[string]*LanguageSpec
	byExt    map[string]*LanguageSpec   // ".go" -> spec (default/fallback claimant for shared exts)
	shared   map[string][]*LanguageSpec // ".h" -> [objc, cpp, c, ...] contenders, for content resolution
	compiled map[string]*Compiled       // spec ID -> compiled patterns
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		byID:     map[string]*LanguageSpec{},
		byExt:    map[string]*LanguageSpec{},
		shared:   map[string][]*LanguageSpec{},
		compiled: map[string]*Compiled{},
	}
}

// Default is the process-wide registry that language init() funcs populate.
var Default = NewRegistry()

// Register adds a spec, compiles its patterns, and indexes its extensions.
// It panics on a duplicate ID or an extension already claimed by another spec,
// since both indicate a programming error at startup.
func (r *Registry) Register(spec LanguageSpec) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if spec.ID == "" {
		panic("langspec: spec with empty ID")
	}
	if _, dup := r.byID[spec.ID]; dup {
		panic(fmt.Sprintf("langspec: duplicate language ID %q", spec.ID))
	}

	s := spec // copy so the stored pointer is stable
	r.byID[s.ID] = &s

	for _, ext := range s.Extensions {
		key := normExt(ext)
		r.shared[key] = append(r.shared[key], &s)

		existing, claimed := r.byExt[key]
		switch {
		case !claimed:
			// First claimant of this extension becomes the default —
			// regardless of Sniff — so single-owner extensions (the common
			// case) keep working with plain Lookup, no clash to resolve.
			r.byExt[key] = &s
		case s.Sniff == nil:
			// s has no Sniff: it's a genuine "I exclusively own this"
			// declaration. Two such declarations for the same extension is
			// an ownership bug, same as before this sharing mechanism
			// existed. If the existing default DOES have a Sniff, s
			// (nil-Sniff) takes over as the new default and demotes it to a
			// pure content-matched contender.
			if existing.Sniff == nil {
				panic(fmt.Sprintf("langspec: extension %q claimed by both %q and %q with no Sniff to disambiguate",
					key, existing.ID, s.ID))
			}
			r.byExt[key] = &s
		}
		// else: s has a Sniff and the extension already has a default —
		// s just joins the shared contenders list without disturbing it.
	}

	r.compiled[s.ID] = compilePatterns(s.ID, s.Patterns)
}

// Lookup returns the spec owning a file extension (with or without dot), or
// nil. For a shared extension (see Sniff) this returns the default/fallback
// claimant, ignoring file content — callers that can read the file should
// prefer ResolveShared for an accurate per-file answer.
func (r *Registry) Lookup(ext string) *LanguageSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byExt[normExt(ext)]
}

// IsShared reports whether ext has more than one registered contender, i.e.
// needs ResolveShared (content-based) rather than Lookup to pick correctly.
func (r *Registry) IsShared(ext string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.shared[normExt(ext)]) > 1
}

// ResolveShared picks the LanguageSpec owning ext for one specific file,
// running each contender's Sniff predicate (in registration order) against
// peekLines and returning the first match. Falls back to the default/no-Sniff
// claimant (same as Lookup) if no Sniff matches, or nil if ext isn't
// registered at all.
func (r *Registry) ResolveShared(ext string, peekLines []string) *LanguageSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	key := normExt(ext)
	for _, s := range r.shared[key] {
		if s.Sniff != nil && s.Sniff(peekLines) {
			return s
		}
	}
	return r.byExt[key]
}

// Get returns the spec with the given ID, or nil.
func (r *Registry) Get(id string) *LanguageSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byID[id]
}

// Compiled returns the compiled patterns for a spec ID, or nil if unknown.
func (r *Registry) Compiled(id string) *Compiled {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.compiled[id]
}

// All returns every registered spec in stable order by ID.
func (r *Registry) All() []*LanguageSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*LanguageSpec, 0, len(r.byID))
	for _, s := range r.byID {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// IsClientPlatform reports whether any registered language on platform p is a
// client/UI language (Swift/ObjC/Kotlin/TS-JS). The architecture module uses
// this to choose pattern-detection vs. layered rendering.
func (r *Registry) IsClientPlatform(p Platform) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.byID {
		if s.Platform == p && s.Client {
			return true
		}
	}
	return false
}

// ModuleNoun returns the (icon, label) a platform uses for its unit of
// modularity, taken from the first language on that platform that defines one,
// falling back to "📦"/"Modules".
func (r *Registry) ModuleNoun(p Platform) (icon, label string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	icon, label = "📦", "Modules"
	// Prefer canonical order so a platform with multiple langs is deterministic.
	for _, want := range append([]Platform{p}, PlatformOrder...) {
		for _, s := range r.byID {
			if s.Platform == want && s.Platform == p && s.ModuleLabel != "" {
				ic := s.ModuleIcon
				if ic == "" {
					ic = "📦"
				}
				return ic, s.ModuleLabel
			}
		}
	}
	return icon, label
}

// Platforms returns the distinct platforms present among registered specs,
// in canonical tab order (PlatformOrder), followed by any extras alphabetically.
func (r *Registry) Platforms() []Platform {
	r.mu.RLock()
	present := map[Platform]bool{}
	for _, s := range r.byID {
		present[s.Platform] = true
	}
	r.mu.RUnlock()

	var out []Platform
	seen := map[Platform]bool{}
	for _, p := range PlatformOrder {
		if present[p] {
			out = append(out, p)
			seen[p] = true
		}
	}
	var extra []Platform
	for p := range present {
		if !seen[p] {
			extra = append(extra, p)
		}
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i] < extra[j] })
	return append(out, extra...)
}

// normExt normalizes an extension to a leading-dot, lowercase form.
func normExt(ext string) string {
	ext = strings.ToLower(strings.TrimSpace(ext))
	if ext == "" {
		return ext
	}
	if ext[0] != '.' {
		ext = "." + ext
	}
	return ext
}

// compilePatterns compiles each non-empty pattern. A bad pattern panics with a
// clear message naming the language and field, since it is a startup-time bug.
func compilePatterns(langID string, p ParsePatterns) *Compiled {
	c := &Compiled{}
	mk := func(field, pat string) *regexp.Regexp {
		if pat == "" {
			return nil
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			panic(fmt.Sprintf("langspec: %s.%s bad regex %q: %v", langID, field, pat, err))
		}
		return re
	}
	c.ImportSingle = mk("ImportSingle", p.ImportSingle)
	c.ImportBlockBeg = mk("ImportBlockBeg", p.ImportBlockBeg)
	c.ImportBlockEnd = mk("ImportBlockEnd", p.ImportBlockEnd)
	c.ImportInBlock = mk("ImportInBlock", p.ImportInBlock)
	c.TypeDecl = mk("TypeDecl", p.TypeDecl)
	c.FuncDecl = mk("FuncDecl", p.FuncDecl)
	c.DocComment = mk("DocComment", p.DocComment)
	return c
}
