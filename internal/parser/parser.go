package parser

import (
	"path/filepath"
	"strings"

	"github.com/exey/archscope/internal/langspec"
)

// Parser ties a language registry and a source loader together.
type Parser struct {
	Reg    *langspec.Registry
	Loader SourceLoader
}

// New returns a Parser using the given registry and the default disk loader.
func New(reg *langspec.Registry) *Parser {
	return &Parser{Reg: reg, Loader: FileLoader{}}
}

// Parse picks the owning LanguageSpec by extension, loads the file once, runs
// the universal scan, then the optional ParseHook. It returns (nil, nil) for
// files that no registered language owns — callers treat that as "skip".
func (p *Parser) Parse(filePath, moduleName, projectType string) (*ParsedFile, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	spec := p.Reg.Lookup(ext)
	if spec == nil {
		return nil, nil
	}

	lines, err := p.Loader.Load(filePath)
	if err != nil {
		return nil, err
	}

	if p.Reg.IsShared(ext) {
		if resolved := p.Reg.ResolveShared(ext, lines); resolved != nil {
			spec = resolved
		}
	}
	c := p.Reg.Compiled(spec.ID)
	if c == nil {
		// Should not happen: a registered spec always has compiled patterns.
		return nil, nil
	}

	pf := ParseUniversal(filePath, lines, spec, c)
	pf.ModuleName = moduleName
	pf.ProjectType = projectType

	if spec.ParseHook != nil {
		spec.ParseHook(filePath, lines, pf)
	}
	return pf, nil
}
