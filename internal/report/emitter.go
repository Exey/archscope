package report

import "github.com/exey/archscope/internal/result"

// Emitter writes an AnalysisResult to a file in a specific output format.
// Implementations register themselves via Register in their package init().
type Emitter interface {
	ID() string  // canonical format name, e.g. "html", "sarif", "md"
	Ext() string // file extension including dot, e.g. ".html"
	Write(*result.AnalysisResult, string) error
}

var emitters []Emitter

// Register adds an emitter to the global registry. Call from init().
func Register(e Emitter) { emitters = append(emitters, e) }

// Lookup returns the emitter for the given canonical ID, or false if unknown.
func Lookup(id string) (Emitter, bool) {
	for _, e := range emitters {
		if e.ID() == id {
			return e, true
		}
	}
	return nil, false
}
