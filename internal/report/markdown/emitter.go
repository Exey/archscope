package markdown

import (
	"github.com/exey/archscope/internal/report"
	"github.com/exey/archscope/internal/result"
)

func init() { report.Register(mdEmitter{}) }

type mdEmitter struct{}

func (mdEmitter) ID() string                                       { return "md" }
func (mdEmitter) Ext() string                                      { return ".md" }
func (mdEmitter) Write(res *result.AnalysisResult, p string) error { return Write(res, p) }
