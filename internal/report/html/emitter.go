package html

import (
	"github.com/exey/archscope/internal/report"
	"github.com/exey/archscope/internal/result"
)

func init() { report.Register(htmlEmitter{}) }

type htmlEmitter struct{}

func (htmlEmitter) ID() string                                       { return "html" }
func (htmlEmitter) Ext() string                                      { return ".html" }
func (htmlEmitter) Write(res *result.AnalysisResult, p string) error { return Write(res, p) }
