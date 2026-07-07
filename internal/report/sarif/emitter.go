package sarif

import (
	"github.com/exey/archscope/internal/report"
	"github.com/exey/archscope/internal/result"
)

func init() { report.Register(sarifEmitter{}) }

type sarifEmitter struct{}

func (sarifEmitter) ID() string                                       { return "sarif" }
func (sarifEmitter) Ext() string                                      { return ".sarif" }
func (sarifEmitter) Write(res *result.AnalysisResult, p string) error { return Write(res, p) }
