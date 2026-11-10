package constructs

import (
	"testing"

	"github.com/exey/archscope/internal/langprofile"
	"github.com/exey/archscope/internal/parser"
)

// The profile table documents the thresholds the Code Structure card applies;
// this keeps the two from drifting apart until the card reads them from it.
func TestProfileLimitsMatchCard(t *testing.T) {
	l := langprofile.DefaultLimits
	for name, pair := range map[string][2]int{
		"MaxParams": {l.MaxParams, csMaxParams}, "MaxNestDepth": {l.MaxNestDepth, csMaxNestDepth}, "MaxCyclomatic": {l.MaxCyclomatic, csMaxCyclomatic},
		"MaxReturns": {l.MaxReturns, csMaxReturns}, "MaxBranches": {l.MaxBranches, csMaxBranches}, "MaxLocals": {l.MaxLocals, csMaxLocals},
		"MaxModuleLines":   {l.MaxModuleLines, csMaxModuleLines},
		"BigFunctionLines": {l.BigFunctionLines, parser.DefaultBigFunctionMinLines}, "BigTypeLines": {l.BigTypeLines, parser.DefaultBigTypeMinLines},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s: profile %d, card %d", name, pair[0], pair[1])
		}
	}
}
