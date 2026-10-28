package result

import (
	"testing"

	"github.com/exey/archscope/internal/modules/constructs"
)

// Review mode reads documentation through the shared docstring model: a Python
// def with a blank line above and a docstring below its multi-line signature
// is documented, in any language of text.
func TestReviewDocIndexUsesDocstrings(t *testing.T) {
	src := []string{
		"import x", "", "",
		"def get_unprocessed_images(",
		"    *, created_from: datetime, untouched_since: Optional[datetime] = None",
		"):",
		`    """`,
		"    Необработанные изображения с файлом.",
		`    """`,
		"    return []",
		"", "",
		"def bare(a):",
		"    return a",
	}
	idx := constructs.NewDocIndex("/x/a.py", src)
	if !idx.Has(4) {
		t.Error("documented function reported as undocumented")
	}
	if idx.Has(13) {
		t.Error("undocumented function reported as documented")
	}
}
