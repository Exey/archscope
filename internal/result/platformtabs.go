package result

import (
	"sort"
	"strings"

	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/scanner"
)

// MinPlatformLOC is the smallest a platform can be and still get a dedicated
// card in "🗂️ Platforms" (and a 🔰 Programming Culture row) — below it a handful
// of files can swing every score wildly, so the read isn't meaningful.
const MinPlatformLOC = 1000

// PlatformTabs returns the platform groups that get a dedicated card — those
// with at least MinPlatformLOC lines — in the exact display order of the HTML
// report, which the Markdown export follows too.
func (r *AnalysisResult) PlatformTabs() []*scanner.PlatformGroup {
	all := r.Scan.PlatformsOrdered()
	if len(all) == 0 {
		return nil
	}

	loc := map[langspec.Platform]int{}
	for _, f := range r.Files {
		loc[langspec.Platform(f.Platform)] += f.LineCount
	}

	platforms := make([]*scanner.PlatformGroup, 0, len(all))
	for _, pg := range all {
		if loc[pg.Platform] >= MinPlatformLOC {
			platforms = append(platforms, pg)
		}
	}
	if len(platforms) == 0 {
		return nil
	}

	if r.Scan.FolderAsTab {
		folderLOC := map[string]int{}
		for _, pg := range platforms {
			folderLOC[tabFolder(pg.Platform)] += loc[pg.Platform]
		}
		sort.SliceStable(platforms, func(i, j int) bool {
			fi, fj := tabFolder(platforms[i].Platform), tabFolder(platforms[j].Platform)
			if fi != fj {
				li, lj := folderLOC[fi], folderLOC[fj]
				if li != lj {
					return li > lj
				}
				return fi < fj
			}
			return platforms[i].TabLabel() < platforms[j].TabLabel()
		})
	} else {
		sort.SliceStable(platforms, func(i, j int) bool {
			li, lj := loc[platforms[i].Platform], loc[platforms[j].Platform]
			if li != lj {
				return li > lj
			}
			return platforms[i].FileCount > platforms[j].FileCount
		})
	}
	return platforms
}

// tabFolder extracts the folder name from a synthetic platform key "lang:folder";
// a plain key is returned as is.
func tabFolder(p langspec.Platform) string {
	s := string(p)
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[i+1:]
	}
	return s
}
