package scanner

import (
	"os"
	"path/filepath"
	"strings"
)

// ParseGitSubmodules reads .gitmodules at rootPath (if present) and returns
// the "path = " value of every [submodule "..."] section — i.e. every
// directory git considers a separate, externally-owned repository checked
// out inside this one. This is the cleanest available signal for
// "third-party code vendored into the tree": unlike a folder-name blocklist,
// it catches a submodule regardless of what its directory happens to be
// called (a vendored fork named after its own project, a submodule at a
// deeply nested path, …).
func ParseGitSubmodules(rootPath string) []string {
	data, err := os.ReadFile(filepath.Join(rootPath, ".gitmodules"))
	if err != nil {
		return nil
	}
	var paths []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "path") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "path"))
		if !strings.HasPrefix(line, "=") {
			continue
		}
		p := strings.TrimSpace(strings.TrimPrefix(line, "="))
		if p != "" {
			paths = append(paths, filepath.FromSlash(p))
		}
	}
	return paths
}
