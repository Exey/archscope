// Package fetch resolves an analysis source — either a local path or a remote
// git URL — to an on-disk directory. Remote URLs are cloned into a temporary
// directory (requirement #5); the returned Cleanup removes it.
package fetch

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Source describes where to analyze. Exactly one of LocalPath / RemoteURL set.
type Source struct {
	LocalPath string
	RemoteURL string // https://github.com/org/repo(.git) or git@host:org/repo.git
	Ref       string // optional branch/tag/sha; "" = default branch
	Depth     int    // 0 = full history (git stats need it); >0 = shallow
}

// Resolved is an on-disk location plus cleanup.
type Resolved struct {
	Path     string
	Cleanup  func() error
	WasClone bool
}

// IsRemoteURL reports whether arg looks like a git URL rather than a local path.
func IsRemoteURL(arg string) bool {
	return strings.HasPrefix(arg, "http://") ||
		strings.HasPrefix(arg, "https://") ||
		strings.HasPrefix(arg, "git@") ||
		strings.HasPrefix(arg, "ssh://") ||
		strings.HasPrefix(arg, "git://")
}

// FromArg builds a Source from a CLI argument and fetch options.
func FromArg(arg, ref string, depth int) Source {
	if IsRemoteURL(arg) {
		return Source{RemoteURL: arg, Ref: ref, Depth: depth}
	}
	return Source{LocalPath: arg}
}

// Resolve returns a local directory for src. For RemoteURL it shells out to
// `git clone` into a fresh temp dir, honoring Ref and Depth, and returns a
// Cleanup that removes the temp dir. For LocalPath the path is returned as-is
// with a no-op Cleanup.
func Resolve(src Source) (*Resolved, error) {
	if src.RemoteURL == "" {
		if src.LocalPath == "" {
			return nil, fmt.Errorf("fetch: empty source")
		}
		return &Resolved{Path: src.LocalPath, Cleanup: func() error { return nil }}, nil
	}
	if _, err := exec.LookPath("git"); err != nil {
		return nil, fmt.Errorf("fetch: git not found on PATH (required for remote URLs): %w", err)
	}

	dir, err := os.MkdirTemp("", "archscope-clone-*")
	if err != nil {
		return nil, err
	}
	cleanup := func() error { return os.RemoveAll(dir) }

	args := []string{"clone"}
	if src.Depth > 0 {
		args = append(args, "--depth", strconv.Itoa(src.Depth))
	}
	if src.Ref != "" {
		// --branch accepts a branch or tag name (not an arbitrary sha).
		args = append(args, "--branch", src.Ref)
	}
	args = append(args, src.RemoteURL, dir)

	cmd := exec.Command("git", args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("fetch: git clone failed: %w", err)
	}

	// If Ref is a sha (clone --branch can't take one), check it out afterwards.
	if src.Ref != "" && src.Depth == 0 {
		_ = exec.Command("git", "-C", dir, "checkout", src.Ref).Run()
	}

	return &Resolved{Path: dir, Cleanup: cleanup, WasClone: true}, nil
}
