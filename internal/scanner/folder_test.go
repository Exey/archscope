package scanner

import (
	"github.com/exey/archscope/internal/langspec"
	"testing"
)

func TestTopFolder(t *testing.T) {
	cases := []struct{ root, file, want string }{
		{"/repo", "/repo/pharmen/views.py", "pharmen"},
		{"/repo", "/repo/gptzakaz/main.go", "gptzakaz"},
		{"/repo", "/repo/main.go", ""},        // directly in root
		{"/repo", "/repo/a/b/c/deep.go", "a"}, // deeply nested → first segment
	}
	for _, c := range cases {
		got := topFolder(c.root, c.file)
		if got != c.want {
			t.Errorf("topFolder(%q, %q) = %q, want %q", c.root, c.file, got, c.want)
		}
	}
}

func TestPlatformShortLabel(t *testing.T) {
	if got := platformShortLabel(langspec.PlatformPython); got != "Py" {
		t.Errorf("Python short label: want Py, got %s", got)
	}
	if got := platformShortLabel(langspec.PlatformTSJS); got != "TS" {
		t.Errorf("TSJS short label: want TS, got %s", got)
	}
	if got := platformShortLabel(langspec.PlatformGo); got != "Go" {
		t.Errorf("Go short label: want Go, got %s", got)
	}
}

func TestTabLabel_FolderAsTab(t *testing.T) {
	pg := &PlatformGroup{
		Platform:         langspec.PlatformGo + ":pharmen",
		LanguagePlatform: langspec.PlatformGo,
		Label:            "pharmen",
	}
	if got := pg.TabLabel(); got != "pharmen" {
		t.Errorf("want 'pharmen', got %q", got)
	}
}

func TestTabLabel_Normal(t *testing.T) {
	pg := &PlatformGroup{
		Platform:         langspec.PlatformGo,
		LanguagePlatform: langspec.PlatformGo,
	}
	if got := pg.TabLabel(); got != "Go" {
		t.Errorf("want 'Go', got %q", got)
	}
}
