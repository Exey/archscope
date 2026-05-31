package arch

import (
	"strings"
	"testing"

	"github.com/exey/archscope/internal/parser"

	// Register language specs so Client flags (swift = client) are populated;
	// the module switches to layered mode for non-client languages.
	_ "github.com/exey/archscope/internal/lang"
)

func pf(path, lang string, lines int, imports []string, decls ...parser.Declaration) *parser.ParsedFile {
	return &parser.ParsedFile{
		FilePath: path, LanguageID: lang, LineCount: lines,
		Imports: imports, Declarations: decls,
	}
}

func cls(name string) parser.Declaration {
	return parser.Declaration{Name: name, Kind: parser.DeclClass}
}
func strct(name string) parser.Declaration {
	return parser.Declaration{Name: name, Kind: parser.DeclStruct}
}

func TestDetectsMVVM(t *testing.T) {
	files := []*parser.ParsedFile{
		pf("App/Views/ProfileView.swift", "swift", 20, []string{"SwiftUI"}, strct("ProfileView")),
		pf("App/Views/SettingsView.swift", "swift", 20, []string{"SwiftUI"}, strct("SettingsView")),
		pf("App/ViewModels/ProfileViewModel.swift", "swift", 30, []string{"Combine"}, cls("ProfileViewModel")),
		pf("App/ViewModels/SettingsViewModel.swift", "swift", 30, []string{"Combine"}, cls("SettingsViewModel")),
		pf("App/Models/User.swift", "swift", 10, nil, strct("User")),
	}
	res, ok := (Module{}).Analyze(files).(Result)
	if !ok {
		t.Fatal("Analyze did not return arch.Result")
	}
	if !res.HasDetection() {
		t.Fatal("expected an architecture pattern to be detected")
	}
	top := res.Patterns[0]
	if !strings.Contains(top.Name, "MVVM") {
		t.Errorf("top pattern = %q, want it to contain MVVM", top.Name)
	}
	if top.Confidence < confidenceThreshold {
		t.Errorf("confidence %.2f below threshold %.2f", top.Confidence, confidenceThreshold)
	}
}

func TestDetectsFrameworkComponents(t *testing.T) {
	files := []*parser.ParsedFile{
		pf("App/ProfileView.swift", "swift", 20, []string{"SwiftUI", "Combine"}, strct("ProfileView")),
	}
	res := (Module{}).Analyze(files).(Result)
	var names []string
	for _, c := range res.Components {
		names = append(names, c.Name)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "SwiftUI") || !strings.Contains(joined, "Combine") {
		t.Errorf("components = %v, want SwiftUI and Combine", names)
	}
}

func TestRenderHTMLContainsPattern(t *testing.T) {
	files := []*parser.ParsedFile{
		pf("App/ViewModels/AViewModel.swift", "swift", 30, []string{"Combine"}, cls("AViewModel")),
		pf("App/Views/AView.swift", "swift", 20, []string{"SwiftUI"}, strct("AView")),
	}
	res := (Module{}).Analyze(files)
	out := (Module{}).RenderHTML(res)
	if !strings.Contains(out, "as-arch__pattern") {
		t.Errorf("rendered HTML missing pattern markup:\n%s", out)
	}
}

func TestEmptyInputRendersGracefully(t *testing.T) {
	out := (Module{}).RenderHTML((Module{}).Analyze(nil))
	if !strings.Contains(out, "as-empty") {
		t.Errorf("expected empty-state note, got: %s", out)
	}
}
