package lang_test

import (
	"fmt"
	_ "github.com/exey/archscope/internal/lang"
	"github.com/exey/archscope/internal/langspec"
	"github.com/exey/archscope/internal/parser"
	"os"
	"testing"
)

func TestKotlinDeclParsing(t *testing.T) {
	content := `package com.example

@HiltViewModel
class MainViewModel : ViewModel() {
	fun loadData(): String = "data"
}

data class UserProfile(val id: Long)

interface Repository {
	fun findById(id: Long): UserProfile?
}

object AppConfig { val URL = "x" }

enum class Status { ACTIVE, INACTIVE }

sealed class Result<T>
`
	f, _ := os.CreateTemp("", "*.kt")
	f.WriteString(content)
	f.Close()
	defer os.Remove(f.Name())

	p := parser.New(langspec.Default)
	pf, err := p.Parse(f.Name(), "app", "")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Declarations (%d):\n", len(pf.Declarations))
	for _, d := range pf.Declarations {
		fmt.Printf("  kind=%-12s name=%s\n", d.Kind, d.Name)
	}
	if len(pf.Declarations) == 0 {
		t.Error("expected declarations, got none")
	}
}
