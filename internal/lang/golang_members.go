package lang

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	archparser "github.com/exey/archscope/internal/parser"
)

// extractGoMembers is Go's phase-1 coupling/cohesion data source: it runs
// stdlib go/parser + go/ast (no new dependency) over the file this
// language's regex-based universal parser just processed, reusing the
// already-loaded `lines` as source (strings.Join, no re-read from disk) so
// it rides the existing single parse pass rather than adding a second
// file-tree walk. It's the most accurate of the four extractors (real AST,
// not a heuristic) since Go is the only language here with a parser in the
// standard library — see swift_members.go, typescript_members.go, and
// python_members.go for the regex/brace-or-indent equivalents the other
// languages use instead.
//
// The natural next step, now that four languages need this, is a shared
// multi-language AST layer (e.g. tree-sitter) that produces TypeMembers —
// and eventually Declarations/BigFunctions themselves — from one consistent
// pass instead of per-language regex specs plus these bespoke extractors.
// Until then: a file that fails to parse (rare, since it already survived
// the regex pass) just yields no members, not an error.
func extractGoMembers(filePath string, lines []string) []archparser.TypeMembers {
	src := strings.Join(lines, "\n")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, src, 0)
	if err != nil {
		return nil
	}

	fields := map[string][]string{} // type name -> field names
	fieldSet := map[string]map[string]bool{}
	var order []string
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				continue
			}
			var names []string
			for _, fld := range st.Fields.List {
				if len(fld.Names) == 0 {
					// Embedded field: the type name doubles as the field name.
					if n := goTypeName(fld.Type); n != "" {
						names = append(names, n)
					}
					continue
				}
				for _, n := range fld.Names {
					names = append(names, n.Name)
				}
			}
			fields[ts.Name.Name] = names
			set := make(map[string]bool, len(names))
			for _, n := range names {
				set[n] = true
			}
			fieldSet[ts.Name.Name] = set
			order = append(order, ts.Name.Name)
		}
	}

	methodsByType := map[string][]archparser.MethodMembers{}
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || len(fd.Recv.List) == 0 {
			continue
		}
		recvType := goTypeName(fd.Recv.List[0].Type)
		if recvType == "" {
			continue
		}
		var recvName string
		if len(fd.Recv.List[0].Names) > 0 {
			recvName = fd.Recv.List[0].Names[0].Name
		}
		mm := archparser.MethodMembers{Name: fd.Name.Name}
		if fd.Type.Params != nil {
			for _, p := range fd.Type.Params.List {
				if n := goTypeName(p.Type); n != "" && n != recvType {
					mm.ParamTypes = append(mm.ParamTypes, n)
				}
			}
		}
		if fd.Body != nil {
			own := fieldSet[recvType]
			seenField := map[string]bool{}
			seenExt := map[string]bool{}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.SelectorExpr:
					if id, ok := node.X.(*ast.Ident); ok && recvName != "" && id.Name == recvName {
						if own[node.Sel.Name] {
							seenField[node.Sel.Name] = true
						}
					}
				case *ast.CompositeLit:
					if n := goTypeName(node.Type); n != "" && n != recvType {
						seenExt[n] = true
					}
				case *ast.CallExpr:
					// Type conversion syntax `T(x)` — Fun is a bare identifier
					// matching a type declared in this file.
					if id, ok := node.Fun.(*ast.Ident); ok && id.Name != recvType {
						if _, isType := fieldSet[id.Name]; isType {
							seenExt[id.Name] = true
						}
					}
				}
				return true
			})
			for k := range seenField {
				mm.FieldRefs = append(mm.FieldRefs, k)
			}
			for k := range seenExt {
				if !goBuiltinTypes[k] {
					mm.ExternalRefs = append(mm.ExternalRefs, k)
				}
			}
			for _, pt := range mm.ParamTypes {
				if !seenExt[pt] && !goBuiltinTypes[pt] {
					mm.ExternalRefs = append(mm.ExternalRefs, pt)
				}
			}
		}
		methodsByType[recvType] = append(methodsByType[recvType], mm)
	}

	var out []archparser.TypeMembers
	for _, name := range order {
		methods := methodsByType[name]
		if len(methods) == 0 {
			// No methods declared on this type in this file — nothing for
			// coupling/cohesion to compute, skip it rather than emit noise.
			continue
		}
		out = append(out, archparser.TypeMembers{TypeName: name, Fields: fields[name], Methods: methods})
	}
	return out
}

// goBuiltinTypes are predeclared Go types — excluded from ExternalRefs
// (CBO counts coupling to other declared *types*, not primitive usage) but
// still kept in ParamTypes (CAM wants the full parameter-type vocabulary,
// primitives included).
var goBuiltinTypes = map[string]bool{
	"string": true, "bool": true, "byte": true, "rune": true, "error": true, "any": true,
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
	"float32": true, "float64": true, "complex64": true, "complex128": true,
}

// goTypeName reduces a type expression to its terminal identifier —
// "T" for T, *T, pkg.T, []T, *pkg.T, and similar shapes. Returns "" for
// anything more exotic (generics, func types, etc.) rather than guessing.
func goTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return goTypeName(t.X)
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.ArrayType:
		return goTypeName(t.Elt)
	default:
		return ""
	}
}
