package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	sqlPrefix       = regexp.MustCompile(`(?i)^\s*(SELECT|INSERT|UPDATE|DELETE|MERGE|WITH|CREATE|ALTER|DROP|TRUNCATE)\b`)
	tableName       = regexp.MustCompile(`(?i)\b(FROM|JOIN|INTO|UPDATE|TABLE|REFERENCES|ON)\s+(IF\s+(NOT\s+)?EXISTS\s+)?(ONLY\s+)?(([A-Za-z_][A-Za-z_0-9]*)\.)?"?(ingest_job_plans|ingest_jobs|upload_tasks|memories|sessions)"?\b`)
	dynamicRelation = regexp.MustCompile(`(?i)\b(FROM|JOIN|INTO|UPDATE|TABLE|REFERENCES|ON)\s+(IF\s+(NOT\s+)?EXISTS\s+)?(ONLY\s+)?\{\{dynamic\}\}`)
	lineComment     = regexp.MustCompile(`(?m)--[^\n]*`)
	blockComment    = regexp.MustCompile(`(?s)/\*.*?\*/`)
	formatDirective = regexp.MustCompile(`%(\[[0-9]+\])?[-+#0 ']*[0-9]*(\.[0-9]+)?[bcdoOqxXUeEfFgGspvtT]`)
	sourceSQLVerb   = regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|MERGE|WITH|CREATE|ALTER|DROP|TRUNCATE)\b`)
)

type candidate struct {
	Owner  string   `json:"owner"`
	Line   int      `json:"line"`
	Text   string   `json:"text"`
	Tables []string `json:"tables"`
}

type expressionRenderer struct {
	resolving map[*ast.Object]bool
	cache     map[ast.Expr]renderedExpression
}

type renderedExpression struct {
	text string
	ok   bool
}

func (r *expressionRenderer) render(expr ast.Expr) (string, bool) {
	if cached, ok := r.cache[expr]; ok {
		return cached.text, cached.ok
	}
	text, ok := r.renderUncached(expr)
	r.cache[expr] = renderedExpression{text: text, ok: ok}
	return text, ok
}

func (r *expressionRenderer) renderUncached(expr ast.Expr) (string, bool) {
	switch value := expr.(type) {
	case *ast.BasicLit:
		if value.Kind != token.STRING {
			return "", false
		}
		text, err := strconv.Unquote(value.Value)
		return text, err == nil
	case *ast.ParenExpr:
		return r.render(value.X)
	case *ast.BinaryExpr:
		if value.Op != token.ADD {
			return "", false
		}
		left, leftOK := r.render(value.X)
		right, rightOK := r.render(value.Y)
		if !leftOK && !rightOK {
			return "", false
		}
		if !leftOK {
			left = "{{dynamic}}"
		}
		if !rightOK {
			right = "{{dynamic}}"
		}
		return left + right, true
	case *ast.Ident:
		if value.Obj == nil || r.resolving[value.Obj] {
			return "{{dynamic}}", true
		}
		r.resolving[value.Obj] = true
		defer delete(r.resolving, value.Obj)
		switch declaration := value.Obj.Decl.(type) {
		case *ast.ValueSpec:
			for index, name := range declaration.Names {
				if name.Obj != value.Obj || len(declaration.Values) == 0 {
					continue
				}
				valueIndex := index
				if len(declaration.Values) == 1 {
					valueIndex = 0
				}
				if valueIndex < len(declaration.Values) {
					return r.render(declaration.Values[valueIndex])
				}
			}
		case *ast.AssignStmt:
			for index, target := range declaration.Lhs {
				ident, ok := target.(*ast.Ident)
				if !ok || ident.Obj != value.Obj || index >= len(declaration.Rhs) {
					continue
				}
				return r.render(declaration.Rhs[index])
			}
		}
		return "{{dynamic}}", true
	case *ast.CallExpr:
		selector, ok := value.Fun.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		packageName, packageOK := selector.X.(*ast.Ident)
		if !packageOK || packageName.Name != "fmt" ||
			selector.Sel.Name != "Sprintf" || len(value.Args) == 0 {
			return "", false
		}
		format, ok := r.render(value.Args[0])
		if !ok {
			return "", false
		}
		return formatDirective.ReplaceAllString(format, "{{dynamic}}"), true
	case *ast.SelectorExpr, *ast.IndexExpr, *ast.IndexListExpr:
		return "{{dynamic}}", true
	default:
		return "", false
	}
}

func canContainSQL(expr ast.Expr) bool {
	switch value := expr.(type) {
	case *ast.BasicLit:
		return value.Kind == token.STRING
	case *ast.BinaryExpr:
		return value.Op == token.ADD
	case *ast.CallExpr:
		selector, ok := value.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		packageName, packageOK := selector.X.(*ast.Ident)
		return packageOK && packageName.Name == "fmt" &&
			selector.Sel.Name == "Sprintf"
	default:
		return false
	}
}

func normalizeSQL(text string) string {
	text = lineComment.ReplaceAllString(text, " ")
	text = blockComment.ReplaceAllString(text, " ")
	return strings.Join(strings.Fields(text), " ")
}

func extractTables(text string) []string {
	tableSet := map[string]bool{}
	for _, match := range tableName.FindAllStringSubmatch(text, -1) {
		tableSet[strings.ToLower(match[7])] = true
	}
	if len(tableSet) == 0 && dynamicRelation.MatchString(text) {
		tableSet["<dynamic-relation>"] = true
	}
	tables := make([]string, 0, len(tableSet))
	for name := range tableSet {
		tables = append(tables, name)
	}
	sort.Strings(tables)
	return tables
}

func isCandidate(text string) bool {
	return sqlPrefix.MatchString(text) &&
		(tableName.MatchString(text) || dynamicRelation.MatchString(text))
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run scripts/extract-go-sql.go <upstream-server-root>")
		os.Exit(2)
	}
	root, err := filepath.Abs(os.Args[1])
	if err != nil {
		panic(err)
	}

	fset := token.NewFileSet()
	result := make([]candidate, 0)
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == "vendor" || entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/internal/testutil/") {
			return nil
		}
		source, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if !sourceSQLVerb.Match(source) {
			return nil
		}
		file, parseErr := parser.ParseFile(fset, path, source, 0)
		if parseErr != nil {
			return parseErr
		}
		parents := map[ast.Node]ast.Node{}
		stack := make([]ast.Node, 0)
		ast.Inspect(file, func(node ast.Node) bool {
			if node == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			if len(stack) > 0 {
				parents[node] = stack[len(stack)-1]
			}
			stack = append(stack, node)
			return true
		})

		renderer := &expressionRenderer{
			resolving: map[*ast.Object]bool{},
			cache:     map[ast.Expr]renderedExpression{},
		}
		seen := map[string]bool{}
		ast.Inspect(file, func(node ast.Node) bool {
			expression, ok := node.(ast.Expr)
			if !ok || !canContainSQL(expression) {
				return true
			}
			text, ok := renderer.render(expression)
			if !ok {
				return true
			}
			text = normalizeSQL(text)
			if !isCandidate(text) {
				return true
			}

			if parentExpression, ok := parents[expression].(ast.Expr); ok &&
				canContainSQL(parentExpression) {
				parentText, parentOK := renderer.render(parentExpression)
				parentText = normalizeSQL(parentText)
				if parentOK && isCandidate(parentText) {
					return true
				}
			}

			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				panic(relErr)
			}
			owner := filepath.ToSlash(filepath.Join("upstream/server", rel))
			line := fset.Position(expression.Pos()).Line
			key := fmt.Sprintf("%s\n%d\n%s", owner, line, text)
			if seen[key] {
				return true
			}
			seen[key] = true
			result = append(result, candidate{
				Owner:  owner,
				Line:   line,
				Text:   text,
				Tables: extractTables(text),
			})
			return true
		})
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Owner != result[j].Owner {
			return result[i].Owner < result[j].Owner
		}
		if result[i].Line != result[j].Line {
			return result[i].Line < result[j].Line
		}
		return result[i].Text < result[j].Text
	})
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		panic(err)
	}
}
