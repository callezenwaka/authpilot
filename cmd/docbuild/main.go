// docbuild pre-renders the Furnace doc pages to static HTML for Netlify hosting.
// Run from the repo root: go run ./cmd/docbuild
package main

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	goldhtml "github.com/yuin/goldmark/renderer/html"
)

var docMeta = []struct {
	Slug  string
	Title string
}{
	{"installation", "Installation"},
	{"onboarding", "Onboarding"},
	{"providers", "Providers"},
	{"integration", "Integration Guide"},
	{"api-reference", "API Reference"},
	{"configuration", "Configuration"},
	{"security", "Security"},
	{"login-simulation", "Login Simulation"},
}

var md = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithRendererOptions(goldhtml.WithUnsafe()),
)

func main() {
	out := "docs"

	copyFile("server/web/static/favicon.svg", filepath.Join(out, "favicon.svg"))
	copyFile("server/web/static/furnace.svg", filepath.Join(out, "furnace.svg"))

	docTmpl := mustTemplate("server/web/templates/doc.html")

	for _, doc := range docMeta {
		src := must(os.ReadFile(filepath.Join("server", "web", "doc", doc.Slug+".md")))

		var buf bytes.Buffer
		check(md.Convert(src, &buf))

		dir := filepath.Join(out, "doc", doc.Slug)
		check(os.MkdirAll(dir, 0o755))

		f := mustFile(filepath.Join(dir, "index.html"))
		check(docTmpl.Execute(f, map[string]any{
			"Slug":  doc.Slug,
			"Title": doc.Title,
			"Body":  template.HTML(buf.String()),
			"Local": false,
		}))
		f.Close()
		fmt.Printf("  docs/doc/%s/index.html\n", doc.Slug)
	}

	homeTmpl := mustTemplate("server/web/templates/doc-home.html")
	dir := filepath.Join(out, "doc", "index")
	check(os.MkdirAll(dir, 0o755))
	f := mustFile(filepath.Join(dir, "index.html"))
	check(homeTmpl.Execute(f, map[string]any{"Local": false}))
	f.Close()
	fmt.Println("  docs/doc/index/index.html")

	fmt.Println("done.")
}

func mustTemplate(path string) *template.Template {
	data := must(os.ReadFile(path))
	t, err := template.New(filepath.Base(path)).Parse(string(data))
	check(err)
	return t
}

func copyFile(src, dst string) {
	check(os.MkdirAll(filepath.Dir(dst), 0o755))
	data := must(os.ReadFile(src))
	check(os.WriteFile(dst, data, 0o644))
	fmt.Printf("  %s\n", dst)
}

func mustFile(path string) *os.File {
	f, err := os.Create(path)
	check(err)
	return f
}

func must[T any](v T, err error) T {
	check(err)
	return v
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
