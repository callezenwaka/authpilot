//go:build prod

package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"sync"
)

//go:embed templates
var embeddedTemplates embed.FS

//go:embed doc
var embeddedDoc embed.FS

//go:embed static/admin
var embeddedAdmin embed.FS

// AdminFS is the embedded admin SPA rooted at static/admin.
var AdminFS fs.FS = func() fs.FS {
	sub, _ := fs.Sub(embeddedAdmin, "static/admin")
	return sub
}()

var (
	parseOnce sync.Once
	parsed    map[string]*template.Template
	parseErr  error
)

func initTemplates() {
	parsed = make(map[string]*template.Template)
	for _, name := range []string{"home.html", "login.html", "mfa.html", "complete.html", "doc.html"} {
		data, err := embeddedTemplates.ReadFile("templates/" + name)
		if err != nil {
			parseErr = fmt.Errorf("read embedded template %s: %w", name, err)
			return
		}
		t, err := template.New(name).Parse(string(data))
		if err != nil {
			parseErr = fmt.Errorf("parse template %s: %w", name, err)
			return
		}
		parsed[name] = t
	}
}

// ParseTemplate returns the pre-parsed template. Templates are parsed once
// at startup from the embedded filesystem.
func ParseTemplate(name string) (*template.Template, error) {
	parseOnce.Do(initTemplates)
	if parseErr != nil {
		return nil, parseErr
	}
	t, ok := parsed[name]
	if !ok {
		return nil, fmt.Errorf("template not found: %s", name)
	}
	return t, nil
}

// ReadDoc reads the named Markdown file from the embedded doc filesystem.
func ReadDoc(name string) ([]byte, error) {
	return embeddedDoc.ReadFile("doc/" + name)
}
