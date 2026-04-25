//go:build !prod

package web

import (
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
)

// AdminFS is nil in dev builds; disk-based file serving is used instead.
var AdminFS fs.FS

// ParseTemplate reads the named template from disk on every call so
// changes to .html files take effect without a server restart.
func ParseTemplate(name string) (*template.Template, error) {
	data, err := os.ReadFile(filepath.Join("server", "web", "templates", name))
	if err != nil {
		return nil, fmt.Errorf("read template %s: %w", name, err)
	}
	return template.New(name).Parse(string(data))
}

// ReadDoc reads the named Markdown file from disk on every call so
// edits take effect without a server restart.
func ReadDoc(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join("server", "web", "doc", name))
}
