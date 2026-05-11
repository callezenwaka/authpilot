package httpapi

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer/html"

	"furnace/server/web"
)

func isLocal(r *http.Request) bool {
	h := r.Host
	return strings.HasPrefix(h, "localhost") ||
		strings.HasPrefix(h, "127.0.0.1") ||
		strings.HasPrefix(h, "[::1]")
}

var md = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithRendererOptions(html.WithUnsafe()),
)

var docMeta = map[string]string{
	"installation":     "Installation",
	"onboarding":       "Onboarding",
	"providers":        "Providers",
	"integration":      "Integration Guide",
	"api-reference":    "API Reference",
	"configuration":    "Configuration",
	"security":         "Security",
	"login-simulation": "Login Simulation",
}

func docHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := mux.Vars(r)["slug"]
		title, ok := docMeta[slug]
		if !ok {
			http.NotFound(w, r)
			return
		}

		src, err := web.ReadDoc(slug + ".md")
		if err != nil {
			http.Error(w, "doc not found", http.StatusNotFound)
			return
		}

		var buf bytes.Buffer
		if err := md.Convert(src, &buf); err != nil {
			http.Error(w, "render error", http.StatusInternalServerError)
			return
		}

		tmpl, err := web.ParseTemplate("doc.html")
		if err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, map[string]any{
			"Slug":  slug,
			"Title": title,
			"Body":  template.HTML(buf.String()),
			"Local": isLocal(r),
		})
	}
}

func docHomeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := web.ParseTemplate("doc-home.html")
		if err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, map[string]any{
			"Local": isLocal(r),
		})
	}
}

func docIndexHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/doc/index", http.StatusFound)
	}
}
