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

var md = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithRendererOptions(html.WithUnsafe()),
)

var docMeta = map[string]string{
	"onboarding":       "Onboarding",
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
		})
	}
}

func docIndexHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// /doc redirects to the onboarding page as the default entry point.
		target := "/doc/onboarding"
		if !strings.HasSuffix(r.URL.Path, "/") {
			target = r.URL.Path + "/onboarding"
		}
		http.Redirect(w, r, target, http.StatusFound)
	}
}
