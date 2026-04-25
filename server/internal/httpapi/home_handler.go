package httpapi

import (
	"net/http"

	"furnace/server/web"
)

func homeHandler(apiKey string) http.HandlerFunc {
	masked := "—"
	if len(apiKey) > 8 {
		masked = apiKey[:8] + "••••••••••••••••••••••••••••••••"
	} else if apiKey != "" {
		masked = apiKey
	}

	return func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := web.ParseTemplate("home.html")
		if err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, map[string]string{"MaskedKey": masked})
	}
}
