package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	httpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "furnace_http_requests_total",
		Help: "Total HTTP requests partitioned by method, path template, and status code.",
	}, []string{"method", "path", "status"})

	httpRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "furnace_http_request_duration_seconds",
		Help:    "HTTP request latency partitioned by method and path template.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})
)

func metricsHandler() http.Handler {
	return promhttp.Handler()
}

// instrumentMiddleware records request count and latency for every handler.
// It uses the gorilla/mux route template (e.g. /api/v1/users/{id}) as the
// path label to avoid high cardinality from literal resource IDs.
func instrumentMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		path := r.URL.Path
		if route := mux.CurrentRoute(r); route != nil {
			if tmpl, err := route.GetPathTemplate(); err == nil {
				path = tmpl
			}
		}

		status := strconv.Itoa(rw.status)
		elapsed := time.Since(start).Seconds()
		httpRequestsTotal.WithLabelValues(r.Method, path, status).Inc()
		httpRequestDuration.WithLabelValues(r.Method, path).Observe(elapsed)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}
