package opa

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	opaEvalTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "furnace_opa_eval_total",
		Help: "Total OPA evaluations partitioned by decision outcome.",
	}, []string{"decision"})

	opaEvalDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "furnace_opa_eval_duration_seconds",
		Help:    "OPA evaluation latency in seconds partitioned by decision outcome.",
		Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5},
	}, []string{"decision"})

	opaCompileErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "furnace_opa_compile_errors_total",
		Help: "Total OPA policy compile errors.",
	})

	opaBatchSize = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "furnace_opa_batch_size",
		Help:    "Number of checks per batch evaluation request.",
		Buckets: []float64{1, 5, 10, 25, 50, 100},
	})
)
