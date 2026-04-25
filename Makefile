.PHONY: build test lint check-ports run run-auto run-default run-bg stop health admin-build notify-build dev setup

RUN_HTTP_ADDR ?= :18025
RUN_PROTOCOL_ADDR ?= :18026
DEFAULT_HTTP_ADDR ?= :8025
DEFAULT_PROTOCOL_ADDR ?= :8026
BUILD ?= 0
build ?=
WATCH ?= 0
ALL ?= 0
all ?=
PID_FILE ?= .furnace.pid
HEALTH_URL ?= http://127.0.0.1$(RUN_HTTP_ADDR)/health
BG_BIN ?= .tmp/furnace

ifneq ($(strip $(all)),)
ALL := $(all)
endif

ifneq ($(strip $(build)),)
BUILD := $(build)
endif

build:
	go build -tags prod -o furnace ./server/cmd/furnace

test:
	go test ./server/...

lint:
	golangci-lint run

check-ports:
	@http_port="$(RUN_HTTP_ADDR)"; http_port=$${http_port#:}; \
	if lsof -nP -iTCP:$$http_port -sTCP:LISTEN >/dev/null 2>&1; then \
		echo "http port $$http_port already in use"; \
		exit 1; \
	fi
	@protocol_port="$(RUN_PROTOCOL_ADDR)"; protocol_port=$${protocol_port#:}; \
	if lsof -nP -iTCP:$$protocol_port -sTCP:LISTEN >/dev/null 2>&1; then \
		echo "protocol port $$protocol_port already in use"; \
		exit 1; \
	fi

run: check-ports
	@if [ "$(BUILD)" = "1" ] || [ "$(BUILD)" = "true" ]; then \
		$(MAKE) admin-build; \
	fi
	@mkdir -p .tmp
	@echo "Starting Furnace on HTTP $(RUN_HTTP_ADDR) and protocol $(RUN_PROTOCOL_ADDR)"
	@echo "Health check: curl -i $(HEALTH_URL)"
	@echo "Admin URL: http://127.0.0.1$(RUN_HTTP_ADDR)/admin"
	@echo "Stop: press Ctrl+C"
	@if [ "$(WATCH)" = "1" ] || [ "$(WATCH)" = "true" ]; then \
		echo "Starting admin SPA watch build (log: .tmp/admin-watch.log)"; \
		cd client/admin-spa && npm install && npm run build -- --watch > ../../.tmp/admin-watch.log 2>&1 & watcher_pid=$$!; \
		trap 'kill $$watcher_pid 2>/dev/null || true' INT TERM EXIT; \
		go run ./server/cmd/furnace -http-addr $(RUN_HTTP_ADDR) -protocol-addr $(RUN_PROTOCOL_ADDR); \
		status=$$?; \
		kill $$watcher_pid 2>/dev/null || true; \
		exit $$status; \
	else \
		go run ./server/cmd/furnace -http-addr $(RUN_HTTP_ADDR) -protocol-addr $(RUN_PROTOCOL_ADDR); \
	fi

run-auto:
	@if [ "$(BUILD)" = "1" ] || [ "$(BUILD)" = "true" ]; then \
		$(MAKE) admin-build; \
	fi
	@mkdir -p .tmp
	@default_http_port="$(DEFAULT_HTTP_ADDR)"; default_http_port=$${default_http_port#:}; \
	default_protocol_port="$(DEFAULT_PROTOCOL_ADDR)"; default_protocol_port=$${default_protocol_port#:}; \
	if lsof -nP -iTCP:$$default_http_port -sTCP:LISTEN >/dev/null 2>&1 || \
	   lsof -nP -iTCP:$$default_protocol_port -sTCP:LISTEN >/dev/null 2>&1; then \
		http_addr="$(RUN_HTTP_ADDR)"; \
		protocol_addr="$(RUN_PROTOCOL_ADDR)"; \
		echo "Default ports are busy; falling back to safe ports $$http_addr/$$protocol_addr"; \
	else \
		http_addr="$(DEFAULT_HTTP_ADDR)"; \
		protocol_addr="$(DEFAULT_PROTOCOL_ADDR)"; \
		echo "Using default ports $$http_addr/$$protocol_addr"; \
	fi; \
	echo "Health check: curl -i http://127.0.0.1$$http_addr/health"; \
	echo "Admin URL: http://127.0.0.1$$http_addr/admin"; \
	echo "Stop: press Ctrl+C"; \
	if [ "$(WATCH)" = "1" ] || [ "$(WATCH)" = "true" ]; then \
		echo "Starting admin SPA watch build (log: .tmp/admin-watch.log)"; \
		cd client/admin-spa && npm install && npm run build -- --watch > ../../.tmp/admin-watch.log 2>&1 & watcher_pid=$$!; \
		trap 'kill $$watcher_pid 2>/dev/null || true' INT TERM EXIT; \
		go run ./server/cmd/furnace -http-addr $$http_addr -protocol-addr $$protocol_addr; \
		status=$$?; \
		kill $$watcher_pid 2>/dev/null || true; \
		exit $$status; \
	else \
		go run ./server/cmd/furnace -http-addr $$http_addr -protocol-addr $$protocol_addr; \
	fi

run-default:
	go run ./server/cmd/furnace

run-bg: check-ports
	@if [ "$(BUILD)" = "1" ] || [ "$(BUILD)" = "true" ]; then \
		$(MAKE) admin-build; \
	fi
	@mkdir -p .tmp
	@go build -o $(BG_BIN) ./server/cmd/furnace
	@nohup $(BG_BIN) -http-addr $(RUN_HTTP_ADDR) -protocol-addr $(RUN_PROTOCOL_ADDR) > .tmp/furnace.log 2>&1 & echo $$! > $(PID_FILE)
	@sleep 1
	@if ! curl -fsS $(HEALTH_URL) >/dev/null; then \
		echo "furnace failed to start; showing log tail"; \
		tail -n 40 .tmp/furnace.log || true; \
		exit 1; \
	fi
	@echo "furnace started in background (pid $$(cat $(PID_FILE)))"
	@echo "logs: .tmp/furnace.log"

stop:
	@stopped=0; \
	if [ -f $(PID_FILE) ]; then \
		pid=$$(cat $(PID_FILE)); \
		kill $$pid 2>/dev/null || true; \
		rm -f $(PID_FILE); \
		echo "furnace stopped (pid $$pid)"; \
		stopped=1; \
	fi; \
	for addr in "$(RUN_HTTP_ADDR)" "$(RUN_PROTOCOL_ADDR)"; do \
		port=$${addr#:}; \
		pids=$$(lsof -t -nP -iTCP:$$port -sTCP:LISTEN 2>/dev/null || true); \
		if [ -n "$$pids" ]; then \
			kill $$pids 2>/dev/null || true; \
			echo "killed listener(s) on port $$port: $$pids"; \
			stopped=1; \
		fi; \
	done; \
	if [ "$(ALL)" = "1" ] || [ "$(ALL)" = "true" ]; then \
		for port in 8025 8026; do \
			pids=$$(lsof -t -nP -iTCP:$$port -sTCP:LISTEN 2>/dev/null || true); \
			if [ -n "$$pids" ]; then \
				kill $$pids 2>/dev/null || true; \
				echo "killed listener(s) on default port $$port: $$pids"; \
				stopped=1; \
			fi; \
		done; \
		for pattern in '/server/cmd/furnace' '/.tmp/furnace' '/Library/Caches/go-build/.*/furnace'; do \
			pids=$$(pgrep -f "$$pattern" 2>/dev/null || true); \
			if [ -n "$$pids" ]; then \
				kill $$pids 2>/dev/null || true; \
				echo "killed process(es) matching $$pattern: $$pids"; \
				stopped=1; \
			fi; \
		done; \
	fi; \
	if [ $$stopped -eq 0 ]; then \
		echo "no running process found (use ALL=1 for broader cleanup)"; \
	fi

health:
	@curl -sS -i $(HEALTH_URL) | sed -n '1,8p'

dev:
	@mkdir -p .tmp
	@echo "Starting admin SPA watcher (log: .tmp/admin-watch.log)"
	@cd client/admin-spa && npm install && npm run build -- --watch > ../../.tmp/admin-watch.log 2>&1 & echo $$! > .tmp/admin-spa.pid
	@echo "Starting Go server with hot-reload (air)"
	@trap 'kill $$(cat .tmp/admin-spa.pid 2>/dev/null) 2>/dev/null || true; rm -f .tmp/admin-spa.pid' INT TERM EXIT; \
	air

setup:
	cd client/admin-spa && npm install

admin-build:
	cd client/admin-spa && npm install && npm run build
