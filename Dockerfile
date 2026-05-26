FROM node:26-alpine AS client
WORKDIR /src
COPY client/package*.json client/
RUN cd client && npm ci
COPY client client
RUN cd client && npm run build

FROM golang:1.26.3-alpine3.23 AS builder

# Upgrade Alpine packages to clear known CVEs in the builder layer.
# The final image is chainguard/static and carries none of these packages.
RUN apk upgrade --no-cache

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=client /src/server/web/static/admin server/web/static/admin

ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -tags prod -o /out/furnace ./server/cmd/furnace
RUN mkdir -p /data

FROM cgr.dev/chainguard/static:latest
WORKDIR /app
COPY --from=builder /out/furnace /app/furnace
# /data is the SQLite volume mount point; chainguard nonroot uid/gid is 65532
COPY --chown=65532:65532 --from=builder /data /data

EXPOSE 8025 8026
ENTRYPOINT ["/app/furnace"]
