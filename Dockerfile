FROM node:22-alpine AS spa-builder
WORKDIR /src
COPY client/admin-spa/package*.json client/admin-spa/
RUN cd client/admin-spa && npm ci
COPY client/admin-spa client/admin-spa
RUN cd client/admin-spa && npm run build

FROM golang:1.26.2-alpine3.23 AS builder

# Upgrade Alpine packages to clear known CVEs in the builder layer.
# The final image is chainguard/static and carries none of these packages.
RUN apk upgrade --no-cache

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=spa-builder /src/client/admin-spa/dist server/web/static/admin

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags prod -o /out/furnace ./server/cmd/furnace

FROM cgr.dev/chainguard/static:latest
WORKDIR /app
COPY --from=builder /out/furnace /app/furnace

EXPOSE 8025 8026
ENTRYPOINT ["/app/furnace"]
