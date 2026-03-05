# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Module download (cache layer)
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build main binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o memoshield .

# Build seed tool
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o seed ./cmd/seed

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates iptables

WORKDIR /app

# Copy binaries
COPY --from=builder /build/memoshield .
COPY --from=builder /build/seed .

# Copy static assets and templates
COPY static/ ./static/
COPY templates/ ./templates/

# Environment variables
ENV PORT=5000 \
    ENABLE_MOCK_STREAM=1 \
    MOCK_STREAM_INTERVAL=4 \
    ADMIN_PASSWORD=admin

# Seed demo data
RUN ./seed

EXPOSE 5000

ENTRYPOINT ["./memoshield"]
