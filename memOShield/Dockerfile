FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /memoshield .

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 memoshield && mkdir /data && chown memoshield /data
COPY --from=builder /memoshield /usr/local/bin/memoshield
USER memoshield
ENV MEMOSHIELD_DATA_DIR=/data MEMOSHIELD_JOURNAL=0 MEMOSHIELD_MODE=monitor
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/memoshield"]
