FROM golang:1.20-alpine AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /usr/local/bin/memoengine ./

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=builder /usr/local/bin/memoengine /usr/local/bin/memoengine
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/memoengine"]
