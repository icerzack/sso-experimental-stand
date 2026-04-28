FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY profile-a/vulnerable/app ./profile-a/vulnerable/app
RUN CGO_ENABLED=0 GOOS=linux go build -o sso-app ./profile-a/vulnerable/app

FROM alpine:latest
RUN apk --no-cache add ca-certificates wget
WORKDIR /app
COPY --from=builder /build/sso-app .
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1
CMD ["./sso-app"]
