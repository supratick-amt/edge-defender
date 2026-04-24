FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /honeypot .

FROM alpine:latest

RUN addgroup -S honeypot && adduser -S -G honeypot honeypot

# Create /logs before dropping to the non-root user so the volume mount
# is writable. Docker-created named volumes are owned by root by default.
RUN mkdir -p /logs && chown honeypot:honeypot /logs

WORKDIR /app
COPY --from=build /honeypot /app/honeypot
COPY configs/ /app/configs/

USER honeypot

EXPOSE 80 443 8080 8443

ENTRYPOINT ["/app/honeypot"]
