# golang:1.27.3-alpine3.24
FROM docker.io/library/golang:1.27.3-alpine3.24@sha256:fa4881266890ef051f0ce63afdfaccb69bbe8186084387f4fafd60d7ecbabc71 AS builder
WORKDIR /app
COPY go.mod ./
COPY *.go ./
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mail-fake .

# alpine:3.24.3
FROM docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
# CI only (tests/e2e/apps/mail-fake): never published.
RUN addgroup -S -g 10011 mailfake \
 && adduser -S -D -H -u 10011 -G mailfake mailfake \
 && mkdir -p /data && chown 10011:10011 /data && chmod 0700 /data
COPY --from=builder /mail-fake /usr/local/bin/mail-fake
USER 10011:10011
VOLUME /data
EXPOSE 8080 8081 9100 10025 10465 10587 10993
ENTRYPOINT ["mail-fake"]
