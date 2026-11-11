# golang:1.27.3-alpine3.24
FROM golang:1.27.3-alpine3.24@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS builder
# CI-only: GO_TAGS=testprovider adds the fake DNS provider (never in the
# production image, which is built without build args).
ARG GO_TAGS=""
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -tags "$GO_TAGS" -ldflags="-s -w" -o /domains .

# alpine:3.24.3
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk add --no-cache ca-certificates \
 && addgroup -S -g 10004 domains \
 && adduser -S -D -H -u 10004 -G domains domains \
 && mkdir -p /data && chown 10004:10004 /data && chmod 0700 /data
COPY --from=builder /domains /usr/local/bin/domains
# Non-root. Reads /run/portcullis/domains/{api-secret (group 10001: compose
# adds that group), age.key, certs-endpoint/{ca.crt,server.crt,server.key}}
# (group 10004, 0640) and writes only /data (domains_data, age-encrypted).
# No AWS config / credential files and no instance metadata: Route 53
# credentials come only from the domain's stored credentials.
ENV AWS_CONFIG_FILE=/dev/null \
    AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    AWS_EC2_METADATA_DISABLED=true
USER 10004:10004
VOLUME /data
EXPOSE 8080 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["domains", "healthcheck"]
ENTRYPOINT ["domains"]
