# golang:1.27.3-alpine3.24
FROM docker.io/library/golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder
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
FROM docker.io/library/alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
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
