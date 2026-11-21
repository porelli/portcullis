# golang:1.27.3-alpine3.24
FROM docker.io/library/golang:1.27.3-alpine3.24@sha256:fa4881266890ef051f0ce63afdfaccb69bbe8186084387f4fafd60d7ecbabc71 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mailctl .
# Stalwart's web admin bundle for the read-only mail admin view (contract
# §19.13), pinned by version and sha256: Stalwart loads it from the file
# (the template copies it next to mailctl), never from the internet.
ARG WEBUI_VERSION=v2.1.0
ARG WEBUI_SHA256=c3627184e3d8dcc42acd49cff0f20d4ac3425a90e875bac83775e4eefbfc1286
RUN wget -q -O /webui.zip "https://github.com/stalwartlabs/webui/releases/download/${WEBUI_VERSION}/webui.zip" \
 && echo "${WEBUI_SHA256}  /webui.zip" | sha256sum -c -

# alpine:3.24.3
FROM docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
# ghcr.io/porelli/portcullis-mailctl: the stalwart template's adapter
# (contract §19; .github/workflows/mailctl.yml). /data (the template's
# adapter_data): state.json and the API key the bootstrap job writes, 10010
# only (0700). No engine access, no LLDAP / Keycloak / DNS credentials; it
# reads the Hub's slot files at /run/portcullis/mail/slot (group 2000, the
# override's group_add) and the certificate at /run/portcullis/mail/tls.
RUN apk add --no-cache ca-certificates \
 && addgroup -S -g 10010 mailctl \
 && adduser -S -D -H -u 10010 -G mailctl mailctl \
 && mkdir -p /data && chown 10010:10010 /data && chmod 0700 /data
COPY --from=builder /mailctl /usr/local/bin/mailctl
COPY --from=builder /webui.zip /usr/share/mailctl/webui.zip
USER 10010:10010
VOLUME /data
EXPOSE 8080 8081 8082 8090 9100
ENTRYPOINT ["mailctl"]
