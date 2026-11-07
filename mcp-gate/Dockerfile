# golang:1.27.3-alpine3.24
FROM golang:1.27.3-alpine3.24@sha256:fa4881266890ef051f0ce63afdfaccb69bbe8186084387f4fafd60d7ecbabc71 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mcp-gate .

# alpine:3.24.3
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
# /data (mcp_gate_data): the access log, 0750 with group 10001 so the Hub
# reads it through its read-only mount (contract §15.8); the gate re-asserts
# the mode and group at every start and refuses to start if it can't.
RUN apk add --no-cache ca-certificates \
 && addgroup -S -g 10005 mcp-gate \
 && adduser -S -D -H -u 10005 -G mcp-gate mcp-gate \
 && mkdir -p /data && chown 10005:10001 /data && chmod 0750 /data
COPY --from=builder /mcp-gate /usr/local/bin/mcp-gate
# Non-root. Reads /hub-data (hub_data, read-only: mcp-gate.json,
# mcp-credentials.json, user-attributes.json), /run/portcullis/mcp-gate/
# {age.key (group 10005), hub-secret (group 10001: compose adds that group)}
# and writes only /data. No Docker access, no LLDAP / Keycloak admin
# credentials (contract §15).
USER 10005:10005
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["mcp-gate", "healthcheck"]
ENTRYPOINT ["mcp-gate"]
