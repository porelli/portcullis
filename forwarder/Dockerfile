# golang:1.27.3-alpine3.24
FROM docker.io/library/golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /forwarder .

# alpine:3.24.3
FROM docker.io/library/alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
COPY --from=builder /forwarder /forwarder
# Runs in a VPN client's network namespace (network_mode: service:<gateway>)
# and forwards :443 to PORTCULLIS_VPN_EDGE with a PROXY v2 header (contract
# §16). nobody; binding :443 needs net.ipv4.ip_unprivileged_port_start = 0
# (Docker's default in a container netns) or cap_add NET_BIND_SERVICE
# (templates add it for rootless Podman).
USER 65534:65534
ENTRYPOINT ["/forwarder"]
