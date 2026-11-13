# golang:1.27.3-alpine3.24
FROM docker.io/library/golang:1.27.3-alpine3.24@sha256:fa4881266890ef051f0ce63afdfaccb69bbe8186084387f4fafd60d7ecbabc71 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /forwarder .

# alpine:3.24.3
FROM docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
COPY --from=builder /forwarder /forwarder
# Runs in a VPN client's network namespace (network_mode: service:<gateway>)
# and forwards :443 to PORTCULLIS_VPN_EDGE with a PROXY v2 header (contract
# §16). nobody; binding :443 needs net.ipv4.ip_unprivileged_port_start = 0
# (Docker's default in a container netns) or cap_add NET_BIND_SERVICE
# (templates add it for rootless Podman).
USER 65534:65534
ENTRYPOINT ["/forwarder"]
