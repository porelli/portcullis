# golang:1.27.3-alpine3.24
FROM docker.io/library/golang:1.27.3-alpine3.24@sha256:fa4881266890ef051f0ce63afdfaccb69bbe8186084387f4fafd60d7ecbabc71 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /wg .

# alpine:3.24.3
FROM docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
# /data (wg_data): status.json, 0640; its group 10001 (the Hub's) comes
# from the setgid directory (2750; stack_prepare's volume_own makes the
# volume 10006:10001 2750): wg is in no other group.
RUN addgroup -S -g 10006 wg \
 && adduser -S -D -H -u 10006 -G wg wg \
 && mkdir -p /data && chown 10006:10001 /data && chmod 2750 /data
COPY --from=builder /wg /wg
# Userspace WireGuard (wireguard-go + gVisor netstack): no capability, no
# /dev/net/tun, an ordinary UDP socket. Reads /vpn-doc/vpn.json
# (the vpn_doc volume, read-only) and /run/portcullis/wg/people.key, writes
# only /data. No engine access (contract §16).
USER 10006:10006
VOLUME /data
ENTRYPOINT ["/wg"]
CMD ["run"]
