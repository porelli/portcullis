# nodeadm (contract §20.1, §20.2). The nodeagent binaries it serves on
# /node/nodeagent-<arch> come from the named build context `nodeagent`:
# the Hub's portcullis-nodeagent image (its files /nodeagent-linux-amd64 and
# /nodeagent-linux-arm64), pinned by digest once the Hub publishes it (plan
# Task 36, ruling P20); before that CI passes a directory built from the
# sibling Hub checkout (`--build-context nodeagent=<dir>`).
# golang:1.27.3-alpine3.24
FROM docker.io/library/golang:1.27.3-alpine3.24@sha256:fa4881266890ef051f0ce63afdfaccb69bbe8186084387f4fafd60d7ecbabc71 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go join.sh ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /nodeadm .

# alpine:3.24.3
FROM docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk add --no-cache ca-certificates \
 && addgroup -S -g 10010 nodeadm \
 && adduser -S -D -H -u 10010 -G nodeadm nodeadm \
 && install -d -m 0755 /usr/local/lib/portcullis
COPY --from=builder /nodeadm /usr/local/bin/nodeadm
COPY --from=nodeagent --chmod=0444 /nodeagent-linux-amd64 /usr/local/lib/portcullis/nodeagent-amd64
COPY --from=nodeagent --chmod=0444 /nodeagent-linux-arm64 /usr/local/lib/portcullis/nodeagent-arm64
# Non-root (the chart's init container alone runs as root, to copy the
# server's etcd client key). Reads the enroll bearer and the etcd copies
# (group 10010), writes nothing on disk: its state is the Secret
# nodeadm-state, its own key stays in memory.
USER 10010:10010
EXPOSE 8080 8443 9105
ENTRYPOINT ["nodeadm"]
CMD ["serve"]
