# golang:1.27.3-alpine3.24
FROM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY web/ ./web/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /enroll .

# alpine:3.24.3
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk add --no-cache ca-certificates \
 && addgroup -S -g 10002 enroll \
 && adduser -S -D -H -u 10002 -G enroll enroll
COPY --from=builder /enroll /usr/local/bin/enroll
# Non-root. Reads only /run/secrets/portcullis-enroll/{role-id,secret-id},
# which ./portcullis vault init makes group 10002, mode 0640 (dir 0750).
USER 10002:10002
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD wget -q -O /dev/null http://127.0.0.1:8443/healthz || exit 1
ENTRYPOINT ["enroll"]
