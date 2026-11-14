# golang:1.27.3-alpine3.24
FROM docker.io/library/golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY web/ ./web/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /enroll .

# alpine:3.24.3
FROM docker.io/library/alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
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
