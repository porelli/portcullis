FROM golang:1.27-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY web/ ./web/
RUN CGO_ENABLED=0 go build -trimpath -o /enroll .

FROM alpine:3.24
RUN apk add --no-cache ca-certificates
COPY --from=builder /enroll /usr/local/bin/enroll
EXPOSE 8443
ENTRYPOINT ["enroll"]
