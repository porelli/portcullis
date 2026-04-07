FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY *.go ./
COPY web/ ./web/
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 go build -o /enroll .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /enroll /usr/local/bin/enroll
EXPOSE 8443
ENTRYPOINT ["enroll"]
