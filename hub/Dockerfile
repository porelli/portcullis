FROM golang:1.22-alpine AS build
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod ./
RUN go mod tidy && go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /hub .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates git curl docker-cli docker-cli-compose
COPY --from=build /hub /usr/local/bin/hub
ENTRYPOINT ["hub"]
