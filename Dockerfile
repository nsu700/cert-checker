FROM golang:1.18
WORKDIR /usr/src/cert-checker
COPY go.sum main.go go.mod .
RUN go mod tidy &&  GOOS=linux go build -v -o /cert-checker /usr/src/cert-checker

FROM debian
WORKDIR /usr/local/bin/
COPY --from=0 /cert-checker .
ENTRYPOINT /usr/local/bin/cert-checker
