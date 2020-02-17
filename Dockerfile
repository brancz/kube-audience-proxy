FROM golang:1.13-alpine AS build
RUN apk add --update make
WORKDIR /go/src/github.com/brancz/kube-audience-proxy
COPY . .
RUN make build && cp /go/src/github.com/brancz/kube-audience-proxy/_output/linux/$(go env GOARCH)/kube-audience-proxy /go/src/github.com/brancz/kube-audience-proxy/_output/linux/kube-audience-proxy

FROM alpine:3.10
RUN apk add -U --no-cache ca-certificates && rm -rf /var/cache/apk/*
COPY --from=build /go/src/github.com/brancz/kube-audience-proxy/_output/linux/kube-audience-proxy .
ENTRYPOINT ["./kube-audience-proxy"]
EXPOSE 8080
