# syntax=docker/dockerfile:1.4
FROM golang:1.19-alpine as build

WORKDIR /workspace

COPY . .

RUN go build -o /build/jwt-inspector

FROM alpine:latest

COPY --from=build /build/jwt-inspector /build/jwt-inspector

CMD ["/build/jwt-inspector"]
