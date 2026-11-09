# syntax=docker/dockerfile:1
# dynv6 管家 Docker 镜像：监听 0.0.0.0:8092，数据统一放在 /data
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY src/go.mod src/go.sum ./
RUN go mod download
COPY src/ ./
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X main.Version=${VERSION}" \
    -o /out/dynv6 .

FROM alpine:3.20
# 运行层只需 CA 证书与时区数据，程序本身为静态二进制
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/dynv6 /usr/local/bin/dynv6

ENV DYNV6_DOCKER=1 \
    DYNV6_DATA_DIR=/data \
    TZ=Asia/Shanghai

WORKDIR /data
VOLUME ["/data"]
EXPOSE 8092

ENTRYPOINT ["/usr/local/bin/dynv6"]
