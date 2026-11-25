# syntax=docker/dockerfile:1
# An app on the Z-Dash server as an image: a static binary on Alpine, with a
# pinned and checksummed cloudflared, as a user without rights.
#
# Copy it to the root of the app's repository and replace APP (the binary
# and the command's folder under cmd/) and APP_ (the environment prefix,
# the app's name in capitals). Data lives in the volume /data.

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/APP ./cmd/APP

# The server downloads cloudflared itself when it is missing; in an image it
# is part of the image instead, pinned with its checksum (the release page of
# cloudflare/cloudflared lists both).
FROM alpine:3.22 AS cloudflared
ARG CLOUDFLARED_VERSION=2026.10.7
ARG CLOUDFLARED_SHA256=1f99fb518b83dec2ba8d870a7cc991d82a77e6196295a3d2754ba17ab9f91872
ADD https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-linux-amd64 /cloudflared
RUN echo "${CLOUDFLARED_SHA256}  /cloudflared" | sha256sum -c - && chmod 0755 /cloudflared

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 10001 app && mkdir /data && chown app /data
COPY --from=cloudflared /cloudflared /usr/local/bin/cloudflared
COPY --from=build /out/APP /usr/local/bin/APP
USER app
# The tunnel's listener on loopback: a Unix socket in a volume works as well,
# but a loopback port survives any volume driver.
ENV APP_DATA=/data APP_TUNNEL_LISTEN=127.0.0.1:8081
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["APP"]
