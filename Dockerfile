# CertWatch — minimal production image.
# Build:  docker build -t certwatch .
# Run:    docker run -d -p 127.0.0.1:8422:8422 -v certwatch-data:/data certwatch

FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO is required by the mattn/go-sqlite3 driver used in this build.
# (Release note: swapping the driver import to modernc.org/sqlite allows
#  CGO_ENABLED=0 and a fully static binary; see RELEASE.md.)
ARG ISSUER_PUBKEY=""
RUN CGO_ENABLED=1 go build -trimpath \
    -ldflags "-s -w -X main.issuerPublicKeyB64=${ISSUER_PUBKEY}" \
    -o /out/certwatch ./cmd/certwatch

FROM debian:bookworm-slim
RUN useradd -r -u 10001 certwatch \
 && apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/certwatch /usr/local/bin/certwatch
USER certwatch
VOLUME /data
EXPOSE 8422
ENTRYPOINT ["certwatch", "-listen", "0.0.0.0:8422", "-db", "/data/certwatch.db", "-license", "/data/license.key"]
