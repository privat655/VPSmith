FROM golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS build

ARG VERSION
ARG REVISION
ARG SOURCE_DATE_EPOCH

WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY build/cmd ./build/cmd
COPY embedded ./embedded

RUN test -n "$VERSION" \
    && test -n "$REVISION" \
    && test -n "$SOURCE_DATE_EPOCH" \
    && go run ./build/cmd/embedded-manifest -root embedded -manifest embedded/manifest.json -check \
    && CGO_ENABLED=0 GOOS=linux go build \
       -trimpath \
       -buildvcs=false \
       -ldflags "-s -w -X main.version=${VERSION} -X main.revision=${REVISION} -X main.sourceDateEpoch=${SOURCE_DATE_EPOCH}" \
       -o /out/vpsmith-studio \
       ./cmd/vpsmith-studio

# Resolve the exact Git and OpenSSH client runtime payloads from the pinned
# Debian snapshot, but do not install them into the final image. Package
# maintainer scripts create logs/caches with per-build state. Extracting the
# immutable .deb payloads preserves reproducible final images while providing
# the real Git and OpenSSH implementations behind VPSmith's narrow adapters.
FROM debian:bookworm-20260713-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS client-runtime

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

RUN printf '%s\n' \
      'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260713T000000Z bookworm main' \
      > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/* \
    && apt-get update \
    && apt-get install -y --download-only --no-install-recommends \
       git=1:2.39.5-0+deb12u3 \
       openssh-client \
    && mkdir -p /client-root \
    && for package in /var/cache/apt/archives/*.deb; do dpkg-deb -x "$package" /client-root; done \
    && if [ -d /client-root/lib ]; then mkdir -p /client-root/usr/lib; cp -a /client-root/lib/. /client-root/usr/lib/; rm -rf /client-root/lib; fi \
    && test -x /client-root/usr/bin/git \
    && test -x /client-root/usr/bin/ssh \
    && test -x /client-root/usr/bin/ssh-keyscan

FROM debian:bookworm-20260713-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

ARG VERSION
ARG REVISION

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=client-runtime /client-root/usr/ /usr/

RUN mkdir -p \
      /var/lib/vpsmith/state \
      /var/lib/vpsmith/sources \
      /var/lib/vpsmith/backups \
      /usr/share/vpsmith/embedded \
      /usr/local/libexec \
    && chown -R 10001:10001 /var/lib/vpsmith

COPY --from=build --chown=10001:10001 /out/vpsmith-studio /usr/local/bin/vpsmith-studio
COPY --chown=0:0 embedded/ /usr/share/vpsmith/embedded/
COPY --chmod=0555 --chown=0:0 build/vpsmith-git-askpass.sh /usr/local/libexec/vpsmith-git-askpass

RUN git --version | grep -F 'git version 2.39.5' \
    && ssh -V 2>&1 | grep -F 'OpenSSH_' \
    && test -x /usr/bin/ssh-keyscan \
    && /usr/local/bin/vpsmith-studio version >/dev/null

LABEL org.opencontainers.image.title="VPSmith Platform" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"

USER 10001:10001

VOLUME ["/var/lib/vpsmith/state", "/var/lib/vpsmith/sources", "/var/lib/vpsmith/backups"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=2s --retries=3 \
  CMD ["/usr/local/bin/vpsmith-studio", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/vpsmith-studio"]
CMD ["serve"]
