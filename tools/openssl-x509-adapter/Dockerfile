FROM gcc:15.2.0-bookworm@sha256:9ca91b05c7b07d2979f16413e8b2cd6ec8a7c80ffca4121ccab0aeba33f90460 AS build

ARG OPENSSL_VERSION=4.0.1
ARG OPENSSL_SHA256=2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09
ADD --checksum=sha256:2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09 \
    https://github.com/openssl/openssl/releases/download/openssl-4.0.1/openssl-4.0.1.tar.gz /tmp/openssl.tar.gz
RUN test "$OPENSSL_SHA256" = "2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09" \
    && mkdir /src \
    && tar -xzf /tmp/openssl.tar.gz -C /src --strip-components=1 \
    && cd /src \
    && ./Configure --prefix=/opt/openssl --openssldir=/opt/openssl/ssl no-shared no-tests no-docs \
    && make -j"$(nproc)" \
    && make install_sw

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
COPY --from=build /opt/openssl /opt/openssl
COPY adapter.sh /adapter.sh
ENV OPENSSL_CONF=/dev/null
ENTRYPOINT ["/adapter.sh"]
