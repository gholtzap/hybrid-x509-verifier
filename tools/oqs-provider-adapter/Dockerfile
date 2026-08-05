FROM ubuntu:22.04@sha256:3b06811b2afd352be909dd088a004166d665dc76d38b13eada33522a9d915c6f AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates cmake git ninja-build pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG OPENSSL_COMMIT=8cf17aaeb4599f8af87fefd810b5b5fee90fe69e
ARG LIBOQS_COMMIT=97f6b86b1b6d109cfd43cf276ae39c2e776aed80
ARG OQSPROVIDER_COMMIT=a635e341d6a4624d9bba36d158804762f316fe5e
ENV PREFIX=/opt/oqs-openssl

RUN git clone --filter=blob:none https://github.com/openssl/openssl.git /src/openssl \
    && git -C /src/openssl checkout --detach "$OPENSSL_COMMIT" \
    && test "$(git -C /src/openssl rev-parse HEAD)" = "$OPENSSL_COMMIT" \
    && cd /src/openssl \
    && ./Configure --prefix="$PREFIX" --openssldir="$PREFIX/ssl" --libdir=lib shared no-docs no-tests \
    && make -j"$(nproc)" \
    && make install_sw

RUN git clone --filter=blob:none https://github.com/open-quantum-safe/liboqs.git /src/liboqs \
    && git -C /src/liboqs checkout --detach "$LIBOQS_COMMIT" \
    && test "$(git -C /src/liboqs rev-parse HEAD)" = "$LIBOQS_COMMIT" \
    && cmake -S /src/liboqs -B /src/liboqs/build -GNinja \
       -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" -DOQS_DIST_BUILD=ON \
       -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=ON \
    && cmake --build /src/liboqs/build \
    && cmake --install /src/liboqs/build

RUN git clone --filter=blob:none https://github.com/open-quantum-safe/oqs-provider.git /src/oqs-provider \
    && git -C /src/oqs-provider checkout --detach "$OQSPROVIDER_COMMIT" \
    && test "$(git -C /src/oqs-provider rev-parse HEAD)" = "$OQSPROVIDER_COMMIT" \
    && cmake -S /src/oqs-provider -B /src/oqs-provider/build -GNinja \
       -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
       -DOPENSSL_ROOT_DIR="$PREFIX" -Dliboqs_DIR="$PREFIX/lib/cmake/liboqs" \
       -DBUILD_TESTING=OFF \
    && cmake --build /src/oqs-provider/build \
    && cmake --install /src/oqs-provider/build

FROM ubuntu:22.04@sha256:3b06811b2afd352be909dd088a004166d665dc76d38b13eada33522a9d915c6f
COPY --from=build /opt/oqs-openssl /opt/oqs-openssl
COPY adapter.sh /adapter.sh
ENV LD_LIBRARY_PATH=/opt/oqs-openssl/lib
ENV OPENSSL_MODULES=/opt/oqs-openssl/lib/ossl-modules
ENTRYPOINT ["/adapter.sh"]
