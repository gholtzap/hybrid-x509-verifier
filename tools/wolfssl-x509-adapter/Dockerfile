FROM ubuntu:22.04@sha256:3b06811b2afd352be909dd088a004166d665dc76d38b13eada33522a9d915c6f AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates cmake git \
    && rm -rf /var/lib/apt/lists/*
ARG WOLFSSL_COMMIT=ac01707f552c611fbd135cc723b2682b3e7f80f2
RUN git clone --filter=blob:none https://github.com/wolfSSL/wolfssl.git /src/wolfssl \
    && git -C /src/wolfssl checkout --detach "$WOLFSSL_COMMIT" \
    && test "$(git -C /src/wolfssl rev-parse HEAD)" = "$WOLFSSL_COMMIT"
COPY wolfssl_verify.c /src/wolfssl_verify.c
RUN for mode in mode1 mode2; do \
      flags=""; \
      if [ "$mode" = mode2 ]; then flags="-DWOLFSSL_DUAL_ALG_CERTS -DWOLFSSL_EXPERIMENTAL_SETTINGS"; fi; \
      cmake -S /src/wolfssl -B "/src/build-$mode" \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="/opt/wolfssl-$mode" \
        -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_C_FLAGS="$flags" \
        -DWOLFSSL_MLDSA=yes -DWOLFSSL_CERTEXT=yes -DWOLFSSL_OPENSSLALL=yes \
        -DWOLFSSL_EXPERIMENTAL=yes -DWOLFSSL_KEYGEN=yes -DWOLFSSL_CERTGEN=yes \
        -DWOLFSSL_EXAMPLES=no -DWOLFSSL_CRYPT_TESTS=no \
      && cmake --build "/src/build-$mode" --parallel "$(nproc)" \
      && cmake --install "/src/build-$mode" \
      && mkdir -p "/opt/wolfssl-$mode/bin" \
      && cc $flags /src/wolfssl_verify.c -I"/opt/wolfssl-$mode/include" \
        -L"/opt/wolfssl-$mode/lib" -Wl,-rpath,"/opt/wolfssl-$mode/lib" -lwolfssl \
        -o "/opt/wolfssl-$mode/bin/wolfssl_verify"; \
    done

FROM ubuntu:22.04@sha256:3b06811b2afd352be909dd088a004166d665dc76d38b13eada33522a9d915c6f
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends libfaketime=0.9.8-9 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/wolfssl-mode1 /opt/wolfssl-mode1
COPY --from=build /opt/wolfssl-mode2 /opt/wolfssl-mode2
COPY adapter.sh /adapter.sh
ENTRYPOINT ["/adapter.sh"]
