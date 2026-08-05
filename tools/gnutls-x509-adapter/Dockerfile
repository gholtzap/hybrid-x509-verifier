FROM ubuntu:22.04@sha256:3b06811b2afd352be909dd088a004166d665dc76d38b13eada33522a9d915c6f

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       gnutls-bin=3.7.3-4ubuntu1.9 \
       libfaketime=0.9.8-9 \
    && rm -rf /var/lib/apt/lists/*
COPY adapter.sh /adapter.sh
ENTRYPOINT ["/adapter.sh"]
