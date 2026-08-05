FROM python:3.14.1-slim-bookworm@sha256:5d17fc066275d26bb2ffe05bc89367dc665310200b5f4cfa8b294e97dc679bff

ARG CRYPTOGRAPHY_VERSION
COPY tools/pyca-x509-adapter/requirements-*.txt /
RUN pip install --no-cache-dir --require-hashes -r "/requirements-${CRYPTOGRAPHY_VERSION}.txt"
COPY tools/pyca-x509-adapter.py /adapter.py
ENTRYPOINT ["python", "/adapter.py"]
