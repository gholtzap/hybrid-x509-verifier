# oqs-provider adapter

This image builds OpenSSL 3.5.7, liboqs 0.15.0, and oqs-provider 0.11.0 from fixed commits.
The provider version is both the paper version and the current release on 2026-08-05. The image
loads the default and OQS providers for each certificate-path check.

The base image uses a fixed digest. The build package repository is not yet fixed to a dated
snapshot, so the source graph is fixed but the complete image is not yet bit reproducible.
