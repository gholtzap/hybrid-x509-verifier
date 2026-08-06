# wolfSSL X.509 adapter

This image builds wolfSSL 5.9.2 from its fixed release commit. Mode 1 uses the default
certificate behavior. Mode 2 enables the experimental dual-algorithm certificate behavior. The
adapter source is adapted from the paper's Apache-2.0 verification harness.

wolfSSL 5.9.2 is GPLv3. A distributed adapter image that links this harness to wolfSSL must follow
GPLv3. This repository does not contain a wolfSSL binary.
