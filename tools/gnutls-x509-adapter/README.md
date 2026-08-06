# GnuTLS X.509 adapter

This adapter runs the paper's GnuTLS 3.7.3 package. It uses libfaketime to apply the supplied
validation time without privileged clock changes. The container has a read-only root file system,
no network access, and a size-limited temporary file system at run time.

The same build command creates a current GnuTLS 3.8.13 image from the signed official source
archive. It uses digest-pinned base images and a dated Debian package snapshot.
