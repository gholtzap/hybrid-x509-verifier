#!/usr/bin/env python3

import argparse
import datetime
import json
import sys

from cryptography import __version__, x509
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError


def load(path: str) -> x509.Certificate:
    with open(path, "rb") as source:
        data = source.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024:
        raise ValueError(f"certificate input exceeds size limit: {path}")
    return x509.load_pem_x509_certificate(data)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--root")
    parser.add_argument("--intermediate")
    parser.add_argument("--leaf")
    parser.add_argument("--dns")
    parser.add_argument("--time")
    parser.add_argument("--hybrid-extension-oid")
    args = parser.parse_args()

    if args.version:
        print(__version__)
        return
    if not all((args.root, args.intermediate, args.leaf, args.dns, args.time)):
        parser.error("root, intermediate, leaf, dns, and time are required")

    root = load(args.root)
    intermediate = load(args.intermediate)
    leaf = load(args.leaf)
    validation_time = datetime.datetime.fromisoformat(
        args.time.replace("Z", "+00:00")
    )
    extension_present = False
    extension_recognized = None
    if args.hybrid_extension_oid:
        oid = x509.ObjectIdentifier(args.hybrid_extension_oid)
        try:
            extension = leaf.extensions.get_extension_for_oid(oid)
            extension_present = True
            extension_recognized = not isinstance(
                extension.value, x509.UnrecognizedExtension
            )
        except x509.ExtensionNotFound:
            pass

    verifier = (
        PolicyBuilder()
        .store(Store([root]))
        .time(validation_time)
        .build_server_verifier(x509.DNSName(args.dns))
    )
    verdict = "accept"
    error = None
    try:
        verifier.verify(leaf, [intermediate])
    except VerificationError as exception:
        error = str(exception)
        verdict = (
            "unsupported"
            if "unsupported" in error.lower() or "forbidden public key" in error.lower()
            else "reject"
        )
    extensions = [
        {"oid": extension.oid.dotted_string, "critical": extension.critical}
        for extension in leaf.extensions
    ]
    print(
        json.dumps(
            {
                "verdict": verdict,
                "error": error,
                "hybrid_extension_present": extension_present,
                "hybrid_extension_recognized": extension_recognized,
                "trace": [
                    {
                        "operation": "verify-server-certificate-path",
                        "target": "leaf",
                        "algorithm": leaf.signature_algorithm_oid.dotted_string,
                        "outcome": verdict,
                    }
                ],
                "extensions": extensions,
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exception:
        print(f"{type(exception).__name__}: {exception}", file=sys.stderr)
        raise SystemExit(2)
