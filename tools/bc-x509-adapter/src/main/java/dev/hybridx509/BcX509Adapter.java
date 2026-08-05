package dev.hybridx509;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.time.Instant;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.Set;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.DeltaCertificateTool;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPublicKey;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import java.io.StringReader;

public final class BcX509Adapter {
    private static final long MAX_INPUT_BYTES = 16L * 1024L * 1024L;

    public static void main(String[] args) {
        try {
            BouncyCastleProvider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
            if (args.length == 1 && args[0].equals("--version")) {
                System.out.println(provider.getVersionStr());
                return;
            }
            Arguments input = Arguments.parse(args);
            if (input.mode().equals("tls-transcript")) {
                TlsTranscriptProbe.Result probe = TlsTranscriptProbe.run(
                    input.root(), input.intermediate(), input.leaf(), input.key(), input.time());
                String trace = probe.validHandshake()
                    ? "{\"operation\":\"validate-pkix-path\",\"target\":\"leaf\","
                        + "\"algorithm\":null,\"outcome\":\"pass\"},"
                        + "{\"operation\":\"tls-certificate-verify\",\"target\":\"leaf\","
                        + "\"algorithm\":\"" + probe.signature() + "\",\"outcome\":\"pass\"},"
                        + "{\"operation\":\"tls-altered-transcript\",\"target\":\"leaf\","
                        + "\"algorithm\":\"" + probe.signature() + "\",\"outcome\":\""
                        + (probe.alteredTranscriptRejected() ? "reject" : "accept") + "\"},"
                        + "{\"operation\":\"tls-incompatible-signature\",\"target\":\"leaf\","
                        + "\"algorithm\":\"" + probe.signature() + "\",\"outcome\":\""
                        + (probe.incompatibleSignatureRejected() ? "reject" : "accept") + "\"}"
                    : "{\"operation\":\"tls-handshake\",\"target\":\"leaf\","
                        + "\"algorithm\":\"" + probe.signature() + "\",\"outcome\":\"reject\"}";
                System.out.println("{\"verdict\":\"" + (probe.passed() ? "accept" : "reject")
                    + "\",\"valid_handshake\":\"" + (probe.validHandshake() ? "accept" : "reject")
                    + "\",\"altered_transcript_handshake\":\""
                    + (probe.alteredTranscriptRejected() ? "reject" : "accept")
                    + "\",\"incompatible_signature_handshake\":\""
                    + (probe.incompatibleSignatureRejected() ? "reject" : "accept")
                    + "\",\"signature\":\"" + probe.signature() + "\",\"trace\":[" + trace + "]}");
                return;
            }
            if (input.mode().equals("path-builder")) {
                buildPath(input);
                return;
            }
            X509Certificate root = load(input.root());
            X509Certificate intermediate = load(input.intermediate());
            X509Certificate leaf = load(input.leaf());
            if (input.mode().equals("crl-status")) {
                X509CRL crl = loadCrl(input.crl());
                Instant time = Instant.parse(input.time());
                boolean valid = verifyCrlStatus(intermediate, leaf, crl, time);
                result(valid ? "accept" : "reject",
                    valid ? null : "CRL status is not valid and good",
                    "check-crl-status", crl.getSigAlgName());
                return;
            }
            if (input.mode().equals("certificate-signature")) {
                boolean valid;
                try {
                    leaf.verify(intermediate.getPublicKey(), "BC");
                    valid = true;
                } catch (Exception error) {
                    valid = false;
                }
                result(valid ? "accept" : "reject",
                    valid ? null : "certificate signature is invalid",
                    "check-certificate-signature", leaf.getSigAlgName());
                return;
            }
            if (input.mode().equals("alternative-signature")) {
                X509CertificateHolder issuer = new X509CertificateHolder(intermediate.getEncoded());
                Extension extension = issuer.toASN1Structure().getTBSCertificate().getExtensions()
                    .getExtension(Extension.subjectAltPublicKeyInfo);
                if (extension == null) throw new IllegalArgumentException("issuer has no alternative public key");
                SubjectAltPublicKeyInfo value = SubjectAltPublicKeyInfo.getInstance(extension.getParsedValue());
                BCMLDSAPublicKey publicKey = new BCMLDSAPublicKey(
                    SubjectPublicKeyInfo.getInstance(value));
                boolean valid = new X509CertificateHolder(leaf.getEncoded()).isAlternativeSignatureValid(
                    new JcaContentVerifierProviderBuilder().setProvider("BC").build(publicKey));
                result(valid ? "accept" : "reject", valid ? null : "alternative signature is invalid",
                    "check-alternative-signature", "ML-DSA");
                return;
            }
            if (input.mode().equals("delta-signature")) {
                X509CertificateHolder issuer = new X509CertificateHolder(intermediate.getEncoded());
                Extension issuerDeltaExtension = issuer.getExtension(Extension.deltaCertificateDescriptor);
                java.security.PublicKey issuerKey = issuerDeltaExtension == null
                    ? intermediate.getPublicKey()
                    : new JcaX509CertificateConverter().setProvider("BC").getCertificate(
                        DeltaCertificateTool.extractDeltaCertificate(issuer)).getPublicKey();
                X509CertificateHolder delta = DeltaCertificateTool.extractDeltaCertificate(
                    new X509CertificateHolder(leaf.getEncoded()));
                boolean valid = delta.isSignatureValid(
                    new JcaContentVerifierProviderBuilder().setProvider("BC").build(issuerKey));
                result(valid ? "accept" : "reject", valid ? null : "delta certificate signature is invalid",
                    "check-delta-certificate-signature", delta.getSignatureAlgorithm().getAlgorithm().getId());
                return;
            }
            CertPath path = CertificateFactory.getInstance("X.509", "BC")
                .generateCertPath(List.of(leaf, intermediate));
            PKIXParameters parameters = new PKIXParameters(Set.of(new TrustAnchor(root, null)));
            parameters.setDate(java.util.Date.from(Instant.parse(input.time())));
            parameters.setRevocationEnabled(false);

            try {
                CertPathValidator.getInstance("PKIX", "BC").validate(path, parameters);
                result("accept", null, "validate-pkix-path", leaf.getSigAlgName());
            } catch (CertPathValidatorException exception) {
                result(isUnsupported(exception) ? "unsupported" : "reject", exception.toString(),
                    "validate-pkix-path", leaf.getSigAlgName());
            }
        } catch (Exception exception) {
            System.err.println(exception.getClass().getSimpleName() + ": " + exception.getMessage());
            System.exit(2);
        }
    }

    private static void buildPath(Arguments input) throws Exception {
        List<X509Certificate> roots = loadAll(input.root());
        List<X509Certificate> candidates = loadAll(input.intermediate());
        X509Certificate leaf = load(input.leaf());
        Set<TrustAnchor> anchors = new LinkedHashSet<>();
        for (X509Certificate root : roots) anchors.add(new TrustAnchor(root, null));
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(leaf);
        PKIXBuilderParameters parameters = new PKIXBuilderParameters(anchors, selector);
        parameters.setDate(java.util.Date.from(Instant.parse(input.time())));
        parameters.setRevocationEnabled(false);
        List<X509Certificate> store = new ArrayList<>(candidates);
        store.add(leaf);
        parameters.addCertStore(CertStore.getInstance("Collection",
            new CollectionCertStoreParameters(store), "BC"));
        try {
            PKIXCertPathBuilderResult built = (PKIXCertPathBuilderResult)
                CertPathBuilder.getInstance("PKIX", "BC").build(parameters);
            List<X509Certificate> path = new ArrayList<>();
            for (java.security.cert.Certificate certificate : built.getCertPath().getCertificates()) {
                path.add((X509Certificate) certificate);
            }
            path.add(built.getTrustAnchor().getTrustedCert());
            StringBuilder hashes = new StringBuilder();
            StringBuilder trace = new StringBuilder();
            for (int index = 0; index < path.size(); index++) {
                String hash = sha256(path.get(index));
                if (index > 0) hashes.append(',');
                hashes.append('"').append(hash).append('"');
                if (trace.length() > 0) trace.append(',');
                trace.append("{\"operation\":\"select-path-certificate\",\"target\":\"")
                    .append(hash).append("\",\"algorithm\":\"")
                    .append(escape(path.get(index).getSigAlgName()))
                    .append("\",\"outcome\":\"pass\"}");
            }
            System.out.println("{\"verdict\":\"accept\",\"selected_path_sha256\":["
                + hashes + "],\"trace\":[" + trace + "]}");
        } catch (CertPathBuilderException exception) {
            result("reject", exception.toString(), "build-pkix-path", leaf.getSigAlgName());
        }
    }

    private static String sha256(X509Certificate certificate) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
            .digest(certificate.getEncoded()));
    }

    private static List<X509Certificate> loadAll(String name) throws Exception {
        Path path = Path.of(name);
        if (!Files.isRegularFile(path) || Files.size(path) > MAX_INPUT_BYTES) {
            throw new IllegalArgumentException("certificate input is not a regular bounded file: " + name);
        }
        String text = Files.readString(path);
        String begin = "-----BEGIN CERTIFICATE-----";
        String end = "-----END CERTIFICATE-----";
        List<X509Certificate> certificates = new ArrayList<>();
        int cursor = 0;
        while (cursor < text.length()) {
            int beginAt = text.indexOf(begin, cursor);
            if (beginAt < 0) {
                if (!text.substring(cursor).isBlank()) {
                    throw new IllegalArgumentException("certificate bundle has trailing data: " + name);
                }
                break;
            }
            if (!text.substring(cursor, beginAt).isBlank()) {
                throw new IllegalArgumentException("certificate bundle has non-PEM data: " + name);
            }
            int endAt = text.indexOf(end, beginAt + begin.length());
            if (endAt < 0) throw new IllegalArgumentException("certificate PEM is incomplete: " + name);
            String item = text.substring(beginAt, endAt + end.length());
            PemObject object;
            try (PemReader reader = new PemReader(new StringReader(item))) {
                object = reader.readPemObject();
                if (object == null || !object.getType().equals("CERTIFICATE")
                        || reader.readPemObject() != null) {
                    throw new IllegalArgumentException("certificate bundle has an invalid item: " + name);
                }
            }
            certificates.add((X509Certificate) CertificateFactory.getInstance("X.509", "BC")
                .generateCertificate(new ByteArrayInputStream(object.getContent())));
            if (certificates.size() > 64) {
                throw new IllegalArgumentException("certificate bundle exceeds 64 certificates: " + name);
            }
            cursor = endAt + end.length();
        }
        if (certificates.isEmpty()) {
            throw new IllegalArgumentException("certificate bundle is empty: " + name);
        }
        return certificates;
    }

    private static X509Certificate load(String name) throws Exception {
        Path path = Path.of(name);
        if (!Files.isRegularFile(path) || Files.size(path) > MAX_INPUT_BYTES) {
            throw new IllegalArgumentException("certificate input is not a regular bounded file: " + name);
        }
        String text = Files.readString(path);
        String begin = "-----BEGIN CERTIFICATE-----";
        String end = "-----END CERTIFICATE-----";
        int beginAt = text.indexOf(begin);
        int endAt = text.indexOf(end);
        if (beginAt < 0 || endAt < beginAt || !text.substring(0, beginAt).isBlank()
                || !text.substring(endAt + end.length()).isBlank()
                || text.indexOf(begin, beginAt + begin.length()) >= 0) {
            throw new IllegalArgumentException("input is not one certificate PEM: " + name);
        }
        PemObject object;
        try (PemReader reader = new PemReader(new StringReader(text))) {
            object = reader.readPemObject();
            if (object == null || !object.getType().equals("CERTIFICATE") || reader.readPemObject() != null) {
                throw new IllegalArgumentException("input is not one certificate PEM: " + name);
            }
        }
        return (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
            .generateCertificate(new ByteArrayInputStream(object.getContent()));
    }

    private static X509CRL loadCrl(String name) throws Exception {
        Path path = Path.of(name);
        if (!Files.isRegularFile(path) || Files.size(path) > MAX_INPUT_BYTES) {
            throw new IllegalArgumentException("CRL input is not a regular bounded file: " + name);
        }
        PemObject object;
        try (PemReader reader = new PemReader(new StringReader(Files.readString(path)))) {
            object = reader.readPemObject();
            if (object == null || !object.getType().equals("X509 CRL")
                    || reader.readPemObject() != null) {
                throw new IllegalArgumentException("input is not one X509 CRL PEM: " + name);
            }
        }
        return (X509CRL) CertificateFactory.getInstance("X.509", "BC")
            .generateCRL(new ByteArrayInputStream(object.getContent()));
    }

    private static boolean verifyCrlStatus(X509Certificate issuer, X509Certificate target,
            X509CRL crl, Instant validationTime) {
        try {
            target.verify(issuer.getPublicKey(), "BC");
            crl.verify(issuer.getPublicKey(), "BC");
            boolean[] keyUsage = issuer.getKeyUsage();
            X509CRLEntry entry = crl.getRevokedCertificate(target.getSerialNumber());
            java.util.Date time = java.util.Date.from(validationTime);
            return target.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
                && crl.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
                && (keyUsage == null || keyUsage.length > 6 && keyUsage[6])
                && !time.before(crl.getThisUpdate())
                && crl.getNextUpdate() != null && !time.after(crl.getNextUpdate())
                && (entry == null || entry.getRevocationDate().after(time));
        } catch (Exception error) {
            return false;
        }
    }

    private static boolean isUnsupported(Throwable error) {
        for (Throwable item = error; item != null; item = item.getCause()) {
            String text = (item.getClass().getName() + " " + item.getMessage()).toLowerCase();
            if (text.contains("nosuchalgorithm") || text.contains("unsupported") || text.contains("unknown algorithm")) {
                return true;
            }
        }
        return false;
    }

    private static void result(String verdict, String error, String operation, String algorithm) {
        System.out.println("{\"verdict\":\"" + verdict + "\",\"error\":"
            + (error == null ? "null" : "\"" + escape(error) + "\"")
            + ",\"trace\":[{\"operation\":\"" + operation + "\",\"target\":\"leaf\","
            + "\"algorithm\":\"" + escape(algorithm) + "\",\"outcome\":\"" + verdict + "\"}]}");
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\r", "\\r");
    }

    private record Arguments(String root, String intermediate, String leaf, String time, String mode,
            String key, String crl) {
        static Arguments parse(String[] args) {
            String root = null, intermediate = null, leaf = null, time = null, key = null,
                crl = null, mode = "path";
            for (int index = 0; index < args.length; index += 2) {
                if (index + 1 >= args.length) throw new IllegalArgumentException("option value is missing");
                switch (args[index]) {
                    case "--root" -> root = args[index + 1];
                    case "--intermediate" -> intermediate = args[index + 1];
                    case "--leaf" -> leaf = args[index + 1];
                    case "--time" -> time = args[index + 1];
                    case "--mode" -> mode = args[index + 1];
                    case "--key" -> key = args[index + 1];
                    case "--crl" -> crl = args[index + 1];
                    default -> throw new IllegalArgumentException("unknown option: " + args[index]);
                }
            }
            if (root == null || intermediate == null || leaf == null || time == null) {
                throw new IllegalArgumentException("root, intermediate, leaf, and time are required");
            }
            if (!mode.equals("path") && !mode.equals("path-builder") && !mode.equals("alternative-signature")
                    && !mode.equals("tls-transcript") && !mode.equals("delta-signature")
                    && !mode.equals("certificate-signature") && !mode.equals("crl-status")) {
                throw new IllegalArgumentException(
                    "mode must be path, path-builder, alternative-signature, delta-signature, certificate-signature, crl-status, or tls-transcript");
            }
            if (mode.equals("tls-transcript") && key == null) {
                throw new IllegalArgumentException("key is required for tls-transcript mode");
            }
            if (mode.equals("crl-status") && crl == null) {
                throw new IllegalArgumentException("crl is required for crl-status mode");
            }
            return new Arguments(root, intermediate, leaf, time, mode, key, crl);
        }
    }
}
