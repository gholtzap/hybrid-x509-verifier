package dev.hybridx509;

import java.io.FilterOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateEntry;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

final class TlsTranscriptProbe {
    private static final long MAX_INPUT_BYTES = 16L * 1024L * 1024L;

    record Result(boolean validHandshake, boolean alteredTranscriptRejected,
            boolean incompatibleSignatureRejected, String signature) {
        boolean passed() {
            return validHandshake && alteredTranscriptRejected && incompatibleSignatureRejected;
        }
    }

    static Result run(String rootFile, String intermediateFile, String leafFile, String keyFile,
            String validationTime) throws Exception {
        byte[] root = readPem(rootFile, "CERTIFICATE");
        byte[] intermediate = readPem(intermediateFile, "CERTIFICATE");
        byte[] leaf = readPem(leafFile, "CERTIFICATE");
        KeyMaterial key = readPrivateKey(keyFile);
        Instant time = Instant.parse(validationTime);
        boolean valid = handshake(root, leaf, intermediate, key, time, false, null);
        boolean alteredRejected = !handshake(root, leaf, intermediate, key, time, true, null);
        SignatureAndHashAlgorithm incompatible = key.name().startsWith("rsa_")
            ? SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa)
            : SignatureAndHashAlgorithm.rsa_pss_rsae_sha256;
        boolean incompatibleRejected = !handshake(
            root, leaf, intermediate, key, time, false, incompatible);
        return new Result(valid, alteredRejected, incompatibleRejected, key.name());
    }

    private static boolean handshake(byte[] root, byte[] leaf, byte[] intermediate,
            KeyMaterial key, Instant validationTime, boolean alterTranscript,
            SignatureAndHashAlgorithm supportedSignature) throws Exception {
        PipedInputStream clientRead = new PipedInputStream(64 * 1024);
        PipedInputStream serverRead = new PipedInputStream(64 * 1024);
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);
        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);
        AtomicReference<Throwable> serverError = new AtomicReference<>();
        Thread serverThread = new Thread(() -> {
            try {
                serverProtocol.accept(new Server(leaf, intermediate, key, alterTranscript));
            } catch (Throwable error) {
                serverError.set(error);
            }
        }, "tls-transcript-probe-server");
        serverThread.start();

        boolean clientComplete;
        try {
            clientProtocol.connect(new Client(
                root, intermediate, leaf, validationTime, supportedSignature));
            clientComplete = true;
        } catch (IOException expected) {
            clientComplete = false;
        } finally {
            try {
                clientProtocol.close();
            } catch (IOException ignored) {
            }
        }
        serverThread.join(5_000);
        if (serverThread.isAlive()) {
            serverProtocol.close();
            serverThread.join(1_000);
            throw new IOException("TLS transcript probe did not stop");
        }
        return clientComplete && serverError.get() == null;
    }

    private static JcaTlsCrypto crypto() {
        return new JcaTlsCryptoProvider().setProvider("BC").create(new SecureRandom());
    }

    private static final class Server extends DefaultTlsServer {
        private final byte[] leaf;
        private final byte[] intermediate;
        private final KeyMaterial key;
        private final boolean alterTranscript;

        Server(byte[] leaf, byte[] intermediate, KeyMaterial key, boolean alterTranscript) {
            super(crypto());
            this.leaf = leaf;
            this.intermediate = intermediate;
            this.key = key;
            this.alterTranscript = alterTranscript;
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() {
            return ProtocolVersion.TLSv13.only();
        }

        @Override
        public TlsCredentials getCredentials() throws IOException {
            JcaTlsCrypto crypto = (JcaTlsCrypto) getCrypto();
            CertificateEntry[] entries = new CertificateEntry[] {
                new CertificateEntry(crypto.createCertificate(leaf), null),
                new CertificateEntry(crypto.createCertificate(intermediate), null)
            };
            Certificate chain = new Certificate(TlsUtils.EMPTY_BYTES, entries);
            TlsCredentialedSigner signer = new JcaDefaultTlsCredentialedSigner(
                new TlsCryptoParameters(context), crypto, key.key(), chain, key.algorithm());
            return alterTranscript ? new AlteredTranscriptSigner(signer) : signer;
        }
    }

    private static final class Client extends DefaultTlsClient {
        private final byte[] root;
        private final byte[] intermediate;
        private final byte[] expectedLeaf;
        private final Instant validationTime;
        private final SignatureAndHashAlgorithm supportedSignature;

        Client(byte[] root, byte[] intermediate, byte[] expectedLeaf, Instant validationTime,
                SignatureAndHashAlgorithm supportedSignature) {
            super(crypto());
            this.root = root;
            this.intermediate = intermediate;
            this.expectedLeaf = expectedLeaf;
            this.validationTime = validationTime;
            this.supportedSignature = supportedSignature;
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() {
            return ProtocolVersion.TLSv13.only();
        }

        @Override
        @SuppressWarnings("rawtypes")
        protected Vector getSupportedSignatureAlgorithms() {
            return supportedSignature == null
                ? super.getSupportedSignatureAlgorithms()
                : TlsUtils.vectorOfOne(supportedSignature);
        }

        @Override
        public TlsAuthentication getAuthentication() {
            return new TlsAuthentication() {
                @Override
                public void notifyServerCertificate(TlsServerCertificate serverCertificate)
                        throws IOException {
                    TlsCertificate[] chain = serverCertificate.getCertificate().getCertificateList();
                    if (chain.length != 2 || !Arrays.equals(expectedLeaf, chain[0].getEncoded())
                            || !Arrays.equals(intermediate, chain[1].getEncoded())) {
                        throw new IOException("the server selected an unexpected certificate");
                    }
                    try {
                        X509Certificate rootCertificate = certificate(root);
                        X509Certificate intermediateCertificate = certificate(intermediate);
                        X509Certificate leafCertificate = certificate(expectedLeaf);
                        CertPath path = CertificateFactory.getInstance("X.509", "BC")
                            .generateCertPath(List.of(leafCertificate, intermediateCertificate));
                        PKIXParameters parameters = new PKIXParameters(
                            Set.of(new TrustAnchor(rootCertificate, null)));
                        parameters.setDate(java.util.Date.from(validationTime));
                        parameters.setRevocationEnabled(false);
                        CertPathValidator.getInstance("PKIX", "BC").validate(path, parameters);
                    } catch (Exception error) {
                        throw new IOException("the server certificate path is invalid", error);
                    }
                }

                @Override
                public TlsCredentials getClientCredentials(CertificateRequest request) {
                    return null;
                }
            };
        }
    }

    private static final class AlteredTranscriptSigner implements TlsCredentialedSigner {
        private final TlsCredentialedSigner delegate;

        AlteredTranscriptSigner(TlsCredentialedSigner delegate) {
            this.delegate = delegate;
        }

        @Override
        public Certificate getCertificate() {
            return delegate.getCertificate();
        }

        @Override
        public byte[] generateRawSignature(byte[] hash) throws IOException {
            byte[] altered = hash.clone();
            altered[0] ^= 1;
            return delegate.generateRawSignature(altered);
        }

        @Override
        public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm() {
            return delegate.getSignatureAndHashAlgorithm();
        }

        @Override
        public TlsStreamSigner getStreamSigner() throws IOException {
            TlsStreamSigner signer = delegate.getStreamSigner();
            return new TlsStreamSigner() {
                private boolean altered;
                private final OutputStream output = new FilterOutputStream(signer.getOutputStream()) {
                    @Override
                    public void write(int value) throws IOException {
                        super.write(alter(value));
                    }

                    @Override
                    public void write(byte[] bytes, int offset, int length) throws IOException {
                        if (length > 0 && !altered) {
                            byte[] copy = Arrays.copyOfRange(bytes, offset, offset + length);
                            copy[0] ^= 1;
                            altered = true;
                            out.write(copy);
                        } else {
                            out.write(bytes, offset, length);
                        }
                    }

                    private int alter(int value) {
                        if (altered) {
                            return value;
                        }
                        altered = true;
                        return value ^ 1;
                    }
                };

                @Override
                public OutputStream getOutputStream() {
                    return output;
                }

                @Override
                public byte[] getSignature() throws IOException {
                    return signer.getSignature();
                }
            };
        }
    }

    private static byte[] readPem(String file, String type) throws Exception {
        Path path = Path.of(file);
        if (!Files.isRegularFile(path) || Files.size(path) > MAX_INPUT_BYTES) {
            throw new IllegalArgumentException("input is not a regular bounded file: " + file);
        }
        String text = Files.readString(path);
        PemObject object;
        try (PemReader reader = new PemReader(new StringReader(text))) {
            object = reader.readPemObject();
            if (object == null || !object.getType().equals(type) || reader.readPemObject() != null) {
                throw new IllegalArgumentException("input is not one " + type + " PEM: " + file);
            }
        }
        return object.getContent();
    }

    private static KeyMaterial readPrivateKey(String file) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(readPem(file, "PRIVATE KEY"));
        try {
            return new KeyMaterial(
                KeyFactory.getInstance("EC", "BC").generatePrivate(spec),
                SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa),
                "ecdsa_secp256r1_sha256");
        } catch (InvalidKeySpecException notEc) {
            try {
                return new KeyMaterial(
                    KeyFactory.getInstance("RSA", "BC").generatePrivate(spec),
                    SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
                    "rsa_pss_rsae_sha256");
            } catch (InvalidKeySpecException notRsa) {
                return new KeyMaterial(
                    KeyFactory.getInstance("ML-DSA", "BC").generatePrivate(spec),
                    SignatureAndHashAlgorithm.mldsa44,
                    "mldsa44");
            }
        }
    }

    private static X509Certificate certificate(byte[] der) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
            .generateCertificate(new ByteArrayInputStream(der));
    }

    private record KeyMaterial(
        PrivateKey key,
        SignatureAndHashAlgorithm algorithm,
        String name) {
    }

    private TlsTranscriptProbe() {
    }
}
