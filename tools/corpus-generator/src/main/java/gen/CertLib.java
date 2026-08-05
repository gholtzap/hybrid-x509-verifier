package gen;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * 결정적 인증서 빌딩 라이브러리 (규율 자산).
 * 모든 키/서명 난수는 Det.rng(label)에서 → 재생성 시 바이트 동일.
 */
public final class CertLib {
    private CertLib(){}

    public static final Path OUT = Paths.get(System.getProperty("corpus.out", "corpus/out"));
    static { try { Files.createDirectories(OUT); } catch (IOException ignored) {} }

    // ---- 결정적 키생성 ----
    public static KeyPair ec(String label) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(new ECGenParameterSpec("P-256"), Det.rng("key-" + label));
        return g.generateKeyPair();
    }
    public static KeyPair rsa(String label, int bits) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", "BC");
        g.initialize(bits, Det.rng("key-" + label));
        return g.generateKeyPair();
    }
    public static KeyPair mldsa(String label) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("ML-DSA", "BC");
        g.initialize(org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44, Det.rng("key-" + label));
        return g.generateKeyPair();
    }
    /** composite(MLDSA44-ECDSA-P256-SHA256) 키쌍 — 결정적. */
    public static KeyPair composite(String label) throws Exception {
        KeyPair postQuantum = mldsa(label + "-mldsa");
        KeyPair classical = ec(label + "-ecdsa");
        ASN1ObjectIdentifier algorithm = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.6.40");
        return new KeyPair(
            new CompositePublicKey(algorithm, postQuantum.getPublic(), classical.getPublic()),
            new CompositePrivateKey(algorithm, postQuantum.getPrivate(), classical.getPrivate()));
    }

    // ---- 결정적 서명기 (서명 난수도 고정) ----
    public static ContentSigner signer(String sigAlg, java.security.PrivateKey key, String label) throws Exception {
        return new JcaContentSignerBuilder(sigAlg).setProvider("BC")
                .setSecureRandom(Det.rng("sign-" + label)).build(key);
    }

    public static ContentSigner compositeSigner(KeyPair keyPair, String label) throws Exception {
        org.bouncycastle.crypto.CryptoServicesRegistrar.setSecureRandom(
                Det.rng("sign-" + label + "-components"));
        return new JcaContentSignerBuilder("MLDSA44-ECDSA-P256-SHA256").setProvider("BC")
                .build(keyPair.getPrivate());
    }

    // ---- 인증서 빌더 ----
    public static JcaX509v3CertificateBuilder builder(X500Name issuer, BigInteger serial, X500Name subject, PublicKey subKey) {
        return new JcaX509v3CertificateBuilder(issuer, serial, Det.NOT_BEFORE, Det.NOT_AFTER, subject, subKey);
    }
    static org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils extUtils() throws Exception {
        return new org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils();
    }
    /** CA 인증서: BC(true)+KU(certSign,cRLSign)+SKI(subKey)+AKI(issuerKey). self-signed면 issuerKey=subKey. */
    public static org.bouncycastle.cert.X509v3CertificateBuilder caBuilder(X500Name issuer, BigInteger serial, X500Name subject, PublicKey subKey, PublicKey issuerKey) throws Exception {
        return builder(issuer, serial, subject, subKey)
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils().createSubjectKeyIdentifier(subKey))
                .addExtension(Extension.authorityKeyIdentifier, false, extUtils().createAuthorityKeyIdentifier(issuerKey));
    }
    /** leaf 인증서: BC(false)+KU(digitalSignature)+SKI+AKI(issuerKey). */
    public static org.bouncycastle.cert.X509v3CertificateBuilder leafBuilder(X500Name issuer, BigInteger serial, X500Name subject, PublicKey subKey, PublicKey issuerKey) throws Exception {
        return leafBuilderDates(issuer, serial, subject, subKey, issuerKey, Det.NOT_BEFORE, Det.NOT_AFTER);
    }
    /** leaf 빌더(만료시각 지정) — Stage 3 EXPIRED 변형용.
     *  KeyUsage는 주체키 타입 기준 일반 규칙(특정 인증서 특례 아님):
     *    RSA leaf(서버)  = digitalSignature | keyEncipherment  (RSA 키전송; NSS certUsageSSLServer 요구)
     *    EC / ML-DSA     = digitalSignature                    (서명 기반)
     *  코퍼스의 유일한 RSA leaf가 related-certA이므로 이 규칙 정정은 certA에만 실질 영향. */
    public static org.bouncycastle.cert.X509v3CertificateBuilder leafBuilderDates(X500Name issuer, BigInteger serial, X500Name subject, PublicKey subKey, PublicKey issuerKey, java.util.Date nb, java.util.Date na) throws Exception {
        int ku = KeyUsage.digitalSignature;
        String alg = subKey.getAlgorithm();
        if (alg != null && alg.toUpperCase().contains("RSA")) ku |= KeyUsage.keyEncipherment;
        return new JcaX509v3CertificateBuilder(issuer, serial, nb, na, subject, subKey)
                .addExtension(Extension.basicConstraints, false, new BasicConstraints(false))
                .addExtension(Extension.keyUsage, true, new KeyUsage(ku))
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils().createSubjectKeyIdentifier(subKey))
                .addExtension(Extension.authorityKeyIdentifier, false, extUtils().createAuthorityKeyIdentifier(issuerKey));
    }

    /** 결정적 CRL: 발급자(issuerDn)가 revoked serial들을 폐지. thisUpdate=NOT_BEFORE, nextUpdate=NOT_AFTER, AKI+CRLNumber. */
    public static org.bouncycastle.cert.X509CRLHolder buildCrl(X500Name issuerDn, PublicKey issuerKey, ContentSigner crlSigner,
            long crlNumber, java.util.List<BigInteger> revoked, int reason) throws Exception {
        return buildCrl(issuerDn, issuerKey, crlSigner, crlNumber, revoked, reason, Det.NOT_BEFORE);
    }
    public static org.bouncycastle.cert.X509CRLHolder buildCrl(X500Name issuerDn, PublicKey issuerKey, ContentSigner crlSigner,
            long crlNumber, java.util.List<BigInteger> revoked, int reason, java.util.Date revocationDate) throws Exception {
        org.bouncycastle.cert.X509v2CRLBuilder cb = new org.bouncycastle.cert.X509v2CRLBuilder(issuerDn, Det.NOT_BEFORE);
        cb.setNextUpdate(Det.NOT_AFTER);
        for (BigInteger s : revoked) cb.addCRLEntry(s, revocationDate, reason);
        cb.addExtension(Extension.authorityKeyIdentifier, false, extUtils().createAuthorityKeyIdentifier(issuerKey));
        cb.addExtension(Extension.cRLNumber, false, new org.bouncycastle.asn1.x509.CRLNumber(BigInteger.valueOf(crlNumber)));
        return cb.build(crlSigner);
    }

    // ---- PEM 출력 + MANIFEST 기록 ----
    public static void writePem(String file, X509CertificateHolder cert, String scheme, String purpose, String gen) throws Exception {
        String pem = "-----BEGIN CERTIFICATE-----\n" + wrap(Base64.getEncoder().encodeToString(cert.getEncoded())) + "-----END CERTIFICATE-----\n";
        Files.write(OUT.resolve(file), pem.getBytes(StandardCharsets.US_ASCII));
        manifest(file, scheme, purpose, gen);
    }
    public static void writePemBytes(String file, String pemType, byte[] der) throws Exception {
        String pem = "-----BEGIN " + pemType + "-----\n" + wrap(Base64.getEncoder().encodeToString(der)) + "-----END " + pemType + "-----\n";
        Files.write(OUT.resolve(file), pem.getBytes(StandardCharsets.US_ASCII));
    }
    public static void writePrivateKey(String file, java.security.PrivateKey key) throws Exception {
        writePemBytes(file, "PRIVATE KEY", key.getEncoded());
    }
    public static void writeCertificateBundle(String file, java.util.List<X509CertificateHolder> certificates,
            String scheme, String purpose, String gen) throws Exception {
        StringBuilder pem = new StringBuilder();
        for (X509CertificateHolder certificate : certificates) {
            pem.append("-----BEGIN CERTIFICATE-----\n")
                .append(wrap(Base64.getEncoder().encodeToString(certificate.getEncoded())))
                .append("-----END CERTIFICATE-----\n");
        }
        Files.writeString(OUT.resolve(file), pem.toString(), StandardCharsets.US_ASCII);
        manifest(file, scheme, purpose, gen);
    }
    public static void writeBase64(String file, byte[] der) throws Exception {
        Files.writeString(OUT.resolve(file), Base64.getEncoder().encodeToString(der) + "\n", StandardCharsets.US_ASCII);
    }
    static String wrap(String b64) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < b64.length(); i += 64) s.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        return s.toString();
    }

    // MANIFEST.tsv: file \t scheme \t purpose \t gen(seed/serial)
    public static synchronized void manifest(String file, String scheme, String purpose, String gen) throws Exception {
        String line = file + "\t" + scheme + "\t" + purpose + "\t" + gen + "\n";
        try (OutputStream o = Files.newOutputStream(OUT.resolve("MANIFEST.tsv"),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND)) { o.write(line.getBytes(StandardCharsets.UTF_8)); }
    }
    public static void resetManifest() throws Exception {
        Files.write(OUT.resolve("MANIFEST.tsv"),
                "# file\tscheme\tpurpose\tgen(seed/serial)\n".getBytes(StandardCharsets.UTF_8));
    }
}
