package gen;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.DeltaCertificateTool;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import org.bouncycastle.openssl.PEMParser;

/**
 * Document 2 Stage 2 — 전 스킴 정상(valid) corpus, 결정적 3계층(Root–ICA–Leaf).
 * 스킴: pure-mldsa / related(RFC9763) / chameleon(DCD) / composite(atomic) / catalyst(alt-sig).
 * 리프 프로파일 통일: SAN(DNS)+EKU(serverAuth). (CMS/S-MIME/IKEv2는 다를 수 있음 — 의도적 스코프.)
 * 모든 키·서명난수·시각·serial 고정 → 재생성 바이트 동일.
 */
public class GenValid {
    static final ASN1ObjectIdentifier ID_PE_RELATED_CERT = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.36");
    static final ASN1ObjectIdentifier OID_SHA256 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");

    static X500Name rootDn, icaDn;
    static KeyPair rootKp, icaKp;
    static ContentSigner rootSigner, icaSigner;
    // Stage 3 desync 재사용: Related 쌍 산출물 (Choice A: certA가 ext 보유, leafB는 ext 없음)
    static X509CertificateHolder icaCert;
    static X509CertificateHolder relatedCertA;   // 제시 cert(classical) — non-critical RelatedCertificate->leafB
    static X509CertificateHolder relatedLeafB;   // 묶인 PQ cred(ext 없음)
    static KeyPair relAKp, relBKp;

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        CertLib.resetManifest();

        rootDn = new X500Name("CN=D2 Root CA,O=pqc-probe,C=KR");
        icaDn  = new X500Name("CN=D2 Issuing CA,O=pqc-probe,C=KR");

        // Root (EC self-signed), ICA (EC) — 공통 체인
        rootKp = CertLib.ec("root");
        rootSigner = CertLib.signer("SHA256withECDSA", rootKp.getPrivate(), "root");
        X509CertificateHolder root = CertLib.caBuilder(rootDn, bi(0x1000), rootDn, rootKp.getPublic(), rootKp.getPublic()).build(rootSigner);
        CertLib.writePem("root.pem", root, "common", "trust anchor Root CA (EC P-256)", "seed=root serial=0x1000");

        icaKp = CertLib.ec("ica");
        X509CertificateHolder ica = CertLib.caBuilder(rootDn, bi(0x1001), icaDn, icaKp.getPublic(), rootKp.getPublic()).build(rootSigner);
        CertLib.writePem("ica.pem", ica, "common", "intermediate CA (EC P-256)", "seed=ica serial=0x1001");
        icaCert = ica;
        icaSigner = CertLib.signer("SHA256withECDSA", icaKp.getPrivate(), "ica");

        genPure();
        genPureMldsaSigned();
        genPurePathScopeChain();
        genRelated();
        genRelatedControls();
        genRelatedOcsp();
        genRelatedDesync();   // Stage 3
        genChameleon();
        genChameleonPathScopeChain();
        genComposite();
        genCompositeControl();
        genCatalyst();
        // Batch2 item11: 방향-무관 대조 — 맨 뒤에서 생성(공유 icaSigner 상태를 main 생성 후에만 소비 → main 파일 byte-불변).
        genRelatedOrientationControl();
        genCatalystPathScopeChain();
        genAtomicPathScopeChain();
        genCrossSignedAtomicChain();
        genRelatedPathScopeChains();
        genCommonRootCrl();

        System.out.println("GenValid 완료 → corpus/out/*.pem (+ MANIFEST.tsv)");
    }

    // ---- pure ML-DSA ----
    static void genPure() throws Exception {
        KeyPair kp = CertLib.mldsa("pure-leaf");
        CertLib.writePrivateKey("pure-leaf-key.pem", kp.getPrivate());
        X509v3CertificateBuilder b = CertLib.leafBuilder(icaDn, bi(0x1020),
                new X500Name("CN=pure ML-DSA leaf,O=pqc-probe,C=KR"), kp.getPublic(), icaKp.getPublic());
        server(b, "pure.pqc-probe.test");
        CertLib.writePem("pure-leaf.pem", b.build(icaSigner), "pure-mldsa",
                "pure ML-DSA-44 leaf (대조군; 3엔진 인식 기준선)", "seed=pure-leaf serial=0x1020");
    }

    // ---- pure ML-DSA **서명** (대조군 보강, 상위 지시2): ML-DSA로 서명하는 CA → 리프 sigAlg=ML-DSA ----
    // 목적: 엔진이 ML-DSA '서명'을 실제 검증·합의하는지 확인 → fracture가 하이브리드 특유임 + baseline의 ML-DSA 검증능력 증명.
    static void genPureMldsaSigned() throws Exception {
        KeyPair mIcaKp = CertLib.mldsa("pure-mldsa-ica");
        X500Name mIcaDn = new X500Name("CN=D2 ML-DSA ICA,O=pqc-probe,C=KR");
        X509CertificateHolder mIca = CertLib.caBuilder(rootDn, bi(0x1070), mIcaDn, mIcaKp.getPublic(), rootKp.getPublic()).build(rootSigner);
        CertLib.writePem("pure-mldsa-ica.pem", mIca, "pure-mldsa-signed", "ML-DSA-keyed ICA (subject key=ML-DSA-44), Root(EC)-signed", "seed=pure-mldsa-ica serial=0x1070");
        ContentSigner mSigner = CertLib.signer("ML-DSA", mIcaKp.getPrivate(), "pure-mldsa-ica");
        KeyPair leafKp = CertLib.ec("pure-mldsa-leaf");
        X509v3CertificateBuilder b = CertLib.leafBuilder(mIcaDn, bi(0x1071),
                new X500Name("CN=ML-DSA-signed leaf,O=pqc-probe,C=KR"), leafKp.getPublic(), mIcaKp.getPublic());
        server(b, "mldsa-signed.pqc-probe.test");
        CertLib.writePem("pure-mldsa-signed-leaf.pem", b.build(mSigner), "pure-mldsa-signed",
                "leaf whose signatureAlgorithm is ML-DSA-44 (2.16.840.1.101.3.4.3.17); ML-DSA 검증 능력 대조 (ML-DSA 미지원 엔진=Unsupported도 데이터)", "seed=pure-mldsa-leaf serial=0x1071");
    }

    static void genPurePathScopeChain() throws Exception {
        X500Name pathRootDn = new X500Name("CN=Pure PQ Path Root,O=pqc-probe,C=KR");
        X500Name pathIcaDn = new X500Name("CN=Pure PQ Path ICA,O=pqc-probe,C=KR");
        KeyPair pathRoot = CertLib.mldsa("pure-path-root");
        KeyPair pathIca = CertLib.mldsa("pure-path-ica");
        KeyPair pathLeaf = CertLib.mldsa("pure-path-leaf");
        ContentSigner rootSigner = CertLib.signer("ML-DSA", pathRoot.getPrivate(), "pure-path-root");
        ContentSigner icaSigner = CertLib.signer("ML-DSA", pathIca.getPrivate(), "pure-path-ica");
        X509CertificateHolder root = CertLib.caBuilder(pathRootDn, bi(0x10d0), pathRootDn,
                pathRoot.getPublic(), pathRoot.getPublic()).build(rootSigner);
        X509CertificateHolder ica = CertLib.caBuilder(pathRootDn, bi(0x10d1), pathIcaDn,
                pathIca.getPublic(), pathRoot.getPublic()).build(rootSigner);
        X509v3CertificateBuilder leafBuilder = CertLib.leafBuilder(pathIcaDn, bi(0x10d2),
                new X500Name("CN=Pure PQ Path Leaf,O=pqc-probe,C=KR"),
                pathLeaf.getPublic(), pathIca.getPublic());
        server(leafBuilder, "pure-path.pqc-probe.test");
        X509CertificateHolder leaf = leafBuilder.build(icaSigner);
        CertLib.writePem("pure-path-root.pem", root, "pure-pq-path", "pure PQ trust anchor",
                "seed=pure-path-root serial=0x10d0");
        CertLib.writePem("pure-path-ica.pem", ica, "pure-pq-path", "pure PQ intermediate",
                "seed=pure-path-ica serial=0x10d1");
        CertLib.writePem("pure-path-leaf.pem", leaf, "pure-pq-path", "pure PQ leaf",
                "seed=pure-path-leaf serial=0x10d2");
        writeOuterSignatureMutation("pure-path-root-bad-signature.pem", root);
        writeOuterSignatureMutation("pure-path-ica-bad-signature.pem", ica);
        writeOuterSignatureMutation("pure-path-leaf-bad-signature.pem", leaf);
        writePurePathCrl("pure-path-root-crl.pem", pathRootDn, pathRoot,
                CertLib.signer("ML-DSA", pathRoot.getPrivate(), "pure-path-root-crl"), 15L);
        writePurePathCrl("pure-path-ica-crl.pem", pathIcaDn, pathIca,
                CertLib.signer("ML-DSA", pathIca.getPrivate(), "pure-path-ica-crl"), 16L);
    }

    static void writePurePathCrl(String file, X500Name issuer, KeyPair issuerKey,
            ContentSigner signer, long number) throws Exception {
        org.bouncycastle.cert.X509CRLHolder crl = CertLib.buildCrl(issuer,
                issuerKey.getPublic(), signer, number, java.util.List.of(), CRLReason.unspecified);
        CertLib.writePemBytes(file, "X509 CRL", crl.getEncoded());
        CertLib.manifest(file, "pure-pq-path", "current empty CRL", "crlNumber=" + number);
    }

    // ---- related (RFC 9763) — Choice A: 제시 cert(certA classical)가 비-critical RelatedCertificate로 leafB(PQ)를 가리킴 ----
    //   목적: default가 검증하는 바로 그 cert(certA)가 무시가능 바인딩을 들고, verifier가 §4.2대로 무시함을 한 artifact로 instantiate.
    static void genRelated() throws Exception {
        // (1) leafB 먼저 — ML-DSA PQ leaf, RelatedCertificate 확장 없음(방향 반전으로 폐기).
        KeyPair bKp = CertLib.mldsa("rel-leafB");
        CertLib.writePrivateKey("related-leafB-key.pem", bKp.getPrivate());
        X509v3CertificateBuilder b = CertLib.leafBuilder(icaDn, bi(0x1031),
                new X500Name("CN=related Leaf B (ML-DSA),O=pqc-probe,C=KR"), bKp.getPublic(), icaKp.getPublic());
        server(b, "related-b.pqc-probe.test");
        X509CertificateHolder leafB = b.build(icaSigner);
        CertLib.writePem("related-leafB.pem", leafB, "related",
                "PQC leaf (ML-DSA), NO RelatedCertificate ext (Choice A: 바인딩은 certA가 보유)", derNote("seed=rel-leafB serial=0x1031", leafB));

        // (2) certA — classical RSA-3072 제시 cert. non-critical RelatedCertificate 확장 값 = SHA-256(leafB DER).
        byte[] bHash = MessageDigest.getInstance("SHA-256").digest(leafB.getEncoded());
        ASN1EncodableVector rc = new ASN1EncodableVector();
        rc.add(new AlgorithmIdentifier(OID_SHA256)); rc.add(new DEROctetString(bHash));
        Extension relatedExt = new Extension(ID_PE_RELATED_CERT, false, new DERSequence(rc).getEncoded());
        KeyPair aKp = CertLib.rsa("rel-certA", 3072);
        CertLib.writePrivateKey("related-certA-key.pem", aKp.getPrivate());
        X509v3CertificateBuilder ab = CertLib.leafBuilder(icaDn, bi(0x1030),
                new X500Name("CN=related Cert A (RSA-3072),O=pqc-probe,C=KR"), aKp.getPublic(), icaKp.getPublic());
        server(ab, "related-a.pqc-probe.test");   // 제시 cert이므로 server 프로파일(SAN/EKU) 부여
        ab.addExtension(relatedExt);
        X509CertificateHolder certA = ab.build(icaSigner);
        CertLib.writePem("related-certA.pem", certA, "related",
                "classical RSA-3072 제시 cert + non-critical RelatedCertificate->leafB (SHA-256(leafB DER)); default가 검증하나 §4.2로 무시",
                derNote("seed=rel-certA serial=0x1030", certA));

        relatedCertA = certA; relAKp = aKp; relBKp = bKp; relatedLeafB = leafB;  // Stage 3 재사용
    }

    static void genRelatedControls() throws Exception {
        byte[] boundHash = MessageDigest.getInstance("SHA-256").digest(relatedLeafB.getEncoded());
        byte[] wrongHash = new byte[boundHash.length];
        Extension validCritical = relatedExtension(OID_SHA256, boundHash, true);
        Extension wrongBinding = relatedExtension(OID_SHA256, wrongHash, false);
        Extension unknownDigest = relatedExtension(
                new ASN1ObjectIdentifier("1.3.6.1.4.1.55555.1"), boundHash, false);
        Extension malformed = new Extension(ID_PE_RELATED_CERT, false,
                new byte[] { 0x01, 0x01, (byte) 0xff });

        writeRelatedControl("related-certA-missing.pem", null, "related-missing",
                "classical certA profile with RelatedCertificate evidence absent");
        writeRelatedControl("related-certA-broken-binding.pem", wrongBinding,
                "related-broken-binding", "RelatedCertificate contains the wrong SHA-256 value");
        writeRelatedControl("related-certA-unknown-digest.pem", unknownDigest,
                "related-unknown-algorithm", "RelatedCertificate uses an unknown digest algorithm");
        writeRelatedControl("related-certA-malformed.pem", malformed, "related-malformed",
                "RelatedCertificate extension value is malformed DER");
        writeRelatedControl("related-certA-critical.pem", validCritical, "related-critical",
                "valid RelatedCertificate binding marked critical");
    }

    static Extension relatedExtension(ASN1ObjectIdentifier algorithm, byte[] digest,
            boolean critical) throws Exception {
        ASN1EncodableVector fields = new ASN1EncodableVector();
        fields.add(new AlgorithmIdentifier(algorithm));
        fields.add(new DEROctetString(digest));
        return new Extension(ID_PE_RELATED_CERT, critical, new DERSequence(fields).getEncoded());
    }

    static Extension relatedExtension(X509CertificateHolder related) throws Exception {
        return relatedExtension(OID_SHA256,
                MessageDigest.getInstance("SHA-256").digest(related.getEncoded()), false);
    }

    static void genRelatedPathScopeChains() throws Exception {
        X500Name rootADn = new X500Name("CN=Related Path Root A,O=pqc-probe,C=KR");
        X500Name rootBDn = new X500Name("CN=Related Path Root B,O=pqc-probe,C=KR");
        X500Name icaADn = new X500Name("CN=Related Path ICA A,O=pqc-probe,C=KR");
        X500Name icaBDn = new X500Name("CN=Related Path ICA B,O=pqc-probe,C=KR");
        KeyPair rootAKey = CertLib.ec("related-path-root-a");
        KeyPair rootBKey = CertLib.mldsa("related-path-root-b");
        KeyPair icaAKey = CertLib.ec("related-path-ica-a");
        KeyPair icaBKey = CertLib.mldsa("related-path-ica-b");
        KeyPair leafAKey = CertLib.ec("related-path-leaf-a");
        KeyPair leafBKey = CertLib.mldsa("related-path-leaf-b");

        ContentSigner rootBSigner = CertLib.signer("ML-DSA", rootBKey.getPrivate(),
                "related-path-root-b");
        X509CertificateHolder rootB = CertLib.caBuilder(rootBDn, bi(0x10b0), rootBDn,
                rootBKey.getPublic(), rootBKey.getPublic()).build(rootBSigner);
        X509v3CertificateBuilder rootABuilder = CertLib.caBuilder(rootADn, bi(0x10b1), rootADn,
                rootAKey.getPublic(), rootAKey.getPublic());
        rootABuilder.addExtension(relatedExtension(rootB));
        ContentSigner rootASigner = CertLib.signer("SHA256withECDSA", rootAKey.getPrivate(),
                "related-path-root-a");
        X509CertificateHolder rootA = rootABuilder.build(rootASigner);

        ContentSigner icaBSigner = CertLib.signer("ML-DSA", icaBKey.getPrivate(),
                "related-path-ica-b");
        X509CertificateHolder icaB = CertLib.caBuilder(rootBDn, bi(0x10b2), icaBDn,
                icaBKey.getPublic(), rootBKey.getPublic()).build(rootBSigner);
        X509v3CertificateBuilder icaABuilder = CertLib.caBuilder(rootADn, bi(0x10b3), icaADn,
                icaAKey.getPublic(), rootAKey.getPublic());
        icaABuilder.addExtension(relatedExtension(icaB));
        ContentSigner icaASigner = CertLib.signer("SHA256withECDSA", icaAKey.getPrivate(),
                "related-path-ica-a");
        X509CertificateHolder icaA = icaABuilder.build(rootASigner);

        X509v3CertificateBuilder leafBBuilder = CertLib.leafBuilder(icaBDn, bi(0x10b4),
                new X500Name("CN=Related Path Leaf B,O=pqc-probe,C=KR"),
                leafBKey.getPublic(), icaBKey.getPublic());
        server(leafBBuilder, "related-path-b.pqc-probe.test");
        X509CertificateHolder leafB = leafBBuilder.build(icaBSigner);
        X509v3CertificateBuilder leafABuilder = CertLib.leafBuilder(icaADn, bi(0x10b5),
                new X500Name("CN=Related Path Leaf A,O=pqc-probe,C=KR"),
                leafAKey.getPublic(), icaAKey.getPublic());
        server(leafABuilder, "related-path-a.pqc-probe.test");
        leafABuilder.addExtension(relatedExtension(leafB));
        X509CertificateHolder leafA = leafABuilder.build(icaASigner);

        writeRelatedPathPair("root", rootA, rootB);
        writeRelatedPathPair("ica", icaA, icaB);
        writeRelatedPathPair("leaf", leafA, leafB);
        writeRelatedPathBadBinding("root", CertLib.caBuilder(rootADn, bi(0x10b1), rootADn,
                rootAKey.getPublic(), rootAKey.getPublic()), rootASigner);
        writeRelatedPathBadBinding("ica", CertLib.caBuilder(rootADn, bi(0x10b3), icaADn,
                icaAKey.getPublic(), rootAKey.getPublic()), rootASigner);
        X509v3CertificateBuilder badLeaf = CertLib.leafBuilder(icaADn, bi(0x10b5),
                new X500Name("CN=Related Path Leaf A,O=pqc-probe,C=KR"),
                leafAKey.getPublic(), icaAKey.getPublic());
        server(badLeaf, "related-path-a.pqc-probe.test");
        writeRelatedPathBadBinding("leaf", badLeaf, icaASigner);

        writeOuterSignatureMutation("related-path-root-a-bad-signature.pem", rootA);
        writeOuterSignatureMutation("related-path-root-b-bad-signature.pem", rootB);
        writeOuterSignatureMutation("related-path-ica-a-bad-signature.pem", icaA);
        writeOuterSignatureMutation("related-path-ica-b-bad-signature.pem", icaB);
        writeOuterSignatureMutation("related-path-leaf-a-bad-signature.pem", leafA);
        writeOuterSignatureMutation("related-path-leaf-b-bad-signature.pem", leafB);

        writeRelatedPathCrl("related-path-root-a-crl.pem", rootADn, rootAKey,
                CertLib.signer("SHA256withECDSA", rootAKey.getPrivate(), "related-path-root-a-crl"), 7L);
        writeRelatedPathCrl("related-path-ica-a-crl.pem", icaADn, icaAKey,
                CertLib.signer("SHA256withECDSA", icaAKey.getPrivate(), "related-path-ica-a-crl"), 8L);
        writeRelatedPathCrl("related-path-root-b-crl.pem", rootBDn, rootBKey,
                CertLib.signer("ML-DSA", rootBKey.getPrivate(), "related-path-root-b-crl"), 9L);
        writeRelatedPathCrl("related-path-ica-b-crl.pem", icaBDn, icaBKey,
                CertLib.signer("ML-DSA", icaBKey.getPrivate(), "related-path-ica-b-crl"), 10L);
    }

    static void writeRelatedPathPair(String position, X509CertificateHolder classical,
            X509CertificateHolder postQuantum) throws Exception {
        CertLib.writePem("related-path-" + position + "-a.pem", classical, "related-path",
                "classical certificate with a RelatedCertificate binding", "position=" + position);
        CertLib.writePem("related-path-" + position + "-b.pem", postQuantum, "related-path",
                "bound post-quantum certificate", "position=" + position);
    }

    static void writeRelatedPathBadBinding(String position, X509v3CertificateBuilder builder,
            ContentSigner signer) throws Exception {
        builder.addExtension(relatedExtension(OID_SHA256, new byte[32], false));
        CertLib.writePem("related-path-" + position + "-a-bad-binding.pem",
                builder.build(signer), "related-path-control",
                "classical certificate with an incorrect RelatedCertificate hash",
                "position=" + position);
    }

    static void writeOuterSignatureMutation(String file, X509CertificateHolder valid)
            throws Exception {
        CertLib.writePem(file, outerSignatureMutation(valid),
                "path-signature-control", "invalid outer certificate signature", "one-bit mutation");
    }

    static X509CertificateHolder outerSignatureMutation(X509CertificateHolder valid)
            throws Exception {
        byte[] signature = valid.getSignature();
        signature[signature.length - 1] ^= 1;
        ASN1EncodableVector fields = new ASN1EncodableVector();
        fields.add(valid.toASN1Structure().getTBSCertificate());
        fields.add(valid.getSignatureAlgorithm());
        fields.add(new DERBitString(signature));
        return new X509CertificateHolder(
                org.bouncycastle.asn1.x509.Certificate.getInstance(new DERSequence(fields)));
    }

    static void writeRelatedPathCrl(String file, X500Name issuer, KeyPair issuerKey,
            ContentSigner signer, long number) throws Exception {
        org.bouncycastle.cert.X509CRLHolder crl = CertLib.buildCrl(issuer,
                issuerKey.getPublic(), signer, number, java.util.List.of(), CRLReason.unspecified);
        CertLib.writePemBytes(file, "X509 CRL", crl.getEncoded());
        CertLib.manifest(file, "related-path", "current empty CRL", "crlNumber=" + number);
    }

    static void writeRelatedControl(String file, Extension extension, String scheme,
            String purpose) throws Exception {
        X509v3CertificateBuilder builder = CertLib.leafBuilder(icaDn, bi(0x1030),
                new X500Name("CN=related Cert A (RSA-3072),O=pqc-probe,C=KR"),
                relAKp.getPublic(), icaKp.getPublic());
        server(builder, "related-a.pqc-probe.test");
        if (extension != null) builder.addExtension(extension);
        X509CertificateHolder certificate = builder.build(CertLib.signer("SHA256withECDSA",
                icaKp.getPrivate(), scheme));
        CertLib.writePem(file, certificate, scheme, purpose, "seed=rel-certA serial=0x1030");
    }

    // ---- Stage 3: Related revocation/validity desync corpus (C1/C2) ----
    // Stage 2의 related-certA(classical, good) + related-leafB(PQ) 쌍을 재사용.
    // desync 시나리오: 묶인 PQ credential(leafB)이 폐지/만료되어도 기본경로가 certA만 보면 accept.
    static void genRelatedDesync() throws Exception {
        // (1) CRL: ICA가 leafB(serial 0x1031)를 keyCompromise로 폐지. certA(0x1030)는 폐지 안 함.
        org.bouncycastle.cert.X509CRLHolder crl = CertLib.buildCrl(icaDn, icaKp.getPublic(), icaSigner,
                1L, java.util.List.of(bi(0x1031)), org.bouncycastle.asn1.x509.CRLReason.keyCompromise);
        CertLib.writePemBytes("related-crl.pem", "X509 CRL", crl.getEncoded());
        CertLib.manifest("related-crl.pem", "related-desync",
                "ICA CRL: leafB(0x1031, PQ) keyCompromise 폐지; certA(0x1030 classical)는 valid", "seed=ica crlNumber=1");

        org.bouncycastle.cert.X509CRLHolder futureCrl = CertLib.buildCrl(icaDn, icaKp.getPublic(),
                CertLib.signer("SHA256withECDSA", icaKp.getPrivate(), "ica-future-crl"),
                3L, java.util.List.of(bi(0x1031)), CRLReason.keyCompromise,
                Det.FUTURE_REVOCATION_TIME);
        CertLib.writePemBytes("related-crl-future.pem", "X509 CRL", futureCrl.getEncoded());
        CertLib.manifest("related-crl-future.pem", "related-crl-control",
                "ICA CRL lists leafB(0x1031) with revocationDate after validation time",
                "crlNumber=3 revocationDate=2026-06-22T00:00:00Z");

        X509v3CertificateBuilder wrongSigner = CertLib.leafBuilder(icaDn, bi(0x1031),
                new X500Name("CN=related Leaf B (ML-DSA),O=pqc-probe,C=KR"),
                relBKp.getPublic(), icaKp.getPublic());
        server(wrongSigner, "related-b.pqc-probe.test");
        X509CertificateHolder wrongSignerLeaf = wrongSigner.build(
                CertLib.signer("SHA256withECDSA", rootKp.getPrivate(), "related-wrong-signer"));
        CertLib.writePem("related-leafB-wrong-signer.pem", wrongSignerLeaf, "related-crl-control",
                "leafB identity and serial with issuer name ICA but signature made by Root key",
                "seed=rel-leafB serial=0x1031 signer=root");

        X509v3CertificateBuilder unbound = CertLib.leafBuilder(icaDn, bi(0x1032),
                new X500Name("CN=related Leaf B UNBOUND (ML-DSA),O=pqc-probe,C=KR"),
                relBKp.getPublic(), icaKp.getPublic());
        server(unbound, "related-b.pqc-probe.test");
        X509CertificateHolder unboundLeaf = unbound.build(
                CertLib.signer("SHA256withECDSA", icaKp.getPrivate(), "related-unbound"));
        CertLib.writePem("related-leafB-unbound.pem", unboundLeaf, "related-binding-control",
                "valid current PQ leaf with the bound key but DER not named by certA hash",
                "seed=rel-leafB serial=0x1032");

        // (2) leafB-expired: 같은 키, RelatedCertificate 확장 없음(Choice A), notAfter=2026-04-01(검증 시점 이전) → EXPIRED.
        X509v3CertificateBuilder eb = CertLib.leafBuilderDates(icaDn, bi(0x1032),
                new X500Name("CN=related Leaf B EXPIRED (ML-DSA),O=pqc-probe,C=KR"),
                relBKp.getPublic(), icaKp.getPublic(), Det.NOT_BEFORE, Det.NOT_AFTER_PAST);
        server(eb, "related-b.pqc-probe.test");
        X509CertificateHolder leafBex = eb.build(icaSigner);
        CertLib.writePem("related-leafB-expired.pem", leafBex, "related-desync",
                "PQC leaf(같은 키) EXPIRED(notAfter=2026-04-01), ext 없음(Choice A); PQ EXPIRED 케이스", derNote("seed=rel-leafB serial=0x1032", leafBex));
    }

    static void genRelatedOcsp() throws Exception {
        writeOcsp("related-certA-good-ocsp.der.b64", relatedCertA, CertificateStatus.GOOD,
                Det.OCSP_THIS_UPDATE, Det.OCSP_NEXT_UPDATE, "related-ocsp-certA-good",
                "good status for classical certA(0x1030)");
        writeOcsp("related-certA-revoked-ocsp.der.b64", relatedCertA,
                new RevokedStatus(Det.OCSP_REVOCATION_TIME, CRLReason.keyCompromise),
                Det.OCSP_THIS_UPDATE, Det.OCSP_NEXT_UPDATE, "related-ocsp-certA-revoked",
                "revoked status for classical certA(0x1030)");
        writeOcsp("related-leafB-good-ocsp.der.b64", relatedLeafB, CertificateStatus.GOOD,
                Det.OCSP_THIS_UPDATE, Det.OCSP_NEXT_UPDATE, "related-ocsp-leafB-good",
                "good status for PQ leafB(0x1031)");
        writeOcsp("related-leafB-revoked-ocsp.der.b64", relatedLeafB,
                new RevokedStatus(Det.OCSP_REVOCATION_TIME, CRLReason.keyCompromise),
                Det.OCSP_THIS_UPDATE, Det.OCSP_NEXT_UPDATE, "related-ocsp-leafB-revoked",
                "revoked status for PQ leafB(0x1031)");
        writeOcsp("related-leafB-unknown-ocsp.der.b64", relatedLeafB, new UnknownStatus(),
                Det.OCSP_THIS_UPDATE, Det.OCSP_NEXT_UPDATE, "related-ocsp-leafB-unknown",
                "unknown status for PQ leafB(0x1031)");
        writeOcsp("related-leafB-stale-ocsp.der.b64", relatedLeafB, CertificateStatus.GOOD,
                Det.OCSP_STALE_THIS_UPDATE, Det.OCSP_STALE_NEXT_UPDATE, "related-ocsp-leafB-stale",
                "stale good status for PQ leafB(0x1031)");

        byte[] nonce = new byte[] {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb,
                (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff
        };
        Extensions nonceExtensions = new Extensions(new Extension(
                org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                false, new DEROctetString(nonce).getEncoded()));
        byte[] nonceResponse = buildOcsp(relatedLeafB, CertificateStatus.GOOD,
                Det.OCSP_THIS_UPDATE, Det.OCSP_NEXT_UPDATE, "related-ocsp-leafB-nonce",
                nonceExtensions);
        CertLib.writeBase64("related-leafB-nonce-ocsp.der.b64", nonceResponse);
        CertLib.manifest("related-leafB-nonce-ocsp.der.b64", "related-ocsp",
                "good PQ status bound to fixed 16-byte nonce", "nonce=ABEiM0RVZneImaq7zN3u/w==");

        KeyPair responderKp = CertLib.ec("ocsp-responder");
        X509v3CertificateBuilder responderBuilder = CertLib.leafBuilder(icaDn, bi(0x1080),
                new X500Name("CN=D2 OCSP Responder,O=pqc-probe,C=KR"),
                responderKp.getPublic(), icaKp.getPublic());
        responderBuilder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
        X509CertificateHolder responderCert = responderBuilder.build(
                CertLib.signer("SHA256withECDSA", icaKp.getPrivate(), "ocsp-responder-cert"));
        byte[] delegatedResponse = buildOcspWithResponder(relatedLeafB, CertificateStatus.GOOD,
                Det.OCSP_THIS_UPDATE, Det.OCSP_NEXT_UPDATE, "ocsp-responder-response", null,
                responderKp, responderCert);
        CertLib.writeBase64("related-leafB-delegated-ocsp.der.b64", delegatedResponse);
        CertLib.manifest("related-leafB-delegated-ocsp.der.b64", "related-ocsp",
                "good PQ status signed by an issuer-authorized delegated responder",
                "responder serial=0x1080 EKU=id-kp-OCSPSigning");

        KeyPair unauthorizedKp = CertLib.ec("ocsp-responder-no-eku");
        X509CertificateHolder unauthorizedCert = CertLib.leafBuilder(icaDn, bi(0x1081),
                new X500Name("CN=D2 OCSP Responder No EKU,O=pqc-probe,C=KR"),
                unauthorizedKp.getPublic(), icaKp.getPublic()).build(
                CertLib.signer("SHA256withECDSA", icaKp.getPrivate(), "ocsp-responder-no-eku-cert"));
        byte[] unauthorizedResponse = buildOcspWithResponder(relatedLeafB, CertificateStatus.GOOD,
                Det.OCSP_THIS_UPDATE, Det.OCSP_NEXT_UPDATE, "ocsp-responder-no-eku-response", null,
                unauthorizedKp, unauthorizedCert);
        CertLib.writeBase64("related-leafB-delegated-no-eku-ocsp.der.b64", unauthorizedResponse);
        CertLib.manifest("related-leafB-delegated-no-eku-ocsp.der.b64", "related-ocsp",
                "good PQ status signed by a delegated responder without OCSP signing EKU",
                "responder serial=0x1081 EKU=missing");

        OCSPResp unavailable = new OCSPRespBuilder().build(OCSPRespBuilder.TRY_LATER, null);
        CertLib.writeBase64("related-leafB-unavailable-ocsp.der.b64", unavailable.getEncoded());
        CertLib.manifest("related-leafB-unavailable-ocsp.der.b64", "related-ocsp",
                "responder returned tryLater; no certificate status", "fixed OCSP response status=3");

        CertLib.writeBase64("related-leafB-malformed-ocsp.der.b64",
                new byte[] { 0x30, 0x03, 0x0a, 0x01 });
        CertLib.manifest("related-leafB-malformed-ocsp.der.b64", "related-ocsp",
                "truncated OCSP response for strict DER rejection", "fixed four-byte DER prefix");
    }

    static void writeOcsp(String file, X509CertificateHolder certificate, CertificateStatus status,
            java.util.Date thisUpdate, java.util.Date nextUpdate, String label, String purpose) throws Exception {
        byte[] response = buildOcsp(certificate, status, thisUpdate, nextUpdate, label, null);
        CertLib.writeBase64(file, response);
        CertLib.manifest(file, "related-ocsp", purpose,
                "issuer=ica CertID=SHA-1 serial=" + certificate.getSerialNumber().toString(16));
    }

    static byte[] buildOcsp(X509CertificateHolder certificate, CertificateStatus status,
            java.util.Date thisUpdate, java.util.Date nextUpdate, String label,
            Extensions responseExtensions) throws Exception {
        return buildOcspWithResponder(certificate, status, thisUpdate, nextUpdate, label,
                responseExtensions, icaKp, icaCert);
    }

    static byte[] buildOcspWithResponder(X509CertificateHolder certificate, CertificateStatus status,
            java.util.Date thisUpdate, java.util.Date nextUpdate, String label,
            Extensions responseExtensions, KeyPair responderKeyPair,
            X509CertificateHolder responderCertificate) throws Exception {
        DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        CertificateID id = new CertificateID(digests.get(CertificateID.HASH_SHA1), icaCert,
                certificate.getSerialNumber());
        JcaBasicOCSPRespBuilder builder = new JcaBasicOCSPRespBuilder(responderKeyPair.getPublic(),
                digests.get(CertificateID.HASH_SHA1));
        builder.addResponse(id, status, thisUpdate, nextUpdate);
        if (responseExtensions != null) builder.setResponseExtensions(responseExtensions);
        BasicOCSPResp basic = builder.build(
                CertLib.signer("SHA256withECDSA", responderKeyPair.getPrivate(), label),
                new X509CertificateHolder[] { responderCertificate }, Det.OCSP_PRODUCED_AT);
        OCSPResp response = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic);
        return response.getEncoded();
    }

    // ---- Batch2 item11: Related orientation control (방향-무관 방어) ----
    //   canonical = RFC 9763 canonical migration 방향: 신규 PQ(leafB)가 기존 traditional(certA)을 참조.
    //   제시 cert는 세 orientation 모두 certA. mutual(양방향)은 대칭 full-DER 해시가 순환이라 결정적 생성 불가 → 생략(Appendix E 명시).
    //   별도 산출(corpus/out/orientation-control/)로 main 65행 매트릭스를 부풀리지 않음.
    static void genRelatedOrientationControl() throws Exception {
        java.nio.file.Files.createDirectories(CertLib.OUT.resolve("orientation-control"));
        // (1) certA: RSA classical, 확장 없음(leafB가 이를 참조), server 프로파일.
        KeyPair aKp = CertLib.rsa("canon-certA", 3072);
        X509v3CertificateBuilder ab = CertLib.leafBuilder(icaDn, bi(0x1070),
                new X500Name("CN=orient canon Cert A (RSA-3072),O=pqc-probe,C=KR"), aKp.getPublic(), icaKp.getPublic());
        server(ab, "canon-a.pqc-probe.test");
        X509CertificateHolder certA = ab.build(icaSigner);
        CertLib.writePem("orientation-control/canon-certA.pem", certA, "orientation-control",
                "canonical: certA(RSA classical) 제시 cert, 확장 없음(leafB가 참조)", derNote("seed=canon-certA serial=0x1070", certA));
        // (2) leafB: ML-DSA + non-critical RelatedCertificate = SHA-256(certA DER).
        byte[] aHash = MessageDigest.getInstance("SHA-256").digest(certA.getEncoded());
        ASN1EncodableVector rc = new ASN1EncodableVector();
        rc.add(new AlgorithmIdentifier(OID_SHA256)); rc.add(new DEROctetString(aHash));
        Extension ext = new Extension(ID_PE_RELATED_CERT, false, new DERSequence(rc).getEncoded());
        KeyPair bKp = CertLib.mldsa("canon-leafB");
        X509v3CertificateBuilder bb = CertLib.leafBuilder(icaDn, bi(0x1071),
                new X500Name("CN=orient canon Leaf B (ML-DSA),O=pqc-probe,C=KR"), bKp.getPublic(), icaKp.getPublic());
        server(bb, "canon-b.pqc-probe.test");
        bb.addExtension(ext);
        X509CertificateHolder leafB = bb.build(icaSigner);
        CertLib.writePem("orientation-control/canon-leafB.pem", leafB, "orientation-control",
                "canonical: leafB(ML-DSA) + non-critical RelatedCertificate->certA (SHA-256(certA DER))", derNote("seed=canon-leafB serial=0x1071", leafB));
        // (3) CRL: canon-leafB(0x1071) keyCompromise 폐지.
        org.bouncycastle.cert.X509CRLHolder crl = CertLib.buildCrl(icaDn, icaKp.getPublic(), icaSigner,
                2L, java.util.List.of(bi(0x1071)), org.bouncycastle.asn1.x509.CRLReason.keyCompromise);
        CertLib.writePemBytes("orientation-control/canon-crl.pem", "X509 CRL", crl.getEncoded());
        CertLib.manifest("orientation-control/canon-crl.pem", "orientation-control", "ICA CRL: canon-leafB(0x1071) keyCompromise 폐지", "seed=ica crlNumber=2");
    }

    // ---- chameleon (DCD) ----
    static void genChameleon() throws Exception {
        // Delta: ECDSA, 독립 serial
        KeyPair deltaKp = CertLib.ec("cham-delta");
        X509CertificateHolder delta = CertLib.leafBuilder(icaDn, bi(0x1042),
                new X500Name("CN=chameleon DELTA (ECDSA),O=pqc-probe,C=KR"), deltaKp.getPublic(), icaKp.getPublic()).build(icaSigner);
        CertLib.writePem("chameleon-delta.pem", delta, "chameleon-control",
                "delta certificate reconstructed by the DCD", "seed=cham-delta serial=0x1042");
        CertLib.writePrivateKey("chameleon-delta-key.pem", deltaKp.getPrivate());
        Extension dcd = DeltaCertificateTool.makeDeltaCertificateExtension(false, delta);
        // Base: ML-DSA + DCD
        KeyPair baseKp = CertLib.mldsa("cham-base");
        CertLib.writePrivateKey("chameleon-base-key.pem", baseKp.getPrivate());
        X509v3CertificateBuilder b = CertLib.leafBuilder(icaDn, bi(0x1041),
                new X500Name("CN=chameleon BASE (ML-DSA),O=pqc-probe,C=KR"), baseKp.getPublic(), icaKp.getPublic());
        server(b, "chameleon.pqc-probe.test");
        b.addExtension(dcd);
        CertLib.writePem("chameleon-base.pem", b.build(icaSigner), "chameleon",
                "Base ML-DSA + DCD(delta ECDSA, serial 0x1042); base serial 0x1041", "seed=cham-base serial=0x1041");

        X509v3CertificateBuilder validDeltaBuilder = CertLib.leafBuilder(icaDn, bi(0x1042),
                new X500Name("CN=chameleon DELTA (ECDSA),O=pqc-probe,C=KR"), deltaKp.getPublic(), icaKp.getPublic());
        server(validDeltaBuilder, "chameleon.pqc-probe.test");
        X509CertificateHolder validDelta = validDeltaBuilder.build(
                CertLib.signer("SHA256withECDSA", icaKp.getPrivate(), "ica-cham-valid-delta"));
        CertLib.writePem("chameleon-delta-valid.pem", validDelta, "chameleon-control",
                "delta certificate with extensions inherited from the base",
                "seed=cham-delta serial=0x1042");
        X509v3CertificateBuilder validBase = CertLib.leafBuilder(icaDn, bi(0x1041),
                new X500Name("CN=chameleon BASE (ML-DSA),O=pqc-probe,C=KR"), baseKp.getPublic(), icaKp.getPublic());
        server(validBase, "chameleon.pqc-probe.test");
        validBase.addExtension(DeltaCertificateTool.makeDeltaCertificateExtension(false, validDelta));
        CertLib.writePem("chameleon-base-valid-delta.pem", validBase.build(
                CertLib.signer("SHA256withECDSA", icaKp.getPrivate(), "ica-cham-valid-base")), "chameleon-control",
                "path-valid base with a valid bound delta certificate",
                "seed=cham-valid-base serial=0x1041");

        KeyPair wrongSigner = CertLib.ec("cham-delta-wrong-signer");
        X509v3CertificateBuilder invalidDeltaBuilder = CertLib.leafBuilder(icaDn, bi(0x1042),
                new X500Name("CN=chameleon DELTA (ECDSA),O=pqc-probe,C=KR"), deltaKp.getPublic(), icaKp.getPublic());
        server(invalidDeltaBuilder, "chameleon.pqc-probe.test");
        X509CertificateHolder invalidDelta = invalidDeltaBuilder.build(
                CertLib.signer("SHA256withECDSA", wrongSigner.getPrivate(), "cham-delta-wrong-signer"));
        X509v3CertificateBuilder invalidBase = CertLib.leafBuilder(icaDn, bi(0x1041),
                new X500Name("CN=chameleon BASE (ML-DSA),O=pqc-probe,C=KR"), baseKp.getPublic(), icaKp.getPublic());
        server(invalidBase, "chameleon.pqc-probe.test");
        invalidBase.addExtension(DeltaCertificateTool.makeDeltaCertificateExtension(false, invalidDelta));
        CertLib.writePem("chameleon-base-bad-delta.pem", invalidBase.build(
                CertLib.signer("SHA256withECDSA", icaKp.getPrivate(), "ica-cham-invalid-base")), "chameleon-control",
                "valid base path with a delta certificate signed by the wrong key",
                "seed=cham-delta-wrong-signer serial=0x1041");
    }

    static void genChameleonPathScopeChain() throws Exception {
        X500Name rootBaseDn = new X500Name("CN=Chameleon Path Root Base,O=pqc-probe,C=KR");
        X500Name rootDeltaDn = new X500Name("CN=Chameleon Path Root Delta,O=pqc-probe,C=KR");
        X500Name icaBaseDn = new X500Name("CN=Chameleon Path ICA Base,O=pqc-probe,C=KR");
        X500Name icaDeltaDn = new X500Name("CN=Chameleon Path ICA Delta,O=pqc-probe,C=KR");
        KeyPair rootBaseKey = CertLib.mldsa("chameleon-path-root-base");
        KeyPair rootDeltaKey = CertLib.ec("chameleon-path-root-delta");
        KeyPair icaBaseKey = CertLib.mldsa("chameleon-path-ica-base");
        KeyPair icaDeltaKey = CertLib.ec("chameleon-path-ica-delta");
        KeyPair leafBaseKey = CertLib.mldsa("chameleon-path-leaf-base");
        KeyPair leafDeltaKey = CertLib.ec("chameleon-path-leaf-delta");
        ContentSigner rootBaseSigner = CertLib.signer("ML-DSA", rootBaseKey.getPrivate(),
                "chameleon-path-root-base");
        ContentSigner rootDeltaSigner = CertLib.signer("SHA256withECDSA", rootDeltaKey.getPrivate(),
                "chameleon-path-root-delta");
        ContentSigner icaBaseSigner = CertLib.signer("ML-DSA", icaBaseKey.getPrivate(),
                "chameleon-path-ica-base");
        ContentSigner icaDeltaSigner = CertLib.signer("SHA256withECDSA", icaDeltaKey.getPrivate(),
                "chameleon-path-ica-delta");

        X509CertificateHolder rootDelta = CertLib.caBuilder(rootDeltaDn, bi(0x10c1), rootDeltaDn,
                rootDeltaKey.getPublic(), rootDeltaKey.getPublic()).build(rootDeltaSigner);
        X509v3CertificateBuilder rootBaseBuilder = CertLib.caBuilder(rootBaseDn, bi(0x10c0),
                rootBaseDn, rootBaseKey.getPublic(), rootBaseKey.getPublic());
        rootBaseBuilder.addExtension(DeltaCertificateTool.makeDeltaCertificateExtension(false, rootDelta));
        X509CertificateHolder rootBase = rootBaseBuilder.build(rootBaseSigner);

        X509CertificateHolder icaDelta = CertLib.caBuilder(rootDeltaDn, bi(0x10c3), icaDeltaDn,
                icaDeltaKey.getPublic(), rootDeltaKey.getPublic()).build(rootDeltaSigner);
        X509v3CertificateBuilder icaBaseBuilder = CertLib.caBuilder(rootBaseDn, bi(0x10c2),
                icaBaseDn, icaBaseKey.getPublic(), rootBaseKey.getPublic());
        icaBaseBuilder.addExtension(DeltaCertificateTool.makeDeltaCertificateExtension(false, icaDelta));
        X509CertificateHolder icaBase = icaBaseBuilder.build(rootBaseSigner);

        X509v3CertificateBuilder leafDeltaBuilder = CertLib.leafBuilder(icaDeltaDn, bi(0x10c5),
                new X500Name("CN=Chameleon Path Leaf Delta,O=pqc-probe,C=KR"),
                leafDeltaKey.getPublic(), icaDeltaKey.getPublic());
        server(leafDeltaBuilder, "chameleon-path.pqc-probe.test");
        X509CertificateHolder leafDelta = leafDeltaBuilder.build(icaDeltaSigner);
        X509v3CertificateBuilder leafBaseBuilder = CertLib.leafBuilder(icaBaseDn, bi(0x10c4),
                new X500Name("CN=Chameleon Path Leaf Base,O=pqc-probe,C=KR"),
                leafBaseKey.getPublic(), icaBaseKey.getPublic());
        server(leafBaseBuilder, "chameleon-path.pqc-probe.test");
        leafBaseBuilder.addExtension(DeltaCertificateTool.makeDeltaCertificateExtension(false, leafDelta));
        X509CertificateHolder leafBase = leafBaseBuilder.build(icaBaseSigner);

        writeChameleonPathPair("root", rootBase, rootDelta);
        writeChameleonPathPair("ica", icaBase, icaDelta);
        writeChameleonPathPair("leaf", leafBase, leafDelta);
        writeChameleonBadDeltaRoot(rootBaseDn, rootDeltaDn, rootBaseKey, rootDeltaKey,
                rootBaseSigner);
        writeChameleonBadDeltaIca(rootBaseDn, rootDeltaDn, icaBaseDn, icaDeltaDn,
                rootBaseKey, rootDeltaKey, icaBaseKey, icaDeltaKey, rootBaseSigner);
        writeChameleonBadDeltaLeaf(icaBaseDn, icaDeltaDn, icaBaseKey, icaDeltaKey,
                leafBaseKey, leafDeltaKey, icaBaseSigner);
        writeOuterSignatureMutation("chameleon-path-root-base-bad-signature.pem", rootBase);
        writeOuterSignatureMutation("chameleon-path-ica-base-bad-signature.pem", icaBase);
        writeOuterSignatureMutation("chameleon-path-leaf-base-bad-signature.pem", leafBase);

        writeChameleonPathCrl("chameleon-path-root-base-crl.pem", rootBaseDn, rootBaseKey,
                CertLib.signer("ML-DSA", rootBaseKey.getPrivate(), "chameleon-path-root-base-crl"), 11L);
        writeChameleonPathCrl("chameleon-path-ica-base-crl.pem", icaBaseDn, icaBaseKey,
                CertLib.signer("ML-DSA", icaBaseKey.getPrivate(), "chameleon-path-ica-base-crl"), 12L);
        writeChameleonPathCrl("chameleon-path-root-delta-crl.pem", rootDeltaDn, rootDeltaKey,
                CertLib.signer("SHA256withECDSA", rootDeltaKey.getPrivate(), "chameleon-path-root-delta-crl"), 13L);
        writeChameleonPathCrl("chameleon-path-ica-delta-crl.pem", icaDeltaDn, icaDeltaKey,
                CertLib.signer("SHA256withECDSA", icaDeltaKey.getPrivate(), "chameleon-path-ica-delta-crl"), 14L);
    }

    static void writeChameleonPathPair(String position, X509CertificateHolder base,
            X509CertificateHolder delta) throws Exception {
        CertLib.writePem("chameleon-path-" + position + "-base.pem", base, "chameleon-path",
                "ML-DSA base certificate with a delta descriptor", "position=" + position);
        CertLib.writePem("chameleon-path-" + position + "-delta.pem", delta,
                "chameleon-path-control", "reconstructed ECDSA delta certificate",
                "position=" + position);
    }

    static void writeChameleonBadDeltaRoot(X500Name baseDn, X500Name deltaDn,
            KeyPair baseKey, KeyPair deltaKey, ContentSigner baseSigner) throws Exception {
        KeyPair wrong = CertLib.ec("chameleon-path-root-wrong-delta");
        X509CertificateHolder badDelta = CertLib.caBuilder(deltaDn, bi(0x10c1), deltaDn,
                deltaKey.getPublic(), deltaKey.getPublic()).build(
                    CertLib.signer("SHA256withECDSA", wrong.getPrivate(), "chameleon-path-root-wrong-delta"));
        X509v3CertificateBuilder builder = CertLib.caBuilder(baseDn, bi(0x10c0), baseDn,
                baseKey.getPublic(), baseKey.getPublic());
        builder.addExtension(DeltaCertificateTool.makeDeltaCertificateExtension(false, badDelta));
        CertLib.writePem("chameleon-path-root-base-bad-delta.pem", builder.build(baseSigner),
                "chameleon-path-control", "valid base with an invalid root delta signature",
                "position=root");
    }

    static void writeChameleonBadDeltaIca(X500Name rootBaseDn, X500Name rootDeltaDn,
            X500Name icaBaseDn, X500Name icaDeltaDn, KeyPair rootBaseKey, KeyPair rootDeltaKey,
            KeyPair icaBaseKey, KeyPair icaDeltaKey, ContentSigner rootBaseSigner) throws Exception {
        KeyPair wrong = CertLib.ec("chameleon-path-ica-wrong-delta");
        X509CertificateHolder badDelta = CertLib.caBuilder(rootDeltaDn, bi(0x10c3), icaDeltaDn,
                icaDeltaKey.getPublic(), rootDeltaKey.getPublic()).build(
                    CertLib.signer("SHA256withECDSA", wrong.getPrivate(), "chameleon-path-ica-wrong-delta"));
        X509v3CertificateBuilder builder = CertLib.caBuilder(rootBaseDn, bi(0x10c2), icaBaseDn,
                icaBaseKey.getPublic(), rootBaseKey.getPublic());
        builder.addExtension(DeltaCertificateTool.makeDeltaCertificateExtension(false, badDelta));
        CertLib.writePem("chameleon-path-ica-base-bad-delta.pem", builder.build(rootBaseSigner),
                "chameleon-path-control", "valid base with an invalid ICA delta signature",
                "position=intermediate");
    }

    static void writeChameleonBadDeltaLeaf(X500Name icaBaseDn, X500Name icaDeltaDn,
            KeyPair icaBaseKey, KeyPair icaDeltaKey, KeyPair leafBaseKey, KeyPair leafDeltaKey,
            ContentSigner icaBaseSigner) throws Exception {
        KeyPair wrong = CertLib.ec("chameleon-path-leaf-wrong-delta");
        X509v3CertificateBuilder deltaBuilder = CertLib.leafBuilder(icaDeltaDn, bi(0x10c5),
                new X500Name("CN=Chameleon Path Leaf Delta,O=pqc-probe,C=KR"),
                leafDeltaKey.getPublic(), icaDeltaKey.getPublic());
        server(deltaBuilder, "chameleon-path.pqc-probe.test");
        X509CertificateHolder badDelta = deltaBuilder.build(
                CertLib.signer("SHA256withECDSA", wrong.getPrivate(), "chameleon-path-leaf-wrong-delta"));
        X509v3CertificateBuilder baseBuilder = CertLib.leafBuilder(icaBaseDn, bi(0x10c4),
                new X500Name("CN=Chameleon Path Leaf Base,O=pqc-probe,C=KR"),
                leafBaseKey.getPublic(), icaBaseKey.getPublic());
        server(baseBuilder, "chameleon-path.pqc-probe.test");
        baseBuilder.addExtension(DeltaCertificateTool.makeDeltaCertificateExtension(false, badDelta));
        CertLib.writePem("chameleon-path-leaf-base-bad-delta.pem",
                baseBuilder.build(icaBaseSigner), "chameleon-path-control",
                "valid base with an invalid leaf delta signature", "position=leaf");
    }

    static void writeChameleonPathCrl(String file, X500Name issuer, KeyPair issuerKey,
            ContentSigner signer, long number) throws Exception {
        org.bouncycastle.cert.X509CRLHolder crl = CertLib.buildCrl(issuer,
                issuerKey.getPublic(), signer, number, java.util.List.of(), CRLReason.unspecified);
        CertLib.writePemBytes(file, "X509 CRL", crl.getEncoded());
        CertLib.manifest(file, "chameleon-path", "current empty CRL", "crlNumber=" + number);
    }

    // ---- composite (atomic): 리프 서명이 composite가 되도록 composite-keyed ICA로 발급 ----
    // Published vectors remain fixed so their paper digests do not change. New controls use
    // CertLib.composite(), which constructs deterministic component keys without the BC KPG.
    static void genComposite() throws Exception {
        boolean exists = java.nio.file.Files.exists(CertLib.OUT.resolve("composite-leaf.pem"))
                && java.nio.file.Files.exists(CertLib.OUT.resolve("composite-ica.pem"));
        if (exists) {
            CertLib.manifest("composite-ica.pem", "composite", "composite-keyed ICA (FIXED committed vector; BC composite KPG seed-비재현)", "committed");
            CertLib.manifest("composite-leaf.pem", "composite", "leaf w/ composite signatureAlgorithm(1.3.6.1.5.5.7.6.40) -> atomic; unaware=Unsupported (FIXED committed vector)", "committed");
            System.out.println("composite: 기존 고정 벡터 유지(재생성 생략).");
            return;
        }
        KeyPair compIcaKp = CertLib.composite("comp-ica");
        X500Name compIcaDn = new X500Name("CN=D2 Composite ICA,O=pqc-probe,C=KR");
        // composite ICA 인증서: subject=composite key, Root(EC)이 서명
        X509CertificateHolder compIca = CertLib.caBuilder(rootDn, bi(0x1050), compIcaDn, compIcaKp.getPublic(), rootKp.getPublic()).build(rootSigner);
        CertLib.writePem("composite-ica.pem", compIca, "composite", "composite-keyed ICA (subject key=MLDSA44-ECDSA-P256), Root-signed", "seed=comp-ica serial=0x1050");
        ContentSigner compSigner = CertLib.signer("MLDSA44-ECDSA-P256-SHA256", compIcaKp.getPrivate(), "comp-ica");
        // Leaf: subject EC, ICA가 composite로 서명 → leaf.signatureAlgorithm = composite(atomic)
        KeyPair leafKp = CertLib.ec("comp-leaf");
        X509v3CertificateBuilder b = CertLib.leafBuilder(compIcaDn, bi(0x1051),
                new X500Name("CN=composite-signed leaf,O=pqc-probe,C=KR"), leafKp.getPublic(), compIcaKp.getPublic());
        server(b, "composite.pqc-probe.test");
        CertLib.writePem("composite-leaf.pem", b.build(compSigner), "composite",
                "leaf whose signatureAlgorithm is composite(1.3.6.1.5.5.7.6.40) -> atomic; unaware engine=Unsupported", "seed=comp-leaf serial=0x1051");
    }

    static void genCompositeControl() throws Exception {
        X509CertificateHolder valid;
        try (PEMParser parser = new PEMParser(Files.newBufferedReader(
                CertLib.OUT.resolve("composite-leaf.pem")))) {
            Object object = parser.readObject();
            if (!(object instanceof X509CertificateHolder) || parser.readObject() != null) {
                throw new IllegalStateException("composite-leaf.pem is not one certificate");
            }
            valid = (X509CertificateHolder) object;
        }
        if (!valid.getSignatureAlgorithm().getAlgorithm().getId().equals("1.3.6.1.5.5.7.6.40")) {
            throw new IllegalStateException("composite leaf has an unexpected signature algorithm");
        }
        KeyPair leafKey = CertLib.ec("comp-leaf");
        if (!java.util.Arrays.equals(valid.getSubjectPublicKeyInfo().getEncoded(),
                leafKey.getPublic().getEncoded())) {
            throw new IllegalStateException("composite leaf does not match the deterministic EC key");
        }
        CertLib.writePrivateKey("composite-leaf-key.pem", leafKey.getPrivate());
        byte[] signature = valid.getSignature();
        int mldsa44SignatureBytes = 2420;
        byte[] ecdsaSignature = java.util.Arrays.copyOfRange(
                signature, mldsa44SignatureBytes, signature.length);
        if (signature.length <= mldsa44SignatureBytes
                || !(ASN1Primitive.fromByteArray(ecdsaSignature) instanceof ASN1Sequence)) {
            throw new IllegalStateException(
                    "composite signature does not contain ML-DSA-44 and ECDSA components");
        }
        signature[0] ^= 1;
        ASN1EncodableVector fields = new ASN1EncodableVector();
        fields.add(valid.toASN1Structure().getTBSCertificate());
        fields.add(valid.getSignatureAlgorithm());
        fields.add(new DERBitString(signature));
        X509CertificateHolder invalid = new X509CertificateHolder(
                org.bouncycastle.asn1.x509.Certificate.getInstance(new DERSequence(fields)));
        CertLib.writePem("composite-leaf-bad-mldsa.pem", invalid, "composite-control",
                "unchanged ECDSA component and invalid ML-DSA-44 signature component",
                "source=composite-leaf.pem mutation=ML-DSA-byte-0-xor-1");
    }

    static void genAtomicPathScopeChain() throws Exception {
        X500Name pathRootDn = new X500Name("CN=Atomic Path Root,O=pqc-probe,C=KR");
        X500Name pathIcaDn = new X500Name("CN=Atomic Path ICA,O=pqc-probe,C=KR");
        KeyPair pathRoot = CertLib.composite("atomic-path-root");
        KeyPair pathIca = CertLib.composite("atomic-path-ica");
        KeyPair pathLeaf = CertLib.ec("atomic-path-leaf");
        ContentSigner rootSigner = CertLib.compositeSigner(pathRoot, "atomic-path-root");
        ContentSigner icaSigner = CertLib.compositeSigner(pathIca, "atomic-path-ica");

        X509CertificateHolder root = CertLib.caBuilder(pathRootDn, bi(0x10a0), pathRootDn,
                pathRoot.getPublic(), pathRoot.getPublic()).build(rootSigner);
        X509CertificateHolder ica = CertLib.caBuilder(pathRootDn, bi(0x10a1), pathIcaDn,
                pathIca.getPublic(), pathRoot.getPublic()).build(rootSigner);
        X509v3CertificateBuilder leafBuilder = CertLib.leafBuilder(pathIcaDn, bi(0x10a2),
                new X500Name("CN=Atomic Path Leaf,O=pqc-probe,C=KR"),
                pathLeaf.getPublic(), pathIca.getPublic());
        server(leafBuilder, "atomic-path.pqc-probe.test");
        X509CertificateHolder leaf = leafBuilder.build(icaSigner);

        CertLib.writePem("atomic-path-root.pem", root, "atomic-path", "atomic trust anchor",
                "seed=atomic-path-root serial=0x10a0");
        CertLib.writePem("atomic-path-ica.pem", ica, "atomic-path", "atomic intermediate",
                "seed=atomic-path-ica serial=0x10a1");
        CertLib.writePem("atomic-path-leaf.pem", leaf, "atomic-path", "atomic leaf signature",
                "seed=atomic-path-leaf serial=0x10a2");
        CertLib.writePrivateKey("atomic-path-root-key.pem", pathRoot.getPrivate());
        CertLib.writePrivateKey("atomic-path-ica-key.pem", pathIca.getPrivate());
        CertLib.writePrivateKey("atomic-path-leaf-key.pem", pathLeaf.getPrivate());

        writeCompositeMutation("atomic-path-root-bad-mldsa.pem", root, true);
        writeCompositeMutation("atomic-path-root-bad-ecdsa.pem", root, false);
        writeCompositeMutation("atomic-path-ica-bad-mldsa.pem", ica, true);
        writeCompositeMutation("atomic-path-ica-bad-ecdsa.pem", ica, false);
        writeCompositeMutation("atomic-path-leaf-bad-mldsa.pem", leaf, true);
        writeCompositeMutation("atomic-path-leaf-bad-ecdsa.pem", leaf, false);

        org.bouncycastle.cert.X509CRLHolder rootCrl = CertLib.buildCrl(pathRootDn,
                pathRoot.getPublic(), rootSigner, 5L, java.util.List.of(),
                org.bouncycastle.asn1.x509.CRLReason.unspecified);
        org.bouncycastle.cert.X509CRLHolder icaCrl = CertLib.buildCrl(pathIcaDn,
                pathIca.getPublic(), icaSigner, 6L, java.util.List.of(),
                org.bouncycastle.asn1.x509.CRLReason.unspecified);
        CertLib.writePemBytes("atomic-path-root-crl.pem", "X509 CRL", rootCrl.getEncoded());
        CertLib.writePemBytes("atomic-path-ica-crl.pem", "X509 CRL", icaCrl.getEncoded());
        CertLib.manifest("atomic-path-root-crl.pem", "atomic-path",
                "current empty CRL for the atomic root", "seed=atomic-path-root crlNumber=5");
        CertLib.manifest("atomic-path-ica-crl.pem", "atomic-path",
                "current empty CRL for the atomic ICA", "seed=atomic-path-ica crlNumber=6");
    }

    static void writeCompositeMutation(String file, X509CertificateHolder valid,
            boolean postQuantum) throws Exception {
        X509CertificateHolder invalid = compositeMutation(valid, postQuantum);
        CertLib.writePem(file, invalid, "atomic-path-control",
                "one invalid composite signature component",
                "source=atomic-path component=" + (postQuantum ? "mldsa" : "ecdsa"));
    }

    static X509CertificateHolder compositeMutation(X509CertificateHolder valid,
            boolean postQuantum) throws Exception {
        byte[] signature = valid.getSignature();
        signature[postQuantum ? 0 : signature.length - 1] ^= 1;
        ASN1EncodableVector fields = new ASN1EncodableVector();
        fields.add(valid.toASN1Structure().getTBSCertificate());
        fields.add(valid.getSignatureAlgorithm());
        fields.add(new DERBitString(signature));
        return new X509CertificateHolder(
                org.bouncycastle.asn1.x509.Certificate.getInstance(new DERSequence(fields)));
    }

    static void genCrossSignedAtomicChain() throws Exception {
        X500Name classicalRootDn = new X500Name("CN=Cross Classical Root,O=pqc-probe,C=KR");
        X500Name atomicRootDn = new X500Name("CN=Cross Atomic Root,O=pqc-probe,C=KR");
        X500Name sharedIcaDn = new X500Name("CN=Cross Shared Atomic ICA,O=pqc-probe,C=KR");
        KeyPair classicalRoot = CertLib.ec("cross-root-classical");
        KeyPair atomicRoot = CertLib.composite("cross-root-atomic");
        KeyPair sharedIca = CertLib.composite("cross-ica");
        KeyPair leafKey = CertLib.ec("cross-leaf");
        ContentSigner classicalRootSigner = CertLib.signer("SHA256withECDSA",
                classicalRoot.getPrivate(), "cross-root-classical");
        ContentSigner atomicRootSigner = CertLib.compositeSigner(atomicRoot, "cross-root-atomic");
        ContentSigner sharedIcaSigner = CertLib.compositeSigner(sharedIca, "cross-ica");
        X509CertificateHolder classicalRootCertificate = CertLib.caBuilder(classicalRootDn,
                bi(0x10e0), classicalRootDn, classicalRoot.getPublic(), classicalRoot.getPublic())
                .build(classicalRootSigner);
        X509CertificateHolder atomicRootCertificate = CertLib.caBuilder(atomicRootDn,
                bi(0x10e1), atomicRootDn, atomicRoot.getPublic(), atomicRoot.getPublic())
                .build(atomicRootSigner);
        X509CertificateHolder classicalIca = CertLib.caBuilder(classicalRootDn, bi(0x10e2),
                sharedIcaDn, sharedIca.getPublic(), classicalRoot.getPublic())
                .build(classicalRootSigner);
        X509CertificateHolder atomicIca = CertLib.caBuilder(atomicRootDn, bi(0x10e3),
                sharedIcaDn, sharedIca.getPublic(), atomicRoot.getPublic())
                .build(atomicRootSigner);
        X509v3CertificateBuilder leafBuilder = CertLib.leafBuilder(sharedIcaDn, bi(0x10e4),
                new X500Name("CN=Cross Atomic Leaf,O=pqc-probe,C=KR"), leafKey.getPublic(),
                sharedIca.getPublic());
        server(leafBuilder, "cross.pqc-probe.test");
        X509CertificateHolder leaf = leafBuilder.build(sharedIcaSigner);

        CertLib.writePem("cross-root-classical.pem", classicalRootCertificate, "cross-signed",
                "classical trust anchor", "seed=cross-root-classical serial=0x10e0");
        CertLib.writePem("cross-root-atomic.pem", atomicRootCertificate, "cross-signed",
                "atomic trust anchor", "seed=cross-root-atomic serial=0x10e1");
        CertLib.writePem("cross-ica-classical.pem", classicalIca, "cross-signed",
                "shared atomic ICA key signed by the classical root",
                "seed=cross-root-classical serial=0x10e2");
        CertLib.writePem("cross-ica-atomic.pem", atomicIca, "cross-signed",
                "shared atomic ICA key signed by the atomic root",
                "seed=cross-root-atomic serial=0x10e3");
        CertLib.writePem("cross-leaf.pem", leaf, "cross-signed", "atomic leaf",
                "seed=cross-ica serial=0x10e4");
        CertLib.writeCertificateBundle("cross-roots.pem",
                java.util.List.of(classicalRootCertificate, atomicRootCertificate), "cross-signed",
                "both trust anchors", "order=classical,atomic");
        CertLib.writeCertificateBundle("cross-icas.pem",
                java.util.List.of(classicalIca, atomicIca), "cross-signed",
                "both cross-signed ICA certificates", "order=classical,atomic");

        X509CertificateHolder badClassicalIca = outerSignatureMutation(classicalIca);
        X509CertificateHolder badAtomicIcaMldsa = compositeMutation(atomicIca, true);
        X509CertificateHolder badAtomicIcaEcdsa = compositeMutation(atomicIca, false);
        writeOuterSignatureMutation("cross-root-classical-bad-signature.pem", classicalRootCertificate);
        writeCompositeMutation("cross-root-atomic-bad-mldsa.pem", atomicRootCertificate, true);
        writeCompositeMutation("cross-root-atomic-bad-ecdsa.pem", atomicRootCertificate, false);
        CertLib.writePem("cross-ica-classical-bad-signature.pem", badClassicalIca,
                "cross-signed-control", "invalid classical cross-certificate signature",
                "one-bit mutation");
        CertLib.writePem("cross-ica-atomic-bad-mldsa.pem", badAtomicIcaMldsa,
                "cross-signed-control", "invalid ML-DSA cross-certificate component",
                "component=mldsa");
        CertLib.writePem("cross-ica-atomic-bad-ecdsa.pem", badAtomicIcaEcdsa,
                "cross-signed-control", "invalid ECDSA cross-certificate component",
                "component=ecdsa");
        writeCompositeMutation("cross-leaf-bad-mldsa.pem", leaf, true);
        writeCompositeMutation("cross-leaf-bad-ecdsa.pem", leaf, false);
        CertLib.writeCertificateBundle("cross-icas-classical-fallback.pem",
                java.util.List.of(classicalIca, badAtomicIcaMldsa), "cross-signed-control",
                "valid classical cross-certificate and invalid atomic cross-certificate",
                "order=classical,bad-atomic-mldsa");
        CertLib.writeCertificateBundle("cross-icas-atomic-fallback.pem",
                java.util.List.of(badClassicalIca, atomicIca), "cross-signed-control",
                "invalid classical cross-certificate and valid atomic cross-certificate",
                "order=bad-classical,atomic");

        org.bouncycastle.cert.X509CRLHolder classicalRootCrl = CertLib.buildCrl(classicalRootDn,
                classicalRoot.getPublic(), CertLib.signer("SHA256withECDSA",
                    classicalRoot.getPrivate(), "cross-root-classical-crl"), 17L,
                java.util.List.of(), CRLReason.unspecified);
        org.bouncycastle.cert.X509CRLHolder atomicRootCrl = CertLib.buildCrl(atomicRootDn,
                atomicRoot.getPublic(), CertLib.compositeSigner(atomicRoot,
                    "cross-root-atomic-crl"), 18L, java.util.List.of(), CRLReason.unspecified);
        org.bouncycastle.cert.X509CRLHolder icaCrl = CertLib.buildCrl(sharedIcaDn,
                sharedIca.getPublic(), CertLib.compositeSigner(sharedIca, "cross-ica-crl"), 19L,
                java.util.List.of(), CRLReason.unspecified);
        CertLib.writePemBytes("cross-root-classical-crl.pem", "X509 CRL",
                classicalRootCrl.getEncoded());
        CertLib.writePemBytes("cross-root-atomic-crl.pem", "X509 CRL", atomicRootCrl.getEncoded());
        CertLib.writePemBytes("cross-ica-crl.pem", "X509 CRL", icaCrl.getEncoded());
        CertLib.manifest("cross-root-classical-crl.pem", "cross-signed", "current empty CRL",
                "seed=cross-root-classical crlNumber=17");
        CertLib.manifest("cross-root-atomic-crl.pem", "cross-signed", "current empty CRL",
                "seed=cross-root-atomic crlNumber=18");
        CertLib.manifest("cross-ica-crl.pem", "cross-signed", "current empty CRL",
                "seed=cross-ica crlNumber=19");
    }

    // ---- catalyst (alt-sig): 하이브리드 ICA(base EC + alt ML-DSA)로 발급 ----
    static void genCatalyst() throws Exception {
        KeyPair catIcaBase = CertLib.ec("cat-ica-base");
        KeyPair catIcaAlt  = CertLib.mldsa("cat-ica-alt");
        X500Name catIcaDn = new X500Name("CN=D2 Catalyst ICA,O=pqc-probe,C=KR");
        // catalyst ICA: base EC subject + subjectAltPublicKeyInfo(alt ML-DSA), Root(EC) 서명
        X509v3CertificateBuilder ib = CertLib.caBuilder(rootDn, bi(0x1060), catIcaDn, catIcaBase.getPublic(), rootKp.getPublic());
        ib.addExtension(Extension.subjectAltPublicKeyInfo, false,
                new SubjectAltPublicKeyInfo(SubjectPublicKeyInfo.getInstance(catIcaAlt.getPublic().getEncoded())));
        X509CertificateHolder catIca = ib.build(rootSigner);
        CertLib.writePem("catalyst-ica.pem", catIca, "catalyst", "hybrid ICA: base EC + subjectAltPublicKeyInfo(ML-DSA alt)", "seed=cat-ica serial=0x1060");
        ContentSigner catBaseSigner = CertLib.signer("SHA256withECDSA", catIcaBase.getPrivate(), "cat-ica-base");
        ContentSigner catAltSigner  = CertLib.signer("ML-DSA", catIcaAlt.getPrivate(), "cat-ica-alt");
        // Leaf: base EC subject + subjectAltPublicKeyInfo(leaf alt ML-DSA); build(base, altCritical=false, alt)
        KeyPair leafBase = CertLib.ec("cat-leaf-base");
        KeyPair leafAlt  = CertLib.mldsa("cat-leaf-alt");
        CertLib.writePrivateKey("catalyst-leaf-base-key.pem", leafBase.getPrivate());
        X509v3CertificateBuilder b = CertLib.leafBuilder(catIcaDn, bi(0x1061),
                new X500Name("CN=catalyst leaf base-ECDSA alt-MLDSA,O=pqc-probe,C=KR"), leafBase.getPublic(), catIcaBase.getPublic());
        server(b, "catalyst.pqc-probe.test");
        b.addExtension(Extension.subjectAltPublicKeyInfo, false,
                new SubjectAltPublicKeyInfo(SubjectPublicKeyInfo.getInstance(leafAlt.getPublic().getEncoded())));
        X509CertificateHolder leaf = b.build(catBaseSigner, false, catAltSigner);
        CertLib.writePem("catalyst-leaf.pem", leaf, "catalyst",
                "base ECDSA sig + altSignature(ML-DSA, non-critical); baseline ignores alt -> Accept-classical", "seed=cat-leaf serial=0x1061");

        // Controlled variant: the classical signature remains valid, but the alternative
        // signature is made by a key that does not match the issuer alternative public key.
        KeyPair wrongAlt = CertLib.mldsa("cat-wrong-alt");
        X509v3CertificateBuilder bad = CertLib.leafBuilder(catIcaDn, bi(0x1061),
                new X500Name("CN=catalyst leaf base-ECDSA alt-MLDSA,O=pqc-probe,C=KR"), leafBase.getPublic(), catIcaBase.getPublic());
        server(bad, "catalyst.pqc-probe.test");
        bad.addExtension(Extension.subjectAltPublicKeyInfo, false,
                new SubjectAltPublicKeyInfo(SubjectPublicKeyInfo.getInstance(leafAlt.getPublic().getEncoded())));
        X509CertificateHolder badLeaf = bad.build(
                CertLib.signer("SHA256withECDSA", catIcaBase.getPrivate(), "cat-ica-base"),
                false,
                CertLib.signer("ML-DSA", wrongAlt.getPrivate(), "cat-wrong-alt"));
        CertLib.writePem("catalyst-leaf-bad-alt.pem", badLeaf, "catalyst-control",
                "valid base ECDSA signature and invalid alternative ML-DSA signature", "seed=cat-wrong-alt serial=0x1061");

        org.bouncycastle.cert.X509CRLHolder crl = CertLib.buildCrl(catIcaDn, catIcaBase.getPublic(),
                CertLib.signer("SHA256withECDSA", catIcaBase.getPrivate(), "cat-ica-base-crl"),
                3L, java.util.List.of(), org.bouncycastle.asn1.x509.CRLReason.unspecified);
        CertLib.writePemBytes("catalyst-crl.pem", "X509 CRL", crl.getEncoded());
        CertLib.manifest("catalyst-crl.pem", "catalyst-control",
                "empty current CRL for the Catalyst issuing CA", "seed=cat-ica-base-crl crlNumber=3");
    }

    static void genCatalystPathScopeChain() throws Exception {
        X500Name pathRootDn = new X500Name("CN=Catalyst Path Root,O=pqc-probe,C=KR");
        X500Name pathIcaDn = new X500Name("CN=Catalyst Path ICA,O=pqc-probe,C=KR");
        KeyPair rootBase = CertLib.ec("cat-path-root-base");
        KeyPair rootAlt = CertLib.mldsa("cat-path-root-alt");
        KeyPair icaBase = CertLib.ec("cat-path-ica-base");
        KeyPair icaAlt = CertLib.mldsa("cat-path-ica-alt");
        KeyPair leafBase = CertLib.ec("cat-path-leaf-base");
        KeyPair leafAlt = CertLib.mldsa("cat-path-leaf-alt");

        X509v3CertificateBuilder rootBuilder = CertLib.caBuilder(pathRootDn, bi(0x1090),
                pathRootDn, rootBase.getPublic(), rootBase.getPublic());
        rootBuilder.addExtension(Extension.subjectAltPublicKeyInfo, false,
                new SubjectAltPublicKeyInfo(SubjectPublicKeyInfo.getInstance(rootAlt.getPublic().getEncoded())));
        X509CertificateHolder root = rootBuilder.build(
                CertLib.signer("SHA256withECDSA", rootBase.getPrivate(), "cat-path-root-base"), false,
                CertLib.signer("ML-DSA", rootAlt.getPrivate(), "cat-path-root-alt"));
        CertLib.writePem("catalyst-path-root.pem", root, "catalyst-path",
                "Catalyst trust anchor with base and alternative signatures",
                "seed=cat-path-root serial=0x1090");

        X509v3CertificateBuilder icaBuilder = CertLib.caBuilder(pathRootDn, bi(0x1091),
                pathIcaDn, icaBase.getPublic(), rootBase.getPublic());
        icaBuilder.addExtension(Extension.subjectAltPublicKeyInfo, false,
                new SubjectAltPublicKeyInfo(SubjectPublicKeyInfo.getInstance(icaAlt.getPublic().getEncoded())));
        X509CertificateHolder ica = icaBuilder.build(
                CertLib.signer("SHA256withECDSA", rootBase.getPrivate(), "cat-path-ica-base"), false,
                CertLib.signer("ML-DSA", rootAlt.getPrivate(), "cat-path-ica-alt"));
        CertLib.writePem("catalyst-path-ica.pem", ica, "catalyst-path",
                "Catalyst intermediate with base and alternative signatures",
                "seed=cat-path-ica serial=0x1091");

        X509v3CertificateBuilder leafBuilder = CertLib.leafBuilder(pathIcaDn, bi(0x1092),
                new X500Name("CN=Catalyst Path Leaf,O=pqc-probe,C=KR"),
                leafBase.getPublic(), icaBase.getPublic());
        server(leafBuilder, "catalyst-path.pqc-probe.test");
        leafBuilder.addExtension(Extension.subjectAltPublicKeyInfo, false,
                new SubjectAltPublicKeyInfo(SubjectPublicKeyInfo.getInstance(leafAlt.getPublic().getEncoded())));
        X509CertificateHolder leaf = leafBuilder.build(
                CertLib.signer("SHA256withECDSA", icaBase.getPrivate(), "cat-path-leaf-base"), false,
                CertLib.signer("ML-DSA", icaAlt.getPrivate(), "cat-path-leaf-alt"));
        CertLib.writePem("catalyst-path-leaf.pem", leaf, "catalyst-path",
                "Catalyst leaf in a Catalyst root and intermediate chain",
                "seed=cat-path-leaf serial=0x1092");
        CertLib.writePrivateKey("catalyst-path-leaf-base-key.pem", leafBase.getPrivate());
        CertLib.writePrivateKey("catalyst-path-leaf-alt-key.pem", leafAlt.getPrivate());

        org.bouncycastle.cert.X509CRLHolder rootCrl = CertLib.buildCrl(pathRootDn,
                rootBase.getPublic(), CertLib.signer("SHA256withECDSA", rootBase.getPrivate(),
                "cat-path-root-crl"), 0x1090L, java.util.List.of(), CRLReason.unspecified);
        CertLib.writePemBytes("catalyst-path-root-crl.pem", "X509 CRL", rootCrl.getEncoded());
        CertLib.manifest("catalyst-path-root-crl.pem", "catalyst-path",
                "current empty CRL for the Catalyst root", "seed=cat-path-root-crl crlNumber=0x1090");
        org.bouncycastle.cert.X509CRLHolder icaCrl = CertLib.buildCrl(pathIcaDn,
                icaBase.getPublic(), CertLib.signer("SHA256withECDSA", icaBase.getPrivate(),
                "cat-path-ica-crl"), 0x1091L, java.util.List.of(), CRLReason.unspecified);
        CertLib.writePemBytes("catalyst-path-ica-crl.pem", "X509 CRL", icaCrl.getEncoded());
        CertLib.manifest("catalyst-path-ica-crl.pem", "catalyst-path",
                "current empty CRL for the Catalyst intermediate", "seed=cat-path-ica-crl crlNumber=0x1091");

        KeyPair wrongLeafAlt = CertLib.mldsa("cat-path-leaf-wrong-alt");
        X509v3CertificateBuilder badLeafBuilder = CertLib.leafBuilder(pathIcaDn, bi(0x1092),
                new X500Name("CN=Catalyst Path Leaf,O=pqc-probe,C=KR"),
                leafBase.getPublic(), icaBase.getPublic());
        server(badLeafBuilder, "catalyst-path.pqc-probe.test");
        badLeafBuilder.addExtension(Extension.subjectAltPublicKeyInfo, false,
                new SubjectAltPublicKeyInfo(SubjectPublicKeyInfo.getInstance(leafAlt.getPublic().getEncoded())));
        CertLib.writePem("catalyst-path-leaf-bad-alt.pem", badLeafBuilder.build(
                CertLib.signer("SHA256withECDSA", icaBase.getPrivate(), "cat-path-leaf-bad-base"), false,
                CertLib.signer("ML-DSA", wrongLeafAlt.getPrivate(), "cat-path-leaf-wrong-alt")),
                "catalyst-path-control", "path-valid leaf with an invalid alternative signature",
                "seed=cat-path-leaf-wrong-alt serial=0x1092");

        KeyPair wrongIcaAlt = CertLib.mldsa("cat-path-ica-wrong-alt");
        X509v3CertificateBuilder badIcaBuilder = CertLib.caBuilder(pathRootDn, bi(0x1091),
                pathIcaDn, icaBase.getPublic(), rootBase.getPublic());
        badIcaBuilder.addExtension(Extension.subjectAltPublicKeyInfo, false,
                new SubjectAltPublicKeyInfo(SubjectPublicKeyInfo.getInstance(icaAlt.getPublic().getEncoded())));
        CertLib.writePem("catalyst-path-ica-bad-alt.pem", badIcaBuilder.build(
                CertLib.signer("SHA256withECDSA", rootBase.getPrivate(), "cat-path-ica-bad-base"), false,
                CertLib.signer("ML-DSA", wrongIcaAlt.getPrivate(), "cat-path-ica-wrong-alt")),
                "catalyst-path-control", "path-valid intermediate with an invalid alternative signature",
                "seed=cat-path-ica-wrong-alt serial=0x1091");

        KeyPair wrongRootAlt = CertLib.mldsa("cat-path-root-wrong-alt");
        X509v3CertificateBuilder badRootBuilder = CertLib.caBuilder(pathRootDn, bi(0x1090),
                pathRootDn, rootBase.getPublic(), rootBase.getPublic());
        badRootBuilder.addExtension(Extension.subjectAltPublicKeyInfo, false,
                new SubjectAltPublicKeyInfo(SubjectPublicKeyInfo.getInstance(rootAlt.getPublic().getEncoded())));
        CertLib.writePem("catalyst-path-root-bad-alt.pem", badRootBuilder.build(
                CertLib.signer("SHA256withECDSA", rootBase.getPrivate(), "cat-path-root-bad-base"), false,
                CertLib.signer("ML-DSA", wrongRootAlt.getPrivate(), "cat-path-root-wrong-alt")),
                "catalyst-path-control", "trust anchor with an invalid alternative self-signature",
                "seed=cat-path-root-wrong-alt serial=0x1090");
    }

    static void genCommonRootCrl() throws Exception {
        org.bouncycastle.cert.X509CRLHolder crl = CertLib.buildCrl(rootDn,
                rootKp.getPublic(), CertLib.signer("SHA256withECDSA", rootKp.getPrivate(),
                "common-root-crl"), 4L, java.util.List.of(), CRLReason.unspecified);
        CertLib.writePemBytes("root-crl.pem", "X509 CRL", crl.getEncoded());
        CertLib.manifest("root-crl.pem", "common-control",
                "current empty CRL for the common root", "seed=common-root-crl crlNumber=4");
    }

    // ---- helpers ----
    static void server(X509v3CertificateBuilder b, String dns) throws Exception {
        b.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, dns)));
        b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
    }
    static BigInteger bi(long v){ return BigInteger.valueOf(v); }
    /** MANIFEST gen 노트에 인증서 DER SHA-256 부기(내용 변경분 추적용, [A3]). */
    static String derNote(String base, X509CertificateHolder c) throws Exception {
        byte[] h = MessageDigest.getInstance("SHA-256").digest(c.getEncoded());
        StringBuilder s = new StringBuilder();
        for (byte x : h) s.append(String.format("%02x", x));
        return base + " der-sha256=" + s;
    }
}
