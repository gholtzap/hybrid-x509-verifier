use clap::{Parser, Subcommand, ValueEnum};
use hybrid_x509_evidence::{
    AdapterReport, AuthenticationLevel, VerificationRequest, VerificationResult,
    adapters::bouncy_castle::{
        BouncyCastleConfig, BouncyCastleMode, verify as verify_bouncy_castle,
    },
    adapters::gnutls::{
        GnuTlsConfig, GnuTlsStudyConfig, verify as verify_gnutls,
        verify_study as verify_gnutls_study,
    },
    adapters::go_x509::{GoX509Config, verify as verify_go_x509},
    adapters::nss::{NssConfig, NssRelease, verify as verify_nss},
    adapters::openssl::{OpenSslConfig, OpenSslTlsConfig, verify as verify_openssl},
    adapters::oqs_provider::{OqsProviderConfig, verify as verify_oqs_provider},
    adapters::pyca::{
        PycaConfig, PycaContainerConfig, PycaRelease, verify as verify_pyca,
        verify_container as verify_pyca_container,
    },
    adapters::wolfssl::{WolfSslConfig, WolfSslMode, verify as verify_wolfssl},
    analysis::atomic_path_scope::{
        AtomicPathScopeConfig, AtomicPathScopeReport, analyze as analyze_atomic_path_scope,
    },
    analysis::atomic_tls::{AtomicTlsConfig, AtomicTlsReport, analyze as analyze_atomic_tls},
    analysis::catalyst_bouncy_castle::{
        CatalystBouncyCastleConfig, CatalystBouncyCastleReport,
        analyze as analyze_catalyst_bouncy_castle,
    },
    analysis::catalyst_path_scope::{
        CatalystPathScopeConfig, CatalystPathScopeReport, analyze as analyze_catalyst_path_scope,
    },
    analysis::catalyst_tls::{
        CatalystTlsConfig, CatalystTlsReport, analyze as analyze_catalyst_tls,
    },
    analysis::chameleon_path_scope::{
        ChameleonPathScopeConfig, ChameleonPathScopeReport, analyze as analyze_chameleon_path_scope,
    },
    analysis::chameleon_tls::{
        ChameleonTlsConfig, ChameleonTlsReport, analyze as analyze_chameleon_tls,
    },
    analysis::cross_signed_path::{
        CrossSignedPathConfig, CrossSignedPathReport, analyze as analyze_cross_signed_path,
    },
    analysis::matrix::{AvailableMatrixConfig, MatrixReport, run_available_matrix},
    analysis::pure_path_scope::{
        PurePathScopeConfig, PurePathScopeReport, analyze as analyze_pure_path_scope,
    },
    analysis::related_openssl::{
        RelatedOpenSslConfig, RelatedOpenSslReport, analyze as analyze_related_openssl,
    },
    analysis::related_path_scope::{
        RelatedPathScopeConfig, RelatedPathScopeReport, analyze as analyze_related_path_scope,
    },
    analysis::related_tls::{RelatedTlsConfig, RelatedTlsReport, analyze as analyze_related_tls},
    analysis::tls::{
        TlsHandshakeEvidence, TlsTranscriptConfig, TlsTranscriptEvidence, observe as observe_tls,
        observe_transcript,
    },
    corpus::verify_corpus,
    evaluate,
    input::read_bounded_file,
    mutation::{corrupt_outer_signature, encode_certificate_pem},
    ocsp::{OcspPolicy, check_ocsp_status},
    pem::{PemKind, read_der},
};
use std::{fs, path::PathBuf, process::ExitCode, time::Duration};

#[derive(Debug, Parser)]
#[command(name = "hybrid-x509-evaluate")]
#[command(about = "Evaluate trusted X.509 evidence claims against an explicit hybrid policy")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Evaluate a versioned JSON request.
    Verify {
        #[arg(value_name = "REQUEST.json")]
        request: PathBuf,
        #[arg(long, default_value_t = 1_048_576)]
        input_limit_bytes: usize,
    },
    /// Print a JSON Schema 2020-12 document.
    Schema {
        #[arg(value_enum)]
        document: SchemaDocument,
    },
    /// Verify an OCSP response independently from a validation stack.
    CheckOcsp {
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        issuer: PathBuf,
        #[arg(long)]
        response: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long)]
        expected_nonce_base64: Option<String>,
        #[arg(long, default_value_t = 604_800)]
        max_age_seconds: u64,
        #[arg(long, default_value_t = 300)]
        clock_skew_seconds: u64,
        #[arg(long, value_enum, default_value_t = RevocationPolicyModeArgument::SoftFail)]
        revocation_mode: RevocationPolicyModeArgument,
        #[arg(long, default_value_t = 1_048_576)]
        input_limit_bytes: usize,
    },
    /// Create a deterministic certificate with a corrupted outer signature.
    MutateCertificateSignature {
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 1_048_576)]
        input_limit_bytes: usize,
    },
    /// Run the OpenSSL path validator and record its raw result.
    ProbeOpenssl {
        #[arg(long, default_value = "openssl")]
        executable: PathBuf,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        untrusted_chain: Option<PathBuf>,
        #[arg(long)]
        leaf: PathBuf,
        #[arg(long)]
        crl: Option<PathBuf>,
        #[arg(long)]
        validation_time: String,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Run an isolated OpenSSL TLS 1.3 server and client and record authentication evidence.
    ProbeOpensslTls {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-openssl:4.0.1")]
        image: String,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        intermediate: PathBuf,
        #[arg(long)]
        leaf: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        hostname: String,
        #[arg(long)]
        validation_time: String,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Prove TLS CertificateVerify transcript binding with a controlled altered input.
    ProbeTlsTranscript {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-bouncycastle:1.85")]
        image: String,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        intermediate: PathBuf,
        #[arg(long)]
        leaf: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Run the GnuTLS certificate validator and record its raw result.
    ProbeGnutls {
        #[arg(long)]
        executable: PathBuf,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        untrusted_chain: Option<PathBuf>,
        #[arg(long)]
        leaf: PathBuf,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Run the pinned GnuTLS study validator in an isolated container.
    ProbeGnutlsStudy {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-gnutls:3.7.3")]
        image: String,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        intermediate: PathBuf,
        #[arg(long)]
        leaf: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Run the Go crypto/x509 adapter and record its raw result.
    ProbeGoX509 {
        #[arg(long)]
        executable: PathBuf,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        intermediate: PathBuf,
        #[arg(long)]
        leaf: PathBuf,
        #[arg(long)]
        dns_name: String,
        #[arg(long)]
        validation_time: String,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Run the Python cryptography adapter and record its raw result.
    ProbePyca {
        #[arg(long, default_value = "python3")]
        python: PathBuf,
        #[arg(long, default_value = "tools/pyca-x509-adapter.py")]
        script: PathBuf,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        intermediate: PathBuf,
        #[arg(long)]
        leaf: PathBuf,
        #[arg(long)]
        dns_name: String,
        #[arg(long)]
        validation_time: String,
        #[arg(long)]
        hybrid_extension_oid: Option<String>,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Run a pinned Python cryptography validator in an isolated container.
    ProbePycaContainer {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, value_enum)]
        release: PycaReleaseArgument,
        #[arg(long)]
        image: Option<String>,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        intermediate: PathBuf,
        #[arg(long)]
        leaf: PathBuf,
        #[arg(long)]
        dns_name: String,
        #[arg(long)]
        validation_time: String,
        #[arg(long)]
        hybrid_extension_oid: Option<String>,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Run the pinned Bouncy Castle PKIX validator in an isolated container.
    ProbeBouncyCastle {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-bouncycastle:1.85")]
        image: String,
        #[arg(long, value_enum, default_value = "path")]
        mode: BouncyCastleModeArgument,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        intermediate: PathBuf,
        #[arg(long)]
        leaf: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long)]
        crl: Option<PathBuf>,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Run the pinned NSS server-certificate validator in an isolated container.
    ProbeNss {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, value_enum, default_value = "study98")]
        release: NssReleaseArgument,
        #[arg(long)]
        image: Option<String>,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        intermediate: PathBuf,
        #[arg(long)]
        leaf: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Run the pinned oqs-provider path validator in an isolated container.
    ProbeOqsProvider {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-oqs-provider:0.11.0")]
        image: String,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        intermediate: PathBuf,
        #[arg(long)]
        leaf: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Run a pinned wolfSSL certificate validator in an isolated container.
    ProbeWolfSsl {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-wolfssl:5.9.2")]
        image: String,
        #[arg(long, value_enum)]
        mode: WolfSslModeArgument,
        #[arg(long)]
        scheme: String,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        intermediate: Option<PathBuf>,
        #[arg(long)]
        leaf: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Evaluate RFC 9763 binding and revocation behavior through OpenSSL.
    AnalyzeRelatedOpenssl {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-openssl:4.0.1")]
        image: String,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        issuer: PathBuf,
        #[arg(long)]
        classical_certificate: PathBuf,
        #[arg(long)]
        post_quantum_certificate: PathBuf,
        #[arg(long)]
        expired_post_quantum_certificate: PathBuf,
        #[arg(long)]
        invalid_binding_certificate: PathBuf,
        #[arg(long)]
        crl: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long, value_enum)]
        policy: PolicyArgument,
        #[arg(long, value_enum)]
        previous_authentication: Option<AuthenticationLevelArgument>,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Test whether Bouncy Castle default validation makes Catalyst PQ evidence decisive.
    AnalyzeCatalystBouncyCastle {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-bouncycastle:1.85")]
        image: String,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        issuer: PathBuf,
        #[arg(long)]
        valid_certificate: PathBuf,
        #[arg(long)]
        invalid_post_quantum_certificate: PathBuf,
        #[arg(long)]
        crl: PathBuf,
        #[arg(long)]
        root_crl: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long, value_enum)]
        policy: PolicyArgument,
        #[arg(long, value_enum)]
        previous_authentication: Option<AuthenticationLevelArgument>,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Test Catalyst evidence at the leaf, intermediate, and trust anchor.
    AnalyzeCatalystPathScope {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-bouncycastle:1.85")]
        image: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        intermediate: PathBuf,
        #[arg(long)]
        leaf: PathBuf,
        #[arg(long)]
        invalid_alternative_root: PathBuf,
        #[arg(long)]
        invalid_alternative_intermediate: PathBuf,
        #[arg(long)]
        invalid_alternative_leaf: PathBuf,
        #[arg(long)]
        root_crl: PathBuf,
        #[arg(long)]
        intermediate_crl: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long, value_enum)]
        policy: PolicyArgument,
        #[arg(long, value_enum)]
        previous_authentication: Option<AuthenticationLevelArgument>,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Test whether a Catalyst PQ signature changes TLS server authentication.
    AnalyzeCatalystTls {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-openssl:4.0.1")]
        openssl_image: String,
        #[arg(long, default_value = "hybrid-x509-bouncycastle:1.85")]
        bouncy_castle_image: String,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        issuer: PathBuf,
        #[arg(long)]
        valid_certificate: PathBuf,
        #[arg(long)]
        invalid_post_quantum_certificate: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        crl: PathBuf,
        #[arg(long)]
        hostname: String,
        #[arg(long)]
        validation_time: String,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Test whether each atomic composite signature component changes TLS acceptance.
    AnalyzeAtomicTls {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-bouncycastle:1.85")]
        image: String,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        issuer: PathBuf,
        #[arg(long)]
        valid_certificate: PathBuf,
        #[arg(long)]
        invalid_post_quantum_certificate: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Test atomic composite evidence at the leaf, intermediate, and trust anchor.
    AnalyzeAtomicPathScope {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-bouncycastle:1.85")]
        image: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        intermediate: PathBuf,
        #[arg(long)]
        leaf: PathBuf,
        #[arg(long)]
        invalid_classical_root: PathBuf,
        #[arg(long)]
        invalid_post_quantum_root: PathBuf,
        #[arg(long)]
        invalid_classical_intermediate: PathBuf,
        #[arg(long)]
        invalid_post_quantum_intermediate: PathBuf,
        #[arg(long)]
        invalid_classical_leaf: PathBuf,
        #[arg(long)]
        invalid_post_quantum_leaf: PathBuf,
        #[arg(long)]
        root_crl: PathBuf,
        #[arg(long)]
        intermediate_crl: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long, value_enum)]
        policy: PolicyArgument,
        #[arg(long, value_enum)]
        previous_authentication: Option<AuthenticationLevelArgument>,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Test a pure post-quantum chain at all path positions.
    AnalyzePurePathScope {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-bouncycastle:1.85")]
        image: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        intermediate: PathBuf,
        #[arg(long)]
        leaf: PathBuf,
        #[arg(long)]
        invalid_root: PathBuf,
        #[arg(long)]
        invalid_intermediate: PathBuf,
        #[arg(long)]
        invalid_leaf: PathBuf,
        #[arg(long)]
        root_crl: PathBuf,
        #[arg(long)]
        intermediate_crl: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long, value_enum)]
        policy: PolicyArgument,
        #[arg(long, value_enum)]
        previous_authentication: Option<AuthenticationLevelArgument>,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Build both routes through a cross-signed atomic intermediate and record the selected path.
    AnalyzeCrossSignedPath {
        #[arg(long, default_value = "tests/fixtures/generated-controls")]
        controls: PathBuf,
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-bouncycastle:1.85")]
        image: String,
        #[arg(long)]
        validation_time: String,
        #[arg(long, value_enum)]
        policy: PolicyArgument,
        #[arg(long, value_enum)]
        previous_authentication: Option<AuthenticationLevelArgument>,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Test whether Chameleon delta evidence changes base-certificate TLS acceptance.
    AnalyzeChameleonTls {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-bouncycastle:1.85")]
        image: String,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        issuer: PathBuf,
        #[arg(long)]
        valid_base_certificate: PathBuf,
        #[arg(long)]
        invalid_delta_base_certificate: PathBuf,
        #[arg(long)]
        delta_certificate: PathBuf,
        #[arg(long)]
        base_private_key: PathBuf,
        #[arg(long)]
        delta_private_key: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Test Chameleon base and delta evidence at all path positions.
    AnalyzeChameleonPathScope {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-bouncycastle:1.85")]
        image: String,
        #[arg(long)]
        root_base: PathBuf,
        #[arg(long)]
        intermediate_base: PathBuf,
        #[arg(long)]
        leaf_base: PathBuf,
        #[arg(long)]
        root_delta: PathBuf,
        #[arg(long)]
        intermediate_delta: PathBuf,
        #[arg(long)]
        leaf_delta: PathBuf,
        #[arg(long)]
        invalid_delta_root_base: PathBuf,
        #[arg(long)]
        invalid_delta_intermediate_base: PathBuf,
        #[arg(long)]
        invalid_delta_leaf_base: PathBuf,
        #[arg(long)]
        invalid_base_root: PathBuf,
        #[arg(long)]
        invalid_base_intermediate: PathBuf,
        #[arg(long)]
        invalid_base_leaf: PathBuf,
        #[arg(long)]
        root_base_crl: PathBuf,
        #[arg(long)]
        intermediate_base_crl: PathBuf,
        #[arg(long)]
        root_delta_crl: PathBuf,
        #[arg(long)]
        intermediate_delta_crl: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long, value_enum)]
        policy: PolicyArgument,
        #[arg(long, value_enum)]
        previous_authentication: Option<AuthenticationLevelArgument>,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Test whether Related PQ evidence changes classical-certificate TLS acceptance.
    AnalyzeRelatedTls {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-bouncycastle:1.85")]
        image: String,
        #[arg(long)]
        trust_store: PathBuf,
        #[arg(long)]
        issuer: PathBuf,
        #[arg(long)]
        classical_certificate: PathBuf,
        #[arg(long)]
        invalid_binding_classical_certificate: PathBuf,
        #[arg(long)]
        missing_binding_classical_certificate: PathBuf,
        #[arg(long)]
        post_quantum_certificate: PathBuf,
        #[arg(long)]
        expired_post_quantum_certificate: PathBuf,
        #[arg(long)]
        classical_private_key: PathBuf,
        #[arg(long)]
        post_quantum_private_key: PathBuf,
        #[arg(long)]
        crl: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Test Related certificate pairs at the leaf, intermediate, and trust anchor.
    AnalyzeRelatedPathScope {
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-bouncycastle:1.85")]
        image: String,
        #[arg(long)]
        classical_root: PathBuf,
        #[arg(long)]
        classical_intermediate: PathBuf,
        #[arg(long)]
        classical_leaf: PathBuf,
        #[arg(long)]
        post_quantum_root: PathBuf,
        #[arg(long)]
        post_quantum_intermediate: PathBuf,
        #[arg(long)]
        post_quantum_leaf: PathBuf,
        #[arg(long)]
        invalid_binding_root: PathBuf,
        #[arg(long)]
        invalid_binding_intermediate: PathBuf,
        #[arg(long)]
        invalid_binding_leaf: PathBuf,
        #[arg(long)]
        invalid_classical_root: PathBuf,
        #[arg(long)]
        invalid_classical_intermediate: PathBuf,
        #[arg(long)]
        invalid_classical_leaf: PathBuf,
        #[arg(long)]
        invalid_post_quantum_root: PathBuf,
        #[arg(long)]
        invalid_post_quantum_intermediate: PathBuf,
        #[arg(long)]
        invalid_post_quantum_leaf: PathBuf,
        #[arg(long)]
        classical_root_crl: PathBuf,
        #[arg(long)]
        classical_intermediate_crl: PathBuf,
        #[arg(long)]
        post_quantum_root_crl: PathBuf,
        #[arg(long)]
        post_quantum_intermediate_crl: PathBuf,
        #[arg(long)]
        validation_time: String,
        #[arg(long, value_enum)]
        policy: PolicyArgument,
        #[arg(long, value_enum)]
        previous_authentication: Option<AuthenticationLevelArgument>,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
    },
    /// Run the matrix and controlled variants through the available stacks.
    MatrixAvailable {
        #[arg(long, default_value = "tests/fixtures/paper-v1.0.2")]
        fixtures: PathBuf,
        #[arg(long, default_value = "tests/fixtures/generated-controls")]
        controls: PathBuf,
        #[arg(long, default_value = "hybrid-x509-openssl:4.0.1")]
        openssl_current_image: String,
        #[arg(long, default_value = "hybrid-x509-oqs-provider:0.11.0")]
        openssl_study_image: String,
        #[arg(long, default_value = "hybrid-x509-gnutls:3.8.13")]
        gnutls_current_image: String,
        #[arg(long, default_value = "hybrid-x509-gnutls:3.7.3")]
        gnutls_study_image: String,
        #[arg(long, default_value = "hybrid-x509-go:1.26.4")]
        go_study_image: String,
        #[arg(long, default_value = "hybrid-x509-go:1.26.5")]
        go_current_image: String,
        #[arg(long, default_value = "hybrid-x509-pyca:49.0.0")]
        pyca_study_image: String,
        #[arg(long, default_value = "hybrid-x509-pyca:50.0.0")]
        pyca_current_image: String,
        #[arg(long, default_value = "docker")]
        docker: PathBuf,
        #[arg(long, default_value = "hybrid-x509-bouncycastle:1.84")]
        bouncy_castle_study_image: String,
        #[arg(long, default_value = "hybrid-x509-bouncycastle:1.85")]
        bouncy_castle_current_image: String,
        #[arg(long, default_value = "hybrid-x509-nss:3.98")]
        nss_study_image: String,
        #[arg(long, default_value = "hybrid-x509-nss:3.126")]
        nss_current_image: String,
        #[arg(long, default_value = "hybrid-x509-oqs-provider:0.11.0")]
        oqs_provider_image: String,
        #[arg(long, default_value = "hybrid-x509-wolfssl:5.9.2")]
        wolfssl_image: String,
        #[arg(long)]
        validation_time: String,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_output_bytes: usize,
        #[arg(long)]
        publication: bool,
    },
    /// Verify generated corpus DER values against the published manifest.
    VerifyCorpus {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(long, default_value = "gen.GenValid (BouncyCastle)")]
        generator: String,
        #[arg(long, default_value_t = 1_048_576)]
        input_limit_bytes: usize,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SchemaDocument {
    Request,
    Result,
    Adapter,
    Tls,
    TlsTranscript,
    RelatedOpenSsl,
    CatalystBouncyCastle,
    CatalystPathScope,
    CatalystTls,
    AtomicTls,
    AtomicPathScope,
    PurePathScope,
    CrossSignedPath,
    ChameleonTls,
    ChameleonPathScope,
    RelatedTls,
    RelatedPathScope,
    Matrix,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PolicyArgument {
    P0,
    P1,
    P2,
    P3,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum WolfSslModeArgument {
    Default,
    DualAlgorithm,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BouncyCastleModeArgument {
    Path,
    PathBuilder,
    AlternativeSignature,
    DeltaSignature,
    CrlStatus,
    CertificateSignature,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AuthenticationLevelArgument {
    Classical,
    Hybrid,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RevocationPolicyModeArgument {
    HardFail,
    SoftFail,
    NotRequired,
}

impl From<RevocationPolicyModeArgument> for hybrid_x509_evidence::RevocationPolicyMode {
    fn from(mode: RevocationPolicyModeArgument) -> Self {
        match mode {
            RevocationPolicyModeArgument::HardFail => Self::HardFail,
            RevocationPolicyModeArgument::SoftFail => Self::SoftFail,
            RevocationPolicyModeArgument::NotRequired => Self::NotRequired,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PycaReleaseArgument {
    Study49,
    Current50,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum NssReleaseArgument {
    Study98,
    Current126,
}

impl NssReleaseArgument {
    fn release(self) -> NssRelease {
        match self {
            Self::Study98 => NssRelease::Study98,
            Self::Current126 => NssRelease::Current126,
        }
    }

    fn default_image(self) -> &'static str {
        match self {
            Self::Study98 => "hybrid-x509-nss:3.98",
            Self::Current126 => "hybrid-x509-nss:3.126",
        }
    }
}

impl PycaReleaseArgument {
    fn release(self) -> PycaRelease {
        match self {
            Self::Study49 => PycaRelease::Study49,
            Self::Current50 => PycaRelease::Current50,
        }
    }

    fn default_image(self) -> &'static str {
        match self {
            Self::Study49 => "hybrid-x509-pyca:49.0.0",
            Self::Current50 => "hybrid-x509-pyca:50.0.0",
        }
    }
}

impl From<AuthenticationLevelArgument> for AuthenticationLevel {
    fn from(level: AuthenticationLevelArgument) -> Self {
        match level {
            AuthenticationLevelArgument::Classical => Self::Classical,
            AuthenticationLevelArgument::Hybrid => Self::Hybrid,
        }
    }
}

impl From<WolfSslModeArgument> for WolfSslMode {
    fn from(mode: WolfSslModeArgument) -> Self {
        match mode {
            WolfSslModeArgument::Default => Self::Default,
            WolfSslModeArgument::DualAlgorithm => Self::DualAlgorithm,
        }
    }
}

impl From<BouncyCastleModeArgument> for BouncyCastleMode {
    fn from(mode: BouncyCastleModeArgument) -> Self {
        match mode {
            BouncyCastleModeArgument::Path => Self::Path,
            BouncyCastleModeArgument::PathBuilder => Self::PathBuilder,
            BouncyCastleModeArgument::AlternativeSignature => Self::AlternativeSignature,
            BouncyCastleModeArgument::DeltaSignature => Self::DeltaSignature,
            BouncyCastleModeArgument::CrlStatus => Self::CrlStatus,
            BouncyCastleModeArgument::CertificateSignature => Self::CertificateSignature,
        }
    }
}

impl From<PolicyArgument> for hybrid_x509_evidence::Policy {
    fn from(policy: PolicyArgument) -> Self {
        match policy {
            PolicyArgument::P0 => Self::P0Classical,
            PolicyArgument::P1 => Self::P1OptionalHybrid,
            PolicyArgument::P2 => Self::P2RequiredHybrid,
            PolicyArgument::P3 => Self::P3Continuity,
        }
    }
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let output = match args.command {
        Command::Verify {
            request,
            input_limit_bytes,
        } => {
            let bytes = read_bounded_file(&request, input_limit_bytes)?;
            let request: VerificationRequest = serde_json::from_slice(&bytes)?;
            serde_json::to_value(evaluate(&request)?)?
        }
        Command::Schema {
            document: SchemaDocument::Request,
        } => serde_json::to_value(schemars::schema_for!(VerificationRequest))?,
        Command::Schema {
            document: SchemaDocument::Result,
        } => serde_json::to_value(schemars::schema_for!(VerificationResult))?,
        Command::Schema {
            document: SchemaDocument::Adapter,
        } => serde_json::to_value(schemars::schema_for!(AdapterReport))?,
        Command::Schema {
            document: SchemaDocument::Tls,
        } => serde_json::to_value(schemars::schema_for!(TlsHandshakeEvidence))?,
        Command::Schema {
            document: SchemaDocument::TlsTranscript,
        } => serde_json::to_value(schemars::schema_for!(TlsTranscriptEvidence))?,
        Command::Schema {
            document: SchemaDocument::RelatedOpenSsl,
        } => serde_json::to_value(schemars::schema_for!(RelatedOpenSslReport))?,
        Command::Schema {
            document: SchemaDocument::CatalystBouncyCastle,
        } => serde_json::to_value(schemars::schema_for!(CatalystBouncyCastleReport))?,
        Command::Schema {
            document: SchemaDocument::CatalystPathScope,
        } => serde_json::to_value(schemars::schema_for!(CatalystPathScopeReport))?,
        Command::Schema {
            document: SchemaDocument::CatalystTls,
        } => serde_json::to_value(schemars::schema_for!(CatalystTlsReport))?,
        Command::Schema {
            document: SchemaDocument::AtomicTls,
        } => serde_json::to_value(schemars::schema_for!(AtomicTlsReport))?,
        Command::Schema {
            document: SchemaDocument::AtomicPathScope,
        } => serde_json::to_value(schemars::schema_for!(AtomicPathScopeReport))?,
        Command::Schema {
            document: SchemaDocument::PurePathScope,
        } => serde_json::to_value(schemars::schema_for!(PurePathScopeReport))?,
        Command::Schema {
            document: SchemaDocument::CrossSignedPath,
        } => serde_json::to_value(schemars::schema_for!(CrossSignedPathReport))?,
        Command::Schema {
            document: SchemaDocument::ChameleonTls,
        } => serde_json::to_value(schemars::schema_for!(ChameleonTlsReport))?,
        Command::Schema {
            document: SchemaDocument::ChameleonPathScope,
        } => serde_json::to_value(schemars::schema_for!(ChameleonPathScopeReport))?,
        Command::Schema {
            document: SchemaDocument::RelatedTls,
        } => serde_json::to_value(schemars::schema_for!(RelatedTlsReport))?,
        Command::Schema {
            document: SchemaDocument::RelatedPathScope,
        } => serde_json::to_value(schemars::schema_for!(RelatedPathScopeReport))?,
        Command::Schema {
            document: SchemaDocument::Matrix,
        } => serde_json::to_value(schemars::schema_for!(MatrixReport))?,
        Command::CheckOcsp {
            certificate,
            issuer,
            response,
            validation_time,
            expected_nonce_base64,
            max_age_seconds,
            clock_skew_seconds,
            revocation_mode,
            input_limit_bytes,
        } => serde_json::to_value(check_ocsp_status(
            &certificate,
            &issuer,
            &response,
            &validation_time,
            expected_nonce_base64.as_deref(),
            OcspPolicy {
                max_age: Duration::from_secs(max_age_seconds),
                clock_skew: Duration::from_secs(clock_skew_seconds),
                revocation_mode: revocation_mode.into(),
                delegated_responder_revocation: None,
            },
            input_limit_bytes,
        )?)?,
        Command::MutateCertificateSignature {
            certificate,
            output,
            input_limit_bytes,
        } => {
            let der = read_der(&certificate, PemKind::Certificate, input_limit_bytes)?;
            fs::write(
                &output,
                encode_certificate_pem(&corrupt_outer_signature(&der)?),
            )?;
            serde_json::json!({
                "input": certificate,
                "output": output,
                "mutation": "outer-signature-bit-flip"
            })
        }
        Command::ProbeOpenssl {
            executable,
            trust_store,
            untrusted_chain,
            leaf,
            crl,
            validation_time,
            timeout_seconds,
            max_output_bytes,
        } => {
            let result = verify_openssl(&OpenSslConfig {
                executable,
                trust_store,
                untrusted_chain,
                leaf,
                crl,
                validation_time,
                timeout: Duration::from_secs(timeout_seconds),
                max_output_bytes,
            })?;
            serde_json::to_value(result.report()?)?
        }
        Command::ProbeOpensslTls {
            docker,
            image,
            trust_store,
            intermediate,
            leaf,
            private_key,
            hostname,
            validation_time,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(observe_tls(&OpenSslTlsConfig {
            docker,
            image,
            trust_store,
            intermediate,
            leaf,
            private_key,
            hostname,
            validation_time,
            timeout: Duration::from_secs(timeout_seconds),
            max_output_bytes,
        })?)?,
        Command::ProbeTlsTranscript {
            docker,
            image,
            trust_store,
            intermediate,
            leaf,
            private_key,
            validation_time,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(observe_transcript(&TlsTranscriptConfig {
            docker,
            image,
            trust_store,
            intermediate,
            leaf,
            private_key,
            validation_time,
            timeout: Duration::from_secs(timeout_seconds),
            max_output_bytes,
        })?)?,
        Command::ProbeGnutls {
            executable,
            trust_store,
            untrusted_chain,
            leaf,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(
            verify_gnutls(&GnuTlsConfig {
                executable,
                trust_store,
                untrusted_chain,
                leaf,
                timeout: Duration::from_secs(timeout_seconds),
                max_output_bytes,
            })?
            .report()?,
        )?,
        Command::ProbeGnutlsStudy {
            docker,
            image,
            trust_store,
            intermediate,
            leaf,
            validation_time,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(
            verify_gnutls_study(&GnuTlsStudyConfig {
                docker,
                image,
                trust_store,
                intermediate,
                leaf,
                validation_time,
                timeout: Duration::from_secs(timeout_seconds),
                max_output_bytes,
            })?
            .report()?,
        )?,
        Command::ProbeGoX509 {
            executable,
            trust_store,
            intermediate,
            leaf,
            dns_name,
            validation_time,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(
            verify_go_x509(&GoX509Config {
                executable,
                trust_store,
                intermediate,
                leaf,
                dns_name,
                validation_time,
                timeout: Duration::from_secs(timeout_seconds),
                max_output_bytes,
            })?
            .report()?,
        )?,
        Command::ProbePyca {
            python,
            script,
            trust_store,
            intermediate,
            leaf,
            dns_name,
            validation_time,
            hybrid_extension_oid,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(
            verify_pyca(&PycaConfig {
                python,
                script,
                trust_store,
                intermediate,
                leaf,
                dns_name,
                validation_time,
                hybrid_extension_oid,
                timeout: Duration::from_secs(timeout_seconds),
                max_output_bytes,
            })?
            .report()?,
        )?,
        Command::ProbePycaContainer {
            docker,
            release,
            image,
            trust_store,
            intermediate,
            leaf,
            dns_name,
            validation_time,
            hybrid_extension_oid,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(
            verify_pyca_container(&PycaContainerConfig {
                docker,
                image: image.unwrap_or_else(|| release.default_image().to_owned()),
                release: release.release(),
                trust_store,
                intermediate,
                leaf,
                dns_name,
                validation_time,
                hybrid_extension_oid,
                timeout: Duration::from_secs(timeout_seconds),
                max_output_bytes,
            })?
            .report()?,
        )?,
        Command::ProbeBouncyCastle {
            docker,
            image,
            mode,
            trust_store,
            intermediate,
            leaf,
            validation_time,
            crl,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(
            verify_bouncy_castle(&BouncyCastleConfig {
                docker,
                image,
                trust_store,
                intermediate,
                leaf,
                validation_time,
                timeout: Duration::from_secs(timeout_seconds),
                max_output_bytes,
                mode: mode.into(),
                private_key: None,
                crl,
            })?
            .report()?,
        )?,
        Command::ProbeNss {
            docker,
            release,
            image,
            trust_store,
            intermediate,
            leaf,
            validation_time,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(
            verify_nss(&NssConfig {
                docker,
                image: image.unwrap_or_else(|| release.default_image().to_owned()),
                release: release.release(),
                trust_store,
                intermediate,
                leaf,
                validation_time,
                timeout: Duration::from_secs(timeout_seconds),
                max_output_bytes,
            })?
            .report()?,
        )?,
        Command::ProbeOqsProvider {
            docker,
            image,
            trust_store,
            intermediate,
            leaf,
            validation_time,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(
            verify_oqs_provider(&OqsProviderConfig {
                docker,
                image,
                trust_store,
                intermediate,
                leaf,
                validation_time,
                timeout: Duration::from_secs(timeout_seconds),
                max_output_bytes,
            })?
            .report()?,
        )?,
        Command::ProbeWolfSsl {
            docker,
            image,
            mode,
            scheme,
            trust_store,
            intermediate,
            leaf,
            validation_time,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(
            verify_wolfssl(&WolfSslConfig {
                docker,
                image,
                mode: mode.into(),
                scheme,
                trust_store,
                intermediate,
                leaf,
                validation_time,
                timeout: Duration::from_secs(timeout_seconds),
                max_output_bytes,
            })?
            .report()?,
        )?,
        Command::AnalyzeRelatedOpenssl {
            docker,
            image,
            trust_store,
            issuer,
            classical_certificate,
            post_quantum_certificate,
            expired_post_quantum_certificate,
            invalid_binding_certificate,
            crl,
            validation_time,
            policy,
            previous_authentication,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(analyze_related_openssl(&RelatedOpenSslConfig {
            docker,
            image,
            trust_store,
            issuer,
            classical_certificate,
            post_quantum_certificate,
            expired_post_quantum_certificate,
            invalid_binding_certificate,
            crl,
            validation_time,
            policy: policy.into(),
            previous_authentication: previous_authentication.map(Into::into),
            timeout: Duration::from_secs(timeout_seconds),
            max_output_bytes,
        })?)?,
        Command::AnalyzeCatalystBouncyCastle {
            docker,
            image,
            trust_store,
            issuer,
            valid_certificate,
            invalid_post_quantum_certificate,
            crl,
            root_crl,
            validation_time,
            policy,
            previous_authentication,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(analyze_catalyst_bouncy_castle(
            &CatalystBouncyCastleConfig {
                docker,
                image,
                trust_store,
                issuer,
                valid_certificate,
                invalid_post_quantum_certificate,
                crl,
                root_crl,
                validation_time,
                policy: policy.into(),
                previous_authentication: previous_authentication.map(Into::into),
                timeout: Duration::from_secs(timeout_seconds),
                max_output_bytes,
            },
        )?)?,
        Command::AnalyzeCatalystPathScope {
            docker,
            image,
            root,
            intermediate,
            leaf,
            invalid_alternative_root,
            invalid_alternative_intermediate,
            invalid_alternative_leaf,
            root_crl,
            intermediate_crl,
            validation_time,
            policy,
            previous_authentication,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(analyze_catalyst_path_scope(&CatalystPathScopeConfig {
            docker,
            image,
            root,
            intermediate,
            leaf,
            invalid_alternative_root,
            invalid_alternative_intermediate,
            invalid_alternative_leaf,
            root_crl,
            intermediate_crl,
            validation_time,
            policy: policy.into(),
            previous_authentication: previous_authentication.map(Into::into),
            timeout: Duration::from_secs(timeout_seconds),
            max_output_bytes,
        })?)?,
        Command::AnalyzeCatalystTls {
            docker,
            openssl_image,
            bouncy_castle_image,
            trust_store,
            issuer,
            valid_certificate,
            invalid_post_quantum_certificate,
            private_key,
            crl,
            hostname,
            validation_time,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(analyze_catalyst_tls(&CatalystTlsConfig {
            docker,
            openssl_image,
            bouncy_castle_image,
            trust_store,
            issuer,
            valid_certificate,
            invalid_post_quantum_certificate,
            private_key,
            crl,
            hostname,
            validation_time,
            timeout: Duration::from_secs(timeout_seconds),
            max_output_bytes,
        })?)?,
        Command::AnalyzeAtomicTls {
            docker,
            image,
            trust_store,
            issuer,
            valid_certificate,
            invalid_post_quantum_certificate,
            private_key,
            validation_time,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(analyze_atomic_tls(&AtomicTlsConfig {
            docker,
            image,
            trust_store,
            issuer,
            valid_certificate,
            invalid_post_quantum_certificate,
            private_key,
            validation_time,
            timeout: Duration::from_secs(timeout_seconds),
            max_output_bytes,
        })?)?,
        Command::AnalyzeAtomicPathScope {
            docker,
            image,
            root,
            intermediate,
            leaf,
            invalid_classical_root,
            invalid_post_quantum_root,
            invalid_classical_intermediate,
            invalid_post_quantum_intermediate,
            invalid_classical_leaf,
            invalid_post_quantum_leaf,
            root_crl,
            intermediate_crl,
            validation_time,
            policy,
            previous_authentication,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(analyze_atomic_path_scope(&AtomicPathScopeConfig {
            docker,
            image,
            root,
            intermediate,
            leaf,
            invalid_classical_root,
            invalid_post_quantum_root,
            invalid_classical_intermediate,
            invalid_post_quantum_intermediate,
            invalid_classical_leaf,
            invalid_post_quantum_leaf,
            root_crl,
            intermediate_crl,
            validation_time,
            policy: policy.into(),
            previous_authentication: previous_authentication.map(Into::into),
            timeout: Duration::from_secs(timeout_seconds),
            max_output_bytes,
        })?)?,
        Command::AnalyzePurePathScope {
            docker,
            image,
            root,
            intermediate,
            leaf,
            invalid_root,
            invalid_intermediate,
            invalid_leaf,
            root_crl,
            intermediate_crl,
            validation_time,
            policy,
            previous_authentication,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(analyze_pure_path_scope(&PurePathScopeConfig {
            docker,
            image,
            root,
            intermediate,
            leaf,
            invalid_root,
            invalid_intermediate,
            invalid_leaf,
            root_crl,
            intermediate_crl,
            validation_time,
            policy: policy.into(),
            previous_authentication: previous_authentication.map(Into::into),
            timeout: Duration::from_secs(timeout_seconds),
            max_output_bytes,
        })?)?,
        Command::AnalyzeCrossSignedPath {
            controls,
            docker,
            image,
            validation_time,
            policy,
            previous_authentication,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(analyze_cross_signed_path(&CrossSignedPathConfig {
            controls,
            docker,
            image,
            validation_time,
            policy: policy.into(),
            previous_authentication: previous_authentication.map(Into::into),
            timeout: Duration::from_secs(timeout_seconds),
            max_output_bytes,
        })?)?,
        Command::AnalyzeChameleonTls {
            docker,
            image,
            trust_store,
            issuer,
            valid_base_certificate,
            invalid_delta_base_certificate,
            delta_certificate,
            base_private_key,
            delta_private_key,
            validation_time,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(analyze_chameleon_tls(&ChameleonTlsConfig {
            docker,
            image,
            trust_store,
            issuer,
            valid_base_certificate,
            invalid_delta_base_certificate,
            delta_certificate,
            base_private_key,
            delta_private_key,
            validation_time,
            timeout: Duration::from_secs(timeout_seconds),
            max_output_bytes,
        })?)?,
        Command::AnalyzeChameleonPathScope {
            docker,
            image,
            root_base,
            intermediate_base,
            leaf_base,
            root_delta,
            intermediate_delta,
            leaf_delta,
            invalid_delta_root_base,
            invalid_delta_intermediate_base,
            invalid_delta_leaf_base,
            invalid_base_root,
            invalid_base_intermediate,
            invalid_base_leaf,
            root_base_crl,
            intermediate_base_crl,
            root_delta_crl,
            intermediate_delta_crl,
            validation_time,
            policy,
            previous_authentication,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(analyze_chameleon_path_scope(&ChameleonPathScopeConfig {
            docker,
            image,
            root_base,
            intermediate_base,
            leaf_base,
            root_delta,
            intermediate_delta,
            leaf_delta,
            invalid_delta_root_base,
            invalid_delta_intermediate_base,
            invalid_delta_leaf_base,
            invalid_base_root,
            invalid_base_intermediate,
            invalid_base_leaf,
            root_base_crl,
            intermediate_base_crl,
            root_delta_crl,
            intermediate_delta_crl,
            validation_time,
            policy: policy.into(),
            previous_authentication: previous_authentication.map(Into::into),
            timeout: Duration::from_secs(timeout_seconds),
            max_output_bytes,
        })?)?,
        Command::AnalyzeRelatedTls {
            docker,
            image,
            trust_store,
            issuer,
            classical_certificate,
            invalid_binding_classical_certificate,
            missing_binding_classical_certificate,
            post_quantum_certificate,
            expired_post_quantum_certificate,
            classical_private_key,
            post_quantum_private_key,
            crl,
            validation_time,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(analyze_related_tls(&RelatedTlsConfig {
            docker,
            image,
            trust_store,
            issuer,
            classical_certificate,
            invalid_binding_classical_certificate,
            missing_binding_classical_certificate,
            post_quantum_certificate,
            expired_post_quantum_certificate,
            classical_private_key,
            post_quantum_private_key,
            crl,
            validation_time,
            timeout: Duration::from_secs(timeout_seconds),
            max_output_bytes,
        })?)?,
        Command::AnalyzeRelatedPathScope {
            docker,
            image,
            classical_root,
            classical_intermediate,
            classical_leaf,
            post_quantum_root,
            post_quantum_intermediate,
            post_quantum_leaf,
            invalid_binding_root,
            invalid_binding_intermediate,
            invalid_binding_leaf,
            invalid_classical_root,
            invalid_classical_intermediate,
            invalid_classical_leaf,
            invalid_post_quantum_root,
            invalid_post_quantum_intermediate,
            invalid_post_quantum_leaf,
            classical_root_crl,
            classical_intermediate_crl,
            post_quantum_root_crl,
            post_quantum_intermediate_crl,
            validation_time,
            policy,
            previous_authentication,
            timeout_seconds,
            max_output_bytes,
        } => serde_json::to_value(analyze_related_path_scope(&RelatedPathScopeConfig {
            docker,
            image,
            classical_root,
            classical_intermediate,
            classical_leaf,
            post_quantum_root,
            post_quantum_intermediate,
            post_quantum_leaf,
            invalid_binding_root,
            invalid_binding_intermediate,
            invalid_binding_leaf,
            invalid_classical_root,
            invalid_classical_intermediate,
            invalid_classical_leaf,
            invalid_post_quantum_root,
            invalid_post_quantum_intermediate,
            invalid_post_quantum_leaf,
            classical_root_crl,
            classical_intermediate_crl,
            post_quantum_root_crl,
            post_quantum_intermediate_crl,
            validation_time,
            policy: policy.into(),
            previous_authentication: previous_authentication.map(Into::into),
            timeout: Duration::from_secs(timeout_seconds),
            max_output_bytes,
        })?)?,
        Command::MatrixAvailable {
            fixtures,
            controls,
            openssl_current_image,
            openssl_study_image,
            gnutls_current_image,
            gnutls_study_image,
            go_study_image,
            go_current_image,
            pyca_study_image,
            pyca_current_image,
            docker,
            bouncy_castle_study_image,
            bouncy_castle_current_image,
            nss_study_image,
            nss_current_image,
            oqs_provider_image,
            wolfssl_image,
            validation_time,
            timeout_seconds,
            max_output_bytes,
            publication,
        } => serde_json::to_value(run_available_matrix(&AvailableMatrixConfig {
            fixtures,
            controls,
            openssl_current_image,
            openssl_study_image,
            gnutls_current_image,
            gnutls_study_image,
            go_study_image,
            go_current_image,
            pyca_study_image,
            pyca_current_image,
            docker,
            bouncy_castle_study_image,
            bouncy_castle_current_image,
            nss_study_image,
            nss_current_image,
            oqs_provider_image,
            wolfssl_image,
            validation_time,
            timeout: Duration::from_secs(timeout_seconds),
            max_output_bytes,
            publication,
        })?)?,
        Command::VerifyCorpus {
            manifest,
            root,
            generator,
            input_limit_bytes,
        } => serde_json::to_value(verify_corpus(
            &manifest,
            &root,
            &generator,
            input_limit_bytes,
        )?)?,
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &output)?;
    println!();
    Ok(())
}
