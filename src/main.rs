//
// src/main.rs -- Generate self-signed root CA, web servers certs and keys
//
// Copyright (c) 2024 Jeff Garzik
//
// This file is part of the self-signed-cert software project covered under
// the MIT License.  For the full license text, please see the LICENSE
// file in the root directory of this project.
// SPDX-License-Identifier: MIT

// Import necessary modules and types from the clap and openssl crates.
use clap::{Parser, ValueEnum};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    ec::{Asn1Flag, EcGroup, EcKey},
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    stack::Stack,
    x509::{X509, X509Builder, X509Extension, X509NameBuilder, X509Req, X509ReqBuilder},
};
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Everything that can go wrong, with enough context to act on.
///
/// The previous `Box<dyn Error>` surfaced through `Termination`, which prints
/// the Debug representation -- an `Os { code: 17, .. }` struct or a raw
/// openssl `ErrorStack`, naming neither the step nor the file.
#[derive(Debug)]
enum AppError {
    /// Contradictory or invalid command line arguments
    Config(String),
    /// An openssl operation failed during a named step
    Crypto(&'static str, ErrorStack),
    /// A file could not be written
    Io(PathBuf, std::io::Error),
    /// The output already exists and --force was not given
    Exists(PathBuf),
    /// The zip archive could not be built
    Zip(PathBuf, zip::result::ZipError),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Config(msg) => write!(f, "{msg}"),
            AppError::Crypto(step, err) => {
                write!(f, "could not {step}: ")?;
                match err.errors().first() {
                    Some(first) => write!(f, "{first}"),
                    None => write!(f, "unknown openssl failure"),
                }
            }
            AppError::Io(path, err) => write!(f, "could not write {}: {err}", path.display()),
            AppError::Exists(path) => write!(
                f,
                "{} already exists; pass --force to overwrite it, \
                 or -o to write somewhere else",
                path.display()
            ),
            AppError::Zip(path, err) => {
                write!(f, "could not build archive {}: {err}", path.display())
            }
        }
    }
}

impl std::error::Error for AppError {}

/// Attach a step name to an openssl failure
trait CryptoContext<T> {
    fn during(self, step: &'static str) -> Result<T, AppError>;
}

impl<T> CryptoContext<T> for Result<T, ErrorStack> {
    fn during(self, step: &'static str) -> Result<T, AppError> {
        self.map_err(|e| AppError::Crypto(step, e))
    }
}

const MODE_NORMAL: u32 = 0o444;
const MODE_KEY: u32 = 0o400;

/// Certificates are backdated by this much so that a client whose clock trails
/// the generating host still accepts a freshly minted certificate.
const CLOCK_SKEW_SECS: i64 = 3600;

/// Apple platforms reject a TLS server certificate issued on or after
/// 2019-07-01 whose validity exceeds 825 days, even under a privately added
/// root.  Warn rather than fail: the tool is used for more than browser tests.
const MAX_LEAF_DAYS: u32 = 825;

/// Seconds since the Unix epoch
fn unix_now() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System clock is before the Unix epoch");
    i64::try_from(now.as_secs()).expect("System clock beyond the range of time_t")
}

/// The validity window for a certificate, as (`notBefore`, `notAfter`).
///
/// Both bounds come from a single `base` timestamp read once per run, so two
/// certificates asked for the same number of days get byte-identical times
/// rather than whatever two independent clock reads happened to produce.
/// `Asn1Time::days_from_now` cannot express a time in the past, so the
/// backdated `notBefore` goes through the Unix epoch instead.
fn validity_window(base: i64, days: u32) -> Result<(Asn1Time, Asn1Time), ErrorStack> {
    let not_before = Asn1Time::from_unix(base - CLOCK_SKEW_SECS)?;
    let not_after = Asn1Time::from_unix(base + i64::from(days) * 86_400)?;
    Ok((not_before, not_after))
}

/// A fresh 128-bit random serial number.
///
/// RFC 5280 4.1.2.2 requires a positive integer; CA/Browser Forum baseline
/// requirement 7.1 requires at least 64 bits of CSPRNG output.
fn random_serial() -> Result<Asn1Integer, ErrorStack> {
    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
    serial.to_asn1_integer()
}

/// Key algorithm for both the root CA and the server certificate.
///
/// The default follows Mozilla's "Modern" server-side TLS profile, which is
/// ECDSA P-256/P-384 only.  RSA remains available for older peers and for
/// compliance regimes that still mandate it; note that no RSA key size offers
/// any resistance to a quantum adversary, so a larger modulus is not a
/// post-quantum hedge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum KeyAlg {
    /// NIST P-256, signed with SHA-256
    EcdsaP256,
    /// NIST P-384, signed with SHA-384
    EcdsaP384,
    /// Edwards-curve DSA, no separate digest
    Ed25519,
    /// RSA at --rsa-bits, signed with SHA-256
    Rsa,
}

/// Fully resolved key settings
struct KeyConfig {
    alg: KeyAlg,
    rsa_bits: u32,
}

impl KeyConfig {
    /// Human-readable name for the summary
    fn describe(&self) -> String {
        match self.alg {
            KeyAlg::EcdsaP256 => String::from("ECDSA P-256"),
            KeyAlg::EcdsaP384 => String::from("ECDSA P-384"),
            KeyAlg::Ed25519 => String::from("Ed25519"),
            KeyAlg::Rsa => format!("RSA {} bit", self.rsa_bits),
        }
    }
}

/// Default RSA modulus size when `--key-alg rsa` is selected without `--rsa-bits`
const DEFAULT_RSA_BITS: u32 = 2048;

/// Parse and validate RSA key size
fn parse_rsa_bits(s: &str) -> Result<u32, String> {
    let bits: u32 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid number"))?;
    match bits {
        2048 | 3072 | 4096 => Ok(bits),
        _ => Err(String::from("RSA bits must be 2048, 3072, or 4096")),
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Output directory for PEM files
    #[arg(short, long, default_value = ".")]
    out_dir: String,

    /// Bundle all output into a single zip archive at this path
    #[arg(long)]
    out_zip: Option<String>,

    /// Overwrite existing output files instead of refusing to run
    #[arg(long)]
    force: bool,

    /// Do not print the summary of what was generated
    #[arg(short, long)]
    quiet: bool,

    /// root CA private key output path
    ///
    /// Pass an empty string to suppress this file.
    #[arg(long, default_value = "ca-key.pem")]
    ca_key_out: String,

    /// root CA cert output path
    ///
    /// Pass an empty string to suppress this file.
    #[arg(long, default_value = "ca-cert.pem")]
    ca_cert_out: String,

    /// server private key output path
    ///
    /// Pass an empty string to suppress this file.
    #[arg(long, default_value = "server-key.pem")]
    key_out: String,

    /// server cert signing request output path
    #[arg(long)]
    csr_out: Option<String>,

    /// server cert output path
    ///
    /// Pass an empty string to suppress this file.
    #[arg(long, default_value = "server-cert.pem")]
    cert_out: String,

    /// Key algorithm for both certificates [default: ecdsa-p256]
    #[arg(long, value_enum)]
    key_alg: Option<KeyAlg>,

    /// RSA key size in bits: 2048, 3072 or 4096 [default: 2048]
    ///
    /// Implies `--key-alg rsa` when given on its own.
    #[arg(long, value_parser = parse_rsa_bits)]
    rsa_bits: Option<u32>,

    /// Subject alternative name for the server cert; repeatable.
    ///
    /// IP addresses and DNS names are told apart automatically.
    /// Defaults to localhost plus the IPv4 and IPv6 loopback addresses.
    #[arg(long)]
    san: Vec<String>,

    /// Server cert: common name, at most 64 characters [default: localhost]
    ///
    /// Modern TLS clients match on the subject alternative name, not this
    /// field; it is copied into the SAN so that it still has an effect.
    #[arg(long)]
    srv_common_name: Option<String>,

    /// Server cert: country code
    #[arg(long, default_value = "US")]
    srv_country: String,

    /// Server cert: state or province
    #[arg(long)]
    srv_state: Option<String>,

    /// Server cert: city or locality
    #[arg(long)]
    srv_city: Option<String>,

    /// Server cert: organization
    #[arg(long)]
    srv_org: Option<String>,

    /// Server cert: days until expiration
    #[arg(long, default_value_t = 397)]
    srv_expire: u32,

    /// CA cert: common name, at most 64 characters
    /// [default: self-signed-cert local CA]
    #[arg(long)]
    ca_common_name: Option<String>,

    /// CA cert: country code
    #[arg(long, default_value = "US")]
    ca_country: String,

    /// CA cert: state or province
    #[arg(long)]
    ca_state: Option<String>,

    /// CA cert: city or locality
    #[arg(long)]
    ca_city: Option<String>,

    /// CA cert: organization
    #[arg(long)]
    ca_org: Option<String>,

    /// CA cert: days until expiration
    #[arg(long, default_value_t = 3650)]
    ca_expire: u32,

    /// common name: Default set for both CA and server certs.
    #[arg(long)]
    common_name: Option<String>,

    /// country code: Default set for both CA and server certs.
    #[arg(long)]
    country: Option<String>,

    /// state or province: Default set for both CA and server certs.
    #[arg(long)]
    state: Option<String>,

    /// city or locality: Default set for both CA and server certs.
    #[arg(long)]
    city: Option<String>,

    /// organization: Default set for both CA and server certs.
    #[arg(long)]
    org: Option<String>,

    /// expire days:  Default set for both CA and server certs.
    #[arg(long)]
    expire: Option<u32>,
}

struct FileOutput {
    /// Full path the file is written to on disk
    path: PathBuf,
    /// Bare file name, used as the entry name inside a zip archive
    name: String,
    /// Human-readable description, for the summary
    label: &'static str,
    data: Vec<u8>,
    is_key: bool,
}

impl FileOutput {
    fn mode(&self) -> u32 {
        if self.is_key { MODE_KEY } else { MODE_NORMAL }
    }
}

/// Process CLI args that assign two settings simultaneously
fn swizzle_args(args: &mut Args) {
    if let Some(txt) = &args.common_name {
        args.ca_common_name = Some(txt.clone());
        args.srv_common_name = Some(txt.clone());
    }
    if let Some(txt) = &args.org {
        args.ca_org = Some(txt.clone());
        args.srv_org = Some(txt.clone());
    }
    if let Some(txt) = &args.country {
        args.ca_country = txt.clone();
        args.srv_country = txt.clone();
    }
    if let Some(txt) = &args.state {
        args.ca_state = Some(txt.clone());
        args.srv_state = Some(txt.clone());
    }
    if let Some(txt) = &args.city {
        args.ca_city = Some(txt.clone());
        args.srv_city = Some(txt.clone());
    }
    if let Some(val) = &args.expire {
        args.ca_expire = *val;
        args.srv_expire = *val;
    }
}

/// Upper bounds on the distinguished-name attributes this tool emits, from
/// RFC 5280 Appendix A.  OpenSSL enforces them inside `append_entry_by_text`,
/// but only as a raw ASN.1 error naming no flag, so check them up front.
const UB_COUNTRY: usize = 2;
const UB_COMMON_NAME: usize = 64;
const UB_ORGANIZATION_NAME: usize = 64;
const UB_STATE_NAME: usize = 128;
const UB_LOCALITY_NAME: usize = 128;

/// Reject a distinguished-name value that OpenSSL would refuse to encode
fn check_dn_field(flag: &str, value: &str, max: usize) -> Result<(), AppError> {
    if value.is_empty() {
        return Err(AppError::Config(format!("{flag} must not be empty")));
    }

    let len = value.chars().count();
    if len > max {
        return Err(AppError::Config(format!(
            "{flag} must be at most {max} characters, got {len}"
        )));
    }

    Ok(())
}

/// Reject an output path that is not a plain file name.
///
/// Archive entries are bare names by contract, so a value carrying a path
/// separator would produce a nested entry -- or, with `..`, one that escapes
/// the extraction directory (zip-slip).  Loose output belongs under
/// `--out-dir` for the same reason.  An empty value is the documented way to
/// suppress an artifact and is left alone.
fn check_output_name(flag: &str, value: &str) -> Result<(), AppError> {
    if value.is_empty() {
        return Ok(());
    }

    if value.contains('/') || value.contains('\\') {
        return Err(AppError::Config(format!(
            "{flag} must be a plain file name without path separators; \
             use --out-dir to choose where files are written"
        )));
    }

    if value == "." || value == ".." {
        return Err(AppError::Config(format!(
            "{flag} must be a file name, got {value:?}"
        )));
    }

    Ok(())
}

/// Validate every user-supplied name.
///
/// Deliberately called *before* `swizzle_args`, so an error names the flag the
/// user actually typed rather than the `--srv-*` / `--ca-*` pair it expands
/// into.
fn validate_args(args: &Args) -> Result<(), AppError> {
    let optional = [
        ("--common-name", &args.common_name, UB_COMMON_NAME),
        ("--country", &args.country, UB_COUNTRY),
        ("--state", &args.state, UB_STATE_NAME),
        ("--city", &args.city, UB_LOCALITY_NAME),
        ("--org", &args.org, UB_ORGANIZATION_NAME),
        ("--srv-common-name", &args.srv_common_name, UB_COMMON_NAME),
        ("--srv-state", &args.srv_state, UB_STATE_NAME),
        ("--srv-city", &args.srv_city, UB_LOCALITY_NAME),
        ("--srv-org", &args.srv_org, UB_ORGANIZATION_NAME),
        ("--ca-common-name", &args.ca_common_name, UB_COMMON_NAME),
        ("--ca-state", &args.ca_state, UB_STATE_NAME),
        ("--ca-city", &args.ca_city, UB_LOCALITY_NAME),
        ("--ca-org", &args.ca_org, UB_ORGANIZATION_NAME),
    ];
    for (flag, value, max) in optional {
        if let Some(text) = value {
            check_dn_field(flag, text, max)?;
        }
    }

    check_dn_field("--srv-country", &args.srv_country, UB_COUNTRY)?;
    check_dn_field("--ca-country", &args.ca_country, UB_COUNTRY)?;

    for value in &args.san {
        if value.is_empty() {
            return Err(AppError::Config(String::from("--san must not be empty")));
        }
    }

    check_output_name("--ca-key-out", &args.ca_key_out)?;
    check_output_name("--ca-cert-out", &args.ca_cert_out)?;
    check_output_name("--key-out", &args.key_out)?;
    check_output_name("--cert-out", &args.cert_out)?;
    if let Some(csr_out) = &args.csr_out {
        check_output_name("--csr-out", csr_out)?;
    }

    Ok(())
}

/// Default CA common name.  Not a host name: the CA never identifies a service.
const DEFAULT_CA_COMMON_NAME: &str = "self-signed-cert local CA";

/// One subject alternative name, already classified
enum SanEntry {
    Dns(String),
    Ip(IpAddr),
}

impl SanEntry {
    /// Classify a user-supplied name.  Anything that parses as an address is
    /// an iPAddress; everything else is a dNSName.
    fn parse(value: &str) -> Self {
        match value.parse::<IpAddr>() {
            Ok(ip) => SanEntry::Ip(ip),
            Err(_) => SanEntry::Dns(String::from(value)),
        }
    }

    /// The form the value takes in the certificate
    fn as_text(&self) -> String {
        match self {
            SanEntry::Dns(name) => name.clone(),
            SanEntry::Ip(ip) => ip.to_string(),
        }
    }
}

/// The names the server certificate will attest to
struct Identity {
    /// `None` when no name short enough for the common-name bound was available
    common_name: Option<String>,
    sans: Vec<SanEntry>,
}

/// Work out the server certificate's identity from the CLI arguments.
///
/// With nothing specified, cover every way a test client reaches a local
/// server: by name, over IPv4, and over IPv6.
fn resolve_identity(args: &Args) -> Identity {
    let mut sans: Vec<SanEntry> = args.san.iter().map(|s| SanEntry::parse(s)).collect();

    if sans.is_empty() && args.srv_common_name.is_none() {
        return Identity {
            common_name: Some(String::from("localhost")),
            sans: vec![
                SanEntry::Dns(String::from("localhost")),
                SanEntry::Ip(IpAddr::from([127, 0, 0, 1])),
                SanEntry::Ip(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])),
            ],
        };
    }

    // RFC 9525: the common name is not matched by clients, so whatever the
    // user asked for there must also appear among the SANs to have an effect.
    let common_name = if let Some(name) = &args.srv_common_name {
        // Already length-checked by validate_args
        if !sans.iter().any(|e| e.as_text() == *name) {
            sans.push(SanEntry::parse(name));
        }
        Some(name.clone())
    } else {
        // Derived from a SAN, which carries no such bound.  A name too long
        // for the subject is dropped rather than fatal: RFC 9525 clients match
        // on the SAN, which still carries it.
        let derived = sans[0].as_text();
        if derived.chars().count() > UB_COMMON_NAME {
            eprintln!(
                "note: subject common name omitted; {derived:?} exceeds the \
                 {UB_COMMON_NAME}-character limit, and clients match on the \
                 subject alternative name regardless"
            );
            None
        } else {
            Some(derived)
        }
    };

    Identity { common_name, sans }
}

/// Build the subjectAltName extension for a set of names
fn build_san_extension(
    sans: &[SanEntry],
    ctx: &openssl::x509::X509v3Context<'_>,
) -> Result<X509Extension, ErrorStack> {
    let mut ext = openssl::x509::extension::SubjectAlternativeName::new();
    for entry in sans {
        match entry {
            SanEntry::Dns(name) => ext.dns(name),
            SanEntry::Ip(ip) => ext.ip(&ip.to_string()),
        };
    }
    ext.build(ctx)
}

/// Warn about validity periods that produce certificates clients will reject
fn warn_about_validity(args: &Args) {
    if args.srv_expire > MAX_LEAF_DAYS {
        eprintln!(
            "warning: server cert validity of {} days exceeds {MAX_LEAF_DAYS} days; \
             Apple platforms reject privately-rooted TLS server certificates \
             beyond that limit",
            args.srv_expire
        );
    }
    // Strictly greater: equal day counts now yield an identical notAfter, so
    // the leaf does not outlive the CA -- and is useless past that point anyway.
    if args.srv_expire > args.ca_expire {
        eprintln!(
            "warning: server cert ({} days) outlives the CA ({} days); \
             the chain will stop verifying when the CA expires",
            args.srv_expire, args.ca_expire
        );
    }
}

/// Resolve the key algorithm and size from the CLI arguments.
///
/// `--rsa-bits` on its own selects RSA, so scripts predating `--key-alg`
/// keep working unchanged.
fn resolve_key_config(args: &Args) -> Result<KeyConfig, String> {
    let alg = match (args.key_alg, args.rsa_bits) {
        (Some(alg), _) => alg,
        (None, Some(_)) => KeyAlg::Rsa,
        (None, None) => KeyAlg::EcdsaP256,
    };

    if args.rsa_bits.is_some() && alg != KeyAlg::Rsa {
        return Err(String::from(
            "--rsa-bits applies only to RSA keys; drop it or pass --key-alg rsa",
        ));
    }

    Ok(KeyConfig {
        alg,
        rsa_bits: args.rsa_bits.unwrap_or(DEFAULT_RSA_BITS),
    })
}

/// The digest a certificate signed by this key algorithm should use.
///
/// `EdDSA` signs the message directly, so openssl requires a null digest there.
fn sig_digest(alg: KeyAlg) -> MessageDigest {
    match alg {
        KeyAlg::EcdsaP384 => MessageDigest::sha384(),
        KeyAlg::Ed25519 => MessageDigest::null(),
        KeyAlg::EcdsaP256 | KeyAlg::Rsa => MessageDigest::sha256(),
    }
}

/// Generate a fresh private key
fn generate_private_key(cfg: &KeyConfig) -> Result<PKey<Private>, ErrorStack> {
    match cfg.alg {
        KeyAlg::EcdsaP256 => generate_ec_key(Nid::X9_62_PRIME256V1),
        KeyAlg::EcdsaP384 => generate_ec_key(Nid::SECP384R1),
        KeyAlg::Ed25519 => PKey::generate_ed25519(),
        KeyAlg::Rsa => PKey::from_rsa(Rsa::generate(cfg.rsa_bits)?),
    }
}

/// Generate an EC key on a named curve.
///
/// The `NAMED_CURVE` flag matters: without it the key is serialized with
/// explicit curve parameters, which a number of TLS stacks reject.
fn generate_ec_key(curve: Nid) -> Result<PKey<Private>, ErrorStack> {
    let mut group = EcGroup::from_curve_name(curve)?;
    group.set_asn1_flag(Asn1Flag::NAMED_CURVE);
    PKey::from_ec_key(EcKey::generate(&group)?)
}

/// Create root CA certificate, given root CA private key
fn create_root_ca_certificate(
    args: &Args,
    key_cfg: &KeyConfig,
    base_time: i64,
    pkey: &PKey<Private>,
) -> Result<X509, ErrorStack> {
    // Build the subject and issuer names.
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("C", &args.ca_country)?;
    if let Some(txt) = args.ca_state.clone() {
        name_builder.append_entry_by_text("ST", &txt)?;
    }
    if let Some(txt) = args.ca_city.clone() {
        name_builder.append_entry_by_text("L", &txt)?;
    }
    if let Some(txt) = args.ca_org.clone() {
        name_builder.append_entry_by_text("O", &txt)?;
    }
    name_builder.append_entry_by_text(
        "CN",
        args.ca_common_name
            .as_deref()
            .unwrap_or(DEFAULT_CA_COMMON_NAME),
    )?;
    let name = name_builder.build();

    // Build base certificate settings
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(pkey)?;

    // Set validity times for the certificate.
    let (not_before, not_after) = validity_window(base_time, args.ca_expire)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Extension: subjectKeyIdentifier
    builder.append_extension(
        openssl::x509::extension::SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(None, None))?,
    )?;

    // Extension: authorityKeyIdentifier
    builder.append_extension(
        openssl::x509::extension::AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&builder.x509v3_context(None, None))?,
    )?;

    // Extension: basicConstraints
    // pathlen:0 -- this CA signs end-entity certificates only, never
    // intermediates.
    builder.append_extension(
        openssl::x509::extension::BasicConstraints::new()
            .critical()
            .ca()
            .pathlen(0)
            .build()?,
    )?;

    // Extension: keyUsage (required for CA certificates per RFC 5280)
    builder.append_extension(
        openssl::x509::extension::KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    // Generate a serial number for the certificate.
    let serial = random_serial()?;
    builder.set_serial_number(&serial)?;

    builder.sign(pkey, sig_digest(key_cfg.alg))?;
    let certificate = builder.build();

    Ok(certificate)
}

/// Generate TLS server cert signing request
fn generate_web_server_csr(
    args: &Args,
    identity: &Identity,
    key_cfg: &KeyConfig,
    server_key: &PKey<Private>,
) -> Result<X509Req, ErrorStack> {
    // Create a new certificate signing request (CSR) builder.
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(server_key)?;

    // Build the subject name.
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("C", &args.srv_country)?;
    if let Some(txt) = args.srv_state.clone() {
        name_builder.append_entry_by_text("ST", &txt)?;
    }
    if let Some(txt) = args.srv_city.clone() {
        name_builder.append_entry_by_text("L", &txt)?;
    }
    if let Some(txt) = args.srv_org.clone() {
        name_builder.append_entry_by_text("O", &txt)?;
    }
    if let Some(common_name) = &identity.common_name {
        name_builder.append_entry_by_text("CN", common_name)?;
    }
    let name = name_builder.build();

    req_builder.set_subject_name(&name)?;

    // Request the subject alternative names.  Without this the CSR carries no
    // identity at all, making it useless to anyone re-signing it elsewhere.
    let mut extensions: Stack<X509Extension> = Stack::new()?;
    extensions.push(build_san_extension(
        &identity.sans,
        &req_builder.x509v3_context(None),
    )?)?;
    req_builder.add_extensions(&extensions)?;

    // Sign the CSR with the server's private key
    req_builder.sign(server_key, sig_digest(key_cfg.alg))?;

    // Return the signed CSR
    let csr = req_builder.build();
    Ok(csr)
}

/// Root CA signs TLS server's cert request, creating final server cert
fn sign_server_csr(
    args: &Args,
    identity: &Identity,
    key_cfg: &KeyConfig,
    base_time: i64,
    server_csr: &X509Req,
    ca_cert: &X509,
    ca_pkey: &PKey<Private>,
) -> Result<X509, ErrorStack> {
    let mut builder = openssl::x509::X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(server_csr.subject_name())?;
    builder.set_issuer_name(ca_cert.subject_name())?;

    let pubkey = server_csr.public_key()?;
    builder.set_pubkey(&*pubkey)?;

    // Every certificate needs its own serial; without this the leaf inherits
    // the X509Builder default of 0, which RFC 5280 forbids.
    let serial = random_serial()?;
    builder.set_serial_number(&serial)?;

    // Set validity, from the same base instant as the CA
    let (not_before, not_after) = validity_window(base_time, args.srv_expire)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Extension: authorityKeyIdentifier
    builder.append_extension(
        openssl::x509::extension::AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&builder.x509v3_context(Some(ca_cert), None))?,
    )?;

    // Extension: basicConstraints
    let ext_basic = openssl::x509::extension::BasicConstraints::new().build()?;
    builder.append_extension(ext_basic)?;

    // Extension: keyUsage (marked critical per RFC 5280)
    //
    // CA/Browser Forum baseline requirement 7.1.2.7.11: an RSA subscriber
    // certificate carries digitalSignature and/or keyEncipherment.
    // dataEncipherment and nonRepudiation have no role in TLS server
    // authentication.
    // keyEncipherment only applies to RSA: an EC or Edwards key never
    // transports a session key.
    let mut key_usage = openssl::x509::extension::KeyUsage::new();
    key_usage.critical().digital_signature();
    if key_cfg.alg == KeyAlg::Rsa {
        key_usage.key_encipherment();
    }
    builder.append_extension(key_usage.build()?)?;

    // Extension: extendedKeyUsage (required by modern TLS validators)
    builder.append_extension(
        openssl::x509::extension::ExtendedKeyUsage::new()
            .server_auth()
            .build()?,
    )?;

    // Extension: subjectAltName
    builder.append_extension(build_san_extension(
        &identity.sans,
        &builder.x509v3_context(Some(ca_cert), None),
    )?)?;

    // Extension: subjectKeyIdentifier
    builder.append_extension(
        openssl::x509::extension::SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(Some(ca_cert), None))?,
    )?;

    // Sign the certificate with the CA's private key
    builder.sign(ca_pkey, sig_digest(key_cfg.alg))?;

    Ok(builder.build())
}

fn write_outputs_zip(filename: &str, outputs: &[FileOutput], force: bool) -> Result<(), AppError> {
    let path = PathBuf::from(filename);

    // Restricting each entry is cosmetic if the archive itself is readable:
    // extracting it hands over the private keys.  Guard the container to match
    // the strictest thing inside it.
    let archive_mode = if outputs.iter().any(|o| o.is_key) {
        MODE_KEY
    } else {
        MODE_NORMAL
    };
    let file = create_file(&path, archive_mode, force)?;
    let mut zip = zip::ZipWriter::new(file);

    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .compression_level(Some(9))
        .unix_permissions(MODE_NORMAL);
    let options_key = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .compression_level(Some(9))
        .unix_permissions(MODE_KEY);

    for output in outputs {
        // Archive entries are bare file names: --out-dir does not leak in as a
        // path prefix, and validate_args has already rejected any --*-out
        // value carrying a separator or `..`.
        let entry_options = if output.is_key { options_key } else { options };
        zip.start_file(&output.name, entry_options)
            .map_err(|e| AppError::Zip(path.clone(), e))?;
        zip.write_all(&output.data)
            .map_err(|e| AppError::Io(path.clone(), e))?;
    }

    zip.finish().map_err(|e| AppError::Zip(path.clone(), e))?;

    Ok(())
}

/// Create an output file, honouring `--force` and the requested mode.
///
/// Without `--force` the create is exclusive, so existing output is never
/// clobbered.  With it, the old file is removed first: it may be mode 0400,
/// which would make opening it for writing fail outright.
fn create_file(path: &Path, mode: u32, force: bool) -> Result<std::fs::File, AppError> {
    if force {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(AppError::Io(path.to_path_buf(), e)),
        }
    }

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);

    #[cfg(unix)]
    opts.mode(mode);
    #[cfg(not(unix))]
    let _ = mode;

    opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            AppError::Exists(path.to_path_buf())
        } else {
            AppError::Io(path.to_path_buf(), e)
        }
    })
}

/// Reject an output set in which two artifacts would land on the same file.
///
/// Every `FileOutput` is joined against the same base path, so equal `name`
/// means equal `path`; one pass covers both loose and archive output.  This
/// runs before anything is created, so a rejected set leaves the filesystem
/// untouched -- previously `--force` would unlink and rewrite, silently
/// leaving one artifact holding another's bytes.
fn check_output_collisions(outputs: &[FileOutput]) -> Result<(), AppError> {
    for (index, output) in outputs.iter().enumerate() {
        if let Some(earlier) = outputs[..index].iter().find(|o| o.name == output.name) {
            return Err(AppError::Config(format!(
                "{} would be written twice: once as the {}, once as the {}; \
                 give them distinct names",
                output.name, earlier.label, output.label
            )));
        }
    }

    Ok(())
}

fn write_outputs(outputs: &[FileOutput], force: bool) -> Result<(), AppError> {
    for output in outputs {
        let mut file = create_file(&output.path, output.mode(), force)?;
        file.write_all(&output.data)
            .map_err(|e| AppError::Io(output.path.clone(), e))?;
    }

    Ok(())
}

fn push_output(
    outputs: &mut Vec<FileOutput>,
    base_path: &Path,
    filename: &str,
    label: &'static str,
    contents: &[u8],
    is_key: bool,
) {
    // if user zeroed filename, do not emit
    if filename.is_empty() {
        return;
    }

    outputs.push(FileOutput {
        path: base_path.join(filename),
        name: String::from(filename),
        label,
        data: contents.to_vec(),
        is_key,
    });
}

/// Report what was generated, and where.
///
/// Silence is a poor result for a tool whose whole job is to produce files:
/// it leaves the user to work out what the defaults were.
fn print_summary(
    outputs: &[FileOutput],
    key_cfg: &KeyConfig,
    identity: &Identity,
    ca_cert: &X509,
    server_cert: &X509,
    out_dir: &Path,
    out_zip: Option<&str>,
) {
    if let Some(zip_path) = out_zip {
        println!("wrote {zip_path} containing {} files:", outputs.len());
    } else {
        println!("wrote {} files to {}:", outputs.len(), out_dir.display());
    }

    let width = outputs.iter().map(|o| o.name.len()).max().unwrap_or(0);
    for output in outputs {
        println!(
            "  {:<width$}  {:04o}  {}",
            output.name,
            output.mode(),
            output.label,
            width = width
        );
    }

    let names: Vec<String> = identity
        .sans
        .iter()
        .map(|entry| match entry {
            SanEntry::Dns(name) => format!("DNS:{name}"),
            SanEntry::Ip(ip) => format!("IP:{ip}"),
        })
        .collect();

    println!();
    println!("  key algorithm  {}", key_cfg.describe());
    println!("  server names   {}", names.join(", "));
    println!("  server cert    expires {}", server_cert.not_after());
    println!("  root CA        expires {}", ca_cert.not_after());
}

fn run() -> Result<(), AppError> {
    // parse command line arguments
    let mut args = Args::parse();
    validate_args(&args)?;
    swizzle_args(&mut args);
    warn_about_validity(&args);
    let key_cfg = resolve_key_config(&args).map_err(AppError::Config)?;
    let identity = resolve_identity(&args);
    let basepath = Path::new(&args.out_dir);

    // One clock read for the whole run, shared by both certificates
    let base_time = unix_now();

    // Generate root CA key and certificate (Steps 1 & 2)
    let ca_key = generate_private_key(&key_cfg).during("generate the root CA key")?;
    let ca_cert = create_root_ca_certificate(&args, &key_cfg, base_time, &ca_key)
        .during("build the root CA certificate")?;

    // Generate server key and CSR (Steps 3 & 4)
    let server_key = generate_private_key(&key_cfg).during("generate the server key")?;
    let server_csr = generate_web_server_csr(&args, &identity, &key_cfg, &server_key)
        .during("build the server certificate request")?;

    // Sign the server CSR with the root CA (Step 5)
    let server_cert = sign_server_csr(
        &args,
        &identity,
        &key_cfg,
        base_time,
        &server_csr,
        &ca_cert,
        &ca_key,
    )
    .during("sign the server certificate")?;

    let mut outputs: Vec<FileOutput> = Vec::new();

    // Output root CA privkey PEM
    push_output(
        &mut outputs,
        basepath,
        &args.ca_key_out,
        "root CA private key",
        &ca_key
            .private_key_to_pem_pkcs8()
            .during("encode the root CA key")?,
        true,
    );

    // Output root CA cert PEM
    push_output(
        &mut outputs,
        basepath,
        &args.ca_cert_out,
        "root CA certificate",
        &ca_cert.to_pem().during("encode the root CA certificate")?,
        false,
    );

    // Output server privkey PEM
    push_output(
        &mut outputs,
        basepath,
        &args.key_out,
        "server private key",
        &server_key
            .private_key_to_pem_pkcs8()
            .during("encode the server key")?,
        true,
    );

    // Output server CSR PEM
    if let Some(csr_out) = &args.csr_out {
        push_output(
            &mut outputs,
            basepath,
            csr_out,
            "server cert signing request",
            &server_csr
                .to_pem()
                .during("encode the certificate request")?,
            false,
        );
    }

    // Output server cert PEM
    push_output(
        &mut outputs,
        basepath,
        &args.cert_out,
        "server certificate",
        &server_cert
            .to_pem()
            .during("encode the server certificate")?,
        false,
    );

    check_output_collisions(&outputs)?;

    if let Some(out_zip) = &args.out_zip {
        write_outputs_zip(out_zip, &outputs, args.force)?;
    } else {
        write_outputs(&outputs, args.force)?;
    }

    if !args.quiet {
        print_summary(
            &outputs,
            &key_cfg,
            &identity,
            &ca_cert,
            &server_cert,
            basepath,
            args.out_zip.as_deref(),
        );
    }

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("self-signed-cert: error: {err}");
            ExitCode::FAILURE
        }
    }
}
