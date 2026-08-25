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
use clap::Parser;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    stack::Stack,
    x509::{X509, X509Builder, X509Extension, X509NameBuilder, X509Req, X509ReqBuilder},
};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const MODE_NORMAL: u32 = 0o444;
const MODE_KEY: u32 = 0o400;

/// Certificates are backdated by this much so that a client whose clock trails
/// the generating host still accepts a freshly minted certificate.
const CLOCK_SKEW_SECS: i64 = 3600;

/// Apple platforms reject a TLS server certificate issued on or after
/// 2019-07-01 whose validity exceeds 825 days, even under a privately added
/// root.  Warn rather than fail: the tool is used for more than browser tests.
const MAX_LEAF_DAYS: u32 = 825;

/// `notBefore`, backdated by `CLOCK_SKEW_SECS`.
///
/// `Asn1Time::days_from_now` cannot express a time in the past, so go through
/// the Unix epoch instead.
fn not_before_time() -> Result<Asn1Time, ErrorStack> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System clock is before the Unix epoch");
    let now = i64::try_from(now.as_secs()).expect("System clock beyond the range of time_t");
    Asn1Time::from_unix(now - CLOCK_SKEW_SECS)
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

    /// If present, send output to a single zipfile `OUT_ZIP`
    #[arg(long)]
    out_zip: Option<String>,

    /// root CA private key output path
    #[arg(long, default_value = "ca-key.pem")]
    ca_key_out: String,

    /// root CA cert output path
    #[arg(long, default_value = "ca-cert.pem")]
    ca_cert_out: String,

    /// server private key output path
    #[arg(long, default_value = "server-key.pem")]
    key_out: String,

    /// server cert signing request output path
    #[arg(long)]
    csr_out: Option<String>,

    /// server cert output path
    #[arg(long, default_value = "server-cert.pem")]
    cert_out: String,

    /// RSA key size in bits
    #[arg(long, default_value_t = 2048, value_parser = parse_rsa_bits)]
    rsa_bits: u32,

    /// Subject alternative name for the server cert; repeatable.
    ///
    /// IP addresses and DNS names are told apart automatically.
    /// [default: `localhost`, `127.0.0.1`, `::1`]
    #[arg(long)]
    san: Vec<String>,

    /// Server cert: common name [default: localhost]
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

    /// CA cert: common name [default: self-signed-cert local CA]
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
    filename: String,
    /// Bare file name, used as the entry name inside a zip archive
    name: String,
    data: Vec<u8>,
    is_key: bool,
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
    common_name: String,
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
            common_name: String::from("localhost"),
            sans: vec![
                SanEntry::Dns(String::from("localhost")),
                SanEntry::Ip(IpAddr::from([127, 0, 0, 1])),
                SanEntry::Ip(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])),
            ],
        };
    }

    // RFC 9525: the common name is not matched by clients, so whatever the
    // user asked for there must also appear among the SANs to have an effect.
    let common_name = match &args.srv_common_name {
        Some(name) => {
            if !sans.iter().any(|e| e.as_text() == *name) {
                sans.push(SanEntry::parse(name));
            }
            name.clone()
        }
        None => sans[0].as_text(),
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
    if args.srv_expire >= args.ca_expire {
        eprintln!(
            "warning: server cert ({} days) outlives the CA ({} days); \
             the chain will stop verifying when the CA expires",
            args.srv_expire, args.ca_expire
        );
    }
}

/// Generate random RSA private key
fn generate_rsa_private_key(bits: u32) -> Result<PKey<Private>, ErrorStack> {
    let rsa = Rsa::generate(bits)?;
    let pkey = PKey::from_rsa(rsa)?;
    Ok(pkey)
}

/// Create root CA certificate, given root CA private key
fn create_root_ca_certificate(args: &Args, pkey: &PKey<Private>) -> Result<X509, ErrorStack> {
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
    let not_before = not_before_time()?;
    let not_after = Asn1Time::days_from_now(args.ca_expire)?;
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

    builder.sign(pkey, MessageDigest::sha256())?;
    let certificate = builder.build();

    Ok(certificate)
}

/// Generate TLS server cert signing request
fn generate_web_server_csr(
    args: &Args,
    identity: &Identity,
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
    name_builder.append_entry_by_text("CN", &identity.common_name)?;
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
    req_builder.sign(server_key, MessageDigest::sha256())?;

    // Return the signed CSR
    let csr = req_builder.build();
    Ok(csr)
}

/// Root CA signs TLS server's cert request, creating final server cert
fn sign_server_csr(
    args: &Args,
    identity: &Identity,
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

    // Set validity
    let not_before = not_before_time()?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(args.srv_expire)?;
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
    builder.append_extension(
        openssl::x509::extension::KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

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
    builder.sign(ca_pkey, openssl::hash::MessageDigest::sha256())?;

    Ok(builder.build())
}

fn write_outputs_zip(
    filename: &str,
    outputs: &Vec<FileOutput>,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(filename)?;
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
        // Archive entries are bare file names; --out-dir applies to loose
        // files only, and must not leak into the archive as a path prefix.
        if output.is_key {
            zip.start_file(&output.name, options_key)?;
        } else {
            zip.start_file(&output.name, options)?;
        }
        zip.write_all(&output.data)?;
    }

    zip.finish()?;

    Ok(())
}

fn write_outputs(outputs: &Vec<FileOutput>) -> Result<(), std::io::Error> {
    for output in outputs {
        #[cfg(unix)]
        {
            let fmode = if output.is_key { MODE_KEY } else { MODE_NORMAL };

            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(fmode)
                .open(&output.filename)?;

            file.write_all(&output.data)?;
        }

        #[cfg(not(unix))]
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output.filename)?;

            file.write_all(&output.data)?;
        }
    }

    Ok(())
}

fn push_output(
    outputs: &mut Vec<FileOutput>,
    base_path: &Path,
    filename: &str,
    contents: &[u8],
    is_key: bool,
) {
    // if user zeroed filename, do not emit
    if filename.is_empty() {
        return;
    }

    outputs.push(FileOutput {
        filename: String::from(base_path.join(filename).to_str().unwrap()),
        name: String::from(filename),
        data: contents.to_vec(),
        is_key,
    });
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // parse command line arguments
    let mut args = Args::parse();
    swizzle_args(&mut args);
    warn_about_validity(&args);
    let identity = resolve_identity(&args);
    let basepath = Path::new(&args.out_dir);

    // Generate root CA key and certificate (Steps 1 & 2)
    let ca_key = generate_rsa_private_key(args.rsa_bits)?;
    let ca_cert = create_root_ca_certificate(&args, &ca_key)?;

    // Generate server key and CSR (Steps 3 & 4)
    let server_key = generate_rsa_private_key(args.rsa_bits)?;
    let server_csr = generate_web_server_csr(&args, &identity, &server_key)?;

    // Sign the server CSR with the root CA (Step 5)
    let server_cert = sign_server_csr(&args, &identity, &server_csr, &ca_cert, &ca_key)?;

    let mut outputs: Vec<FileOutput> = Vec::new();

    // Output root CA privkey PEM
    push_output(
        &mut outputs,
        basepath,
        &args.ca_key_out,
        &ca_key.private_key_to_pem_pkcs8()?,
        true,
    );

    // Output root CA cert PEM
    push_output(
        &mut outputs,
        basepath,
        &args.ca_cert_out,
        &ca_cert.to_pem()?,
        false,
    );

    // Output server privkey PEM
    push_output(
        &mut outputs,
        basepath,
        &args.key_out,
        &server_key.private_key_to_pem_pkcs8()?,
        true,
    );

    // Output server CSR PEM
    if let Some(csr_out) = &args.csr_out {
        push_output(
            &mut outputs,
            basepath,
            csr_out,
            &server_csr.to_pem()?,
            false,
        );
    }

    // Output server cert PEM
    push_output(
        &mut outputs,
        basepath,
        &args.cert_out,
        &server_cert.to_pem()?,
        false,
    );

    if let Some(out_zip) = &args.out_zip {
        write_outputs_zip(out_zip, &outputs)?;
    } else {
        write_outputs(&outputs)?;
    }

    Ok(())
}
