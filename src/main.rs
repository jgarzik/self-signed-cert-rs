//
// src/main.rs -- Generate self-signed root CA, web servers certs and keys
//
// Copyright (c) 2024 Jeff Garzik
//
// This file is part of the self-signed-cert software project covered under
// the MIT License.  For the full license text, please see the LICENSE
// file in the root directory of this project.
// SPDX-License-Identifier: MIT

extern crate clap;
extern crate openssl;
extern crate zip;

// Import necessary modules and types from the clap and openssl crates.
use clap::Parser;
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{X509Builder, X509NameBuilder, X509Req, X509ReqBuilder, X509},
};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const MODE_NORMAL: u32 = 0o444;
const MODE_KEY: u32 = 0o400;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Output directory for PEM files
    #[arg(short, long, default_value = ".")]
    out_dir: String,

    /// If present, send output to a single zipfile OUT_ZIP
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

    /// Server cert: common name
    #[arg(long, default_value = "127.0.0.1")]
    srv_common_name: String,

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
    #[arg(long, default_value_t = 365)]
    srv_expire: u32,

    /// CA cert: common name
    #[arg(long, default_value = "127.0.0.1")]
    ca_common_name: String,

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
    #[arg(long, default_value_t = 365)]
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
    filename: String,
    data: Vec<u8>,
    is_key: bool,
}

/// Process CLI args that assign two settings simultaneously
fn swizzle_args(args: &mut Args) {
    if let Some(txt) = &args.common_name {
        args.ca_common_name = txt.clone();
        args.srv_common_name = txt.clone();
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

/// Generate random RSA private key
fn generate_rsa_private_key() -> Result<PKey<Private>, ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;
    Ok(pkey)
}

/// Create root CA certificate, given root CA private key
fn create_root_ca_certificate(args: &Args, pkey: &PKey<Private>) -> Result<X509, ErrorStack> {
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
    name_builder.append_entry_by_text("CN", &args.ca_common_name)?;
    let name = name_builder.build();

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(pkey)?;

    let not_before = Asn1Time::days_from_now(0)?;
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
    builder.append_extension(
        openssl::x509::extension::BasicConstraints::new()
            .critical()
            .ca()
            .build()?,
    )?;

    // Generate a serial number for the certificate.
    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();

    builder.sign(pkey, MessageDigest::sha256())?;
    let certificate = builder.build();

    Ok(certificate)
}

/// Generate TLS server cert signing request
fn generate_web_server_csr(args: &Args, server_key: &PKey<Private>) -> Result<X509Req, ErrorStack> {
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(server_key)?;

    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("C", &args.srv_country)?;
    match args.srv_state.clone() {
        Some(txt) => {
            name_builder.append_entry_by_text("ST", &txt)?;
        }
        None => {}
    }
    match args.srv_city.clone() {
        Some(txt) => {
            name_builder.append_entry_by_text("L", &txt)?;
        }
        None => {}
    }
    match args.srv_org.clone() {
        Some(txt) => {
            name_builder.append_entry_by_text("O", &txt)?;
        }
        None => {}
    }
    name_builder.append_entry_by_text("CN", &args.srv_common_name)?;
    let name = name_builder.build();

    req_builder.set_subject_name(&name)?;

    // Sign the CSR with the server's private key
    req_builder.sign(server_key, MessageDigest::sha256())?;

    let csr = req_builder.build();
    Ok(csr)
}

/// Root CA signs TLS server's cert request, creating final server cert
fn sign_server_csr(
    args: &Args,
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

    // Set validity
    let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(args.srv_expire)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Extension: authorityKeyIdentifier
    builder.append_extension(
        openssl::x509::extension::AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&builder.x509v3_context(Some(ca_cert), None))?,
    )?;

    // Extension: basicConstraints
    let ext_basic = openssl::x509::extension::BasicConstraints::new().build()?;
    builder.append_extension(ext_basic)?;

    // Extension: keyUsage
    builder.append_extension(
        openssl::x509::extension::KeyUsage::new()
            .non_repudiation()
            .digital_signature()
            .key_encipherment()
            .data_encipherment()
            .build()?,
    )?;

    // Extension: subjectAltName
    builder.append_extension(
        openssl::x509::extension::SubjectAlternativeName::new()
            .dns(&args.srv_common_name)
            .build(&builder.x509v3_context(Some(ca_cert), None))?,
    )?;

    // Extension: subjectKeyIdentifier
    builder.append_extension(
        openssl::x509::extension::SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(Some(ca_cert), None))?,
    )?;

    // Sign the certificate with the CA's private key
    builder.sign(&ca_pkey, openssl::hash::MessageDigest::sha256())?;

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

    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .compression_level(Some(9))
        .unix_permissions(MODE_NORMAL);
    let options_key = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .compression_level(Some(9))
        .unix_permissions(MODE_KEY);

    for output in outputs {
        if output.is_key {
            zip.start_file(&output.filename, options_key)?;
        } else {
            zip.start_file(&output.filename, options)?;
        }
        zip.write(&output.data)?;
    }

    zip.finish()?;

    Ok(())
}

fn write_outputs(outputs: &Vec<FileOutput>) -> Result<(), std::io::Error> {
    for output in outputs {
        #[cfg(unix)]
        {
            let fmode;
            if output.is_key {
                fmode = MODE_KEY;
            } else {
                fmode = MODE_NORMAL;
            }

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
        data: contents.to_vec(),
        is_key,
    });
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // parse command line arguments
    let mut args = Args::parse();
    swizzle_args(&mut args);
    let basepath = Path::new(&args.out_dir);

    // Generate root CA key and certificate (Steps 1 & 2)
    let ca_key = generate_rsa_private_key()?;
    let ca_cert = create_root_ca_certificate(&args, &ca_key)?;

    // Generate server key and CSR (Steps 3 & 4)
    let server_key = generate_rsa_private_key()?;
    let server_csr = generate_web_server_csr(&args, &server_key)?;

    // Sign the server CSR with the root CA (Step 5)
    let server_cert = sign_server_csr(&args, &server_csr, &ca_cert, &ca_key)?;

    let mut outputs: Vec<FileOutput> = Vec::new();

    // Output root CA privkey PEM
    push_output(
        &mut outputs,
        &basepath,
        &args.ca_key_out,
        &ca_key.private_key_to_pem_pkcs8()?,
        true,
    );

    // Output root CA cert PEM
    push_output(
        &mut outputs,
        &basepath,
        &args.ca_cert_out,
        &ca_cert.to_pem()?,
        false,
    );

    // Output server privkey PEM
    push_output(
        &mut outputs,
        &basepath,
        &args.key_out,
        &server_key.private_key_to_pem_pkcs8()?,
        true,
    );

    // Output server CSR PEM
    if args.csr_out.is_some() {
        push_output(
            &mut outputs,
            &basepath,
            &args.csr_out.unwrap(),
            &server_csr.to_pem()?,
            false,
        );
    }

    // Output server cert PEM
    push_output(
        &mut outputs,
        &basepath,
        &args.cert_out,
        &server_cert.to_pem()?,
        false,
    );

    if args.out_zip.is_none() {
        write_outputs(&outputs)?;
    } else {
        write_outputs_zip(&args.out_zip.unwrap(), &outputs)?;
    }

    Ok(())
}
