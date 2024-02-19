//
// src/main.rs -- Generate self-signed root CA, web servers certs and keys
//
// Copyright (c) 2024 Jeff Garzik
//
// This file is part of the pcgtoolssoftware project covered under
// the MIT License.  For the full license text, please see the LICENSE
// file in the root directory of this project.
// SPDX-License-Identifier: MIT

extern crate clap;
extern crate openssl;

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
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Output directory for PEM files
    #[arg(short, long, default_value = ".")]
    out_dir: String,

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
}

fn swizzle_args(args: &mut Args) {
    match &args.common_name {
        Some(txt) => {
            args.ca_common_name = txt.clone();
            args.srv_common_name = txt.clone();
        }
        None => {}
    }
    match &args.org {
        Some(txt) => {
            args.ca_org = Some(txt.clone());
            args.srv_org = Some(txt.clone());
        }
        None => {}
    }
    match &args.country {
        Some(txt) => {
            args.ca_country = txt.clone();
            args.srv_country = txt.clone();
        }
        None => {}
    }
    match &args.state {
        Some(txt) => {
            args.ca_state = Some(txt.clone());
            args.srv_state = Some(txt.clone());
        }
        None => {}
    }
    match &args.city {
        Some(txt) => {
            args.ca_city = Some(txt.clone());
            args.srv_city = Some(txt.clone());
        }
        None => {}
    }
}

fn generate_rsa_private_key() -> Result<PKey<Private>, ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;
    Ok(pkey)
}

fn create_root_ca_certificate(args: &Args, pkey: &PKey<Private>) -> Result<X509, ErrorStack> {
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("C", &args.ca_country)?;
    match args.ca_state.clone() {
        Some(txt) => {
            name_builder.append_entry_by_text("ST", &txt)?;
        }
        None => {}
    }
    match args.ca_city.clone() {
        Some(txt) => {
            name_builder.append_entry_by_text("L", &txt)?;
        }
        None => {}
    }
    match args.ca_org.clone() {
        Some(txt) => {
            name_builder.append_entry_by_text("O", &txt)?;
        }
        None => {}
    }
    name_builder.append_entry_by_text("CN", &args.ca_common_name)?;
    let name = name_builder.build();

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(pkey)?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?; // Certificate valid for 1 year
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
    let not_after = openssl::asn1::Asn1Time::days_from_now(365)?; // Valid for 1 year
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

/// Writes PEM-formatted content to a file within a specified directory.
fn write_pem_file(base_path: &Path, filename: &str, contents: &[u8]) -> Result<(), std::io::Error> {
    if filename.is_empty() {
        return Ok(());
    }
    let path = base_path.join(filename);
    let mut file = File::create(&path)?;
    file.write_all(contents)
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

    write_pem_file(
        &basepath,
        &args.ca_key_out,
        &ca_key.private_key_to_pem_pkcs8()?,
    )?;

    write_pem_file(&basepath, &args.ca_cert_out, &ca_cert.to_pem()?)?;

    write_pem_file(
        &basepath,
        &args.key_out,
        &server_key.private_key_to_pem_pkcs8()?,
    )?;

    if args.csr_out.is_some() {
        write_pem_file(&basepath, &args.csr_out.unwrap(), &server_csr.to_pem()?)?;
    }

    write_pem_file(&basepath, &args.cert_out, &server_cert.to_pem()?)?;

    Ok(())
}
