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

use clap::Parser;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509NameBuilder, X509Req, X509ReqBuilder, X509};
use std::fs;

const DEF_CA_KEY: &str = "ca-key.pem";
const DEF_CA_CERT: &str = "ca-cert.pem";
const DEF_SVR_KEY: &str = "server-key.pem";
const DEF_SVR_CSR: &str = "";
const DEF_SVR_CERT: &str = "server-cert.pem";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Pathname to output root CA private key
    #[arg(long, default_value = DEF_CA_KEY)]
    ca_key: String,

    /// Pathname to output root CA certificate
    #[arg(long, default_value = DEF_CA_CERT)]
    ca_cert: String,

    /// Pathname to output web server private key
    #[arg(long, default_value = DEF_SVR_KEY)]
    key: String,

    /// Pathname to output web server cert signing request (CSR)
    #[arg(long, default_value = DEF_SVR_CSR)]
    csr: String,

    /// Pathname to output web server certificate
    #[arg(long, default_value = DEF_SVR_CERT)]
    cert: String,
}

fn generate_rsa_private_key() -> Result<PKey<Private>, ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;
    Ok(pkey)
}

fn create_root_ca_certificate(pkey: &PKey<Private>) -> Result<X509, ErrorStack> {
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("C", "US")?;
    name_builder.append_entry_by_text("ST", "Florida")?;
    name_builder.append_entry_by_text("L", "Miami")?;
    name_builder.append_entry_by_text("CN", "127.0.0.1")?;
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

fn generate_web_server_csr(server_key: &PKey<Private>) -> Result<X509Req, ErrorStack> {
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(server_key)?;

    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("C", "US")?;
    name_builder.append_entry_by_text("ST", "Florida")?;
    name_builder.append_entry_by_text("L", "Miami")?;
    name_builder.append_entry_by_text("CN", "127.0.0.1")?;
    let name = name_builder.build();

    req_builder.set_subject_name(&name)?;

    // Sign the CSR with the server's private key
    req_builder.sign(server_key, MessageDigest::sha256())?;

    let csr = req_builder.build();
    Ok(csr)
}

fn sign_server_csr(
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
            .dns("127.0.0.1")
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

fn main() -> Result<(), ErrorStack> {
    // parse command line arguments
    let args = Args::parse();

    // Generate root CA key and certificate (Steps 1 & 2)
    let ca_key = generate_rsa_private_key()?;
    let ca_cert = create_root_ca_certificate(&ca_key)?;

    // Generate server key and CSR (Steps 3 & 4)
    let server_key = generate_rsa_private_key()?;
    let server_csr = generate_web_server_csr(&server_key)?;

    // Sign the server CSR with the root CA (Step 5)
    let server_cert = sign_server_csr(&server_csr, &ca_cert, &ca_key)?;

    // Output root CA private key PEM
    if !args.ca_key.is_empty() {
        let pem = ca_key.private_key_to_pem_pkcs8()?;
        fs::write(args.ca_key, pem).expect("I/O error");
    }

    // Output root CA certificate
    if !args.ca_cert.is_empty() {
        let pem = ca_cert.to_pem()?;
        fs::write(args.ca_cert, pem).expect("I/O error");
    }

    // Output web server private key
    if !args.key.is_empty() {
        let pem = server_key.private_key_to_pem_pkcs8()?;
        fs::write(args.key, pem).expect("I/O error");
    }

    // Output web server CSR
    if !args.csr.is_empty() {
        let pem = server_csr.to_pem()?;
        fs::write(args.csr, pem).expect("I/O error");
    }

    // Output final, self-signed web server certificate
    if !args.cert.is_empty() {
        let pem = server_cert.to_pem()?;
        fs::write(args.cert, pem).expect("I/O error");
    }

    Ok(())
}
