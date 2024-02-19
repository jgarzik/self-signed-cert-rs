//
// src/main.rs -- Generate self-signed root CA, web servers certs and keys
//
// Copyright (c) 2024 Jeff Garzik
//
// This file is part of the pcgtoolssoftware project covered under
// the MIT License.  For the full license text, please see the LICENSE
// file in the root directory of this project.
// SPDX-License-Identifier: MIT
// External crate declarations, bringing in third-party libraries for parsing command-line arguments and handling OpenSSL functionalities.
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
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

// Constants defining default file names and certificate parameters.
const DEF_CA_KEY: &str = "ca-key.pem";
const DEF_CA_CERT: &str = "ca-cert.pem";
const DEF_SVR_KEY: &str = "server-key.pem";
const DEF_SVR_CSR: &str = "server-csr.pem";
const DEF_SVR_CERT: &str = "server-cert.pem";
const DEF_COUNTRY: &str = "US";
const DEF_STATE: &str = "None";
const DEF_LOCALITY: &str = "None";
const DEF_ORGANIZATION: &str = "MyOrg";
const DEF_CA_COMMON_NAME: &str = "My CA";
const DEF_SRV_COMMON_NAME: &str = "my.server.com";

/// Struct to define and parse command-line arguments using clap.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    // Paths for output files with default values.
    #[arg(long, default_value = DEF_CA_KEY)]
    ca_key: String,
    #[arg(long, default_value = DEF_CA_CERT)]
    ca_cert: String,
    #[arg(long, default_value = DEF_SVR_KEY)]
    key: String,
    #[arg(long, default_value = DEF_SVR_CSR)]
    csr: String,
    #[arg(long, default_value = DEF_SVR_CERT)]
    cert: String,

    // Optional certificate details for the CA and server certificates.
    #[arg(long)]
    ca_country: Option<String>,
    #[arg(long)]
    ca_state: Option<String>,
    #[arg(long)]
    ca_locality: Option<String>,
    #[arg(long)]
    ca_organization: Option<String>,
    #[arg(long)]
    ca_common_name: Option<String>,
    #[arg(long)]
    srv_country: Option<String>,
    #[arg(long)]
    srv_state: Option<String>,
    #[arg(long)]
    srv_locality: Option<String>,
    #[arg(long)]
    srv_organization: Option<String>,
    #[arg(long)]
    srv_common_name: Option<String>,

    /// Pathname to the output directory with a default value.
    #[arg(long, default_value = "out")]
    out_dir: String,
}

/// Generates an RSA private key for use in certificate creation.
fn generate_rsa_private_key() -> Result<PKey<Private>, ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    PKey::from_rsa(rsa)
}

/// Creates a root CA certificate based on provided details or defaults.
fn create_root_ca_certificate(pkey: &PKey<Private>, args: &Args) -> Result<X509, ErrorStack> {
    let mut name_builder = X509NameBuilder::new()?;
    // Fill in the certificate's subject and issuer name fields.
    name_builder.append_entry_by_text("C", args.ca_country.as_deref().unwrap_or(DEF_COUNTRY))?;
    name_builder.append_entry_by_text("ST", args.ca_state.as_deref().unwrap_or(DEF_STATE))?;
    name_builder.append_entry_by_text("L", args.ca_locality.as_deref().unwrap_or(DEF_LOCALITY))?;
    name_builder.append_entry_by_text(
        "O",
        args.ca_organization.as_deref().unwrap_or(DEF_ORGANIZATION),
    )?;
    name_builder.append_entry_by_text(
        "CN",
        args.ca_common_name.as_deref().unwrap_or(DEF_CA_COMMON_NAME),
    )?;
    let name = name_builder.build();

    let mut builder = X509Builder::new()?;
    // Set certificate version, subject, issuer, and public key.
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(pkey)?;

    // Set certificate validity period.
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?; // Valid for 1 year
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Generate and set a unique serial number for the certificate.
    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
    // Convert BigNum to Asn1Integer outside the function call
    let serial_asn1 = serial.to_asn1_integer()?;
    // Now, pass the Asn1Integer to set_serial_number
    builder.set_serial_number(&serial_asn1)?;

    // Sign the certificate with the CA's private key using SHA-256.
    builder.sign(pkey, MessageDigest::sha256())?;
    Ok(builder.build())
}

/// Generates a CSR (Certificate Signing Request) for the web server, using optional details or defaults.
fn generate_web_server_csr(server_key: &PKey<Private>, args: &Args) -> Result<X509Req, ErrorStack> {
    let mut req_builder = X509ReqBuilder::new()?;
    // Set the public key for the CSR.
    req_builder.set_pubkey(server_key)?;

    // Fill in the CSR's subject name fields.
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("C", args.srv_country.as_deref().unwrap_or(DEF_COUNTRY))?;
    name_builder.append_entry_by_text("ST", args.srv_state.as_deref().unwrap_or(DEF_STATE))?;
    name_builder.append_entry_by_text("L", args.srv_locality.as_deref().unwrap_or(DEF_LOCALITY))?;
    name_builder.append_entry_by_text(
        "O",
        args.srv_organization.as_deref().unwrap_or(DEF_ORGANIZATION),
    )?;
    name_builder.append_entry_by_text(
        "CN",
        args.srv_common_name
            .as_deref()
            .unwrap_or(DEF_SRV_COMMON_NAME),
    )?;
    let name = name_builder.build();

    // Set the CSR's subject name and sign the CSR with the server's private key.
    req_builder.set_subject_name(&name)?;
    req_builder.sign(server_key, MessageDigest::sha256())?;
    Ok(req_builder.build())
}

/// Signs a server CSR with the root CA certificate, creating a server certificate.
fn sign_server_csr(
    server_csr: &X509Req,
    ca_cert: &X509,
    ca_pkey: &PKey<Private>,
) -> Result<X509, ErrorStack> {
    let mut builder = X509Builder::new()?;
    // Set certificate version, subject name, issuer name, and public key from CSR.
    builder.set_version(2)?;
    builder.set_subject_name(server_csr.subject_name())?;
    builder.set_issuer_name(ca_cert.subject_name())?;

    let pubkey = server_csr.public_key()?;
    builder.set_pubkey(&pubkey)?;

    // Set certificate validity period.
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?; // Valid for 1 year
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Sign the server certificate with the CA's private key.
    builder.sign(&ca_pkey, MessageDigest::sha256())?;
    Ok(builder.build())
}

/// Writes PEM-formatted content to a file within a specified directory.
fn write_pem_file(base_path: &Path, filename: &str, contents: &[u8]) -> Result<(), std::io::Error> {
    let path = base_path.join(filename);
    let mut file = File::create(&path)?;
    file.write_all(contents)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Ensure the specified output directory exists.
    fs::create_dir_all(&args.out_dir)?;

    let out_path = Path::new(&args.out_dir);

    // Generate the root CA key and certificate.
    let ca_key = generate_rsa_private_key()?;
    let ca_cert = create_root_ca_certificate(&ca_key, &args)?;

    // Generate the server key and CSR.
    let server_key = generate_rsa_private_key()?;
    let server_csr = generate_web_server_csr(&server_key, &args)?;

    // Sign the server CSR with the root CA, creating the server certificate.
    let server_cert = sign_server_csr(&server_csr, &ca_cert, &ca_key)?;

    // Write the generated keys and certificates to the specified output directory.
    write_pem_file(out_path, &args.ca_key, &ca_key.private_key_to_pem_pkcs8()?)?;
    write_pem_file(out_path, &args.ca_cert, &ca_cert.to_pem()?)?;
    write_pem_file(out_path, &args.key, &server_key.private_key_to_pem_pkcs8()?)?;
    write_pem_file(out_path, &args.csr, &server_csr.to_pem()?)?;
    write_pem_file(out_path, &args.cert, &server_cert.to_pem()?)?;

    Ok(())
}
