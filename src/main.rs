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

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Display generated certs and keys
    #[arg(short, long, default_value_t = false)]
    display: bool,
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

fn main() -> Result<(), ErrorStack> {
    // parse command line arguments
    let args = Args::parse();

    let root_pkey = generate_rsa_private_key()?;
    let root_pem = root_pkey.private_key_to_pem_pkcs8()?;

    if args.display {
        println!(
            "Root CA private key generated successfully.\n{}",
            String::from_utf8(root_pem).unwrap()
        );
    }

    let root_cert = create_root_ca_certificate(&root_pkey)?;

    if args.display {
        println!("Root CA Certificate Generated Successfully.");
        println!(
            "{}",
            String::from_utf8(root_cert.to_pem().unwrap()).unwrap()
        );
    }

    let server_pkey = generate_rsa_private_key()?;
    let server_pem = server_pkey.private_key_to_pem_pkcs8()?;

    if args.display {
        println!(
            "Server private key generated successfully.\n{}",
            String::from_utf8(server_pem).unwrap()
        );
    }

    let server_csr = generate_web_server_csr(&server_pkey)?;
    let server_csr_pem = server_csr.to_pem()?;

    if args.display {
        println!(
            "Server CSR generated successfully.\n{}",
            String::from_utf8(server_csr_pem).unwrap()
        );
    }

    Ok(())
}
