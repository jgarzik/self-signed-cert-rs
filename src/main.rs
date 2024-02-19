extern crate openssl;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509NameBuilder, X509Builder};

fn generate_root_ca() -> Result<(PKey<Private>, X509), ErrorStack> {
    // Step 1: Generate a new RSA private key
    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;

    // Step 2: Generate a root CA x509 certificate
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("C", "US")?;
    name_builder.append_entry_by_text("ST", "Florida")?;
    name_builder.append_entry_by_text("L", "Miami")?;
    name_builder.append_entry_by_text("CN", "127.0.0.1")?;
    let name = name_builder.build();

    let mut x509_builder = X509Builder::new()?;
    x509_builder.set_version(2)?;
    x509_builder.set_subject_name(&name)?;
    x509_builder.set_issuer_name(&name)?;
    x509_builder.set_pubkey(&pkey)?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?; // Valid for 1 year
    x509_builder.set_not_before(&not_before)?;
    x509_builder.set_not_after(&not_after)?;

    let mut serial_number = BigNum::new().expect("BN::new err");
    serial_number.rand(159, MsbOption::MAYBE_ZERO, false)?;
    let asn1_serial_number = serial_number.to_asn1_integer()?;
    x509_builder.set_serial_number(&asn1_serial_number)?;

    x509_builder.sign(&pkey, MessageDigest::sha256())?;
    let certificate = x509_builder.build();

    Ok((pkey, certificate))
}

fn main() {
    match generate_root_ca() {
        Ok((pkey, certificate)) => {
            println!("Root CA Private Key and Certificate Generated Successfully.");

            // Saving or printing the key and certificate can be done here
            // For demonstration, we'll print the PEM encoded certificate
            println!("{}", String::from_utf8(certificate.to_pem().unwrap()).unwrap());
            // Note: In a real application, you should handle errors (e.g., unwrap) more gracefully
        },
        Err(e) => eprintln!("Failed to generate root CA: {}", e),
    }
}

