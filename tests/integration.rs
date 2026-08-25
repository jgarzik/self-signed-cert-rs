//
// tests/integration.rs -- Integration tests for self-signed-cert
//
// These tests run the binary and verify the generated certificates using
// the openssl command-line tool, which provides authoritative validation.
//

use std::process::Command;
use tempfile::TempDir;

/// Path to the openssl CLI used for validation.
///
/// Overridable via `OPENSSL_BIN` because the binary on `PATH` is not always a
/// usable OpenSSL: macOS ships `LibreSSL`, and Windows ships nothing at all.
fn openssl_bin() -> String {
    std::env::var("OPENSSL_BIN").unwrap_or_else(|_| String::from("openssl"))
}

/// Helper to run the self-signed-cert binary with given arguments
fn run_cert_generator(args: &[&str]) -> (TempDir, std::process::Output) {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    let mut cmd_args = vec!["-o", temp_dir.path().to_str().unwrap()];
    cmd_args.extend(args);

    let output = Command::new(env!("CARGO_BIN_EXE_self-signed-cert"))
        .args(&cmd_args)
        .output()
        .expect("Failed to execute binary");

    (temp_dir, output)
}

/// Run openssl x509 command to get certificate text
fn get_cert_text(cert_path: &std::path::Path) -> String {
    let output = Command::new(openssl_bin())
        .args([
            "x509",
            "-in",
            cert_path.to_str().unwrap(),
            "-noout",
            "-text",
        ])
        .output()
        .expect("Failed to run openssl x509 command");

    assert!(
        output.status.success(),
        "openssl x509 failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Verify a certificate against a CA certificate
fn verify_cert_chain(ca_path: &std::path::Path, cert_path: &std::path::Path) -> bool {
    let output = Command::new(openssl_bin())
        .args([
            "verify",
            "-CAfile",
            ca_path.to_str().unwrap(),
            cert_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run openssl verify command");

    output.status.success()
}

/// Run the binary against an existing directory.
///
/// `run_cert_generator` always creates a fresh `TempDir`, which makes output
/// collisions (and therefore `--force`) impossible to exercise.
fn run_in_dir(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    let mut cmd_args = vec!["-o", dir.to_str().unwrap()];
    cmd_args.extend(args);

    Command::new(env!("CARGO_BIN_EXE_self-signed-cert"))
        .args(&cmd_args)
        .output()
        .expect("Failed to execute binary")
}

/// Dump a private key as text, independent of its algorithm.
///
/// `openssl rsa` only understands RSA keys; `openssl pkey` handles every
/// algorithm the tool can emit.
fn get_key_text(key_path: &std::path::Path) -> String {
    let output = Command::new(openssl_bin())
        .args(["pkey", "-in", key_path.to_str().unwrap(), "-noout", "-text"])
        .output()
        .expect("Failed to run openssl pkey command");

    assert!(
        output.status.success(),
        "openssl pkey failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Dump a CSR as text, verifying its self-signature along the way
fn get_csr_text(csr_path: &std::path::Path) -> String {
    let output = Command::new(openssl_bin())
        .args([
            "req",
            "-in",
            csr_path.to_str().unwrap(),
            "-noout",
            "-text",
            "-verify",
        ])
        .output()
        .expect("Failed to run openssl req command");

    assert!(
        output.status.success(),
        "openssl req failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // -verify writes its verdict to stderr on some builds, stdout on others
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

/// Verify a certificate chain *and* that the leaf matches a DNS name.
///
/// Plain `openssl verify` ignores subject identity entirely, which is why a
/// certificate carrying the wrong SAN type still passes it.
fn verify_hostname(ca_path: &std::path::Path, cert_path: &std::path::Path, name: &str) -> bool {
    Command::new(openssl_bin())
        .args([
            "verify",
            "-CAfile",
            ca_path.to_str().unwrap(),
            "-verify_hostname",
            name,
            cert_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run openssl verify command")
        .status
        .success()
}

/// Verify a certificate chain *and* that the leaf matches an IP address
fn verify_ip(ca_path: &std::path::Path, cert_path: &std::path::Path, ip: &str) -> bool {
    Command::new(openssl_bin())
        .args([
            "verify",
            "-CAfile",
            ca_path.to_str().unwrap(),
            "-verify_ip",
            ip,
            cert_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run openssl verify command")
        .status
        .success()
}

/// True if the certificate is still valid `days` from now.
///
/// Wraps `openssl x509 -checkend`, which exits 0 when the certificate will
/// *not* have expired by then.
fn valid_in_days(cert_path: &std::path::Path, days: u64) -> bool {
    Command::new(openssl_bin())
        .args([
            "x509",
            "-in",
            cert_path.to_str().unwrap(),
            "-noout",
            "-checkend",
            &(days * 86400).to_string(),
        ])
        .output()
        .expect("Failed to run openssl x509 -checkend")
        .status
        .success()
}

/// A sortable (year, month, day, hour, min, sec) tuple
type DateTuple = (i32, u32, u32, u32, u32, u32);

/// Parse an openssl date such as `Aug 25 04:39:25 2027 GMT`.
///
/// Hand-rolled rather than pulling in a date crate: openssl always prints
/// this in GMT, so a plain tuple compares correctly.
fn parse_openssl_date(value: &str) -> DateTuple {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let fields: Vec<&str> = value.split_whitespace().collect();
    assert!(
        fields.len() >= 4,
        "Unrecognized openssl date format: {value}"
    );

    let month = u32::try_from(
        MONTHS
            .iter()
            .position(|m| *m == fields[0])
            .unwrap_or_else(|| panic!("Unrecognized month in openssl date: {value}")),
    )
    .expect("Month index always fits in u32")
        + 1;
    let day: u32 = fields[1].parse().expect("Bad day in openssl date");
    let time: Vec<u32> = fields[2]
        .split(':')
        .map(|f| f.parse().expect("Bad time in openssl date"))
        .collect();
    let year: i32 = fields[3].parse().expect("Bad year in openssl date");

    (year, month, day, time[0], time[1], time[2])
}

/// Read `notBefore` / `notAfter` from a certificate
fn cert_date(cert_path: &std::path::Path, which: &str) -> DateTuple {
    let output = Command::new(openssl_bin())
        .args(["x509", "-in", cert_path.to_str().unwrap(), "-noout", which])
        .output()
        .expect("Failed to run openssl x509 date command");

    assert!(
        output.status.success(),
        "openssl x509 {which} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let text = String::from_utf8_lossy(&output.stdout);
    let value = text
        .trim()
        .split_once('=')
        .unwrap_or_else(|| panic!("Unexpected openssl output: {text}"))
        .1;
    parse_openssl_date(value)
}

fn not_before(cert_path: &std::path::Path) -> DateTuple {
    cert_date(cert_path, "-startdate")
}

fn not_after(cert_path: &std::path::Path) -> DateTuple {
    cert_date(cert_path, "-enddate")
}

/// Permission bits of a file, Unix only
#[cfg(unix)]
fn file_mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .expect("Failed to stat file")
        .permissions()
        .mode()
        & 0o777
}

/// Read a certificate's serial number as an uppercase hex string
fn cert_serial(cert_path: &std::path::Path) -> String {
    let output = Command::new(openssl_bin())
        .args([
            "x509",
            "-in",
            cert_path.to_str().unwrap(),
            "-noout",
            "-serial",
        ])
        .output()
        .expect("Failed to run openssl x509 -serial");

    assert!(
        output.status.success(),
        "openssl x509 -serial failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout)
        .trim()
        .split_once('=')
        .expect("Unexpected openssl -serial output")
        .1
        .to_string()
}

/// Pull the indented body of a named X.509 extension out of `openssl x509 -text`
fn extension_value(cert_text: &str, ext_name: &str) -> String {
    let needle = format!("X509v3 {ext_name}:");
    let hit = cert_text
        .find(&needle)
        .unwrap_or_else(|| panic!("Extension {ext_name:?} not present in certificate"));

    // Rewind to the start of the line so the header's indentation is visible;
    // slicing at the match would report an indent of zero and swallow every
    // following extension.
    let start = cert_text[..hit].rfind('\n').map_or(0, |nl| nl + 1);

    let mut lines = cert_text[start..].lines();
    let header = lines.next().unwrap_or_default();
    let header_indent = header.len() - header.trim_start().len();

    let mut body = String::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent <= header_indent {
            break;
        }
        body.push_str(line.trim());
        body.push(' ');
    }
    body.trim().to_string()
}

/// Run `openssl verify` as though the clock read `unix_time`
fn verify_at_time(
    ca_path: &std::path::Path,
    cert_path: &std::path::Path,
    unix_time: u64,
) -> std::process::Output {
    Command::new(openssl_bin())
        .args([
            "verify",
            "-CAfile",
            ca_path.to_str().unwrap(),
            "-attime",
            &unix_time.to_string(),
            cert_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run openssl verify -attime")
}

/// Seconds since the Unix epoch
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("System clock before the Unix epoch")
        .as_secs()
}

/// Read a certificate's subject line, in a version-stable format.
///
/// `-nameopt rfc2253` is not cosmetic here: OpenSSL's default subject
/// rendering differs between releases -- 3.0 prints `C = US`, newer builds
/// print `C=US` -- so an assertion written against one spelling fails on the
/// other platform.
fn cert_subject(cert_path: &std::path::Path) -> String {
    let output = Command::new(openssl_bin())
        .args([
            "x509",
            "-in",
            cert_path.to_str().unwrap(),
            "-noout",
            "-subject",
            "-nameopt",
            "rfc2253",
        ])
        .output()
        .expect("Failed to run openssl x509 -subject");

    assert!(
        output.status.success(),
        "openssl x509 -subject failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// A string of `n` repeated characters, for exercising length bounds
fn long_name(n: usize) -> String {
    "a".repeat(n)
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_basic_certificate_generation() {
    let (temp_dir, output) = run_cert_generator(&[]);

    assert!(
        output.status.success(),
        "Binary failed with stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Check all expected files exist
    assert!(
        temp_dir.path().join("ca-key.pem").exists(),
        "ca-key.pem not created"
    );
    assert!(
        temp_dir.path().join("ca-cert.pem").exists(),
        "ca-cert.pem not created"
    );
    assert!(
        temp_dir.path().join("server-key.pem").exists(),
        "server-key.pem not created"
    );
    assert!(
        temp_dir.path().join("server-cert.pem").exists(),
        "server-cert.pem not created"
    );
}

#[test]
fn test_server_cert_has_extended_key_usage_server_auth() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cert_path = temp_dir.path().join("server-cert.pem");
    let cert_text = get_cert_text(&cert_path);

    // Check for extendedKeyUsage extension
    assert!(
        cert_text.contains("X509v3 Extended Key Usage"),
        "Server certificate must have X509v3 Extended Key Usage extension.\nCertificate:\n{cert_text}"
    );

    // Check for serverAuth (TLS Web Server Authentication)
    assert!(
        cert_text.contains("TLS Web Server Authentication"),
        "Server certificate must have TLS Web Server Authentication in extendedKeyUsage.\nCertificate:\n{cert_text}"
    );
}

#[test]
fn test_ca_cert_has_ca_constraint() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cert_path = temp_dir.path().join("ca-cert.pem");
    let cert_text = get_cert_text(&cert_path);

    // Check for basicConstraints with CA:TRUE
    assert!(
        cert_text.contains("CA:TRUE"),
        "CA certificate must have CA:TRUE in basicConstraints.\nCertificate:\n{cert_text}"
    );
}

#[test]
fn test_ca_cert_has_key_usage() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cert_path = temp_dir.path().join("ca-cert.pem");
    let cert_text = get_cert_text(&cert_path);

    // Check for keyUsage extension (should be critical for CA certs per RFC 5280)
    assert!(
        cert_text.contains("X509v3 Key Usage: critical"),
        "CA certificate must have critical keyUsage extension.\nCertificate:\n{cert_text}"
    );

    // Check for Certificate Sign permission
    assert!(
        cert_text.contains("Certificate Sign"),
        "CA certificate must have Certificate Sign in keyUsage.\nCertificate:\n{cert_text}"
    );

    // Check for CRL Sign permission
    assert!(
        cert_text.contains("CRL Sign"),
        "CA certificate must have CRL Sign in keyUsage.\nCertificate:\n{cert_text}"
    );
}

#[test]
fn test_server_cert_signed_by_ca() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let ca_path = temp_dir.path().join("ca-cert.pem");
    let server_path = temp_dir.path().join("server-cert.pem");

    assert!(
        verify_cert_chain(&ca_path, &server_path),
        "Server certificate must be verifiable against CA certificate"
    );
}

#[test]
fn test_server_cert_has_subject_alt_name() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cert_path = temp_dir.path().join("server-cert.pem");
    let cert_text = get_cert_text(&cert_path);

    // Check for Subject Alternative Name extension
    assert!(
        cert_text.contains("X509v3 Subject Alternative Name"),
        "Server certificate must have Subject Alternative Name extension.\nCertificate:\n{cert_text}"
    );

    // Default common name is 127.0.0.1
    assert!(
        cert_text.contains("127.0.0.1"),
        "Server certificate SAN should contain the common name.\nCertificate:\n{cert_text}"
    );
}

#[test]
fn test_custom_common_name() {
    let (temp_dir, output) = run_cert_generator(&["--common-name", "example.local"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cert_path = temp_dir.path().join("server-cert.pem");
    let cert_text = get_cert_text(&cert_path);

    // Check that custom common name appears in the certificate
    assert!(
        cert_text.contains("CN=example.local") || cert_text.contains("CN = example.local"),
        "Server certificate should have custom common name.\nCertificate:\n{cert_text}"
    );
}

#[test]
fn test_keys_are_valid_pem() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // `openssl pkey` rather than `openssl rsa`: the key algorithm is
    // configurable, so this must not assume RSA.
    for key in ["ca-key.pem", "server-key.pem"] {
        let key_path = temp_dir.path().join(key);

        let check = Command::new(openssl_bin())
            .args([
                "pkey",
                "-in",
                key_path.to_str().unwrap(),
                "-check",
                "-noout",
            ])
            .output()
            .expect("Failed to run openssl pkey command");

        assert!(
            check.status.success(),
            "{key} should be a structurally valid private key: {}",
            String::from_utf8_lossy(&check.stderr)
        );

        // PKCS#8, unencrypted
        let pem = std::fs::read_to_string(&key_path).expect("Failed to read key");
        assert!(
            pem.contains("-----BEGIN PRIVATE KEY-----"),
            "{key} should be an unencrypted PKCS#8 PEM"
        );

        assert!(
            !get_key_text(&key_path).is_empty(),
            "{key} should dump as text"
        );
    }
}

#[test]
fn test_csr_output_when_requested() {
    let (temp_dir, output) = run_cert_generator(&["--csr-out", "server-csr.pem"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let csr_path = temp_dir.path().join("server-csr.pem");
    assert!(
        csr_path.exists(),
        "CSR file should be created when requested"
    );

    // Verify CSR is valid
    let csr_check = Command::new(openssl_bin())
        .args([
            "req",
            "-in",
            csr_path.to_str().unwrap(),
            "-noout",
            "-verify",
        ])
        .output()
        .expect("Failed to run openssl req command");

    assert!(
        csr_check.status.success(),
        "CSR should be valid: {}",
        String::from_utf8_lossy(&csr_check.stderr)
    );
}

#[test]
fn test_default_rsa_key_size_is_2048() {
    let (temp_dir, output) = run_cert_generator(&["--key-alg", "rsa"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Check server key size using openssl
    let key_info = Command::new(openssl_bin())
        .args([
            "rsa",
            "-in",
            temp_dir.path().join("server-key.pem").to_str().unwrap(),
            "-text",
            "-noout",
        ])
        .output()
        .expect("Failed to run openssl rsa command");

    let key_text = String::from_utf8_lossy(&key_info.stdout);
    assert!(
        key_text.contains("Private-Key: (2048 bit")
            || key_text.contains("RSA Private-Key: (2048 bit"),
        "Default RSA key should be 2048 bits.\nKey info:\n{key_text}"
    );
}

#[test]
fn test_rsa_key_size_3072() {
    let (temp_dir, output) = run_cert_generator(&["--key-alg", "rsa", "--rsa-bits", "3072"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Check server key size
    let key_info = Command::new(openssl_bin())
        .args([
            "rsa",
            "-in",
            temp_dir.path().join("server-key.pem").to_str().unwrap(),
            "-text",
            "-noout",
        ])
        .output()
        .expect("Failed to run openssl rsa command");

    let key_text = String::from_utf8_lossy(&key_info.stdout);
    assert!(
        key_text.contains("Private-Key: (3072 bit")
            || key_text.contains("RSA Private-Key: (3072 bit"),
        "RSA key should be 3072 bits when --rsa-bits 3072 is specified.\nKey info:\n{key_text}"
    );
}

#[test]
fn test_rsa_key_size_4096() {
    let (temp_dir, output) = run_cert_generator(&["--key-alg", "rsa", "--rsa-bits", "4096"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Check server key size
    let key_info = Command::new(openssl_bin())
        .args([
            "rsa",
            "-in",
            temp_dir.path().join("server-key.pem").to_str().unwrap(),
            "-text",
            "-noout",
        ])
        .output()
        .expect("Failed to run openssl rsa command");

    let key_text = String::from_utf8_lossy(&key_info.stdout);
    assert!(
        key_text.contains("Private-Key: (4096 bit")
            || key_text.contains("RSA Private-Key: (4096 bit"),
        "RSA key should be 4096 bits when --rsa-bits 4096 is specified.\nKey info:\n{key_text}"
    );
}

#[test]
fn test_invalid_rsa_key_size_rejected() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    let output = Command::new(env!("CARGO_BIN_EXE_self-signed-cert"))
        .args([
            "-o",
            temp_dir.path().to_str().unwrap(),
            "--rsa-bits",
            "1024",
        ])
        .output()
        .expect("Failed to execute binary");

    assert!(
        !output.status.success(),
        "Binary should reject invalid RSA key size (1024)"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("2048") || stderr.contains("3072") || stderr.contains("4096"),
        "Error message should mention valid key sizes.\nStderr:\n{stderr}"
    );
}

/// Read a zip archive, returning (entry name, unix mode, contents) per entry
fn read_zip(zip_path: &std::path::Path) -> Vec<(String, u32, Vec<u8>)> {
    use std::io::Read;

    let file = std::fs::File::open(zip_path).expect("Failed to open zip archive");
    let mut archive = zip::ZipArchive::new(file).expect("Failed to parse zip archive");

    let mut entries = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).expect("Failed to read zip entry");
        let name = entry.name().to_string();
        let mode = entry.unix_mode().unwrap_or(0) & 0o777;
        let mut data = Vec::new();
        entry.read_to_end(&mut data).expect("Failed to read entry");
        entries.push((name, mode, data));
    }
    entries
}

#[test]
fn test_zip_entry_names_are_bare() {
    // --out-dir governs loose files only.  It must never leak into the
    // archive as a path prefix on the entry names.
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let out_dir = temp_dir.path().join("certs");
    std::fs::create_dir(&out_dir).expect("Failed to create output directory");
    let zip_path = temp_dir.path().join("bundle.zip");

    let output = Command::new(env!("CARGO_BIN_EXE_self-signed-cert"))
        .args([
            "-o",
            out_dir.to_str().unwrap(),
            "--out-zip",
            zip_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute binary");
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let entries = read_zip(&zip_path);
    let names: Vec<&str> = entries.iter().map(|(n, _, _)| n.as_str()).collect();

    for name in &names {
        assert!(
            !name.contains('/') && !name.contains('\\'),
            "Zip entry name should be bare, got a path: {name}"
        );
    }

    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        vec![
            "ca-cert.pem",
            "ca-key.pem",
            "server-cert.pem",
            "server-key.pem"
        ],
        "Unexpected zip entry names"
    );
}

#[test]
fn test_openssl_version_guard() {
    // Every assertion in this suite is delegated to the openssl CLI.  If it is
    // missing or ancient, fail with a message that says so rather than letting
    // downstream tests report confusing mismatches.
    let output = Command::new(openssl_bin())
        .arg("version")
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "Cannot run `{}`: {e}.  Set OPENSSL_BIN to a usable OpenSSL 3.x binary.",
                openssl_bin()
            )
        });

    let version = String::from_utf8_lossy(&output.stdout);
    assert!(
        version.starts_with("OpenSSL 3") || version.starts_with("OpenSSL 4"),
        "Tests require OpenSSL 3.x or newer (LibreSSL is not sufficient); \
         found {version:?}.  Set OPENSSL_BIN to override."
    );
}

#[test]
fn test_verify_hostname_rejects_unlisted() {
    // Negative control: proves verify_hostname() actually discriminates, so
    // the positive hostname/IP assertions elsewhere mean something.
    let (temp_dir, output) = run_cert_generator(&["--srv-common-name", "example.test"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let ca = temp_dir.path().join("ca-cert.pem");
    let cert = temp_dir.path().join("server-cert.pem");

    assert!(
        !verify_hostname(&ca, &cert, "evil.example"),
        "A name absent from the SAN must not verify"
    );
}

#[cfg(unix)]
#[test]
fn test_file_modes() {
    let (temp_dir, output) = run_cert_generator(&["--csr-out", "server-csr.pem"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for key in ["ca-key.pem", "server-key.pem"] {
        assert_eq!(
            file_mode(&temp_dir.path().join(key)),
            0o400,
            "Private key {key} should be mode 0400"
        );
    }

    for pub_file in ["ca-cert.pem", "server-cert.pem", "server-csr.pem"] {
        assert_eq!(
            file_mode(&temp_dir.path().join(pub_file)),
            0o444,
            "Public file {pub_file} should be mode 0444"
        );
    }
}

#[test]
fn test_empty_filename_suppresses_output() {
    // An empty output path suppresses that artifact entirely.
    let (temp_dir, output) = run_cert_generator(&["--cert-out", "", "--ca-key-out", ""]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !temp_dir.path().join("server-cert.pem").exists(),
        "--cert-out \"\" should suppress the server certificate"
    );
    assert!(
        !temp_dir.path().join("ca-key.pem").exists(),
        "--ca-key-out \"\" should suppress the CA key"
    );
    assert!(
        temp_dir.path().join("ca-cert.pem").exists(),
        "Unsuppressed outputs should still be written"
    );
    assert!(
        temp_dir.path().join("server-key.pem").exists(),
        "Unsuppressed outputs should still be written"
    );
}

#[test]
fn test_zip_permissions() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let zip_path = temp_dir.path().join("bundle.zip");

    let output = run_in_dir(temp_dir.path(), &["--out-zip", zip_path.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for (name, mode, _) in read_zip(&zip_path) {
        let expected = if name.ends_with("-key.pem") {
            0o400
        } else {
            0o444
        };
        assert_eq!(mode, expected, "Wrong unix mode on zip entry {name}");
    }
}

#[test]
fn test_zip_contents_verify() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let zip_path = temp_dir.path().join("bundle.zip");

    let output = run_in_dir(temp_dir.path(), &["--out-zip", zip_path.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Extract and prove the archived pair is a working chain, not just bytes
    let extract_dir = TempDir::new().expect("Failed to create temp directory");
    for (name, _, data) in read_zip(&zip_path) {
        std::fs::write(extract_dir.path().join(&name), &data)
            .unwrap_or_else(|e| panic!("Failed to write extracted {name}: {e}"));
    }

    assert!(
        verify_cert_chain(
            &extract_dir.path().join("ca-cert.pem"),
            &extract_dir.path().join("server-cert.pem"),
        ),
        "Certificates extracted from the zip should verify as a chain"
    );
}

#[test]
fn test_verify_ip_rejects_unlisted() {
    // Negative control for verify_ip(), mirroring test_verify_hostname_rejects_unlisted.
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !verify_ip(
            &temp_dir.path().join("ca-cert.pem"),
            &temp_dir.path().join("server-cert.pem"),
            "10.99.99.99",
        ),
        "An address absent from the SAN must not verify"
    );
}

#[test]
fn test_csr_is_well_formed() {
    let (temp_dir, output) = run_cert_generator(&["--csr-out", "server-csr.pem"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // get_csr_text() runs -verify, so reaching here proves the self-signature
    let text = get_csr_text(&temp_dir.path().join("server-csr.pem"));
    assert!(
        text.contains("Certificate Request:"),
        "CSR should dump as a certificate request, got: {text}"
    );
    assert!(
        text.contains("Subject:"),
        "CSR should carry a subject, got: {text}"
    );
}

#[test]
fn test_validity_window_is_sane() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for cert in ["ca-cert.pem", "server-cert.pem"] {
        let path = temp_dir.path().join(cert);
        assert!(
            not_before(&path) < not_after(&path),
            "{cert}: notBefore must precede notAfter"
        );
        assert!(
            valid_in_days(&path, 1),
            "{cert} should still be valid tomorrow"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 2: RFC 5280 / CA-Browser-Forum conformance
// ---------------------------------------------------------------------------

#[test]
fn test_leaf_serial_nonzero() {
    // RFC 5280 4.1.2.2: the serial number MUST be a positive integer.
    // CABF BR 7.1: at least 64 bits of CSPRNG output.
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let serial = cert_serial(&temp_dir.path().join("server-cert.pem"));

    assert!(
        serial.trim_start_matches('0').chars().next().is_some(),
        "Leaf serial must be a positive integer, got {serial:?}"
    );
    assert!(
        serial.len() >= 16,
        "Leaf serial must carry at least 64 bits of entropy \
         (>= 16 hex digits), got {serial:?} ({} digits)",
        serial.len()
    );
}

#[test]
fn test_ca_and_leaf_serials_differ() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_ne!(
        cert_serial(&temp_dir.path().join("ca-cert.pem")),
        cert_serial(&temp_dir.path().join("server-cert.pem")),
        "CA and leaf must not share a serial number"
    );
}

#[test]
fn test_leaf_key_usage_rsa() {
    // CABF BR 7.1.2.7.11: for an RSA subscriber certificate, keyUsage should
    // be digitalSignature and/or keyEncipherment.  dataEncipherment and
    // nonRepudiation are not appropriate for TLS server authentication.
    let (temp_dir, output) = run_cert_generator(&["--key-alg", "rsa"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let text = get_cert_text(&temp_dir.path().join("server-cert.pem"));
    let usage = extension_value(&text, "Key Usage");

    assert!(
        text.contains("X509v3 Key Usage: critical"),
        "Leaf keyUsage must be critical"
    );
    assert!(
        usage.contains("Digital Signature"),
        "Leaf keyUsage must include Digital Signature, got {usage:?}"
    );
    assert!(
        usage.contains("Key Encipherment"),
        "RSA leaf keyUsage must include Key Encipherment, got {usage:?}"
    );
    assert!(
        !usage.contains("Non Repudiation"),
        "Leaf keyUsage must not include Non Repudiation, got {usage:?}"
    );
    assert!(
        !usage.contains("Data Encipherment"),
        "Leaf keyUsage must not include Data Encipherment, got {usage:?}"
    );
}

#[test]
fn test_ca_pathlen_zero() {
    // The CA issues exactly one leaf; it must not be able to mint intermediates.
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let text = get_cert_text(&temp_dir.path().join("ca-cert.pem"));
    let bc = extension_value(&text, "Basic Constraints");

    assert!(
        bc.contains("CA:TRUE"),
        "CA basicConstraints must assert CA:TRUE, got {bc:?}"
    );
    assert!(
        bc.contains("pathlen:0"),
        "CA basicConstraints must set pathlen:0, got {bc:?}"
    );
}

#[test]
fn test_leaf_aki_matches_ca_ski() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let ca_text = get_cert_text(&temp_dir.path().join("ca-cert.pem"));
    let leaf_text = get_cert_text(&temp_dir.path().join("server-cert.pem"));

    let ca_ski = extension_value(&ca_text, "Subject Key Identifier");
    let leaf_aki = extension_value(&leaf_text, "Authority Key Identifier");

    assert!(!ca_ski.is_empty(), "CA must carry a subjectKeyIdentifier");
    assert!(
        leaf_aki.contains(&ca_ski),
        "Leaf authorityKeyIdentifier {leaf_aki:?} must name the CA's subjectKeyIdentifier {ca_ski:?}"
    );
}

#[test]
fn test_ca_outlives_leaf() {
    // A CA that expires with its leaf breaks the chain the moment it matters.
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let ca_expiry = not_after(&temp_dir.path().join("ca-cert.pem"));
    let leaf_expiry = not_after(&temp_dir.path().join("server-cert.pem"));

    assert!(
        ca_expiry > leaf_expiry,
        "CA must outlive the leaf: CA {ca_expiry:?} vs leaf {leaf_expiry:?}"
    );
}

#[test]
fn test_default_validity_days() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let leaf = temp_dir.path().join("server-cert.pem");
    let ca = temp_dir.path().join("ca-cert.pem");

    // Leaf: 397 days -- comfortably under Apple's 825-day ceiling for
    // privately-rooted server certificates.
    assert!(
        valid_in_days(&leaf, 396),
        "Leaf should be valid at 396 days"
    );
    assert!(
        !valid_in_days(&leaf, 398),
        "Leaf should have expired by 398 days"
    );

    // CA: 10 years
    assert!(valid_in_days(&ca, 3649), "CA should be valid at 3649 days");
    assert!(
        !valid_in_days(&ca, 3651),
        "CA should have expired by 3651 days"
    );
}

#[test]
fn test_not_before_backdated() {
    // notBefore is backdated so a client whose clock runs slightly behind the
    // generating host does not reject a freshly minted certificate.
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let ca = temp_dir.path().join("ca-cert.pem");
    let leaf = temp_dir.path().join("server-cert.pem");

    let half_hour_ago = unix_now() - 1800;
    let result = verify_at_time(&ca, &leaf, half_hour_ago);

    assert!(
        result.status.success(),
        "Certificate should already be valid 30 minutes ago, but verification failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn test_warns_over_825_days() {
    let (_temp_dir, output) = run_cert_generator(&["--srv-expire", "900", "--ca-expire", "1200"]);
    assert!(
        output.status.success(),
        "An over-long validity should warn, not fail: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("825"),
        "Should warn that 900 days exceeds the 825-day limit, got: {stderr:?}"
    );
}

#[test]
fn test_warns_leaf_outlives_ca() {
    let (_temp_dir, output) = run_cert_generator(&["--srv-expire", "700", "--ca-expire", "365"]);
    assert!(
        output.status.success(),
        "A leaf outliving its CA should warn, not fail: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("outlives"),
        "Should warn that the leaf outlives the CA, got: {stderr:?}"
    );
}

// ---------------------------------------------------------------------------
// Phase 3: subject alternative names (RFC 9525 -- identity lives in the SAN)
// ---------------------------------------------------------------------------

#[test]
fn test_verify_ip_127() {
    // An IP literal must appear as an iPAddress SAN.  Placed in a dNSName it
    // is ignored by every strict TLS client, even though plain
    // `openssl verify` still reports the chain as OK.
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        verify_ip(
            &temp_dir.path().join("ca-cert.pem"),
            &temp_dir.path().join("server-cert.pem"),
            "127.0.0.1",
        ),
        "Default certificate must verify for 127.0.0.1"
    );
}

#[test]
fn test_verify_ip_v6() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        verify_ip(
            &temp_dir.path().join("ca-cert.pem"),
            &temp_dir.path().join("server-cert.pem"),
            "::1",
        ),
        "Default certificate must verify for the IPv6 loopback"
    );
}

#[test]
fn test_verify_hostname_localhost() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        verify_hostname(
            &temp_dir.path().join("ca-cert.pem"),
            &temp_dir.path().join("server-cert.pem"),
            "localhost",
        ),
        "Default certificate must verify for localhost"
    );
}

#[test]
fn test_default_san_set() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let text = get_cert_text(&temp_dir.path().join("server-cert.pem"));
    let san = extension_value(&text, "Subject Alternative Name");

    assert!(
        san.contains("DNS:localhost"),
        "Default SAN should include DNS:localhost, got {san:?}"
    );
    assert!(
        san.contains("IP Address:127.0.0.1"),
        "Default SAN should include IP Address:127.0.0.1, got {san:?}"
    );
    assert!(
        san.contains("IP Address:0:0:0:0:0:0:0:1"),
        "Default SAN should include the IPv6 loopback, got {san:?}"
    );
    assert!(
        !san.contains("DNS:127.0.0.1"),
        "An IP literal must never be emitted as a dNSName, got {san:?}"
    );
}

#[test]
fn test_san_flag_multiple() {
    let (temp_dir, output) = run_cert_generator(&[
        "--san",
        "example.test",
        "--san",
        "10.0.0.1",
        "--san",
        "fd00::1",
    ]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let ca = temp_dir.path().join("ca-cert.pem");
    let cert = temp_dir.path().join("server-cert.pem");
    let san = extension_value(&get_cert_text(&cert), "Subject Alternative Name");

    assert!(
        san.contains("DNS:example.test"),
        "A hostname should become a dNSName, got {san:?}"
    );
    assert!(
        san.contains("IP Address:10.0.0.1"),
        "An IPv4 literal should become an iPAddress, got {san:?}"
    );
    assert!(
        !san.contains("DNS:10.0.0.1") && !san.contains("DNS:fd00::1"),
        "IP literals must not be emitted as dNSNames, got {san:?}"
    );

    assert!(verify_hostname(&ca, &cert, "example.test"));
    assert!(verify_ip(&ca, &cert, "10.0.0.1"));
    assert!(verify_ip(&ca, &cert, "fd00::1"));

    // Explicit --san replaces the defaults rather than extending them
    assert!(
        !verify_hostname(&ca, &cert, "localhost"),
        "Explicit --san should replace the default identity set"
    );
}

#[test]
fn test_custom_common_name_appears_in_san() {
    // RFC 9525: clients match on the SAN, so a common name the user asked for
    // is useless unless it is also present there.
    let (temp_dir, output) = run_cert_generator(&["--srv-common-name", "myhost.test"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let ca = temp_dir.path().join("ca-cert.pem");
    let cert = temp_dir.path().join("server-cert.pem");

    assert!(
        extension_value(&get_cert_text(&cert), "Subject Alternative Name")
            .contains("DNS:myhost.test"),
        "--srv-common-name should be reflected in the SAN"
    );
    assert!(
        verify_hostname(&ca, &cert, "myhost.test"),
        "--srv-common-name should verify as a hostname"
    );
}

#[test]
fn test_common_name_ip_becomes_ip_san() {
    // The historical default was an IP literal in the common name; that must
    // now produce an iPAddress SAN, not a dNSName.
    let (temp_dir, output) = run_cert_generator(&["--srv-common-name", "192.168.1.10"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let san = extension_value(
        &get_cert_text(&temp_dir.path().join("server-cert.pem")),
        "Subject Alternative Name",
    );
    assert!(
        san.contains("IP Address:192.168.1.10"),
        "An IP common name should become an iPAddress SAN, got {san:?}"
    );
    assert!(
        !san.contains("DNS:192.168.1.10"),
        "An IP common name must not become a dNSName, got {san:?}"
    );
    assert!(
        verify_ip(
            &temp_dir.path().join("ca-cert.pem"),
            &temp_dir.path().join("server-cert.pem"),
            "192.168.1.10",
        ),
        "An IP common name should verify as an address"
    );
}

#[test]
fn test_csr_has_san() {
    // The CSR is emitted for users who want to re-sign elsewhere.  Without
    // an extension request it carries no identity at all.
    let (temp_dir, output) =
        run_cert_generator(&["--csr-out", "server-csr.pem", "--san", "csr.test"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let text = get_csr_text(&temp_dir.path().join("server-csr.pem"));
    assert!(
        text.contains("Requested Extensions:"),
        "CSR should carry an extension request, got: {text}"
    );
    assert!(
        text.contains("DNS:csr.test"),
        "CSR should request the subject alternative name, got: {text}"
    );
}

// ---------------------------------------------------------------------------
// Phase 4: key algorithms
// ---------------------------------------------------------------------------

#[test]
fn test_default_key_alg_is_ecdsa_p256() {
    // Mozilla's "Modern" server-side TLS profile is ECDSA P-256/P-384 only.
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for key in ["ca-key.pem", "server-key.pem"] {
        let text = get_key_text(&temp_dir.path().join(key));
        assert!(
            text.contains("prime256v1") || text.contains("P-256"),
            "{key} should be an ECDSA P-256 key, got: {text}"
        );
    }

    let cert_text = get_cert_text(&temp_dir.path().join("server-cert.pem"));
    assert!(
        cert_text.contains("id-ecPublicKey"),
        "Default leaf should carry an EC public key, got: {cert_text}"
    );
}

#[test]
fn test_ec_key_uses_named_curve() {
    // An EC key encoded with explicit curve parameters instead of a named
    // curve is rejected by a number of TLS stacks.
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let text = get_key_text(&temp_dir.path().join("server-key.pem"));
    assert!(
        text.contains("ASN1 OID: prime256v1"),
        "EC key should name its curve, got: {text}"
    );
    assert!(
        !text.contains("Field Type"),
        "EC key must not carry explicit curve parameters, got: {text}"
    );
}

#[test]
fn test_key_alg_ecdsa_p384() {
    let (temp_dir, output) = run_cert_generator(&["--key-alg", "ecdsa-p384"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let key_text = get_key_text(&temp_dir.path().join("server-key.pem"));
    assert!(
        key_text.contains("secp384r1") || key_text.contains("P-384"),
        "Should be a P-384 key, got: {key_text}"
    );

    // A P-384 key deserves a matching digest strength
    let cert_text = get_cert_text(&temp_dir.path().join("server-cert.pem"));
    assert!(
        cert_text.contains("ecdsa-with-SHA384"),
        "P-384 certificates should be signed with SHA-384, got: {cert_text}"
    );

    assert!(verify_cert_chain(
        &temp_dir.path().join("ca-cert.pem"),
        &temp_dir.path().join("server-cert.pem"),
    ));
}

#[test]
fn test_key_alg_ed25519() {
    let (temp_dir, output) = run_cert_generator(&["--key-alg", "ed25519"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let key_text = get_key_text(&temp_dir.path().join("server-key.pem"));
    assert!(
        key_text.to_uppercase().contains("ED25519"),
        "Should be an Ed25519 key, got: {key_text}"
    );

    // Proves the null-digest signing path: EdDSA has no separate hash step
    assert!(
        verify_cert_chain(
            &temp_dir.path().join("ca-cert.pem"),
            &temp_dir.path().join("server-cert.pem"),
        ),
        "Ed25519 chain should verify"
    );
    assert!(verify_hostname(
        &temp_dir.path().join("ca-cert.pem"),
        &temp_dir.path().join("server-cert.pem"),
        "localhost",
    ));
}

#[test]
fn test_key_alg_rsa_still_supported() {
    let (temp_dir, output) = run_cert_generator(&["--key-alg", "rsa"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let key_text = get_key_text(&temp_dir.path().join("server-key.pem"));
    assert!(
        key_text.contains("2048 bit") || key_text.contains("2048)"),
        "--key-alg rsa should default to 2048 bits, got: {key_text}"
    );
    assert!(
        get_cert_text(&temp_dir.path().join("server-cert.pem")).contains("sha256WithRSAEncryption"),
        "RSA certificates should be signed with SHA-256"
    );
}

#[test]
fn test_rsa_bits_implies_rsa_alg() {
    // Back-compat: scripts that only ever passed --rsa-bits keep working.
    let (temp_dir, output) = run_cert_generator(&["--rsa-bits", "3072"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let key_text = get_key_text(&temp_dir.path().join("server-key.pem"));
    assert!(
        key_text.contains("3072"),
        "--rsa-bits alone should select RSA at that size, got: {key_text}"
    );
}

#[test]
fn test_rsa_bits_with_ecdsa_rejected() {
    let (_temp_dir, output) =
        run_cert_generator(&["--key-alg", "ecdsa-p256", "--rsa-bits", "4096"]);
    assert!(
        !output.status.success(),
        "Combining --rsa-bits with a non-RSA --key-alg should fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--rsa-bits") && stderr.contains("--key-alg"),
        "Error should name both flags, got: {stderr}"
    );
}

#[test]
fn test_leaf_key_usage_ecdsa() {
    // CABF BR 7.1.2.7.11: an ECDSA subscriber certificate uses
    // digitalSignature.  keyEncipherment is meaningless for an EC key.
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let usage = extension_value(
        &get_cert_text(&temp_dir.path().join("server-cert.pem")),
        "Key Usage",
    );
    assert!(
        usage.contains("Digital Signature"),
        "ECDSA leaf should assert Digital Signature, got {usage:?}"
    );
    assert!(
        !usage.contains("Key Encipherment"),
        "ECDSA leaf must not assert Key Encipherment, got {usage:?}"
    );
}

#[test]
fn test_signature_algorithm_matches_key() {
    for (alg, expected) in [
        ("ecdsa-p256", "ecdsa-with-SHA256"),
        ("ecdsa-p384", "ecdsa-with-SHA384"),
        ("ed25519", "ED25519"),
        ("rsa", "sha256WithRSAEncryption"),
    ] {
        let (temp_dir, output) = run_cert_generator(&["--key-alg", alg]);
        assert!(
            output.status.success(),
            "Binary failed for {alg}: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        for cert in ["ca-cert.pem", "server-cert.pem"] {
            let text = get_cert_text(&temp_dir.path().join(cert));
            assert!(
                text.contains(expected),
                "{alg}: {cert} should be signed with {expected}, got: {text}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 5: output summary, --force, error reporting
// ---------------------------------------------------------------------------

#[test]
fn test_summary_on_stdout() {
    let (_temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.trim().is_empty(),
        "A successful run should say what it produced"
    );

    for expected in [
        "ca-cert.pem",
        "ca-key.pem",
        "server-cert.pem",
        "server-key.pem",
    ] {
        assert!(
            stdout.contains(expected),
            "Summary should name {expected}, got: {stdout}"
        );
    }
    assert!(
        stdout.contains("P-256"),
        "Summary should report the key algorithm, got: {stdout}"
    );
    assert!(
        stdout.contains("localhost"),
        "Summary should report the names the certificate covers, got: {stdout}"
    );
}

#[test]
fn test_quiet_suppresses_summary() {
    let (temp_dir, output) = run_cert_generator(&["--quiet"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        output.stdout.is_empty(),
        "--quiet should print nothing, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        temp_dir.path().join("server-cert.pem").exists(),
        "--quiet should still write the files"
    );
}

#[test]
fn test_rerun_fails_without_force() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    let first = run_in_dir(temp_dir.path(), &[]);
    assert!(first.status.success(), "First run should succeed");

    let second = run_in_dir(temp_dir.path(), &[]);
    assert!(
        !second.status.success(),
        "Second run must not silently clobber existing output"
    );

    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("ca-key.pem"),
        "Error should name the file that already exists, got: {stderr}"
    );
    assert!(
        stderr.contains("--force"),
        "Error should point at --force, got: {stderr}"
    );
    assert!(
        !stderr.contains("Os {") && !stderr.contains("kind:"),
        "Error should be a sentence, not a Debug dump, got: {stderr}"
    );
}

#[test]
fn test_force_overwrites() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let cert = temp_dir.path().join("server-cert.pem");

    let first = run_in_dir(temp_dir.path(), &[]);
    assert!(first.status.success(), "First run should succeed");
    let before = std::fs::read(&cert).expect("Failed to read first certificate");

    let second = run_in_dir(temp_dir.path(), &["--force"]);
    assert!(
        second.status.success(),
        "--force should overwrite: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    let after = std::fs::read(&cert).expect("Failed to read second certificate");
    assert_ne!(
        before, after,
        "--force should have replaced the certificate"
    );

    // Overwriting must not loosen the permissions
    #[cfg(unix)]
    {
        assert_eq!(file_mode(&cert), 0o444);
        assert_eq!(file_mode(&temp_dir.path().join("server-key.pem")), 0o400);
    }

    assert!(verify_cert_chain(
        &temp_dir.path().join("ca-cert.pem"),
        &cert
    ));
}

#[test]
fn test_force_overwrites_zip() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let zip_path = temp_dir.path().join("bundle.zip");
    let zip_arg = zip_path.to_str().unwrap();

    assert!(
        run_in_dir(temp_dir.path(), &["--out-zip", zip_arg])
            .status
            .success()
    );
    assert!(
        !run_in_dir(temp_dir.path(), &["--out-zip", zip_arg])
            .status
            .success(),
        "Existing archive must not be clobbered without --force"
    );
    assert!(
        run_in_dir(temp_dir.path(), &["--out-zip", zip_arg, "--force"])
            .status
            .success(),
        "--force should replace the archive"
    );
}

#[test]
fn test_bad_key_alg_error_is_readable() {
    let (_temp_dir, output) = run_cert_generator(&["--key-alg", "nonsense"]);
    assert!(!output.status.success(), "An unknown algorithm should fail");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ecdsa-p256"),
        "Error should list the valid algorithms, got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Phase 6: documentation
// ---------------------------------------------------------------------------

#[test]
fn test_readme_help_matches_binary() {
    // The README's help block silently went stale before: --rsa-bits was
    // added with three dedicated tests and never appeared in the docs.
    let readme =
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md"))
            .expect("Failed to read README.md");

    let begin = readme
        .find("<!-- BEGIN HELP -->")
        .expect("README.md should delimit its help block with <!-- BEGIN HELP -->");
    let end = readme
        .find("<!-- END HELP -->")
        .expect("README.md should delimit its help block with <!-- END HELP -->");

    let documented = readme[begin..end]
        .trim_start_matches("<!-- BEGIN HELP -->")
        .trim()
        .trim_start_matches("```")
        .trim_end_matches("```");

    let output = Command::new(env!("CARGO_BIN_EXE_self-signed-cert"))
        .arg("--help")
        .output()
        .expect("Failed to execute binary");
    let actual = String::from_utf8_lossy(&output.stdout);

    // Compare line by line, ignoring trailing whitespace: clap pads some
    // continuation lines, and editors strip that.  The usage line carries the
    // executable name, so on Windows it reads "self-signed-cert.exe"; fold that
    // away rather than keeping a per-platform copy of the block.
    let normalize = |text: &str| -> Vec<String> {
        let mut lines: Vec<String> = text
            .lines()
            .map(|line| {
                line.trim_end()
                    .replace("self-signed-cert.exe", "self-signed-cert")
            })
            .collect();
        while lines.first().is_some_and(String::is_empty) {
            lines.remove(0);
        }
        while lines.last().is_some_and(String::is_empty) {
            lines.pop();
        }
        lines
    };

    assert_eq!(
        normalize(documented),
        normalize(&actual),
        "README.md help block is out of date; regenerate it from `self-signed-cert --help`"
    );
}

// ---------------------------------------------------------------------------
// Phase 7: end-to-end TLS handshake
// ---------------------------------------------------------------------------

/// Grab a port the OS says is free.
///
/// Inherently racy, but the window is small and the alternative -- a
/// hardcoded port -- collides with anything else on the machine.
fn free_port() -> u16 {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind an ephemeral port");
    listener
        .local_addr()
        .expect("Failed to read bound address")
        .port()
}

/// Whether this openssl build offers `s_server`.
///
/// Not every packaging does -- some Windows builds ship the library and the
/// `x509`/`verify` subcommands but no test server.  Where it is missing the
/// handshake tests announce a skip rather than failing, since the
/// socket-free `verify -verify_ip` / `-verify_hostname` checks already cover
/// the same ground.
fn s_server_available() -> bool {
    Command::new(openssl_bin())
        .args(["s_server", "-help"])
        .output()
        .is_ok_and(|out| {
            let text = String::from_utf8_lossy(&out.stderr);
            !text.contains("Invalid command") && !text.contains("unknown option")
        })
}

/// Serve `cert`/`key` with `openssl s_server` and connect with `openssl
/// s_client`, returning the client's combined output.
///
/// This is the only check that exercises a real handshake; everything else
/// inspects the certificate as a static object.
fn tls_handshake(dir: &std::path::Path, client_args: &[&str]) -> String {
    let port = free_port();

    let mut server = Command::new(openssl_bin())
        .args([
            "s_server",
            "-cert",
            dir.join("server-cert.pem").to_str().unwrap(),
            "-key",
            dir.join("server-key.pem").to_str().unwrap(),
            "-accept",
            &port.to_string(),
            "-naccept",
            "1",
            "-quiet",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn openssl s_server");

    let mut args = vec![
        "s_client".to_string(),
        "-connect".to_string(),
        format!("127.0.0.1:{port}"),
        "-CAfile".to_string(),
        dir.join("ca-cert.pem").to_str().unwrap().to_string(),
        "-verify_return_error".to_string(),
    ];
    args.extend(client_args.iter().map(ToString::to_string));

    // Retry the client rather than probing the port first: s_server is run
    // with -naccept 1, and a probe connection would consume the one accept
    // the real client needs.  A refused connection is never accepted, so
    // retrying costs nothing.
    let mut combined = String::new();
    for _ in 0..60 {
        let client = Command::new(openssl_bin())
            .args(&args)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("Failed to run openssl s_client");

        combined = String::from_utf8_lossy(&client.stdout).to_string();
        combined.push_str(&String::from_utf8_lossy(&client.stderr));

        if !combined.contains("Connection refused") {
            break;
        }

        if let Ok(Some(status)) = server.try_wait() {
            panic!("openssl s_server exited early with {status}");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let _ = server.kill();
    let _ = server.wait();

    combined
}

#[test]
fn test_tls_handshake_ecdsa() {
    if !s_server_available() {
        eprintln!("skipping: this openssl build has no s_server");
        return;
    }

    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result = tls_handshake(temp_dir.path(), &["-verify_ip", "127.0.0.1"]);
    assert!(
        result.contains("Verify return code: 0 (ok)"),
        "Default certificate should complete a verified handshake, got: {result}"
    );
}

#[test]
fn test_tls_handshake_hostname() {
    if !s_server_available() {
        eprintln!("skipping: this openssl build has no s_server");
        return;
    }

    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(output.status.success());

    let result = tls_handshake(temp_dir.path(), &["-verify_hostname", "localhost"]);
    assert!(
        result.contains("Verify return code: 0 (ok)"),
        "Default certificate should verify as localhost over a real handshake, got: {result}"
    );
}

#[test]
fn test_tls_handshake_rsa() {
    if !s_server_available() {
        eprintln!("skipping: this openssl build has no s_server");
        return;
    }

    let (temp_dir, output) = run_cert_generator(&["--key-alg", "rsa"]);
    assert!(output.status.success());

    let result = tls_handshake(temp_dir.path(), &["-verify_ip", "127.0.0.1"]);
    assert!(
        result.contains("Verify return code: 0 (ok)"),
        "RSA certificate should complete a verified handshake, got: {result}"
    );
}

#[test]
fn test_tls_handshake_ed25519() {
    if !s_server_available() {
        eprintln!("skipping: this openssl build has no s_server");
        return;
    }

    let (temp_dir, output) = run_cert_generator(&["--key-alg", "ed25519"]);
    assert!(output.status.success());

    let result = tls_handshake(temp_dir.path(), &["-verify_ip", "127.0.0.1"]);
    assert!(
        result.contains("Verify return code: 0 (ok)"),
        "Ed25519 certificate should complete a verified handshake, got: {result}"
    );
}

// ---------------------------------------------------------------------------
// Phase 8: colliding output paths
// ---------------------------------------------------------------------------

#[test]
fn test_duplicate_output_names_rejected() {
    let (_temp_dir, output) = run_cert_generator(&["--cert-out", "ca-cert.pem"]);
    assert!(
        !output.status.success(),
        "Two outputs resolving to the same file must be rejected"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ca-cert.pem"),
        "Error should name the colliding file, got: {stderr}"
    );
    assert!(
        stderr.contains("root CA certificate") && stderr.contains("server certificate"),
        "Error should name both roles that want the file, got: {stderr}"
    );
}

#[test]
fn test_duplicate_output_does_not_corrupt_with_force() {
    // The regression test.  Previously --force happily unlinked and rewrote,
    // leaving ca-cert.pem holding the *server* certificate while the summary
    // reported both files written correctly.
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    assert!(
        run_in_dir(temp_dir.path(), &[]).status.success(),
        "Seeding run should succeed"
    );

    let ca_path = temp_dir.path().join("ca-cert.pem");
    let before = std::fs::read(&ca_path).expect("Failed to read seeded CA cert");

    let output = run_in_dir(temp_dir.path(), &["--cert-out", "ca-cert.pem", "--force"]);
    assert!(
        !output.status.success(),
        "A colliding --force run must be rejected, not silently applied"
    );

    let after = std::fs::read(&ca_path).expect("CA cert should still exist");
    assert_eq!(
        before, after,
        "The rejected run must not have touched the existing CA certificate"
    );
    assert!(
        get_cert_text(&ca_path).contains("self-signed-cert local CA"),
        "ca-cert.pem must still hold the CA certificate, not the server's"
    );
}

#[test]
fn test_duplicate_output_names_rejected_zip() {
    // In zip mode the collision previously surfaced as a ZipError partway
    // through, leaving a truncated archive on disk.
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let zip_path = temp_dir.path().join("bundle.zip");

    let output = run_in_dir(
        temp_dir.path(),
        &[
            "--out-zip",
            zip_path.to_str().unwrap(),
            "--cert-out",
            "ca-cert.pem",
        ],
    );
    assert!(
        !output.status.success(),
        "A colliding archive entry must be rejected"
    );
    assert!(
        !zip_path.exists(),
        "No archive should be created when the output set is invalid"
    );
}

#[test]
fn test_suppressed_names_do_not_collide() {
    // Two outputs suppressed with "" must not be mistaken for duplicates of
    // each other -- push_output drops them before they reach the output set.
    let (temp_dir, output) = run_cert_generator(&["--ca-key-out", "", "--key-out", ""]);
    assert!(
        output.status.success(),
        "Suppressed outputs should not register as a collision: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(!temp_dir.path().join("ca-key.pem").exists());
    assert!(!temp_dir.path().join("server-key.pem").exists());
    assert!(temp_dir.path().join("ca-cert.pem").exists());
    assert!(temp_dir.path().join("server-cert.pem").exists());
}

// ---------------------------------------------------------------------------
// Phase 9: distinguished-name field validation (RFC 5280 Appendix A bounds)
// ---------------------------------------------------------------------------

#[test]
fn test_long_derived_cn_omitted() {
    // A common name derived from --san may exceed the 64-character bound.
    // RFC 9525 clients never look at the CN, so drop it rather than failing:
    // the SAN still carries the name and the certificate stays usable.
    let host = format!("{}.example.com", long_name(60));
    let (temp_dir, output) = run_cert_generator(&["--san", &host]);
    assert!(
        output.status.success(),
        "A long SAN should not fail the run: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cert = temp_dir.path().join("server-cert.pem");
    let subject = cert_subject(&cert);
    assert!(
        !subject.contains("CN="),
        "Over-long derived common name should be omitted, got: {subject}"
    );
    assert!(
        subject.contains("C=US"),
        "The rest of the subject should survive, got: {subject}"
    );

    assert!(
        verify_hostname(&temp_dir.path().join("ca-cert.pem"), &cert, &host),
        "The name should still verify via the SAN"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("common name") && stderr.contains("64"),
        "Should explain why the common name was dropped, got: {stderr}"
    );
}

#[test]
fn test_long_explicit_common_name_rejected() {
    // Explicitly asking for an impossible common name is a user error.
    let (_temp_dir, output) = run_cert_generator(&["--srv-common-name", &long_name(65)]);
    assert!(
        !output.status.success(),
        "An over-long CN should be rejected"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--srv-common-name") && stderr.contains("64"),
        "Error should name the flag and the limit, got: {stderr}"
    );
    assert!(
        !stderr.contains("asn1") && !stderr.contains("maxsize"),
        "Error should be a sentence, not a raw ASN.1 dump, got: {stderr}"
    );
}

#[test]
fn test_long_ca_common_name_rejected() {
    let (_temp_dir, output) = run_cert_generator(&["--ca-common-name", &long_name(65)]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--ca-common-name"),
        "Error should name --ca-common-name"
    );
}

#[test]
fn test_bad_country_rejected() {
    // Validation runs before swizzle_args, so the error names the flag the
    // user actually typed rather than the --srv-*/--ca-* it expands into.
    let (_temp_dir, output) = run_cert_generator(&["--country", "USA"]);
    assert!(!output.status.success(), "A 3-letter country should fail");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--country"),
        "Error should name --country, not the flag it swizzles into, got: {stderr}"
    );
    assert!(
        stderr.contains('2'),
        "Error should state the 2-character limit, got: {stderr}"
    );
}

#[test]
fn test_long_org_rejected() {
    let (_temp_dir, output) = run_cert_generator(&["--org", &long_name(65)]);
    assert!(!output.status.success(), "An over-long org should fail");
    assert!(String::from_utf8_lossy(&output.stderr).contains("--org"));
}

#[test]
fn test_long_state_rejected() {
    let (_temp_dir, output) = run_cert_generator(&["--state", &long_name(129)]);
    assert!(!output.status.success(), "An over-long state should fail");
    assert!(String::from_utf8_lossy(&output.stderr).contains("--state"));
}

#[test]
fn test_empty_san_rejected() {
    let (_temp_dir, output) = run_cert_generator(&["--san", ""]);
    assert!(!output.status.success(), "An empty SAN should be rejected");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--san"),
        "Error should name --san, got: {stderr}"
    );
    assert!(
        !stderr.contains("minsize"),
        "Error should be a sentence, not a raw ASN.1 dump, got: {stderr}"
    );
}

#[test]
fn test_cn_length_boundary() {
    // Exactly at the bound is legal; one over is not.
    let (temp_dir, output) = run_cert_generator(&["--srv-common-name", &long_name(64)]);
    assert!(
        output.status.success(),
        "A 64-character common name is legal: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        cert_subject(&temp_dir.path().join("server-cert.pem")).contains(&long_name(64)),
        "A 64-character common name should appear in the subject"
    );

    let (_t2, over) = run_cert_generator(&["--srv-common-name", &long_name(65)]);
    assert!(!over.status.success(), "65 characters must be rejected");
}

#[test]
fn test_country_boundary_accepts_two() {
    let (_temp_dir, output) = run_cert_generator(&["--country", "FR"]);
    assert!(
        output.status.success(),
        "A 2-letter country code is legal: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// Phase 10: archive permissions
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn test_zip_archive_mode_is_restrictive() {
    // The archive holds unencrypted PKCS#8 private keys.  Protecting them
    // per-entry is cosmetic if anyone on the host can read the archive and
    // extract them; the loose-file path guards the same bytes at 0400.
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let zip_path = temp_dir.path().join("bundle.zip");

    let output = run_in_dir(temp_dir.path(), &["--out-zip", zip_path.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(
        file_mode(&zip_path),
        0o400,
        "An archive containing private keys must not be world-readable"
    );
}

#[cfg(unix)]
#[test]
fn test_zip_archive_mode_without_keys() {
    // With both keys suppressed the archive holds only public material, so
    // the restrictive mode is unnecessary.
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let zip_path = temp_dir.path().join("public.zip");

    let output = run_in_dir(
        temp_dir.path(),
        &[
            "--out-zip",
            zip_path.to_str().unwrap(),
            "--ca-key-out",
            "",
            "--key-out",
            "",
        ],
    );
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        read_zip(&zip_path)
            .iter()
            .all(|(name, _, _)| !name.ends_with("-key.pem")),
        "Sanity check: this archive should hold no keys"
    );
    assert_eq!(
        file_mode(&zip_path),
        0o444,
        "An archive with no private keys need not be restricted"
    );
}

// ---------------------------------------------------------------------------
// Phase 11: validity windows derived from a single clock read
// ---------------------------------------------------------------------------

#[test]
fn test_expire_flag_emits_no_warning() {
    // --expire sets both certificates by design, so warning that one outlives
    // the other on that very flag is nonsense.
    let (_temp_dir, output) = run_cert_generator(&["--expire", "100"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("outlives"),
        "--expire sets both certs equal; it must not warn, got: {stderr}"
    );
}

#[test]
fn test_equal_expiry_yields_identical_notafter() {
    // Previously each certificate read the clock independently, so "equal"
    // day counts were only approximately equal instants.
    let (temp_dir, output) = run_cert_generator(&["--expire", "100"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let ca = temp_dir.path().join("ca-cert.pem");
    let leaf = temp_dir.path().join("server-cert.pem");

    assert_eq!(
        not_after(&ca),
        not_after(&leaf),
        "Equal validity in days should give byte-identical notAfter"
    );
    assert_eq!(
        not_before(&ca),
        not_before(&leaf),
        "Both certificates should share one notBefore"
    );
}

#[test]
fn test_unequal_expiry_still_warns() {
    // The real case must keep warning.
    let (_temp_dir, output) = run_cert_generator(&["--srv-expire", "700", "--ca-expire", "365"]);
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("outlives"),
        "A leaf genuinely outliving its CA must still warn"
    );
}

// ---------------------------------------------------------------------------
// Output names must be plain file names
// ---------------------------------------------------------------------------

#[test]
fn test_output_name_with_separator_rejected() {
    let (_temp_dir, output) = run_cert_generator(&["--cert-out", "sub/x.pem"]);
    assert!(
        !output.status.success(),
        "An output name containing a path separator should be rejected"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--cert-out"),
        "Error should name the flag, got: {stderr}"
    );
    assert!(
        stderr.contains("--out-dir"),
        "Error should point at --out-dir as the way to choose a location, got: {stderr}"
    );
}

#[test]
fn test_output_name_parent_escape_rejected() {
    // Written into an archive verbatim, "../evil.pem" is a zip-slip entry: a
    // naive extractor drops it outside the target directory.
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let zip_path = temp_dir.path().join("bundle.zip");

    let output = run_in_dir(
        temp_dir.path(),
        &[
            "--out-zip",
            zip_path.to_str().unwrap(),
            "--cert-out",
            "../evil.pem",
        ],
    );
    assert!(
        !output.status.success(),
        "An escaping output name should be rejected"
    );
    assert!(
        !zip_path.exists(),
        "No archive should be produced for an invalid output set"
    );
}

#[test]
fn test_output_name_dotdot_rejected() {
    let (_temp_dir, output) = run_cert_generator(&["--key-out", ".."]);
    assert!(!output.status.success(), "'..' is not a valid file name");
    assert!(String::from_utf8_lossy(&output.stderr).contains("--key-out"));
}

#[test]
fn test_all_zip_entries_are_plain_names() {
    // The contract write_outputs_zip documents: entry names carry no path
    // component at all.
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let zip_path = temp_dir.path().join("bundle.zip");

    let output = run_in_dir(
        temp_dir.path(),
        &[
            "--out-zip",
            zip_path.to_str().unwrap(),
            "--csr-out",
            "server-csr.pem",
        ],
    );
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for (name, _, _) in read_zip(&zip_path) {
        assert_eq!(
            std::path::Path::new(&name)
                .file_name()
                .map(|f| f.to_string_lossy().to_string()),
            Some(name.clone()),
            "Zip entry {name:?} should be a plain file name"
        );
    }
}
