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
