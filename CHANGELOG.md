# Changelog

All notable changes to this project are documented here.

## [2.0.0]

Breaking release.  The zero-config output changes shape: it is now an ECDSA
certificate covering `localhost`, `127.0.0.1` and `::1`, rather than an RSA
certificate covering a single (unmatchable) `DNS:127.0.0.1`.

### Fixed

- **Subject alternative names.** The default identity was `CN=127.0.0.1`,
  copied into the SAN as `DNS:127.0.0.1`. An IP literal only matches as an
  `iPAddress`, so rustls, Go and Chrome all rejected the zero-config output.
  `openssl verify -verify_ip 127.0.0.1` failed against every certificate this
  tool produced; it now passes.
- **Leaf serial number was 0.** `sign_server_csr` never set one, so every
  server certificate inherited the OpenSSL default. RFC 5280 4.1.2.2 requires
  a positive integer and CA/Browser Forum BR 7.1 requires at least 64 bits of
  CSPRNG output. Now 128 random bits, as the CA already had.
- **Leaf key usage** carried `nonRepudiation` and `dataEncipherment`, neither
  of which has a role in TLS server authentication (CABF BR 7.1.2.7.11).
- **CA and leaf expired at the same instant** — both defaulted to 365 days.
  The CA now defaults to 3650 days and the leaf to 397.
- **`notBefore` was exactly "now"**, so a client whose clock trailed the
  generating host rejected a freshly written certificate. Both certificates
  are backdated one hour.
- **CA `basicConstraints` had no `pathlen`.** Now `pathlen:0`.
- **Zip entry names included `--out-dir`**, so `-o /tmp/x --out-zip o.zip`
  produced entries named `/tmp/x/ca-cert.pem`. Entries are now bare names.
- **The CSR carried no extensions**, so `--csr-out` emitted a request that
  lost all identity. It now requests the subject alternative names.
- A non-UTF-8 output path caused a panic.

### Added

- `--key-alg` accepting `ecdsa-p256`, `ecdsa-p384`, `ed25519` or `rsa`.
- `--san`, repeatable; IP addresses and DNS names are told apart
  automatically.
- `--force` to overwrite existing output. Previously a re-run failed with a
  bare `AlreadyExists`, and the 0400/0444 modes made the obvious retry fail
  too.
- `--quiet` (`-q`).
- A summary of what was generated, printed on success. The tool previously
  produced no output whatsoever.
- Errors now name the step and the file instead of dumping a `Debug`
  representation of an OS error or an openssl `ErrorStack`.

### Changed

- **Default key algorithm is ECDSA P-256**, was RSA-2048. This matches
  Mozilla's Server Side TLS "Modern" profile. RSA remains available at
  2048/3072/4096; `--rsa-bits` on its own still selects RSA, so existing
  invocations are unaffected.
- **Default server common name is `localhost`**, was `127.0.0.1`.
- **Default CA common name is `self-signed-cert local CA`**, was `127.0.0.1`.
  The CA identifies no service, so a host name there was misleading.
- Warns when `--srv-expire` exceeds 825 days (Apple rejects privately-rooted
  TLS server certificates beyond that), or when the leaf would outlive its CA.
- Rust edition 2024; minimum supported Rust version 1.88.
- Dependencies: zip 0.6 to 8, openssl to 0.10.81, clap to 4.6.
- CI gained rustfmt, clippy, MSRV and `cargo audit` jobs; macOS and Windows
  now run the test suite rather than only building.

## [1.0.3] and earlier

See the git history.
