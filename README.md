
# self-signed-cert

## Introduction

A command line tool to generate self-signed web server TLS certificates,
for use in testing.

## Operation

`self-signed-cert` generates the four (4) files needed to test a single
client/server scenario:
1. Root CA certificate
2. Root CA private key
3. Server certificate
4. Server private key

Optionally, the server cert request (CSR) may also be generated.

Many options exist to tweak certificate settings.  _All CLI options are
optional_.  The program is designed to do the right thing by default, with
zero configuration.

## Requirements

Building requires a system OpenSSL (1.1.1 or 3.x) and its development
headers, because the tool links against it via the `openssl` crate.

- Debian/Ubuntu: `apt install libssl-dev pkg-config`
- Fedora/RHEL: `dnf install openssl-devel`
- macOS: `brew install openssl@3`
- Windows: `vcpkg install openssl:x64-windows-static-md`

The integration tests additionally shell out to the `openssl` command line
tool for validation.  Set `OPENSSL_BIN` if it is not on `PATH` under that
name — macOS ships LibreSSL, which is not sufficient.

## Example invocation

```
$ self-signed-cert
wrote 4 files to .:
  ca-key.pem       0400  root CA private key
  ca-cert.pem      0444  root CA certificate
  server-key.pem   0400  server private key
  server-cert.pem  0444  server certificate

  key algorithm  ECDSA P-256
  server names   DNS:localhost, IP:127.0.0.1, IP:::1
  server cert    expires Sep 26 05:09:08 2027 GMT
  root CA        expires Aug 22 05:09:08 2036 GMT
```

The result works out of the box for a local test server reached by name or
by address, over either IP version:

```
$ openssl s_server -cert server-cert.pem -key server-key.pem -accept 8443
$ curl --cacert ca-cert.pem https://localhost:8443/
$ curl --cacert ca-cert.pem https://127.0.0.1:8443/
```

## Common tasks

Cover extra names — IP addresses and DNS names are told apart automatically:

```
$ self-signed-cert --san api.test --san 10.0.0.7 --san fd00::1
```

Pick a different key algorithm:

```
$ self-signed-cert --key-alg ed25519
$ self-signed-cert --key-alg rsa --rsa-bits 4096
```

Bundle everything into one archive, and overwrite a previous run:

```
$ self-signed-cert --out-zip certs.zip --force
```

Suppress an output file by giving it an empty name:

```
$ self-signed-cert --csr-out server-csr.pem --ca-key-out ""
```

## Output files

Written with restrictive permissions: private keys are mode `0400`, everything
else `0444`.  Keys are unencrypted PKCS#8 PEM (`BEGIN PRIVATE KEY`).

Existing files are never overwritten unless `--force` is given.

With `--out-zip`, the archive holds the same files under bare names and the
same per-entry permissions; `--out-dir` then applies only to loose output.

## Trusting the CA locally

The generated root CA is not trusted by anything until you say so.  To trust
it system-wide for testing:

```
# Debian/Ubuntu
$ sudo cp ca-cert.pem /usr/local/share/ca-certificates/self-signed-test.crt
$ sudo update-ca-certificates

# Fedora/RHEL
$ sudo cp ca-cert.pem /etc/pki/ca-trust/source/anchors/
$ sudo update-ca-trust

# macOS
$ sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain ca-cert.pem
```

Remove it again when you are done.  A CA you have trusted system-wide can
vouch for any name, so do not leave test roots installed.

## Defaults, and why

| Setting | Default | Rationale |
|---|---|---|
| Key algorithm | ECDSA P-256 | Mozilla's [Server Side TLS](https://ssl-config.mozilla.org/) "Modern" profile is ECDSA P-256/P-384 only. Smaller and faster than RSA at equivalent strength. |
| Server names | `localhost`, `127.0.0.1`, `::1` | Covers every way a test client reaches a local server. Addresses are emitted as `iPAddress`, which is the only form a strict client will match. |
| Identity location | Subject alternative name | [RFC 9525](https://www.rfc-editor.org/info/rfc9525/) (2023) removed the common name from hostname matching. The common name is retained for readability and copied into the SAN. |
| Server cert validity | 397 days | Under the 825-day ceiling Apple enforces on TLS server certificates even under a privately added root. |
| Root CA validity | 3650 days | The CA must outlive the certificates it signs. |
| `notBefore` | one hour in the past | Tolerates a client whose clock trails the generating host. |
| Serial numbers | 128 random bits | RFC 5280 requires a positive integer; CA/Browser Forum baseline requirement 7.1 requires at least 64 bits of CSPRNG output. |
| Leaf key usage | `digitalSignature` (+ `keyEncipherment` for RSA) | CA/Browser Forum BR 7.1.2.7.11. |
| CA basic constraints | `CA:TRUE, pathlen:0` | This CA signs end-entity certificates only. |

### On RSA key size and quantum resistance

A larger RSA modulus is **not** a post-quantum hedge.  Shor's algorithm is
polynomial in key length, so RSA-4096 buys hours over RSA-2048 against a
capable quantum adversary, not security.  [NIST IR 8547](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf)
deprecates RSA and ECDSA alike after 2030 and disallows them after 2035
*regardless of key size*.

Certificate signatures are also the least urgent part of that migration.
Unlike key exchange, a signature cannot be harvested now and forged later —
it only has to hold during the handshake.  The urgent post-quantum work is
hybrid key exchange (`X25519MLKEM768`), which is a TLS server setting, not a
property of any certificate this tool emits.

Genuine post-quantum certificates mean ML-DSA, which requires OpenSSL 3.5 or
newer and is not yet trusted by any browser.  Not currently supported.

## Command Line Interface

The CLI interface is described via `--help`:

<!-- BEGIN HELP -->
```
Tool to generate self-signed root CA, web server certs and keys

Usage: self-signed-cert [OPTIONS]

Options:
  -o, --out-dir <OUT_DIR>
          Output directory for PEM files
          
          [default: .]

      --out-zip <OUT_ZIP>
          Bundle all output into a single zip archive at this path

      --force
          Overwrite existing output files instead of refusing to run

  -q, --quiet
          Do not print the summary of what was generated

      --ca-key-out <CA_KEY_OUT>
          root CA private key output path
          
          Pass an empty string to suppress this file.
          
          [default: ca-key.pem]

      --ca-cert-out <CA_CERT_OUT>
          root CA cert output path
          
          Pass an empty string to suppress this file.
          
          [default: ca-cert.pem]

      --key-out <KEY_OUT>
          server private key output path
          
          Pass an empty string to suppress this file.
          
          [default: server-key.pem]

      --csr-out <CSR_OUT>
          server cert signing request output path

      --cert-out <CERT_OUT>
          server cert output path
          
          Pass an empty string to suppress this file.
          
          [default: server-cert.pem]

      --key-alg <KEY_ALG>
          Key algorithm for both certificates [default: ecdsa-p256]

          Possible values:
          - ecdsa-p256: NIST P-256, signed with SHA-256
          - ecdsa-p384: NIST P-384, signed with SHA-384
          - ed25519:    Edwards-curve DSA, no separate digest
          - rsa:        RSA at --rsa-bits, signed with SHA-256

      --rsa-bits <RSA_BITS>
          RSA key size in bits: 2048, 3072 or 4096 [default: 2048]
          
          Implies `--key-alg rsa` when given on its own.

      --san <SAN>
          Subject alternative name for the server cert; repeatable.
          
          IP addresses and DNS names are told apart automatically. Defaults to localhost plus the IPv4 and IPv6 loopback addresses.

      --srv-common-name <SRV_COMMON_NAME>
          Server cert: common name, at most 64 characters [default: localhost]
          
          Modern TLS clients match on the subject alternative name, not this field; it is copied into the SAN so that it still has an effect.

      --srv-country <SRV_COUNTRY>
          Server cert: country code
          
          [default: US]

      --srv-state <SRV_STATE>
          Server cert: state or province

      --srv-city <SRV_CITY>
          Server cert: city or locality

      --srv-org <SRV_ORG>
          Server cert: organization

      --srv-expire <SRV_EXPIRE>
          Server cert: days until expiration
          
          [default: 397]

      --ca-common-name <CA_COMMON_NAME>
          CA cert: common name, at most 64 characters [default: self-signed-cert local CA]

      --ca-country <CA_COUNTRY>
          CA cert: country code
          
          [default: US]

      --ca-state <CA_STATE>
          CA cert: state or province

      --ca-city <CA_CITY>
          CA cert: city or locality

      --ca-org <CA_ORG>
          CA cert: organization

      --ca-expire <CA_EXPIRE>
          CA cert: days until expiration
          
          [default: 3650]

      --common-name <COMMON_NAME>
          common name: Default set for both CA and server certs

      --country <COUNTRY>
          country code: Default set for both CA and server certs

      --state <STATE>
          state or province: Default set for both CA and server certs

      --city <CITY>
          city or locality: Default set for both CA and server certs

      --org <ORG>
          organization: Default set for both CA and server certs

      --expire <EXPIRE>
          expire days:  Default set for both CA and server certs

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```
<!-- END HELP -->
