
# self-signed-cert

## Introduction

A command line tool to generate self-signed web server TLS certificates,
for use in testing.

## Usage

The CLI interface is described via `--help`:
```
$ cargo run -- --help
Tool to generate self-signed root CA, web server certs and keys

Usage: self-signed-cert [OPTIONS]

Options:
      --ca-key-out <CA_KEY_OUT>
          root CA private key output path [default: ca-key.pem]
      --ca-cert-out <CA_CERT_OUT>
          root CA cert output path [default: ca-cert.pem]
      --key-out <KEY_OUT>
          server private key output path [default: server-key.pem]
      --csr-out <CSR_OUT>
          server cert signing request output path
      --cert-out <CERT_OUT>
          server cert output path [default: server-cert.pem]

      --srv-common-name <SRV_COMMON_NAME>
          Server cert: common name [default: 127.0.0.1]
      --srv-country <SRV_COUNTRY>
          Server cert: country code [default: US]
      --srv-state <SRV_STATE>
          Server cert: state or province
      --srv-city <SRV_CITY>
          Server cert: city or locality
      --srv-org <SRV_ORG>
          Server cert: organization

      --ca-common-name <CA_COMMON_NAME>
          CA cert: common name [default: 127.0.0.1]
      --ca-country <CA_COUNTRY>
          CA cert: country code [default: US]
      --ca-state <CA_STATE>
          CA cert: state or province
      --ca-city <CA_CITY>
          CA cert: city or locality
      --ca-org <CA_ORG>
          CA cert: organization

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

  -h, --help
          Print help
  -V, --version
          Print version

```

## Example invocation

```
$ cargo run
    Finished dev [unoptimized + debuginfo] target(s) in 0.03s
     Running `target/debug/self-signed-cert`
$ ls *.pem
ca-cert.pem	ca-key.pem	server-cert.pem	server-key.pem
```

