# self-signed-cert

## Introduction

A command-line tool to generate self-signed root CA and web server TLS certificates for use in testing and development environments. It offers customizable certificate details and output paths, providing a quick way to set up a secure connection for local servers.

## Installation

Before using the tool, ensure you have Rust and Cargo installed on your system. You can download and install Rust, which includes Cargo, from [https://rustup.rs/](https://rustup.rs/).

## Usage

The tool's CLI interface is described via `--help`:

```shell
$ cargo run -- --help
    Finished dev [unoptimized + debuginfo] target(s) in 0.03s
     Running `target/debug/self-signed-cert --help`
Tool to generate self-signed root CA, web server certs, and keys

Usage: self-signed-cert [OPTIONS]

Options:
      --ca-key <CA_KEY>           Pathname to output root CA private key [default: ca-key.pem]
      --ca-cert <CA_CERT>         Pathname to output root CA certificate [default: ca-cert.pem]
      --key <KEY>                 Pathname to output web server private key [default: server-key.pem]
      --csr <CSR>                 Pathname to output web server cert signing request (CSR)
      --cert <CERT>               Pathname to output web server certificate [default: server-cert.pem]
      --out-dir <OUT_DIR>         Pathname to the output directory [default: out]
      --[ca|srv]-[detail] <VALUE> Optional details for the CA/server certificate (e.g., --ca-country US)
  -h, --help                      Print help
  -V, --version                   Print version
```

Replace `[detail]` with `country`, `state`, `locality`, `organization`, or `common_name` to specify certificate details for the CA or server.

## Example Invocation

To generate certificates with the default configuration:

```shell
$ cargo run
    Finished dev [unoptimized + debuginfo] target(s) in 0.03s
     Running `target/debug/self-signed-cert`
$ ls out/*.pem
out/ca-cert.pem	out/ca-key.pem	out/server-cert.pem	out/server-key.pem
```

To specify certificate details and output directory:

```shell
$ cargo run -- --ca-country US --ca-state California --ca-organization "My Org" --out-dir custom_certs
```

This will generate the certificates and keys inside the `custom_certs` directory with the specified CA details.
