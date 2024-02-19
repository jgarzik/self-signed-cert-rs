
# self-signed-cert

## Introduction

A command line tool to generate self-signed web server TLS certificates,
for use in testing.

## Usage

The CLI interface is described via `--help`:
```
$ cargo run -- --help
    Finished dev [unoptimized + debuginfo] target(s) in 0.03s
     Running `target/debug/self-signed-cert --help`
Tool to generate self-signed root CA, web server certs and keys

Usage: self-signed-cert [OPTIONS]

Options:
      --ca-key <CA_KEY>    Pathname to output root CA private key [default: ca-key.pem]
      --ca-cert <CA_CERT>  Pathname to output root CA certificate [default: ca-cert.pem]
      --key <KEY>          Pathname to output web server private key [default: server-key.pem]
      --csr <CSR>          Pathname to output web server cert signing request (CSR) [default: ]
      --cert <CERT>        Pathname to output web server certificate [default: server-cert.pem]
  -h, --help               Print help
  -V, --version            Print version

```

## Example invocation

```
$ cargo run
    Finished dev [unoptimized + debuginfo] target(s) in 0.03s
     Running `target/debug/self-signed-cert`
$ ls *.pem
ca-cert.pem	ca-key.pem	server-cert.pem	server-key.pem
```

