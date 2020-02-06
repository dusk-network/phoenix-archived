# phoenix

[![Build Status](https://travis-ci.com/dusk-network/phoenix.svg?token=czzGwcZEd8hUsCLG3xJC&branch=master)](https://travis-ci.com/dusk-network/phoenix)
[![Repository](https://dusk-network.github.io/phoenix/repo-badge.svg)](https://github.com/dusk-network/phoenix)
[![Documentation](https://dusk-network.github.io/phoenix/badge.svg)](https://dusk-network.github.io/phoenix/phoenix_lib/index.html)

Phoenix is a zero-knowledge powered anonymous unspent outputs transaction layer that backs up Dusk Network tokens.

# General

Different from standard UTXO models in the wild, Phoenix doesn't require the owner of a note revealing its identity or position to spend it.

Considering that based on the revealed information during a transaction propagation, several well-known attacks compromise the anonymity of a spender, or even allow malicious agents to reverse-engineer the balance of his wallet. Phoenix aims to protect the spender from those attacks.

All the transactions are one-time-key based. It is totally up to the user how he wants to manage his secret key: he could have one or many secret keys for many unspent outputs. The inner Diffie-Hellman key exchange randomness mechanism guarantees the note public key will not repeat for the same spender public key, which causes the identification of the spender to be unfeasible.

For further details, check the [whitepaper](https://dusk.network/).

# Concepts

## Zero-knowledge

Phoenix uses zero-knowledge proofs to guarantee:

* Transaction balance consistency
* Prevent double-spending attacks
* Prove the ownership of unspent outputs

The unspent outputs are instances of `transparent` and `obfuscated` notes. Both notes share a similar structure, but the obfuscated have encrypted values, whereas transparent notes have their value exposed.

The owner of an obfuscated note can share a `View Key` that will allow revealing the value of the note without allowing the spending of that note.

The spending of a note can be done only via a `Secret Key`, known only to the owner of the note.

# Installation

## Requirements

* [Rust Nightly](https://www.rust-lang.org/tools/install)

## Instructions

Clone the github repo

```
$ git clone https://github.com/dusk-network/phoenix.git
$ cd phoenix
```

Test the build

`$ cargo test --release`

Build the binaries

`$ cargo build --release`

# Usage

Phoenix follows a server-client architecture. After performing the installation, you can proceed with the following steps

![phoenix](https://user-images.githubusercontent.com/8730839/73960472-4176e400-490b-11ea-998f-a3cb36bedf8e.gif)

## Server

The `phoenix-server` allows a few options described below

```
USAGE:
    phoenix-server [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -b, --bind <BIND>        Bind the server to listen on the specified address [default: 0.0.0.0:8051]
    -l, --log-level <LOG>    Output log level [default: info]  [possible values: error, warn, info, debug, trace]

SUBCOMMANDS:
    help    Prints this message or the help of the given subcommand(s)
    note    Create a new unspent note on initialization. Usage: note <SEED> <VALUE>
```

* Example

    This will instantiate a new server and create a test obfuscated note for bob with the value of 1500

    `$ ./target/release/phoenix-server -b 127.0.0.1:8051 -l trace note bob 1500`

## Client

To perform transactions, you need to use the client

`$ ./target/release/phoenix-cli`
