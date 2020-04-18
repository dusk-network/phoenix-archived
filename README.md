# phoenix

[![Build Status](https://travis-ci.com/dusk-network/phoenix.svg?token=czzGwcZEd8hUsCLG3xJC&branch=master)](https://travis-ci.com/dusk-network/phoenix)
[![Repository](https://dusk-network.github.io/phoenix/repo-badge.svg)](https://github.com/dusk-network/phoenix)
[![Documentation](https://dusk-network.github.io/phoenix/badge.svg)](https://dusk-network.github.io/phoenix/phoenix_lib/index.html)

Phoenix is an anonymity-preserving zero-knowledge proof-powered transaction model formalized and developed by Dusk Network.

# General

Although somewhat based on the UTXO model utilized in the [Zcash protocol](https://github.com/zcash/zips/blob/master/protocol/protocol.pdf), Phoenix is uniquely capable to enable privacy-preserving smart contract by allowing confidential spending of public output (gas and coinbase transactions).

Unlike Zcash, in which transactions can be potentially linked [\[1\]](https://arxiv.org/pdf/1712.01210)[\[2\]](https://orbilu.uni.lu/bitstream/10993/39996/1/Zcash_Miner_Linking%20%282%29.pdf), Phoenix guarantees transaction unlinkability through combining the so-called "obfuscated notes" (i.e. outputs containing encrypted values) with "transparent notes" (i.e. outputs containing plain values) into a single Merkle Tree.

All the transactions utilize one-time keys. It is totally up to the user how he wants to manage his secret key: he could have one or many secret keys for many unspent outputs. The inner Diffie-Hellman key exchange randomness mechanism guarantees the note public key will not repeat for the same spender public key, which causes the identification of the spender to be unfeasible.

For further details, check out the technical paper to be published soon.

# Concepts

## Zero-knowledge

Phoenix uses zero-knowledge proofs to guarantee:

* Transaction balance consistency
* Prevent double-spending attacks
* Prove the ownership of unspent outputs

The set of unspent outputs is a union of obfuscated and transparent note sets. Both notes share a similar structure aside from the obfuscated containing encrypted values and transparent notes containing plain values.

The owner of a note can share his/her `View Key`, allowing a third-party (e.g. a wallet provider) to detect the outputs belonging to the owner as well as the value of the encrypted in the note, in case of an obfuscated note.

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
