# dusk-protobuf

This repository contains the definition of the protobuf messages and RPC exposed by the components of the Dusk Network stack.

 - [node](node/README.md) services are normally called by user-facing components such as the CLI wallet, the desktop wallet
 - [rusk](rusk/README.md) includes definition of Rusk VM services as well as cryptographic primitives implemented in rustlang. These services are meant to be called by the components bundled within the node, like consensus, the mempool, the chain and transactor. As such, these RPCs are not exposed to the internet, but proxied by the node process
 - [monitor](monitor/README.md) defines the messages, services and structures collected by a remote monitor for alarms and performance tracking
