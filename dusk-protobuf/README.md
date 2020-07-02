# dusk-protobuf


This repository contains the definition of the protobuf messages and RPC exposed by the components of the Dusk Network stack.

 - [node](node/README.md) services are normally called by user-facing components such as the CLI wallet, the desktop wallet
 - [rusk](rusk/README.md) includes definition of Rusk VM services as well as cryptographic primitives implemented in rustlang. These services are meant to be called by the components bundled within the node, like consensus, the mempool, the chain and transactor. As such, these RPCs are not exposed to the internet, but proxied by the node process
 - [monitor](monitor/README.md) defines the messages, services and structures collected by a remote monitor for alarms and performance tracking

## Autogen

The `autogen` folder contains the `protoc` transpiled struct bindings for different programming languages, with a focus on golang. To regenerate all the bindings it is enough to launch the following command from the project root:

```
$ make
```

### Go

Following are the golang generated packages:
 - monitor: all structs and services used by the monitoring system to communicate the status of the node, and the consensus in particular
 - node: includes wallet and transaction services, including genesis contract calling preparation and alike
 - rusk: expose rusk functionalities. This is not supposed to be exposed to the public

This will also regenerate the mocks

#### Mocking capabilities 

To allow for easy smoke testing of the interconnected components (rusk VM, wallet, node, etc), all golang packages include simple mocking capabilities that would help in defining different behaviours of the RPC services for testing purposes.

In general it is not needed to re-generate the mocks, but in case it would be needed, it is enough to type the following:

```
$ make mock
```