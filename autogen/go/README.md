# Autogen

The `autogen` folder contains the `protoc` transpiled struct binding for different programming languages, with a focus on golang and rustlang

## Go

Following are the golang generated packages:
 - monitor: all structs and services used by the monitoring system to communicate the status of the node, and the consensus in particular
 - node: includes wallet and transaction services, including genesis contract calling preparation and alike
 - rusk: expose rusk functionalities. This is not supposed to be exposed to the public

### Mocking capabilities 

To allow for easy smoke testing of the interconnected components (rusk VM, wallet, node, etc), all golang packages include simple mocking capabilities that would help in defining different behaviours of the RPC services for testing purposes.
