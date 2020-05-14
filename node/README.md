# Protocol Documentation - Node

## Table of contents

- [node.proto](#node.proto)
	- [TxType](#txtype)
	- [Tx](#tx)
	- [SelectRequest](#selectrequest)
	- [SelectResponse](#selectresponse)
	- [Methods](#methods)
- [wallet.proto](#wallet.proto)
    - [TxRecord](#txrecord)

## node.proto

### TxType

| Name | Number | Description |
| ---- | ------ | ----------- |
| STANDARD | 0 | A standard transaction which can be also a generic smart contract call|
| DISTRIBUTE | 1 | Coinbase transaction (Reserved for the BlockGenerator) |
| WITHDRAWFEES | 2 | WithdrawFee transaction (reserved for the Provisioner)|
| BID | 3 | Bid transaction to enable block generations |
| STAKE | 4 | Stake transaction to become a Provisioner |
| SLASH | 5 | Slash the Stake of a malicious Provisioner (reserved for the Provisioner committee) |
| WITHDRAWSTAKE | 6 | Used by the Provisioner to withdraw stakes |
| WITHDRAWBID | 7 | Used by the BlockGenerator to withdraw her blind bid |

### Tx

| Field | Type | Description |
| ----- | ---- | ----------- |
| type | [TxType](#txtype) | Identifier for the type of transaction |
| id | string | Hex-encoded hash of the transaction |
| lock_time | fixed64 | The amount of blocks the transaction will be locked up for upon acceptance |

### SelectRequest

| Field | Type | Description |
| ----- | ---- | ----------- |
| types | [TxType](#txtype) (repeated) | Types of transactions that the caller wishes to receive |
| id | string | Hex-encoded hash of the transaction that the caller wants to see |

### SelectResponse

| Field | Type | Description |
| ----- | ---- | ----------- |
| result | [Tx](#Tx) (repeated) | Selected transactions |

### Methods

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ----------- |
| SelectTx | [SelectRequest](#selectrequest) | [SelectResponse](#selectresponse) | Request an overview of the node's mempool. Can be filtered to only include specific transactions, based on the parameters given |

## wallet.proto

### TxRecord

| Field | Type | Description |
| ----- | ---- | ----------- |
| height | fixed64 | blockheight | 
| direction | Direction | direction of the transaction (0 Incoming, 1 Outgoing) | 
| timestamp | int64 | timestamp of the transaction| 
| type | [TxType](#txtype) | type of of the transaction | 
| amount | fixed64 | sum of all the outputs of the transaction | 
| fee | fixed64 | fee paid | 
| unlockHeight | fixed64 | timelock of the transaction| 
| hash | bytes | hash of the transaction | 
| data | bytes | encoded inputs of the smart contract call | 
| obfuscated | bool | whether the transaction has obfuscated outputs | 
