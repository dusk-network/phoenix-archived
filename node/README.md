# Protocol Documentation - Node

## Table of contents

- [node.proto](#node.proto)
	- [TxType](#txtype)
	- [Tx](#tx)
	- [SelectRequest](#selectrequest)
	- [SelectResponse](#selectresponse)
	- [Methods](#methods)

## node.proto

### TxType

| Name | Number | Description |
| ---- | ------ | ----------- |
| COINBASE | 0 | A coinbase transaction |
| BID | 1 | A bid transaction |
| STAKE | 2 | A stake transaction |
| STANDARD | 3 | A standard transaction |
| TIMELOCK | 4 | A timelock transaction |
| CONTRACT | 5 | A contract transaction |

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
