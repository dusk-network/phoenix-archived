# Protocol Documentation

## Table of Contents

- [field.proto](#field.proto)
    - [CompressedPoint](#phoenix.CompressedPoint)
    - [Scalar](#phoenix.Scalar)

- [keys.proto](#keys.proto)
    - [PublicKey](#phoenix.PublicKey)
    - [SecretKey](#phoenix.SecretKey)
    - [ViewKey](#phoenix.ViewKey)

- [note.proto](#note.proto)
    - [Idx](#phoenix.Idx)
    - [Note](#phoenix.Note)
    - [NoteType](#phoenix.NoteType)

- [phoenix.proto](#phoenix.proto)
    - [FetchDecryptedNoteRequest](#phoenix.FetchDecryptedNoteRequest)
    - [FetchNoteResponse](#phoenix.FetchNoteResponse)
    - [GetFeeResponse](#phoenix.GetFeeResponse)
    - [KeysResponse](#phoenix.KeysResponse)
    - [SetFeePkRequest](#phoenix.SetFeePkRequest)
    - [SetFeePkResponse](#phoenix.SetFeePkResponse)
    - [StoreTransactionsRequest](#phoenix.StoreTransactionsRequest)
    - [StoreTransactionsResponse](#phoenix.StoreTransactionsResponse)
    - [VerifyTransactionResponse](#phoenix.VerifyTransactionResponse)
    - [VerifyTransactionRootRequest](#phoenix.VerifyTransactionRootRequest)
    - [VerifyTransactionRootResponse](#phoenix.VerifyTransactionRootResponse)
    - [Status](#phoenix.Status)
    - [Phoenix](#phoenix.Phoenix)

- [transaction.proto](#transaction.proto)
    - [Transaction](#phoenix.Transaction)
    - [TransactionInput](#phoenix.TransactionInput)
    - [TransactionOutput](#phoenix.TransactionOutput)

- [Scalar Value Types](#scalar-value-types)

## field.proto

### CompressedPoint

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| y | [bytes](#bytes) |  |  |

### Scalar

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| data | [bytes](#bytes) |  |  |

## keys.proto

### PublicKey

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| a_g | [CompressedPoint](#phoenix.CompressedPoint) |  |  |
| b_g | [CompressedPoint](#phoenix.CompressedPoint) |  |  |

### SecretKey

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| a | [Scalar](#phoenix.Scalar) |  |  |
| b | [Scalar](#phoenix.Scalar) |  |  |

### ViewKey

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| a | [Scalar](#phoenix.Scalar) |  |  |
| b_g | [CompressedPoint](#phoenix.CompressedPoint) |  |  |

## note.proto

### Idx

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pos | [uint64](#uint64) |  |  |

### Note

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| note_type | [NoteType](#phoenix.NoteType) |  |  |
| pos | [Idx](#phoenix.Idx) |  |  |
| value | [uint64](#uint64) |  |  |
| unspent | [bool](#bool) |  |  |
| raw | [bytes](#bytes) |  |  |

### NoteType

| Name | Number | Description |
| ---- | ------ | ----------- |
| TRANSPARENT | 0 |  |
| OBFUSCATED | 1 |  |

## phoenix.proto

### FetchDecryptedNoteRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pos | [Idx](#phoenix.Idx) |  |  |
| vk | [ViewKey](#phoenix.ViewKey) |  |  |

### FetchNoteResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| status | [Status](#phoenix.Status) |  |  |
| note | [Note](#phoenix.Note) |  |  |

### GetFeeResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| fee | [uint64](#uint64) |  |  |

### KeysResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| vk | [ViewKey](#phoenix.ViewKey) |  |  |
| pk | [PublicKey](#phoenix.PublicKey) |  |  |

### SetFeePkRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| transaction | [Transaction](#phoenix.Transaction) |  |  |
| pk | [PublicKey](#phoenix.PublicKey) |  |  |

### SetFeePkResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| status | [Status](#phoenix.Status) |  |  |
| transaction | [Transaction](#phoenix.Transaction) |  |  |

### StoreTransactionsRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| transactions | [Transaction](#phoenix.Transaction) | repeated |  |

### StoreTransactionsResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| status | [Status](#phoenix.Status) |  |  |
| root | [Scalar](#phoenix.Scalar) |  |  |

### VerifyTransactionResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| status | [Status](#phoenix.Status) |  |  |

### VerifyTransactionRootRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| transaction | [Transaction](#phoenix.Transaction) |  |  |
| root | [Scalar](#phoenix.Scalar) |  |  |

### VerifyTransactionRootResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| status | [Status](#phoenix.Status) |  |  |

### Status

| Name | Number | Description |
| ---- | ------ | ----------- |
| OK | 0 |  |
| ERROR | 1 |  |

### Phoenix

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Keys | [SecretKey](#phoenix.SecretKey) | [KeysResponse](#phoenix.KeysResponse) |  |
| FetchNote | [Idx](#phoenix.Idx) | [FetchNoteResponse](#phoenix.FetchNoteResponse) |  |
| FetchDecryptedNote | [FetchDecryptedNoteRequest](#phoenix.FetchDecryptedNoteRequest) | [FetchNoteResponse](#phoenix.FetchNoteResponse) |  |
| VerifyTransaction | [Transaction](#phoenix.Transaction) | [VerifyTransactionResponse](#phoenix.VerifyTransactionResponse) |  |
| VerifyTransactionRoot | [VerifyTransactionRootRequest](#phoenix.VerifyTransactionRootRequest) | [VerifyTransactionRootResponse](#phoenix.VerifyTransactionRootResponse) |  |
| StoreTransactions | [StoreTransactionsRequest](#phoenix.StoreTransactionsRequest) | [StoreTransactionsResponse](#phoenix.StoreTransactionsResponse) |  |
| GetFee | [Transaction](#phoenix.Transaction) | [GetFeeResponse](#phoenix.GetFeeResponse) |  |
| SetFeePk | [SetFeePkRequest](#phoenix.SetFeePkRequest) | [SetFeePkResponse](#phoenix.SetFeePkResponse) |  |

## transaction.proto

### Transaction

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| inputs | [TransactionInput](#phoenix.TransactionInput) | repeated |  |
| outputs | [TransactionOutput](#phoenix.TransactionOutput) | repeated |  |

### TransactionInput

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pos | [Idx](#phoenix.Idx) |  |  |
| sk | [SecretKey](#phoenix.SecretKey) |  |  |

### TransactionOutput

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| note_type | [NoteType](#phoenix.NoteType) |  |  |
| pk | [PublicKey](#phoenix.PublicKey) |  |  |
| value | [uint64](#uint64) |  |  |

## Scalar Value Types

| .proto Type | Notes | C++ Type | Java Type | Python Type |
| ----------- | ----- | -------- | --------- | ----------- |
| double |  | double | double | float |
| float |  | float | float | float |
| int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int |
| int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long |
| uint32 | Uses variable-length encoding. | uint32 | int | int/long |
| uint64 | Uses variable-length encoding. | uint64 | long | int/long |
| sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int |
| sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long |
| fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int |
| fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long |
| sfixed32 | Always four bytes. | int32 | int | int |
| sfixed64 | Always eight bytes. | int64 | long | int/long |
| bool |  | bool | boolean | boolean |
| string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode |
| bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str |
