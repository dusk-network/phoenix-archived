# Protocol Documentation

## Table of Contents

- [field.proto](#field.proto)
    - [CompressedPoint](#phoenix.CompressedPoint)
    - [Nonce](#phoenix.Nonce)
    - [Scalar](#phoenix.Scalar)

- [keys.proto](#keys.proto)
    - [PublicKey](#phoenix.PublicKey)
    - [SecretKey](#phoenix.SecretKey)
    - [ViewKey](#phoenix.ViewKey)

- [note.proto](#note.proto)
    - [DecryptedNote](#phoenix.DecryptedNote)
    - [Idx](#phoenix.Idx)
    - [Note](#phoenix.Note)
    - [Nullifier](#phoenix.Nullifier)
    - [InputOutput](#phoenix.InputOutput)
    - [NoteType](#phoenix.NoteType)

- [phoenix.proto](#phoenix.proto)
    - [DecryptNoteRequest](#phoenix.DecryptNoteRequest)
    - [KeysResponse](#phoenix.KeysResponse)
    - [NullifierRequest](#phoenix.NullifierRequest)
    - [NullifierResponse](#phoenix.NullifierResponse)
    - [NullifierStatusRequest](#phoenix.NullifierStatusRequest)
    - [NullifierStatusResponse](#phoenix.NullifierStatusResponse)
    - [SetFeePkRequest](#phoenix.SetFeePkRequest)
    - [StoreTransactionsRequest](#phoenix.StoreTransactionsRequest)
    - [VerifyTransactionResponse](#phoenix.VerifyTransactionResponse)
    - [VerifyTransactionRootRequest](#phoenix.VerifyTransactionRootRequest)
    - [VerifyTransactionRootResponse](#phoenix.VerifyTransactionRootResponse)
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

### Nonce

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bs | [bytes](#bytes) |  |  |

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

### DecryptedNote

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| note_type | [NoteType](#phoenix.NoteType) |  |  |
| pos | [Idx](#phoenix.Idx) |  |  |
| value | [uint64](#uint64) |  |  |
| io | [InputOutput](#phoenix.InputOutput) |  |  |
| nonce | [Nonce](#phoenix.Nonce) |  |  |
| r_g | [CompressedPoint](#phoenix.CompressedPoint) |  |  |
| pk_r | [CompressedPoint](#phoenix.CompressedPoint) |  |  |
| commitment | [CompressedPoint](#phoenix.CompressedPoint) |  |  |
| blinding_factor | [Scalar](#phoenix.Scalar) |  |  |

### Idx

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pos | [uint64](#uint64) |  |  |

### Note

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| note_type | [NoteType](#phoenix.NoteType) |  |  |
| pos | [Idx](#phoenix.Idx) |  |  |
| io | [InputOutput](#phoenix.InputOutput) |  |  |
| nonce | [Nonce](#phoenix.Nonce) |  |  |
| r_g | [CompressedPoint](#phoenix.CompressedPoint) |  |  |
| pk_r | [CompressedPoint](#phoenix.CompressedPoint) |  |  |
| commitment | [CompressedPoint](#phoenix.CompressedPoint) |  |  |
| encrypted_blinding_factor | [bytes](#bytes) |  |  |
| transparent_value | [uint64](#uint64) |  |  |
| encrypted_value | [bytes](#bytes) |  |  |

### Nullifier

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| h | [Scalar](#phoenix.Scalar) |  |  |

### InputOutput

| Name | Number | Description |
| ---- | ------ | ----------- |
| INPUT | 0 |  |
| OUTPUT | 1 |  |

### NoteType

| Name | Number | Description |
| ---- | ------ | ----------- |
| TRANSPARENT | 0 |  |
| OBFUSCATED | 1 |  |

## phoenix.proto

### DecryptNoteRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| note | [Note](#phoenix.Note) |  |  |
| vk | [ViewKey](#phoenix.ViewKey) |  |  |

### KeysResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| vk | [ViewKey](#phoenix.ViewKey) |  |  |
| pk | [PublicKey](#phoenix.PublicKey) |  |  |

### NullifierRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| note | [Note](#phoenix.Note) |  |  |
| sk | [SecretKey](#phoenix.SecretKey) |  |  |

### NullifierResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nullifier | [Nullifier](#phoenix.Nullifier) |  |  |

### NullifierStatusRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nullifier | [Nullifier](#phoenix.Nullifier) |  |  |

### NullifierStatusResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| unspent | [bool](#bool) |  |  |

### SetFeePkRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| transaction | [Transaction](#phoenix.Transaction) |  |  |
| pk | [PublicKey](#phoenix.PublicKey) |  |  |

### StoreTransactionsRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| transactions | [Transaction](#phoenix.Transaction) | repeated |  |

### VerifyTransactionResponse

### VerifyTransactionRootRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| transaction | [Transaction](#phoenix.Transaction) |  |  |
| root | [Scalar](#phoenix.Scalar) |  |  |

### VerifyTransactionRootResponse

### Phoenix

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Keys | [SecretKey](#phoenix.SecretKey) | [KeysResponse](#phoenix.KeysResponse) |  |
| Nullifier | [NullifierRequest](#phoenix.NullifierRequest) | [NullifierResponse](#phoenix.NullifierResponse) |  |
| NullifierStatus | [NullifierStatusRequest](#phoenix.NullifierStatusRequest) | [NullifierStatusResponse](#phoenix.NullifierStatusResponse) |  |
| FetchNote | [Idx](#phoenix.Idx) | [Note](#phoenix.Note) |  |
| DecryptNote | [DecryptNoteRequest](#phoenix.DecryptNoteRequest) | [DecryptedNote](#phoenix.DecryptedNote) |  |
| VerifyTransaction | [Transaction](#phoenix.Transaction) | [VerifyTransactionResponse](#phoenix.VerifyTransactionResponse) |  |
| VerifyTransactionRoot | [VerifyTransactionRootRequest](#phoenix.VerifyTransactionRootRequest) | [VerifyTransactionRootResponse](#phoenix.VerifyTransactionRootResponse) |  |
| StoreTransactions | [StoreTransactionsRequest](#phoenix.StoreTransactionsRequest) | [Scalar](#phoenix.Scalar) |  |
| SetFeePk | [SetFeePkRequest](#phoenix.SetFeePkRequest) | [Transaction](#phoenix.Transaction) |  |

## transaction.proto

### Transaction

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| inputs | [TransactionInput](#phoenix.TransactionInput) | repeated |  |
| outputs | [TransactionOutput](#phoenix.TransactionOutput) | repeated |  |
| fee | [TransactionOutput](#phoenix.TransactionOutput) |  |  |
| r1cs | [bytes](#bytes) |  |  |
| commitments | [CompressedPoint](#phoenix.CompressedPoint) | repeated |  |

### TransactionInput

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pos | [Idx](#phoenix.Idx) |  |  |
| sk | [SecretKey](#phoenix.SecretKey) |  |  |

### TransactionOutput

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| note | [Note](#phoenix.Note) |  |  |
| pk | [PublicKey](#phoenix.PublicKey) |  |  |
| value | [uint64](#uint64) |  |  |
| blinding_factor | [Scalar](#phoenix.Scalar) |  |  |
