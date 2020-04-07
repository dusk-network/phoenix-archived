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
    - [Note](#phoenix.Note)
    - [Nullifier](#phoenix.Nullifier)
    - [NoteType](#phoenix.NoteType)

- [phoenix.proto](#phoenix.proto)
    - [DecryptNoteRequest](#phoenix.DecryptNoteRequest)
    - [EchoMethod](#phoenix.EchoMethod)
    - [FetchNoteRequest](#phoenix.FetchNoteRequest)
    - [GenerateSecretKeyRequest](#phoenix.GenerateSecretKeyRequest)
    - [KeysResponse](#phoenix.KeysResponse)
    - [NewTransactionInputRequest](#phoenix.NewTransactionInputRequest)
    - [NewTransactionOutputRequest](#phoenix.NewTransactionOutputRequest)
    - [NewTransactionRequest](#phoenix.NewTransactionRequest)
    - [NullifierRequest](#phoenix.NullifierRequest)
    - [NullifierResponse](#phoenix.NullifierResponse)
    - [NullifierStatusRequest](#phoenix.NullifierStatusRequest)
    - [NullifierStatusResponse](#phoenix.NullifierStatusResponse)
    - [OwnedNotesRequest](#phoenix.OwnedNotesRequest)
    - [OwnedNotesResponse](#phoenix.OwnedNotesResponse)
    - [SetFeePkRequest](#phoenix.SetFeePkRequest)
    - [StoreTransactionsRequest](#phoenix.StoreTransactionsRequest)
    - [StoreTransactionsResponse](#phoenix.StoreTransactionsResponse)
    - [VerifyTransactionResponse](#phoenix.VerifyTransactionResponse)
    - [VerifyTransactionRootRequest](#phoenix.VerifyTransactionRootRequest)
    - [VerifyTransactionRootResponse](#phoenix.VerifyTransactionRootResponse)
    - [Phoenix](#phoenix.Phoenix)

- [rusk.proto](#rusk.proto)
    - [Provisioner](#phoenix.Provisioner)
    - [EchoRequest](#phoenix.EchoRequest)
    - [EchoResponse](#phoenix.EchoResponse)
    - [ValidateStateTransitionRequest](#phoenix.ValidateStateTransitionRequest)
    - [ValidateStateTransitionResponse](#phoenix.ValidateStateTransitionResponse)
    - [DistributeRequest](#phoenix.DistributeRequest)
    - [DistributeResponse](#phoenix.DistributeResponse)
    - [WithdrawRequest](#phoenix.WithdrawRequest)
    - [WithdrawResponse](#phoenix.WithdrawResponse)
    - [Rusk](#phoenix.Rusk)

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
| pos | [fixed64](#fixed64) |  |  |
| value | [fixed64](#fixed64) |  |  |
| nonce | [Nonce](#phoenix.Nonce) |  |  |
| r_g | [CompressedPoint](#phoenix.CompressedPoint) |  |  |
| pk_r | [CompressedPoint](#phoenix.CompressedPoint) |  |  |
| value_commitment | [Scalar](#phoenix.Scalar) |  |  |
| blinding_factor | [Scalar](#phoenix.Scalar) |  |  |
| transparent_blinding_factor | [Scalar](#phoenix.Scalar) |  |  |
| encrypted_blinding_factor | [bytes](#bytes) |  |  |
| transparent_value | [fixed64](#fixed64) |  |  |
| encrypted_value | [bytes](#bytes) |  |  |

### Note

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| note_type | [NoteType](#phoenix.NoteType) |  |  |
| pos | [fixed64](#fixed64) |  |  |
| nonce | [Nonce](#phoenix.Nonce) |  |  |
| r_g | [CompressedPoint](#phoenix.CompressedPoint) |  |  |
| pk_r | [CompressedPoint](#phoenix.CompressedPoint) |  |  |
| value_commitment | [Scalar](#phoenix.Scalar) |  |  |
| transparent_blinding_factor | [Scalar](#phoenix.Scalar) |  |  |
| encrypted_blinding_factor | [bytes](#bytes) |  |  |
| transparent_value | [fixed64](#fixed64) |  |  |
| encrypted_value | [bytes](#bytes) |  |  |

### Nullifier

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| h | [Scalar](#phoenix.Scalar) |  |  |

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

### EchoMethod

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| m | [string](#string) |  |  |

### FetchNoteRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pos | [fixed64](#fixed64) |  |  |

### GenerateSecretKeyRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| b | [bytes](#bytes) |  |  |

### KeysResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| vk | [ViewKey](#phoenix.ViewKey) |  |  |
| pk | [PublicKey](#phoenix.PublicKey) |  |  |

### NewTransactionInputRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pos | [fixed64](#fixed64) |  |  |
| sk | [SecretKey](#phoenix.SecretKey) |  |  |

### NewTransactionOutputRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| note_type | [NoteType](#phoenix.NoteType) |  |  |
| pk | [PublicKey](#phoenix.PublicKey) |  |  |
| value | [fixed64](#fixed64) |  |  |

### NewTransactionRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| inputs | [TransactionInput](#phoenix.TransactionInput) | repeated |  |
| outputs | [TransactionOutput](#phoenix.TransactionOutput) | repeated |  |
| fee | [fixed64](#fixed64) |  |  |

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

### OwnedNotesRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| vk | [ViewKey](#phoenix.ViewKey) |  |  |
| notes | [Note](#phoenix.Note) | repeated |  |

### OwnedNotesResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| notes | [DecryptedNote](#phoenix.DecryptedNote) | repeated |  |

### SetFeePkRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| transaction | [Transaction](#phoenix.Transaction) |  |  |
| pk | [PublicKey](#phoenix.PublicKey) |  |  |

### StoreTransactionsRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| transactions | [Transaction](#phoenix.Transaction) | repeated |  |

### StoreTransactionsResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| notes | [Note](#phoenix.Note) | repeated |  |
| root | [Scalar](#phoenix.Scalar) |  |  |

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
| Echo | [EchoMethod](#phoenix.EchoMethod) | [EchoMethod](#phoenix.EchoMethod) |  |
| GenerateSecretKey | [GenerateSecretKeyRequest](#phoenix.GenerateSecretKeyRequest) | [SecretKey](#phoenix.SecretKey) |  |
| Keys | [SecretKey](#phoenix.SecretKey) | [KeysResponse](#phoenix.KeysResponse) |  |
| Nullifier | [NullifierRequest](#phoenix.NullifierRequest) | [NullifierResponse](#phoenix.NullifierResponse) |  |
| NullifierStatus | [NullifierStatusRequest](#phoenix.NullifierStatusRequest) | [NullifierStatusResponse](#phoenix.NullifierStatusResponse) |  |
| FetchNote | [FetchNoteRequest](#phoenix.FetchNoteRequest) | [Note](#phoenix.Note) |  |
| DecryptNote | [DecryptNoteRequest](#phoenix.DecryptNoteRequest) | [DecryptedNote](#phoenix.DecryptedNote) |  |
| OwnedNotes | [OwnedNotesRequest](#phoenix.OwnedNotesRequest) | [OwnedNotesResponse](#phoenix.OwnedNotesResponse) |  |
| FullScanOwnedNotes | [ViewKey](#phoenix.ViewKey) | [OwnedNotesResponse](#phoenix.OwnedNotesResponse) |  |
| NewTransactionInput | [NewTransactionInputRequest](#phoenix.NewTransactionInputRequest) | [TransactionInput](#phoenix.TransactionInput) |  |
| NewTransactionOutput | [NewTransactionOutputRequest](#phoenix.NewTransactionOutputRequest) | [TransactionOutput](#phoenix.TransactionOutput) |  |
| NewTransaction | [NewTransactionRequest](#phoenix.NewTransactionRequest) | [Transaction](#phoenix.Transaction) |  |
| SetFeePk | [SetFeePkRequest](#phoenix.SetFeePkRequest) | [Transaction](#phoenix.Transaction) |  |
| VerifyTransaction | [Transaction](#phoenix.Transaction) | [VerifyTransactionResponse](#phoenix.VerifyTransactionResponse) |  |
| VerifyTransactionRoot | [VerifyTransactionRootRequest](#phoenix.VerifyTransactionRootRequest) | [VerifyTransactionRootResponse](#phoenix.VerifyTransactionRootResponse) |  |
| StoreTransactions | [StoreTransactionsRequest](#phoenix.StoreTransactionsRequest) | [StoreTransactionsResponse](#phoenix.StoreTransactionsResponse) |  |

## rusk.proto

### Provisioner

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| address | [bytes](#bytes) | | Address of a provisioner |

### EchoRequest

### EchoResponse

### ValidateStateTransitionRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| txs | [Transaction](#phoenix.Transaction) | repeated | List of transactions to be validated |

### ValidateStateTransitionResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| success | [bool](#bool) |  | Status of the state transition |

### DistributeRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| total_reward | [fixed64](#fixed64) | | Total reward to be distributed from the block reward and fee. |
| addresses | [Provisioner](#phoenix.Provisioner) | repeated | Addresses of provisioners who helped to finalize the block. |
| pk | [PublicKey](#phoenix.PublicKey) | | Public key of the block generator, who generated the winning block. |

### DistributeResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| success | [bool](#bool) |  | Status of the distribution request |

### WithdrawRequest

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| signature | [Transaction](#phoenix.Transaction) | repeated | An Ed25519 signature of the `address`, and a `nonce`. |
| address | [Transaction](#phoenix.Transaction) | repeated | The BLS public key of the provisioner who wishes to withdraw their funds. |
| value | [Transaction](#phoenix.Transaction) | repeated | The amount of funds to withdraw. |
| pk | [PublicKey](#phoenix.PublicKey) | | Public key of the provisioner who wishes to withdraw their funds. |

### WithdrawResponse

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| success | [bool](#bool) |  | Status of the withdraw request |

### Rusk

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Echo | [EchoRequest](#phoenix.EchoRequest) | [EchoResponse](#phoenix.EchoResponse) | Simple echo request |
| ValidateStateTransition | [ValidateStateTransitionRequest](#phoenix.ValidateStateTransitionRequest) | [ValidateStateTransitionResponse](#phoenix.ValidateStateTransitionResponse) | Validate a set of transactions, returning false if at least one of the listed transactions is inconsistent |

## transaction.proto

### Transaction

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nullifiers | [Nullifier](#phoenix.Nullifier) | repeated |  |
| outputs | [TransactionOutput](#phoenix.TransactionOutput) | repeated |  |
| fee | [TransactionOutput](#phoenix.TransactionOutput) |  |  |
| proof | [bytes](#bytes) |  |  |
| public_inputs | [Scalar](#phoenix.Scalar) | repeated |  |

### TransactionInput

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| pos | [fixed64](#fixed64) |  |  |
| sk | [SecretKey](#phoenix.SecretKey) |  |  |

### TransactionOutput

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| note | [Note](#phoenix.Note) |  |  |
| pk | [PublicKey](#phoenix.PublicKey) |  |  |
| value | [fixed64](#fixed64) |  |  |
| blinding_factor | [Scalar](#phoenix.Scalar) |  |  |
