# Protocol Documentation - Monitor

## Table of contents

- [monitor.proto](#monitor.proto)
	- [Level](#level)
	- [Field](#field)
	- [ErrorAlert](#erroralert)
	- [SemverRequest](#semverrequest)
	- [SlowdownAlert](#slowdownalert)
	- [BlockUpdate](#blockupdate)
	- [EmptyRequest](#emptyrequest)
	- [EmptyResponse](#emptyresponse)

## monitor.proto

### Level

| Name | Number | Description |
| ---- | ------ | ----------- |
| WARN | 0 | Identifyh a warning |
| ERROR | 1 | Identify an error |
| FATAL | 2 | Identify a fatal error |
| PANIC | 3 | Identify a panic |

### Field

| Field | Type | Description |
| ----- | ---- | ----------- |
| field | string | Identifier for an arbitrary log field |
| value | string | string encoded payload of an arbitrary field |

### ErrorAlert

| Field | Type | Description |
| ----- | ---- | ----------- |
| level | [Leve](#leve) | The log level set for this alert |
| msg | string | The text message carried by the alert |
| timestampMillis | string | Hex-encoded hash of the transaction that the caller wants to see |
| file | string | File name where the error was generated (can be empty) |
| line | uint32 | Line number where the error was triggered (0 means no line available) |
| function | string | Name of the function where the error was triggered (can be null) |
| fields | [Field](#field) (repeated) | An array of fields added by the user to the log entry |

### SemverRequest

| Field | Type | Description |
| ----- | ---- | ----------- |
| major  | uint32 | Major part of the version according to [semantic versioning requirements](https://semver.org/)|
| minor  | uint32 | Minor part of the version according to [semantic versioning requirements](https://semver.org/)|
| patch  | uint32 | Patch part of the version according to [semantic versioning requirements](https://semver.org/)|

### SlowdownAlert

| Field | Type | Description |
| ----- | ---- | ----------- |
| timeSinceLastBlockSec  | uint32 | Amount of seconds since the last block was produced |
| lastKnownHeight  | uint64 | Height of last known block |
| lastKnownHash | bytes | Hash of the last known block |

###  BlockUpdate 
| Field | Type | Description |
| ----- | ---- | ----------- |
| height |uint64| Block height |
| hash | bytes| Block Hash | 
| timestamp | int64 | Unix timestamp - amount of seconds from 1st of January 1970 |
| txAmount | uint32 | Amount of transactions in the block |
| blockTimeSec | uint32| Time taken to accept the block |

### EmptyRequest

| Field | Type | Description |
| ----- | ---- | ----------- |

Just an empty message, for requests that do not need parameters.

### EmptyRequest

| Field | Type | Description |
| ----- | ---- | ----------- |

Just an empty message, for responses that carry only the status code

### Methods

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ----------- |
| Hallo | [EmptyRequest](#emptyrequest) | [EmptyResponse](#emptyresponse) | Notifies that the client has started |
| Bye | [EmptyRequest](#emptyrequest) | [EmptyResponse](#emptyresponse) | Notifies that the client is halting |
| NotifyBlock | [BlockUpdate](#blockupdate) | [EmptyResponse](#emptyresponse) | Notifies that a new block has been successfully finalized |
| NotifySlowdown | [SlowdownAlert](#slowdownalert) | [EmptyResponse](#emptyresponse) | Notifies that the consensus has slowed down in producing a Block. This is a potential symptom that we incurred into problems |
| NotifyError | [ErrorAlert](#erroralert) | [EmptyResponse](#emptyresponse) | Notifies that an error log entry has been encountered on the node |
