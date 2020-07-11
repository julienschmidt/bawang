# Midterm Report
Midterm Report for Bawang, brought to you by Julien Schmidt and Michael Loipführer.

## Changes to Initial Assumptions
So far we haven't made any substantial changes to our initial assumptions/plans.

## Architecture

### Logical Structure
Since Go does not have classes, the main approach to structure a Go project is to group corresponding features/functions in files or sub modules.
Implementation of data processing and handling is mainly done by using structs and methods on these structs.

All code that handles protocol messages (parsing and packing) for both our onion protocol and the voidphone API protocol is grouped in the submodule `message`.
We defined a general `Message` interface that is implemented for each message type handling byte packing and unpacking.

Currently, all logic handling our onion protocol is implemented in `onion.go` storing connection and peer data in different structs (`Link`, `Peer`, `Circuit`). We might move this logic to a different submodule.

Config parsing and option storing is implemented in `config.go` which exposes a struct (`Config`) containing all configuration parameters.

Communication with the RPS module API is implemented in `rps.go` exposing a simple interface to fetch a peer from the RPS API.

The main entry point of our module is `bawang.go`, which will start both the API listen socket and our onion listen socket.

### Process Architecture
We mainly make use of goroutines for parallelization. Each incoming/outgoing onion API or voidphone API connection will start a goroutine to handle messages from connected peer.

Additionally, our two network sockets listeners (voidphone API, onion API) are started in a goroutine each.

### Networking
For network layer operations we use standard Go library functions for TLS and TCP connection handling.

### Security Measures
We use two layers of authentication and encryption in our onion protocol.
Connections between hops in our onion circuits are formed by TLS connections using the peer key as server certificate for authentication.
On top of this link layer we perform authenticated Diffie-Hellman handshakes in our onion protocol to generate symmetric keys for our onion layer encryption.

For all cryptographic operations we use library functions, mainly from the go standard library with additional functions for Diffie-Hellman cryptography from the `golang.org/x/crypto` library.

## Protocol
Our onion protocol resembles a thinned out and adapted version of the onion protocol used by the TOR project.

### Messages
We extended the message format defined for the voidphone API with additional message types for our onion protocol.
These are defined as follows:

!!TODO!!

#### `OnionCreate`

#### `OnionCreated`

#### `OnionExtend`

#### `OnionExtended`

#### `OnionPeerRelay`

#### `OnionPeerDestroy`

### Exception Handling
Go already enforces strict and explicit error handling by using an additional return values (of type `error`) in functions.
Thus, we rely on those explicit error values wherever errors can occur, instead of "throwing exceptions" like in Java or Python for example.

TODO error handling definitions

#### Network errors on voidphone API

#### Data errors on voidpohone API
If we receive invalid or malformed data from other voidphone components via the API we immediately terminate the connection.

#### Network errors on link layer
In case of errors on our onion link layer

#### Data errors on the onion layer

## Future Work
- Finish final implementation of our onion protocol
- Integrate onion protocol functions with the API layer
- Fully integrate the voidphone_testing library into our continuous integration testing
- Potentially different underlying network protocols (QUIC / unreliable UDP in addition to TCP)

## Workload Distribution - Who did what
?

## Effort Spent
? (individual effort)
