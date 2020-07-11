# Midterm Report
Midterm Report for Bawang, brought to you by Julien Schmidt and Michael Loipführer. 

## Changes to Initial Assumptions
So far we haven't made any substantial changes to our initial assumptions/plans.

## Architecture
### Logical Structure
Since go does not have classes the main approach to structure a go project is grouping corresponding features/functions in files or sub modules.
Implementation of data processing and handling is mainly done by using structs and struct methods.

We grouped all of our code that handles protocol message parsing both for our onion protocol, and the voidphone API protocol in the go submodule `message`.
We defined a general `Message` interface that is implemented for each message type handling byte packing and unpacking.

Communication with the RPS module API is implemented in `rps.go` exposing a simple interface to fetch a peer from the RPS API.

Config parsing and option storing is implemented in `config.go` which exposes a struct (`Config`) containing all configuration parameters.

Currently, all logic handling our onion protocol is implemented in `onion.go` storing connection and peer data in different structs (`Link`, `Peer`, `Circuit`). We might move this logic to a different submodule.

The main entrypoint of our module is `bawang.go` which will start both the API listen socket and our onion listen socket.

### Process Architecture
We mainly make use of goroutines for parallelization. Each incoming/outgoing onion API or voidphone API connection will start a goroutine to handle messages from connected peer.

Additionally, our two network sockets listeners (voidphone API, onion API) are started in a goroutine each.

### Networking
For network layer operations we use standard go library functions for tls and tcp connection handling.

### Security Measures
For all cryptographic operations we use library functions, mainly from the go standard library with additional functions for diffie hellman cryptography from the `golang.org/x/crypto` library.

We use two layers of authentication and encryption in our onion protocol.
Connections between hops in our onion circuits are formed by TLS connections using the peer key as server certificate for authentication.
On top of this link layer we perform authenticated diffie hellman handshakes in our onion protocol to generate symmetric keys for our onion layer encryption.

## Protocol
Our Onion protocol represents a thinned out and adapted version of the onion protocol used by the tor project.

### Messages
We extended the message format defined for the voidphone API with additional message types for our onion protocol.
These are defined as follows:

!!TODO!!

OnionCreate
OnionCreated
OnionExtend
OnionExtended
OnionPeerRelay
OnionPeerDestroy

### Exception Handling
Since go already has a very strict built in exception handling using an additional return value (of type `error`) in functions that can throw exceptions we simply adhere to go standards to handle exceptions.

TODO error handling definitions
- Network errors on voidphone API
- Data errors on voidpohone API
If we receive invalid or malformatted data from other voidphone components via the API we immediately terminate the connection.

- Network errors on link layer
In case of errors on our onion link layer
- Data errors on the onion layer

## Future Work
- finish final implementation of our onion protocol
- integrate onion protocol functions with the api layer
- fully integrate the voidphone_testing library into our ci testing
- potentially different underlying network protocols (udp/quick in addition to tcp)

## Workload Distribution - Who did what
?

## Effort Spent
? (individual effort)