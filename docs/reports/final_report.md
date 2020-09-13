# Final Report

Midterm Report for Bawang, brought to you by Julien Schmidt and Michael Loipführer.


## Architecture

### Terminology

Link: Encrypted network connection between two peers. Data for multiple independent tunnels may be transmitted over the same link.

Tunnel: End-to-end onion connection consisting of multiple hops.


### Logical Structure

All code handling VoidPhone API protocol messages can be found in the `api` sub-module.
Likewise, there is a `p2p` sub-module containing the code for our P2P onion tunnel protocol.
Both define a general `Message` interface that is implemented for each message type, handling byte packing and unpacking. Implementation of data processing and handling is mainly done by using structs and methods on these structs, similar to the concept of classes in other languages.

The application logic itself is mostly contained in the `onion` sub-module, which implements the data structures (such as `Link`, `Peer`, `Router`) and algorithms handling the p2p onion handshake, connection and routing tracking as well as the tcp/tls-level connections.

Config parsing and option storing is implemented in the sub-module `config` which exposes a struct `Config` containing all configuration parameters.

Communication with the RPS module API is implemented in the sub-module `rps`, exposing a simple interface to fetch one or multiple peers from the RPS API.

The application logic exposing the onion module API interface is implemented in `api.go` which opens a tcp socket and processes incoming API messages.

The main entry point of our module is `bawang.go`, which will start both the API listen socket and our onion listen socket.


### Process Architecture

We mainly make use of goroutines for concurrency, which are a form of green-threads and provide a thread-like interface for async execution. If one goroutine blocks, another goroutine (if available) gets scheduled on the processor. Thus, we do not need to manually spin up an event-loop or keep track of the state. 

As goroutines are very lightweight (compared to OS Threads), we make excessive use of them to enable concurrency. Our two network socket listeners (VoidPhone API, P2P Onion Tunnels) are started in a goroutine each. Further, each VoidPhone API and P2P connection is handled in its own goroutine instead of the "socket goroutine", thus enabling concurrent handling of those.


### Networking

For network layer operations we use standard Go library functions for TLS and TCP connection handling. All connections are handled concurrently in separate goroutines such that those do not block each other.


### Security Measures

We use two layers of authentication and encryption in our P2P protocol.
Connections between hops (links) in our onion tunnels are formed by TLS connections using the peer key as server certificate for authentication.
On top of this link layer we perform authenticated Diffie-Hellman handshakes in our onion tunnel protocol to generate symmetric keys for our onion layer encryption.

For all cryptographic operations we use library functions, mainly from the Go standard library with additional functions for Diffie-Hellman cryptography from the `golang.org/x/crypto` library.

We employ fixed packet size schemes against traffic analysis in two places:
Packets between links are padded to the fixed size of 1024 to prevent information leakage to an outside adversary through the packet sizes.
Likewise, relayed packets (in `TUNNEL RELAY`) have fixed size 1008 (1024 minus the message and relay header sizes) to prevent information leakage to an adversary operating a peer used for the tunnel. Thus, the peer cannot for example derive the number of previous hops from the packet size.

The relay header contains a digest for end-to-end checksum for integrity checking.

To have both replay protection and unique IVs for our AES CTR encryption we use a monotonically increasing counter in our relay sub protocol packets.

### Error Handling

In case of misbehaving peers or network errors we cleanly tear down all tunnels using the affected peer.

#### VoidPhone API

If we receive invalid or malformed data from other VoidPhone components via the API we immediately terminate the connection.


#### P2P Protocol

Our P2P protocol employs TLS for the connection between two hops. If the MAC of a packet does not match, the packet is simply ignored, which might eventually lead to a timeout e.g. in the case of a lost `TUNNEL CREATE` message.

If the digest of relay message does not match and the message cannot be relayed further, it is treated as an invalid message and the tunnel is destroyed immediately.

If a message not adhering to the fixed size scheme is received, the respective sender is assumed broken or malicious and is disconnected immediately.


## Protocol Specification

See [docs/protocol.md](../protocol.md).

### Changes since the Midterm Report

* Added [`TUNNEL RELAY COVER` message](../protocol.md#tunnel-relay-cover), required for cover traffic
* Added a counter to the [Relay Sub Protocol Header](../protocol.md#relay-sub-protocol-header), required for secure encryption but also used for replay protection
* Increased the size of `Encrypted Diffie-Hellman Public Key` to 512 byte in [`TUNNEL CREATE`](../protocol.md#tunnel-create) and [`TUNNEL RELAY EXTENDED`](../protocol.md#tunnel-relay-extended) as 4096 bit RSA has a block size of 512 byte (4096 bit). Consequently, the size of P2P messages had to be increased from 512 byte to 1024 byte to fit the larger message types.


## Setup Instructions

See [README.md](../../README.md).


## Known Issues
- `verbose` config option is ignored.


## Future Work

- Fully integrate the `voidphone_testing` library into our continuous integration testing. We found `voidphone_testing` to be horrible documented and hard / unintuitive to use. We eventually came to the conclusion, that it was not worth the effort to get it running.
- Potentially different underlying network protocols (QUIC / unreliable UDP in addition to TCP)


## Workload Distribution - Who did what

ML: Michael Loipführer, JS: Julien Schmidt

- P2P Protocol Design: ML, JS (jointly)
- P2P Message Parsing and Packing: mostly JS
- P2P Handshake Implementation: ML
- API Message Parsing and Packing: mostly JS
- API Protocol Logic: mostly ML
- Onion Round Logic: JS
- Onion Relay Implementation: mostly ML
- CI: JS
- Documentation: ML, JS (more)


## Effort Spent

We mainly worked together intensively on the project on three weekends (23./24. May, 06./07. June, 10./11. July) and independently on some additional days before the midterm report.
As a final implementation sprint we both worked more intensively on the project during the last week before the submission due date, i.e. from the 7. Sep to 13. Sep. In total, both team members spent a similar effort.
