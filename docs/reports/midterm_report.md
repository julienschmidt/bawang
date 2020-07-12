# Midterm Report
Midterm Report for Bawang, brought to you by Julien Schmidt and Michael Loipführer.

## Changes to Initial Assumptions
So far we haven't made any substantial changes to our initial assumptions/plans.

## Architecture

### Terminology

Link: Encrypted network connection between two peers. Data for multiple independent tunnels may be transmitted over the same link.

Tunnel: End-to-end onion connection consisting of multiple hops.

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

Similar to the original tor protocol we divide our protocol definition in two parts: control and relay, with the relay part forming its own sub protocol.

The control protocol consists of the messages `TunnelCreate`, `TunnelCreated` and `TunnelDestroy` which are responsible for control communication between two neighboring hops in a tunnel.
The relay sub protocol is used when passing messages through a tunnel and consists of the messages `TunnelExtend`, `TunnelExtended` and `TunnelRelay`.

Connections between hops in a tunnel are secured via standard TLS encryption such that all tunnel protocol commands cannot be deciphered by outside attackers.

When building a tunnel we strictly adhere to the specification, first forming an ephemeral session key with the first hop in the tunnel which we then use to encrypt all further traffic.
This initial handshake is part of our control protocol.
To extend the tunnel we instruct the first hop to build a connection to the next peer in the tunnel with which we then again form an ephemeral session key.
After fully constructing a tunnel data that is to be sent through the tunnel is then encapsulated in a relay message and iteratively encrypted with all ephemeral session keys.
This means that for example a packet to Hop3 in a tunnel consisting of Source, Hop1, Hop2, Hop3 with corresponding ephemeral session keys `K_i` between the Source and Hop i is formed as `TunnelRelay(E_K_1(E_K_2(E_K_3(relay_metadata, data))))` and then sent to the first hop.
Each hop removes on layer of encryption, checks if it should pass the message along and does so if needed.
For a response each hop in turn adds a layer of encryption, meaning the message can only be fully encrypted by the destination as it is the only peer in possession of ephemeral session keys.

For more detail consult sections on each message types and the general protocol flow.

### Message Types

#### `TunnelCreate`
OnionTunnelCreate is sent from peer A to peer B to initiate the creation of tunnel over link between two peers.

#### `TunnelCreated`
OnionTunnelCreated is the response sent from peer B to peer A to confirm the creation of a tunnel initiated with OnionTunnelCreate.

#### `TunnelDestroy`

#### `TunnelExtend`

#### `TunnelExtended`

#### `TunnelRelay`

### Protocol Flow
#### Initial Handshake and Tunnel Extension
~~~ascii
+---------+                                                             +-------+                               +-------+
| Source  |                                                             | Hop1  |                               | Hop2  |
+---------+                                                             +-------+                               +-------+
     |                                                                      |                                       |
     | TunnelCreate (ID_1, E_h1p(g^x1))                                     |                                       |
     |--------------------------------------------------------------------->|                                       |
     |                                                                      |                                       |
     |                                    TunnelCreated (ID_1, g^y1, H(K1)) |                                       |
     |<---------------------------------------------------------------------|                                       |
     |                                                                      |                                       |
     | TunnelExtend(ID1, E_K1(E_h2p(g^x2), addr, port, dest host key))      |                                       |
     |--------------------------------------------------------------------->|                                       |
     |                                                                      |                                       |
     |                                                                      | TunnelCreate (ID2, g^x2)              |
     |                                                                      |-------------------------------------->|
     |                                                                      |                                       |
     |                                                                      |     TunnelCreated (ID2, g^y2, H(K2))  |
     |                                                                      |<--------------------------------------|
     |                                                                      |                                       |
     |                              TunnelExtended(ID1, E_K1(g^y2, H(K2)))  |                                       |
     |<---------------------------------------------------------------------|                                       |
     |                                                                      |                                       |
~~~
To build an onion tunnel we initially generate a diffie hellman key pair with public key `g^x1`.
We encrypt our public key using the identifier public key (host key, `h1p`) of the next hop in our tunnel and send it to said hop.
The next hop in turn generates a diffie hellman key pair and computes the shared diffie hellman key. 
To perform unilateral authentication the next hop hashes the computed shared diffie hellman key and sends it along with its diffie hellman public key back to us.
We then also compute the diffie hellman shared key and verify the hash Hop1 sent to us.
If the hash is valid Hop1 has proven its identity by being able to decrypt our diffie hellman public key using its corresponding hop identifier private key.
Each of the handshake messages contain the tunnel ID used to uniquely identify that connection between hops.

In order to extend the currently existing circuit we make use of our tunnel relay sub protocol.
We send a TunnelExtend message with the relay sub message encrypted by the shared diffie hellman key to Hop1 instructing it to extend the circuit by another hop.
Hop1 decrypts the relay message containing the onion API address/port, the identifier public key of the next hop and a diffie hellman public key similar to the first create message.
It generates a new tunnel ID (ID2) used for the connection between it and then next hop (Hop2) and saves the mapping.
It then constructs a `TunnelCreate` message and performs the create/created handshake with Hop2, sending the diffie hellman public key of Hop2 back to us in a `TunnelCreated` message.

In the above diagram `H()` denotes a secure hash function and `E_abc()` encryption with key `abc`.

#### Data Relaying
~~~ascii
+---------+                                                   +-------+                                              +-------+                                        +-------------+
| Source  |                                                   | Hop1  |                                              | Hop2  |                                        | Destination |
+---------+                                                   +-------+                                              +-------+                                        +-------------+
     |                                                            |                                                      |                                                   |
     | TunnelRelay(ID1, E_k1(E_k2(E_dst(relay_meta, data))))      |                                                      |                                                   |
     |----------------------------------------------------------->|                                                      |                                                   |
     |                                                            |                                                      |                                                   |
     |                                                            | TunnelRelay(ID2, E_k2(E_dst(relay_meta, data)))      |                                                   |
     |                                                            |----------------------------------------------------->|                                                   |
     |                                                            |                                                      |                                                   |
     |                                                            |                                                      | TunnelRelay(ID3, E_dst(relay_meta, data))         |
     |                                                            |                                                      |-------------------------------------------------->|
     |                                                            |                                                      |                                                   |
     |                                                            |                                                      |        TunnelRelay(ID3, E_dst(relay_meta, reply)) |
     |                                                            |                                                      |<--------------------------------------------------|
     |                                                            |                                                      |                                                   |
     |                                                            |     TunnelRelay(ID2, E_k2(E_dst(relay_meta, reply))) |                                                   |
     |                                                            |<-----------------------------------------------------|                                                   |
     |                                                            |                                                      |                                                   |
     |     TunnelRelay(ID1, E_k1(E_k2(E_dst(relay_meta, reply)))) |                                                      |                                                   |
     |<-----------------------------------------------------------|                                                      |                                                   |
     |                                                            |                                                      |                                                   |
~~~
To pass data (or commands) along the tunnel we construct a `TunnelRelay` (or other relay sub protocol messages) message containing our data payload. 
After computing the message digest and embedding it in the message we then encrypt it iteratively using the ephemeral session keys shared with each hop.
When passing the message through the tunnel each hop first decrypts the relay sub protocol part of the message using its session key.
It then checks whether the decrypted digest matches the received message.
If the digest matches the message is destined for the current hop which will then either accept the payload data in case of a `TunnelRelay` message or interpret the relay sub command such as a `TunnelExtend`.
In case the digest does match the decrypted message the hop checks if it can pass the message along the tunnel, meaning if it has stored a tunnel ID mapping passing the message along if one is found.
If no mapping is stored the message is invalid, and the hop will tear down the tunnel by sending `TunnelDestroy` to its adjacent hops.

### Exception Handling
Go already enforces strict and explicit error handling by using an additional return values (of type `error`) in functions.
Thus, we rely on those explicit error values wherever errors can occur, instead of "throwing exceptions" like in Java or Python for example.

TODO error handling definitions

- timeout when establishing a tunnel

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

ML: Michael Loipführer, JS: Julien Schmidt

- P2P Protocol Design: ML, JS
- CI: JS
- P2P Handshake Implementation: ML
- API Protocol Message Parsing and Packing: JS
- API Protocol Logic: ML
- Documentation: ML, JS

## Effort Spent
? (individual effort)

Michael Loipführer: TODO

Julien Schmidt: TODO
