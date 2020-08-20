# Midterm Report

Midterm Report for Bawang, brought to you by Julien Schmidt and Michael Loipführer.


## Changes to Initial Assumptions

So far we haven't made any substantial changes to our initial assumptions/plans.

## Architecture

### Terminology

Link: Encrypted network connection between two peers. Data for multiple independent tunnels may be transmitted over the same link.

Tunnel: End-to-end onion connection consisting of multiple hops.


### Logical Structure

All code handling VoidPhone API protocol messages can be found in the `api` sub-module.
Likewise, there is a `p2p` sub-module containing the code for our P2P onion tunnel protocol.
Both define a general `Message` interface that is implemented for each message type, handling byte packing and unpacking. Implementation of data processing and handling is mainly done by using structs and methods on these structs, similar to the concept of classes in other languages.

The application logic itself is in the main module, grouped into several files:

`onion.go` contains all logic for our onion protocol, like storing connection and peer data in different structs (`Link`, `Peer`, `Tunnel`).
If this grows further in complexity, we might also move it into a sub-module.

Config parsing and option storing is implemented in `config.go` which exposes a struct `Config` containing all configuration parameters.

Communication with the RPS module API is implemented in `rps.go`, exposing a simple interface to fetch a peer from the RPS API.

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
Packets between links are padded to the fixed size of 512 to prevent information leakage to an outside adversary through the packet sizes.
Likewise, relayed packets (in `TUNNEL RELAY`) have fixed size 496 (512 minus the message and relay header sizes) to prevent information leakage to an adversary operating a peer used for the tunnel. Thus, the peer cannot for example derive the number of previous hops from the packet size.

The relay header contains a digest for end-to-end checksum for integrity checking.


## Protocol

Our onion protocol resembles a thinned out and adapted version of the onion protocol used by the TOR project.

Similar to the original TOR protocol we divide our protocol definition in two parts: control and relay, with the relay part forming its own sub protocol.

The control protocol consists of the messages `TUNNEL CREATE`, `TUNNEL CREATED`, `TUNNEL DESTROY` and `TUNNEL RELAY` which are responsible for control communication between two neighboring hops in a tunnel.
The relay sub protocol is used when passing messages through a tunnel (using `TUNNEL RELAY` messages) and consists of the messages `RELAY TUNNEL EXTEND`, `RELAY TUNNEL EXTENDED` and `RELAY TUNNEL DATA`.

Connections between hops (links) in a tunnel are secured via standard TLS encryption such that all tunnel protocol commands cannot be deciphered by outside attackers.

When building a tunnel we strictly adhere to the specification, first forming an ephemeral session key with the first hop in the tunnel which we then use to encrypt all further traffic.
This initial handshake is part of our control protocol.
To extend the tunnel we instruct the first hop to build a connection to the next peer in the tunnel with which we then again form an ephemeral session key.
After fully constructing a tunnel data that is to be sent through the tunnel is then encapsulated in a relay message and iteratively encrypted with all ephemeral session keys.
This means that for example a packet to Hop3 in a tunnel consisting of Source, Hop1, Hop2, Hop3 with corresponding ephemeral session keys `K_i` between the Source and Hop i is formed as `TUNNEL RELAY (E_K_1(E_K_2(E_K_3(relay_metadata, data))))` and then sent to the first hop.
Each hop removes on layer of encryption, checks if it should pass the message along and does so if needed.
For a response each hop in turn adds a layer of encryption, meaning the message can only be fully encrypted by the destination as it is the only peer in possession of ephemeral session keys.

For more detail consult sections on each message type, and the general protocol flow.


### Message Types

Our protocol messages all share the common header:

~~~ascii
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Tunnel ID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    TYPE       |                    ...                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

The header specifies the tunnel ID of the tunnel the message is addressed to and the message type as an unsigned 8 bit integer.

| Value | Message Type   |
|-------|----------------|
|     1 | TUNNEL CREATE  |
|     2 | TUNNEL CREATED |
|     3 | TUNNEL DESTROY |
|     4 | TUNNEL RELAY   |


#### `TUNNEL CREATE`

~~~ascii
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Tunnel ID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| TUNNEL CREATE |    Version    |      Reserved / Padding       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Encrypted Diffie-Hellman Public Key  (32 byte)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

This message is sent to a peer to initiate our onion protocol handshake.
It includes a version for future proofing our protocol as well as a Diffie-Hellman public key used for ephemeral key derivation.
In order to facilitate unilateral authentication of the next hop with regards to the tunnel's initiator the Diffie-Hellman public key is encrypted using the public identifier key of the next hop.
Since the second message in the handshake requires sending a hash of the derived Diffie-Hellman shared key knowledge of the shared key proves ownership over the private identifier key and therefore authenticates the next hop.


#### `TUNNEL CREATED`

~~~ascii
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Tunnel ID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| TUNNEL CREATED|              Reserved / Padding               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     DH Public Key (32 byte)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  DH shared key hash (32 byte)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

`TUNNEL CREATED` is sent as a response to `TUNNEL CREATE` containing the next hops Diffie-Hellman public key for ephemeral key derivation as well as a hash of the derived key proving ownership of the private identifier key.
After receiving the `TUNNEL CREATED` message both peers have derived the ephemeral Diffie-Hellman key used for encryption in our relay sub protocol.


#### `TUNNEL DESTROY`

~~~ascii
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Tunnel ID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| TUNNEL DESTROY|               Reserved / Padding              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

Sent to neighboring hops to initial tunnel teardown.
When receiving a `TUNNEL DESTROY` message peers will tear down the tunnel and send a new `TUNNEL DESTROY` message to the next hop in the tunnel.


#### `TUNNEL RELAY`

~~~ascii
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Tunnel ID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  TUNNEL RELAY |        Encrypted Relay Sub Message ...        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            ... Encrypted Relay Sub Message                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

This message defines the wrapping header around our relay sub protocol which is used when passing data and commands through tunnels across multiple hops.
When passing a relay message to a destination hop the whole relay sub protocol message is iteratively encrypted using the ephemeral session keys shared between the intermediate hops and the source peer.
Each hop receiving a `TUNNEL RELAY` message decrypts the relay sub message and verifies the message digest.
Depending on whether the digest ist valid the hop then forwards the full `TUNNEL RELAY` message with the top most encryption layer removed along the circuit or processes the relay sub message.
For more details consult the section on protocol flow.


#### Relay Sub Protocol Header

~~~ascii
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Tunnel ID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  TUNNEL RELAY |                   Counter                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Relay Type  |             Size              |    Reserved   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Digest (8 byte)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

When constructing a relay message the sender first computes the message digest as a secure hash `H(K)` of the full `TUNNEL RELAY` message including the sub message payload with the digest field initially set to 0.
Afterwards the sender iteratively encrypts the relay sub message with the ephemeral session keys of all intermediate hops on the route to the packet's destination peer.

| Value | Relay Type |
|-------|------------|
|     1 | EXTEND     |
|     2 | EXTENDED   |
|     3 | DATA       |


#### `TUNNEL RELAY EXTEND`

~~~ascii
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Tunnel ID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  TUNNEL RELAY |                   Counter                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    EXTEND     |             Size              |    Reserved   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Digest (8 byte)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Reserved / Padding       |V|      Next Hop Onion Port      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Next Hop IP Address (IPv4 - 32 bits, IPv6 - 128 bits)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Encrypted Diffie-Hellman Public Key  (32 byte)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

Relay sub protocol message to instruct a hop in the tunnel to extend the tunnel to the peer given by next hop IP address and next hop onion port.
The flag `V` is set to 0 for an IPv4 address as the next hop IP address and to 1 for an IPv6 address.
The encrypted Diffie-Hellman public key will then be packed into a `TUNNEL CREATE` message to initiate a handshake with the next hop.


#### `TUNNEL RELAY EXTENDED`

~~~ascii
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Tunnel ID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  TUNNEL RELAY |                   Counter                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   EXTENDED    |             Size              |    Reserved   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Digest (8 byte)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|              Diffie-Hellman Public Key  (32 byte)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  DH shared key hash (32 byte)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

Relays the created message from the next hop back to the original sender of the `TUNNEL EXTEND` message.


#### `TUNNEL RELAY DATA`

~~~ascii
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Tunnel ID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  TUNNEL RELAY |                   Counter                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     DATA      |             Size              |    Reserved   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Digest (8 byte)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Data Payload                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

Relay sub protocol message to finally pass normal data payload along the constructed tunnels.


### Protocol Flow

#### Initial Handshake and Tunnel Extension

~~~ascii
+---------+                                                             +-------+                               +-------+
| Source  |                                                             | Hop1  |                               | Hop2  |
+---------+                                                             +-------+                               +-------+
     |                                                                      |                                       |
     | TUNNEL CREATE (ID_1, E_h1p(g^x1))                                    |                                       |
     |--------------------------------------------------------------------->|                                       |
     |                                                                      |                                       |
     |                                   TUNNEL CREATED (ID_1, g^y1, H(K1)) |                                       |
     |<---------------------------------------------------------------------|                                       |
     |                                                                      |                                       |
     | TUNNEL EXTEND (ID1, E_K1(E_h2p(g^x2), addr, port, dest host key))    |                                       |
     |--------------------------------------------------------------------->|                                       |
     |                                                                      |                                       |
     |                                                                      | TUNNEL CREATE (ID2, g^x2)             |
     |                                                                      |-------------------------------------->|
     |                                                                      |                                       |
     |                                                                      |     TUNNEL CREATED (ID2, g^y2, H(K2)) |
     |                                                                      |<--------------------------------------|
     |                                                                      |                                       |
     |                             TUNNEL EXTENDED (ID1, E_K1(g^y2, H(K2))) |                                       |
     |<---------------------------------------------------------------------|                                       |
     |                                                                      |                                       |
~~~

To build an onion tunnel we initially generate a Diffie-Hellman key pair with public key `g^x1`.
We encrypt our public key using the identifier public key (host key, `h1p`) of the next hop in our tunnel and send it to said hop.
The next hop in turn generates a Diffie-Hellman key pair and computes the shared Diffie-Hellman key.
To perform unilateral authentication the next hop hashes the computed shared Diffie-Hellman key and sends it along with its Diffie-Hellman public key back to us.
We then also compute the Diffie-Hellman shared key and verify the hash Hop1 sent to us.
If the hash is valid Hop1 has proven its identity by being able to decrypt our Diffie-Hellman public key using its corresponding hop identifier private key.
Each of the handshake messages contain the tunnel ID used to uniquely identify that connection between hops.

In order to extend the currently existing circuit we make use of our tunnel relay sub protocol.
We send a TunnelExtend message with the relay sub message encrypted by the shared Diffie-Hellman key to Hop1 instructing it to extend the circuit by another hop.
Hop1 decrypts the relay message containing the onion API address/port, the identifier public key of the next hop and a Diffie-Hellman public key similar to the first create message.
It generates a new tunnel ID (ID2) used for the connection between it and then next hop (Hop2) and saves the mapping.
It then constructs a `TUNNEL CREATE` message and performs the create/created handshake with Hop2, sending the Diffie-Hellman public key of Hop2 back to us in a `TUNNEL CREATED` message.

In the above diagram `H()` denotes a secure hash function and `E_abc()` encryption with key `abc`.


#### Data Relaying

~~~ascii
+---------+                                                   +-------+                                              +-------+                                        +-------------+
| Source  |                                                   | Hop1  |                                              | Hop2  |                                        | Destination |
+---------+                                                   +-------+                                              +-------+                                        +-------------+
     |                                                            |                                                      |                                                   |
     | TUNNEL RELAY (ID1, E_k1(E_k2(E_dst(relay_meta, data))))    |                                                      |                                                   |
     |----------------------------------------------------------->|                                                      |                                                   |
     |                                                            |                                                      |                                                   |
     |                                                            | TUNNEL RELAY (ID2, E_k2(E_dst(relay_meta, data)))    |                                                   |
     |                                                            |----------------------------------------------------->|                                                   |
     |                                                            |                                                      |                                                   |
     |                                                            |                                                      | TUNNEL RELAY (ID3, E_dst(relay_meta, data))       |
     |                                                            |                                                      |-------------------------------------------------->|
     |                                                            |                                                      |                                                   |
     |                                                            |                                                      |      TUNNEL RELAY (ID3, E_dst(relay_meta, reply)) |
     |                                                            |                                                      |<--------------------------------------------------|
     |                                                            |                                                      |                                                   |
     |                                                            |   TUNNEL RELAY (ID2, E_k2(E_dst(relay_meta, reply))) |                                                   |
     |                                                            |<-----------------------------------------------------|                                                   |
     |                                                            |                                                      |                                                   |
     |   TUNNEL RELAY (ID1, E_k1(E_k2(E_dst(relay_meta, reply)))) |                                                      |                                                   |
     |<-----------------------------------------------------------|                                                      |                                                   |
     |                                                            |                                                      |                                                   |
~~~

To pass data (or commands) along the tunnel we construct a `TUNNEL RELAY` (or other relay sub protocol messages) message containing our data payload.
After computing the message digest and embedding it in the message we then encrypt it iteratively using the ephemeral session keys shared with each hop.
When passing the message through the tunnel each hop first decrypts the relay sub protocol part of the message using its session key.
It then checks whether the decrypted digest matches the received message.
If the digest matches the message is destined for the current hop which will then either accept the payload data in case of a `TUNNEL RELAY` message or interpret the relay sub command such as a `TUNNEL EXTEND`.
In case the digest does match the decrypted message the hop checks if it can pass the message along the tunnel, meaning if it has stored a tunnel ID mapping passing the message along if one is found.
If no mapping is stored the message is invalid, and the hop will tear down the tunnel by sending `TUNNEL DESTROY` to its adjacent hops.


### Exception Handling

Go already enforces strict and explicit error handling by using an additional return values (of type `error`) in functions.
Thus, we rely on those explicit error values wherever errors can occur, instead of "throwing exceptions" like in Java or Python for example.


#### VoidPhone API

If we receive invalid or malformed data from other VoidPhone components via the API we immediately terminate the connection.


#### P2P Protocol

Our P2P protocol employs TLS for the connection between two hops. If the MAC of a packet does not match, the packet is simply ignored, which might eventually lead to a timeout e.g. in the case of a lost `TUNNEL CREATE` message.

If the digest of relay message does not match and the message cannot be relayed further, it is treated as an invalid message and the tunnel is destroyed immediately.

If a message not adhering to the fixed size scheme is received, the respective sender is assumed broken or malicious and is disconnected immediately.



## Future Work

- Finish final implementation of our onion protocol
- Integrate onion protocol functions with the API layer
- Fully integrate the `voidphone_testing` library into our continuous integration testing
- Potentially different underlying network protocols (QUIC / unreliable UDP in addition to TCP)


## Workload Distribution - Who did what

ML: Michael Loipführer, JS: Julien Schmidt

- P2P Protocol Design: ML, JS
- Message Parsing and Packing: mostly JS
- P2P Handshake Implementation: ML
- API Protocol Logic: mostly ML
- CI: JS
- Documentation: ML, JS


## Effort Spent

We mainly worked together intensively on the project on three weekends (23./24. May, 06./07. June, 10./11. July) and independently on some additional days. So far, we believe that we both spent enough effort on the project and that the workload was fairly distributed, as the git history confirms.

