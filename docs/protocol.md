## Protocol Specification

The Bawang protocol resembles a thinned out and adapted version of the onion protocol used by the TOR project.

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


## Message Types

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


### `TUNNEL CREATE`

~~~ascii
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Tunnel ID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| TUNNEL CREATE |    Version    |      Reserved / Padding       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Encrypted Diffie-Hellman Public Key  (512 byte)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

This message is sent to a peer to initiate our onion protocol handshake.
It includes a version for future proofing our protocol as well as a Diffie-Hellman public key used for ephemeral key derivation.
In order to facilitate unilateral authentication of the next hop with regards to the tunnel's initiator the Diffie-Hellman public key is encrypted using the public identifier key of the next hop.
Since the second message in the handshake requires sending a hash of the derived Diffie-Hellman shared key knowledge of the shared key proves ownership over the private identifier key and therefore authenticates the next hop.


### `TUNNEL CREATED`

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


### `TUNNEL DESTROY`

~~~ascii
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Tunnel ID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| TUNNEL DESTROY|               Reserved / Padding              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

Sent to neighboring hops to initiate tunnel teardown.
When receiving a `TUNNEL DESTROY` message peers will tear down the tunnel and send a new `TUNNEL DESTROY` message to the next hop in the tunnel.


### `TUNNEL RELAY`

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


### Relay Sub Protocol Header

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
|     4 | COVER      |


### `TUNNEL RELAY EXTEND`

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
|        Encrypted Diffie-Hellman Public Key  (512 byte)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

Relay sub protocol message to instruct a hop in the tunnel to extend the tunnel to the peer given by next hop IP address and next hop onion port.
The flag `V` is set to 0 for an IPv4 address as the next hop IP address and to 1 for an IPv6 address.
The encrypted Diffie-Hellman public key will then be packed into a `TUNNEL CREATE` message to initiate a handshake with the next hop.


### `TUNNEL RELAY EXTENDED`

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


### `TUNNEL RELAY DATA`

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

### `TUNNEL RELAY COVER`

~~~ascii
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Tunnel ID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  TUNNEL RELAY |                   Counter                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     COVER     |             Size              |    Reserved   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Digest (8 byte)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Reserved / Padding       |P|      Reserved / Padding       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
We send a relay cover message as tunnel cover traffic.
According to the specification cover traffic is only sent on outgoing random tunnels and then echoed back.
The bit `P` specifies whether this is a Ping or a Pong message, i.e. whether it is the original cover message or the echo.

## Protocol Flow

### Initial Handshake and Tunnel Extension

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


### Data Relaying

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
