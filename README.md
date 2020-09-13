# Bawang

An implementation of onion routing in Go.

## Installation

```sh
# build (dependencies are downloaded automatically)
$ go build

# run
$ ./bawang -c <path to config file>
```

## Generating the hostkey

```sh
$ make hostkey
```

## Configuration
An example config file can be found in [config.conf](./config.conf).

All options must be specified in the `[onion]` section.

| Option           | Description                                                     | Default | Required |
|------------------|-----------------------------------------------------------------|---------|----------|
| `hostkey`        | Path to the file containing the host's 4096 bit RSA private key | *none*  | X        |
| `api_address`    | Onion API endpoint address                                      | *none*  | X        |
| `p2p_hostname`   | Host name or IP address the P2P endpoint should listen on       | *none*  | X        |
| `p2p_port`       | Port the P2P endpoint should listen on                          | *none*  | X        |
| `build_timeout`  | Max. time in seconds for building a tunnel before aborting      | 10      |          |
| `api_timeout`    | Max. time in seconds API calls may take before aborting         | 5       |          |
| `verbose`        | Verbosity level. 0 = no informational logging, 2 = max          | 0       |          |
| `tunnel_length`  | Number of hops (peers) an onion tunnel consists of              | 3       |          |
| `round_duration` | Length of a round in seconds                                    | 60      |          |

## Testing

To run the complete test-suite (including formatting check and linters):

```sh
$ make me_sad
```

## Protocol Specification

See [docs/protocol.md](./docs/protocol.md).
