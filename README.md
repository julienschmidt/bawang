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

## Testing

To run the complete test-suite (including formatting check and linters):

```sh
$ make me_sad
```
