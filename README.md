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
$ openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out hostkey.pem
```

## Testing

To run the complete test-suite (including formatting check and linters):

```sh
$ ./make_me_sad.sh
```
