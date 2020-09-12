package config

import (
	"bytes"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const configFile = "../config.conf"

func fixHostKeyPath(data []byte) []byte {
	// replace hostkey path
	return bytes.Replace(data,
		[]byte(" hostkey.pem"),
		[]byte(" ../.testing/hostkey.pem"),
		1)
}

func prepareConfigFile(t *testing.T, modifierFunc func([]byte) []byte) (fileName string) {
	file, err := ioutil.TempFile("", "test_config")
	require.Nil(t, err)
	fileName = file.Name()

	data, err := ioutil.ReadFile(configFile)
	require.Nil(t, err)

	if modifierFunc != nil {
		data = modifierFunc(data)
	}

	err = ioutil.WriteFile(fileName, data, 0600)
	require.Nil(t, err)

	return fileName
}

func TestConfigFromFile(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fileName := prepareConfigFile(t, fixHostKeyPath)
		defer os.Remove(fileName)

		config := Config{}
		err := config.FromFile(fileName)
		require.Nil(t, err)
	})

	t.Run("unreadable", func(t *testing.T) {
		config := Config{}
		err := config.FromFile("nope")
		require.NotNil(t, err)
	})

	t.Run("missing hostkey entry", func(t *testing.T) {
		fileName := prepareConfigFile(t, func(data []byte) []byte {
			// replace hostkey path
			return bytes.Replace(data,
				[]byte(" hostkey.pem"),
				[]byte(""),
				1)
		})
		defer os.Remove(fileName)

		config := Config{}
		err := config.FromFile(fileName)
		require.Equal(t, err, errMissingHostKey)
	})

	t.Run("invalid hostkey entry", func(t *testing.T) {
		fileName := prepareConfigFile(t, func(data []byte) []byte {
			// replace hostkey path
			return bytes.Replace(data,
				[]byte(" hostkey.pem"),
				[]byte(" nope"),
				1)
		})
		defer os.Remove(fileName)

		config := Config{}
		err := config.FromFile(fileName)
		require.NotNil(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "could not read host key file"))
	})

	t.Run("invalid hostkey file", func(t *testing.T) {
		fileName := prepareConfigFile(t, func(data []byte) []byte {
			// replace hostkey path
			return bytes.Replace(data,
				[]byte(" hostkey.pem"),
				[]byte(" "+configFile),
				1)
		})
		defer os.Remove(fileName)

		config := Config{}
		err := config.FromFile(fileName)
		require.Equal(t, errInvalidHostKeyPem, err)
	})

	t.Run("missing hostname entry", func(t *testing.T) {
		fileName := prepareConfigFile(t, func(data []byte) []byte {
			// replace hostkey path
			return bytes.Replace(fixHostKeyPath(data),
				[]byte("p2p_hostname = 127.0.0.1"),
				[]byte("p2p_hostname = "),
				1)
		})
		defer os.Remove(fileName)

		config := Config{}
		err := config.FromFile(fileName)
		require.Equal(t, errMissingHostname, err)
	})

	t.Run("missing port entry", func(t *testing.T) {
		fileName := prepareConfigFile(t, func(data []byte) []byte {
			// replace hostkey path
			return bytes.Replace(fixHostKeyPath(data),
				[]byte("p2p_port = 6602"),
				[]byte("p2p_port = "),
				1)
		})
		defer os.Remove(fileName)

		config := Config{}
		err := config.FromFile(fileName)
		require.Equal(t, errMissingPort, err)
	})
}

func TestParseHostKey(t *testing.T) {
	key, err := parseHostKey([]byte(`
-----BEGIN Type-----
FAIL
-----END Type-----
`))
	require.Equal(t, errUnknownKeyType, err)
	require.Nil(t, key)

	key, err = parseHostKey([]byte(`
-----BEGIN RSA PRIVATE KEY-----
FAIL
-----END RSA PRIVATE KEY-----
`))
	require.NotNil(t, err)
	require.True(t, strings.HasPrefix(err.Error(), "invalid hostkey:"))
	require.Nil(t, key)

	key, err = parseHostKey([]byte(`
-----BEGIN PRIVATE KEY-----
FAIL
-----END PRIVATE KEY-----
`))
	require.NotNil(t, err)
	require.True(t, strings.HasPrefix(err.Error(), "invalid hostkey:"))
	require.Nil(t, key)

	// Ed25519 private key in PKCS8 (not allowed here)
	key, err = parseHostKey([]byte(`
-----BEGIN PRIVATE KEY-----
MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB
Z9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PRIVATE KEY-----
`))
	require.NotNil(t, err)
	require.True(t, strings.HasPrefix(err.Error(), "invalid hostkey:"))
	require.Nil(t, key)

	// valid RSA priv key
	key, err = parseHostKey([]byte(`
-----BEGIN RSA PRIVATE KEY-----
MIGrAgEAAiEAiIvpHniTWgmpxWOLLwHiOmJbzLV1VF1QsUBUw7vO6A0CAwEAAQIh
AIYQICTLq5jWLfpgPrI7fjn3KbrXsDbs6/3wWnCD3iWdAhEAwWp3JQKvqBivex3s
oO/NmwIRALS6sVkJzVYZkEbbm8uiz3cCEQCtgDiyrY8vBj3b/kL3N0ZDAhBH4lX1
90sf6u0S8fiGx4xDAhAwlDAZP8HmxXKZQjcyFvGN
-----END RSA PRIVATE KEY-----
`))
	require.Nil(t, err)
	require.NotNil(t, key)

}
