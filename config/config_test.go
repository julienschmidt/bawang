package config

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const configFile = "../config.conf"

func TestConfigFromFile(t *testing.T) {
	file, err := ioutil.TempFile("", "test_config")
	require.Nil(t, err)
	defer os.Remove(file.Name())

	data, err := ioutil.ReadFile(configFile)
	require.Nil(t, err)

	// replace hostkey path
	data = bytes.Replace(data,
		[]byte(" hostkey.pem"),
		[]byte(" ../.testing/hostkey.pem"),
		1)

	err = ioutil.WriteFile(file.Name(), data, 0600)
	require.Nil(t, err)

	config := Config{}
	err = config.FromFile(file.Name())

	assert.Nil(t, err)
}
