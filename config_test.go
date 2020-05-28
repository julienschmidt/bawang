package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConfig_FromFile(t *testing.T) {
	config := Config{}
	err := config.FromFile("config.conf")

	assert.Nil(t, err)
}
