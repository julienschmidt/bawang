package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConnectionSend(t *testing.T) {
	// TODO: test for actual implementation
	var conn Connection
	err := conn.Send(nil)
	require.Nil(t, err)
}

func TestConnectionTerminate(t *testing.T) {
	// TODO: test for actual implementation
	var conn Connection
	err := conn.Terminate()
	require.Nil(t, err)
}
