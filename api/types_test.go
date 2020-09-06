package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppType(t *testing.T) {
	require.True(t, AppTypeDHT.valid())
	require.True(t, AppTypeGossip.valid())
	require.True(t, AppTypeNSE.valid())
	require.True(t, AppTypeOnion.valid())

	at := AppType(42)
	require.False(t, at.valid())
}
