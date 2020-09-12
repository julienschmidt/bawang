package onion

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"bawang/config"
	"bawang/p2p"
	"bawang/rps"
)

func TestEncryptDecryptRelayMsg(t *testing.T) {
	var dhShared1, dhShared2, dhShared3 [32]byte
	_, err := rand.Read(dhShared1[:])
	require.Nil(t, err)
	_, err = rand.Read(dhShared2[:])
	require.Nil(t, err)
	_, err = rand.Read(dhShared3[:])
	require.Nil(t, err)
	peers := []*rps.Peer{
		{DHShared: dhShared1},
		{DHShared: dhShared2},
		{DHShared: dhShared3},
	}
	tunnel := Tunnel{
		Hops: peers,
		ID:   1234,
	}

	payload := []byte("asdf1234")

	relayData := p2p.RelayTunnelData{
		Data: payload,
	}
	prevCounter := uint32(123)
	buf := make([]byte, p2p.MaxSize)
	_, n, err := p2p.PackRelayMessage(buf, prevCounter, &relayData)
	require.Nil(t, err)

	encryptedMsg, err := tunnel.EncryptRelayMsg(buf[:n])
	require.Nil(t, err)

	relayHdr, decryptedMsg, ok, err := tunnel.DecryptRelayMessage(encryptedMsg)
	require.Nil(t, err)
	require.True(t, ok)
	assert.NotNil(t, relayHdr)

	decryptedDataMsg := p2p.RelayTunnelData{}
	err = decryptedDataMsg.Parse(decryptedMsg)
	require.Nil(t, err)
	assert.Equal(t, payload, decryptedDataMsg.Data)
}

func TestGenerateDHKeys(t *testing.T) {
	peerKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.Nil(t, err)

	privDH, encDHPubKey, err := generateDHKeys(&rsa.PublicKey{N: peerKey.N, E: peerKey.E})
	require.Nil(t, err)
	require.NotNil(t, privDH)
	require.NotNil(t, encDHPubKey)

	decDHKey, err := rsa.DecryptPKCS1v15(rand.Reader, peerKey, encDHPubKey[:])
	require.Nil(t, err)
	require.NotNil(t, decDHKey)
	assert.Equal(t, 32, len(decDHKey))
}

func TestHandleTunnelCreate(t *testing.T) {
	peerKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.Nil(t, err)

	privDH, msgCreate, err := CreateTunnelCreate(&rsa.PublicKey{N: peerKey.N, E: peerKey.E})
	require.Nil(t, err)
	require.NotNil(t, privDH)

	cfg := &config.Config{
		HostKey: peerKey,
	}

	dhShared, response, err := HandleTunnelCreate(msgCreate, cfg)
	require.Nil(t, err)
	require.NotNil(t, dhShared)
	require.NotNil(t, response)

	sharedHash := sha256.Sum256(dhShared[:32])
	assert.True(t, bytes.Equal(sharedHash[:], response.SharedKeyHash[:]))
}
