// Package api provides types and helper functions to send and receive API messages.
package api

type Type uint16

const (
	TypeGossipAnnounce     Type = 500
	TypeGossipNotify       Type = 501
	TypeGossipNotification Type = 502
	TypeGossipValidation   Type = 503
	// gossip reserved until 519

	TypeNSEQuery    Type = 520
	TypeNSEEstimate Type = 521
	// NSE reserved until 539

	TypeRPSQuery Type = 540
	TypeRPSPeer  Type = 541
	// RPS reserved until 559

	TypeOnionTunnelBuild    Type = 560
	TypeOnionTunnelReady    Type = 561
	TypeOnionTunnelIncoming Type = 562
	TypeOnionTunnelDestroy  Type = 563
	TypeOnionTunnelData     Type = 564
	TypeOnionError          Type = 565
	TypeOnionCover          Type = 566
	// Onion reserved until 599

	TypeAuthSessionStart       Type = 600
	TypeAuthSessionHS1         Type = 601
	TypeAuthSessionIncomingHS1 Type = 602
	TypeAuthSessionHS2         Type = 603
	TypeAuthSessionIncomingHS2 Type = 604
	TypeAuthLayerEncrypt       Type = 605
	TypeAuthLayerDecrypt       Type = 606
	TypeAuthLayerEncryptResp   Type = 607
	TypeAuthLayerDecryptResp   Type = 608
	TypeAuthSessionClose       Type = 609
	TypeAuthError              Type = 610
	TypeAuthCipherEncrypt      Type = 611
	TypeAuthCipherEncryptResp  Type = 612
	TypeAuthCipherDecrypt      Type = 613
	TypeAuthCipherDecryptResp  Type = 614
	// Onion Auth reserved until 649

	DHTPut     Type = 650
	DHTGet     Type = 651
	DHTSuccess Type = 652
	DHTFailure Type = 653
	// DHT reserved until 679

	TypeEnrollInit    Type = 680
	TypeEnrolRegister Type = 681
	TypeEnrolSuccess  Type = 682
	TypeEnrolFailure  Type = 683
	// Enroll reserved until 689
)

type AppType uint16

func (at AppType) valid() bool {
	switch at {
	case AppTypeDHT,
		AppTypeGossip,
		AppTypeNSE,
		AppTypeOnion:
		return true
	default:
		return false
	}
}

const (
	AppTypeDHT    AppType = 650
	AppTypeGossip AppType = 500
	AppTypeNSE    AppType = 520
	AppTypeOnion  AppType = 560
)
