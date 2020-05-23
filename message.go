package main

const (
	msgTypeGossipAnnounce     = 500
	msgTypeGossipNotify       = 501
	msgTypeGossipNotification = 502
	msgTypeGossipValidation   = 503
	// gossip reserved until 519

	msgTypeNSEQuery    = 520
	msgTypeNSEEstimate = 521
	// NSE reserved until 539

	msgTypeRSPQuery = 540
	msgTypeRSPPeer  = 541
	// RSP reserved until 559

	msgTypeOnionTunnelBuild    = 560
	msgTypeOnionTunnelReady    = 561
	msgTypeOnionTunnelIncoming = 562
	msgTypeOnionTunnelDestroy  = 563
	msgTypeOnionTunnelData     = 564
	msgTypeOnionError          = 565
	msgTypeOnionCover          = 566
	// Onion reserved until 599

	msgTypeAuthSessionStart       = 600
	msgTypeAuthSessionHS1         = 601
	msgTypeAuthSessionIncomingHS1 = 602
	msgTypeAuthSessionHS2         = 603
	msgTypeAuthSessionIncomingHS2 = 604
	msgTypeAuthLayerEncrypt       = 605
	msgTypeAuthLayerDecrypt       = 606
	msgTypeAuthLayerEncryptResp   = 607
	msgTypeAuthLayerDecryptResp   = 608
	msgTypeAuthSessionClose       = 609
	msgTypeAuthError              = 610
	msgTypeAuthCipherEncrypt      = 611
	msgTypeAuthCipherEncryptResp  = 612
	msgTypeAuthCipherDecrypt      = 613
	msgTypeAuthCipherDecryptResp  = 614
	// Onion Auth reserved until 649

	msgDHTPut     = 650
	msgDHTGet     = 651
	msgDHTSuccess = 652
	msgDHTFailure = 653
	// DHT reserved until 679

	msgTypeEnrollInit    = 680
	msgTypeEnrolRegister = 681
	msgTypeEnrolSuccess  = 682
	msgTypeEnrolFailure  = 683
	// Enroll reserved until 689
)
