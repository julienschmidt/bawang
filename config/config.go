// Package config provides the Bawang config.
package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/go-ini/ini"
)

type Config struct {
	P2PHostname     string
	P2PPort         int
	RPSAPIAddress   string // API socket address of the RPS module
	OnionAPIAddress string
	TunnelLength	int
	BuildTimeout    int
	CreateTimeout   int
	APITimeout      int
	Verbosity       int
	HostKey         *rsa.PrivateKey
}

func (config *Config) FromFile(path string) error {
	cfg, err := ini.Load(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	config.RPSAPIAddress = cfg.Section("rps").Key("api_address").String()
	config.OnionAPIAddress = cfg.Section("onion").Key("api_address").String()
	config.P2PHostname = cfg.Section("onion").Key("p2p_hostname").String()
	config.P2PPort = cfg.Section("onion").Key("p2p_port").MustInt()
	config.BuildTimeout = cfg.Section("onion").Key("build_timeout").MustInt(10)
	config.CreateTimeout = cfg.Section("onion").Key("create_timeout").MustInt(10)
	config.APITimeout = cfg.Section("onion").Key("api_timeout").MustInt(5)
	config.Verbosity = cfg.Section("onion").Key("verbose").MustInt(0)
	config.TunnelLength = cfg.Section("onion").Key("tunnel_length").MustInt(3)

	hostKeyFile := cfg.Section("onion").Key("hostkey").String()
	if hostKeyFile == "" {
		return errors.New("missing config file entry: [onion] hostkey")
	}

	data, err := ioutil.ReadFile(hostKeyFile)
	if err != nil {
		return fmt.Errorf("could not read host key file: %v", err)
	}

	pemBlock, rest := pem.Decode(data)
	if pemBlock == nil || len(rest) != 0 {
		return errors.New("invalid pem entry in host key file")
	}

	switch pemBlock.Type {
	case "RSA PRIVATE KEY":
		config.HostKey, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err != nil {
			return fmt.Errorf("invalid hostkey: %v", err)
		}
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		if err != nil {
			return fmt.Errorf("invalid hostkey: %v", err)
		}
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			config.HostKey = rsaKey
		} else {
			return errors.New("hostkey is not an RSA key")
		}
	default:
		return errors.New("unknown key type")
	}

	if config.P2PHostname == "" {
		return errors.New("missing config file entry: [onion] p2p_hostname")
	}

	if config.P2PPort == 0 {
		return errors.New("missing config file entry: [onion] p2p_port")
	}

	return nil
}
