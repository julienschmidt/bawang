package main

import (
	"fmt"
	"github.com/go-ini/ini"
	"io/ioutil"
	"os"
)

type Config struct {
	P2PHostname     string
	P2PPort         int
	RPSAPIAddress   string // api socket address of the RPS module
	OnionAPIAddress string
	HostKey         string
	BuildTimeout    int
	CreateTimeout   int
	Verbosity       int
}

func (c *Config) FromFile(path string) {
	cfg, err := ini.Load(path)
	if err != nil {
		fmt.Printf("Fail to read config file: %v", err)
		os.Exit(1)
	}

	c.RPSAPIAddress = cfg.Section("rps").Key("api_address").String()
	c.OnionAPIAddress = cfg.Section("onion").Key("api_address").String()
	c.P2PHostname = cfg.Section("onion").Key("p2p_hostname").String()
	c.P2PPort = cfg.Section("onion").Key("p2p_port").MustInt()
	c.BuildTimeout = cfg.Section("onion").Key("build_timeout").MustInt(10)
	c.CreateTimeout = cfg.Section("onion").Key("create_timeout").MustInt(10)
	c.Verbosity = cfg.Section("onion").Key("verbose").MustInt(0)

	hostKeyFile := cfg.Section("onion").Key("hostkey").String()
	if hostKeyFile == "" {
		fmt.Printf("Missing config file entry: [onion] hostkey")
		os.Exit(1)
	}

	data, err := ioutil.ReadFile(hostKeyFile)
	if err != nil {
		fmt.Printf("Could not read host key file: %v", err)
	}
	c.HostKey = string(data)

	if c.P2PHostname == "" {
		fmt.Println("Missing config file entry: [onion] p2p_hostname")
		os.Exit(1)
	}

	if c.P2PPort == 0 {
		fmt.Println("Missing config file entry: [onion] p2p_port")
		os.Exit(1)
	}
}
