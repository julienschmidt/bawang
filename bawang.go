package main

import (
	"flag"
	"log"
)

func main() {
	var configFilePath string
	flag.StringVar(&configFilePath, "config", "config.ini", "Path to config file, default is config.ini")

	var cfg Config
	err := cfg.FromFile(configFilePath)
	if err != nil {
		log.Fatalf("Error loading config file: %v", err)
	}

	err = listenAPISocket(&cfg)
	if err != nil {
		log.Fatalf("Error listening on API socket: %v", err)
	}
}
