package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"bawang/onion"
)

func main() {
	var configFilePath string
	flag.StringVar(&configFilePath, "config", "config.conf", "Path to config file, default is config.conf")

	var cfg onion.Config
	var onjon onion.Onion
	err := cfg.FromFile(configFilePath)
	if err != nil {
		log.Fatalf("Error loading config file: %v", err)
	}

	quitChan := make(chan struct{})
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.Printf("Received signal %v, shutting down\n", sig)
		close(quitChan)
	}()

	errChanOnion := make(chan error)

	go ListenOnionSocket(&onjon, &cfg, errChanOnion, quitChan)

	errChanAPI := make(chan error)
	go ListenAPISocket(&cfg, errChanAPI, quitChan)

	select {
	case err = <-errChanOnion:
		log.Fatalf("Error listening on Onion socket: %v", err)
	case err = <-errChanAPI:
		log.Fatalf("Error listening on API socket: %v", err)
	}
}
