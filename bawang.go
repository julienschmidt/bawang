// Package main provides the main application logic of bawang.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"bawang/config"
	"bawang/onion"
)

func main() {
	var configFilePath string
	flag.StringVar(&configFilePath, "config", "config.conf", "Path to config file, default is config.conf")

	var cfg config.Config
	err := cfg.FromFile(configFilePath)
	if err != nil {
		log.Fatalf("Error loading config file: %v", err)
	}

	quitChan := make(chan struct{})
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down\n", sig)
		close(quitChan)
	}()

	router := onion.NewRouter(&cfg)
	rps, err := NewRPS(&cfg)
	if err != nil {
		log.Fatalf("Error initializing RPS: %v", err)
	}
	errChanOnion := make(chan error)

	go ListenOnionSocket(&cfg, router, errChanOnion, quitChan)

	errChanAPI := make(chan error)
	go ListenAPISocket(&cfg, router, rps, errChanAPI, quitChan)

	select {
	case err = <-errChanOnion:
		log.Fatalf("Error listening on Onion socket: %v", err)
	case err = <-errChanAPI:
		log.Fatalf("Error listening on API socket: %v", err)
	}
}
