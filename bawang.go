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
	"bawang/rps"
)

func main() {
	var configFilePath string
	flag.StringVar(&configFilePath, "config", "config.conf", "Path to config file, default is config.conf")

	// init config
	var cfg config.Config
	err := cfg.FromFile(configFilePath)
	if err != nil {
		log.Fatalf("Error loading config file: %v", err)
	}

	// handle shutdown signals
	quitChan := make(chan struct{})
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down\n", sig)
		close(quitChan)
	}()

	// initialize modules
	router := onion.NewRouter(&cfg)
	rps, err := rps.New(&cfg)
	if err != nil {
		close(quitChan)
		log.Fatalf("Error initializing RPS: %v", err)
	}

	// start listening on sockets in child goroutines
	errChanOnion := make(chan error)
	go onion.ListenOnionSocket(&cfg, router, errChanOnion, quitChan)

	errChanAPI := make(chan error)
	go ListenAPISocket(&cfg, router, rps, errChanAPI, quitChan)

	// handle errors from child goroutines
	select {
	case err = <-errChanOnion:
		close(quitChan)
		log.Fatalf("Error listening on Onion socket: %v", err)
	case err = <-errChanAPI:
		close(quitChan)
		log.Fatalf("Error listening on API socket: %v", err)
	}
}
