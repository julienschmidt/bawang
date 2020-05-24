package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
)

func handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		// try and read the packet header
		buf := make([]byte, 4)
		n, err := io.ReadFull(reader, buf)
		if err != nil || n != 4 {
			fmt.Printf("Error when reading packet header: %v", err)
			break
		}

		size := binary.BigEndian.Uint16(buf[:2])
		//messageType := binary.BigEndian.Uint16(buf[2:])
		// TODO: sanity checks for package size
		packet := make([]byte, size)

		n, err = io.ReadFull(reader, packet)
		if err != nil || n != int(size) {
			fmt.Printf("Error when reading main packet: %v", err)
			break
		}

		// TODO: call packet processing function
		// something like
		// switch (messageType) do something with packet
	}
}

func openAPISocket(cfg *Config) {
	ln, err := net.Listen("tcp", cfg.OnionAPIAddress)
	if err != nil {
		// TODO: error on listen
		fmt.Printf("Error starting API listen socket: %v", err)
		os.Exit(1)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// TODO: error on client connection
			fmt.Println("Error when accepting client connection")
			continue
		}
		fmt.Println("Received connection")

		go handleConnection(conn)
	}
}

func main() {
	var configFilePath string
	flag.StringVar(&configFilePath, "config", "config.ini", "Path to config file, default is config.ini")

	var cfg Config
	err := cfg.FromFile(configFilePath)
	if err != nil {
		fmt.Printf("Error when loading config file: %v", err)
		os.Exit(1)
	}

	openAPISocket(&cfg)
}
