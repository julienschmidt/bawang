package main

import (
	"flag"
)

var (
	config Config
)

func main() {
	var configFilePath string
	flag.StringVar(&configFilePath, "config", "config.ini", "Path to config file, default is config.ini")

	config.FromFile(configFilePath)

	println("Ik bin ne Swibel!")
}
