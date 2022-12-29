package main

import (
	"fmt"

	"strings"

	"github.com/shammalie/go-network-monitor-client/internal/pcap"
	"github.com/spf13/viper"
)

const (
	logPrefix   = "main %v\n"
	envFileName = "app"
)

func main() {
	viper.AddConfigPath(".")
	viper.SetConfigName(envFileName)
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Printf(logPrefix, err)
	}

	ipIgnore := viper.GetString("IP_IGNORE")

	packetCapture := pcap.New("eth0", 0, true, 0, "", strings.Split(ipIgnore, ","))

	for packet := range packetCapture.Capture {
		simplePacket := pcap.Processor(packet)
		fmt.Println(*simplePacket)
	}
}
