package main

import (
	"fmt"

	"strings"

	"github.com/shammalie/go-network-monitor-client/internal/pcap"
	network_capture_v1 "github.com/shammalie/go-network-monitor/pkg/network_capture.v1"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
	pcapInterface := viper.GetString("PCAP_INTERFACE")
	pcapFilter := viper.GetString("PCAP_BPF_FILTER")

	hostname := viper.GetString("SERVER_HOSTNAME")
	port := viper.GetInt("SERVER_PORT")
	if port == 0 {
		panic("port is %d, make sure you set it via environment or app.env file")
	}

	grpcClient := network_capture_v1.NewNetworkCaptureClient(fmt.Sprintf("%s:%d", hostname, port), grpc.WithTransportCredentials(insecure.NewCredentials()))

	packetCapture := pcap.New(pcapInterface, 0, true, 0, pcapFilter, strings.Split(ipIgnore, ","))

	go func() {
		for action := range grpcClient.ReceivedActions {
			fmt.Println(action)
		}
	}()

	for packet := range packetCapture.Capture {
		grpcClient.SendNetworkCapture(pcap.Processor(packet))
	}
}
