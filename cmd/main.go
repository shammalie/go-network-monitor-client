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
	logPrefix      = "main %v\n"
	envFileName    = "app"
	grpcServerAddr = "localhost:4320"
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

	grpcClient := network_capture_v1.NewNetworkCaptureClient(grpcServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))

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
