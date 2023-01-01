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

	packetCapture := pcap.New(pcapInterface, 0, true, 0, pcapFilter, strings.Split(ipIgnore, ","))

	grpcClient := network_capture_v1.NewNetworkCaptureClient(grpcServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))

	for packet := range packetCapture.Capture {
		captureRequest := pcap.Processor(packet)
		resp, err := grpcClient.SendNetworkCapture(captureRequest)
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Println(resp)
	}
}
