package pcap

import (
	"fmt"

	"github.com/google/gopacket"
	network_capture_v1 "github.com/shammalie/go-network-monitor/pkg/network_capture.v1"
)

func Processor(packet gopacket.Packet) *network_capture_v1.NetworkCaptureRequest {
	if packet.ErrorLayer() != nil {
		fmt.Println(packet.ErrorLayer().Error())
	}

	var simpleTransportLayer network_capture_v1.TransportLayer
	var simpleNetworkLayer network_capture_v1.NetworkLayer
	var simpleAppliationLayer network_capture_v1.ApplicationLayer
	var simpleMetadata network_capture_v1.Metadata

	transportLayer := packet.TransportLayer()
	if transportLayer != nil {
		simpleTransportLayer = processTransportLayer(transportLayer)
	}

	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		simpleNetworkLayer = processNetworkLayer(networkLayer)
	}

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		simpleAppliationLayer = processApplicationLayer(applicationLayer)
	}

	metadata := packet.Metadata()
	if metadata != nil {
		simpleMetadata = processMetadata(metadata)
	}

	return &network_capture_v1.NetworkCaptureRequest{
		NetworkLayer:     &simpleNetworkLayer,
		TransportLayer:   &simpleTransportLayer,
		ApplicationLayer: &simpleAppliationLayer,
		Metadata:         &simpleMetadata,
	}
}

func processTransportLayer(layer gopacket.TransportLayer) network_capture_v1.TransportLayer {
	src := layer.TransportFlow().Src().String()
	dst := layer.TransportFlow().Dst().String()
	return network_capture_v1.TransportLayer{
		SrcPort: src,
		DstPort: dst,
		Protocol: &network_capture_v1.Protocol{
			Name: layer.LayerType().String(),
		},
	}
}

func processNetworkLayer(layer gopacket.NetworkLayer) network_capture_v1.NetworkLayer {
	src := layer.NetworkFlow().Src().String()
	dst := layer.NetworkFlow().Dst().String()
	return network_capture_v1.NetworkLayer{
		SrcIp: src,
		DstIp: dst,
		Protocol: &network_capture_v1.Protocol{
			Name: layer.LayerType().String(),
		},
	}
}

func processApplicationLayer(layer gopacket.ApplicationLayer) network_capture_v1.ApplicationLayer {
	return network_capture_v1.ApplicationLayer{
		Protocol: &network_capture_v1.Protocol{
			Name: layer.LayerType().String(),
		},
		Payload: layer.Payload(),
	}
}

func processMetadata(metadata *gopacket.PacketMetadata) network_capture_v1.Metadata {
	return network_capture_v1.Metadata{
		Timestamp:            metadata.Timestamp.UnixMilli(),
		CaptureLength:        int64(metadata.CaptureLength),
		OriginalPacketLength: int64(metadata.Length),
		Truncated:            metadata.Truncated,
	}
}
