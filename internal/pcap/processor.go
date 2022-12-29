package pcap

import (
	"fmt"

	"github.com/google/gopacket"
)

type SimplePacket struct {
	Network     SimpleNetworkLayer
	Transport   SimpleTransportLayer
	Application SimpleApplicationLayer
	Metadata    gopacket.PacketMetadata
}

type SimpleNetworkLayer struct {
	SrcIp    string
	DstIp    string
	Protocol string
}

type SimpleTransportLayer struct {
	SrcPort  string
	DstPort  string
	Protocol string
}

type SimpleApplicationLayer struct {
	Protocol string
	Payload  string
}

func Processor(packet gopacket.Packet) *SimplePacket {
	if packet.ErrorLayer() != nil {
		fmt.Println(packet.ErrorLayer().Error())
	}

	var simpleTransportLayer SimpleTransportLayer
	var simpleNetworkLayer SimpleNetworkLayer
	var simpleAppliationLayer SimpleApplicationLayer

	transportLayer := packet.TransportLayer()
	if transportLayer != nil {
		simpleTransportLayer = processTransportLayer(packet.TransportLayer())
	}

	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		simpleNetworkLayer = processNetworkLayer(packet.NetworkLayer())
	}

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		simpleAppliationLayer = processApplicationLayer(applicationLayer)
	}

	return &SimplePacket{
		Network:     simpleNetworkLayer,
		Transport:   simpleTransportLayer,
		Application: simpleAppliationLayer,
		Metadata:    *packet.Metadata(),
	}
}

func processTransportLayer(layer gopacket.TransportLayer) SimpleTransportLayer {
	src := layer.TransportFlow().Src().String()
	dst := layer.TransportFlow().Dst().String()
	return SimpleTransportLayer{
		SrcPort:  src,
		DstPort:  dst,
		Protocol: layer.LayerType().String(),
	}
}

func processNetworkLayer(layer gopacket.NetworkLayer) SimpleNetworkLayer {
	src := layer.NetworkFlow().Src().String()
	dst := layer.NetworkFlow().Dst().String()
	return SimpleNetworkLayer{
		SrcIp:    src,
		DstIp:    dst,
		Protocol: layer.LayerType().String(),
	}
}

func processApplicationLayer(layer gopacket.ApplicationLayer) SimpleApplicationLayer {
	return SimpleApplicationLayer{
		Protocol: layer.LayerType().String(),
		Payload:  string(layer.Payload()),
	}
}
