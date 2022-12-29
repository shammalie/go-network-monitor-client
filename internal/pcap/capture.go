package pcap

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	logPrefix = "pcap: %v\n"
)

type PacketCapture struct {
	Capture       chan gopacket.Packet
	ignoreMap     map[string]*struct{}
	captureFilter string
	Interupt      chan interface{}
	handle        *pcap.Handle
	mu            sync.RWMutex
}

func New(iFace string, snaplen int32, promisc bool, listenDuration time.Duration, filter string, ipIgnoreList []string) *PacketCapture {
	if iFace == "" {
		fmt.Printf(logPrefix, "no capture interface found, defaulting to loopback")
		iFace = "lo"
	}
	if snaplen == 0 {
		fmt.Printf(logPrefix, "defaulting snaplen to 1600")
		snaplen = 1600
	}
	if listenDuration.Abs().Nanoseconds() == 0 {
		fmt.Printf(logPrefix, "no duration set, will set to block forever")
		listenDuration = pcap.BlockForever
	}
	ignoreMap := make(map[string]*struct{})
	for _, ip := range ipIgnoreList {
		ignoreMap[ip] = &struct{}{}
	}
	var handle *pcap.Handle
	var err error
	if handle, err = pcap.OpenLive(iFace, snaplen, promisc, listenDuration); err != nil {
		panic(err)
	} else if err = handle.SetBPFFilter(filter); err != nil {
		panic(err)
	}
	pcap := &PacketCapture{
		Capture:       make(chan gopacket.Packet),
		ignoreMap:     ignoreMap,
		captureFilter: filter,
		Interupt:      make(chan interface{}),
		handle:        handle,
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		pcap.capture()
	}()
	return pcap
}

func (p *PacketCapture) capture() {
	defer p.handle.Close()
	defer close(p.Capture)
	defer close(p.Interupt)
	select {
	case <-p.Interupt:
		return
	default:
		fmt.Printf(logPrefix, "starting capture service")
		for packet := range gopacket.NewPacketSource(p.handle, p.handle.LinkType()).Packets() {
			if packet == nil || packet.NetworkLayer() == nil {
				continue
			}
			p.mu.RLock()
			if p.ignoreMap[packet.NetworkLayer().NetworkFlow().Src().String()] != nil {
				continue
			}
			p.mu.RUnlock()
			p.Capture <- packet
		}
	}
}

func (p *PacketCapture) AddIp(ip string) {
	defer p.mu.Unlock()
	p.mu.Lock()
	p.ignoreMap[ip] = &struct{}{}
}

func (p *PacketCapture) RemoveIp(ip string) {
	defer p.mu.Unlock()
	p.mu.Lock()
	delete(p.ignoreMap, ip)
}
