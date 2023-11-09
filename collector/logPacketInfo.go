package collector

import (
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
)

func LogPacketInfo(packet gopacket.Packet) {
	// Let's see if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

		// Ethernet type is typically IPv4 but could be ARP or other
		log.WithFields(log.Fields{
			"Source MAC":      ethernetPacket.SrcMAC,
			"Destination MAC": ethernetPacket.DstMAC,
			"Ethernet type":   ethernetPacket.EthernetType,
		}).Infoln("Ethernet layer detected")
	}

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		log.WithFields(log.Fields{
			"From":     ip.SrcIP,
			"To":       ip.DstIP,
			"Protocol": ip.Protocol,
		}).Infoln("IPv4 layer detected")
	}

	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		log.WithFields(log.Fields{
			"From":            tcp.SrcPort,
			"To":              tcp.DstPort,
			"Sequence number": tcp.Seq,
		}).Infoln("TCP layer detected")
	}

	// Iterate over all layers, printing out each layer type
	var layers string
	for _, layer := range packet.Layers() {
		layers += layer.LayerType().String() + " "
	}
	log.WithFields(log.Fields{
		"Layers": layers,
	}).Infoln("All packet layers")

	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		log.WithFields(log.Fields{
			"Payload": string(applicationLayer.Payload()),
		}).Infoln("Application layer/Payload found")

		// Search for a string inside the payload
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			log.Infoln("HTTP found!")
		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		log.WithFields(log.Fields{
			"Error": err,
		}).Error("Error decoding some part of the packet")
	}
}
