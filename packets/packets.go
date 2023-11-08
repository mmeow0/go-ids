package packets

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
)

// func createPacket(packet gopacket.Packet, radio *layers.RadioTap, ether *layers.Dot11, iface string) models.Wireless80211Frame {
// 	frame := models.Wireless80211Frame{
// 		Length:           radio.Length,
// 		TSFT:             radio.TSFT,
// 		FlagsRadio:       radio.Flags,
// 		Rate:             radio.Rate,
// 	}

// 	frame.ParseElements(packet, ether)

// 	return frame
// }

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

func DecodePacket(packet gopacket.Packet) {
	var eth layers.Ethernet
	var arp layers.ARP
	var icmp4 layers.ICMPv4
	var icmp6 layers.ICMPv6
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var payload gopacket.Payload

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp, &icmp4, &icmp6, &ip4, &ip6, &tcp, &udp, &payload)

	decodedLayers := make([]gopacket.LayerType, 0, 10)

	fmt.Println("Decoding packet")
	parser.DecodeLayers(packet.Data(), &decodedLayers)
	for _, typ := range decodedLayers {
		fmt.Println("  Successfully decoded layer type", typ)
		switch typ {
		case layers.LayerTypeEthernet:
			fmt.Println("    Eth ", eth.SrcMAC, eth.DstMAC)
		case layers.LayerTypeARP:
			fmt.Println("    Arp ", arp.AddrType, arp.Protocol)
		case layers.LayerTypeICMPv4:
			fmt.Println("    ICMPv4 ", icmp4.TypeCode, icmp4.Checksum)
		case layers.LayerTypeICMPv6:
			fmt.Println("    ICMPv4 ", icmp6.TypeCode, icmp6.Checksum)
		case layers.LayerTypeIPv4:
			fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)
		case layers.LayerTypeIPv6:
			fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
		case layers.LayerTypeTCP:
			fmt.Println("    TCP ", tcp.SrcPort, tcp.DstPort)
		case layers.LayerTypeUDP:
			fmt.Println("    UDP ", udp.SrcPort, udp.DstPort)
		}
	}

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
}
