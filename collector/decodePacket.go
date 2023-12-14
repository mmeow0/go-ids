package collector

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mmeow0/go-sensor/models"
)

func decodePacket(packet gopacket.Packet) models.Packet {
	var eth layers.Ethernet
	var arp layers.ARP

	// TCP/IP control protocols
	var icmp4 layers.ICMPv4
	var icmp6 layers.ICMPv6

	// TCP/IP network layer
	var ip4 layers.IPv4
	var ip6 layers.IPv6

	// TCP/IP transport layer types.
	var tcp layers.TCP
	var udp layers.UDP

	decodedPacket := models.Packet{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length}

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp, &icmp4, &icmp6, &ip4, &ip6, &tcp, &udp)

	decodedLayers := make([]gopacket.LayerType, 0, 10)

	parser.DecodeLayers(packet.Data(), &decodedLayers)
	for _, typ := range decodedLayers {
		switch typ {
		case layers.LayerTypeEthernet:
			// Ethernet type is typically IPv4 but could be ARP or other
			decodedPacket.SrcMAC = eth.SrcMAC
			decodedPacket.DstMAC = eth.DstMAC

		case layers.LayerTypeIPv4:
			decodedPacket.SrcIP = ip4.SrcIP
			decodedPacket.DstIP = ip4.DstIP

		case layers.LayerTypeIPv6:
			decodedPacket.SrcIP = ip6.SrcIP
			decodedPacket.DstIP = ip6.DstIP

		case layers.LayerTypeTCP:
			decodedPacket.SrcPort = tcp.SrcPort
			decodedPacket.DstPort = tcp.DstPort

		case layers.LayerTypeUDP:
			decodedPacket.SrcPort = layers.TCPPort(udp.SrcPort)
			decodedPacket.DstPort = layers.TCPPort(udp.DstPort)
		}
	}

	return decodedPacket
}
