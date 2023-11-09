package collector

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mmeow0/packet-collector/models"
)

func DecodePacket(packet gopacket.Packet) models.Packet {
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

	var tls layers.TLS

	decodedPacket := models.Packet{
		Timestamp:     packet.Metadata().Timestamp,
		Length:        packet.Metadata().Length,
		Payload:       "",
		DecodingError: false}

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp, &icmp4, &icmp6, &ip4, &ip6, &tcp, &udp, &tls)

	decodedLayers := make([]gopacket.LayerType, 0, 10)

	parser.DecodeLayers(packet.Data(), &decodedLayers)
	for _, typ := range decodedLayers {
		switch typ {
		case layers.LayerTypeEthernet:
			// Ethernet type is typically IPv4 but could be ARP or other
			decodedPacket.Layers.Ethernet = true
			decodedPacket.Ethernet = &models.Ethernet{
				EthernetType: eth.EthernetType,
				SrcMAC:       eth.SrcMAC,
				DstMAC:       eth.DstMAC,
				Length:       eth.Length,
			}

		case layers.LayerTypeARP:
			decodedPacket.Layers.Arp = true
			decodedPacket.Arp = &models.Arp{
				Operation:         arp.Operation,
				Protocol:          arp.Protocol,
				SourceHwAddress:   arp.SourceHwAddress,
				SourceProtAddress: arp.SourceProtAddress,
				DstHwAddress:      arp.DstHwAddress,
				DstProtAddress:    arp.DstProtAddress,
			}

		case layers.LayerTypeICMPv4:
			decodedPacket.Layers.ICMPv4 = true
			decodedPacket.ICMPv4 = &models.ICMPv4{
				TypeCode: icmp4.TypeCode,
				Checksum: icmp4.Checksum,
				Id:       icmp4.Id,
				Seq:      icmp4.Seq,
			}

		case layers.LayerTypeICMPv6:
			decodedPacket.Layers.ICMPv6 = true
			decodedPacket.ICMPv6 = &models.ICMPv6{
				TypeCode: icmp6.TypeCode,
				Checksum: icmp6.Checksum,
			}

		case layers.LayerTypeIPv4:
			decodedPacket.Layers.IPv4 = true
			decodedPacket.IPv4 = &models.IPv4{
				Id:       ip4.Id,
				Length:   ip4.Length,
				Checksum: ip4.Checksum,
				TTL:      ip4.TTL,
				SrcIP:    ip4.SrcIP,
				DstIP:    ip4.DstIP,
			}

		case layers.LayerTypeIPv6:
			decodedPacket.Layers.IPv6 = true
			decodedPacket.IPv6 = &models.IPv6{
				Length:   ip6.Length,
				HopLimit: ip6.HopLimit,
				SrcIP:    ip6.SrcIP,
				DstIP:    ip6.DstIP,
			}

		case layers.LayerTypeTCP:
			decodedPacket.Layers.TCP = true
			decodedPacket.TCP = &models.TCP{
				SrcPort:  tcp.SrcPort,
				DstPort:  tcp.DstPort,
				Checksum: tcp.Checksum,
				Seq:      tcp.Seq,
			}

		case layers.LayerTypeUDP:
			decodedPacket.Layers.UDP = true
			decodedPacket.UDP = &models.UDP{
				SrcPort:  udp.SrcPort,
				DstPort:  udp.DstPort,
				Checksum: udp.Checksum,
				Length:   udp.Length,
			}

		case layers.LayerTypeTLS:
			decodedPacket.Layers.TLS = true
			decodedPacket.TLS = &models.TLS{
				Handshake: tls.Handshake,
			}
		}
	}

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		decodedPacket.Payload = string(applicationLayer.Payload())
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		decodedPacket.DecodingError = true
	}

	return decodedPacket
}
