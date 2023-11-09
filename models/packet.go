package models

import (
	"net"
	"time"

	"github.com/google/gopacket/layers"
)

type Layers struct {
	Ethernet bool `json:"ethernet"`
	Arp      bool `json:"arp"`
	ICMPv4   bool `json:"icmp4"`
	ICMPv6   bool `json:"icmp6"`
	IPv4     bool `json:"ip4"`
	IPv6     bool `json:"ip6"`
	TCP      bool `json:"tcp"`
	UDP      bool `json:"udp"`
	TLS      bool `json:"tls"`
}

type Ethernet struct {
	EthernetType layers.EthernetType `json:"ethernetType"`
	SrcMAC       net.HardwareAddr    `json:"srcMac"`
	DstMAC       net.HardwareAddr    `json:"dstMac"`
	Length       uint16              `json:"length"`
}

type Arp struct {
	Protocol          layers.EthernetType `json:"protocol"`
	Operation         uint16              `json:"operation"`
	SourceHwAddress   []byte              `json:"sourceHwAddress"`
	SourceProtAddress []byte              `json:"sourceProtAddress"`
	DstHwAddress      []byte              `json:"dstHwAddress"`
	DstProtAddress    []byte              `json:"dstProtAddress"`
}

type ICMPv4 struct {
	TypeCode layers.ICMPv4TypeCode `json:"typeCode"`
	Checksum uint16                `json:"checksum"`
	Id       uint16                `json:"id"`
	Seq      uint16                `json:"seq"`
}

type ICMPv6 struct {
	TypeCode layers.ICMPv6TypeCode `json:"typeCode"`
	Checksum uint16                `json:"checksum"`
}

type IPv4 struct {
	Id       uint16 `json:"id"`
	Length   uint16 `json:"length"`
	Checksum uint16 `json:"checksum"`
	TTL      uint8  `json:"ttl"`
	SrcIP    net.IP `json:"srcIp"`
	DstIP    net.IP `json:"dstIp"`
}

type IPv6 struct {
	Length   uint16 `json:"length"`
	HopLimit uint8  `json:"hopLimit"`
	SrcIP    net.IP `json:"srcIp"`
	DstIP    net.IP `json:"dstIp"`
}

type TCP struct {
	SrcPort  layers.TCPPort `json:"srcPort"`
	DstPort  layers.TCPPort `json:"dstPort"`
	Checksum uint16         `json:"checksum"`
	Seq      uint32         `json:"seq"`
}

type UDP struct {
	SrcPort, DstPort layers.UDPPort
	Checksum         uint16 `json:"checksum"`
	Length           uint16 `json:"length"`
}

type TLS struct {
	Handshake []layers.TLSHandshakeRecord `json:"handshake"`
}

type Packet struct {
	Timestamp     time.Time `json:"timestamp"`
	Length        int       `json:"length"`
	Layers        `json:"layers,omitempty"`
	*Ethernet     `json:"ethernet,omitempty"`
	*Arp          `json:"arp,omitempty"`
	*ICMPv4       `json:"icmp4,omitempty"`
	*ICMPv6       `json:"icmp6,omitempty"`
	*IPv4         `json:"ip4,omitempty"`
	*IPv6         `json:"ip6,omitempty"`
	*TCP          `json:"tcp,omitempty"`
	*UDP          `json:"udp,omitempty"`
	*TLS          `json:"tls,omitempty"`
	Payload       string `json:"payload"`
	DecodingError bool   `json:"decodingError"`
}
