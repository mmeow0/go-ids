package models

import (
	"net"
	"time"

	"github.com/google/gopacket/layers"
)

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
	SrcPort  layers.UDPPort `json:"srcPort"`
	DstPort  layers.UDPPort `json:"dstPort"`
	Checksum uint16         `json:"checksum"`
	Length   uint16         `json:"length"`
}

type Packet struct {
	Timestamp    time.Time        `json:"timestamp"`
	Length       int              `json:"length"`
	SrcMAC       net.HardwareAddr `json:"srcMac"`
	DstMAC       net.HardwareAddr `json:"dstMac"`
	SrcIP        net.IP           `json:"srcIp"`
	DstIP        net.IP           `json:"dstIp"`
	SrcPort      layers.TCPPort   `json:"srcPort"`
	DstPort      layers.TCPPort   `json:"dstPort"`
	MatchedRules []string         `json:"matchedRules"`
}
