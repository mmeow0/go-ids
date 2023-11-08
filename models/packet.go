package models

import (
	"net"
	"time"

	"github.com/google/gopacket/layers"
)

// PACKET: 86 bytes, wire length 86 cap length 86 @ 2023-11-08 02:00:14.96484 +0300 MSK
// - Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..72..] SrcMAC=c4:35:d9:7f:e4:37 DstMAC=76:27:32:ff:de:40 EthernetType=IPv6 Length=0}
// - Layer 2 (40 bytes) = IPv6     {Contents=[..40..] Payload=[..32..] Version=6 TrafficClass=0 FlowLabel=768 Length=32 NextHeader=TCP HopLimit=64 SrcIP=fe80::da:59fa:c6e0:4808 DstIP=fe80::1c66:e3e3:92a0:76d0 HopByHop=nil}
// - Layer 3 (32 bytes) = TCP      {Contents=[..32..] Payload=[] SrcPort=57876 DstPort=61906 Seq=213013259 Ack=746750798 DataOffset=8 FIN=false SYN=false RST=false PSH=false ACK=true URG=false ECE=false CWR=false NS=false Window=2048 Checksum=31928 Urgent=0 Options=[TCPOption(NOP:), TCPOption(NOP:), TCPOption(Timestamps:2008127170/3665868064 0x77b196c2da80b520)] Padding=[]}

// -------------------------------------------
// PACKET: 98 bytes, wire length 98 cap length 98 @ 2023-11-08 02:00:15.172411 +0300 MSK
// - Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..84..] SrcMAC=c4:35:d9:7f:e4:37 DstMAC=40:ed:00:dc:c0:f5 EthernetType=IPv4 Length=0}
// - Layer 2 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..64..] Version=4 IHL=5 TOS=0 Length=84 Id=15669 Flags= FragOffset=0 TTL=64 Protocol=ICMPv4 Checksum=36990 SrcIP=192.168.0.104 DstIP=10.203.225.26 Options=[] Padding=[]}
// - Layer 3 (08 bytes) = ICMPv4   {Contents=[..8..] Payload=[..56..] TypeCode=EchoRequest Checksum=8428 Id=40965 Seq=33938}
// - Layer 4 (56 bytes) = Payload  56 byte(s)

// -------------------------------------------
// PACKET: 42 bytes, wire length 42 cap length 42 @ 2023-11-08 02:00:15.578252 +0300 MSK
// - Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..28..] SrcMAC=40:ed:00:dc:c0:f5 DstMAC=ff:ff:ff:ff:ff:ff EthernetType=ARP Length=0}
// - Layer 2 (28 bytes) = ARP      {Contents=[..28..] Payload=[] AddrType=Ethernet Protocol=IPv4 HwAddressSize=6 ProtAddressSize=4 Operation=1 SourceHwAddress=[..6..] SourceProtAddress=[192, 168, 0, 1] DstHwAddress=[..6..] DstProtAddress=[192, 168, 0, 105]}

// PACKET: 66 bytes, wire length 66 cap length 66 @ 2023-11-08 02:00:21.920552 +0300 MSK
// - Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..52..] SrcMAC=40:ed:00:dc:c0:f5 DstMAC=c4:35:d9:7f:e4:37 EthernetType=IPv4 Length=0}
// - Layer 2 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..32..] Version=4 IHL=5 TOS=40 Length=52 Id=0 Flags=DF FragOffset=0 TTL=56 Protocol=TCP Checksum=18588 SrcIP=17.253.38.243 DstIP=192.168.0.104 Options=[] Padding=[]}
// - Layer 3 (32 bytes) = TCP      {Contents=[..32..] Payload=[] SrcPort=443(https) DstPort=58242 Seq=243032728 Ack=3336154523 DataOffset=8 FIN=true SYN=false RST=false PSH=false ACK=true URG=false ECE=false CWR=false NS=false Window=129 Checksum=10202 Urgent=0 Options=[TCPOption(NOP:), TCPOption(NOP:), TCPOption(Timestamps:3617980132/1682132683 0xd7a5fee464434ecb)] Padding=[]}

// PACKET: 98 bytes, wire length 98 cap length 98 @ 2023-11-08 02:00:23.209923 +0300 MSK
// - Layer 1 (14 bytes) = Ethernet {Contents=[..14..] Payload=[..84..] SrcMAC=c4:35:d9:7f:e4:37 DstMAC=40:ed:00:dc:c0:f5 EthernetType=IPv4 Length=0}
// - Layer 2 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..64..] Version=4 IHL=5 TOS=0 Length=84 Id=11739 Flags= FragOffset=0 TTL=64 Protocol=ICMPv4 Checksum=40920 SrcIP=192.168.0.104 DstIP=10.203.225.26 Options=[] Padding=[]}
// - Layer 3 (08 bytes) = ICMPv4   {Contents=[..8..] Payload=[..56..] TypeCode=EchoRequest Checksum=36406 Id=40965 Seq=33946}
// - Layer 4 (56 bytes) = Payload  56 byte(s)
type LinkLayer struct {
	layers.BaseLayer
	Length       uint32
	EthernetType layers.EthernetType
}

type NetworkLayer struct {
	layers.BaseLayer
	Length uint32
}

type TransportLayer struct {
	layers.BaseLayer
	Length uint32
}

type ApplicationLayer struct {
	layers.BaseLayer
	Length uint32
}

type Packet struct {
	Timestamp        time.Time
	Length           uint32
	SrcMAC, DstMAC   net.HardwareAddr
	SrcIP, DstIP     uint16
	SrcPort, DstPort uint16
}
