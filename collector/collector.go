package collector

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/mmeow0/packet-collector/models"
	log "github.com/sirupsen/logrus"
)

func Collector(device string,
	snapshotLen int32,
	promiscuous bool,
	timeout time.Duration,
	packets chan models.Packet,
) {
	log.Infoln("Packets collector starting...")

	// Open device
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.WithFields(log.Fields{
			"at":        "collector",
			"error":     err,
			"interface": device,
		}).Fatal("failed to open handler")
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		packets <- DecodePacket(packet)
	}

}
