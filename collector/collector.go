package collector

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/hillu/go-yara/v4"
	"github.com/mmeow0/packet-collector/models"
	log "github.com/sirupsen/logrus"
)

func Collector(device string,
	snapshotLen int32,
	promiscuous bool,
	timeout time.Duration,
	packets chan models.Packet,
	compiler *yara.Compiler,
) {
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

	r, err := compiler.GetRules()
	if err != nil {
		log.Fatalf("Failed to compile rules: %s", err)
	}

	s, _ := yara.NewScanner(r)

	for packet := range packetSource.Packets() {
		packet := decodePacket(packet)

		payload := packet.Payload
		var m yara.MatchRules
		s.SetCallback(&m).ScanMem([]byte(payload))

		if len(m) != 0 {
			log.Infof("Founded rules for %s...", payload)

			var matchedRules []string
			for _, match := range m {
				matchedRules = append(matchedRules, match.Rule)
			}
			packet.MatchedRules = matchedRules

			packets <- packet
		}
	}
}
