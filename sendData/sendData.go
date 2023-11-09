package sendData

import (
	"encoding/json"

	"github.com/mmeow0/packet-collector/models"
	log "github.com/sirupsen/logrus"
)

func SendData(packets chan models.Packet) {
	for {
		for packet := range packets {
			flat, err := json.Marshal(packet)
			if err != nil {
				log.WithFields(log.Fields{
					"at":    "SendData",
					"error": err,
				}).Warn("failed to marshal packet")
				continue
			}

			log.Infoln(string(flat))
		}
	}
}
