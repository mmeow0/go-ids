package sendData

import (
	"encoding/json"
	"net"

	"github.com/mmeow0/packet-collector/models"
	log "github.com/sirupsen/logrus"
)

func SendData(packets chan models.Packet) {
	con, err := net.Dial("tcp", "localhost:9988")

	if err != nil {
		log.Warn("failed to connect socket")
		return
	}
	defer con.Close()

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

			_, _ = con.Write([]byte(flat))
			log.Infoln(string(flat))
		}
	}
}
