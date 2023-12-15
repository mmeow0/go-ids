package sendData

import (
	"encoding/json"
	"net"

	"github.com/mmeow0/go-sensor/models"
	log "github.com/sirupsen/logrus"
)

func SendData(matchedPackets chan models.Packet, address string) {
	con, err := net.Dial("tcp", address)

	if err != nil {
		log.Fatal("failed to connect socket")
		return
	}
	defer con.Close()

	for {
		for packet := range matchedPackets {
			flat, err := json.Marshal(packet)
			if err != nil {
				log.WithFields(log.Fields{
					"at":    "SendData",
					"error": err,
				}).Warn("failed to marshal packet")
				continue
			}

			log.Infoln("Send", string(flat))

			data := append(flat, []byte("uPMf1gZsTwt2TNh\n")...)
			con.Write(data)
		}
	}
}
