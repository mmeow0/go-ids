package main

import (
	"flag"
	"time"

	"github.com/mmeow0/packet-collector/collector"
	"github.com/mmeow0/packet-collector/models"
	"github.com/mmeow0/packet-collector/sendData"
)

const (
	snapshotLen int32         = 1024
	promiscuous bool          = false
	timeout     time.Duration = 5 * time.Second
)

func main() {
	var device string

	flag.StringVar(&device, "interface", "en0", "network interface to collect")

	packets := make(chan models.Packet, 100)
	go sendData.SendData(packets)
	go collector.Collector(device, snapshotLen, promiscuous, timeout, packets)
	select {}
}
