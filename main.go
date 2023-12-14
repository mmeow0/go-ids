package main

import (
	"flag"
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/mmeow0/packet-collector/collector"
	"github.com/mmeow0/packet-collector/models"
	"github.com/mmeow0/packet-collector/sendData"
	log "github.com/sirupsen/logrus"
)

const (
	snapshotLen int32         = 1024
	promiscuous bool          = false
	timeout     time.Duration = 5 * time.Second
)

func main() {
	var device string

	flag.StringVar(&device, "interface", "en0", "network interface to collect")

	log.Infoln("Sensor starting...")
	ensureRoot()

	packets := make(chan models.Packet, 100)
	go sendData.SendData(packets)
	go collector.Collector(device, snapshotLen, promiscuous, timeout, packets)
	select {}
}

func ensureRoot() {
	switch runtime.GOOS {
	case "windows":
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		if err != nil {
			log.Fatal("Run this as root user!!")

		}
	case "linux":
		if uid := syscall.Getuid(); uid != 0 {
			log.Fatal("Run this as root user!!")

		}
	}
}
