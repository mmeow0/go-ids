package main

import (
	"flag"
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/hillu/go-yara/v4"
	"github.com/mmeow0/go-sensor/collector"
	"github.com/mmeow0/go-sensor/models"
	"github.com/mmeow0/go-sensor/sendData"
	log "github.com/sirupsen/logrus"
)

const (
	snapshotLen int32         = 1024
	promiscuous bool          = false
	timeout     time.Duration = 5 * time.Second
)

func main() {
	var (
		device        string
		rulesFileName string
		address       string
	)

	flag.StringVar(&device, "i", "en0", "network interface")
	flag.StringVar(&rulesFileName, "r", "example.yar", "yara rules file")
	flag.StringVar(&address, "h", "localhost:9988", "where to send data")
	flag.Parse()

	log.Infoln("Sensor starting...")
	ensureRoot()

	compiler, err := yara.NewCompiler()
	if err != nil {
		log.Fatalf("Failed to initialize YARA compiler: %s", err)
	}

	rulesFile, err := os.Open(rulesFileName)
	if err != nil {
		log.Fatalf("Could not open rule file %s: %s", rulesFileName, err)
	}
	err = compiler.AddFile(rulesFile, "rules")
	rulesFile.Close()
	if err != nil {
		log.Fatalf("Could not parse rule file %s: %s", rulesFileName, err)
	}

	matchedPackets := make(chan models.Packet, 100)
	go sendData.SendData(matchedPackets, address)
	go collector.Collector(device, snapshotLen, promiscuous, timeout, matchedPackets, compiler)
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
