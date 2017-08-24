package main

import (
	"log"
	"os"

	"github.com/getlantern/direct-ip-scanner/config"
	"github.com/getlantern/direct-ip-scanner/scanner"
)

func main() {
	err, ipranges := config.GetRanges()
	if err != nil{
		log.Fatalf(err.Error())
		os.Exit(1)
	}

	for _, r := range ipranges {
		scanner.ScanDomain(r.Domain.Name, r.Domain.Ranges)
	}

	log.Println("Done.")
}
