package main

import (
	"log"
	"os"

	"github.com/workiva/go-datastructures/set"

	"github.com/getlantern/direct-ip-scanner/config"
	"github.com/getlantern/direct-ip-scanner/scanner"
)

var (
	results map[string]*set.Set = make(map[string]*set.Set)
)

func main() {
	err, ipranges := config.GetRanges()
	if err != nil {
		log.Fatalf(err.Error())
		os.Exit(1)
	}

	for _, r := range ipranges {
		scanner.ScanDomain(r, results)
	}

	log.Println("Done.")
}
