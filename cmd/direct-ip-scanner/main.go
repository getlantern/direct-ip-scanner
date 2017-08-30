package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/getlantern/direct-ip-scanner/config"
	"github.com/getlantern/direct-ip-scanner/scanner"
)

var (
	results scanner.ScanResults = make(scanner.ScanResults)

	outputFile string
)

func init() {
	flag.StringVar(&outputFile, "output", "found-ips.json", "Output JSON file for the found IPs")
}

type OutputDomain struct {
	Name string   `json:"domain"`
	IPs  []string `json:"ips"`
}

type Output struct {
	Domains []OutputDomain `json:"domains"`
}

func main() {
	flag.Parse()

	err, ipranges := config.GetRanges()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	for _, r := range ipranges {
		scanner.ScanDomain(r, results)
	}

	output := &Output{}
	for k, v := range results {
		flattened := v.Flatten()
		ips := make([]string, len(flattened))
		for i, e := range flattened {
			ips[i] = e.(string)
		}
		output.Domains = append(output.Domains, OutputDomain{
			Name: k,
			IPs:  ips,
		})
	}

	outJson, err := json.MarshalIndent(output, "", "    ")
	if err != nil {
		log.Fatalf("Error generating JSON: %s", err)
	}

	err = ioutil.WriteFile(outputFile, []byte(outJson), 0644)
	if err != nil {
		log.Fatalf("Error writing output file: %s", err)
	}

	log.Println("Done.")
}
