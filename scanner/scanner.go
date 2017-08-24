package scanner

import (
	"log"
)

func scanRange(domain string, iprange string) error {
	err, ipreader := NewIPRangeReader(iprange)
	if err != nil {
		return err
	}

	
	for current := ipreader.GetCurrentIP(); current != nil; current = ipreader.GetNextIP(){
		log.Printf("    * Scanning IP: %v", ipreader.GetCurrentIP())
		// TODO: here we scan the IP for a given domain
	}

	return nil
}

func ScanDomain(domain string, ipranges []string) {
	log.Printf("Scanning domain %v...\n", domain)

	for _, r := range ipranges {
		log.Printf(" - Using IP range %v\n", r)

		if err := scanRange(domain, r); err != nil {
			log.Printf("There was an error scanning the range: %s", r)
		}
	}
}
