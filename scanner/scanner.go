package scanner

import (
	"crypto/tls"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/getlantern/direct-ip-scanner/config"
)

func scanRange(iprange, urlTemplate string, headers []string) error {
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	err, ipreader := NewIPRangeReader(iprange)
	if err != nil {
		return err
	}

	for current := ipreader.GetCurrentIP(); current != nil; current = ipreader.GetNextIP() {
		ip := ipreader.GetCurrentIP().String()
		url := strings.Replace(urlTemplate, "<ip>", ip, 1)
		log.Printf("    * Scanning: %v\n", url)

		req, err := http.NewRequest("HEAD", url, nil)
		if err != nil {
			log.Printf("Error creating request: %v", err)
			continue
		}
		req.Host = "www.youtube.com"

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		if err != nil {
			log.Printf("Error connecting to client: %v", err)
			continue
		}
		log.Println(resp.Header["Server"])
		resp.Body.Close()
	}

	return nil
}

func ScanDomain(iprange config.IPRange) {
	log.Printf("Scanning domain %v...\n", iprange.Domain.Name)

	for _, r := range iprange.Domain.Ranges {
		log.Printf(" - Using IP range %v\n", r)

		if err := scanRange(r, iprange.Domain.Url, iprange.Domain.Response.Headers); err != nil {
			log.Printf("There was an error scanning the range %s: %s", r, err)
		}
	}
}
