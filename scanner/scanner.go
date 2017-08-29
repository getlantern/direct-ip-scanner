package scanner

import (
	"crypto/tls"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/workiva/go-datastructures/set"

	"github.com/getlantern/direct-ip-scanner/config"
)

func checkAllHeaders(respHeaders http.Header, headersToMatch map[string]string) bool {
	for h, v := range headersToMatch {
		if v != strings.Join(respHeaders[h], ", ") {
			return false
		}
	}
	return true
}

func scanIp(client *http.Client, url string, headers map[string]string) (bool, error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return false, nil
	}
	req.Host = "www.youtube.com"

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	if err != nil {
		log.Printf("Error connecting to client: %v", err)
		return false, nil
	}

	if checkAllHeaders(resp.Header, headers) {
		return true, nil
	}

	resp.Body.Close()

	return false, nil
}

func ScanDomain(iprange config.IPRange, results map[string]*set.Set) {
	log.Printf("Scanning domain %v...\n", iprange.Domain.Name)

	newSet := set.New()
	results[iprange.Domain.Name] = newSet

	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	for _, r := range iprange.Domain.Ranges {
		log.Printf(" - Using IP range %v\n", r)

		err, ipreader := NewIPRangeReader(r)
		if err != nil {
			log.Fatalf("Error creating IP Reader: %v", err)
			continue
		}

		for current := ipreader.GetCurrentIP(); current != nil; current = ipreader.GetNextIP() {
			ip := ipreader.GetCurrentIP().String()
			url := strings.Replace(iprange.Domain.Url, "<ip>", ip, 1)
			log.Printf("    * Scanning: %v\n", url)

			found, err := scanIp(client, url, iprange.Domain.Response.Headers)
			if err != nil {
				log.Printf("There was an error scanning the range %s: %s", r, err)
			}
			if found {
				newSet.Add(ip)
			}
		}
	}
}
