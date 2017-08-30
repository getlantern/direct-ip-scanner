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

type ScanResults map[string]*set.Set

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

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error connecting to client: %v", err)
		return false, nil
	}
	defer resp.Body.Close()

	if checkAllHeaders(resp.Header, headers) {
		return true, nil
	}
	return false, nil
}

func ScanDomain(iprange config.IPRange, results ScanResults, nThreads, timeout int) {
	log.Printf("Scanning domain %v with %v threads (timeout=%v)...\n", iprange.Domain.Name, nThreads, timeout)

	newSet := set.New()
	results[iprange.Domain.Name] = newSet

	tr := &http.Transport{
		MaxIdleConns:       10,
		DisableCompression: true,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	for _, r := range iprange.Domain.Ranges {
		ips, err := EnumerateIPs(r)
		if err != nil {
			log.Fatalf("Error creating IP Reader: %v", err)
			continue
		}

		log.Printf(" - Scanning IP range %v, with %v addresses\n", r, len(ips))

		workers := make(chan bool, nThreads)
		for _, ip := range ips {
			workers <- true

			go func(ip string) {
				url := strings.Replace(iprange.Domain.Url, "<ip>", ip, 1)
				log.Printf("    * Scanning: %v...", ip)

				found, err := scanIp(client, url, iprange.Domain.Response.Headers)
				if err != nil {
					log.Printf("There was an error scanning the range %s: %s", r, err)
				}
				if found {
					log.Printf("Found IP! -> %s", ip)
					newSet.Add(ip)
				}

				<-workers
			}(ip)
		}
	}
}
