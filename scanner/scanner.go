package scanner

import (
	"crypto/tls"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
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

func ScanDomain(iprange config.IPRange, results ScanResults, nThreads int) {
	log.Printf("Scanning domain %v with %v threads...\n", iprange.Domain.Name, nThreads)

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
		ips, err := EnumerateIPs(r)
		if err != nil {
			log.Fatalf("Error creating IP Reader: %v", err)
			continue
		}

		log.Printf(" - Scanning IP range %v, with %v addresses\n", r, len(ips))

		var wg sync.WaitGroup
		var workers int64 = 0

		for _, ip := range ips {
			if atomic.LoadInt64(&workers) >= int64(nThreads) {
				wg.Wait()
			}
			atomic.AddInt64(&workers,1)
			wg.Add(1)
			
			go func(ip string) {
				url := strings.Replace(iprange.Domain.Url, "<ip>", ip, 1)
				log.Printf("    * Scanning: %v\n", url)

				found, err := scanIp(client, url, iprange.Domain.Response.Headers)
				if err != nil {
					log.Printf("There was an error scanning the range %s: %s", r, err)
				}
				if found {
					newSet.Add(ip)
				}
				wg.Done()
			}(ip)
		}

		wg.Wait()
	}
}
