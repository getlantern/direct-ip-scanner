package scanner

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/workiva/go-datastructures/set"

	"github.com/getlantern/direct-ip-scanner/config"
)

type ScanResults map[string]*set.Set

type ExpectedResponse struct {
	Headers map[string]string
	Status  string
}

func checkAllHeaders(respHeaders http.Header, headersToMatch map[string]string) bool {
	for h, v := range headersToMatch {
		if v != strings.Join(respHeaders[h], ", ") {
			return false
		}
	}
	return true
}

func checkStatus(respStatus, status string) bool {
	return status == "" || respStatus == status
}

func scanIp(client *http.Client, timeout time.Duration, url, setHost string, expected ExpectedResponse) (bool, error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return false, nil
	}

	if setHost != "" {
		req.Host = setHost
	}

	ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := client.Do(req)

	if err != nil {
		log.Printf("Error connecting to client: %v", err)
		return false, nil
	}
	defer resp.Body.Close()

	if checkAllHeaders(resp.Header, expected.Headers) &&
		checkStatus(resp.Status, expected.Status) {
		return true, nil
	}
	return false, nil
}

func ScanDomain(iprange config.IPRange, results ScanResults, nThreads, timeout int) {
	log.Printf("Scanning domain %v with %v threads (timeout=%v)...\n", iprange.Domain.Name, nThreads, timeout)

	newSet := set.New()
	results[iprange.Domain.Name] = newSet

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		// Timeout:   time.Duration(timeout) * time.Second,
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

				found, err := scanIp(client,
					time.Duration(timeout)*time.Second,
					url,
					iprange.Domain.SetHost,
					ExpectedResponse{
						Headers: iprange.Domain.Response.Headers,
						Status:  iprange.Domain.Response.Status,
					})
				if err != nil {
					log.Printf("There was an error scanning the range %s: %s", r, err)
				}
				if found {
					log.Printf("Found IP: %s -> %s", iprange.Domain.Name, ip)
					newSet.Add(ip)
				}

				<-workers
			}(ip)
		}
	}
}
