package scanner

import (
	"bufio"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/url"
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

func scanIp(ip string, timeout time.Duration, urlStr, setHost string, expected ExpectedResponse) (bool, error) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	_url, err := url.Parse(urlStr)
	if err != nil {
		return false, nil
	}

	var conn net.Conn
	if _url.Scheme == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", ip+":443", &tls.Config{})
		if err != nil {
			log.Printf("Error connecting to client: %v", err)
			return false, nil
		}
	} else {
		conn, err = dialer.Dial("tcp", ip+":80")
	}
	defer conn.Close()

	req, err := http.NewRequest("HEAD", urlStr, nil)
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return false, nil
	}

	err = req.Write(conn)
	if err != nil {
		log.Printf("Error writing request to connection: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		log.Printf("Error reading response: %v", err)
	}
	defer resp.Body.Close()

	if setHost != "" {
		req.Host = setHost
	}

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

				found, err := scanIp(
					ip,
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
