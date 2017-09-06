package scanner

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/workiva/go-datastructures/set"

	"github.com/getlantern/direct-ip-scanner/config"
)

type ScanResults map[string]*set.Set

type expectedResponse struct {
	SanValue   string
	Headers    map[string]string
	StatusCode int
}

func checkAllHeaders(respHeaders http.Header, headersToMatch map[string]string) bool {
	for h, v := range headersToMatch {
		if v != strings.Join(respHeaders[h], ", ") {
			return false
		}
	}
	return true
}

func checkStatus(actual, expected int) bool {
	return expected == 0 || actual == expected
}

func checkSanValue(sanList []string, expected string) bool {
	expectedParts := strings.Split(expected, ".")
	for _, v := range sanList {
		if v == expected {
			return true
		}
		vParts := strings.Split(v, ".")
		if wildcardDomainEquals(vParts, expectedParts) {
			return true
		}
	}
	return false
}

func wildcardDomainEquals(domain []string, expected []string) bool {
	if domain[0] != "*" {
		return false
	}
	if len(domain) != len(expected) {
		return false
	}
	for i := 1; i < len(domain); i++ {
		if domain[i] != expected[i] {
			return false
		}
	}
	return true
}

func scanIp(ip, domain string, timeout time.Duration, urlStr string, expected expectedResponse) (found, verifiedCert bool, err error) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	_url, err := url.Parse(urlStr)
	if err != nil {
		return false, false, nil
	}

	var conn net.Conn
	if _url.Scheme == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", ip+":443", &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			log.Printf("Error connecting to client: %v", err)
			return false, false, nil
		}
	} else {
		conn, err = dialer.Dial("tcp", ip+":80")
	}
	defer conn.Close()

	req, err := http.NewRequest("HEAD", urlStr, nil)
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return false, false, nil
	}
	req.Host = domain

	err = req.Write(conn)
	if err != nil {
		log.Printf("Error writing request to connection: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		log.Printf("Error reading response: %v", err)
		return false, false, nil
	}
	defer resp.Body.Close()

	if checkAllHeaders(resp.Header, expected.Headers) &&
		checkStatus(resp.StatusCode, expected.StatusCode) {

		tlsConn, ok := conn.(*tls.Conn)
		if ok {
			sanList := tlsConn.ConnectionState().PeerCertificates[0].DNSNames
			return true, checkSanValue(sanList, expected.SanValue), nil
		}
		return true, false, nil
	}

	return false, false, nil
}

func scanWorker(wg *sync.WaitGroup, timeout time.Duration, workerItems *chan (scanItem), foundCallback func(i scanItem, verifiedCert bool)) {
	for item := range *workerItems{
		url := strings.Replace(item.url, "<ip>", item.ip, 1)
		log.Printf("    * Scanning: %v...", item.ip)

		found, verifiedCert, err := scanIp(
			item.ip,
			item.domain,
			timeout,
			url,
			item.expected,
		)
		if err != nil {
			log.Printf("There was an error scanning the IP %s: %s", item.ip, err)
		}
		if found {
			foundCallback(item, verifiedCert)
		}
	}
	wg.Done()
}

type scanItem struct {
	domain   string
	url      string
	ip       string
	expected expectedResponse
}

func ScanDomain(iprange config.IPRange, results ScanResults, nThreads int, timeout time.Duration, randomize bool) {
	log.Printf("Scanning domain %v with %v threads (timeout=%v)...\n", iprange.Domain.Name, nThreads, timeout)

	newSet := set.New()
	results[iprange.Domain.Name] = newSet

	itemsQueue := make(chan scanItem, nThreads)
	csvOut := csv.NewWriter(os.Stdout)
	wg := sync.WaitGroup{}

	for i := 0; i < nThreads; i = i + 1 {
		wg.Add(1)
		go scanWorker(
			&wg,
			timeout,
			&itemsQueue,
			func(item scanItem, verifiedCert bool) {
				log.Printf("Found IP: %s -> %s, %v", item.domain, item.ip, verifiedCert)
				csvOut.Write([]string{item.domain, item.ip, fmt.Sprint(verifiedCert)})
				csvOut.Flush()
				newSet.Add(item.ip)
			},
		)
	}

	randomOrder := rand.Perm(len(iprange.Domain.Ranges))
	for i, n := range randomOrder {
		var pick int
		if randomize {
			pick = n
		} else {
			pick = i
		}
		r := iprange.Domain.Ranges[pick]

		ips, err := EnumerateIPs(r)
		if err != nil {
			log.Fatalf("Error creating IP Reader: %v", err)
			continue
		}

		log.Printf(" - Scanning IP range %v, with %v addresses\n", r, len(ips))

		for _, ip := range ips {
			itemsQueue <- scanItem{
				domain: iprange.Domain.Name,
				url:    iprange.Domain.Url,
				ip:     ip,
				expected: expectedResponse{
					Headers:    iprange.Domain.Response.Headers,
					StatusCode: iprange.Domain.Response.StatusCode,
					SanValue:   iprange.Domain.Response.SanValue,
				},
			}
		}
	}

	close(itemsQueue)
	wg.Wait()
}
