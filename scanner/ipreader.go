package scanner

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

// IP ranges parser
type ipRangeReader struct {
	first   net.IP
	last    net.IP
	current net.IP
	ipnet   *net.IPNet
}

func incIP(ip net.IP) net.IP {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
	return ip
}

// CIDR parser
func listAllCIDRHosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); ip = incIP(ip) {
		ips = append(ips, ip.String())
	}
	// Remove network address and broadcast address
	return ips, nil
}

func (r *ipRangeReader) getNextIPForCIDR() net.IP {
	for ip := r.current; r.ipnet.Contains(ip); r.current = incIP(ip) {
		r.current = incIP(ip)
		return ip
	}
	return nil
}

func (r *ipRangeReader) getNextIP() net.IP {
	for checkIndex := 15; checkIndex > 11; checkIndex = checkIndex - 1 {
		if r.current[checkIndex] < r.last[checkIndex] {
			r.current[checkIndex] = r.current[checkIndex] + 1
			break
		} else {
			r.current[checkIndex] = 0
		}
	}

	if bytes.Equal([]byte(r.current[12:]), []byte{0, 0, 0, 0}) {
		r.current = nil
	}

	return r.current
}

func (r *ipRangeReader) listAllIPs() (ips []string) {
	for ip := r.first; ip != nil; ip = r.getNextIP() {
		ips = append(ips, ip.String())
	}
	return ips
}

func EnumerateIPs(input string) (ipsIterator func() net.IP, err error) {
	limits := strings.Split(input, "-")

	var rreader *ipRangeReader

	if len(limits) == 2 {
		// First try with a ip-based range
		first := net.ParseIP(limits[0])
		if first == nil {
			return nil, fmt.Errorf("Invalid IP definition in range: %v", input)
		}
		last := net.ParseIP(limits[1])
		if last == nil {
			return nil, fmt.Errorf("Invalid IP definition in range: %v", input)
		}

		rreader = &ipRangeReader{first, last, first, nil}
	} else {
		// Otherwise try with CIDR
		ip, ipnet, err := net.ParseCIDR(input)
		if err != nil {
			return nil, err
		}

		rreader = &ipRangeReader{nil, nil, ip.Mask(ipnet.Mask), ipnet}
	}

	iteratorF := func() net.IP {
		if rreader.ipnet != nil {
			return rreader.getNextIPForCIDR()
		} else {
			return rreader.getNextIP()
		}
	}

	return iteratorF, nil
}
