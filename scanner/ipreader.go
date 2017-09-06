package scanner

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

// CIDR parser
func listCIDRHosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	inc := func(ip net.IP) {
		for j := len(ip) - 1; j >= 0; j-- {
			ip[j]++
			if ip[j] > 0 {
				break
			}
		}
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// Remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

// IP ranges parser
type ipRangeReader struct {
	first   net.IP
	last    net.IP
	current net.IP
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

func EnumerateIPs(input string) (ips []string, err error) {
	for _, s := range strings.Split(input, ",") {

		limits := strings.Split(s, "-")

		if len(limits) == 2 {
			// First try with a ip-based range
			first := net.ParseIP(limits[0])
			if first == nil {
				return nil, fmt.Errorf("Invalid IP definition in subrange: %v", s)
			}
			last := net.ParseIP(limits[1])
			if last == nil {
				return nil, fmt.Errorf("Invalid IP definition in subrange: %v", s)
			}

			rreader := &ipRangeReader{first, last, first}
			ips = append(ips, rreader.listAllIPs()...)
		} else {
			// Otherwise try with CIDR
			cidrIps, err := listCIDRHosts(s)
			if err != nil {
				return nil, fmt.Errorf("Invalid IP definition in subrange: %v", s)
			}
			ips = append(ips, cidrIps...)
		}
	}
	return ips, nil
}
