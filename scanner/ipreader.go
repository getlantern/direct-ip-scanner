package scanner

import (
	"fmt"
	"net"
	"strings"
)

type subRange struct {
	first net.IP
	last  net.IP
}

type IPRangeReader struct {
	raw        string
	subRanges  []subRange
	currentSub int
	current    net.IP
}

func NewIPRangeReader(input string) (error, *IPRangeReader) {
	err, subRanges := splitInSubRanges(input)
	if err != nil {
		return err, nil
	}

	return nil, &IPRangeReader{
		raw:        input,
		subRanges:  subRanges,
		currentSub: 0,
	}
}

func (r *IPRangeReader) NextIP() (ip *net.IP) {
	ip = r.getNextInSub()
	if ip == nil && r.currentSub < len(r.subRanges)-1 {
		r.currentSub = r.currentSub + 1
		ip = r.getNextInSub()
	}
	return
}

func (r *IPRangeReader) getNextInSub() (ip *net.IP) {
	s := r.subRanges[r.currentSub]

	fmt.Printf("SUBRANGE: %v to %v\n", s.first, s.last)

	//return &net.IP{}
	return nil
}

func splitInSubRanges(input string) (err error, subranges []subRange) {
	for _, s := range strings.Split(input, ",") {
		limits := strings.Split(s, "-")
		if len(limits) != 2 {
			return fmt.Errorf("Invalid subrange definition: %v", s), nil
		}

		first := net.ParseIP(limits[0])
		if first == nil {
			return fmt.Errorf("Invalid IP definition in subrange: %v", s), nil
		}
		last := net.ParseIP(limits[0])
		if last == nil {
			return fmt.Errorf("Invalid IP definition in subrange: %v", s), nil
		}

		subranges = append(subranges, subRange{first, last})
	}
	return
}
