package scanner

import (
	"bytes"
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
		current:    subRanges[0].first,
	}
}

func (r *IPRangeReader) GetNextIP() net.IP {
	if r.current == nil {
		return nil
	}

	r.getNextInSub()

	if r.current == nil && r.currentSub < len(r.subRanges)-1 {
		r.currentSub = r.currentSub + 1
		r.current = r.subRanges[r.currentSub].first
		r.getNextInSub()
	}

	return r.current
}

func (r *IPRangeReader) GetCurrentIP() net.IP {
	return r.current
}

func (r *IPRangeReader) getNextInSub() {
	s := r.subRanges[r.currentSub]

	for checkIndex := 15; checkIndex > 11; checkIndex = checkIndex - 1 {
		if r.current[checkIndex] < s.last[checkIndex] {
			r.current[checkIndex] = r.current[checkIndex] + 1
			break
		} else {
			r.current[checkIndex] = 0
		}
	}

	if bytes.Equal([]byte(r.current[12:]), []byte{0,0,0,0}) {
		r.current = nil
	}
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

		last := net.ParseIP(limits[1])
		if last == nil {
			return fmt.Errorf("Invalid IP definition in subrange: %v", s), nil
		}

		// TODO: check that all values are less in the first than last

		subranges = append(subranges, subRange{first, last})
	}
	return
}
