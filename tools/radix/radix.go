package radix

import (
	"net"
	"io"
	"github.com/hashicorp/go-immutable-radix"
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/binary"
	"strconv"
	"os"
	"fmt"
)

// Converts an IP into a byte slice whose elements are the individual bytes of the IP address in big endian format
// This function assumes that the IPv4 bits are in the LSB of the net.IP. This is an assumption because this is
// undocumented at the time of writing.
func getIPBitsInBytes(ip net.IP) []byte {
	var input, ret []byte
	input = ip.To4()
	if input == nil {
		input = ip
	}
	ptr := 0
	for ptr < len(input) {
		intRepr := binary.BigEndian.Uint32(input[ptr:ptr+4])
		var i uint32 = 1 << 31
		var val byte
		for i > 0 {
			if intRepr & i != 0 {
				val = 1
			} else {
				val = 0

			}
			ret = append(ret, val)
			i >>= 1
		}
		ptr += 4
	}
	return ret
}

func buildRadixTree(rd io.Reader) (*iradix.Tree, error) {
	t := iradix.New()
	txn := t.Txn()

	scanner := bufio.NewScanner(rd)
	for scanner.Scan() {
		buf := new(bytes.Buffer)
		buf.WriteString(scanner.Text())
		csvrd := csv.NewReader(buf)
		csvrd.Comma = ' '
		csvrd.FieldsPerRecord = 2
		rec, err := csvrd.Read()
		if err != nil {
			return nil, err
		}
		asn, err := strconv.Atoi(rec[0])
		if err != nil {
			return nil, err
		}
		_, prefix, err := net.ParseCIDR(rec[1])
		if err != nil {
			return nil, err
		}
		prefixLen, _ := prefix.Mask.Size()
		ipBstr := getIPBitsInBytes(prefix.IP)
		txn.Insert(ipBstr[:prefixLen], asn)
	}
	if err := scanner.Err() ; err != nil {
		return nil, err
	}

	return txn.Commit(), nil
}

func GetASNTree(fn string) (*iradix.Tree, error) {
	var fd *os.File
	var err error
	if fd, err = os.Open(fn) ; err != nil {
		return nil, err
	}
	defer fd.Close()

	return buildRadixTree(fd)
}

func GetASNFor(t *iradix.Tree, ip net.IP) (int, error) {
	if t == nil {
		return 0, fmt.Errorf("tree is uninitialized")
	}

	var val interface{}
	var ok bool
	ipBstr := getIPBitsInBytes(ip)
	if _, val, ok = t.Root().LongestPrefix(ipBstr) ; !ok {
		return 0, fmt.Errorf("Cannot find ASN for %s", ip.String())
	}
	asn := val.(int)
	return asn, nil
}
