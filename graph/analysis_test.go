package graph

import (
	"testing"
	"net"
	"bytes"
)

func TestGetBitsFromIP(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	bstr := getIPBitsInBytes(ip)
	vector := []byte{
		0, 0, 0, 0, 1, 0 ,1, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1,
	}
	for i, b := range bstr {
		if b != vector[i] {
			t.Fail()
		}
	}
}

func TestIsInTree(t *testing.T) {
	buf := new(bytes.Buffer)
	buf.WriteString("12345 192.168.10.0/24")
	tr, err := BuildRadixTree(buf)
	if err != nil {
		t.Fatal("Failed tree building")
	}

	asn, err := getASNFor(tr, net.ParseIP("192.168.0.1"))
	if err == nil {
		t.Fatal("Got a match for 192.168.0.1")
	}

	asn, ok := getASNFor(tr, net.ParseIP("192.168.10.1"))
	if ok != nil || asn != 12345 {
		t.Fatal("Did not discover 12345")
	}

}

func TestIsInAS(t *testing.T) {
	buf := new(bytes.Buffer)
	buf.WriteString("12345 192.168.10.0/24")
	tr, err := BuildRadixTree(buf)
	if err != nil {
		t.Fatal("Failed tree building")
	}
	n := NewIPNode("192.168.10.1")
	f := getASNFilteringFunc(tr)
	f2 := getASNTestFunc(f, 12345)
	f3 := getASNTestFunc(f, 12346)

	if !f2(n) {
		t.Fatal("Not in 12345")
	}
	if f3(n) {
		t.Fatal("In 12346")
	}

}