package graph

import (
	"crypto/sha256"
	"encoding/json"
	"github.com/miekg/dns"
	"net"
	"strings"
)

type serializedIPNode struct {
	Addr   net.IP `json:"ip"`
	Name   string `json:"name"`
	ASN    int    `json:"asn"`
	Prefix net.IP `json:"prefix"`
}

type IPNode struct {
	addr       net.IP
	name       string
	asn        int
	prefix     net.IP
	parentNode Node
}

func NewIPNode(ip string, asn int) (n *IPNode) {
	n = NewIPNodeWithName(ip, "", asn)
	return
}

func NewIPNodeWithName(ip string, dn string, asn int) *IPNode {
	n := new(IPNode)
	n.addr = net.ParseIP(ip)
	n.asn = asn
	n.name = strings.ToLower(dns.Fqdn(dn))

	if n.IsV4() {
		n.prefix = n.addr.Mask(net.CIDRMask(24, 32))
	} else {
		n.prefix = n.addr.Mask(net.CIDRMask(48, 128))
	}

	return n
}

func (n *IPNode) MarshalJSON() ([]byte, error) {
	sip := new(serializedIPNode)
	sip.Addr = n.addr
	sip.Name = n.name
	sip.Prefix = n.prefix
	sip.ASN = n.asn
	return json.Marshal(sip)
}

func (n *IPNode) UnmarshalJSON(bstr []byte) error {
	sip := new(serializedIPNode)
	if err := json.Unmarshal(bstr, sip) ; err != nil {
		return err
	}
	n.addr = sip.Addr
	n.name = sip.Name
	n.prefix = sip.Prefix
	n.asn = sip.ASN
	return nil
}

func (n *IPNode) String() string {
	jsonbstr, err := json.Marshal(n)
	if err != nil {
		return ""
	}
	return string(jsonbstr)
}

func (n *IPNode) IsV4() bool {
	return n.addr.To4() != nil
}

func (n *IPNode) IP() string {
	return n.addr.String()
}

func (n *IPNode) ASN() int {
	return n.asn
}

func (n *IPNode) Prefix() string {
	return n.prefix.String()
}

func (n *IPNode) deepcopy() Node {
	nn := new(IPNode)
	nn.name = n.name
	nn.addr = n.addr
	nn.asn = n.asn
	nn.prefix = n.prefix
	nn.parentNode = n.parentNode
	return nn
}

func (n *IPNode) setParent(g Node) {
	n.parentNode = g
}

func (n *IPNode) parent() Node {
	return n.parentNode
}

func (n *IPNode) similar(o LeafNode) bool {
	otherIP, ok := o.(*IPNode)
	return ok && n.addr.Equal(otherIP.addr)
}

func (n *IPNode) similarASN(o LeafNode) bool {
	otherIP, ok := o.(*IPNode)
	return ok && n.ASN() != 0 && n.ASN() == otherIP.ASN()
}

func (n *IPNode) similarPrefix(o LeafNode) bool {
	otherIP, ok := o.(*IPNode)
	if !ok || n.IsV4() != otherIP.IsV4() {
		return false
	}
	return n.prefix.Equal(otherIP.prefix)
}

func (n *IPNode) hash() [8]byte {
	var ret [8]byte
	h := sha256.Sum256([]byte(n.addr.String()))
	copy(ret[:], h[:8])
	return ret
}
