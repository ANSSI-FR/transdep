package graph

import (
	"crypto/sha256"
	"encoding/json"
	"github.com/miekg/dns"
	"strings"
)

/* serializedDomainNameNode is a proxy struct used to serialize an DomainNameNode into JSON.
The DomainNameNode struct is not directly used because the Go json module requires that attributes must be exported for
it to work, and DomainNameNode struct attributes have no other reason for being exported.
*/
type serializedDomainNameNode struct {
	Domain          string `json:"domain"`
	DnssecProtected bool   `json:"dnssec"`
}

// DomainNameNode represents a domain name or an alias of a name within the dependency tree
// As a metadata, if a node represents a zone apex, a DNSSEC indicator is set if there is a DS record for this name.
type DomainNameNode struct {
	domain          string
	dnssecProtected bool
	parentNode      Node
}

// NewDomainNameNode returns a new DomainNameNode instance and initializes it with the domain name and the
// DNSSEC indicator
func NewDomainNameNode(domain string, dnssecProtected bool) *DomainNameNode {
	n := new(DomainNameNode)
	n.domain = strings.ToLower(dns.Fqdn(domain))
	n.dnssecProtected = dnssecProtected
	return n
}

// Implements json.Marshaler
func (n *DomainNameNode) MarshalJSON() ([]byte, error) {
	sn := new(serializedDomainNameNode)
	sn.Domain = n.domain
	sn.DnssecProtected = n.dnssecProtected
	return json.Marshal(sn)
}

// Implements json.Unmarshaler
func (n *DomainNameNode) UnmarshalJSON(bstr []byte) error {
	sn := new(serializedDomainNameNode)
	err := json.Unmarshal(bstr, sn)
	if err != nil {
		return err
	}
	n.domain = sn.Domain
	n.dnssecProtected = sn.DnssecProtected
	return nil
}

func (n *DomainNameNode) Domain() string {
	return n.domain
}

func (n *DomainNameNode) DNSSECProtected() bool {
	return n.dnssecProtected
}

func (n *DomainNameNode) String() string {
	jsonbstr, err := json.Marshal(n)
	if err != nil {
		return ""
	}
	return string(jsonbstr)
}

func (n *DomainNameNode) deepcopy() Node {
	nn := new(DomainNameNode)
	nn.domain = n.domain
	nn.dnssecProtected = n.dnssecProtected
	nn.parentNode = n.parentNode
	return nn
}

func (n *DomainNameNode) setParent(g Node) {
	n.parentNode = g
}

func (n *DomainNameNode) parent() Node {
	return n.parentNode
}

// similar returns true if the o LeafNode is a DomainNameNode and the domain are similar, regardless of the DNSSEC protection status
func (n *DomainNameNode) similar(o LeafNode) bool {
	otherDomain, ok := o.(*DomainNameNode)
	// It is safe to use == to compare domain names here, because NewDomainNameNode performed canonicalization
	return ok && n.domain == otherDomain.domain
}

func (n *DomainNameNode) hash() [8]byte {
	var ret [8]byte
	h := sha256.Sum256([]byte(n.domain))
	copy(ret[:], h[:8])
	return ret
}
