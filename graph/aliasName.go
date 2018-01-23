package graph

import (
	"crypto/sha256"
	"encoding/json"
	"github.com/miekg/dns"
	"strings"
)

/* serializedAliasNode is a proxy struct used to serialize an Alias node into JSON.
The AliasNode struct is not directly used because the Go json module requires that attributes must be exported for it
to work, and AliasNode struct attributes have no other reason for being exported.
*/
type serializedAliasNode struct {
	Target string `json:"target"`
	Source string `json:"source"`
}

// AliasNode represents a CNAME in the dependency graph of a name.
type AliasNode struct {
	// target is the right-hand name of the CNAME RR
	target string
	// source is the owner name of the CNAME RR
	source string
	// parentNode is a reference to the parent node in the dependency graph. This is used to visit the graph from leafs
	// to root
	parentNode Node
}

/* NewAliasNode returns a new instance of AliasNode after initializing it.

target is the right-hand name of the CNAME RR

source is the owner name of the CNAME RR
*/
func NewAliasNode(target, source string) *AliasNode {
	n := new(AliasNode)
	n.target = strings.ToLower(dns.Fqdn(target))
	n.source = strings.ToLower(dns.Fqdn(source))
	return n
}

// Implements json.Marshaler
func (n *AliasNode) MarshalJSON() ([]byte, error) {
	sn := new(serializedAliasNode)
	sn.Target = n.target
	sn.Source = n.source
	return json.Marshal(sn)
}

// Implements json.Unmarshaler
func (n *AliasNode) UnmarshalJSON(bstr []byte) error {
	sn := new(serializedAliasNode)
	err := json.Unmarshal(bstr, sn)
	if err != nil {
		return err
	}
	n.target = sn.Target
	n.source = sn.Source
	return nil
}

func (n *AliasNode) Target() string {
	return n.target
}

func (n *AliasNode) Source() string {
	return n.source
}

func (n *AliasNode) String() string {
	jsonbstr, err := json.Marshal(n)
	if err != nil {
		return ""
	}
	return string(jsonbstr)
}

func (n *AliasNode) deepcopy() Node {
	nn := new(AliasNode)
	nn.target = n.target
	nn.source = n.source
	nn.parentNode = n.parentNode
	return nn
}

func (n *AliasNode) setParent(g Node) {
	n.parentNode = g
}

func (n *AliasNode) parent() Node {
	return n.parentNode
}

// similar compares to LeafNode and returns true if the o LeafNode is also an AliasNode and the targets are the same.
func (n *AliasNode) similar(o LeafNode) bool {
	otherDomain, ok := o.(*AliasNode)
	// It is safe to use == here to compare domain names b/c NewAliasNode performs canonicalization of the domain names
	return ok && n.target == otherDomain.target //&& n.source == otherDomain.source
}

func (n *AliasNode) hash() [8]byte {
	var ret [8]byte
	h := sha256.Sum256([]byte(n.target + n.source))
	copy(ret[:], h[:8])
	return ret
}
