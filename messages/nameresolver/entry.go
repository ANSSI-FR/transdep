package nameresolver

import (
	"github.com/miekg/dns"
	"net"
	"strings"
	"encoding/json"
)

// serializedEntry is used as a proxy to generate a JSON representation of an entry, using the json go module.
type serializedEntry struct {
	Name  string    `json:"name"`
	Alias *string   `json:"alias,omitempty"`
	Addrs *[]net.IP `json:"addrs,omitempty"`
}

// Entry represents the resolution of a name, either into an alias (CNAME) or a list of IP addresses (both v4 and v6).
type Entry struct {
	owner       string
	cNAMETarget string
	addrs       []net.IP
}

// NewAliasEntry is the constructor of an entry whose content symbolizes a domain name owning just a CNAME.
func NewAliasEntry(owner, CNAMETarget string) *Entry {
	e := new(Entry)
	e.owner = strings.ToLower(dns.Fqdn(owner))
	e.cNAMETarget = strings.ToLower(dns.Fqdn(CNAMETarget))
	return e
}

// NewIPEntry is the constructor of an entry whose content is a domain name and its associated IP addresses.
func NewIPEntry(name string, addrs []net.IP) *Entry {
	e := new(Entry)
	e.owner = strings.ToLower(dns.Fqdn(name))
	e.cNAMETarget = ""
	e.addrs = addrs
	return e
}

// Implements json.Marshaler
func (e *Entry) MarshalJSON() ([]byte, error) {
	sre := new(serializedEntry)
	sre.Name = e.owner
	if e.cNAMETarget != "" {
		sre.Alias = new(string)
		*sre.Alias = e.cNAMETarget
	} else if len(e.addrs) > 0 {
		sre.Addrs = new([]net.IP)
		*sre.Addrs = e.addrs
	}
	return json.Marshal(sre)
}

// Implements json.Unmarshaler
func (e *Entry) UnmarshalJSON(bstr []byte) error {
	sre := new(serializedEntry)
	err := json.Unmarshal(bstr, sre)
	if err != nil {
		return err
	}
	e.owner = sre.Name
	if sre.Alias != nil {
		e.cNAMETarget = *sre.Alias
	}
	if sre.Addrs != nil {
		e.addrs = *sre.Addrs
	}
	return nil
}

func (e *Entry) Owner() string {
	return e.owner
}

func (e *Entry) CNAMETarget() string {
	return e.cNAMETarget
}

func (e *Entry) Addrs() []net.IP {
	return e.addrs
}
