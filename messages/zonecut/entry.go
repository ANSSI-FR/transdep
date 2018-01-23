package zonecut

import (
	"encoding/json"
	"github.com/miekg/dns"
	"strings"
)

// serializedEntry is a proxy for Entry, used for JSON serialization
type serializedEntry struct {
	Domain      string        `json:"domain"`
	DNSSEC      bool          `json:"dnssec"`
	NameServers []NameSrvInfo `json:"nameservers"`
}

// Entry contains the response to a zonecut request when no error occurred. It contains information about the delegation
// of a zone,
type Entry struct {
	// domain is the name that is being delegated (so if we query "d.nic.fr" for the delegation of "ssi.gouv.fr", domain
	// contains "ssi.gouv.fr")
	domain string
	// dnssec values true if there was a DS record at the parent zone for the domain referenced in the "attribute" name
	dnssec bool
	// nameServers contains the list of NameSrvInfo records
	nameServers []*NameSrvInfo
}

// NewEntry builds a new entry, and performs some normalization on the input values.
func NewEntry(domain string, DNSSECEnabled bool, nameServers []*NameSrvInfo) *Entry {
	e := new(Entry)
	e.domain = strings.ToLower(dns.Fqdn(domain))
	e.dnssec = DNSSECEnabled
	e.nameServers = nameServers
	return e
}

// SetDNSSEC allows modification of the DNSSEC status relative to that entry, if need be afterwards
func (e *Entry) SetDNSSEC(val bool) {
	e.dnssec = val
}

func (e *Entry) Domain() string {
	return e.domain
}

func (e *Entry) DNSSEC() bool {
	return e.dnssec
}

func (e *Entry) NameServers() []*NameSrvInfo {
	return e.nameServers
}

func (e *Entry) MarshalJSON() ([]byte, error) {
	se := new(serializedEntry)
	se.Domain = e.domain
	se.DNSSEC = e.dnssec
	for _, val := range e.nameServers {
		se.NameServers = append(se.NameServers, *val)
	}
	return json.Marshal(se)
}

func (e *Entry) UnmarshalJSON(bstr []byte) error {
	se := new(serializedEntry)
	if err := json.Unmarshal(bstr, se); err != nil {
		return err
	}

	e.domain = se.Domain
	e.dnssec = se.DNSSEC
	for _, srvInfo := range se.NameServers {
		val := srvInfo
		e.nameServers = append(e.nameServers, &val)
	}
	return nil
}

func (e *Entry) String() string {
	jsonrepr, _ := json.Marshal(e)
	return string(jsonrepr)
}
