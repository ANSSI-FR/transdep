package zonecut

import (
	"net"
	"encoding/json"
	"strings"
	"github.com/miekg/dns"
)

type serializedNameSrvInfo struct {
	Name  string   `json:"name"`
	Addrs []net.IP `json:"addrs"`
}

type NameSrvInfo struct {
	name  string
	addrs []net.IP
}

func NewNameSrv(name string, addrs []net.IP) *NameSrvInfo {
	n := new(NameSrvInfo)
	n.name = strings.ToLower(dns.Fqdn(name))
	n.addrs = addrs
	return n
}

func (n *NameSrvInfo) Name() string {
	return n.name
}

func (n *NameSrvInfo) Addrs() []net.IP {
	return n.addrs
}

func (n *NameSrvInfo) MarshalJSON() ([]byte, error) {
	sns := new(serializedNameSrvInfo)
	sns.Name = n.name
	sns.Addrs = n.addrs
	return json.Marshal(sns)
}

func (n *NameSrvInfo) UnmarshalJSON(bstr []byte) error {
	sns := new(serializedNameSrvInfo)
	if err := json.Unmarshal(bstr, sns) ; err != nil {
		return err
	}
	n.name = sns.Name
	n.addrs = sns.Addrs
	return nil
}