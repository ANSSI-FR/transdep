package errors

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"net"
)

const (
	UDP_TRANSPORT = 17
	TCP_TRANSPORT = 6
)

var PROTO_TO_STR = map[int]string{
	TCP_TRANSPORT: "TCP",
	UDP_TRANSPORT: "UDP",
}

var STR_TO_PROTO = map[string]int{
	"":    UDP_TRANSPORT,
	"TCP": TCP_TRANSPORT,
	"tcp": TCP_TRANSPORT,
	"UDP": UDP_TRANSPORT,
	"udp": UDP_TRANSPORT,
}

type serializedServfailError struct {
	Type  string `json:"type"`
	Qname string `json:"qname"`
	Qtype string `json:"qtype"`
	Addr  string `json:"ip"`
	Proto string `json:"protocol"`
}

type ServfailError struct {
	qname string
	qtype uint16
	addr  net.IP
	proto int
}

func NewServfailError(qname string, qtype uint16, addr net.IP, proto int) *ServfailError {
	se := new(ServfailError)
	se.qname = qname
	se.qtype = qtype
	se.addr = addr
	se.proto = proto
	return se
}

func (se *ServfailError) MarshalJSON() ([]byte, error) {
	sse := new(serializedServfailError)
	sse.Type = dns.RcodeToString[dns.RcodeServerFailure]
	sse.Qname = se.qname
	sse.Qtype = dns.TypeToString[se.qtype]
	sse.Addr = se.addr.String()
	sse.Proto = PROTO_TO_STR[se.proto]
	return json.Marshal(sse)
}

func (se *ServfailError) UnmarshalJSON(bstr []byte) error {
	sse := new(serializedServfailError)
	if err := json.Unmarshal(bstr, sse); err != nil {
		return err
	}
	se.qname = sse.Qname
	se.qtype = dns.StringToType[sse.Qtype]
	se.addr = net.ParseIP(sse.Addr)
	se.proto = STR_TO_PROTO[sse.Proto]
	return nil
}

func (se *ServfailError) Error() string {
	return fmt.Sprintf("received a SERVFAIL while trying to query %s %s? from %s with %s", se.qname, dns.TypeToString[se.qtype], se.addr.String(), PROTO_TO_STR[se.proto])
}

type serializedNXDomainError struct {
	Type  string `json:"type"`
	Qname string `json:"qname"`
	Qtype string `json:"qtype"`
	Addr  string `json:"ip"`
	Proto string `json:"protocol"`
}

type NXDomainError struct {
	qname string
	qtype uint16
	addr  net.IP
	proto int
}

func NewNXDomainError(qname string, qtype uint16, addr net.IP, proto int) *NXDomainError {
	nx := new(NXDomainError)
	nx.qname = qname
	nx.qtype = qtype
	nx.addr = addr
	nx.proto = proto
	return nx
}
func (nx *NXDomainError) Error() string {
	return fmt.Sprintf("received a NXDomain while trying to query %s %s? from %s with %s", nx.qname, dns.TypeToString[nx.qtype], nx.addr.String(), PROTO_TO_STR[nx.proto])
}

func (nx *NXDomainError) MarshalJSON() ([]byte, error) {
	snx := new(serializedNXDomainError)
	snx.Type = dns.RcodeToString[dns.RcodeNameError]
	snx.Qname = nx.qname
	snx.Qtype = dns.TypeToString[nx.qtype]
	snx.Addr = nx.addr.String()
	snx.Proto = PROTO_TO_STR[nx.proto]
	return json.Marshal(snx)
}

func (nx *NXDomainError) UnmarshalJSON(bstr []byte) error {
	snx := new(serializedNXDomainError)
	if err := json.Unmarshal(bstr, snx); err != nil {
		return err
	}
	nx.qname = snx.Qname
	nx.qtype = dns.StringToType[snx.Qtype]
	nx.addr = net.ParseIP(snx.Addr)
	nx.proto = STR_TO_PROTO[snx.Proto]
	return nil
}

type serializedNoNameError struct {
	Name string `json:"name"`
}

type NoNameServerError struct {
	name string
}

func (ne *NoNameServerError) MarshalJSON() ([]byte, error) {
	sne := new(serializedNoNameError)
	sne.Name = ne.name
	return json.Marshal(sne)
}

func (ne *NoNameServerError) UnmarshalJSON(bstr []byte) error {
	sne := new(serializedNoNameError)
	if err := json.Unmarshal(bstr, sne); err != nil {
		return err
	}
	ne.name = sne.Name
	return nil
}

func NewNoNameServerError(name string) *NoNameServerError {
	return &NoNameServerError{name}
}

func (ne *NoNameServerError) Error() string {
	return fmt.Sprintf("%s has no nameservers", ne.name)
}
