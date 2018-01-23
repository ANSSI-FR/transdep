package graph

import "net"

type CriticalIP struct {
	IP net.IP `json:"ip"`
}

type CriticalName struct {
	Name string `json:"name"`
}

type CriticalAlias struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

type CriticalASN struct {
	ASN int `json:"asn"`
}

type CriticalPrefix struct {
	Prefix net.IP `json:"prefix"`
}

type CriticalNode interface {
	isCriticalNode()
}

func (n CriticalIP) isCriticalNode() {}
func (n CriticalName) isCriticalNode() {}
func (n CriticalAlias) isCriticalNode() {}
func (n CriticalASN) isCriticalNode() {}
func (n CriticalPrefix) isCriticalNode() {}

// Cycles are also critical nodes
func (c *Cycle) isCriticalNode() {}