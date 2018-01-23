package graph

import (
	"fmt"
	"encoding/hex"
	"github.com/awalterschulze/gographviz"
)

// isCritical returns true if n is similar to any of the criticalNodes
func isCritical(n LeafNode, criticalNodes []CriticalNode) bool {
	IPNode, isIPNode := n.(*IPNode)
	critical := false
	for _, cn := range criticalNodes {
		switch typedCritNode := cn.(type) {
		case CriticalName:
			critical = n.similar(NewDomainNameNode(typedCritNode.Name, false))
		case CriticalIP:
			critical = n.similar(NewIPNode(typedCritNode.IP.String(), 0))
		case CriticalAlias:
			critical = n.similar(NewAliasNode(typedCritNode.Target, typedCritNode.Source))
		case CriticalASN:
			if isIPNode {
				critical = IPNode.ASN() == typedCritNode.ASN
			}
		case CriticalPrefix:
			if isIPNode {
				critical = IPNode.Prefix() == typedCritNode.Prefix.String()
			}
		}
		if critical {
			return true
		}
	}
	return false
}

// DrawGraph initializes a graphviz graph instance rooted on g, then returns it, along with the "root" node of that
// "subgraph" (since g could be the children of another node). Members of the criticalNodes are highlighted.
func DrawGraph(g Node, criticalNodes []CriticalNode) (*gographviz.Graph, string) {
	gv := gographviz.NewGraph()
	gv.SetStrict(true)
	gv.SetDir(true)
	gv.Attrs.Add(string(gographviz.RankSep), "3")
	gv.Attrs.Add(string(gographviz.NodeSep), "1")
	h := g.hash()
	nodeId := "node" + hex.EncodeToString(h[:8])

	// Create a node, then add it and keep the reference to self, to add the edges later on.
	// Use attributes to encode AND or OR.
	switch node := g.(type) {
	case *RelationshipNode:
		var label string

		if node.relation == AND_REL {
			label = fmt.Sprintf("AND rel: %s", node.comment)
		} else {
			label = fmt.Sprintf("OR rel: %s", node.comment)
		}
		attr := make(map[gographviz.Attr]string)
		attr[gographviz.Label] = "\"" + label + "\""
		gv.Nodes.Add(&gographviz.Node{nodeId, attr})
		for _, chld := range node.children {
			chldGraph, firstNode := DrawGraph(chld, criticalNodes)
			for _, chldNode := range chldGraph.Nodes.Nodes {
				gv.Nodes.Add(chldNode)
			}
			for _, chldEdge := range chldGraph.Edges.Edges {
				gv.Edges.Add(chldEdge)
			}
			gv.AddEdge(nodeId, firstNode, true, nil)
		}
	case *Cycle:
		label := "Cycle"
		attr := make(map[gographviz.Attr]string)
		attr[gographviz.Label] = label
		attr[gographviz.Style] = "radial"
		attr[gographviz.FillColor] = "\"red:white\""
		gv.Nodes.Add(&gographviz.Node{nodeId, attr})
	case *DomainNameNode:
		label := node.Domain()
		attr := make(map[gographviz.Attr]string)
		if isCritical(node, criticalNodes) {
			attr[gographviz.Style] = "radial"
			attr[gographviz.FillColor] = "\"red:white\""
		}
		attr[gographviz.Label] = "\""+ label + "\""
		gv.Nodes.Add(&gographviz.Node{nodeId, attr})
	case *AliasNode:
		source := node.Source()
		attr := make(map[gographviz.Attr]string)
		attr[gographviz.Style] = "dotted"
		attr[gographviz.Label] = "\"" + source + "\""
		gv.Nodes.Add(&gographviz.Node{nodeId, attr})
		target := node.Target()
		attr = make(map[gographviz.Attr]string)
		attr[gographviz.Style] = "solid"
		attr[gographviz.Label] = "\"" + target + "\""
		gv.Nodes.Add(&gographviz.Node{nodeId+"2", attr})
		attr = make(map[gographviz.Attr]string)
		attr[gographviz.Label] = "CNAME"
		gv.Edges.Add(&gographviz.Edge{nodeId, "", nodeId+"2", "", true, attr})
	case *IPNode:
		label := node.IP()
		attr := make(map[gographviz.Attr]string)
		attr[gographviz.Label] = "\"" + label + "\""
		if isCritical(node, criticalNodes) {
			attr[gographviz.Style] = "radial"
			attr[gographviz.FillColor] = "\"red:white\""
		}
		gv.Nodes.Add(&gographviz.Node{nodeId, attr})
	}

	return gv, nodeId
}