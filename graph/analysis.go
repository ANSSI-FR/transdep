package graph

import (
	"fmt"
	"github.com/hashicorp/go-immutable-radix"
	"github.com/deckarep/golang-set"
	"net"
	"github.com/ANSSI-FR/transdep/tools"
)

/* simplifyRelWithCycle recursively visit the tree and bubbles up Cycle instances in AND Relations or removes them if
they are in OR Relations.
It also simplifies relation nodes with only one child by bubbling up the child.

This function returns true if the children list of the receiver was modified.
*/
func (rn *RelationshipNode) simplifyRelWithCycle() bool {
	// newChildren is the list of children of the receiver after this function actions.
	var newChildren []Node
	modif := false
	childrenToAnalyze := rn.children[:]

	Outerloop:
	for len(childrenToAnalyze) != 0 {
		// mergedChildren will contain nodes contained in a child relation node which, itself, only has one child.
		// For instance, if a node A has a child B, and B only child is C, then B is suppressed from A's children
		// and C is added to mergedChildren.
		var mergedChildren []Node
		Innerloop:
		for _, chld := range childrenToAnalyze {
			if dg, ok := chld.(*RelationshipNode); ok {
				// If the child node is a relation ship, visit the child recursively
				modif = dg.simplifyRelWithCycle() || modif
				// Now, if the child, after the recursive visit only has one child, bubble up that child
				if len(dg.children) == 1 {
					mergedChildren = append(mergedChildren, dg.children[0])
					modif = true
					// We continue, because this child node will not be added back to the children of the receiver
					continue Innerloop
				}
			}
			if _, ok := chld.(*Cycle); ok {
				// Implicit: if the relation is not an AND, it is a OR. In OR relations, Cycles are a neutral element,
				// like a 1 in a multiplicative expression.
				if rn.relation == AND_REL && len(rn.children) > 1 {
					// If the considered child is a Cycle and the receiver is an AND relation, then the receiver
					// evaluation is summarized by this Cycle (because a Cycle in a AND relation is like a 0 in a
					// multiplicative expression), so we just set the receiver's only child to a Cycle and don't process
					// the remaining children.
					newChildren = []Node{new(Cycle)}
					modif = true
					break Outerloop
				}
			}
			// This node is not a Cycle, so we add it back as a child the receiver
			newChildren = append(newChildren, chld)
		}
		// If we have bubbled up some grand-children nodes, we need to analyse them as children of the receiver
		childrenToAnalyze = mergedChildren
	}
	rn.children = newChildren
	return modif
}

/* auxSimplifyGraph recursively visits the graph and simplifies it. Simplification is done by merging relation
nodes when the receiver and one of its child relation node have the same relation type. Child relation nodes are like
parenthesis in a mathematical expression: 1 + (2*3 + 4) is equivalent to 1 + 2*3 + 4 and 2 * (3 * 4) is equivalent
to 2 * 3 * 4. Simplifying the graph that way reduces the depth of the graph and accelerates future visits.

This function returns true if the graph/tree below the receiver was altered
*/
func (rn *RelationshipNode) auxSimplifyGraph() bool {
	var newChildren []Node
	modif := false

	// TODO I don't think I need to actually duplicate this
	childrenToAnalyze := make([]Node, len(rn.children))
	copy(childrenToAnalyze, rn.children)

	for len(childrenToAnalyze) > 0 {
		var mergedChildren []Node
		for _, chldGraphNode := range childrenToAnalyze {
			if chld, ok := chldGraphNode.(*RelationshipNode); ok {
				if chld.relation == rn.relation {
					// If the receiver's child currently considered is a RelationshipNode with the relation type as the
					// receiver, then, add the children of this child node to the list of nodes that will be considered
					// as children of the receiver.
					mergedChildren = append(mergedChildren, chld.children...)
					modif = true
				} else {
					// The child RelationshipNode node has a different relation type
					// (AND containing an OR, or an OR containing an AND).
					newChildren = append(newChildren, chldGraphNode)
				}
			} else {
				// This child node is a LeafNode
				newChildren = append(newChildren, chldGraphNode)
			}
		}
		// TODO I don't think I need to actually duplicate this
		childrenToAnalyze = make([]Node, len(mergedChildren))
		copy(childrenToAnalyze, mergedChildren)
	}
	// TODO I don't think I need to actually duplicate this
	rn.children = make([]Node, len(newChildren))
	copy(rn.children, newChildren)

	// Once the receiver simplified, we apply this function on all remaining children relation nodes
	for _, chldGraphNode := range rn.children {
		if chld, ok := chldGraphNode.(*RelationshipNode); ok {
			modif = chld.auxSimplifyGraph() || modif
		}
	}
	return modif
}

// SimplifyGraph creates a copy of the tree under the receiver, simplifies the radix under the copy, by applying
// repetitively auxSimplyGraph and simplifyRelWithCycle until the tree is stable.
// The copy is then returned.
func (rn *RelationshipNode) SimplifyGraph() *RelationshipNode {
	ng, ok := rn.deepcopy().(*RelationshipNode)
	if !ok {
		return nil
	}

	modif := true
	for modif {
		modif = false
		modif = ng.auxSimplifyGraph() || modif
		modif = ng.simplifyRelWithCycle() || modif
	}
	return ng
}

// buildLeafNodeInventory visits the tree under the receiver and returns the list of the LeafNodes. This list is built
// by visiting the tree recursively.
func (rn *RelationshipNode) buildLeafNodeInventory() []LeafNode {
	l := make([]LeafNode, 0)
	for _, absChld := range rn.children {
		switch chld := absChld.(type) {
		case *RelationshipNode:
			l2 := chld.buildLeafNodeInventory()
			l = append(l, l2...)
		case LeafNode:
			l = append(l, chld)
		}
	}
	return l
}

// TODO add comment
func getSiblingsUsingSimilarity(leafNode LeafNode, inventory []LeafNode, breakV4, breakV6, DNSSECOnly bool) []LeafNode {
	// siblings are leafNode that are considered unavailable during the analysis of leafNode
	// Are considered unavailable other nodes that are similar to leafNode (similarity being defined by the similar()
	// implementation of the leafNode underlying type. Are never considered unavailable unsigned names when DNSSECOnly
	// is true as well as alias names. Alias names are always ignored because they are never the actual source of an
	// unavailability; either the zone that contains the alias is unavailable or the zone containing the target of the
	// alias is unavailable.
	// IPv4 addresses are always considered unavailable if breakV4 is true. The same applies for IPv6 addresses w.r.t.
	// breakV6.
	var siblings []LeafNode
	for _, node := range inventory {
		toIgnore := false
		toAdd := false
		switch n := node.(type) {
		case *DomainNameNode:
			if DNSSECOnly && !n.DNSSECProtected() {
				toIgnore = true
			}
		case *AliasNode:
			toIgnore = true
		case *IPNode:
			isV4 := n.IsV4()
			if (breakV4 && isV4) || (breakV6 && !isV4) {
				toAdd = true
			}
		case *Cycle:
			toAdd = true
		}
		if toAdd || (!toIgnore && leafNode.similar(node)) {
			siblings = append(siblings, node)
		}
	}
	return siblings
}

/* TODO revise this comment
testNodeCriticity returns true if leafNode is necessary for this tree to be resolved. External factors may influence
whether this leafNode is required to be available, including whether the IPv4 network or the IPv6 network are
available or whether we consider that only DNSSEC-protected zone may break (e.g. in case of invalid/expired
record signatures, or DS/DNSKEY algorithm mismatches) versus all zones (e.g. truncated zone, corrupted data, etc.).

leafNode is the node being tested

inventory is the list of all leafNodes that might be broken too and influence the result

breakV4, breakV6 and DNSSEConly are flags that indicates additional conditions for a node to be available or not.
*/
func (rn *RelationshipNode) testNodeCriticity(siblings []LeafNode) bool {
	// The following loops purpose is to bubble up the unavailability markers of the leafNode. If an unavailable node
	// is a child of an AND relationship, the whole relationship is unavailable. If an unavailable node is a child of
	// an OR relationship, the whole relationship is unavailable if all of its children are unavailable.
	// The algorithm terminates if the tree root is added to new unavailable node list or if there a no more
	// unavailability markers that may bubble up.
	// Since multiple "and" branches may have bubbling unavailability markers, "and"s bubble up only once, so that it
	// does not mess up with the "or" count. "And"s bubbles up only once by marking it as "already bubbled". This is
	// done by inserting it in the andSet. The number of children of an Or relationship that have bubbled up an
	// unavailability marker is stored in the orSet variable.
	orSet := make(map[*RelationshipNode]int)
	andSet := make(map[*RelationshipNode]bool)

	var unavailableNodes []Node
	for _, n := range siblings {
		unavailableNodes = append(unavailableNodes, n)
	}

	for len(unavailableNodes) > 0 {
		nodesToHandle := unavailableNodes
		unavailableNodes = []Node{}

		for _, node := range nodesToHandle {
			parent := node.parent()
			if parent == nil {
				// if "node" is the root node
				return true
			}

			n := parent.(*RelationshipNode)
			if n.relation == AND_REL {
				if _, ok := andSet[n]; !ok {
					andSet[n] = true
					unavailableNodes = append(unavailableNodes, n)
				}
			} else {
				if v, ok := orSet[n]; ok {
					orSet[n] = v + 1
				} else {
					orSet[n] = 1
				}
				if len(n.children) == orSet[n] {
					unavailableNodes = append(unavailableNodes, n)
				}
			}
		}
	}
	return false
}

// TODO add comment
func getSiblingsByPrefixCloseness(n LeafNode, inventory []LeafNode) []LeafNode {
	if ipn, ok := n.(*IPNode) ; ok {
		return getSiblingsUsingFilteringFun(inventory, ipn.similarPrefix)
	}
	return []LeafNode{}
}

// TODO add comment
func (rn *RelationshipNode) findMandatoryNodesUsingPrefixCloseness(inventory []LeafNode)(mandatoryNodes, optionalNodes mapset.Set) {
	return rn.findMandatoryNodes(inventory, getSiblingsByPrefixCloseness)
}

// TODO add comment
func (rn *RelationshipNode) findMandatoryNodesUsingSimilarity(inventory []LeafNode, breakV4, breakV6, DNSSECOnly bool) (mandatoryNodes, optionalNodes mapset.Set) {
	getSiblingsFun := func(n LeafNode, inv []LeafNode) []LeafNode {
		return getSiblingsUsingSimilarity(n, inv, breakV4, breakV6, DNSSECOnly)
	}
	return rn.findMandatoryNodes(inventory, getSiblingsFun)
}

// TODO add comment
func getSiblingsUsingFilteringFun(inventory []LeafNode, customFilterFun func(lf LeafNode) bool) []LeafNode {
	var siblings []LeafNode
	for _, lf := range inventory {
		if _, ok := lf.(*Cycle) ; ok || customFilterFun(lf) {
			siblings = append(siblings, lf)
		}
	}
	return siblings
}

// TODO add comment
func getSiblingsByASN(n LeafNode, inventory []LeafNode) []LeafNode {
	if ipn, ok := n.(*IPNode) ; ok {
		return getSiblingsUsingFilteringFun(inventory, ipn.similarASN)
	}
	return []LeafNode{}
}

// TODO add comment
func (rn *RelationshipNode) findMandatoryNodesUsingASN(inventory []LeafNode) (mandatoryNodes, optionalNodes mapset.Set) {
	return rn.findMandatoryNodes(inventory, getSiblingsByASN)
}

// TODO revise comment
// findMandatoryNodes explores all nodes from the inventory and returns the list of leafNodes that are mandatory
func (rn *RelationshipNode) findMandatoryNodes(inventory []LeafNode, getSiblingsFun func(LeafNode, []LeafNode) []LeafNode) (mandatoryNodes, optionalNodes mapset.Set) {
	mandatoryNodesSet := make(map[[8]byte]LeafNode)
	optionalNodesSet := make(map[[8]byte]LeafNode)

	for _, leafNode := range inventory {
		// We use a hash of the leafNode to "uniquely" identify nodes. This is because several leafNode instances have
		// different memory addresses, while still representing the same node (at the semantic level).
		h := leafNode.hash()

		// Test whether this node was already evaluated
		if _, ok := mandatoryNodesSet[h]; ok {
			continue
		}
		if _, ok := optionalNodesSet[h]; ok {
			continue
		}

		// We cut the inventory using pos, because if we are here, all previous nodes were not "siblings" of this one.
		// If they had been, we would have "continue"d  during the previous tests
		siblings := getSiblingsFun(leafNode, inventory)
		if rn.testNodeCriticity(siblings) {
			mandatoryNodesSet[h] = leafNode
		} else {
			optionalNodesSet[h] = leafNode
		}
	}

	mandatoryNodes = mapset.NewThreadUnsafeSet()
	optionalNodes = mapset.NewThreadUnsafeSet()
	// Convert the map into a list of the map values
	for _, v := range mandatoryNodesSet {
		mandatoryNodes.Add(v)
	}
	// Convert the map into a list of the map values
	for _, v := range optionalNodesSet {
		optionalNodes.Add(v)
	}
	return mandatoryNodes, optionalNodes
}

// TODO add comment
func convertToListOfLeafNodes(s mapset.Set) []LeafNode {
	var l []LeafNode
	for _, v := range s.ToSlice() {
		l = append(l, v.(LeafNode))
	}
	return l
}

// analyse starts the analysis of the tree under the receiver and returns the list of mandatory nodes
func (rn *RelationshipNode) analyse(breakV4, breakV6, DNSSECOnly bool, tree *iradix.Tree) []CriticalNode {
	// A copy of the receiver's tree is performed because we will alter the nodes by simplyfing the graph and setting
	// the parent of the nodes and we don't want to be "destructive" in anyway
	ng := rn.SimplifyGraph()
	ng.setParentNodes()

	inventory := ng.buildLeafNodeInventory()

	var criticalNodes []CriticalNode

	mandatoryNodes, _ := ng.findMandatoryNodesUsingSimilarity(inventory, breakV4, breakV6, DNSSECOnly)
	for _, node := range convertToListOfLeafNodes(mandatoryNodes) {
		switch typedNode := node.(type) {
		case *DomainNameNode:
			criticalNodes = append(criticalNodes, CriticalName{typedNode.Domain()})
		case *IPNode:
			criticalNodes = append(criticalNodes, CriticalIP{net.ParseIP(typedNode.IP())})
		case *Cycle:
			criticalNodes = append(criticalNodes, &Cycle{})
		}
	}

	mandatoryNodes, _ = ng.findMandatoryNodesUsingASN(inventory)
	asnSet := make(map[int]bool)
	for _, node := range convertToListOfLeafNodes(mandatoryNodes) {
		if typedNode, ok := node.(*IPNode) ; ok {
			asnSet[typedNode.ASN()] = true
		}
	}
	for asn, _ := range asnSet {
		criticalNodes = append(criticalNodes, CriticalASN{asn})
	}

	mandatoryNodes, _ = ng.findMandatoryNodesUsingPrefixCloseness(inventory)
	prefixSet := make(map[string]bool)
	for _, node := range convertToListOfLeafNodes(mandatoryNodes) {
		if typedNode, ok := node.(*IPNode) ; ok {
			prefixSet[typedNode.Prefix()] = true
		}
	}
	for prefix, _ := range prefixSet {
		criticalNodes = append(criticalNodes, CriticalPrefix{net.ParseIP(prefix)})
	}
	return criticalNodes
}

// Analyse is the exported version of analyse. It starts the analysis of the tree under the receiver and returns the
// list of mandatory nodes.
// IPv4 and IPv6 addresses have normal availability markers (no breakV4/breakV6)
func (rn *RelationshipNode) Analyse(DNSSECOnly bool, tree *iradix.Tree) []CriticalNode {
	return rn.analyse(false, false, DNSSECOnly, tree)
}

// AnalyseWithoutV4 runs the same type of analysis as "Analyse" except all IPv4 addresses are marked as unavailable.
// This may reveal that some IPv6 are actually SPOFs when IPv4 addresses are not available.
// AnalyseWithoutV4 may either return the list of mandatory leafNodes or an error if the name cannot be resolved without
// IPv4 address participation.
func (rn *RelationshipNode) AnalyseWithoutV4(DNSSECOnly bool, tree *iradix.Tree) ([]CriticalNode, error) {
	l := rn.analyse(true, false, DNSSECOnly, tree)
	for _, e := range l {
		if node, ok := e.(CriticalIP); ok {
			if node.IP.To4() != nil {
				return []CriticalNode{}, fmt.Errorf("this domain name requires some IPv4 addresses to be resolved properly")
			}
		}
	}
	return l, nil
}

// AnalyseWithoutV6 runs the same type of analysis as "Analyse" except all IPv6 addresses are marked as unavailable.
// This may reveal that some IPv4 are actually SPOFs when IPv6 addresses are not available.
// AnalyseWithoutV6 may either return the list of mandatory leafNodes or an error if the name cannot be resolved without
// IPv6 address participation.
func (rn *RelationshipNode) AnalyseWithoutV6(DNSSECOnly bool, tree *iradix.Tree) ([]CriticalNode, error) {
	l := rn.analyse(false, true, DNSSECOnly, tree)
	for _, e := range l {
		if node, ok := e.(CriticalIP); ok {
			if node.IP.To4() == nil {
				return []CriticalNode{}, fmt.Errorf("this domain name requires some IPv6 addresses to be resolved properly")
			}
		}
	}
	return l, nil
}


type WorkerAnalysisResult struct {
	Nodes []CriticalNode
	Err   error
}

func PerformAnalyseOnResult(g *RelationshipNode, reqConf *tools.RequestConfig, tree *iradix.Tree) (allNamesResult, allNamesNo4Result, allNamesNo6Result, dnssecResult, dnssecNo4Result, dnssecNo6Result *WorkerAnalysisResult) {
	if !reqConf.AnalysisCond.DNSSEC || reqConf.AnalysisCond.All {
		dnssecResult = nil
		dnssecNo4Result = nil
		dnssecNo6Result = nil
		allNamesResult, allNamesNo4Result, allNamesNo6Result = performAnalyseOnResultWithDNSSECIndicator(g, reqConf,false, tree)
	}

	if reqConf.AnalysisCond.DNSSEC || reqConf.AnalysisCond.All {
		if !reqConf.AnalysisCond.All {
			allNamesResult = nil
			allNamesNo4Result = nil
			allNamesNo6Result = nil
		}
		dnssecResult, dnssecNo4Result, dnssecNo6Result = performAnalyseOnResultWithDNSSECIndicator(g, reqConf, true, tree)
	}
	return
}

func performAnalyseOnResultWithDNSSECIndicator(g *RelationshipNode, reqConf *tools.RequestConfig, DNSSEC bool, tree *iradix.Tree) (natural, noV4, noV6 *WorkerAnalysisResult) {
	if reqConf.AnalysisCond.All || (!reqConf.AnalysisCond.NoV4 && !reqConf.AnalysisCond.NoV6) {
		natural = &WorkerAnalysisResult{g.Analyse(DNSSEC, tree), nil}
	} else {
		natural = nil
	}

	if reqConf.AnalysisCond.All || reqConf.AnalysisCond.NoV4 {
		analyseResult, err := g.AnalyseWithoutV4(DNSSEC, tree)
		noV4 = &WorkerAnalysisResult{analyseResult, err}
	} else {
		noV4 = nil
	}

	if reqConf.AnalysisCond.All || reqConf.AnalysisCond.NoV6 {
		analyseResult, err := g.AnalyseWithoutV6(DNSSEC, tree)
		noV6 = &WorkerAnalysisResult{analyseResult, err}
	} else {
		noV6 = nil
	}
	return
}

