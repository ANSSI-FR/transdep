package graph

// A node is an intermediary node (RelationshipNode) or a LeafNode in a dependency graph.
type Node interface {
	String() string
	// deepcopy performs a copy the receiver node and returns the new identical instance
	deepcopy() Node
	// setParent sets the parent node of the receiver
	setParent(g Node)
	// parent returns the parent node of the receiver
	parent() Node
	// hash returns a byte array representing the node as a value that can be used as a map key
	hash() [8]byte
}

// A LeafNode is, as the name implies a leaf node in a dependency tree. The only difference with the Node interface
// is that LeadNode instances can be compared using the similar() method.
type LeafNode interface {
	Node
	// similar compares two LeafNode and returns true if they are similar enough (not necessarily strictly similar, though)
	similar(g LeafNode) bool
}
