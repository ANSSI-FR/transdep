package graph

import (
	"crypto/sha256"
	"encoding/json"
)


const (
	// OR_REL is a constant used to designate the OR relationship in RelationshipNode instances
	OR_REL = iota
	// AND_REL is a constant used to designate the AND relationship in RelationshipNode instances
	AND_REL
)

/* serializedRelationshipNode is a proxy struct used to serialize an RelationshipNode node into JSON.
The RelationshipNode struct is not directly used because the Go json module requires that attributes must be exported
for it to work, and RelationshipNode struct attributes have no other reason for being exported.
*/
type serializedRelationshipNode struct {
	Comment  string        `json:"comment"`
	Relation int           `json:"rel"`
	Children []interface{} `json:"elmts"`
}

// RelationshipNode instances represents intermediary nodes in the dependency graph. RelationshipNode are N-ary trees,
// not necessarily binary trees.
// Children of such a node are related following either an "and" or an "or" boolean expression.
type RelationshipNode struct {
	comment    string
	relation   int
	parentNode Node
	children   []Node
}

/* NewRelationshipNode returns a new RelationshipNode after initializing it.

comment is a free-form string giving some indication as to why this node exists and what it represents w.r.t. the 
dependency tree.

relation is either equal to AND_REL or OR_REL
*/
func NewRelationshipNode(comment string, relation int) *RelationshipNode {
	if relation != AND_REL && relation != OR_REL {
		panic("Contract violation: relation is not equal to AND_REL or OR_REL.")
	}
	g := new(RelationshipNode)
	g.comment = comment
	g.relation = relation
	return g
}

// Implements json.Marshaler
func (rn *RelationshipNode) MarshalJSON() ([]byte, error) {
	srn := new(serializedRelationshipNode)
	srn.Comment = rn.comment
	srn.Relation = rn.relation
	for _, v := range rn.children {
		srn.Children = append(srn.Children, v)
	}
	return json.Marshal(srn)
}

// Implements json.Unmarshaler
func (rn *RelationshipNode) UnmarshalJSON(b []byte) error {
	// This function unserializes first a serializedRelationShip node then tries to use this object to initialize the
	// receiver.
	srn := new(serializedRelationshipNode)
	err := json.Unmarshal(b, srn)
	if err != nil {
		return err
	}
	rn.comment = srn.Comment
	rn.relation = srn.Relation

	for _, chld := range srn.Children {
		m := chld.(map[string]interface{})
		rn.addChildrenFromMap(m)
	}
	return nil
}

/* addChildrenFromMap discovers from a map of interface{} the type of the object that was serialized as this map.
This is due to the fact that struct instances implementing an interface are uniformed as interface{} instances during
the serialization process and it is up to the unserializer to detect what's what.
Using the map key names, the object type is discovered. Ultimately, the object is initialized and added as a child of
the receiver.
*/
func (rn *RelationshipNode) addChildrenFromMap(m map[string]interface{}) {
	if _, ok := m["target"]; ok {
		rn.children = append(rn.children, NewAliasNode(m["target"].(string), m["source"].(string)))
	} else if _, ok := m["domain"]; ok {
		rn.children = append(rn.children, NewDomainNameNode(m["domain"].(string), m["dnssec"].(bool)))
	} else if _, ok := m["ip"]; ok {
		if _, ok := m["name"]; ok {
			rn.children = append(rn.children, NewIPNodeWithName(m["ip"].(string), m["name"].(string), int(m["asn"].(float64))))
		} else {
			rn.children = append(rn.children, NewIPNode(m["ip"].(string), int(m["asn"].(float64))))
		}
	} else if _, ok := m["comment"]; ok {
		// When there is a comment, this indicates a RelationshipNode => recursive call
		chldGraph := new(RelationshipNode)
		// Initialization of the child RelationshipNode cannot be done with initializeFromSerializedRelNode because the
		// child node is also represented as a map!
		chldGraph.initializeFromMap(m)
		rn.children = append(rn.children, chldGraph)
	} else if c, ok := m["type"] ; ok && c.(string) == "cycle" {
		// Cycles are represented in JSON as an object containing a "type" key, and a "cycle" string value.
		rn.children = append(rn.children, new(Cycle))
	} else {
		panic("BUG: invalid or unknown child type")
	}
}

// initializeFromMap initializes the receiver using a map representing a RelationshipNode unserialized from JSON
func (rn *RelationshipNode) initializeFromMap(m map[string]interface{}) {
	rn.comment = m["comment"].(string)
	// float64 is used for type casting because JSON numbers are floats. We recast it as int because we know that values
	// are only equal to AND_REL or OR_REL
	rn.relation = int(m["rel"].(float64))

	for _, chld := range m["elmts"].([]interface{}) {
		m := chld.(map[string]interface{})
		rn.addChildrenFromMap(m)
	}
}

func (rn *RelationshipNode) deepcopy() Node {
	cg := new(RelationshipNode)
	cg.comment = rn.comment
	cg.relation = rn.relation
	cg.children = make([]Node, 0, len(rn.children))
	cg.parentNode = rn.parentNode
	for _, chld := range rn.children {
		cg.children = append(cg.children, chld.deepcopy())
	}
	return cg
}

// AddChild adds a Node to the children of the receiver. This is the main function used for tree building
func (rn *RelationshipNode) AddChild(c Node) {
	rn.children = append(rn.children, c)
}

func (rn *RelationshipNode) String() string {
	jsonbtr, err := json.Marshal(rn)
	if err != nil {
		return ""
	}
	return string(jsonbtr)
}

func (rn *RelationshipNode) hash() [8]byte {
	var ret [8]byte
	h := sha256.Sum256([]byte(rn.String()))
	copy(ret[:], h[:8])
	return ret
}

func (rn *RelationshipNode) setParent(p Node) {
	rn.parentNode = p
}

func (rn *RelationshipNode) parent() Node {
	return rn.parentNode
}

func (rn *RelationshipNode) setParentNodes() {
	for _, chld := range rn.children {
		chld.setParent(rn)
		if cg, ok := chld.(*RelationshipNode); ok {
			cg.setParentNodes()
		}
	}
}