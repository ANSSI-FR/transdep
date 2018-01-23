package graph

import (
	"bytes"
	"encoding/json"
)

// Cycle instances represent parts of the graph where circular dependencies are detected. During analysis, they
// signify that this branch of the graph is always invalid.
type Cycle struct {
	parentNode Node
}

func (c *Cycle) String() string {
	jsonbstr, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return string(jsonbstr)
}

// Implements json.Marshaler
func (c *Cycle) MarshalJSON() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.WriteString("{\"type\": \"cycle\"}")
	return buf.Bytes(), nil
}

// Implements json.Unmarshaler
func (c *Cycle) UnmarchalJSON([]byte) error {
	return nil
}

func (c *Cycle) deepcopy() Node {
	nc := new(Cycle)
	nc.parentNode = c.parentNode
	return nc
}

func (c *Cycle) setParent(g Node) {
	c.parentNode = g
}

func (c *Cycle) parent() Node {
	return c.parentNode
}

// similar returns true if the provided LeafNode is also a Cycle node
func (c *Cycle) similar(o LeafNode) bool {
	_, ok := o.(*Cycle)
	return ok
}

func (c *Cycle) hash() (ret [8]byte) {
	copy(ret[:], []byte("Cycle")[:8])
	return
}
