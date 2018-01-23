package dependency

import (
	"github.com/ANSSI-FR/transdep/graph"
	"github.com/ANSSI-FR/transdep/errors"
)

/* result contains the result of a dependency request, containing the dependency tree or an error message associated to
that dependency tree resolution.

This struct is used mainly as a vector inside go channels to emulate multiple return values.
*/
type result struct {
	Result graph.Node
	Err    *errors.ErrorStack
}
