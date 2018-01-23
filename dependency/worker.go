package dependency

import (
	"fmt"
	"github.com/hashicorp/go-immutable-radix"
	"github.com/miekg/dns"
	"github.com/ANSSI-FR/transdep/graph"
	"github.com/ANSSI-FR/transdep/messages/dependency"
	"github.com/ANSSI-FR/transdep/messages/nameresolver"
	"github.com/ANSSI-FR/transdep/messages/zonecut"
	"github.com/ANSSI-FR/transdep/tools"
	"github.com/ANSSI-FR/transdep/tools/radix"
	"github.com/ANSSI-FR/transdep/errors"
)

const WORKER_CHAN_CAPACITY = 10

// worker represents a handler of requests for a specific requestTopic.
// It retrieves the relevant information, cache it in memory and serves it until stop() is called.
type worker struct {
	// req is the request that is handled by this worker
	req *dependency.Request
	// reqs is a channel of requests with identical requestTopic as the original request
	reqs chan *dependency.Request
	// joinChan is used by stop() to wait for the completion of the start() goroutine
	joinChan chan bool
	// closedReqChan is used to prevent double-close during stop()
	closedReqChan bool
	// tree is the reference to a radix tree containing a view of the prefixes announced with BGP over the Internet.
	// This is used to fill IPNode instances with their corresponding ASN number, at the time of query.
	tree *iradix.Tree
	// depHandler is the handler used to fetch the dependency tree of a dependency of the current requestTopic
	depHandler func(*dependency.Request) *errors.ErrorStack
	// zcHandler is used to get the delegation info of some name that is part of the dependency tree of the current requestTopic
	zcHandler func(request *zonecut.Request) *errors.ErrorStack
	// nrHandler is used to get the IP addresses or Alias associated to a name that is part of the dependency tree of the current requestTopic
	nrHandler func(*nameresolver.Request) *errors.ErrorStack
	// config is the configuration of the current Transdep run
	config    *tools.TransdepConfig
}

/* newWorker instantiates and returns a new worker.
It builds the worker struct, and starts the routine in charge of building the dependency tree of the
requested topic and serving the answer to subsequent requests.

req is the first request that triggered the instantiation of that worker

depHandler is a function that can be called to have another dependency graph resolved (probably to integrate it to the current one)

zcHandler is a function that can be called to obtain the zone cut of a requested name

nrHandler is a function that can be called to obtain the IP address or Alias of a name
*/
func newWorker(req *dependency.Request, depHandler func(*dependency.Request) *errors.ErrorStack, zcHandler func(request *zonecut.Request) *errors.ErrorStack, nrHandler func(*nameresolver.Request) *errors.ErrorStack, conf *tools.TransdepConfig, tree *iradix.Tree) *worker {
	w := new(worker)
	w.req = req

	w.reqs = make(chan *dependency.Request, WORKER_CHAN_CAPACITY)
	w.closedReqChan = false

	w.joinChan = make(chan bool, 1)

	w.config = conf

	w.tree = tree

	w.depHandler = depHandler
	w.zcHandler = zcHandler
	w.nrHandler = nrHandler

	w.start()
	return w
}

/* handle is the function called to submit a new request to that worker.
Caller may call req.Result() after this function returns to get the result for this request.
This method returns an error if the worker is stopped or if the submitted request does not match the request usually
handled by this worker.
*/
func (w *worker) handle(req *dependency.Request) *errors.ErrorStack {
	if w.closedReqChan {
		return errors.NewErrorStack(fmt.Errorf("handle: dependency worker channel for %s is already closed", w.req.Name()))
	} else if !w.req.Equal(req) {
		return errors.NewErrorStack(fmt.Errorf("handle: invalid request; the submitted request (%s) does not match the requests handled by this worker (%s)", req.Name(), w.req.Name()))
	}
	w.reqs <- req
	return nil
}

// resolveRoot is a trick used to simplify the circular dependency of the root-zone, which is self-sufficient by definition.
func (w *worker) resolveRoot() graph.Node {
	g := graph.NewRelationshipNode("resolveRoot: dependency graph of the root zone", graph.AND_REL)
	g.AddChild(graph.NewDomainNameNode(".", true))
	return g
}

/*getParentGraph is a helper function which gets the dependency graph of the parent domain.
This function submits a new dependency request for the parent domain and waits for the result.
Consequently, this function triggers a recursive search of the parent domain dependency tree until the root-zone
dependency tree is reached. Said otherwise, for "toto.fr", this function triggers a search for the dependency radix of
"fr.", which will recursively trigger a search for the dependency tree of ".".
*/
func (w *worker) getParentGraph() (graph.Node, *errors.ErrorStack) {
	nxtLblPos, end := dns.NextLabel(w.req.Name(), 1)
	shrtndName := "."
	if !end {
		shrtndName = w.req.Name()[nxtLblPos:]
	}

	// resolveName and includeIP are set to false, because this name is not dependent of the IP address of set at the
	// parent domain, and we are not compatible with DNAME.
	req := dependency.NewRequestWithContext(shrtndName, false, false, w.req, 0)

	w.depHandler(req)

	res, err := req.Result()
	if err != nil {
		err.Push(fmt.Errorf("getParentGraph: error during resolution of parent graph %s of %s", shrtndName, w.req.Name()))
		return nil, err
	}

	return res, nil
}

// resolveSelf returns the graph of the current requestTopic
func (w *worker) resolveSelf() (graph.Node, *errors.ErrorStack) {
	g := graph.NewRelationshipNode(fmt.Sprintf("Dependency graph of exact name %s", w.req.Name()), graph.AND_REL)

	// First, we resolve the current name, to get its IP addresses or the indication that it is an alias
	nr := nameresolver.NewRequest(w.req.Name(), w.req.Exceptions())
	w.nrHandler(nr)

	var ne *nameresolver.Entry
	ne, err := nr.Result()
	if err != nil {
		err.Push(fmt.Errorf("resolveSelf: error while getting the exact resolution of %s", w.req.Name()))
		return nil, err
	}

	if ne.CNAMETarget() != "" {
		if !w.req.FollowAlias() {
			return nil, errors.NewErrorStack(fmt.Errorf("resolveSelf: alias detected (%s) but alias is not requested to be added to the graph of %s", ne.CNAMETarget(), w.req.Name()))
		}
		// the following line is commented because we might not want to add to the dependency graph the name of the node
		// that contains an alias that draws in a complete dependency graph, because this name is not really important
		// per se wrt dependency graphs.
		g.AddChild(graph.NewAliasNode(ne.CNAMETarget(), ne.Owner()))

		// We reuse the FollowAlias and IncludeIP value of the current requestTopic because if we are resolving a
		// name for a NS, we will want the IP address and to follow CNAMEs, even though this is an illegal configuration.
		// Depth is incremented so that overly long chains can be detected
		depReq := dependency.NewRequestWithContext(ne.CNAMETarget(), w.req.FollowAlias(), w.req.IncludeIP(), w.req, w.req.Depth()+1)
		w.depHandler(depReq)

		aliasGraph, err := depReq.Result()
		if err != nil {
			err.Push(fmt.Errorf("resolveSelf: error while getting the dependency graph of alias %s", ne.CNAMETarget()))
			return nil, err
		}
		g.AddChild(aliasGraph)
	} else if w.req.IncludeIP() {
		gIP := graph.NewRelationshipNode(fmt.Sprintf("IPs of %s", ne.Owner()), graph.OR_REL)
		g.AddChild(gIP)
		for _, addr := range ne.Addrs() {
			asn, err := radix.GetASNFor(w.tree, addr)
			if err != nil {
				asn = 0
			}
			gIP.AddChild(graph.NewIPNodeWithName(addr.String(), ne.Owner(), asn))
		}
	}
	return g, nil
}

// getDelegationGraph gets the graph relative to the delegation info of the current name. The graph is empty if the
// request topic is not a zone apex.
func (w *worker) getDelegationGraph() (graph.Node, *errors.ErrorStack) {
	g := graph.NewRelationshipNode(fmt.Sprintf("Dependency graph for %s delegation", w.req.Name()), graph.AND_REL)
	// Get the graph for the current zone. First, we get the delegation info for this zone, and we add it.
	req := zonecut.NewRequest(w.req.Name(), w.req.Exceptions())
	w.zcHandler(req)

	entry, err := req.Result()
	if err != nil {
		var returnErr bool
		switch typedErr := err.OriginalError().(type) {
		case *errors.TimeoutError:
			returnErr = true
		case *errors.NXDomainError:
			returnErr = w.req.Exceptions().RFC8020
		case *errors.ServfailError:
			returnErr = !w.req.Exceptions().AcceptServFailAsNoData
		case *errors.NoNameServerError:
			returnErr = false
		default:
			_ = typedErr
			returnErr = true
		}
		if returnErr {
			err.Push(fmt.Errorf("getDelegationGraph: error while getting the zone cut of %s", w.req.Name()))
			return nil, err
		}
		err = nil
		entry = nil
	}

	// If entry is nil, then we are at a non-terminal node, so we have no other dependencies (except aliases)
	if entry != nil {
		g.AddChild(graph.NewDomainNameNode(entry.Domain(), entry.DNSSEC()))

		nameSrvsGraph := graph.NewRelationshipNode(fmt.Sprintf("Graph of NameSrvInfo of %s", w.req.Name()), graph.OR_REL)
		g.AddChild(nameSrvsGraph)
		for _, nameSrv := range entry.NameServers() {
			nsGraph := graph.NewRelationshipNode(fmt.Sprintf("Graph of NS %s from NameSrvInfo of %s", nameSrv.Name(), w.req.Name()), graph.AND_REL)
			nameSrvsGraph.AddChild(nsGraph)

			// If there are glues
			if len(nameSrv.Addrs()) > 0 {
				nsAddrGraph := graph.NewRelationshipNode(fmt.Sprintf("IPs of %s", nameSrv.Name()), graph.OR_REL)
				nsGraph.AddChild(nsAddrGraph)
				for _, ip := range nameSrv.Addrs() {
					asn, err := radix.GetASNFor(w.tree, ip)
					if err != nil {
						asn = 0
					}
					nsAddrGraph.AddChild(graph.NewIPNodeWithName(ip.String(), nameSrv.Name(), asn))
				}
			} else {
				// The NS is out-of-bailiwick and does not contain glues; thus we ask for the dependency graph of
				// this NS name res
				req := dependency.NewRequestWithContext(nameSrv.Name(), true, true, w.req, 0)
				w.depHandler(req)

				NSGraph, err := req.Result()
				if err != nil {
					err.Push(fmt.Errorf("getDelegationGraph: error while getting the dependency graph of NS %s", nameSrv.Name()))
					return nil, err
				}
				nsGraph.AddChild(NSGraph)
			}
		}
	}
	return g, nil
}

// resolve orchestrates the resolution of the worker request topic and returns it
func (w *worker) resolve() (graph.Node, *errors.ErrorStack) {
	// Shortcut if this is the root zone, because we don't want to have to handle the circular dependency of the root-zone
	if w.req.Name() == "." {
		g := w.resolveRoot()
		return g, nil
	}

	// The graph of a name is the graph of the parent name + the graph of the name in itself (including its eventual
	// delegation info and its eventual alias/IP address)
	g := graph.NewRelationshipNode(fmt.Sprintf("Dependency graph for %s", w.req.Name()), graph.AND_REL)

	// Get Graph of the parent zone
	res, err := w.getParentGraph()
	if err != nil {
		err.Push(fmt.Errorf("resolve: error while getting the parent graph of %s", w.req.Name()))
		return nil, err
	}
	g.AddChild(res)

	// Get Graph of the delegation of the request topic
	graphDelegRes, err := w.getDelegationGraph()
	if err != nil {
		err.Push(fmt.Errorf("resolve: error while getting the delegation graph of %s", w.req.Name()))
		return nil, err
	}
	g.AddChild(graphDelegRes)

	// If the request topic is interesting in itself (for instance, because it is the name used in a NS record and that
	// name is out-of-bailiwick), we resolve its graph and add it
	if w.req.ResolveTargetName() {
		res, err := w.resolveSelf()
		if err != nil {
			err.Push(fmt.Errorf("resolve: error while resolving %s", w.req.Name()))
			return nil, err
		}
		g.AddChild(res)
	}

	return g, nil
}

// start launches a goroutine in charge of resolving the request topic, and then serving the result of this resolution
// to subsequent identical request topic
func (w *worker) start() {
	go func() {
		result, err := w.resolve()
		if err != nil {
			result = nil
			err.Push(fmt.Errorf("start: error while resolving dependency graph of %s", w.req.Name()))
		}
		for req := range w.reqs {
			req.SetResult(result, err)
		}
		w.joinChan <- true
	}()
}

// stop is to be called during the cleanup of the worker. It shuts down the goroutine started by start() and waits for
// it to actually end.
func (w *worker) stop() bool {
	if w.closedReqChan {
		return false
	}
	close(w.reqs)
	w.closedReqChan = true
	<-w.joinChan
	close(w.joinChan)
	return true
}
