package dependency

import (
	"github.com/miekg/dns"
	"github.com/ANSSI-FR/transdep/graph"
	"github.com/ANSSI-FR/transdep/tools"
	"strings"
	"time"
	"github.com/ANSSI-FR/transdep/errors"
)

/* RequestTopic is a key used to uniquely represent a request.
This may be used in order to detect request loops and circular dependencies, and to identify the topic of a
dependency resolver worker.
*/
type RequestTopic struct {
	// domain is the queried domain name
	domain string
	/* followAlias indicates whether to insert the resolved name as part of the dependency tree. This is part of the
	topic because we could have two workers, one returning the cached result WITH the name resolved, and one
	WITHOUT the name resolved.
	*/
	followAlias bool
	// includeIP indicates whether to insert to the IP addresses as part of the dependency tree. This is part of the
	// topic of the same reasons resolveName is.
	includeIP bool
	/* depth is used to detect CNAME/aliases loops and overly long chains. Also, it is used to differentiate request
	topic because a chain might be considered too long from a starting point and not too long if considered from a
	node in the middle of the chain. For instance, let's consider of a CNAME chain where "A" is a CNAME to "B",
	"B" is a CNAME to "C" and so on until "K". This is a 10 CNAME long chain. We might not be interested in
	following through after "K" to spare resources. Now, if that "not following through" was cached, this would be
	problematic if someone considered the chain from "F"; indeed, the "F" to "K" chain is not 10 CNAME long. In that
	case, we want to follow through to see where "K" resolves. Since the response to the "A" request is composed of
	the resolution of "A" and the response to "B" (and so on), caching the "K" response saying that this is a "dead"
	chain would be incorrect, except if we cache that this is the "K" response after a 9 CNAME long chain.
	*/
	depth int
	/*
	except contains a list of booleans indicating the exceptions/violations to the DNS protocol that we are OK to accept
	for this query
	 */
	except tools.Exceptions
}

//TODO revoir cet exemple !
/* Request struct represents a request sent to fetch the dependency tree about a domain name.

It is initialized by calling NewRequest. A request is passed to the Finder.Handle() method. The result of the Finder
handling is obtained by calling the request Result() method.
	import (
		"github.com/ANSSI-FR/transdep/graph"
		"github.com/ANSSI-FR/transdep/dependency"
		"github.com/ANSSI-FR/transdep/tools"
	)

	func example(f *dependency.Finder, domain string) *graph.Node {
		r := NewRequest(domain, false, false)
		f.Handle(r)
		result, err := r.Result()
		if err != nil {
			if err == tools.ERROR_TIMEOUT {
				fmt.Printf("Timeout during resolution of %s\n", domain)
			} else {
				fmt.Println(err)
			}
			return
		} else if result.Err != nil {
			fmt.Println(result.Err)
			return
		}
		graph := result.Result
		return graph
	}
*/
type Request struct {
	topic RequestTopic
	// resultChan is used as a "blocking" communication channel between the goroutine that resolves the request and the
	// goroutine that is waiting for the result. The goroutine waiting for the result blocks on "Result()" until the
	// worker responsible for the result is ready to send it by calling SetResult on the request.
	resultChan chan *result
	// context is used to detect dependency loops. It is just a stack of request topic that were already spooled and
	// that led to the resolution of the current request topic
	context map[RequestTopic]bool
}

/* NewRequest builds a new request from a context-free perspective.
This is mainly used when making a request that is completely unrelated to any other request. Thus, it should be used
by the dependency finder users to submit requests.

domain is the domain name that is requested for dependency resolution

resolveName indicates whether we are interested in following an eventual CNAME that is found at the requested domain
name. False indicates that we only want the dependency tree for the parent domains of the requested name and the
delegation info to that name.

includeIP indicates that on top of following the eventual CNAME, we want the IP addresses associated to the requested domain name
*/
func NewRequest(domain string, resolveName, includeIP bool, except tools.Exceptions) *Request {
	dr := new(Request)
	dr.topic.domain = strings.ToLower(dns.Fqdn(domain))
	dr.topic.followAlias = resolveName
	dr.topic.includeIP = includeIP
	dr.topic.depth = 0
	dr.topic.except = except
	dr.resultChan = make(chan *result, 1)
	dr.context = make(map[RequestTopic]bool)
	return dr
}

/* NewRequestWithContext builds a new request that is built in the context of the resolution of another request. Thus,
it is possible that loops get created, if a request is dependent on the resolution of another request which is dependent
on the result of the resolution of the first request. Building a request using NewRequestWithContext will prevent this
by using the DetectCycle() method whenever appropriate.
*/
func NewRequestWithContext(domain string, resolveName, includeIP bool, parentReq *Request, depth int) *Request {
	dr := new(Request)
	dr.topic.domain = strings.ToLower(dns.Fqdn(domain))
	dr.topic.followAlias = resolveName
	dr.topic.includeIP = includeIP
	dr.topic.depth = depth
	dr.topic.except = parentReq.Exceptions()
	dr.resultChan = make(chan *result, 1)

	/* Simply affecting the parentReq.context to dr.context would only copy the map reference, but we need a deepcopy
	here, because the parentReq context must NOT be changed by the addition of the parentReq to the context :)) Else,
	this would break cycle detection if the parent request was to be dependent of multiple request results. */
	dr.context = make(map[RequestTopic]bool)
	for k, v := range parentReq.context {
		dr.context[k] = v
	}
	dr.context[parentReq.topic] = true

	return dr
}

// Name is the getter of the domain name that is the topic of this request.
func (dr *Request) Name() string {
	return dr.topic.domain
}

func (dr *Request) Exceptions() tools.Exceptions {
	return dr.topic.except
}

// FollowAlias is the getter of the FollowAlias value part of the topic of this request.
func (dr *Request) FollowAlias() bool {
	return dr.topic.followAlias
}

// IncludeIP is the getter of the IncludeIP value part of the topic of this request.
func (dr *Request) IncludeIP() bool {
	return dr.topic.includeIP
}

func (dr *Request) Equal(other *Request) bool {
	return dr.topic == other.topic
}

/* ResolveTargetName indicates whether the requester is interested in the value of the requested name (the CNAME and
its dependency tree or the IP addresses) or if the request topic is only the dependency graph of the apex of the zone
containing the requested domain name.
*/
func (dr *Request) ResolveTargetName() bool {
	return dr.topic.followAlias || dr.topic.includeIP
}

// Topic is the getter of the request topic as specified during this request initialization
func (dr *Request) Topic() RequestTopic {
	return dr.topic
}

// Returns the depth of the current request. This is used to detect overly long alias chains
func (dr *Request) Depth() int {
	return dr.topic.depth
}

// SetResult records the result of this request.
// This function must only be called once per request, although nothing enforces it at the moment...
func (dr *Request) SetResult(g graph.Node, err *errors.ErrorStack) {
	if err != nil {
		err = err.Copy()
	}
	dr.resultChan <- &result{g, err}
}

/* Result returns the result that is set by SetResult().
If the result is yet to be known when this method is called, a timeout duration is waited and if there are still no
result available after that period, tools.ERROR_TIMEOUT is returned as an error.
The specific timeout duration may be specified if the default one is not appropriate, using the
ResultWithSpecificTimeout() method, instead of calling Result()
*/
func (dr *Request) Result() (graph.Node, *errors.ErrorStack) {
	return dr.ResultWithSpecificTimeout(tools.DEFAULT_TIMEOUT_DURATION)
}

// ResultWithSpecificTimeout usage is described in the documentation of Request.Result()
func (dr *Request) ResultWithSpecificTimeout(dur time.Duration) (graph.Node, *errors.ErrorStack) {
	select {
	case res := <-dr.resultChan:
		return res.Result, res.Err
	case _ = <-tools.StartTimeout(dur):
		return nil, errors.NewErrorStack(errors.NewTimeoutError("dependency graph resolution", dr.topic.domain))
	}
}

// DetectCycle returns true if this request creates a dependency cycle
func (dr *Request) DetectCycle() bool {
	_, ok := dr.context[dr.topic]
	return ok
}
