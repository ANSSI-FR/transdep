package nameresolver

import (
	"github.com/miekg/dns"
	"github.com/ANSSI-FR/transdep/tools"
	"time"
	"strings"
	"github.com/ANSSI-FR/transdep/errors"
)

type RequestTopic struct {
	// name is the request topic.
	Name string
	// except is the list of exceptions/violations of the DNS protocol that we are willing to accept for this query
	Exceptions tools.Exceptions
}

// Request represents a request to the name resolution "finder".
type Request struct {
	topic RequestTopic
	// resultChan is used internally by the request methods to pass around the result of the request between the worker
	// goroutine doing the resolution and the calling goroutines that initiated the resolution.
	resultChan chan *result
	// context is used for cycle detection to prevent cyclic name resolution, for instance if a domain name owns a
	// CNAME to itself or if a CNAME chain is circular.
	context    map[RequestTopic]bool
}

// NewRequest builds a new Request instance.
// This is the standard way of building new requests from a third-party module.
func NewRequest(name string, except tools.Exceptions) *Request {
	nr := new(Request)
	nr.topic.Name = strings.ToLower(dns.Fqdn(name))
	nr.topic.Exceptions = except
	nr.resultChan = make(chan *result, 1)
	nr.context = make(map[RequestTopic]bool)
	return nr
}

// NewRequestWithContext builds a new Request instance, adding some context information to it to prevent resolution loops.
// This is mainly used by github.com/ANSSI-FR/transdep/nameresolver
func NewRequestWithContext(name string, except tools.Exceptions, ctx *Request) *Request {
	nr := new(Request)
	nr.topic.Name = strings.ToLower(dns.Fqdn(name))
	nr.topic.Exceptions = except
	nr.resultChan = make(chan *result, 1)
	nr.context = make(map[RequestTopic]bool)
	for k, v := range ctx.context {
		nr.context[k] = v
	}
	nr.context[ctx.topic] = true
	return nr
}

func (nr *Request) Name() string {
	return nr.topic.Name
}

func (nr *Request) Exceptions() tools.Exceptions {
	return nr.topic.Exceptions
}

func (nr *Request) RequestTopic() RequestTopic {
	return nr.topic
}

// DetectLoop returns true if this request is part of a resolution loop
func (nr *Request) DetectLoop() bool {
	_, ok := nr.context[nr.topic]
	return ok
}

func (nr *Request) Equal(other *Request) bool {
	return nr.topic == other.topic
}

// Result returns the result of a name resolution or an error.
// The error may be caused by a timeout after the default timeout duration, or an error during the resolution process.
func (nr *Request) Result() (*Entry, *errors.ErrorStack) {
	return nr.ResultWithSpecificTimeout(tools.DEFAULT_TIMEOUT_DURATION)
}

// ResultWithSpecificTimeout is similar to Result except that a timeout duration may be specified.
func (nr *Request) ResultWithSpecificTimeout(dur time.Duration) (*Entry, *errors.ErrorStack) {
	select {
	case res := <-nr.resultChan:
		return res.Result, res.Err
	case _ = <-tools.StartTimeout(dur):
		return nil, errors.NewErrorStack(errors.NewTimeoutError("name resolution", nr.topic.Name))
	}
}

// SetResult allows the definition of the result value associated with this request.
func (nr *Request) SetResult(resEntry *Entry, err *errors.ErrorStack) {
	if err != nil {
		err = err.Copy()
	}
	nr.resultChan <- &result{resEntry, err}
}
