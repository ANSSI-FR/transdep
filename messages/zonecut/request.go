package zonecut

import (
	"github.com/miekg/dns"
	"github.com/ANSSI-FR/transdep/tools"
	"strings"
	"time"
	"github.com/ANSSI-FR/transdep/errors"
)

type RequestTopic struct {
	// domain is the topic of the request: the name whose delegation info is sought.
	Domain string
	// exceptions is the list of exceptions we are willing to make for this request w.r.t to the DNS standard
	Exceptions tools.Exceptions
}

// Request contains the elements of a request for a delegation information
type Request struct {
	topic RequestTopic
	// ansChan is the channel used to return the result of the request from the worker goroutine to the calling goroutine
	ansChan chan *result
}

// NewRequest builds a new request instance
func NewRequest(name string, exceptions tools.Exceptions) *Request {
	zcr := new(Request)
	zcr.topic.Domain = strings.ToLower(dns.Fqdn(name))
	zcr.topic.Exceptions = exceptions
	zcr.ansChan = make(chan *result, 1)
	return zcr
}

func (zcr *Request) Domain() string {
	return zcr.topic.Domain
}

func (zcr *Request) Exceptions() tools.Exceptions {
	return zcr.topic.Exceptions
}

func (zcr *Request) RequestTopic() RequestTopic {
	return zcr.topic
}

func (zcr *Request) Equal(other *Request) bool {
	return zcr.topic == other.topic
}

// Result returns the result of this request. It blocks for the default timeout duration or until an answer is provided.
// An error is returned upon timeout or if an incident occurred during the discovery of the delegation information.
// The entry might value nil even if error is nil too, if the request topic is not a zone apex.
func (zcr *Request) Result() (*Entry, *errors.ErrorStack) {
	return zcr.ResultWithSpecificTimeout(tools.DEFAULT_TIMEOUT_DURATION)
}

// ResultWithSpecificTimeout is identical to Result except a timeout duration may be specified.
func (zcr *Request) ResultWithSpecificTimeout(dur time.Duration) (*Entry, *errors.ErrorStack) {
	select {
	case res := <-zcr.ansChan:
		return res.Result, res.Err
	case _ = <-tools.StartTimeout(dur):
		return nil, errors.NewErrorStack(errors.NewTimeoutError("zone cut retrieval", zcr.topic.Domain))
	}
}

// SetResult is used to set/pass along the result associated to this request
// This function is meant to be called only once, though the implemention does not currently prevent this.
func (zcr *Request) SetResult(res *Entry, err *errors.ErrorStack) {
	if err != nil {
		err = err.Copy()
	}
	zcr.ansChan <- &result{res, err}
}
