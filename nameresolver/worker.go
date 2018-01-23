package nameresolver

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"github.com/ANSSI-FR/transdep/messages/zonecut"
	"github.com/ANSSI-FR/transdep/tools"
	"github.com/ANSSI-FR/transdep/messages/nameresolver"
	"github.com/ANSSI-FR/transdep/errors"
	"strings"
)

// WORKER_CHAN_CAPACITY indicates the maximum number of request unhandled by the start() goroutine can be spooled before
// the call to Handle() becomes blocking.
const WORKER_CHAN_CAPACITY = 10

// MAX_CNAME_CHAIN indicates the longest chain of CNAME that is acceptable to be followed a name is considered a
// dead-end (i.e. unfit for name resolution)
const MAX_CNAME_CHAIN = 10

// worker represents a request handler for a specific request target domain name for which name resolution is sought.
type worker struct {
	// req is the request topic for which this worker was started in the first place.
	req           *nameresolver.Request
	// reqs is the channel by which subsequent requests for the same topic as for "req" are received.
	reqs          chan *nameresolver.Request
	// closedReqChan helps prevent double-close issue on reqs channel, when the worker is stopping.
	closedReqChan bool
	// joinChan is used by stop() to wait for the completion of the start() goroutine
	joinChan      chan bool
	// zcHandler is used to submit new zone cut requests. This is most notably used to get the delegation information of
	// the parent zone of the requested name, in order to query its name servers for the requested name delegation
	// information.
	zcHandler     func(*zonecut.Request) *errors.ErrorStack
	// nrHandler is used to submit new name resolution requests. This is used, for instance, to get the IP addresses
	// associated to nameservers that are out-of-bailiwick and for which we don't have acceptable glues or IP addresses.
	nrHandler     func(*nameresolver.Request) *errors.ErrorStack
	// config is the configuration of the current Transdep run
	config    *tools.TransdepConfig
}

// initNewWorker builds a new worker instance and returns it.
// It DOES NOT start the new worker, and should not be called directly by the finder.
func initNewWorker(req *nameresolver.Request, nrHandler func(*nameresolver.Request) *errors.ErrorStack, zcHandler func(*zonecut.Request) *errors.ErrorStack, conf *tools.TransdepConfig) *worker {
	w := new(worker)
	w.req = req
	w.zcHandler = zcHandler
	w.nrHandler = nrHandler
	w.config = conf
	w.reqs = make(chan *nameresolver.Request, WORKER_CHAN_CAPACITY)
	w.closedReqChan = false
	w.joinChan = make(chan bool, 1)
	return w
}

// newWorker builds a new worker instance and returns it.
// The worker is started and will resolve the request from the network.
func newWorker(req *nameresolver.Request, nrHandler func(*nameresolver.Request) *errors.ErrorStack, zcHandler func(*zonecut.Request) *errors.ErrorStack, conf *tools.TransdepConfig) *worker {
	w := initNewWorker(req, nrHandler, zcHandler, conf)
	w.start()
	return w
}

// newWorker builds a new worker instance and returns it.
// The worker is started and will resolve the request from a cache file.
func newWorkerWithCachedResult(req *nameresolver.Request, nrHandler func(*nameresolver.Request) *errors.ErrorStack, zcHandler func(*zonecut.Request) *errors.ErrorStack, cf *nameresolver.CacheFile, conf *tools.TransdepConfig) *worker {
	w := initNewWorker(req, nrHandler, zcHandler, conf)
	w.startWithCachedResult(cf)
	return w
}

// handle allows the submission of new requests to this worker.
// This method returns an error if the worker is stopped or if the submitted request does not match the request usually
// handled by this worker.
func (w *worker) handle(req *nameresolver.Request) *errors.ErrorStack {
	if w.closedReqChan {
		return errors.NewErrorStack(fmt.Errorf("handle: worker channel for name resolution of %s is already closed", w.req.Name()))
	} else if !w.req.Equal(req) {
		return errors.NewErrorStack(fmt.Errorf("handle: invalid request; the submitted request (%s) does not match the requests handled by this worker (%s)", req.Name(), w.req.Name()))
	}
	w.reqs <- req
	return nil
}

// resolveFromWith resolves the topic of the requests associated with this worker by querying the "ip" IP address and
// using the "proto" protocol (either "" for UDP or "tcp"). It returns an entry corresponding to the requested topic, or an
// definitive error that happened during the resolution.
func (w *worker) resolveFromWith(ip net.IP, proto string) (*nameresolver.Entry, *errors.ErrorStack) {
	var ipList []net.IP

	// We first query about the IPv4 addresses associated to the request topic.
	clnt := new(dns.Client)
	clnt.Net = proto

	ma := new(dns.Msg)
	ma.SetEdns0(4096, false)
	ma.SetQuestion(w.req.Name(), dns.TypeA)
	ma.RecursionDesired = false
	ans, _, err := clnt.Exchange(ma, net.JoinHostPort(ip.String(), "53"))

	if err != nil {
		errStack := errors.NewErrorStack(err)
		errStack.Push(fmt.Errorf("resolveFromWith: error while exchanging with %s over %s for %s %s?", ip.String(), errors.PROTO_TO_STR[errors.STR_TO_PROTO[proto]], w.req.Name(), dns.TypeToString[dns.TypeA]))
		return nil, errStack
	}
	if ans == nil {
		return nil, errors.NewErrorStack(fmt.Errorf("resolveFromWith: got empty answer from %s over %s for %s %s?", ip.String(), errors.PROTO_TO_STR[errors.STR_TO_PROTO[proto]], w.req.Name(), dns.TypeToString[dns.TypeA]))
	}
	if ans.Rcode != dns.RcodeSuccess {
		return nil, errors.NewErrorStack(fmt.Errorf("resolveFromWith: got DNS error %s from %s over %s for %s %s?", dns.RcodeToString[ans.Rcode], ip.String(), errors.PROTO_TO_STR[errors.STR_TO_PROTO[proto]], w.req.Name(), dns.TypeToString[dns.TypeA]))
	}
	if !ans.Authoritative {
		// We expect an non-empty answer from the server, with a positive answer (no NXDOMAIN (lame delegation),
		// no SERVFAIL (broken server)). We also expect the server to be authoritative; if it is not, it is not clear
		// why, because the name is delegated to this server according to the parent zone, so we assume that this server
		// is broken, but there might be other reasons for this that I can't think off from the top of my head.
		return nil, errors.NewErrorStack(fmt.Errorf("resolveFromWith: got non-authoritative data from %s over %s for %s %s?", ip.String(), errors.PROTO_TO_STR[errors.STR_TO_PROTO[proto]], w.req.Name(), dns.TypeToString[dns.TypeA]))
	}

	// If the answer is truncated, we might want to retry over TCP... except of course if the truncated answer is
	// already provided over TCP (see Spotify blog post about when it happened to them :))
	if ans.Truncated {
		if proto == "tcp" {
			return nil, errors.NewErrorStack(fmt.Errorf("resolveFromWith: got a truncated answer from %s over %s for %s %s?", ip.String(), errors.PROTO_TO_STR[errors.STR_TO_PROTO[proto]], w.req.Name(), dns.TypeToString[dns.TypeA]))
		}
		return w.resolveFromWith(ip, "tcp")
	}

	for _, grr := range ans.Answer {
		// We only consider records from the answer section that have a owner name equal to the qname.
		if dns.CompareDomainName(grr.Header().Name, w.req.Name()) == dns.CountLabel(w.req.Name()) && dns.CountLabel(grr.Header().Name) == dns.CountLabel(w.req.Name()){
			// We may receive either A or CNAME records with matching owner name. We dismiss all other cases
			// (which are probably constituted of NSEC and DNAME and similar stuff. NSEC is of no value here, and DNAME
			// are not supported by this tool.
			switch rr := grr.(type) {
			case *dns.A:
				// We stack IPv4 addresses because the RRSet might be composed of multiple A records
				ipList = append(ipList, rr.A)
			case *dns.CNAME:
				// A CNAME is supposed to be the only record at a given domain name. Thus, we return this alias marker
				// and forget about all other records that might resides here.
				return nameresolver.NewAliasEntry(w.req.Name(), rr.Target), nil
			}
		}
	}

	// We now query for the AAAA records to also get the IPv6 addresses
	clnt = new(dns.Client)
	clnt.Net = proto

	maaaa := new(dns.Msg)
	maaaa.SetEdns0(4096, false)
	maaaa.SetQuestion(w.req.Name(), dns.TypeAAAA)
	maaaa.RecursionDesired = false
	ans, _, err = clnt.Exchange(maaaa, net.JoinHostPort(ip.String(), "53"))

	if err != nil {
		errStack := errors.NewErrorStack(err)
		errStack.Push(fmt.Errorf("resolveFromWith: error while exchanging with %s over %s for %s %s?", ip.String(), errors.PROTO_TO_STR[errors.STR_TO_PROTO[proto]], w.req.Name(), dns.TypeToString[dns.TypeAAAA]))
		return nil, errStack
	}
	if ans == nil {
		return nil, errors.NewErrorStack(fmt.Errorf("resolveFromWith: got empty answer from %s over %s for %s %s?", ip.String(), errors.PROTO_TO_STR[errors.STR_TO_PROTO[proto]], w.req.Name(), dns.TypeToString[dns.TypeAAAA]))
	}
	if ans.Rcode != dns.RcodeSuccess {
		return nil, errors.NewErrorStack(fmt.Errorf("resolveFromWith: got DNS error %s from %s over %s for %s %s?", dns.RcodeToString[ans.Rcode], ip.String(), errors.PROTO_TO_STR[errors.STR_TO_PROTO[proto]], w.req.Name(), dns.TypeToString[dns.TypeAAAA]))
	}
	if !ans.Authoritative {
		return nil, errors.NewErrorStack(fmt.Errorf("resolveFromWith: got non-authoritative data from %s over %s for %s %s?", ip.String(), errors.PROTO_TO_STR[errors.STR_TO_PROTO[proto]], w.req.Name(), dns.TypeToString[dns.TypeAAAA]))
	}
	if ans.Truncated {
		if proto == "tcp" {
			return nil, errors.NewErrorStack(fmt.Errorf("resolveFromWith: got a truncated answer from %s over %s for %s %s?", ip.String(), errors.PROTO_TO_STR[errors.STR_TO_PROTO[proto]], w.req.Name(), dns.TypeToString[dns.TypeAAAA]))
		}
		return w.resolveFromWith(ip, "tcp")
	}

	for _, grr := range ans.Answer {
		if dns.CompareDomainName(grr.Header().Name, w.req.Name()) == dns.CountLabel(w.req.Name()) && dns.CountLabel(grr.Header().Name) == dns.CountLabel(w.req.Name()){
			switch rr := grr.(type) {
			case *dns.AAAA:
				ipList = append(ipList, rr.AAAA)
			case *dns.CNAME:
				// We should have a CNAME here because the CNAME was not returned when asked for A records, and if we
				// had received a CNAME, we would already have returned.
				return nil, errors.NewErrorStack(fmt.Errorf("resolveFromWith: got a CNAME that was not provided for the A query from %s over %s for %s %s?", ip.String(), errors.PROTO_TO_STR[errors.STR_TO_PROTO[proto]], w.req.Name(), dns.TypeToString[dns.TypeAAAA]))
			}
		}
	}
	return nameresolver.NewIPEntry(w.req.Name(), ipList), nil
}

// resolveFrom resolves the request associated to this worker. It returns the entry generated from a successful
// resolution or the error that occurred.
func (w *worker) resolveFrom(ip net.IP) (*nameresolver.Entry, *errors.ErrorStack) {
	// (proto == "" means UDP)
	return w.resolveFromWith(ip, "")
}

// resolveFromGlues tries to resolve the request associated to this worker using the list of servers provided as
// parameters, assuming their are all delegation with glues (i.e. IP addresses of nameservers are already known).
func (w *worker) resolveFromGlues(nameSrvs []*zonecut.NameSrvInfo) (*nameresolver.Entry, *errors.ErrorStack) {
	var errList []string
	for _, ns := range nameSrvs {
		for _, ip := range ns.Addrs() {
			// Tries every IP address of every name server. If an error occurs, the next IP, then server is tried.
			entry, err := w.resolveFrom(ip)
			if err == nil {
				return entry, nil
			}
			errList = append(errList, fmt.Sprintf("resolveFromGlues: error from %s(%s): %s", ns.Name(), ip.String(), err.Error()))
		}
	}
	// No IP address of any server returned a positive result.
	return nil, errors.NewErrorStack(fmt.Errorf("resolveFromGlues: no valid glued delegation for %s: [%s]", w.req.Name(), strings.Join(errList, ", ")))
}

// resolveFromGluelessNameSrvs resolves the request associated to this worker using name servers whose IP address is not
// known thanks to glues and in-bailiwick address records. It returns the answer to that request or an error no server
// returned an acceptable response.
func (w *worker) resolveFromGluelessNameSrvs(nameSrvs []*zonecut.NameSrvInfo) (*nameresolver.Entry, *errors.ErrorStack) {
	var errList []string
Outerloop:
	for _, ns := range nameSrvs {
		var addrs []net.IP
		// requestedName is the nameserver name, by default. It may evolve, as aliases/CNAME are met along the resolution
		requestedName := ns.Name()
		// We limit to MAX_CNAME_CHAIN the number of CNAME that we are willing to follow
		Innerloop:
		for i := 0; i < MAX_CNAME_CHAIN && len(addrs) == 0; i++ {
			// Start up the resolution of the name of the nameserver into IP addresses so that we can query these IP
			// addresses for the request topic of this worker.
			req := nameresolver.NewRequestWithContext(requestedName, w.req.Exceptions(), w.req)
			w.nrHandler(req)

			ne, err := req.Result()
			if err != nil || ne == nil {
				// if an error occurred, we just try with the next nameserver until we get an answer or all servers have
				// been tried.
				continue Outerloop
			}

			if ne.CNAMETarget() == "" {
				// We got some IP addresses ; we store them away and go to the next step
				addrs = ne.Addrs()
				break Innerloop
			}
			// If the answer is an alias, we retry with the new target name
			requestedName = ne.CNAMETarget()
		}

		if len(addrs) == 0 {
			// We hit a very long CNAME Chain or the name cannot be resolved for some reason
			continue
		}

		// Try to query every IP that we found, until we get a valid answer
		for _, addr := range addrs {
			entry, err := w.resolveFrom(addr)
			if err == nil {
				return entry, nil
			}
			errList = append(errList, fmt.Sprintf("resolveFromGluelessNameSrvs: error from %s(%s): %s", ns.Name(), addr.String(), err.Error()))
		}
	}
	// We tried every IP address of every name server to no avail. Return an error
	return nil, errors.NewErrorStack(fmt.Errorf("resolveFromGluelessNameSrvs: no valid glueless delegation for %s: [%s]", w.req.Name(), strings.Join(errList, ", ")))
}

// resolve is in charge of orchestrating the resolution of the request that is associated with this worker
func (w *worker) resolve() (*nameresolver.Entry, *errors.ErrorStack) {
	// First, we search the list of name servers to which the requested domain name is delegated. This is obtained by
	// submitting delegation info request, removing a label each time, until a non-null response is provided (meaning we
	// reached the apex of the zone containing the requested name).
	var entry *zonecut.Entry
	reqName := w.req.Name()
	for entry == nil {
		var err *errors.ErrorStack
		// Get the servers for this zonecut
		req := zonecut.NewRequest(reqName, w.req.Exceptions())
		w.zcHandler(req)

		entry, err = req.Result()
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
			// If we receive an error while searching for the delegation info, we will not be able to perform the
			// subsequent queries, so we bail out on this request.
			if returnErr {
				err.Push(fmt.Errorf("resolve: error while getting zone cut info of %s for %s", reqName, w.req.Name()))
				return nil, err
			}
			err = nil
			entry = nil
		}

		if entry == nil {
			// If no entry was provided, reqName is not the zone apex, so we remove a label and retry.
			pos, end := dns.NextLabel(reqName, 1)
			if end {
				reqName = "."
			} else {
				reqName = reqName[pos:]
			}
		}
	}

	// Setting apart glueless delegations and glued delegations
	var nameSrvsWithGlues []*zonecut.NameSrvInfo
	var gluelessNameSrvs []*zonecut.NameSrvInfo

	for _, nameSrv := range entry.NameServers() {
		if len(nameSrv.Addrs()) == 0 {
			gluelessNameSrvs = append(gluelessNameSrvs, nameSrv)
		} else {
			nameSrvsWithGlues = append(nameSrvsWithGlues, nameSrv)
		}
	}

	// Try to resolve first using glues to go faster
	r, gluedErr := w.resolveFromGlues(nameSrvsWithGlues)
	if gluedErr != nil {
		if _, ok := gluedErr.OriginalError().(*errors.NXDomainError) ; ok {
			gluedErr.Push(fmt.Errorf("resolve: got NXDomain while resolving %s from glued servers", w.req.Name()))
			return nil, gluedErr
		}
		// No glued servers returned an answer, so we now try with the glueless delegations.
		var gluelessErr *errors.ErrorStack
		r, gluelessErr = w.resolveFromGluelessNameSrvs(gluelessNameSrvs)
		if gluelessErr != nil {
			gluelessErr.Push(fmt.Errorf("resolve: unable to resolve %s: glued errors: [%s]", w.req.Name(), gluedErr.Error()))
			return nil, gluelessErr
		}
	}
	return r, nil
}

// start prepares the worker for handling new requests.
// The current implementation is to launch a goroutine that will read from the reqs channel attribute new requests and
// will try to answer them. When stopped, it will immediately send the join signal.
func (w *worker) start() {
	go func() {
		result, err := w.resolve()
		for req := range w.reqs {
			req.SetResult(result, err)
		}
		w.joinChan <- true
	}()
}

// startWithCachedResult performs the same kind of operations that start(), except that the response is not obtained
// from the network, but by loading it from a cache file.
func (w *worker) startWithCachedResult(cf *nameresolver.CacheFile) {
	go func() {
		var result *nameresolver.Entry
		var resultErr *errors.ErrorStack
		var err error

		result, resultErr, err = cf.Result()
		if err != nil {
			result = nil
			cacheErr := fmt.Errorf("startWithCachedResult: error while loading cache of %s: %s", w.req.Name(), err.Error())
			if resultErr != nil {
				resultErr.Push(cacheErr)
			} else {
				resultErr = errors.NewErrorStack(cacheErr)
			}
		}

		for req := range w.reqs {
			req.SetResult(result, resultErr)
		}
		w.joinChan <- true
	}()
}

// stop is to be called during the cleanup of the worker. It shuts down the goroutine started by start() and waits for
// it to actually end. stop returns true if it is the first time it is called and the start() routine was stopped, or
// else it returns false.
func (w *worker) stop() bool {
	if w.closedReqChan {
		return false
	}
	close (w.reqs)
	w.closedReqChan = true
	_ = <-w.joinChan
	close(w.joinChan)
	return true
}