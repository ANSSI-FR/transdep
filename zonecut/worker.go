package zonecut

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"os"
	"github.com/ANSSI-FR/transdep/messages/nameresolver"
	"github.com/ANSSI-FR/transdep/messages/zonecut"
	"github.com/ANSSI-FR/transdep/tools"
	"strings"
	"github.com/ANSSI-FR/transdep/errors"
)

// WORKER_CHAN_CAPACITY is the maximum number of unhandled requests that may be to the worker, before a call to handle()
// is blocking.
const WORKER_CHAN_CAPACITY = 10

// worker represents a request handler for a specific request target domain name for which delegation information is sought.
type worker struct {
	// req is the request associated with this worker
	req *zonecut.Request
	// reqs is the channel by which subsequent requests for the same topic as for "dn" are received.
	reqs chan *zonecut.Request
	// closedReqChan helps prevent double-close issue on reqs channel, when the worker is stopping.
	closedReqChan bool
	// joinChan is used by stop() to wait for the completion of the start() goroutine
	joinChan chan bool
	// zcHandler is used to submit new zone cut requests. This is most notably used to get the delegation information of
	// the parent zone of the requested name, in order to query its name servers for the requested name delegation
	// information. By definition, this may loop up to the root zone which is hardcoded in this program.
	zcHandler func(*zonecut.Request) *errors.ErrorStack
	// nrHandler is used to submit new name resolution requests. This is used, for instance, to get the IP addresses
	// associated to nameservers that are out-of-bailiwick and for which we don't have acceptable glues or IP addresses.
	nrHandler func(*nameresolver.Request) *errors.ErrorStack
	// config is the configuration of the current Transdep run
	config    *tools.TransdepConfig
}

// initNewWorker builds a new worker instance and returns it.
// It DOES NOT start the new worker, and should not be called directly by the finder.
func initNewWorker(req *zonecut.Request, zcHandler func(*zonecut.Request) *errors.ErrorStack, nrHandler func(*nameresolver.Request) *errors.ErrorStack, config *tools.TransdepConfig) *worker {
	w := new(worker)
	w.req = req
	w.reqs = make(chan *zonecut.Request, WORKER_CHAN_CAPACITY)
	w.closedReqChan = false
	w.joinChan = make(chan bool, 1)
	w.zcHandler = zcHandler
	w.nrHandler = nrHandler
	w.config = config
	return w
}

/* newWorker builds a new worker instance and returns it.
The worker is started and will resolve the request from the network.

dn is the domain name to which this worker is associated. All subsequent requests that this worker will handle will have
the same target domain name.

zcHandler is the function to call to submit new requests for delegation information (most notably for parent domains,
while chasing for a zone apex).

nrHandler is the function to call to submit new requests for name resolution (most notably to resolve a name server name
into an IP address).
*/
func newWorker(req *zonecut.Request, zcHandler func(*zonecut.Request) *errors.ErrorStack, nrHandler func(*nameresolver.Request) *errors.ErrorStack, config *tools.TransdepConfig) *worker {
	w := initNewWorker(req, zcHandler, nrHandler, config)
	w.start()
	return w
}

// newWorkerFromCachedResult is similar to newWorker, except this worker will not chase the answer on the network; it will
// simply load the answer from cache.
func newWorkerFromCachedResult(req *zonecut.Request, zcHandler func(*zonecut.Request) *errors.ErrorStack, nrHandler func(*nameresolver.Request) *errors.ErrorStack, cf *zonecut.CacheFile, config *tools.TransdepConfig) *worker {
	w := initNewWorker(req, zcHandler, nrHandler, config)
	w.startWithCachedResult(cf)
	return w
}

// newRootZoneWorker is similar to newWorker, except it handles the root zone, which is a special case, since it can be
// loaded from a root hints file
func newRootZoneWorker(exceptions tools.Exceptions, config *tools.TransdepConfig) *worker {
	req := zonecut.NewRequest(".", exceptions)
	w := initNewWorker(req, nil, nil, config)
	w.startForRootZone(w.config.RootHintsFile)
	return w
}

// handle allows the submission of new requests to this worker.
// This method returns an error if the worker is stopped or if the submitted request does not match the request usually
// handled by this worker.
func (w *worker) handle(req *zonecut.Request) *errors.ErrorStack {
	if w.closedReqChan {
		return errors.NewErrorStack(fmt.Errorf("handle: worker request channel for zone cut of %s is already closed", w.req.Domain()))
	} else if w.req.RequestTopic() != req.RequestTopic() {
		return errors.NewErrorStack(fmt.Errorf("handle: invalid request; the submitted request (%s) does not match the requests handled by this worker (%s)", req.Domain(), w.req.Domain()))
	}
	w.reqs <- req
	return nil
}

// getHardcodedRootZone returns an entry for the root zone. This entry is currently hardcoded for simplicity's sake.
func (w *worker) getHardcodedRootZone() (*zonecut.Entry, *errors.ErrorStack) {
	// TODO Complete hardcoded root zone
	zce := zonecut.NewEntry(w.req.Domain(), true, []*zonecut.NameSrvInfo{
		zonecut.NewNameSrv("l.root-servers.net.", []net.IP{net.ParseIP("199.7.83.42")}),
	},
	)
	return zce, nil
}

// getRootZoneFromFile loads the entries from the specified rootHints file. An error is returned, if the root zone file
// cannot be opened
func (w *worker) getRootZoneFromFile(rootHints string) (*zonecut.Entry, *errors.ErrorStack) {
	fd, err := os.Open(rootHints)
	if err != nil {
		return nil, errors.NewErrorStack(err)
	}
	defer fd.Close()

	nsList := make(map[string]bool)
	addrList := make(map[string][]net.IP)

	zoneIter := dns.ParseZone(fd, ".", "")
	for token := range zoneIter {
		if token.Error != nil {
			return nil, errors.NewErrorStack(token.Error)
		}
		if token.RR != nil {
			switch rr := token.RR.(type) {
			case *dns.NS:
				// Just a small test to only consider NS entries for the root zone, in case additional records are provided
				if rr.Hdr.Name == "." {
					nsList[rr.Ns] = true
				}
			case *dns.A:
				addrList[rr.Hdr.Name] = append(addrList[rr.Hdr.Name], rr.A)
			case *dns.AAAA:
				addrList[rr.Hdr.Name] = append(addrList[rr.Hdr.Name], rr.AAAA)
			}
		}
	}
	var nameSrvs []*zonecut.NameSrvInfo
	for name, ipAddrs := range addrList {
		if _, ok := nsList[name]; ok {
			nameSrvs = append(nameSrvs, zonecut.NewNameSrv(name, ipAddrs))
		}
	}
	return zonecut.NewEntry(".", true, nameSrvs), nil
}

// extractDelegationInfo extracts the list of name servers that are authoritative for the domain that is associated to
// this worker.
// The parent domain is used to filter out additional address records whose credibility are insufficient (because they
// are out-of-bailiwick of the parent domain).
func (w *worker) extractDelegationInfo(parentDomain string, m *dns.Msg) []*zonecut.NameSrvInfo {
	nsList := make(map[string][]net.IP, 0)
	// Going after the delegation info; we look into the Answer and Authority sections, because following implementations,
	// the answer to that NS query might be in both sections (e.g. ns2.msft.com answers in answer section for
	// glbdns2.microsoft.com. NS?)
	for _, rr := range m.Answer {
		// From the Authority section, we only observe NS records whose owner name is equal to the domain name associated to this worker.
		if dns.CompareDomainName(rr.Header().Name, w.req.Domain()) == dns.CountLabel(rr.Header().Name) &&
			dns.CountLabel(rr.Header().Name) == dns.CountLabel(w.req.Domain()) {

			if nsrr, ok := rr.(*dns.NS); ok {
				// We create a list of potential IP addresses for each name server; we don't know yet if we will have glues for them or not.
				nsList[strings.ToLower(nsrr.Ns)] = make([]net.IP, 0)
			}
		}
	}
	for _, rr := range m.Ns {
		// From the Authority section, we only observe NS records whose owner name is equal to the domain name associated to this worker.
		if dns.CompareDomainName(rr.Header().Name, w.req.Domain()) == dns.CountLabel(rr.Header().Name) &&
			dns.CountLabel(rr.Header().Name) == dns.CountLabel(w.req.Domain()) {

			if nsrr, ok := rr.(*dns.NS); ok {
				// We create a list of potential IP addresses for each name server; we don't know yet if we will have glues for them or not.
				nsList[strings.ToLower(nsrr.Ns)] = make([]net.IP, 0)
			}
		}
	}

	//Going after the glue records
	for _, rr := range m.Extra {
		rrname := strings.ToLower(rr.Header().Name)
		// Is it an in-bailiwick glue? If not, ignore
		if dns.CompareDomainName(rrname, parentDomain) != dns.CountLabel(parentDomain) {
			continue
		}
		// Is this glue record within the NS list
		if _, ok := nsList[rrname]; !ok {
			continue
		}
		switch addrrr := rr.(type) {
		case *dns.A:
			nsList[rrname] = append(nsList[rrname], addrrr.A)
		case *dns.AAAA:
			nsList[rrname] = append(nsList[rrname], addrrr.AAAA)
		}
	}

	nameSrvs := make([]*zonecut.NameSrvInfo, 0)
	for name, addrs := range nsList {
		// Ignore NS requiring a glue but without the associated glue records
		if dns.CompareDomainName(name, w.req.Domain()) != dns.CountLabel(w.req.Domain()) || len(addrs) > 0 {
			nameSrvs = append(nameSrvs, zonecut.NewNameSrv(name, addrs))
		}
	}

	return nameSrvs
}

/*getDelegationInfo searches for the delegation info of the name associated to this worker. It initially tries over UDP
and returns the delegation info as an entry, or the error that occurred during the retrieval of the delegation info.
It also returns a boolean in case of an error; if true, the error is definitive and there is no point in trying other IP
addresses. An exemple of such case is if we obtain a NXDomain error: the parent zone does not know about this domain at
all (assuming all parent nameservers are in sync).

parentDomain is the name of the parent zone. This will be used to filter out non-credible glue records.

addr is the IP address of one of the name server authoritative for the parent zone of the domain that is associated with
this worker. For instance, if the worker is about "example.com.", addr will be the IP address of one of the name servers
that are authoritative for "com."
*/
func (w *worker) getDelegationInfo(parentDomain string, addr net.IP) (*zonecut.Entry, *errors.ErrorStack, bool) {
	// proto == "" means UDP
	nameSrvs, err, definitiveErr := w.getDelegationInfoOverProto(parentDomain, addr, "")
	if err != nil {
		err.Push(fmt.Errorf("getDelegationInfo: for %s", w.req.Domain()))
		return nil, err, definitiveErr
	}
	if len(nameSrvs) == 0 {
		// having no name servers is the indication that the current name is not an apex. Thus, we don't need to check
		// whether there is a DS record. There are "none that we want to consider" :)
		return nil, errors.NewErrorStack(errors.NewNoNameServerError(w.req.Domain())), true
	}

	dnssecProtected, err := w.getDNSSECInfoOverProto(addr, "")
	if err != nil {
		err.Push(fmt.Errorf("getDelegationInfo: for %s: failed to get DNSSEC info", w.req.Domain()))
		return nil, err, false
	}
	return zonecut.NewEntry(w.req.Domain(), dnssecProtected, nameSrvs), nil, false
}

/* getDNSSECInfoOverProto discovers whether there is a DS record for the domain associated with the domain associated to
this worker in its parent zone.

addr is the address to send the DNS query to

proto is the transport protocol to use to query addr

This function returns a boolean indicator of whether there is a DS record of not in the parent domain. This value is
meaningless if an error occurred while searching for the DS record (error != nil).
*/
func (w *worker) getDNSSECInfoOverProto(addr net.IP, proto string) (bool, *errors.ErrorStack) {
	// Sends a DNS query to addr about the domain name associated with this worker, using the "proto" protocol.
	clnt := new(dns.Client)
	clnt.Net = proto // Let's switch the "DNSSECEnabled" flag on if there is a DS record for this delegation

	mds := new(dns.Msg)
	mds.SetEdns0(4096, false)
	mds.SetQuestion(w.req.Domain(), dns.TypeDS)
	mds.RecursionDesired = false
	ansds, _, err := clnt.Exchange(mds, net.JoinHostPort(addr.String(), "53"))

	// Is this server broken? We should get a delegation or an authoritative DS record
	if err != nil {
		errStack := errors.NewErrorStack(err)
		errStack.Push(fmt.Errorf("getDNSSECInfoOverProto: error during exchange with %s for %s %s?", addr.String(), w.req.Domain(), dns.TypeToString[dns.TypeDS]))
		return false, errStack
	}
	if ansds == nil {
		return false, errors.NewErrorStack(fmt.Errorf("getDNSSECInfoOverProto: no answer to DS query or got a DNS error code for %s from %s", w.req.Domain(), addr.String()))
	}
	if ansds.Rcode != dns.RcodeSuccess {
		return false, errors.NewErrorStack(fmt.Errorf("getDNSSECInfoOverProto: received error when asking for %s %s? => %s", w.req.Domain(), dns.TypeToString[dns.TypeDS], dns.RcodeToString[ansds.Rcode]))
	}

	if ansds.Truncated {
		// idem as above
		if proto == "tcp" {
			return false, errors.NewErrorStack(fmt.Errorf("getDNSSECInfoOverProto: got a truncated answer over TCP while querying DS of %s", w.req.Domain()))
		}
		return w.getDNSSECInfoOverProto(addr, "tcp")
	}

	return ansds.Authoritative && len(ansds.Answer) > 0, nil // DNSSEC protected zone or not
}

/* getDelegationInfoOverProto retrieves the list of name servers to which the domain associated with this worker is
delegated to.

parentDomain is the name of the parent domain of the domain associated with this worker.

If an error occurred during the retrieval of this information, the error is not nil. In that case, the list of name
servers is meaningless. The returned bool indicates whether the error is likely to occur when querying one of the other
name servers that we could query for this exact same delegation info.
*/
func (w *worker) getDelegationInfoOverProto(parentDomain string, addr net.IP, proto string) ([]*zonecut.NameSrvInfo, *errors.ErrorStack, bool) {
	// Sends a DNS query to addr about the domain name associated with this worker, using the "proto" protocol.
	clnt := new(dns.Client)
	clnt.Net = proto
	m := new(dns.Msg)
	m.SetEdns0(4096, false)
	m.SetQuestion(w.req.Domain(), dns.TypeNS)
	m.RecursionDesired = false
	ans, _, err := clnt.Exchange(m, net.JoinHostPort(addr.String(), "53"))

	// Did the server answered a valid response?
	if err != nil {
		errStack := errors.NewErrorStack(err)
		errStack.Push(fmt.Errorf("getDelegationInfoOverProto: error while exchanging with %s for %s %s?", addr.String(), w.req.Domain(), dns.TypeToString[dns.TypeNS]))
		return nil, errStack, false
	}
	if ans == nil {
		// Not getting an answer may just indicate that this server timed out.
		// This is probably not a definitive error, so might wanna retry
		return nil, errors.NewErrorStack(fmt.Errorf("getDelegationInfoOverProto: no answer for %s %s? from %s", w.req.Domain(), dns.TypeToString[dns.TypeNS], addr.String())), false
	}
	// Did the server returned a negative answer?
	// (most probably meaning that this name server does not know about this child zone)
	if ans.Rcode == dns.RcodeNameError {
		// Having the server answer us authoritatively that the name does not exist is probably good enough for us to
		// stop waste time on this name. It might be a server that is out-of-sync, though... Currently, we consider
		// that this error is definitive.
		return nil, errors.NewErrorStack(errors.NewNXDomainError(w.req.Domain(), dns.TypeNS, addr, errors.STR_TO_PROTO[proto])), true
	}
	if ans.Rcode == dns.RcodeServerFailure {
		// If we accept servfail as no data, then this is a definitive answer, else it is not
		return nil, errors.NewErrorStack(errors.NewServfailError(w.req.Domain(), dns.TypeNS, addr, errors.STR_TO_PROTO[proto])), w.req.Exceptions().AcceptServFailAsNoData
	}
	if ans.Rcode != dns.RcodeSuccess {
		// A non-NXDomain error may be FORMERR or SERVFAIL which indicates a failure to communicate with the server.
		// Maybe this particular server is broken; let's try another one! Not a definitive error for the target domain name.
		return nil, errors.NewErrorStack(fmt.Errorf("getDelegationInfoOverProto: got a DNS error for %s %s? from %s: %s", w.req.Domain(), dns.TypeToString[dns.TypeNS], addr.String(), dns.RcodeToString[ans.Rcode])), false
	}
	if ans.Authoritative {
		// The server is authoritative for this name... that means that w.dn is a non-terminal node or the Apex
		return nil, nil, true
	}
	if ans.Truncated {
		// A truncated answer usually means retry over TCP. However, sometimes TCP answer are truncated too...
		// In that case, we return an error. I don't see how this would not be a definitive error; other servers will
		// probably return the same overly large answer!
		if proto == "tcp" {
			return nil, errors.NewErrorStack(fmt.Errorf("getDelegationInfoOverProto: got a truncated answer over TCP while querying NS of %s", w.req.Domain())), true
		}
		return w.getDelegationInfoOverProto(parentDomain, addr, "tcp")
	}
	// Extract info from the DNS message
	nameSrvs := w.extractDelegationInfo(parentDomain, ans)

	return nameSrvs, nil, false
}

// getDelegationInfoFromGluedNameSrvs does what the name implies. It will stop iterating over the server list if one of
// the servers returns a definitive error that is likely to occur on other servers too.
func (w *worker) getDelegationInfoFromGluedNameSrvs(parentDomain string, nameSrvs []*zonecut.NameSrvInfo) (*zonecut.Entry, *errors.ErrorStack) {
	var errList []string
	for _, ns := range nameSrvs {
		for _, addr := range ns.Addrs() {
			entry, err, definitiveError := w.getDelegationInfo(parentDomain, addr)
			if err == nil {
				return entry, nil
			}
			if definitiveError {
				err.Push(fmt.Errorf("getDelegationInfoFromGluedNameSrvs: definitive error for %s from %s(%s)", w.req.Domain(), ns.Name(), addr.String()))
				return nil, err
			}
			errList = append(errList, fmt.Sprintf("getDelegationInfoFromGluedNameSrvs: %s", err.Error()))
		}
	}
	// No server returned a valid answer nor a definitive error
	return nil, errors.NewErrorStack(fmt.Errorf("getDelegationInfoFromGluedNameSrvs: cannot get the delegation info of %s from glued delegation: %s", w.req.Domain(), strings.Join(errList, ", ")))
}

// getDelegationInfoFromGluelessNameSrvs retrieves the IP addresses of the name servers then queries them. It will stop
// iterating over the server list if one of the servers returns a definitive error that is likely to occur on other
// servers too.
func (w *worker) getDelegationInfoFromGluelessNameSrvs(parentDomain string, nameSrvs []string) (*zonecut.Entry, *errors.ErrorStack) {
	var errList []string
	for _, ns := range nameSrvs {
		req := nameresolver.NewRequest(ns, w.req.Exceptions())
		w.nrHandler(req)
		res, err := req.Result()
		if err != nil {
			err.Push(fmt.Errorf("getDelegationInfoFromGluelessNameSrvs: error while resolving the IP addresses of nameserver %s of %s", ns, w.req.Domain()))
			return nil, err
		}

		if res.CNAMETarget() != "" {
			// This name server name points to a CNAME... This is illegal, so we just skip that server :o)
			continue
		}

		for _, addr := range res.Addrs() {
			entry, err, definitiveError := w.getDelegationInfo(parentDomain, addr)
			if err == nil {
				return entry, nil
			}
			if definitiveError {
				err.Push(fmt.Errorf("getDelegationInfoFromGluelessNameSrvs: definitive error for %s from %s(%s)", w.req.Domain(), ns, addr.String()))
				return nil, err
			}
			errList = append(errList, fmt.Sprintf("getDelegationInfoFromGluelessNameSrvs: error for %s from %s(%s): %s", w.req.Domain(), ns, addr.String(), err.Error()))
		}
	}
	// No server returned a valid answer nor a definitive error
	return nil, errors.NewErrorStack(fmt.Errorf("getDelegationInfoFromGluelessNameSrvs: cannot get the delegation info of %s from glueless delegation: [%s]", w.req.Domain(), strings.Join(errList, ", ")))
}

func (w *worker) resolve() (*zonecut.Entry, *errors.ErrorStack) {
	var parentZCE *zonecut.Entry
	queriedName := w.req.Domain()

	// Cycling until we get the delegation info for the parent zone. Cycling like this is necessary if the parent domain
	// is not a zone apex. For instance, this is necessary for ssi.gouv.fr, since gouv.fr is an ENT.
	for parentZCE == nil {
		var err *errors.ErrorStack
		// First we get the Entry for the parent zone
		pos, end := dns.NextLabel(queriedName, 1)
		if end {
			queriedName = "."
		} else {
			queriedName = queriedName[pos:]
		}

		newReq := zonecut.NewRequest(queriedName, w.req.Exceptions())
		w.zcHandler(newReq)

		parentZCE, err = newReq.Result()
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
				err.Push(fmt.Errorf("resolve: error while getting the zone cut info of %s for %s", queriedName, w.req.Domain()))
				return nil, err
			}
			parentZCE = nil
			err = nil
		}
	}

	// Split delegation info into glued vs glueless, to prioritize glued delegations, which are faster (no additional
	// query required).
	var gluedNameSrvs []*zonecut.NameSrvInfo
	var gluelessNameSrvs []string
	for _, nameSrv := range parentZCE.NameServers() {
		inbailiwick := dns.CompareDomainName(nameSrv.Name(), parentZCE.Domain()) == dns.CountLabel(parentZCE.Domain())
		if inbailiwick || len(nameSrv.Addrs()) > 0 {
			gluedNameSrvs = append(gluedNameSrvs, nameSrv)
		} else if !inbailiwick {
			gluelessNameSrvs = append(gluelessNameSrvs, nameSrv.Name())
		}
	}

	var entry *zonecut.Entry
	entry, gluedErr := w.getDelegationInfoFromGluedNameSrvs(parentZCE.Domain(), gluedNameSrvs)
	if gluedErr != nil {
		switch typedErr := gluedErr.OriginalError().(type) {
		case *errors.NXDomainError:
			gluedErr.Push(fmt.Errorf("resolve: got NXDomain while resolving from glued NS of %s", w.req.Domain()))
			return nil, gluedErr
		case *errors.NoNameServerError:
			return nil, nil
		default:
			_ = typedErr
		}
		var gluelessErr *errors.ErrorStack
		entry, gluelessErr = w.getDelegationInfoFromGluelessNameSrvs(parentZCE.Domain(), gluelessNameSrvs)
		if gluelessErr != nil {
			if _, ok := gluelessErr.OriginalError().(*errors.NoNameServerError) ; ok {
				return nil, nil
			}
			gluelessErr.Push(fmt.Errorf("resolve: unable to resolve %s: glued errors: [%s]", w.req.Domain(), gluedErr.Error()))
			return nil, gluelessErr
		}
	}
	return entry, nil
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
func (w *worker) startWithCachedResult(cf *zonecut.CacheFile) {
	go func() {
		result, resultErr, err := cf.Result()
		if err != nil {
			result = nil
			cacheErr := fmt.Errorf("startWithCachedResult: error while loading from cache: %s", err)
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

// startForRootZone is a special starting procedure for the root zone. Root zone can be loaded from a root hints file,
// but we can also use an hardcoded-but-probably-obsolete list for easy startups. If the rootzone file cannot be loaded,
// the hardcoded list is used instead and an error message is printed on stderr.
func (w *worker) startForRootZone(rootHints string) {
	go func() {
		var result *zonecut.Entry
		var err *errors.ErrorStack
		if rootHints == "" {
			result, err = w.getHardcodedRootZone()
		} else {
			result, err = w.getRootZoneFromFile(rootHints)
			if err != nil {
				fmt.Fprintf(os.Stderr, "startForRootZone: error loading from root hints. Using hardcoded value instead: %s", err)
				result, err = w.getHardcodedRootZone()
			}
		}
		for req := range w.reqs {
			req.SetResult(result, err)
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
	close(w.reqs)
	w.closedReqChan = true
	<-w.joinChan
	close(w.joinChan)
	return true
}
