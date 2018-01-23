// Depfinder package contains the DNS dependency finder.
// Its purpose is to provide a request channel, and to build the dependency graph of a requested domain name.
package dependency

import (
	"fmt"
	"github.com/hashicorp/golang-lru"
	"github.com/ANSSI-FR/transdep/graph"
	"github.com/ANSSI-FR/transdep/nameresolver"
	"github.com/ANSSI-FR/transdep/zonecut"
	"github.com/ANSSI-FR/transdep/messages/dependency"
	msg_nameresolver "github.com/ANSSI-FR/transdep/messages/nameresolver"
	"github.com/hashicorp/go-immutable-radix"
	"github.com/ANSSI-FR/transdep/tools"
	"github.com/ANSSI-FR/transdep/errors"
)

// REQ_CHAN_CAPACITY indicates the maximum number of requests that can be queued to a dependency finder instance,
// before the write call is blocking.
const REQ_CHAN_CAPACITY = 10

// Finder is a worker pool maintainer for the construction of dependency trees of domain names.
type Finder struct {
	// workerPool LRU keys are requestTopic instances and values are *worker.
	// Its use is to have at most one worker per domain (and type of request (resolveName/includeIP)) and spool matching
	// requests to that worker.
	workerPool    *lru.Cache
	// reqs is the channel that feeds new requests to the finder.
	reqs          chan *dependency.Request
	// closedReqChan is true when the reqs channel has been closed. This prevents double-close or writes to a closed chan
	closedReqChan bool
	// cacheDir is the path to the root directory for on-disk cache.
	cacheRootDir string
	// joinChan is used for goroutine synchronization so that the owner of a finder instance does not exit before
	// this finder is done cleaning up after itself.
	joinChan      chan bool
	// nameResolver is the instance of Name Resolver that is started by this Finder. Its handler is passed to this
	// finder workers.
	nameResolver  *nameresolver.Finder
	// zoneCutFinder is the instance of Zone Cut Finder that is started by this Finder. Its handler is passed to this
	// finder workers.
	zoneCutFinder *zonecut.Finder
	// tree is the reference to a radix tree containing a view of the prefixes announced with BGP over the Internet.
	// This is used to fill IPNode instances with their corresponding ASN number, at the time of query.
	tree *iradix.Tree
	// config is the configuration of the current Transdep run
	config    *tools.TransdepConfig
}

/* NewFinder initializes a new dependency finder struct instance.

dependencyWorkerCount designates the maximum number of workers simultaneously live for dependency tree construction.

zoneCutWorkerCount designates the maximum number of workers simultaneously live for zone cut/delegation information retrieval.
nameResolverWorkerCount designates the maximum number of workers simultaneously live for name resolution.

cacheRootDir designates the root cache directory in which the on-disk cache will be stored. The directory will be created
if it does not already exist.

rootHints is the name of the file from which the root hints should be loaded.
*/
func NewFinder(transdepConf *tools.TransdepConfig, tree *iradix.Tree) *Finder {
	df := new(Finder)

	var err error
	df.workerPool, err = lru.NewWithEvict(transdepConf.LRUSizes.DependencyFinder, cleanupWorker)
	if err != nil {
		return nil
	}

	df.reqs = make(chan *dependency.Request, REQ_CHAN_CAPACITY)
	df.closedReqChan = false
	df.joinChan = make(chan bool, 1)
	df.tree = tree
	df.config = transdepConf

	// Trick using late binding to have circular declaration of zonecut finder and name resolver handlers
	var nrHandler func(request *msg_nameresolver.Request) *errors.ErrorStack
	df.zoneCutFinder = zonecut.NewFinder(func(req *msg_nameresolver.Request) *errors.ErrorStack {return nrHandler(req)}, transdepConf)
	df.nameResolver = nameresolver.NewFinder(df.zoneCutFinder.Handle, transdepConf)
	nrHandler = df.nameResolver.Handle

	df.start()
	return df
}

// cleanupWorker is the callback called by the LRU when an entry is evicted.
// value is the worker instance stored within the evicted entry.
func cleanupWorker(_, value interface{}) {
	wrk := value.(*worker)
	wrk.stop()
}

/*spool finds an already existing worker for the spooled request or create a new worker and adds it to the LRU. It
then feeds the request to that worker.

req is the request to be forwarded to the appropriate worker. If no existing worker can handle that request, a new one
is created and added to the list of workers
*/
func (df *Finder) spool(req *dependency.Request) {
	var wrk *worker
	key := req.Topic()
	if val, ok := df.workerPool.Get(key); ok {
		wrk = val.(*worker)
	} else {
		wrk = newWorker(req, df.Handle, df.zoneCutFinder.Handle, df.nameResolver.Handle, df.config, df.tree)
		df.workerPool.Add(key, wrk)
	}
	wrk.handle(req)
}

// Handle is the function called to submit new requests.
// Caller may call req.Result() after calling Handle(req) to get the result of that Handle call.
// This method returns an error if the Finder is stopped.
func (df *Finder) Handle(req *dependency.Request) *errors.ErrorStack {
	if df.closedReqChan {
		return errors.NewErrorStack(fmt.Errorf("Handle: dependency finder request channel already closed"))
	}
	df.reqs <- req
	return nil
}

// start handles new requests, detects dependency cycles or else spools the requests for processing.
// When no more requests are expected, start cleans up all workers.
// start must be called as a separate goroutine (go instance.start()).
func (df *Finder) start() {
	go func() {
		for req := range df.reqs {
			if req.DetectCycle() {
				//Detect dependency loops
				g := graph.NewRelationshipNode(fmt.Sprintf("start: cycle detected on %s", req.Name), graph.AND_REL)
				g.AddChild(new(graph.Cycle))
				req.SetResult(g, nil)
			} else if req.Depth() > nameresolver.MAX_CNAME_CHAIN {
				// Detect long CNAME chain (incremented only when an alias is drawing in a new dependency graph)
				g := graph.NewRelationshipNode(fmt.Sprintf("start: overly long CNAME chain detected %s", req.Name), graph.AND_REL)
				g.AddChild(new(graph.Cycle))
				req.SetResult(g, nil)
			} else {
				df.spool(req)
			}
		}

		// Cleanup workers
		for _, key := range df.workerPool.Keys() {
			val, _ := df.workerPool.Peek(key)
			wrk := val.(*worker)
			wrk.stop()
		}
		df.joinChan <- true
	}()
}

// Stop signals that no more requests are expected.
// This function must be called for proper memory and cache management. Thus, it is advised to defer a call to this
// function as soon as a Finder is instantiated with NewFinder().
func (df *Finder) Stop() bool {
	if df.closedReqChan {
		// This if prevents double closes
		return false
	}
	close(df.reqs)
	df.closedReqChan = true

	// wait for the "start() func to terminate
	_ = <- df.joinChan
	close(df.joinChan)

	// Cleanup other tools
	df.nameResolver.Stop()
	df.zoneCutFinder.Stop()
	return true
}
