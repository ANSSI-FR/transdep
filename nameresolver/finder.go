package nameresolver

import (
	"fmt"
	"github.com/hashicorp/golang-lru"
	"github.com/ANSSI-FR/transdep/messages/nameresolver"
	"github.com/ANSSI-FR/transdep/messages/zonecut"
	"github.com/ANSSI-FR/transdep/tools"
	"github.com/ANSSI-FR/transdep/errors"
)

// REQ_CHAN_CAPACITY is the capacity of the channel into which are submitted new requests. This is used as a back off
// mechanism if the submitter is much faster than the finder.
const REQ_CHAN_CAPACITY = 10

// Finder is a worker pool maintainer for resolution of domain names into aliases or IP addresses.
type Finder struct {
	// reqs is the channel used internally to spool new requests to the goroutine that is handling the new requests and
	// the worker orchestration.
	reqs chan *nameresolver.Request
	// closedReqChan is used to prevent double-close issue
	closedReqChan bool
	// zcHandler is a callback used to submit new requests for zone cut/delegation information for discovery.
	zcHandler func(*zonecut.Request) *errors.ErrorStack
	// workerPool stores worker instances indexed by the domain name they are charged of resolving.
	workerPoll *lru.Cache
	// joinChan is used for goroutine synchronization so that the owner of a finder instance does not exit before
	// this finder is done cleaning up after itself.
	joinChan     chan bool
	// config is the configuration of the current Transdep run
	config    *tools.TransdepConfig
}

/* NewFinder instantiates a new Finder

zcHandler is a function that may be called to submit new requests for zone cut/delegation info discovery.

maxWorkerCount is the number of concurrent workers that will be maintained by this finder. Once this number of workers reached,
the Finder will shut down those that were the least recently used (LRU).

cacheRootDir is the root directory for caching. Workers that are shut down store the result that they are distributing
into a cache file, for later use.
*/
func NewFinder(zcHandler func(*zonecut.Request) *errors.ErrorStack, conf *tools.TransdepConfig) *Finder {
	nr := new(Finder)

	// Preemptively tries to create the cache directory, to prevent usage of the finder if the cache directory cannot be created.
	if err := nameresolver.CreateCacheDir(conf.CacheRootDir); err != nil {
		return nil
	}

	nr.config = conf

	var err error
	nr.workerPoll, err = lru.NewWithEvict(conf.LRUSizes.NameResolverFinder, nr.writeOnDisk)
	if err != nil {
		return nil
	}

	nr.zcHandler = zcHandler
	nr.reqs = make(chan *nameresolver.Request, REQ_CHAN_CAPACITY)
	nr.closedReqChan = false
	nr.joinChan = make(chan bool, 1)

	nr.start()
	return nr
}

// Handle is the method to call to submit new name resolution requests.
// An error might be returned if this finder is already stopping.
func (nr *Finder) Handle(req *nameresolver.Request) *errors.ErrorStack {
	if nr.closedReqChan {
		return errors.NewErrorStack(fmt.Errorf("name resolver request channel already closed"))
	}
	// Spool the request for handling by the goroutine started using start()
	nr.reqs <- req
	return nil
};

// writeOnDisk is a method to clean up entries from the LRU list. It writes the result from the evicted worker on disk
// as JSON, then shuts the worker down.
func (nr *Finder) writeOnDisk(key, value interface{}) {
	wrk := value.(*worker)

	// Get an entry of that worker to persist it on disk before shutting it down
	topic := key.(nameresolver.RequestTopic)
	req := nameresolver.NewRequest(topic.Name, topic.Exceptions)
	wrk.handle(req)

	nrres, err := req.Result()
	if err != nil {
		if _, ok := err.OriginalError().(*errors.TimeoutError) ; ok {
			return
		}
	}

	// Shutting the worker down
	wrk.stop()

	// Caching on disk the result obtained from the worker
	cf := nameresolver.NewCacheFile(nr.config.CacheRootDir, topic)
	errSetRes := cf.SetResult(nrres, err)
	if errSetRes != nil {
		return
	}
}

// loadFromDisk searches on disk for a cache file for the specified request and starts off a new worker to handle that
// request.
// The new started worker is returned. An error is returned if no cache file are found for that request or if an error
// happened during the initialization of that worker.
func (nr *Finder) loadFromDisk(req *nameresolver.Request) (*worker, error) {
	cf, err := nameresolver.NewExistingCacheFile(nr.config.CacheRootDir, req.RequestTopic())
	if err != nil {
		return nil, err
	}

	w := newWorkerWithCachedResult(req, nr.Handle, nr.zcHandler, cf, nr.config)
	if w == nil {
		return nil, fmt.Errorf("unable to create new worker!")
	}
	return w, nil
}

// spool searches for a live worker that can handle the specified request, or starts a new one for that purpose.
func (nr *Finder) spool(req *nameresolver.Request) {
	var wrk *worker
	var err error

	if val, ok := nr.workerPoll.Get(req.RequestTopic()); ok {
		// First, search in the LRU of live workers
		wrk = val.(*worker)
	} else if wrk, err = nr.loadFromDisk(req); err == nil {
		// Then, search if the worker can be started from a cache file
		nr.workerPoll.Add(req.RequestTopic(), wrk)
	} else {
		// Finally, start a new worker to handle that request, if nothing else worked
		wrk = newWorker(req, nr.Handle, nr.zcHandler, nr.config)
		nr.workerPoll.Add(req.RequestTopic(), wrk)
	}

	// Spools the request to the worker
	wrk.handle(req)
}

// start performs the operation for the finder to be ready to handle new requests.
func (nr *Finder) start() {
	// Current start implementation start off a goroutine which reads from the reqs request channel attribute
	go func() {
		for req := range nr.reqs {
			//Detect dependency loops
			if req.DetectLoop() {
				req.SetResult(nil, errors.NewErrorStack(fmt.Errorf("Loop detected on %s", req.Name())))
			} else {
				nr.spool(req)
			}

		}

		// Cleanup, because Stop() was called by the goroutine that owns the finder
		for _, key := range nr.workerPoll.Keys() {
			wrk, _ := nr.workerPoll.Peek(key)
			nr.writeOnDisk(key, wrk)
		}
		// Signal that the cleanup is over
		nr.joinChan <- true
	}()
}

// Stop signals that no new requests will be submitted. It triggers some cleanup of the remaining live workers, wait for
// them to finish and then returns true. Subsequent calls to Stop will return false as the finder is already stopped.
func (nr *Finder) Stop() bool {
	if nr.closedReqChan {
		return false
	}
	close(nr.reqs)
	nr.closedReqChan = true
	_ = <-nr.joinChan
	close(nr.joinChan)
	return true
}
