package zonecut

import (
	"fmt"
	"github.com/hashicorp/golang-lru"
	"github.com/ANSSI-FR/transdep/messages/nameresolver"
	"github.com/ANSSI-FR/transdep/messages/zonecut"
	"github.com/ANSSI-FR/transdep/tools"
	"github.com/ANSSI-FR/transdep/errors"
	errors2 "errors"
)

// REQ_CHAN_CAPACITY is the capacity of the channel into which are submitted new requests. This is used as a back off
// mechanism if the submitter is much faster than the finder.
const REQ_CHAN_CAPACITY = 10

// Finder is a worker pool maintainer for the retrieval of zone cuts/delegation information of requested zones.
type Finder struct {
	// reqs is the channel used by the goroutine started by this finder to handle new requests submitted by the calling
	// goroutine owning the finder instance.
	reqs chan *zonecut.Request
	// closedReqChan is used to prevent double-close issue on the reqs channel
	closedReqChan bool
	// workerPool stores references to live workers, indexed by the name of the zone for which the worker returns the
	// delegation information.
	workerPool *lru.Cache
	// cacheRootDir is the root directory for caching
	cacheRootDir string
	// joinChan is used for goroutine synchronization so that the owner of a finder instance does not exit before
	// this finder is done cleaning up after itself.
	joinChan chan bool
	// nrHandler is the function to call to submit new name resolution requests.
	nrHandler func(*nameresolver.Request) *errors.ErrorStack
	// config is the configuration of the current Transdep run
	config *tools.TransdepConfig
}

/* NewFinder builds a new Finder instance and starts the associated goroutine for request handling.

nrHandler is the function to call to submit new name resolution requests

maxWorkerCount is the maximum number of simultaneously live zone cut workers. Once this number is reached, the least
recently used worker is shut down and a new worker is started to handle the new request.

cacheRootDir is the root directory for caching

rootHints is the name of the file from which the root hints should be loaded.
*/
func NewFinder(nrHandler func(*nameresolver.Request) *errors.ErrorStack, conf *tools.TransdepConfig) *Finder {
	z := new(Finder)
	z.nrHandler = nrHandler

	// Preemptively tries to create the cache directory, to prevent usage of the finder if the cache directory cannot be created.
	if err := zonecut.CreateCacheDir(conf.CacheRootDir); err != nil {
		return nil
	}
	z.cacheRootDir = conf.CacheRootDir

	z.reqs = make(chan *zonecut.Request, REQ_CHAN_CAPACITY)
	z.closedReqChan = false
	z.joinChan = make(chan bool, 1)

	var err error
	z.workerPool, err = lru.NewWithEvict(conf.LRUSizes.ZoneCutFinder, z.writeOnDisk)
	if err != nil {
		return nil
	}

	z.config = conf

	z.start()
	return z
}

// Handle is the method to call to submit new zone cut/delegation information discovery requests.
// An error might be returned if this finder is already stopping.
func (z *Finder) Handle(req *zonecut.Request) *errors.ErrorStack {
	if z.closedReqChan {
		return errors.NewErrorStack(errors2.New("request channel for zone cut finding is already closed"))
	}
	z.reqs <- req
	return nil
}

// writeOnDisk is a method to clean up entries from the LRU list. It writes the result from the evicted worker on disk
// as JSON, then shuts the worker down.
func (z *Finder) writeOnDisk(key, value interface{}) {
	wrk := value.(*worker)

	// Get an entry of that worker to persist it on disk before shutting it down
	topic := key.(zonecut.RequestTopic)
	req := zonecut.NewRequest(topic.Domain, topic.Exceptions)
	wrk.handle(req)

	entry, err := req.Result()
	if err != nil {
		if _, ok := err.OriginalError().(*errors.TimeoutError) ; ok {
			return
		}
	}
	wrk.stop()

	cf := zonecut.NewCacheFile(z.cacheRootDir, topic)
	errSetRes := cf.SetResult(entry, err)
	if errSetRes != nil {
		return
	}
}

// loadFromDisk searches on disk for a cache file for the specified request and starts off a new worker to handle that
// request.
// The new started worker is returned. An error is returned if no cache file are found for that request or if an error
// happened during the initialization of that worker.
func (z *Finder) loadFromDisk(req *zonecut.Request) (*worker, error) {
	cf, err := zonecut.NewExistingCacheFile(z.cacheRootDir, req.RequestTopic())
	if err != nil {
		return nil, err
	}

	w := newWorkerFromCachedResult(req, z.Handle, z.nrHandler, cf, z.config)
	if w == nil {
		return nil, fmt.Errorf("unable to create new worker!")
	}
	return w, nil
}

// spool searches for a live worker that can handle the specified request, or starts a new one for that purpose.
func (z *Finder) spool(req *zonecut.Request) {
	var wrk *worker
	var err error
	if val, ok := z.workerPool.Get(req.RequestTopic()); ok {
		// First, search in the LRU of live workers
		wrk = val.(*worker)
	} else if wrk, err = z.loadFromDisk(req); err == nil {
		// Then, search if the worker can be started from a cache file
		z.workerPool.Add(req.RequestTopic(), wrk)
	} else {
		// Finally, start a new worker to handle that request, if nothing else worked
		if req.Domain() == "." {
			// Starts immediately the worker for the root zone, which is a special-case
			wrk = newRootZoneWorker(req.Exceptions(), z.config)
		} else {
			wrk = newWorker(req, z.Handle, z.nrHandler, z.config)
		}

		z.workerPool.Add(req.RequestTopic(), wrk)
	}

	// Spools the request to the worker
	wrk.handle(req)
}

// start performs the operation for the finder to be ready to handle new requests.
func (z *Finder) start() {
	// Current start implementation start off a goroutine which reads from the reqs request channel attribute
	go func() {
		for req := range z.reqs {
			z.spool(req)
		}

		// Cleanup workers, because Stop() was called by the goroutine that owns the finder
		for _, key := range z.workerPool.Keys() {
			wrk, _ := z.workerPool.Peek(key)
			z.writeOnDisk(key, wrk)
		}
		z.joinChan <- true
	}()
}

// Stop signals that no new requests will be submitted. It triggers some cleanup of the remaining live workers, wait for
// them to finish and then returns true. Subsequent calls to Stop will return false as the finder is already stopped.
func (z *Finder) Stop() bool {
	if z.closedReqChan {
		return false
	}
	close(z.reqs)
	z.closedReqChan = true
	_ = <-z.joinChan
	close(z.joinChan)
	return true
}
