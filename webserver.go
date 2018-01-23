package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"github.com/ANSSI-FR/transdep/dependency"
	"github.com/ANSSI-FR/transdep/graph"
	dependency2 "github.com/ANSSI-FR/transdep/messages/dependency"
	"github.com/ANSSI-FR/transdep/tools"
	"strconv"
	"time"
)

// handleRequest is common to all request handlers. The difference lies in the reqConf parameter whose value varies
// depending on the request handler.
func handleRequest(
	params url.Values, reqConf *tools.RequestConfig, reqChan chan<- *dependency2.Request,
	w http.ResponseWriter, req *http.Request,
) {
	// Get requested domain
	domain, ok := params["domain"]
	if !ok || len(domain) != 1 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Submit the request
	depReq := dependency2.NewRequest(domain[0], true, false, reqConf.Exceptions)
	select {
	case <-tools.StartTimeout(20 * time.Second):
		w.WriteHeader(http.StatusRequestTimeout)
		return
	case reqChan <- depReq:
		res, err := depReq.Result()
		if err != nil {
			bstr, err := json.Marshal(err)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Header().Add("content-type", "application/json+error")
			w.Write(bstr)
			return
		}

		rootNode, ok := res.(*graph.RelationshipNode)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var queryResult *graph.WorkerAnalysisResult
		allNamesResult, allNamesNo4Result, allNamesNo6Result, dnssecResult, dnssecNo4Result, dnssecNo6Result :=
			graph.PerformAnalyseOnResult(rootNode, reqConf, nil)

		if reqConf.AnalysisCond.DNSSEC == false {
			if reqConf.AnalysisCond.NoV4 {
				queryResult = allNamesNo4Result
			} else if reqConf.AnalysisCond.NoV6 {
				queryResult = allNamesNo6Result
			} else {
				queryResult = allNamesResult
			}
		} else {
			if reqConf.AnalysisCond.NoV4 {
				queryResult = dnssecNo4Result
			} else if reqConf.AnalysisCond.NoV6 {
				queryResult = dnssecNo6Result
			} else {
				queryResult = dnssecResult
			}
		}
		if queryResult.Err != nil {
			bstr, jsonErr := json.Marshal(queryResult.Err)
			if jsonErr != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Header().Add("content-type", "application/json+error")
			w.Write(bstr)
			return
		}
		bstr, jsonErr := json.Marshal(queryResult.Nodes)
		if jsonErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Header().Add("content-type", "application/json+nodes")
		w.Write(bstr)
		return
	}
}

// getRequestConf uses the parameters from the query string to define the request configuration, notably concerning
// deemed acceptable DNS violations
func getRequestConf(params url.Values) *tools.RequestConfig {
	var RFC8020, AcceptServfail bool

	paramRFC8020, ok := params["rfc8020"]
	if !ok || len(paramRFC8020) != 1 {
		RFC8020 = false
	} else if i, err := strconv.ParseInt(paramRFC8020[0], 10, 0); err != nil {
		RFC8020 = false
	} else {
		RFC8020 = i != 0
	}

	paramAcceptServfail, ok := params["servfail"]
	if !ok || len(paramAcceptServfail) != 1 {
		AcceptServfail = false
	} else if i, err := strconv.ParseInt(paramAcceptServfail[0], 10, 0); err != nil {
		AcceptServfail = false
	} else {
		AcceptServfail = i != 0
	}

	// Prepare request-specific configuration based on rfc8020 and servfail query string parameters presence and value
	reqConf := &tools.RequestConfig{
		AnalysisCond: tools.AnalysisConditions{
			All:    false,
			DNSSEC: false,
			NoV4:   false,
			NoV6:   false,
		},
		Exceptions: tools.Exceptions{
			RFC8020:                RFC8020,
			AcceptServFailAsNoData: AcceptServfail,
		},
	}

	return reqConf
}

func handleAllNamesRequests(reqChan chan<- *dependency2.Request, w http.ResponseWriter, req *http.Request) {
	params, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Prepare request-specific configuration
	reqConf := getRequestConf(params)
	handleRequest(params, reqConf, reqChan, w, req)
}

func handleDNSSECRequests(reqChan chan<- *dependency2.Request, w http.ResponseWriter, req *http.Request) {
	params, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Prepare request-specific configuration
	reqConf := getRequestConf(params)
	reqConf.AnalysisCond.DNSSEC = true
	handleRequest(params, reqConf, reqChan, w, req)
}

func handleNo4Requests(reqChan chan<- *dependency2.Request, w http.ResponseWriter, req *http.Request) {
	params, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Prepare request-specific configuration
	reqConf := getRequestConf(params)
	reqConf.AnalysisCond.NoV4 = true
	handleRequest(params, reqConf, reqChan, w, req)
}

func handleNo6Requests(reqChan chan<- *dependency2.Request, w http.ResponseWriter, req *http.Request) {
	params, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Prepare request-specific configuration
	reqConf := getRequestConf(params)
	reqConf.AnalysisCond.NoV6 = true
	handleRequest(params, reqConf, reqChan, w, req)
}

func stopFinder(df *dependency.Finder, reqChan chan<- *dependency2.Request, secret string, w http.ResponseWriter, req *http.Request) {
	params, err := url.ParseQuery(req.URL.RawQuery)
	if err == nil {
		if secretParam, ok := params["secret"]; ok && len(secretParam) == 1 && secretParam[0] == secret {
			// Secret is correct, initiating graceful stop
			go func() {
				// Wait for 1 second, just to give the time to send the web confirmation page
				time.Sleep(1 * time.Second)
				fmt.Printf("Stopping the finder: ")
				// Will print dots until os.Exit kills the process
				go func() {
					for {
						fmt.Printf(".")
						time.Sleep(100 * time.Millisecond)
					}
				}()
				close(reqChan)
				// Perform a graceful stop of the dependency finder, which will flush caches on disk
				df.Stop()
				fmt.Printf("OK\n")
				os.Exit(0)
			}()
			// Returns a webpage confirming shutdown
			w.WriteHeader(http.StatusOK)
			buf := new(bytes.Buffer)
			buf.WriteString("Stopping.")
			w.Write(buf.Bytes())
			return
		}
	}

	// Reject all requests that are missing the secret parameter or whose secret value is different from the "secret"
	// function parameter.
	w.WriteHeader(http.StatusForbidden)
}

// runWebWorker is a go routine that handles dependency requests received from the web handlers.
func runWebWorker(df *dependency.Finder, reqChan <-chan *dependency2.Request) {
	for req := range reqChan {
		df.Handle(req)
	}
}

func main() {
	var transdepConf tools.TransdepConfig
	var ip string
	var port int
	secret := make([]byte, 16)
	var secretString string

	tmpdir := os.Getenv("TMPDIR")
	if tmpdir == "" {
		tmpdir = "/tmp"
	}

	flag.IntVar(&transdepConf.JobCount, "jobs", 5, "Indicates the maximum number of concurrent workers")
	flag.IntVar(&transdepConf.LRUSizes.DependencyFinder, "dflrusize", 2000, "Indicates the maximum number of concurrent Dependency Finder workers")
	flag.IntVar(&transdepConf.LRUSizes.ZoneCutFinder, "zcflrusize", 10000, "Indicates the maximum number of concurrent Zone Cut Finder workers")
	flag.IntVar(&transdepConf.LRUSizes.NameResolverFinder, "nrlrusize", 10000, "Indicates the maximum number of concurrent Name Resolver workers")
	flag.StringVar(&transdepConf.CacheRootDir, "cachedir", tmpdir, "Specifies the cache directory")
	flag.StringVar(&transdepConf.RootHintsFile, "hints", "", "An updated DNS root hint file. If left unspecified, some hardcoded values will be used.")
	flag.StringVar(&ip, "bind", "127.0.0.1", "IP address to which the HTTP server will bind and listen")
	flag.IntVar(&port, "port", 5000, "Port on which the HTTP server will bind and listen")
	flag.Parse()

	// A single dependency finder is shared between all web clients. This allows for cache sharing.
	df := dependency.NewFinder(&transdepConf, nil)

	reqChan := make(chan *dependency2.Request)
	for i := 0; i < transdepConf.JobCount; i++ {
		go runWebWorker(df, reqChan)
	}

	// A secret is generated from random. The point of this secret is to be an authentication token allowing graceful
	// shutdown
	rand.Read(secret[:])
	secretString = hex.EncodeToString(secret)
	// The URL to call to perform a graceful shutodown is printed on stdout
	fmt.Printf("To stop the server, send a query to http://%s:%d/stop?secret=%s\n", ip, port, secretString)

	// handles all requests where we want a list of all SPOF, even domain names that are not protected by DNSSEC
	http.HandleFunc("/allnames", func(w http.ResponseWriter, req *http.Request) {
		handleAllNamesRequests(reqChan, w, req)
	})

	// handles all requests where we want a list of all SPOF (domain are considered a SPOF candidates only if they are DNSSEC-protected)
	http.HandleFunc("/dnssec", func(w http.ResponseWriter, req *http.Request) {
		handleDNSSECRequests(reqChan, w, req)
	})

	// handles all requests where we want a list of all SPOF when IPv4 addresses are unreachable
	http.HandleFunc("/break4", func(w http.ResponseWriter, req *http.Request) {
		handleNo4Requests(reqChan, w, req)
	})

	// handles all requests where we want a list of all SPOF when IPv6 addresses are unreachable
	http.HandleFunc("/break6", func(w http.ResponseWriter, req *http.Request) {
		handleNo6Requests(reqChan, w, req)
	})

	// handles requests to stop graceful this webservice
	http.HandleFunc("/stop", func(w http.ResponseWriter, req *http.Request) {
		stopFinder(df, reqChan, secretString, w, req)
	})

	// start web server and log fatal error that may arise during execution
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", ip, port), nil))
}
