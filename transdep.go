package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"github.com/ANSSI-FR/transdep/dependency"
	dep_msg "github.com/ANSSI-FR/transdep/messages/dependency"
	"github.com/ANSSI-FR/transdep/graph"
	"strings"
	"github.com/hashicorp/go-immutable-radix"
	"github.com/ANSSI-FR/transdep/tools/radix"
	"github.com/ANSSI-FR/transdep/tools"
)

func displayDomain(prefix string, res *graph.WorkerAnalysisResult, conf *tools.RequestConfig) {
	if res.Err != nil {
		if conf.OutputFormat.ScriptFriendlyOutput {
			fmt.Printf("%s%s\n", prefix, "-ERROR-")
		} else {
			fmt.Printf("%s%s\n", prefix, res.Err)
		}
	} else {
		for _, elmt := range res.Nodes {
			switch e := elmt.(type) {
			case graph.CriticalName:
				fmt.Printf("%sName:%s\n", prefix, e.Name)
			case graph.CriticalAlias:
				fmt.Printf("%sAlias:%s->%s\n", prefix, e.Source, e.Target)
			case graph.CriticalIP:
				fmt.Printf("%sIP:%s\n", prefix, e.IP.String())
			case graph.CriticalASN:
				fmt.Printf("%sASN:%d\n", prefix, e.ASN)
			case graph.CriticalPrefix:
				if e.Prefix.To4() != nil {
					fmt.Printf("%sPrefix:%s/24\n", prefix, e.Prefix.String())
				} else {
					fmt.Printf("%sPrefix:%s/48\n", prefix, e.Prefix.String())
				}
			case *graph.Cycle:
				fmt.Printf("%sCycle\n", prefix)
			default:
				panic("BUG: missing case")
			}
		}
	}
}

type WorkerResult struct {
	dn          string
	stringRepr  string
	allNames    *graph.WorkerAnalysisResult
	dnssec      *graph.WorkerAnalysisResult
	allNamesNo4 *graph.WorkerAnalysisResult
	dnssecNo4   *graph.WorkerAnalysisResult
	allNamesNo6 *graph.WorkerAnalysisResult
	dnssecNo6   *graph.WorkerAnalysisResult
	err         error
}

func performBackgroundAnalysis(name string, g *graph.RelationshipNode, ansChan chan<- *WorkerResult, analysisDoneChan chan<- bool, requestConf *tools.RequestConfig, tree *iradix.Tree) {
	allNamesResult, allNamesNo4Result, allNamesNo6Result, dnssecResult, dnssecNo4Result, dnssecNo6Result := graph.PerformAnalyseOnResult(g, requestConf, tree)

	ansChan <- &WorkerResult{
		name, "",
		allNamesResult,
		dnssecResult,
		allNamesNo4Result,
		dnssecNo4Result,
		allNamesNo6Result,
		dnssecNo6Result,
		nil,
	}
	analysisDoneChan <- true
}

func spoolDependencyRequest(wc <-chan *dep_msg.Request, ansChan chan<- *WorkerResult, df *dependency.Finder, reqConf *tools.RequestConfig, transdepConf *tools.TransdepConfig, tree *iradix.Tree) {
	currentlyAnalyzedCounter := 0
	analysisDoneChan := make(chan bool, transdepConf.JobCount)
	inputClosed := false
	for !inputClosed || currentlyAnalyzedCounter != 0 {
		select {
		case _ = <- analysisDoneChan:
			currentlyAnalyzedCounter--
		case req, opened := <-wc:
			inputClosed = !opened
			if req != nil && opened {
				if err := df.Handle(req) ; err != nil {
					ansChan <- &WorkerResult{
						req.Name(), "",nil, nil,
						nil, nil, nil, nil,
						err,
					}
				}

				res, err := req.Result()
				if err != nil {
					ansChan <- &WorkerResult{
						req.Name(), "", nil, nil,
						nil, nil, nil, nil,
						err,
					}
				} else {
					relNode, ok := res.(*graph.RelationshipNode)
					if !ok {
						ansChan <- &WorkerResult{
							req.Name(), "", nil, nil,
							nil, nil, nil, nil,
							fmt.Errorf("returned node is not a RelationshipNode instance"),
						}
					}
					if reqConf.OutputFormat.Graph {
						jsonbstr, err := json.Marshal(relNode.SimplifyGraph())
						ansChan <- &WorkerResult{
							req.Name(), string(jsonbstr), nil, nil,
							nil, nil, nil, nil,
							err,
						}
					} else if reqConf.OutputFormat.DotOutput {
						ansChanForDot := make(chan *WorkerResult, 1)
						analysisDoneChanForDot := make(chan bool, 1)
						go performBackgroundAnalysis(req.Name(), relNode, ansChanForDot, analysisDoneChanForDot, reqConf, tree)
						<- analysisDoneChanForDot
						analysisResult := <- ansChanForDot
						var criticalNodes []graph.CriticalNode
						if reqConf.AnalysisCond.DNSSEC {
							if reqConf.AnalysisCond.NoV4 {
								criticalNodes = analysisResult.dnssecNo4.Nodes
							} else if reqConf.AnalysisCond.NoV6 {
								criticalNodes = analysisResult.dnssecNo6.Nodes
							} else {
								criticalNodes = analysisResult.dnssec.Nodes
							}
						} else if reqConf.AnalysisCond.NoV4 {
							criticalNodes = analysisResult.allNamesNo4.Nodes
						} else if reqConf.AnalysisCond.NoV6 {
							criticalNodes = analysisResult.allNamesNo6.Nodes
						} else {
							criticalNodes = analysisResult.allNames.Nodes
						}

						g, _ := graph.DrawGraph(relNode.SimplifyGraph(), criticalNodes)
						g.SetStrict(true)
						ansChan <- &WorkerResult{
							req.Name(), g.String(), nil, nil,
							nil, nil, nil, nil,
							nil,
						}
					} else {
						go performBackgroundAnalysis(req.Name(), relNode, ansChan, analysisDoneChan, reqConf, tree)
						currentlyAnalyzedCounter++
					}
				}
			}
		}
	}
	ansChan <- nil
}

func handleWorkerResponse(res *WorkerResult, reqConf *tools.RequestConfig) bool {
	if res == nil {
		return true
	}

	if res.err != nil {
		if reqConf.OutputFormat.ScriptFriendlyOutput {
			fmt.Printf("Error:%s:%s\n", res.dn, "-FAILURE-")
		} else {
			fmt.Printf("Error:%s:%s\n", res.dn, fmt.Sprintf("Error while resolving this name: %s", res.err))
		}
	} else if reqConf.OutputFormat.Graph {
		fmt.Printf("%s:%s\n", res.dn, res.stringRepr)
	} else if reqConf.OutputFormat.DotOutput {
		fmt.Println(res.stringRepr)
	} else {
		if reqConf.AnalysisCond.All {
			displayDomain(fmt.Sprintf("AllNames:%s:", res.dn), res.allNames, reqConf)
			displayDomain(fmt.Sprintf("DNSSEC:%s:", res.dn), res.dnssec, reqConf)
			displayDomain(fmt.Sprintf("AllNamesNo4:%s:", res.dn), res.allNamesNo4, reqConf)
			displayDomain(fmt.Sprintf("DNSSECNo4:%s:", res.dn), res.dnssecNo4, reqConf)
			displayDomain(fmt.Sprintf("AllNamesNo6:%s:", res.dn), res.allNamesNo6, reqConf)
			displayDomain(fmt.Sprintf("DNSSECNo6:%s:", res.dn), res.dnssecNo6, reqConf)
		} else if reqConf.AnalysisCond.DNSSEC {
			if reqConf.AnalysisCond.NoV4 {
				displayDomain(fmt.Sprintf("%s:", res.dn), res.dnssecNo4, reqConf)
			} else if reqConf.AnalysisCond.NoV6 {
				displayDomain(fmt.Sprintf("%s:", res.dn), res.dnssecNo6, reqConf)
			} else {
				displayDomain(fmt.Sprintf("%s:", res.dn), res.dnssec, reqConf)
			}
		} else {
			if reqConf.AnalysisCond.NoV4 {
				displayDomain(fmt.Sprintf("%s:", res.dn), res.allNamesNo4, reqConf)
			} else if reqConf.AnalysisCond.NoV6 {
				displayDomain(fmt.Sprintf("%s:", res.dn), res.allNamesNo6, reqConf)
			} else {
				displayDomain(fmt.Sprintf("%s:", res.dn), res.allNames, reqConf)
			}
		}
	}
	return false
}

func createDomainNameStreamer(fileName string, c chan<- string) {
	fd, err := os.Open(fileName)
	if err != nil {
		panic("Unable to open file for read access")
	}
	reader := bufio.NewReader(fd)
	err = nil
	for err == nil {
		var line string
		line, err = reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				panic("Error while reading file")
			}
		}
		c <- strings.TrimRight(line, "\n")
	}
	close(c)
}

func analyseDomains(domainNameChan <-chan string, reqConf *tools.RequestConfig, transdepConf *tools.TransdepConfig, df *dependency.Finder, tree *iradix.Tree) {
	// Start workers
	wc := make(chan *dep_msg.Request)
	ansChan := make(chan *WorkerResult, 1)
	for i := 0; i < transdepConf.JobCount; i++ {
		go spoolDependencyRequest(wc, ansChan, df, reqConf, transdepConf, tree)
	}

	// Prepare for reading input file
	deadWorker := 0
	sent := true
	var req *dep_msg.Request

	// Loop until all lines are read and a corresponding request has been spooled
Outerloop:
	for {
		opened := true
		// This loop does not only loop when a new request is spooled, but also when a response is received. Thus,
		// we need this "sent" switch to know whether we should continue to try to push a request or read a new line
		if sent {
			sent = false
			targetDn := ""
			for targetDn == "" {
				// Read a domain name
				targetDn, opened = <-domainNameChan
				if targetDn == "" && !opened {
					close(wc)
					break Outerloop
				}
			}
			// Build the dependency request
			req = dep_msg.NewRequest(targetDn, true, false, reqConf.Exceptions)
		}

		select {
		case wc <- req:
			if !opened {
				close(wc)
				break Outerloop
			}
			sent = true
		case res := <-ansChan:
			if handleWorkerResponse(res, reqConf) {
				deadWorker++
			}
		}
	}

	for deadWorker < transdepConf.JobCount {
		res := <-ansChan
		if handleWorkerResponse(res, reqConf) {
			deadWorker++
		}
	}
	close(ansChan)
}

func analyseFromFile(loadFile string, requestConf *tools.RequestConfig, tree *iradix.Tree) {
	fd, err := os.Open(loadFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	bufrd := bufio.NewReader(fd)
	targetDn, err := bufrd.ReadString(':')
	if err != nil {
		fmt.Println(err)
		return
	}
	targetDn = strings.TrimRight(targetDn, ":")

	jsonbstr, err := bufrd.ReadBytes('\x00')
	if err != nil && err != io.EOF {
		fmt.Println(err)
		return
	}

	g := new(graph.RelationshipNode)
	err = json.Unmarshal(jsonbstr, g)
	if err != nil {
		fmt.Println(err)
		return
	}

	ansChan := make(chan *WorkerResult, 1)
	analysisDoneChan := make(chan bool, 1)
	go performBackgroundAnalysis(targetDn, g, ansChan, analysisDoneChan, requestConf, tree)

	<-analysisDoneChan
	wr := <-ansChan
	handleWorkerResponse(wr, requestConf)
}

func analyseFromDomainList(domChan <-chan string, reqConf *tools.RequestConfig, transdepConf *tools.TransdepConfig, tree *iradix.Tree) {

	df := dependency.NewFinder(transdepConf, tree)
	defer df.Stop()

	analyseDomains(domChan, reqConf, transdepConf, df, tree)
}

func buildDomainListChan(targetDn, fileName string) <-chan string {
	domChan := make(chan string)
	if len(targetDn) != 0 {
		go func() {
			domChan <- targetDn
			close(domChan)
		}()
	} else {
		go createDomainNameStreamer(fileName, domChan)
	}
	return domChan
}

func main() {
	var targetDn, fileName, loadFile string

	var transdepConf tools.TransdepConfig
	var requestConf tools.RequestConfig

	tmpdir := os.Getenv("TMPDIR")
	if tmpdir == "" {
		tmpdir = "/tmp"
	}

	flag.StringVar(&targetDn, "domain", "", "Indicates the domain name to analyze")
	flag.StringVar(&fileName, "file", "", "Indicates the file containing domain to analyze, one per line")
	flag.StringVar(&loadFile, "load", "", "Indicates the file containing a dependency graph in JSON format")
	flag.IntVar(&transdepConf.JobCount, "jobs", 5, "Indicates the maximum number of concurrent workers")
	flag.BoolVar(&requestConf.AnalysisCond.All, "all", false, "Indicates that IPv4 are not available")
	flag.BoolVar(&requestConf.AnalysisCond.NoV4, "break4", false, "Indicates that IPv4 are not available")
	flag.BoolVar(&requestConf.AnalysisCond.NoV6, "break6", false, "Indicates that IPv6 are not available")
	flag.BoolVar(&requestConf.AnalysisCond.DNSSEC, "dnssec", false, "Indicates that only DNSSEC-protected domains can break")
	flag.BoolVar(&requestConf.OutputFormat.ScriptFriendlyOutput, "script", false, "On error, just write \"-ERROR-\"")
	flag.BoolVar(&requestConf.OutputFormat.Graph, "graph", false, "Indicates whether to just print the graph")
	flag.BoolVar(&requestConf.OutputFormat.DotOutput, "dot", false, "Indicates whether to just print the graphviz dot file representation")
	flag.IntVar(&transdepConf.LRUSizes.DependencyFinder, "dflrusize", 2000, "Indicates the maximum number of concurrent Dependency Finder workers")
	flag.IntVar(&transdepConf.LRUSizes.ZoneCutFinder, "zcflrusize", 10000, "Indicates the maximum number of concurrent Zone Cut Finder workers")
	flag.IntVar(&transdepConf.LRUSizes.NameResolverFinder, "nrlrusize", 10000, "Indicates the maximum number of concurrent Name Resolver workers")
	flag.StringVar(&transdepConf.CacheRootDir, "cachedir", tmpdir, "Specifies the cache directory")
	flag.StringVar(&transdepConf.RootHintsFile, "hints", "", "An updated DNS root hint file. If left unspecified, some hardcoded values will be used.")
	flag.StringVar(&transdepConf.MaboFile, "mabo", "", "Indicates the name of a file containing the output of the Mabo tool when used with the prefix option")
	flag.BoolVar(&requestConf.Exceptions.RFC8020, "rfc8020", false, "If set, a RCODE=3 on a zonecut request will be considered as an ENT.")
	flag.BoolVar(&requestConf.Exceptions.AcceptServFailAsNoData, "servfail", false, "Consider a SERVFAIL error as an ENT (for servers that can't answer to anything else than A and AAAA)")
	flag.Parse()

	if len(targetDn) == 0 && len(fileName) == 0 && len(loadFile) == 0 {
		panic("Either domain parameter, load parameter or file parameter must be specified.")
	}

	if err := requestConf.Check(fileName) ; err != nil {
		panic(err.Error())
	}

	var tree *iradix.Tree
	var err error
	if len(transdepConf.MaboFile) != 0 {
		tree, err = radix.GetASNTree(transdepConf.MaboFile)
		if err != nil {
			panic(err)
		}
	}

	if len(loadFile) != 0 {
		analyseFromFile(loadFile, &requestConf, tree)
	} else {
		analyseFromDomainList(buildDomainListChan(targetDn, fileName), &requestConf, &transdepConf, tree)
	}
}
