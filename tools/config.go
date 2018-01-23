package tools

import "fmt"

type AnalysisConditions struct {
	All    bool
	DNSSEC bool
	NoV4   bool
	NoV6   bool
}

type LRUConfig struct {
	DependencyFinder   int
	ZoneCutFinder      int
	NameResolverFinder int
}

type FormatOptions struct {
	ScriptFriendlyOutput bool
	Graph                bool
	DotOutput            bool
}

type TransdepConfig struct {
	JobCount                              int
	LRUSizes                              LRUConfig
	CacheRootDir, RootHintsFile, MaboFile string
}

type RequestConfig struct {
	AnalysisCond AnalysisConditions
	OutputFormat FormatOptions
	Exceptions   Exceptions
}

type Exceptions struct {
	RFC8020, AcceptServFailAsNoData bool
}

func (tc RequestConfig) Check(fileName string) error {
	if tc.OutputFormat.Graph &&
		(tc.AnalysisCond.All || tc.AnalysisCond.NoV4 || tc.AnalysisCond.NoV6 || tc.AnalysisCond.DNSSEC || tc.OutputFormat.ScriptFriendlyOutput || tc.OutputFormat.DotOutput) {
		return fmt.Errorf("-graph option is supposed to be used alone w.r.t. to other output selection options.")
	}

	if tc.OutputFormat.DotOutput && (len(fileName) != 0 || tc.AnalysisCond.All || tc.OutputFormat.Graph || tc.OutputFormat.ScriptFriendlyOutput) {
		return fmt.Errorf("Cannot use -dot with -file, -all, -graph, or -script")
	}

	if tc.AnalysisCond.All && (tc.AnalysisCond.DNSSEC || tc.AnalysisCond.NoV6 || tc.AnalysisCond.NoV4) {
		return fmt.Errorf("Can't have -all option on at the same time as -break4, -break6 or -dnssec")
	}
	return nil
}
