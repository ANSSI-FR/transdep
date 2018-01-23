package nameresolver

import (
	"encoding/json"
	"github.com/ANSSI-FR/transdep/errors"
)

type serializedResult struct {
	Result *Entry `json:"result,omitempty"`
	Err *errors.ErrorStack `json:"error,omitempty"`
}

// result is used for serialization of entries/errors for caching purposes as well as for transmission between
// goroutines using channels
type result struct {
	Result *Entry
	Err    *errors.ErrorStack
}

func (r *result) MarshalJSON() ([]byte, error) {
	sr := new(serializedResult)
	sr.Result = r.Result
	sr.Err = r.Err
	return json.Marshal(sr)
}

func (r *result) UnmarshalJSON(bstr []byte) error {
	sr := new(serializedResult)
	if err := json.Unmarshal(bstr, sr) ; err != nil {
		return err
	}
	r.Result = sr.Result
	r.Err = sr.Err
	return nil
}
