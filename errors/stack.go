package errors

import (
	"strings"
	"encoding/json"
	"errors"
	"github.com/miekg/dns"
	"net"
	"fmt"
)

type ErrorStack struct {
	errors []error
}

func NewErrorStack(err error) *ErrorStack {
	s := new(ErrorStack)
	s.Push(err)
	return s
}

func (es *ErrorStack) Copy() *ErrorStack {
	newStack := new(ErrorStack)
	for _, err := range es.errors {
		// provision for when an error type will require a deepcopy
		switch typedErr := err.(type) {
/*		case *NXDomainError:
			newStack.errors = append(newStack.errors, err)
		case *ServfailError:
			newStack.errors = append(newStack.errors, err)
		case *NoNameServerError:
			newStack.errors = append(newStack.errors, err)
		case *TimeoutError:
			newStack.errors = append(newStack.errors, err)*/
		default:
			_ = typedErr
			newStack.errors = append(newStack.errors, err)
		}

	}
	return newStack
}

func (es *ErrorStack) MarshalJSON() ([]byte, error) {
	var ses []interface{}
	for _, err := range es.errors {
		switch typedErr := err.(type) {
		case *NXDomainError:
			ses = append(ses, typedErr)
		case *ServfailError:
			ses = append(ses, typedErr)
		case *NoNameServerError:
			ses = append(ses, typedErr)
		default:
			ses = append(ses, typedErr.Error())
		}
	}
	return json.Marshal(ses)
}

func (es *ErrorStack) UnmarshalJSON(bstr []byte) error {
	var ses []interface{}
	if err := json.Unmarshal(bstr, &ses) ; err != nil {
		return err
	}
	for _, err := range ses {
		switch typedErr := err.(type) {
		case string:
			es.errors = append(es.errors, errors.New(typedErr))
		case map[string]interface{}:
			if typeVal, ok := typedErr["type"] ; ok {
				if typeVal.(string) == dns.RcodeToString[dns.RcodeServerFailure] {
					es.errors = append(es.errors, NewServfailError(typedErr["qname"].(string), dns.StringToType[typedErr["qtype"].(string)], net.ParseIP(typedErr["ip"].(string)), STR_TO_PROTO[typedErr["protocol"].(string)]))
				} else if typeVal.(string) == dns.RcodeToString[dns.RcodeNameError] {
					es.errors = append(es.errors, NewNXDomainError(typedErr["qname"].(string), dns.StringToType[typedErr["qtype"].(string)], net.ParseIP(typedErr["ip"].(string)), STR_TO_PROTO[typedErr["protocol"].(string)]))
				} else {
					panic(fmt.Sprintf("missing case: type unknown: %s", typeVal))
				}
			} else if name, ok := typedErr["name"] ; ok {
				es.errors = append(es.errors, NewNoNameServerError(name.(string)))
			}
		default:
			panic("missing case: not a string nor a map?")
		}
	}
	return nil
}

func (es *ErrorStack) Push(err error) {
	es.errors = append(es.errors, err)
}

func (es *ErrorStack) OriginalError() error {
	if len(es.errors) > 0 {
		return es.errors[0]
	}
	return nil
}

func (es *ErrorStack) LatestError() error {
	if len(es.errors) > 0 {
		return es.errors[len(es.errors)-1]
	}
	return nil
}

func (es *ErrorStack) Error() string {
	errCount := len(es.errors)
	l := make([]string, errCount)
	if errCount == 1 {
		l[0] = es.errors[0].Error()
	} else {
		for i := 0; i < len(es.errors)/2; i++ {
			l[i] = es.errors[errCount-1-i].Error()
			l[errCount-1-i] = es.errors[i].Error()
		}
	}
	return strings.Join(l, ", ")
}