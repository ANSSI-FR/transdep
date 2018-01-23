package errors

import "fmt"

type TimeoutError struct {
	operation string
	requestTopic string
}

func NewTimeoutError(operation, topic string) *TimeoutError {
	te := new(TimeoutError)
	te.operation = operation
	te.requestTopic = topic
	return te
}

func (te *TimeoutError) Error() string {
	return fmt.Sprintf("timeout while performing \"%s\" on \"%s\"", te.operation, te.requestTopic)
}
