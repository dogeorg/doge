package wrapped

import (
	"errors"
	"fmt"
)

// Create a function that wraps errors from third-party sources.
// Those wrapped errors also satisfy errors.Is(err, Base)
//
// Base is a new well-known error that should be a public field
// of your package, so users can test errors.Is(err, Base)
//
// Example:
//
// var WrongTime, wrapWrongTime = wrapped.New("wrong time")
//
//	func foo() error {
//		    ...
//		    if err != nil {
//		        return wrapWrongTime(err)
//		    }
//	}
func New(msg string) (base error, wrap WrapErrorFunc) {
	base = errors.New(msg)
	return base, func(err error) error {
		return &errorDoge{
			wrap: err,
			base: base,
		}
	}
}

type WrapErrorFunc func(err error) error

// errorString is a trivial implementation of error.
type errorDoge struct {
	wrap error
	base error
}

func (e *errorDoge) Error() string {
	return fmt.Sprintf("%v: %v", e.base.Error(), e.wrap)
}

// Unwrap satisfies errors.Is(e, base) and errors.Is(e, wrap)
func (e *errorDoge) Unwrap() []error {
	return []error{e.wrap, e.base}
}
