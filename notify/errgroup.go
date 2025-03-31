package notify

import (
	"context"
	"errors"
	"sync"
)

type errGroup struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	wg     sync.WaitGroup
}

// ErrorGroup is an asynchronous job runner that collects the first error that occurs,
// cancels all remaining jobs and waits for everything to terminate.
func ErrorGroup(ctx context.Context) *errGroup {
	ctx, cancel := context.WithCancelCause(ctx)
	return &errGroup{ctx: ctx, cancel: cancel}
}

func (f *errGroup) RunCtx(fn func(context.Context) error) {
	f.wg.Add(1)
	go func() {
		err := fn(f.ctx)
		if err != nil {
			f.cancel(err)
		}
		f.wg.Done()
	}()
}

func (f *errGroup) Run(fn func() error) {
	f.wg.Add(1)
	go func() {
		err := fn()
		if err != nil {
			f.cancel(err)
		}
		f.wg.Done()
	}()
}

func (f *errGroup) Cancel() {
	f.cancel(nil)
}

func (f *errGroup) CancelWith(err error) {
	f.cancel(err)
}

// Error returns the first error that occurs, immediately as it happens. If all
// jobs complete without failure, Error returns nil after all have completed.
func (f *errGroup) Error() error {
	// Asynchronously wait for all jobs to finish if no errors occur
	exited := make(chan struct{})
	go func() {
		f.wg.Wait()
		close(exited)
	}()

	// Wait for either an error or all tasks to terminate successfully
	select {
	case <-f.ctx.Done():
	case <-exited:
	}
	return f.error()
}

func (f *errGroup) error() error {
	err := context.Cause(f.ctx)
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}

// Wait returns after all jobs have completed, returning the first error (if any
// errored, or none otherwise)
func (f *errGroup) Wait() error {
	f.wg.Wait()
	return f.error()
}
