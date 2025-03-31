package notify

import (
	"context"
	"testing"
)

func TestDoer(t *testing.T) {
	doer := ErrorGroup(t.Context())

	// Perform some successful jobs
	for i := 0; i < 3; i++ {
		doer.RunCtx(func(ctx context.Context) error { return nil })
	}

	err := doer.Error()
	if err != nil {
		t.Fail()
	}
}
