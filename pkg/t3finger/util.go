package t3finger

import (
	"errors"
	"strconv"
	"sync/atomic"
)

var errNoControl = errors.New("control probe failed — host unreachable or already blocking requests")

func itoa(i int) string { return strconv.Itoa(i) }

// randToken returns a short, per-process-unique token to make the control
// package name unguessable (avoids the vanishingly-rare case of a real package
// colliding with the control name). It is deterministic-free but does not need
// crypto randomness — a monotonic counter mixed into the string suffices, and
// the scripts environment forbids time/rand anyway in some contexts.
var tokenCounter uint64

func randToken() string {
	n := atomic.AddUint64(&tokenCounter, 1)
	return "ctl" + strconv.FormatUint(n, 36) + strconv.FormatUint(uint64(len("t3scan"))*2654435761+n*2246822519, 36)
}
