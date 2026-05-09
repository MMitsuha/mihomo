package rewrite

import (
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
)

var current atomic.Pointer[Rules]

// Update replaces the active rule set used by handlers.
func Update(r *Rules) {
	if r == nil {
		r = NewRules(nil, nil)
	}
	current.Store(r)
}

// Current returns the active rule set; never nil.
func Current() C.RewriteRule {
	r := current.Load()
	if r == nil {
		return NewRules(nil, nil)
	}
	return r
}
