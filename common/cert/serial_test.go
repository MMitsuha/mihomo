package cert

import (
	"sync"
	"testing"
)

// TestNextSerialUnique exercises the previously-racy initialisation: many
// goroutines hammer nextSerial from cold, every returned serial must be
// distinct. Before the CompareAndSwap fix, two callers could both observe
// counter==0 and Add(1) past the same seeded value, minting duplicates.
func TestNextSerialUnique(t *testing.T) {
	// Reset the package-level counter so the test sees the cold path.
	serialCounter.Store(0)

	const goroutines = 64
	const perG = 200

	var wg sync.WaitGroup
	results := make(chan int64, goroutines*perG)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perG; j++ {
				results <- nextSerial().Int64()
			}
		}()
	}
	wg.Wait()
	close(results)

	seen := make(map[int64]struct{}, goroutines*perG)
	for s := range results {
		if _, dup := seen[s]; dup {
			t.Fatalf("duplicate serial %d", s)
		}
		seen[s] = struct{}{}
	}

	if int64(len(seen)) != int64(goroutines*perG) {
		t.Fatalf("expected %d unique serials, got %d", goroutines*perG, len(seen))
	}
}
