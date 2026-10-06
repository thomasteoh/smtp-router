package server

import (
	"fmt"
	"sync"
)

// providerChoice is one weighted entry in an account's allocation list.
type providerChoice struct {
	name   string
	weight int
}

// allocator is a per-account weighted round-robin selector. It uses the
// nginx smooth weighted round-robin algorithm: at each pick the provider with
// the highest (current_weight + weight) wins, then its current weight is
// decremented by the total. With equal weights this degenerates to plain
// round-robin; with tiered weights it distributes proportionally and still
// cycles through every provider, so a lower-tier provider is never starved.
type allocator struct {
	mu      sync.Mutex
	choices []providerChoice
	total   int
	// current is the running weight state (one per choice), mutated per pick.
	current []int
}

// newAllocator builds an allocator from weighted choices. Weights are
// normalized: a non-positive weight becomes 1 so every listed provider is
// used. An empty list yields an allocator that always errors.
func newAllocator(choices []providerChoice) *allocator {
	a := &allocator{}
	total := 0
	for _, c := range choices {
		w := c.weight
		if w <= 0 {
			w = 1
		}
		a.choices = append(a.choices, providerChoice{name: c.name, weight: w})
		a.current = append(a.current, 0)
		total += w
	}
	a.total = total
	return a
}

// pick returns the next provider name. It is safe for concurrent use.
func (a *allocator) pick() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.total == 0 {
		return "", fmt.Errorf("no providers in allocation")
	}
	// Smooth weighted round-robin: add each provider's weight to its current,
	// select the highest, then subtract the total from the winner.
	best := -1
	bestScore := -1
	for i := range a.choices {
		a.current[i] += a.choices[i].weight
		if a.current[i] > bestScore {
			bestScore = a.current[i]
			best = i
		}
	}
	a.current[best] -= a.total
	return a.choices[best].name, nil
}
