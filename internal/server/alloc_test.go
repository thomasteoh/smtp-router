package server

import "testing"

func TestAllocatorRoundRobin(t *testing.T) {
	// Equal weights must cycle evenly (round-robin).
	a := newAllocator([]providerChoice{{name: "a", weight: 1}, {name: "b", weight: 1}})
	var got []string
	for i := 0; i < 10; i++ {
		name, err := a.pick()
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		got = append(got, name)
	}
	// Expect strict alternation: a,b,a,b,...
	for i := range got {
		want := "a"
		if i%2 == 1 {
			want = "b"
		}
		if got[i] != want {
			t.Fatalf("round-robin index %d = %q, want %q", i, got[i], want)
		}
	}
}

func TestAllocatorWeighted(t *testing.T) {
	// Weight 3:1 must distribute ~75/25 and cycle through both.
	a := newAllocator([]providerChoice{{name: "a", weight: 3}, {name: "b", weight: 1}})
	count := map[string]int{}
	for i := 0; i < 400; i++ {
		name, err := a.pick()
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		count[name]++
	}
	if count["a"] < 290 || count["a"] > 310 {
		t.Fatalf("weighted distribution a = %d, want ~300/400", count["a"])
	}
	if count["b"] < 90 || count["b"] > 110 {
		t.Fatalf("weighted distribution b = %d, want ~100/400", count["b"])
	}
	// Both must appear (no starvation).
	if count["a"] == 0 || count["b"] == 0 {
		t.Fatalf("starvation: counts = %v", count)
	}
}

func TestAllocatorEmpty(t *testing.T) {
	a := newAllocator(nil)
	if _, err := a.pick(); err == nil {
		t.Fatal("empty allocator must error")
	}
}

func TestAllocatorNonPositiveWeight(t *testing.T) {
	// A weight of 0 is normalized to 1 so every listed provider is used.
	a := newAllocator([]providerChoice{{name: "a", weight: 0}, {name: "b", weight: 2}})
	var names []string
	for i := 0; i < 6; i++ {
		n, _ := a.pick()
		names = append(names, n)
	}
	seen := map[string]bool{}
	for _, n := range names {
		seen[n] = true
	}
	if !seen["a"] || !seen["b"] {
		t.Fatalf("normalized weight must still use both: got %v", names)
	}
}
