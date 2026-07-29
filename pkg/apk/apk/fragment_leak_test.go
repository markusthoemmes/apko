package apk

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// TestIndexGenerationsAreCollectable guards against derived resolution data
// (fragments, resolvers, disqualify sets) outliving the index generation it
// was built from. The old global resolver/disqualify caches pinned every etag
// generation of every index, growing without bound in long-running processes.
func TestIndexGenerationsAreCollectable(t *testing.T) {
	const nPkgs = 10000

	idx := &APKIndex{Description: "leak-test"}
	for i := range nPkgs {
		idx.Packages = append(idx.Packages, &Package{
			Name:        fmt.Sprintf("pkg-%d", i),
			Version:     "1.0.0-r0",
			Arch:        "x86_64",
			Description: fmt.Sprintf("synthetic package %d", i),
			Checksum:    []byte("01234567890123456789"),
			// A short chain keeps the resolve cheap; the index stays large.
			Dependencies: []string{fmt.Sprintf("pkg-%d", min(i+1, 20))},
			Provides:     []string{fmt.Sprintf("cmd:tool-%d=1.0.0-r0", i)},
			BuildTime:    time.Unix(1700000000, 0).UTC(),
		})
	}
	archive, err := ArchiveFromIndex(idx)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	if _, err := body.ReadFrom(archive); err != nil {
		t.Fatal(err)
	}

	var etag atomic.Value
	etag.Store("gen-0")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", fmt.Sprintf("%q", etag.Load()))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body.Bytes())
	}))
	defer srv.Close()

	ctx := context.Background()
	heapMB := func() float64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return float64(m.HeapAlloc) / (1 << 20)
	}

	fetch := func(g int) []NamedIndex {
		etag.Store(fmt.Sprintf("gen-%d", g))
		indexes, err := GetRepositoryIndexes(ctx, []string{srv.URL}, nil, "x86_64",
			WithIgnoreSignatures(true), WithHTTPClient(srv.Client()))
		if err != nil {
			t.Fatal(err)
		}
		return indexes
	}
	resolve := func(indexes []NamedIndex) {
		p := NewPkgResolver(ctx, indexes)
		// Two arches so the cross-arch predicate (and the fragments it
		// captures) is exercised too.
		if _, _, err := p.GetPackagesWithDependencies(ctx, []string{"pkg-0"},
			map[string][]NamedIndex{"x86_64": indexes, "aarch64": indexes}); err != nil {
			t.Fatal(err)
		}
	}

	// Warm up allocator and caches, then measure growth across generations.
	resolve(fetch(0))
	base := heapMB()
	const generations = 8
	prev := fetch(1)
	for g := 2; g <= generations+1; g++ {
		// Fetching generation g supersedes generation g-1, which an unfinished
		// resolution still holds — like a build racing an index rotation.
		// Resolving with it afterwards must not pin it beyond the caller's
		// own reference.
		indexes := fetch(g)
		resolve(prev)
		resolve(indexes)
		prev = indexes
	}
	prev = nil
	_ = prev
	grown := heapMB() - base

	// Each pinned generation retains several MB (index + fragment + wrappers).
	// With correct collection, growth stays near zero; the old global caches
	// grew by roughly generations * per-generation size (tens of MB here).
	if grown > 20 {
		t.Errorf("heap grew by %.1f MB across %d index generations, derived data is likely pinned", grown, generations)
	}
}
