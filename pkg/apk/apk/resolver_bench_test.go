package apk

import (
	"context"
	"fmt"
	"os"
	"testing"
)

// loadBenchIndexes loads a real APKINDEX for benchmarks. Set
// APKO_BENCH_INDEX_DIR to a directory containing APKINDEX-<arch>.tar.gz files.
func loadBenchIndexes(tb testing.TB, arch string) []NamedIndex {
	dir := os.Getenv("APKO_BENCH_INDEX_DIR")
	if dir == "" {
		tb.Skip("APKO_BENCH_INDEX_DIR not set")
	}
	f, err := os.Open(fmt.Sprintf("%s/APKINDEX-%s.tar.gz", dir, arch))
	if err != nil {
		tb.Fatal(err)
	}
	idx, err := IndexFromArchive(f)
	if err != nil {
		tb.Fatal(err)
	}
	repo := Repository{URI: "https://packages.wolfi.dev/os/" + arch}
	return []NamedIndex{NewNamedRepositoryWithIndex("", repo.WithIndex(idx))}
}

var benchWorld = []string{
	"busybox", "bash", "git", "curl", "python-3.12", "go", "nodejs", "glibc",
}

func BenchmarkNewPkgResolverCold(b *testing.B) {
	indexes := loadBenchIndexes(b, "x86_64")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buildFragment(indexes[0])
	}
}

func BenchmarkNewPkgResolverWarm(b *testing.B) {
	indexes := loadBenchIndexes(b, "x86_64")
	_ = NewPkgResolver(context.Background(), indexes) // prime
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewPkgResolver(context.Background(), indexes)
	}
}

func BenchmarkGetPackagesWithDependencies(b *testing.B) {
	ctx := context.Background()
	allArchs := map[string][]NamedIndex{
		"x86_64":  loadBenchIndexes(b, "x86_64"),
		"aarch64": loadBenchIndexes(b, "aarch64"),
	}
	_ = NewPkgResolver(ctx, allArchs["x86_64"]) // prime
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := NewPkgResolver(ctx, allArchs["x86_64"])
		if _, _, err := p.GetPackagesWithDependencies(ctx, benchWorld, allArchs); err != nil {
			b.Fatal(err)
		}
	}
}
