// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package repo provides a pluggable interface for APK repository I/O operations.
// The Client interface abstracts all network and cache operations for fetching
// packages, indexes, and keys from APK repositories.
package repo

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/hashicorp/go-cleanhttp"

	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/apk/expandapk"
)

// Client defines the interface for all APK repository I/O operations.
// Implementations handle package fetching, index retrieval, and key discovery.
// The default implementation (DefaultClient) provides HTTP-based fetching with
// filesystem caching and in-memory request coalescing.
type Client interface {
	// GetPackage fetches and expands an APK package. The implementation handles
	// caching, request coalescing, and retry logic.
	GetPackage(ctx context.Context, pkg PackageInfo) (*expandapk.APKExpanded, error)

	// GetIndex fetches and parses an APKINDEX for the given repository and architecture.
	// The keys parameter contains trusted signing keys for signature verification.
	GetIndex(ctx context.Context, repoURL, arch string, keys map[string][]byte, opts ...IndexOption) (NamedIndex, error)

	// DiscoverKeys performs Chainguard-style key discovery for a repository.
	// Returns discovered keys or nil if the repository doesn't support discovery.
	DiscoverKeys(ctx context.Context, repoURL, arch string) (map[string][]byte, error)

	// GetKey fetches a signing key from the given URL.
	GetKey(ctx context.Context, keyURL string) ([]byte, error)

	// GetAlpineKeys fetches Alpine Linux signing keys for the given version and architecture.
	GetAlpineKeys(ctx context.Context, version, arch string) ([]Key, error)
}

// PackageInfo provides the information needed to fetch a package.
type PackageInfo interface {
	URL() string
	PackageName() string
	ChecksumString() string
}

// Key represents a signing key with its identifier and raw bytes.
type Key struct {
	ID    string
	Bytes []byte
}

// NamedIndex is an interface for a repository index with a name.
// This is defined here to avoid circular imports with the apk package.
type NamedIndex interface {
	Name() string
	Source() string
	Packages() []*RepositoryPackage
	Count() int
}

// RepositoryPackage is a placeholder for the package type from the apk package.
// The actual implementation will use the real type.
type RepositoryPackage = interface{}

// GetIndex fetches and parses an APKINDEX for the given repository and architecture.
// This is a stub implementation that will be completed in phase 2.
func (c *DefaultClient) GetIndex(ctx context.Context, repoURL, arch string, keys map[string][]byte, opts ...IndexOption) (NamedIndex, error) {
	// TODO: Implement in phase 2
	return nil, fmt.Errorf("GetIndex not yet implemented")
}

// DiscoverKeys performs Chainguard-style key discovery for a repository.
// This is a stub implementation that will be completed in phase 3.
func (c *DefaultClient) DiscoverKeys(ctx context.Context, repoURL, arch string) (map[string][]byte, error) {
	// TODO: Implement in phase 3
	return nil, nil
}

// GetKey fetches a signing key from the given URL.
// This is a stub implementation that will be completed in phase 3.
func (c *DefaultClient) GetKey(ctx context.Context, keyURL string) ([]byte, error) {
	// TODO: Implement in phase 3
	return nil, fmt.Errorf("GetKey not yet implemented")
}

// GetAlpineKeys fetches Alpine Linux signing keys for the given version and architecture.
// This is a stub implementation that will be completed in phase 3.
func (c *DefaultClient) GetAlpineKeys(ctx context.Context, version, arch string) ([]Key, error) {
	// TODO: Implement in phase 3
	return nil, nil
}

// IndexOption configures index fetching behavior.
type IndexOption func(*indexOpts)

type indexOpts struct {
	ignoreSignatures   bool
	noSignatureIndexes []string
}

// WithIgnoreSignatures configures whether to skip signature verification.
func WithIgnoreSignatures(ignore bool) IndexOption {
	return func(o *indexOpts) {
		o.ignoreSignatures = ignore
	}
}

// WithIgnoreSignatureForIndexes specifies indexes that should skip signature verification.
func WithIgnoreSignatureForIndexes(indexes ...string) IndexOption {
	return func(o *indexOpts) {
		o.noSignatureIndexes = append(o.noSignatureIndexes, indexes...)
	}
}

// DefaultClient is the standard implementation of Client that provides
// HTTP-based fetching with filesystem caching and in-memory request coalescing.
type DefaultClient struct {
	httpClient *http.Client
	cacheDir   string
	offline    bool
	auth       auth.Authenticator

	// In-memory caches for request coalescing
	packageFlight *flightCache[string, *expandapk.APKExpanded]
	indexFlight   *flightCache[string, NamedIndex]
	keysFlight    *flightCache[string, map[string][]byte]
}

// NewClient creates a new DefaultClient with the given options.
func NewClient(opts ...Option) *DefaultClient {
	o := &clientOpts{
		transport: cleanhttp.DefaultPooledTransport(),
		auth:      auth.DefaultAuthenticators,
	}

	for _, opt := range opts {
		opt(o)
	}

	return &DefaultClient{
		httpClient:    &http.Client{Transport: o.transport},
		cacheDir:      o.cacheDir,
		offline:       o.offline,
		auth:          o.auth,
		packageFlight: newFlightCache[string, *expandapk.APKExpanded](),
		indexFlight:   newFlightCache[string, NamedIndex](),
		keysFlight:    newFlightCache[string, map[string][]byte](),
	}
}

// flightCache coalesces concurrent requests and caches successful results.
// This replaces the global caches (globalApkCache, globalIndexCache, etc.)
// with instance-scoped caching.
type flightCache[K comparable, V any] struct {
	mux   sync.RWMutex
	cache map[K]func() (V, error)
}

func newFlightCache[K comparable, V any]() *flightCache[K, V] {
	return &flightCache[K, V]{
		cache: make(map[K]func() (V, error)),
	}
}

// Do returns coalesces multiple calls, like singleflight, but also caches
// the result if the call is successful. Failures are not cached to avoid
// permanently failing for transient errors.
func (f *flightCache[K, V]) Do(key K, fn func() (V, error)) (V, error) {
	f.mux.RLock()
	if v, ok := f.cache[key]; ok {
		f.mux.RUnlock()
		return v()
	}
	f.mux.RUnlock()

	f.mux.Lock()

	// Doubly-checked-locking in case of race conditions.
	if v, ok := f.cache[key]; ok {
		f.mux.Unlock()
		return v()
	}

	v := sync.OnceValues(fn)
	f.cache[key] = v

	// Unlock before calling the function to avoid holding the lock for a potentially long time.
	f.mux.Unlock()

	val, err := v()
	if err != nil {
		f.Forget(key)
	}
	return val, err
}

// Forget removes the given key from the cache.
func (f *flightCache[K, V]) Forget(key K) {
	f.mux.Lock()
	defer f.mux.Unlock()
	delete(f.cache, key)
}
