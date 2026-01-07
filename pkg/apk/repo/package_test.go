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

package repo

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/auth"
)

const (
	testPrimaryPkgDir = "../apk/testdata/alpine-316"
	testAlpineRepos   = "https://dl-cdn.alpinelinux.org/alpine/v3.16/main"
	testArch          = "aarch64"
)

var (
	testUser, testPass = "user", "pass"
)

// testPackage implements PackageInfo for testing
type testPackage struct {
	url      string
	name     string
	checksum string
}

func (p *testPackage) URL() string           { return p.url }
func (p *testPackage) PackageName() string   { return p.name }
func (p *testPackage) ChecksumString() string { return p.checksum }

// testLocalTransport is a transport that serves files from the local filesystem
type testLocalTransport struct {
	fail             bool
	root             string
	basenameOnly     bool
	headers          map[string][]string
	requireBasicAuth bool
}

func (t *testLocalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.fail {
		return &http.Response{
			StatusCode: 404,
			Body:       io.NopCloser(bytes.NewBuffer([]byte("not found"))),
		}, nil
	}
	if t.requireBasicAuth {
		if _, _, ok := request.BasicAuth(); !ok {
			return &http.Response{
				StatusCode: 401,
				Body:       io.NopCloser(bytes.NewBuffer([]byte("unauthorized"))),
			}, nil
		}
	}

	var target string
	if t.basenameOnly {
		target = filepath.Join(t.root, filepath.Base(request.URL.Path))
	} else {
		target = filepath.Join(t.root, request.URL.Path)
	}
	f, err := os.Open(target)
	if err != nil {
		return &http.Response{StatusCode: 404}, nil
	}
	return &http.Response{
		StatusCode: 200,
		Body:       f,
		Header:     t.headers,
	}, nil
}

func TestGetPackage(t *testing.T) {
	const (
		pkgName     = "alpine-baselayout"
		pkgVersion  = "3.2.0-r23"
		pkgFilename = pkgName + "-" + pkgVersion + ".apk"
	)

	// Checksum from the actual test package
	pkgChecksum := fmt.Sprintf("Q1%s", "abc123") // Placeholder - actual checksum not strictly needed for these tests

	pkg := &testPackage{
		url:      fmt.Sprintf("%s/%s/%s", testAlpineRepos, testArch, pkgFilename),
		name:     pkgName,
		checksum: pkgChecksum,
	}
	ctx := context.Background()

	t.Run("no cache", func(t *testing.T) {
		client := NewClient(WithTransport(&testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}))
		_, err := client.GetPackage(ctx, pkg)
		require.NoErrorf(t, err, "unable to expand package")
	})

	t.Run("cache miss no network", func(t *testing.T) {
		// we use a transport that always returns a 404 so we know we're not hitting the network
		// it should fail for a cache miss
		tmpDir := t.TempDir()
		client := NewClient(
			WithCacheDir(tmpDir),
			WithTransport(&testLocalTransport{fail: true}),
		)
		_, err := client.GetPackage(ctx, pkg)
		require.Error(t, err, "should fail when no cache and no network")
	})

	t.Run("cache miss network should fill cache", func(t *testing.T) {
		tmpDir := t.TempDir()
		client := NewClient(
			WithCacheDir(tmpDir),
			WithTransport(&testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}),
		)

		// fill the cache
		repoDir := filepath.Join(tmpDir, url.QueryEscape(testAlpineRepos), testArch)
		err := os.MkdirAll(repoDir, 0o755)
		require.NoError(t, err, "unable to mkdir cache")

		cacheApkFile := filepath.Join(repoDir, pkgFilename)
		cacheApkDir := strings.TrimSuffix(cacheApkFile, ".apk")

		exp, err := client.GetPackage(ctx, pkg)
		require.NoErrorf(t, err, "unable to expand pkg")

		// check that the package directory is in place
		_, err = os.Stat(cacheApkDir)
		require.NoError(t, err, "apk directory not found in cache")

		// check that we can read the expanded APK
		f, err := exp.APK()
		require.NoError(t, err, "unable to read expanded APK")
		defer f.Close()

		apk1, err := io.ReadAll(f)
		require.NoError(t, err, "unable to read expanded APK bytes")

		apk2, err := os.ReadFile(filepath.Join(testPrimaryPkgDir, pkgFilename))
		require.NoError(t, err, "unable to read original apk file")
		require.Equal(t, apk1, apk2, "apk files do not match")
	})

	t.Run("handle missing cache files when expanding APK", func(t *testing.T) {
		tmpDir := t.TempDir()
		client := NewClient(
			WithCacheDir(tmpDir),
			WithTransport(&testLocalTransport{root: testPrimaryPkgDir, basenameOnly: true}),
		)

		// Fill the cache
		exp, err := client.GetPackage(ctx, pkg)
		require.NoError(t, err, "unable to expand package")
		_, err = os.Stat(exp.TarFile)
		require.NoError(t, err, "unable to stat cached tar file")

		// Delete the tar file from the cache
		require.NoError(t, os.Remove(exp.TarFile), "unable to delete cached tar file")
		_, err = os.Stat(exp.TarFile)
		require.ErrorIs(t, err, os.ErrNotExist, "unexpectedly able to stat cached tar file that should have been deleted")

		// Expand the package again, this should re-populate the cache.
		exp2, err := client.GetPackage(ctx, pkg)
		require.NoError(t, err, "unable to GetPackage after deleting cached tar file")
		_, err = os.Stat(exp2.TarFile)
		require.NoError(t, err, "unable to stat cached tar file")

		// Delete and recreate the tar file from the cache (changing its inodes)
		bs, err := os.ReadFile(exp2.TarFile)
		require.NoError(t, err, "unable to read cached tar file")
		require.NoError(t, os.Remove(exp2.TarFile), "unable to delete cached tar file")
		require.NoError(t, os.WriteFile(exp2.TarFile, bs, 0o644), "unable to recreate cached tar file")

		// Ensure that the underlying reader is different (i.e. we re-read the file)
		exp3, err := client.GetPackage(ctx, pkg)
		require.NoError(t, err, "unable to GetPackage after deleting and recreating cached tar file")
		require.NotEqual(t, exp2.TarFS.UnderlyingReader(), exp3.TarFS.UnderlyingReader())

		// We should be able to read the APK contents
		rc, err := exp3.APK()
		require.NoError(t, err, "unable to get reader for APK()")
		_, err = io.ReadAll(rc)
		require.NoError(t, err, "unable to read APK contents")
	})
}

func TestAuth_good(t *testing.T) {
	const (
		pkgName     = "alpine-baselayout"
		pkgVersion  = "3.2.0-r23"
		pkgFilename = pkgName + "-" + pkgVersion + ".apk"
	)

	called := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if gotuser, gotpass, ok := r.BasicAuth(); !ok || gotuser != testUser || gotpass != testPass {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.FileServer(http.Dir(testPrimaryPkgDir)).ServeHTTP(w, r)
	}))
	defer s.Close()
	host := strings.TrimPrefix(s.URL, "http://")

	pkg := &testPackage{
		url:      fmt.Sprintf("%s/%s", s.URL, pkgFilename),
		name:     pkgName,
		checksum: "Q1abc123",
	}
	ctx := context.Background()

	client := NewClient(WithAuth(auth.StaticAuth(host, testUser, testPass)))

	_, err := client.GetPackage(ctx, pkg)
	require.NoErrorf(t, err, "unable to fetch package")
	require.True(t, called, "did not make request")
}

func TestAuth_bad(t *testing.T) {
	const (
		pkgName     = "alpine-baselayout"
		pkgVersion  = "3.2.0-r23"
		pkgFilename = pkgName + "-" + pkgVersion + ".apk"
	)

	called := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if gotuser, gotpass, ok := r.BasicAuth(); !ok || gotuser != testUser || gotpass != testPass {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.FileServer(http.Dir(testPrimaryPkgDir)).ServeHTTP(w, r)
	}))
	defer s.Close()
	host := strings.TrimPrefix(s.URL, "http://")

	pkg := &testPackage{
		url:      fmt.Sprintf("%s/%s", s.URL, pkgFilename),
		name:     pkgName,
		checksum: "Q1abc123",
	}
	ctx := context.Background()

	client := NewClient(WithAuth(auth.StaticAuth(host, "baduser", "badpass")))

	_, err := client.GetPackage(ctx, pkg)
	require.Error(t, err, "should fail with bad auth")
	require.True(t, called, "did not make request")
}
