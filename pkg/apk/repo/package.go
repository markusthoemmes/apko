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
	"crypto/sha1" //nolint:gosec // this is what apk tools is using
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
	"go.lsp.dev/uri"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"chainguard.dev/apko/internal/tarfs"
	"chainguard.dev/apko/pkg/apk/expandapk"
	"chainguard.dev/apko/pkg/paths"
)

// GetPackage fetches and expands an APK package.
func (c *DefaultClient) GetPackage(ctx context.Context, pkg PackageInfo) (*expandapk.APKExpanded, error) {
	if c.cacheDir == "" {
		// If we don't have a cache configured, don't use request coalescing.
		// Calling APKExpanded.Close() will clean up a tempdir.
		return c.expandPackage(ctx, pkg)
	}

	cached := true
	val, err := c.packageFlight.Do(pkg.URL(), func() (*expandapk.APKExpanded, error) {
		cached = false
		return c.expandPackage(ctx, pkg)
	})
	if !cached {
		return val, err
	}
	if val != nil {
		// Check if the cached value is still valid (backing files exist)
		if !val.IsValid() {
			c.packageFlight.Forget(pkg.URL())
			return c.GetPackage(ctx, pkg)
		}
	}
	return val, err
}

func (c *DefaultClient) expandPackage(ctx context.Context, pkg PackageInfo) (*expandapk.APKExpanded, error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("go-apk").Start(ctx, "expandPackage", trace.WithAttributes(attribute.String("package", pkg.PackageName())))
	defer span.End()

	cacheDir := ""
	if c.cacheDir != "" {
		var err error
		cacheDir, err = c.cacheDirForPackage(pkg)
		if err != nil {
			return nil, err
		}

		exp, err := c.cachedPackage(ctx, pkg, cacheDir)
		if err == nil {
			log.Debugf("cache hit (%s)", pkg.PackageName())
			return exp, nil
		}

		log.Debugf("cache miss (%s): %v", pkg.PackageName(), err)

		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return nil, fmt.Errorf("unable to create cache directory %q: %w", cacheDir, err)
		}
	}

	rc, err := c.fetchPackage(ctx, pkg)
	if err != nil {
		return nil, fmt.Errorf("fetching package %q: %w", pkg.PackageName(), err)
	}
	defer rc.Close()

	exp, err := expandapk.ExpandApk(ctx, rc, cacheDir)
	if err != nil {
		return nil, fmt.Errorf("expanding %s: %w", pkg.PackageName(), err)
	}

	if c.cacheDir == "" {
		return exp, nil
	}

	return c.cachePackage(ctx, pkg, exp, cacheDir)
}

func (c *DefaultClient) fetchPackage(ctx context.Context, pkg PackageInfo) (io.ReadCloser, error) {
	log := clog.FromContext(ctx)
	log.Debugf("fetching %s", pkg.PackageName())

	ctx, span := otel.Tracer("go-apk").Start(ctx, "fetchPackage", trace.WithAttributes(attribute.String("package", pkg.PackageName())))
	defer span.End()

	u := pkg.URL()

	asURL, err := packageAsURL(u)
	if err != nil {
		return nil, fmt.Errorf("failed to parse package as URL: %w", err)
	}

	switch asURL.Scheme {
	case "file":
		f, err := os.Open(u)
		if err != nil {
			return nil, fmt.Errorf("failed to read repository package apk %s: %w", u, err)
		}
		return f, nil
	case "https", "http":
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		if err := c.auth.AddAuth(ctx, req); err != nil {
			return nil, err
		}

		rrt := newRangeRetryTransport(ctx, c.httpClient)
		res, err := rrt.RoundTrip(req)
		if err != nil {
			return nil, fmt.Errorf("unable to get package apk at %s: %w", u, err)
		}
		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			return nil, fmt.Errorf("unable to get package apk at %s: %v", u, res.Status)
		}
		return res.Body, nil
	default:
		return nil, fmt.Errorf("repository scheme %s not supported", asURL.Scheme)
	}
}

func (c *DefaultClient) cachedPackage(ctx context.Context, pkg PackageInfo, cacheDir string) (*expandapk.APKExpanded, error) {
	_, span := otel.Tracer("go-apk").Start(ctx, "cachedPackage", trace.WithAttributes(attribute.String("package", pkg.PackageName())))
	defer span.End()

	chk := pkg.ChecksumString()
	if !strings.HasPrefix(chk, "Q1") {
		return nil, fmt.Errorf("unexpected checksum: %q", chk)
	}

	checksum, err := base64.StdEncoding.DecodeString(chk[2:])
	if err != nil {
		return nil, err
	}

	pkgHexSum := hex.EncodeToString(checksum)

	exp := expandapk.APKExpanded{}

	ctl := filepath.Join(cacheDir, pkgHexSum+".ctl.tar.gz")
	cf, err := os.Stat(ctl)
	if err != nil {
		return nil, err
	}
	exp.ControlFile = ctl
	exp.ControlHash = checksum
	exp.ControlSize = cf.Size()

	control, err := exp.ControlData()
	if err != nil {
		return nil, err
	}

	exp.ControlFS, err = tarfs.New(bytes.NewReader(control), int64(len(control)))
	if err != nil {
		return nil, fmt.Errorf("indexing %q: %w", exp.ControlFile, err)
	}

	exp.Size += cf.Size()

	sig := filepath.Join(cacheDir, pkgHexSum+".sig.tar.gz")
	sf, err := os.Stat(sig)
	if err == nil {
		exp.SignatureFile = sig
		exp.Signed = true
		exp.Size += sf.Size()
		exp.SignatureSize = sf.Size()
		signatureData, err := os.ReadFile(sig)
		if err != nil {
			return nil, err
		}
		signatureHash := sha1.Sum(signatureData) //nolint:gosec // this is what apk tools is using
		exp.SignatureHash = signatureHash[:]
	}

	datahash, err := c.datahash(exp.ControlFS)
	if err != nil {
		return nil, fmt.Errorf("datahash for %s: %w", pkg.PackageName(), err)
	}

	dat := filepath.Join(cacheDir, datahash+".dat.tar.gz")
	df, err := os.Stat(dat)
	if err != nil {
		return nil, err
	}
	exp.PackageFile = dat
	exp.PackageSize = df.Size()
	exp.Size += df.Size()

	exp.PackageHash, err = hex.DecodeString(datahash)
	if err != nil {
		return nil, err
	}

	exp.TarFile = strings.TrimSuffix(exp.PackageFile, ".gz")
	data, err := exp.PackageData()
	if err != nil {
		return nil, err
	}
	info, err := data.Stat()
	if err != nil {
		return nil, err
	}
	exp.TarFS, err = tarfs.New(data, info.Size())
	if err != nil {
		return nil, err
	}

	return &exp, nil
}

func (c *DefaultClient) cachePackage(ctx context.Context, pkg PackageInfo, exp *expandapk.APKExpanded, cacheDir string) (*expandapk.APKExpanded, error) {
	_, span := otel.Tracer("go-apk").Start(ctx, "cachePackage", trace.WithAttributes(attribute.String("package", pkg.PackageName())))
	defer span.End()

	// Rename exp's temp files to content-addressable identifiers in the cache.
	ctlHex := hex.EncodeToString(exp.ControlHash)
	ctlDst := filepath.Join(cacheDir, ctlHex+".ctl.tar.gz")

	if err := paths.AdvertiseCachedFile(exp.ControlFile, ctlDst); err != nil {
		return nil, err
	}

	exp.ControlFile = ctlDst

	if exp.SignatureFile != "" {
		sigDst := filepath.Join(cacheDir, ctlHex+".sig.tar.gz")

		if err := paths.AdvertiseCachedFile(exp.SignatureFile, sigDst); err != nil {
			return nil, err
		}

		exp.SignatureFile = sigDst
	}

	datHex := hex.EncodeToString(exp.PackageHash)
	datDst := filepath.Join(cacheDir, datHex+".dat.tar.gz")

	if err := paths.AdvertiseCachedFile(exp.PackageFile, datDst); err != nil {
		return nil, err
	}

	exp.PackageFile = datDst

	if err := exp.TarFS.Close(); err != nil {
		return nil, fmt.Errorf("closing tarfs: %w", err)
	}

	tarDst := strings.TrimSuffix(exp.PackageFile, ".gz")

	if err := paths.AdvertiseCachedFile(exp.TarFile, tarDst); err != nil {
		return nil, err
	}

	exp.TarFile = tarDst

	// Re-initialize the tarfs with the renamed file.
	data, err := exp.PackageData()
	if err != nil {
		return nil, err
	}
	info, err := data.Stat()
	if err != nil {
		return nil, err
	}
	exp.TarFS, err = tarfs.New(data, info.Size())
	if err != nil {
		return nil, err
	}

	return exp, nil
}

func (c *DefaultClient) datahash(controlFS *tarfs.FS) (string, error) {
	mapping, err := controlValue(controlFS, "datahash")
	if err != nil {
		return "", fmt.Errorf("reading datahash from control: %w", err)
	}

	values, ok := mapping["datahash"]
	if !ok || len(values) != 1 {
		return "", fmt.Errorf("saw %d datahash values", len(values))
	}

	return values[0], nil
}

func (c *DefaultClient) cacheDirForPackage(pkg PackageInfo) (string, error) {
	asURL, err := packageAsURL(pkg.URL())
	if err != nil {
		return "", err
	}

	p, err := cachePathFromURL(c.cacheDir, *asURL)
	if err != nil {
		return "", err
	}

	if ext := filepath.Ext(p); ext != ".apk" {
		return "", fmt.Errorf("unexpected ext (%s) to cache dir: %q", ext, p)
	}

	return strings.TrimSuffix(p, ".apk"), nil
}

// Helper functions

func packageAsURI(u string) (uri.URI, error) {
	if strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://") {
		return uri.Parse(u)
	}
	return uri.New(u), nil
}

func packageAsURL(u string) (*url.URL, error) {
	asURI, err := packageAsURI(u)
	if err != nil {
		return nil, err
	}
	return url.Parse(string(asURI))
}

func cachePathFromURL(root string, u url.URL) (string, error) {
	u2 := u
	u2.ForceQuery = false
	u2.RawFragment = ""
	u2.RawQuery = ""
	filename := filepath.Base(u2.Path)
	archDir := filepath.Dir(u2.Path)
	dir := filepath.Base(archDir)
	repoDir := filepath.Dir(archDir)
	u2.Path = repoDir

	repoDir = url.QueryEscape(u2.String())
	cacheFile := filepath.Join(root, repoDir, dir, filename)
	cacheFile = filepath.Clean(cacheFile)
	cleanroot := filepath.Clean(root)
	if !strings.HasPrefix(cacheFile, cleanroot) {
		return "", fmt.Errorf("cache file %s is not within root %s", cacheFile, cleanroot)
	}
	return cacheFile, nil
}
