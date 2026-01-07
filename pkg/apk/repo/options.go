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
	"net/http"
	"os"
	"path/filepath"

	"chainguard.dev/apko/pkg/apk/auth"
)

// clientOpts holds the configuration for a DefaultClient.
type clientOpts struct {
	cacheDir  string
	offline   bool
	auth      auth.Authenticator
	transport http.RoundTripper
}

// Option configures a DefaultClient.
type Option func(*clientOpts)

// WithCacheDir sets the directory for caching downloaded packages and indexes.
// If empty, a default cache directory will be used.
func WithCacheDir(dir string) Option {
	return func(o *clientOpts) {
		if dir == "" {
			cacheDir, err := os.UserCacheDir()
			if err != nil {
				return
			}
			dir = filepath.Join(cacheDir, "dev.chainguard.go-apk")
		} else {
			absDir, err := filepath.Abs(dir)
			if err != nil {
				return
			}
			dir = absDir
		}
		o.cacheDir = dir
	}
}

// WithOffline configures the client to only use cached data and not make
// network requests.
func WithOffline(offline bool) Option {
	return func(o *clientOpts) {
		o.offline = offline
	}
}

// WithAuth sets the authenticator for adding authentication to HTTP requests.
func WithAuth(a auth.Authenticator) Option {
	return func(o *clientOpts) {
		if a != nil {
			o.auth = a
		}
	}
}

// WithTransport sets the HTTP transport for the client.
func WithTransport(t http.RoundTripper) Option {
	return func(o *clientOpts) {
		if t != nil {
			o.transport = t
		}
	}
}
