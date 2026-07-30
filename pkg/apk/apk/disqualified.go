// Copyright 2026 Chainguard, Inc.
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

package apk

import (
	"errors"
	"fmt"
)

// disqualified tracks the packages ruled out during one resolution: the
// reasons accumulated as packages are excluded, plus the per-architecture
// index data packages must be available in, checked lazily with hits
// memoized as reasons.
type disqualified struct {
	reasons map[*RepositoryPackage]string
	byArch  map[string][]*indexFragment
}

// dqed reports whether pkg is disqualified, consulting the accumulated
// reasons first and the cross-arch availability check second. Check hits are
// memoized so their reasons are available for error reporting.
func (d *disqualified) dqed(pkg *RepositoryPackage) bool {
	if _, ok := d.reasons[pkg]; ok {
		return true
	}
	if reason := d.unavailable(pkg); reason != "" {
		d.reasons[pkg] = reason
		return true
	}
	return false
}

// disqualify records why pkg cannot be used.
func (d *disqualified) disqualify(pkg *RepositoryPackage, reason string) {
	d.reasons[pkg] = reason

	// TODO: Ripple up and disqualify anything that is no longer solvable.
}

type DisqualifiedError struct {
	Package *RepositoryPackage
	Wrapped error
}

func (e *DisqualifiedError) Error() string {
	return fmt.Sprintf("  %s disqualified because %s", e.Package.Filename(), e.Wrapped.Error())
}

func (e *DisqualifiedError) Unwrap() error {
	return e.Wrapped
}

func maybedqerror(pkgs []*repositoryPackage, dq *disqualified) error {
	errs := make([]error, 0, len(pkgs))
	for _, pkg := range pkgs {
		reason, ok := dq.reasons[pkg.RepositoryPackage]
		if ok {
			errs = append(errs, &DisqualifiedError{pkg.RepositoryPackage, errors.New(reason)})
		}
	}

	if len(errs) != 0 {
		return errors.Join(errs...)
	}

	return errors.New("not in indexes")
}

// unavailable reports why pkg cannot be used across all architectures of
// this resolution, or "" if it can. A package is usable if some index of
// every architecture carries its name and version. An architecture requested
// with zero indexes carries nothing, so it disqualifies every package.
//
// Only packages originating from byArch's own index objects are checked.
// The eager implementation this replaces keyed disqualification by package
// pointer, so packages from index objects outside byArch (e.g. a different
// generation of the same index, fetched moments earlier) were never
// disqualified — notably a candidate was never disqualified against its own
// architecture by a newer generation. Preserve that.
func (d *disqualified) unavailable(pkg *RepositoryPackage) string {
	if len(d.byArch) == 0 {
		return ""
	}

	fromByArch := false
	for _, frags := range d.byArch {
		if carries(frags, pkg) {
			fromByArch = true
			break
		}
	}
	if !fromByArch {
		return ""
	}

	nv := nameVersion{pkg.Name, pkg.Version}
	for arch, frags := range d.byArch {
		if !available(frags, nv) {
			return fmt.Sprintf("package %q not available for arch %q", pkg.Filename(), arch)
		}
	}
	return ""
}

// carries reports whether pkg originates from one of frags' indexes.
func carries(frags []*indexFragment, pkg *RepositoryPackage) bool {
	for _, f := range frags {
		for _, rp := range f.byName[pkg.Name] {
			if rp.RepositoryPackage == pkg {
				return true
			}
		}
	}
	return false
}

// available reports whether some index behind frags carries nv.
func available(frags []*indexFragment, nv nameVersion) bool {
	for _, f := range frags {
		if _, ok := f.versions[nv]; ok {
			return true
		}
	}
	return false
}

// fragmentsByArch resolves byArch's indexes to their fragments, or nil for a
// single architecture: there is no difference between archs if we have one.
func fragmentsByArch(byArch map[string][]NamedIndex) map[string][]*indexFragment {
	if len(byArch) <= 1 {
		return nil
	}

	fragments := make(map[string][]*indexFragment, len(byArch))
	for arch, indexes := range byArch {
		frags := make([]*indexFragment, 0, len(indexes))
		for _, index := range indexes {
			frags = append(frags, fragmentOf(index))
		}
		fragments[arch] = frags
	}
	return fragments
}
