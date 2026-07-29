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

// indexFragment is the resolution data derived from a single index: its
// packages bucketed by principal name and by provided name, install_if
// reverse mappings, and a name→version set for cross-arch disqualification.
//
// A fragment references only its own index, so caching it on the index
// object gives it exactly the index's lifetime. PkgResolver composes
// fragments per lookup instead of merging them, so no combination-level
// state exists anywhere.
type indexFragment struct {
	byName     map[string][]*repositoryPackage
	byProvides map[string][]*repositoryPackage
	installIf  map[string][]*repositoryPackage
	versions   map[nameVersion]struct{}
}

type nameVersion struct {
	name    string
	version string
}

func buildFragment(index NamedIndex) *indexFragment {
	pkgs := index.Packages()
	f := &indexFragment{
		byName:     make(map[string][]*repositoryPackage, len(pkgs)),
		byProvides: map[string][]*repositoryPackage{},
		installIf:  map[string][]*repositoryPackage{},
		versions:   make(map[nameVersion]struct{}, len(pkgs)),
	}
	pinnedName := index.Name()
	for _, pkg := range pkgs {
		rp := &repositoryPackage{RepositoryPackage: pkg, pinnedName: pinnedName}
		f.byName[pkg.Name] = append(f.byName[pkg.Name], rp)
		for _, dep := range pkg.InstallIf {
			f.installIf[dep] = append(f.installIf[dep], rp)
		}
		for _, provide := range pkg.Provides {
			name := cachedResolvePackageNameVersionPin(provide).Name
			f.byProvides[name] = append(f.byProvides[name], rp)
		}
		f.versions[nameVersion{pkg.Name, pkg.Version}] = struct{}{}
	}
	return f
}

// fragmentOf returns the index's cached fragment. Indexes provided by other
// NamedIndex implementations get an uncached fragment built per resolver.
func fragmentOf(index NamedIndex) *indexFragment {
	if n, ok := index.(*namedRepositoryWithIndex); ok {
		return n.fragment()
	}
	return buildFragment(index)
}
