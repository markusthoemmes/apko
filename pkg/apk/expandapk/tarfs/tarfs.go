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

package tarfs

import (
	"archive/tar"
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"sync"
	"time"
)

const seekableBufSize = 1 << 20

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, seekableBufSize)
		return &b
	},
}

type Entry struct {
	Header tar.Header
	Offset int64

	dir string
	fi  fs.FileInfo
}

func (e Entry) Name() string {
	return e.fi.Name()
}

func (e Entry) Size() int64 {
	return e.Header.Size
}

func (e Entry) Type() fs.FileMode {
	return e.fi.Mode()
}

func (e Entry) Info() (fs.FileInfo, error) {
	return e.fi, nil
}

func (e Entry) IsDir() bool {
	return e.fi.IsDir()
}

type File struct {
	fsys  *FS
	sr    *io.SectionReader
	Entry *Entry
}

func (f *File) Stat() (fs.FileInfo, error) {
	return f.Entry.fi, nil
}

func (f *File) Read(p []byte) (int, error) {
	return f.sr.Read(p)
}

func (f *File) Seek(offset int64, whence int) (int64, error) {
	return f.sr.Seek(offset, whence)
}

func (f *File) ReadAt(p []byte, off int64) (int, error) {
	return f.sr.ReadAt(p, off)
}

func (f *File) Close() error {
	return nil
}

type FS struct {
	ra    io.ReaderAt
	files []*Entry
	index map[string]int
	dirs  map[string][]fs.DirEntry
}

func (fsys *FS) Readlink(name string) (string, error) {
	i, ok := fsys.index[name]
	if !ok {
		return "", fs.ErrNotExist
	}

	e := fsys.files[i]

	switch e.Header.Typeflag {
	case tar.TypeSymlink, tar.TypeLink:
		return e.Header.Linkname, nil
	}

	return "", fmt.Errorf("Readlink(%q): file is not a link", name)
}

const maxHops = 64

// open follows symlinks up to [maxHops] times.
func (fsys *FS) open(name string, hops int) (fs.File, error) {
	if hops > maxHops {
		return nil, fmt.Errorf("Open(%q): chased too many (%d) symlinks", name, maxHops)
	}

	i, ok := fsys.index[name]
	if !ok {
		return nil, fs.ErrNotExist
	}

	e := fsys.files[i]

	switch e.Header.Typeflag {
	case tar.TypeSymlink, tar.TypeLink:
		link := e.Header.Linkname
		if path.IsAbs(link) {
			return fsys.open(link, hops+1)
		}

		return fsys.open(path.Join(e.dir, link), hops+1)
	}

	f := &File{
		fsys:  fsys,
		Entry: e,
	}

	f.sr = io.NewSectionReader(fsys.ra, e.Offset, e.Header.Size)

	return f, nil
}

// Open implements fs.FS.
func (fsys *FS) Open(name string) (fs.File, error) {
	return fsys.open(name, 0)
}

func (fsys *FS) Entries() []*Entry {
	return fsys.files
}

type root struct{}

func (r root) Name() string       { return "." }
func (r root) Size() int64        { return 0 }
func (r root) Mode() fs.FileMode  { return fs.ModeDir }
func (r root) ModTime() time.Time { return time.Unix(0, 0) }
func (r root) IsDir() bool        { return true }
func (r root) Sys() any           { return nil }

func (fsys *FS) Stat(name string) (fs.FileInfo, error) {
	if i, ok := fsys.index[name]; ok {
		return fsys.files[i].fi, nil
	}

	// fs.WalkDir expects "." to return a root entry to bootstrap the walk.
	// If we didn't find it above, synthesize one.
	if name == "." {
		return root{}, nil
	}

	return nil, fs.ErrNotExist
}

func (fsys *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	dirs, ok := fsys.dirs[name]
	if !ok {
		return []fs.DirEntry{}, nil
	}

	return dirs, nil
}

// seekableBuf is a buffered, seekable reader over an io.ReaderAt. Unlike
// bufio.Reader it implements io.Seeker, which lets tar.Reader.Next() skip
// past entry bodies and padding instead of discard-reading them. Buffering
// is still important: some callers are backed by gcsfuse, where each raw
// read is a GCS API call.
type seekableBuf struct {
	ra      io.ReaderAt
	size    int64
	pos     int64 // logical offset in the underlying stream
	buf     []byte
	bufBase int64 // underlying offset at buf[0]
	bufLen  int   // valid bytes in buf
	bufOff  int   // current read offset within buf
}

func newSeekableBuf(ra io.ReaderAt, size int64) *seekableBuf {
	bp := bufPool.Get().(*[]byte)
	return &seekableBuf{
		ra:   ra,
		size: size,
		buf:  *bp,
	}
}

func (s *seekableBuf) release() {
	if s.buf == nil {
		return
	}
	b := s.buf
	s.buf = nil
	bp := &b
	bufPool.Put(bp)
}

func (s *seekableBuf) Read(p []byte) (int, error) {
	if s.bufOff >= s.bufLen {
		if s.pos >= s.size {
			return 0, io.EOF
		}
		want := int64(len(s.buf))
		if remaining := s.size - s.pos; remaining < want {
			want = remaining
		}
		n, err := s.ra.ReadAt(s.buf[:want], s.pos)
		if n == 0 {
			if err == nil {
				err = io.EOF
			}
			return 0, err
		}
		s.bufBase = s.pos
		s.bufLen = n
		s.bufOff = 0
		// A non-nil err with n > 0 (e.g. io.EOF from ReadAt on a short
		// final chunk) is fine; surface it on the next refill.
	}
	n := copy(p, s.buf[s.bufOff:s.bufLen])
	s.bufOff += n
	s.pos += int64(n)
	return n, nil
}

func (s *seekableBuf) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = s.pos + offset
	case io.SeekEnd:
		abs = s.size + offset
	default:
		return 0, errors.New("seekableBuf: invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("seekableBuf: negative position")
	}
	// Fast path: target is still within the current buffer window.
	if s.bufLen > 0 && abs >= s.bufBase && abs < s.bufBase+int64(s.bufLen) {
		s.bufOff = int(abs - s.bufBase)
	} else {
		s.bufOff = 0
		s.bufLen = 0
		s.bufBase = abs
	}
	s.pos = abs
	return abs, nil
}

func New(ra io.ReaderAt, size int64) (*FS, error) {
	fsys := &FS{
		ra:    ra,
		files: []*Entry{},
		index: map[string]int{},
		dirs:  map[string][]fs.DirEntry{},
	}

	// Number of entries in a given directory, so we know how large of a slice to allocate.
	dirCount := map[string]int{}

	// TODO: Consider caching this across builds.
	sb := newSeekableBuf(ra, size)
	defer sb.release()

	tr := tar.NewReader(sb)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		// After Next() returns, the reader is positioned at the start
		// of this entry's body. tar.Reader uses our Seek to skip the
		// previous entry's body+padding instead of discard-reading it.
		off, err := sb.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, err
		}
		// Seek-skip bypasses actually reading the body, so a header
		// claiming a body bigger than the archive would otherwise slip
		// through indexing and only fail on a later Open+Read. Reject
		// it here so we mirror the old pipeline's implicit bounds check.
		if off < 0 || hdr.Size < 0 || off > size || hdr.Size > size-off {
			return nil, fmt.Errorf("tarfs: entry %q extends past end of archive: offset=%d size=%d archive=%d", hdr.Name, off, hdr.Size, size)
		}
		dir := path.Dir(hdr.Name)
		fsys.index[hdr.Name] = len(fsys.files)
		fsys.files = append(fsys.files, &Entry{
			Header: *hdr,
			Offset: off,
			dir:    dir,
			fi:     hdr.FileInfo(),
		})

		dirCount[dir]++
	}

	// Pre-generate the results of ReadDir so we don't allocate a ton if fs.WalkDir calls us.
	// TODO: Consider doing this lazily in a sync.Once the first time we see a ReadDir.
	for dir, count := range dirCount {
		fsys.dirs[dir] = make([]fs.DirEntry, 0, count)
	}

	for _, f := range fsys.files {
		fsys.dirs[f.dir] = append(fsys.dirs[f.dir], f)
	}

	for _, files := range fsys.dirs {
		slices.SortFunc(files, func(a, b fs.DirEntry) int {
			return cmp.Compare(a.Name(), b.Name())
		})
	}

	return fsys, nil
}

func (fsys *FS) UnderlyingReader() io.ReaderAt {
	return fsys.ra
}

func (fsys *FS) Close() error {
	if fsys == nil {
		return nil
	}

	closer, ok := fsys.ra.(io.Closer)
	if !ok {
		return nil
	}

	return closer.Close()
}
