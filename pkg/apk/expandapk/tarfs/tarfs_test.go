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

package tarfs

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
)

// countingReaderAt wraps a bytes.Reader and counts the total number of
// bytes requested via ReadAt. Used to verify that indexing no longer
// reads through entry bodies.
type countingReaderAt struct {
	ra    io.ReaderAt
	bytes int64
	calls int64
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	atomic.AddInt64(&c.calls, 1)
	n, err := c.ra.ReadAt(p, off)
	atomic.AddInt64(&c.bytes, int64(n))
	return n, err
}

type fixtureEntry struct {
	name     string
	typeflag byte
	body     []byte
	linkname string
	mode     int64
}

// buildTar writes a tar archive exercising the cases that matter for
// offset correctness: bodies not aligned to 512, zero-length files,
// symlinks, directories, and long names that force PAX records.
func buildTar(t *testing.T, entries []fixtureEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Mode:     e.mode,
			Size:     int64(len(e.body)),
			Linkname: e.linkname,
			Format:   tar.FormatPAX,
		}
		if e.typeflag == tar.TypeDir || e.typeflag == tar.TypeSymlink {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader %q: %v", e.name, err)
		}
		if hdr.Size > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("Write %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tw.Close: %v", err)
	}
	return buf.Bytes()
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

func fixtureEntries(t *testing.T) []fixtureEntry {
	t.Helper()
	return []fixtureEntry{
		{name: "dir/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "empty", typeflag: tar.TypeReg, body: nil, mode: 0o644},
		{name: "small", typeflag: tar.TypeReg, body: []byte("hello"), mode: 0o644},
		// 511 bytes: maximum non-aligned that still fits a single block with padding.
		{name: "unaligned-short", typeflag: tar.TypeReg, body: randBytes(t, 511), mode: 0o644},
		// Larger non-aligned body — forces multiple 512 blocks + padding.
		{name: "unaligned-long", typeflag: tar.TypeReg, body: randBytes(t, 4097), mode: 0o644},
		// Exactly-aligned body (no padding).
		{name: "aligned", typeflag: tar.TypeReg, body: randBytes(t, 2048), mode: 0o644},
		// Long name forces PAX "x" record before the real header; exercises
		// the path where tar.Reader consumes an extension-header body
		// between headers.
		{name: strings.Repeat("a", 200) + "/longname", typeflag: tar.TypeReg, body: []byte("paxbody"), mode: 0o644},
		{name: "link", typeflag: tar.TypeSymlink, linkname: "small", mode: 0o777},
		// Body large enough to be interesting for a big buffer window.
		{name: "big", typeflag: tar.TypeReg, body: randBytes(t, 1<<15), mode: 0o644},
	}
}

func TestNewOffsetsPointAtBodies(t *testing.T) {
	entries := fixtureEntries(t)
	raw := buildTar(t, entries)

	fsys, err := New(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	byName := map[string]fixtureEntry{}
	for _, e := range entries {
		byName[e.name] = e
	}

	for _, entry := range fsys.Entries() {
		want := byName[entry.Header.Name]
		if want.typeflag == tar.TypeDir || want.typeflag == tar.TypeSymlink {
			if entry.Header.Size != 0 {
				t.Errorf("%s: expected Size 0, got %d", entry.Header.Name, entry.Header.Size)
			}
			continue
		}
		got := make([]byte, len(want.body))
		if len(want.body) > 0 {
			n, err := bytes.NewReader(raw).ReadAt(got, entry.Offset)
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("%s: ReadAt(%d, %d): %v", entry.Header.Name, entry.Offset, len(want.body), err)
			}
			if n != len(want.body) {
				t.Fatalf("%s: short ReadAt: got %d want %d", entry.Header.Name, n, len(want.body))
			}
		}
		if !bytes.Equal(got, want.body) {
			t.Errorf("%s: body at offset %d does not match", entry.Header.Name, entry.Offset)
		}
	}
}

func TestNewOpenReadsCorrectBodies(t *testing.T) {
	entries := fixtureEntries(t)
	raw := buildTar(t, entries)

	fsys, err := New(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, e := range entries {
		if e.typeflag != tar.TypeReg {
			continue
		}
		f, err := fsys.Open(e.name)
		if err != nil {
			t.Fatalf("Open(%q): %v", e.name, err)
		}
		got, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			t.Fatalf("ReadAll(%q): %v", e.name, err)
		}
		if !bytes.Equal(got, e.body) {
			t.Errorf("Open(%q): body mismatch", e.name)
		}
	}
}

func TestNewSkipsLargeEntryBodies(t *testing.T) {
	// Large entries let the Seek-skip path show real IO savings: a
	// Seek well past the current buffer window causes the next refill
	// to start at the Seek target, skipping megabytes of body bytes.
	// This test asserts that indexing such a tar reads substantially
	// less than the full file size.
	const nEntries = 4
	const bodySize = 8 * 1024 * 1024 // 8 MiB — much larger than the buffer.

	entries := make([]fixtureEntry, 0, nEntries)
	for i := range nEntries {
		entries = append(entries, fixtureEntry{
			name:     fmt.Sprintf("big-%02d", i),
			typeflag: tar.TypeReg,
			body:     make([]byte, bodySize),
			mode:     0o644,
		})
	}
	raw := buildTar(t, entries)

	cra := &countingReaderAt{ra: bytes.NewReader(raw)}
	fsys, err := New(cra, int64(len(raw)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := len(fsys.Entries()); got != nEntries {
		t.Fatalf("entries: got %d want %d", got, nEntries)
	}

	totalSize := int64(len(raw))
	readBytes := atomic.LoadInt64(&cra.bytes)

	// We need at least one refill per entry to read its header, but
	// should read far less than the full file — bodies are skipped.
	if readBytes >= totalSize {
		t.Fatalf("indexing read %d bytes of a %d-byte tar; bodies were not skipped", readBytes, totalSize)
	}
	// Each header refill is at most one buffer window. For 4 entries
	// with 8 MiB bodies, a correct seek-skip implementation reads at
	// most ~4 * seekableBufSize = 4 MiB. Be a bit generous.
	if max := int64(nEntries+2) * int64(seekableBufSize); readBytes > max {
		t.Fatalf("indexing read %d bytes; expected at most %d for %d headers with skipping", readBytes, max, nEntries)
	}
	t.Logf("indexed %d big entries in a %d-byte tar with %d bytes read (%d calls)", nEntries, totalSize, readBytes, cra.calls)
}

func TestNewSmallEntriesReadsSimilarToFileSize(t *testing.T) {
	// Small entries don't benefit much from Seek-skip (the buffer
	// pulls bodies in as a side effect of reading headers) — but the
	// pipeline should still be correct. This test just asserts it
	// doesn't blow up and the read volume stays sane (at most a
	// small margin above the file size).
	const nEntries = 64
	const bodySize = 128 * 1024

	entries := make([]fixtureEntry, 0, nEntries)
	for i := range nEntries {
		entries = append(entries, fixtureEntry{
			name:     fmt.Sprintf("f%04d", i),
			typeflag: tar.TypeReg,
			body:     make([]byte, bodySize),
			mode:     0o644,
		})
	}
	raw := buildTar(t, entries)

	cra := &countingReaderAt{ra: bytes.NewReader(raw)}
	if _, err := New(cra, int64(len(raw))); err != nil {
		t.Fatalf("New: %v", err)
	}

	totalSize := int64(len(raw))
	readBytes := atomic.LoadInt64(&cra.bytes)
	if readBytes > totalSize+int64(seekableBufSize) {
		t.Fatalf("indexing read %d bytes of a %d-byte tar; excessive overhead", readBytes, totalSize)
	}
	t.Logf("indexed %d small entries in a %d-byte tar with %d bytes read (%d calls)", nEntries, totalSize, readBytes, cra.calls)
}

func TestNewRejectsTruncatedArchive(t *testing.T) {
	// Build a valid tar with one big entry, then lie about its length
	// by passing a size shorter than the actual archive. The old
	// pipeline would have caught this via a short-read during the
	// body discard; the Seek-skip path needs an explicit bounds check.
	entries := []fixtureEntry{
		{name: "big", typeflag: tar.TypeReg, body: make([]byte, 1<<20), mode: 0o644},
	}
	raw := buildTar(t, entries)

	// Pretend the archive ends midway through the body. The header
	// reads fine; the body claim extends past our size.
	truncated := int64(len(raw)) / 2
	_, err := New(bytes.NewReader(raw), truncated)
	if err == nil {
		t.Fatal("expected New to reject a truncated archive; got nil error")
	}
	if !strings.Contains(err.Error(), "extends past end of archive") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSeekableBufSeekWithinWindowNoRefill(t *testing.T) {
	raw := randBytes(t, seekableBufSize*2)
	cra := &countingReaderAt{ra: bytes.NewReader(raw)}
	sb := newSeekableBuf(cra, int64(len(raw)))
	defer sb.release()

	// Prime the first window.
	p := make([]byte, 100)
	if _, err := io.ReadFull(sb, p); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if atomic.LoadInt64(&cra.calls) != 1 {
		t.Fatalf("expected 1 ReadAt after priming, got %d", cra.calls)
	}

	// Seek forward inside the window; should not refill.
	if _, err := sb.Seek(500, io.SeekStart); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	if _, err := io.ReadFull(sb, p); err != nil {
		t.Fatalf("ReadFull after Seek: %v", err)
	}
	if got := atomic.LoadInt64(&cra.calls); got != 1 {
		t.Fatalf("in-window seek triggered refill: calls=%d", got)
	}
	// Bytes should match raw[500:600].
	if !bytes.Equal(p, raw[500:600]) {
		t.Fatalf("content mismatch after in-window seek")
	}

	// Seek outside the window; next Read should refill.
	if _, err := sb.Seek(seekableBufSize+200, io.SeekStart); err != nil {
		t.Fatalf("Seek outside: %v", err)
	}
	if _, err := io.ReadFull(sb, p); err != nil {
		t.Fatalf("ReadFull after out-of-window Seek: %v", err)
	}
	if got := atomic.LoadInt64(&cra.calls); got != 2 {
		t.Fatalf("out-of-window seek should have triggered exactly one refill; calls=%d", got)
	}
	if !bytes.Equal(p, raw[seekableBufSize+200:seekableBufSize+300]) {
		t.Fatalf("content mismatch after out-of-window seek")
	}
}

func TestSeekableBufSeekEndAndCurrent(t *testing.T) {
	raw := []byte("abcdefghij")
	sb := newSeekableBuf(bytes.NewReader(raw), int64(len(raw)))
	defer sb.release()

	if got, err := sb.Seek(-3, io.SeekEnd); err != nil || got != 7 {
		t.Fatalf("SeekEnd: got=%d err=%v", got, err)
	}
	p := make([]byte, 3)
	if _, err := io.ReadFull(sb, p); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(p) != "hij" {
		t.Fatalf("content mismatch: got %q", p)
	}

	// SeekCurrent(0) returns the current position.
	if got, err := sb.Seek(0, io.SeekCurrent); err != nil || got != 10 {
		t.Fatalf("SeekCurrent 0: got=%d err=%v", got, err)
	}
	// Negative SeekCurrent to go back.
	if got, err := sb.Seek(-5, io.SeekCurrent); err != nil || got != 5 {
		t.Fatalf("SeekCurrent -5: got=%d err=%v", got, err)
	}
	if _, err := io.ReadFull(sb, p); err != nil {
		t.Fatalf("ReadFull 2: %v", err)
	}
	if string(p) != "fgh" {
		t.Fatalf("content mismatch 2: got %q", p)
	}
}

func TestSeekableBufNegativeAndInvalid(t *testing.T) {
	sb := newSeekableBuf(bytes.NewReader([]byte("xyz")), 3)
	defer sb.release()
	if _, err := sb.Seek(-1, io.SeekStart); err == nil {
		t.Fatal("expected error for negative absolute seek")
	}
	if _, err := sb.Seek(0, 42); err == nil {
		t.Fatal("expected error for invalid whence")
	}
}

func TestSeekableBufReadToEOF(t *testing.T) {
	// Raw size not a multiple of the buffer size: forces a short final chunk.
	raw := randBytes(t, seekableBufSize+123)
	sb := newSeekableBuf(bytes.NewReader(raw), int64(len(raw)))
	defer sb.release()

	got, err := io.ReadAll(sb)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("content mismatch: len got=%d want=%d", len(got), len(raw))
	}
}

func TestSeekableBufReadPastEndReturnsEOF(t *testing.T) {
	sb := newSeekableBuf(bytes.NewReader([]byte("abc")), 3)
	defer sb.release()
	if _, err := sb.Seek(10, io.SeekStart); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	p := make([]byte, 4)
	n, err := sb.Read(p)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("expected (0, io.EOF), got (%d, %v)", n, err)
	}
}

func BenchmarkNew(b *testing.B) {
	const nEntries = 10_000
	entries := make([]fixtureEntry, 0, nEntries)
	for i := range nEntries {
		entries = append(entries, fixtureEntry{
			name:     fmt.Sprintf("dir/file-%05d", i),
			typeflag: tar.TypeReg,
			body:     make([]byte, 1024),
			mode:     0o644,
		})
	}
	// Inline buildTar because benchmarks can't take *testing.T.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Mode:     e.mode,
			Size:     int64(len(e.body)),
			Format:   tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			b.Fatalf("WriteHeader: %v", err)
		}
		if _, err := tw.Write(e.body); err != nil {
			b.Fatalf("Write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		b.Fatalf("Close: %v", err)
	}
	raw := buf.Bytes()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		fsys, err := New(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			b.Fatalf("New: %v", err)
		}
		if len(fsys.Entries()) != nEntries {
			b.Fatalf("entries: got %d want %d", len(fsys.Entries()), nEntries)
		}
	}
}
