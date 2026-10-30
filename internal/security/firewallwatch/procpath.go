package firewallwatch

import (
	"path/filepath"
	"strings"
)

// nettopNameLen is how many bytes of a process name nettop prints: names
// longer than this appear cut (MAXCOMLEN minus the terminator).
const nettopNameLen = 15

// processImage is what the kernel reports for a running process: the path it
// was started from and the code directory hash of the image it runs (the
// first 20 bytes, lowercase hex; "" when the kernel holds none). The path
// names where the process came from; the file there may since have been
// replaced, so only a matching hash ties that file's signature to the process.
type processImage struct {
	Path   string
	CDHash string
}

// procInfo is the part of a process's kernel record that confirms a nettop
// row still describes the same process.
type procInfo struct {
	PID   int
	Comm  string
	Start int64
}

// lookupProcessImage resolves a nettop row's process to its image; tests
// replace it.
var lookupProcessImage = resolveProcessImage

// confirmImage returns pid's image when the process is the one nettop printed:
// its kernel name matches, and its name and start time are the same before
// and after the image lookup, so a pid reused, or re-executed under another
// name, in between is not attributed. An exec under the same name keeps the
// pid, the name and the start time, so one at any time between nettop's
// sample and the second read cannot be told apart; the path and hash reads
// are not one snapshot either. The zero value means not confirmed.
func confirmImage(pid int, name string, info func(int) (procInfo, bool), image func(int) (processImage, bool)) processImage {
	before, ok := info(pid)
	if !ok || before.PID != pid || !nameMatches(before.Comm, name) {
		return processImage{}
	}
	img, ok := image(pid)
	if !ok || img.Path == "" {
		return processImage{}
	}
	after, ok := info(pid)
	if !ok || after.PID != pid || after.Comm != before.Comm || after.Start != before.Start {
		return processImage{}
	}
	return img
}

// attributePaths gives each nettop item its process's path and image hash,
// looked up once per pid per sample.
func attributePaths(items []Item, lookup func(pid int, name string) processImage) {
	seen := map[int]processImage{}
	for i := range items {
		it := &items[i]
		if it.Source != "nettop" || it.PID <= 0 {
			continue
		}
		img, ok := seen[it.PID]
		if !ok {
			img = lookup(it.PID, it.ProcName)
			seen[it.PID] = img
		}
		if img.Path != "" {
			it.Path, it.ImageCDHash = img.Path, img.CDHash
		}
	}
}

// nameMatches reports whether the kernel's name for a process (p_comm, up to
// MAXCOMLEN bytes) is the one nettop printed. A printed name of exactly
// nettopNameLen bytes may be cut, so it matches the kernel name's prefix;
// any other printed name must be the whole kernel name.
func nameMatches(comm, printed string) bool {
	if printed == "" {
		return false
	}
	if len(printed) == nettopNameLen {
		return strings.HasPrefix(comm, printed)
	}
	return comm == printed
}

// eventPath is the path stored on an event: only for nettop, only an
// absolute path, as valid text.
func eventPath(it Item) string {
	if it.Source != "nettop" || !filepath.IsAbs(it.Path) {
		return ""
	}
	if !persistedText(it.Path, 1024) {
		return ""
	}
	return it.Path
}

// validEventPath admits a stored path only on a nettop event, absolute and
// within the persisted-text limits.
func validEventPath(e Event) bool {
	if e.Path == "" {
		return true
	}
	return e.Source == "nettop" && filepath.IsAbs(e.Path) && persistedText(e.Path, 1024)
}

// validCDHash admits a code directory hash as the kernel and codesign print
// it: 40 lowercase hex digits.
func validCDHash(v string) bool {
	if len(v) != 40 {
		return false
	}
	for _, c := range v {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
