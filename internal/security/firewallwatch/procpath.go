package firewallwatch

import (
	"path/filepath"
	"strings"
)

// nettopNameLen is how many bytes of a process name nettop prints: names
// longer than this appear cut (MAXCOMLEN minus the terminator).
const nettopNameLen = 15

// lookupProcessPath resolves a nettop row's process to its executable; tests
// replace it.
var lookupProcessPath = resolveProcessPath

// attributePaths gives each nettop item its confirmed executable path, once
// per pid per sample, and lets the signer inspection use it.
func attributePaths(items []Item, lookup func(pid int, name string) string) {
	seen := map[int]string{}
	for i := range items {
		it := &items[i]
		if it.Source != "nettop" || it.PID <= 0 {
			continue
		}
		path, ok := seen[it.PID]
		if !ok {
			path = lookup(it.PID, it.ProcName)
			seen[it.PID] = path
		}
		if path != "" {
			it.Path, it.InspectionPath = path, path
		}
	}
}

// nameMatches reports whether the kernel's name for a process (p_comm, up to
// MAXCOMLEN bytes) is the one nettop printed, allowing for nettop's cut.
func nameMatches(comm, printed string) bool {
	if printed == "" {
		return false
	}
	if len(printed) >= nettopNameLen {
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

// validEventPath admits a stored path only on a nettop event, absolute, clean
// and within the persisted-text limits.
func validEventPath(e Event) bool {
	if e.Path == "" {
		return true
	}
	return e.Source == "nettop" && filepath.IsAbs(e.Path) && persistedText(e.Path, 1024)
}
