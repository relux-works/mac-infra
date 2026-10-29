package toolsecret

import (
	"encoding/json"
	"os"
	"strings"
	"syscall"
)

func MultiplexerPresent(lookup func(string) (string, bool)) bool {
	for _, key := range []string{"TMUX", "STY"} {
		if _, set := lookup(key); set {
			return true
		}
	}
	return false
}

// This is an output scope, not a fallback to unrestricted enumeration. An
// explicit service-prefix further narrows it; only attended --all widens it.
func KnownService(service string) bool {
	return strings.HasPrefix(service, "works.relux.") || strings.HasPrefix(service, "a2a") || service == "Claude Code-credentials"
}

func WriteLocalInventory(path string, result any) (err error) {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	created, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	defer func() {
		f.Close()
		if current, e := os.Lstat(path); err != nil && e == nil && os.SameFile(created, current) {
			os.Remove(path)
		}
	}()
	if err = json.NewEncoder(f).Encode(result); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return f.Close()
}
