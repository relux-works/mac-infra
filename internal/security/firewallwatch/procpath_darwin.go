//go:build darwin && cgo

package firewallwatch

/*
#include <libproc.h>
*/
import "C"

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// resolveProcessPath returns the executable of pid when the process is still
// the one nettop printed: its kernel name matches, and its start time is the
// same before and after the path lookup, so a pid reused in between is not
// attributed. It reads only the path, never the arguments. "" means not
// confirmed.
func resolveProcessPath(pid int, name string) string {
	before, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || before.Proc.P_pid != int32(pid) || !nameMatches(comm(before), name) {
		return ""
	}
	var buf [C.PROC_PIDPATHINFO_MAXSIZE]C.char
	n := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return ""
	}
	path := C.GoStringN(&buf[0], n)
	after, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || after.Proc.P_pid != int32(pid) || after.Proc.P_starttime != before.Proc.P_starttime {
		return ""
	}
	return path
}

func comm(kp *unix.KinfoProc) string {
	b := kp.Proc.P_comm[:]
	for i, c := range b {
		if c == 0 {
			b = b[:i]
			break
		}
	}
	return string(b)
}
