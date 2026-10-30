//go:build darwin && cgo

package firewallwatch

/*
#include <libproc.h>
#include <stddef.h>
#include <sys/types.h>

// csops is the kernel's code signing query; CS_OPS_CDHASH (5) copies the
// running image's code directory hash.
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
*/
import "C"

import (
	"encoding/hex"
	"unsafe"

	"golang.org/x/sys/unix"
)

const csOpsCDHash = 5

// resolveProcessImage reads pid's path and running image hash when the
// process is still the one nettop printed. It reads only the path and the
// hash, never the arguments.
func resolveProcessImage(pid int, name string) processImage {
	return confirmImage(pid, name, kernelProcInfo, kernelImage)
}

func kernelProcInfo(pid int) (procInfo, bool) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return procInfo{}, false
	}
	return procInfo{PID: int(kp.Proc.P_pid), Comm: comm(kp), Start: kp.Proc.P_starttime.Nano()}, true
}

func kernelImage(pid int) (processImage, bool) {
	var buf [C.PROC_PIDPATHINFO_MAXSIZE]C.char
	n := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return processImage{}, false
	}
	img := processImage{Path: C.GoStringN(&buf[0], n)}
	var cd [20]byte
	if C.csops(C.pid_t(pid), csOpsCDHash, unsafe.Pointer(&cd[0]), C.size_t(len(cd))) == 0 {
		img.CDHash = hex.EncodeToString(cd[:])
	}
	return img, true
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
