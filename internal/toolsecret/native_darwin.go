//go:build darwin && cgo

package toolsecret

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Foundation -framework Security
#include <stdlib.h>
char *ts_metadata_call(const char *request);
*/
import "C"

import (
	"golang.org/x/sys/unix"
	"unsafe"
)

func terminalFD(fd int) bool { _, err := unix.IoctlGetTermios(fd, unix.TIOCGETA); return err == nil }
func nativeCall(request string) (string, error) {
	s := C.CString(request)
	defer C.free(unsafe.Pointer(s))
	r := C.ts_metadata_call(s)
	defer C.free(unsafe.Pointer(r))
	return C.GoString(r), nil
}
