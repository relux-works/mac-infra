//go:build darwin && cgo

package chromectl

/*
#cgo LDFLAGS: -framework ApplicationServices -framework AppKit
#include <stdlib.h>

int macChromeAXProcessID(void);
int macChromeAXTypeText(int pid, const char *description, const char *value);
int macChromeAXPress(int pid, const char *description);
int macChromeAXUploadFiles(int pid, const char *description, const char *stagingDirectory);
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func chromeAXProcessID() (int, error) {
	pid := int(C.macChromeAXProcessID())
	if pid <= 0 {
		return 0, fmt.Errorf("Chrome Accessibility refused: %s", chromeAXStatus(-pid))
	}
	return pid, nil
}

func chromeAXTypeText(pid int, description, value string) error {
	descriptionCString := C.CString(description)
	valueCString := C.CString(value)
	defer C.free(unsafe.Pointer(descriptionCString))
	defer C.free(unsafe.Pointer(valueCString))
	return chromeAXResult(int(C.macChromeAXTypeText(C.int(pid), descriptionCString, valueCString)))
}

func chromeAXPress(pid int, description string) error {
	descriptionCString := C.CString(description)
	defer C.free(unsafe.Pointer(descriptionCString))
	return chromeAXResult(int(C.macChromeAXPress(C.int(pid), descriptionCString)))
}

func chromeAXUploadFiles(pid int, description, stagingDirectory string) error {
	descriptionCString := C.CString(description)
	directoryCString := C.CString(stagingDirectory)
	defer C.free(unsafe.Pointer(descriptionCString))
	defer C.free(unsafe.Pointer(directoryCString))
	return chromeAXResult(int(C.macChromeAXUploadFiles(C.int(pid), descriptionCString, directoryCString)))
}

func chromeAXResult(status int) error {
	if status == 0 {
		return nil
	}
	return fmt.Errorf("Chrome Accessibility refused: %s", chromeAXStatus(status))
}

func chromeAXStatus(status int) string {
	switch status {
	case 1:
		return "accessibility-not-authorized"
	case 2:
		return "chrome-process-unavailable"
	case 3:
		return "native-window-missing"
	case 4:
		return "native-window-ambiguous"
	case 5:
		return "native-element-missing"
	case 6:
		return "native-element-ambiguous"
	case 7:
		return "accessibility-tree-too-large"
	case 8:
		return "native-operation-unsupported"
	case 9:
		return "native-operation-failed"
	case 10:
		return "native-focus-unverified"
	case 11:
		return "native-element-focus-unverified"
	case 12:
		return "file-chooser-missing"
	case 13:
		return "file-chooser-ambiguous"
	case 14:
		return "file-chooser-navigation-failed"
	case 15:
		return "file-chooser-selection-failed"
	case 16:
		return "file-chooser-replaced"
	case 17:
		return "file-chooser-unreadable"
	default:
		return "unknown-native-refusal"
	}
}
