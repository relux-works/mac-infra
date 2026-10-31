//go:build darwin && cgo

package firewallwatch

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <libproc.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// csops is the kernel's code signing query; CS_OPS_CDHASH (5) copies the
// running image's code directory hash.
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

enum {
	fwUnsigned = 1,
	fwAdhoc,
	fwNoRequirement,
	fwApple,
	fwAppStore,
	fwDeveloperID,
};

// Requirement checks verify the signature over the code directory and its
// certificate chain. The kernel already holds the running image to its code
// directory's page hashes, so the executable and resources are not hashed
// again, and no network lookup runs.
static const SecCSFlags fwCheckFlags = kSecCSDoNotValidateExecutable | kSecCSDoNotValidateResources | kSecCSNoNetworkAccess;

static int fwSatisfies(SecStaticCodeRef code, const char *text) {
	CFStringRef s = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
	if (s == NULL) {
		return 0;
	}
	SecRequirementRef req = NULL;
	OSStatus st = SecRequirementCreateWithString(s, kSecCSDefaultFlags, &req);
	CFRelease(s);
	if (st != errSecSuccess) {
		return 0;
	}
	st = SecStaticCodeCheckValidity(code, fwCheckFlags, req);
	CFRelease(req);
	return st == errSecSuccess;
}

static void fwCopyString(CFTypeRef v, char *out, size_t n) {
	out[0] = 0;
	if (v == NULL || CFGetTypeID(v) != CFStringGetTypeID() || !CFStringGetCString((CFStringRef)v, out, (CFIndex)n, kCFStringEncodingUTF8)) {
		out[0] = 0;
	}
}

// fwCodeFacts reads path's signing facts from its signature: the kind, the
// code directory hash (20 bytes) when there is one, and for App Store code
// the team, for Developer ID code the validated leaf certificate's summary.
// It returns -1 when the file's signature cannot be read.
static int fwCodeFacts(const char *path, int *kind, unsigned char *hash, int *hasHash, char *name, size_t nameLen) {
	*kind = 0;
	*hasHash = 0;
	name[0] = 0;
	CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, (CFIndex)strlen(path), false);
	if (url == NULL) {
		return -1;
	}
	SecStaticCodeRef code = NULL;
	OSStatus st = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
	CFRelease(url);
	if (st != errSecSuccess) {
		return -1;
	}
	// Install the offline policy before requesting signing metadata: that
	// request can itself evaluate the certificate chain. Refuse invalid code
	// here, rather than treating partial metadata as validated signer facts.
	st = SecStaticCodeCheckValidity(code, fwCheckFlags, NULL);
	if (st == errSecCSUnsigned) {
		*kind = fwUnsigned;
		CFRelease(code);
		return 0;
	}
	if (st != errSecSuccess) {
		CFRelease(code);
		return -1;
	}
	CFDictionaryRef info = NULL;
	st = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
	if (st != errSecSuccess || info == NULL) {
		CFRelease(code);
		return -1;
	}
	CFTypeRef unique = CFDictionaryGetValue(info, kSecCodeInfoUnique);
	if (unique == NULL) {
		*kind = fwUnsigned;
		CFRelease(info);
		CFRelease(code);
		return 0;
	}
	if (CFGetTypeID(unique) == CFDataGetTypeID() && CFDataGetLength((CFDataRef)unique) >= 20) {
		memcpy(hash, CFDataGetBytePtr((CFDataRef)unique), 20);
		*hasHash = 1;
	}
	uint32_t flags = 0;
	CFTypeRef f = CFDictionaryGetValue(info, kSecCodeInfoFlags);
	if (f != NULL && CFGetTypeID(f) == CFNumberGetTypeID()) {
		CFNumberGetValue((CFNumberRef)f, kCFNumberSInt32Type, &flags);
	}
	if (fwSatisfies(code, "anchor apple")) {
		*kind = fwApple;
	} else if (fwSatisfies(code, "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists")) {
		*kind = fwAppStore;
		fwCopyString(CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier), name, nameLen);
	} else if (fwSatisfies(code, "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists")) {
		*kind = fwDeveloperID;
		CFTypeRef certs = CFDictionaryGetValue(info, kSecCodeInfoCertificates);
		if (certs != NULL && CFGetTypeID(certs) == CFArrayGetTypeID() && CFArrayGetCount((CFArrayRef)certs) > 0) {
			CFStringRef summary = SecCertificateCopySubjectSummary((SecCertificateRef)CFArrayGetValueAtIndex((CFArrayRef)certs, 0));
			fwCopyString(summary, name, nameLen);
			if (summary != NULL) {
				CFRelease(summary);
			}
		}
	} else if (flags & kSecCodeSignatureAdhoc) {
		*kind = fwAdhoc;
	} else {
		*kind = fwNoRequirement;
	}
	CFRelease(info);
	CFRelease(code);
	return 0;
}
*/
import "C"

import (
	"encoding/hex"
	"errors"
	"strings"
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

// staticCodeFacts reads a file's signer and code directory hash from its
// signature through the Security framework. The signer kinds and their text
// retain the established labels; the Developer ID name comes from the validated leaf
// certificate and the App Store team from the signature, never from a path.
func staticCodeFacts(path string) (codeFacts, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var kind, hasHash C.int
	var hash [20]C.uchar
	var name [512]C.char
	if C.fwCodeFacts(cpath, &kind, &hash[0], &hasHash, &name[0], C.size_t(len(name))) != 0 {
		return codeFacts{Signer: "unknown", CDHash: noCDHash}, errors.New("signature unreadable")
	}
	f := codeFacts{CDHash: noCDHash}
	if hasHash != 0 {
		f.CDHash = hex.EncodeToString(C.GoBytes(unsafe.Pointer(&hash[0]), 20))
	}
	n := strings.TrimSpace(C.GoString(&name[0]))
	switch kind {
	case C.fwUnsigned:
		f.Signer = "unsigned"
	case C.fwAdhoc:
		f.Signer = "ad-hoc"
	case C.fwNoRequirement:
		f.Signer = "no designated requirement"
	case C.fwApple:
		f.Signer = "Apple"
	case C.fwAppStore:
		f.Signer = "App Store"
		if n != "" {
			f.Signer = "App Store: " + n
		}
	case C.fwDeveloperID:
		f.Signer = "Developer ID: " + strings.TrimSpace(strings.TrimPrefix(n, "Developer ID Application:"))
	default:
		return codeFacts{Signer: "unknown", CDHash: noCDHash}, errors.New("signature unclassified")
	}
	return f, nil
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
