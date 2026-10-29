//go:build darwin && cgo

package toolsecretprobe

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <stdlib.h>
static OSStatus negative_read(const char *path, const char *service, const char *account) {
    OSStatus s=SecKeychainSetUserInteractionAllowed(false);
    if(s)return -10000002;
    SecKeychainRef kc=NULL;
    s=SecKeychainOpen(path,&kc); if(s)return -10000002;
    SecKeychainStatus state=0;
    s=SecKeychainGetStatus(kc,&state);
    if(s || !(state & kSecUnlockStateStatus)){CFRelease(kc);return s ? -10000002 : -10000001;}
    CFStringRef sv=CFStringCreateWithCString(NULL,service,kCFStringEncodingUTF8);
    CFStringRef ac=CFStringCreateWithCString(NULL,account,kCFStringEncodingUTF8);
    CFArrayRef list=CFArrayCreate(NULL,(const void **)&kc,1,&kCFTypeArrayCallBacks);
    const void *keys[]={kSecClass,kSecAttrService,kSecAttrAccount,kSecMatchSearchList,kSecReturnData,kSecUseAuthenticationUI};
    const void *vals[]={kSecClassGenericPassword,sv,ac,list,kCFBooleanTrue,kSecUseAuthenticationUIFail};
    CFDictionaryRef q=CFDictionaryCreate(NULL,keys,vals,6,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    CFTypeRef data=NULL;
    s=SecItemCopyMatching(q,&data);
    // Never inspect, convert, print or transfer the returned bytes.
    if(data)CFRelease(data);
    // A locked keychain is inconclusive even if the read returned an auth code.
    OSStatus stateStatus=SecKeychainGetStatus(kc,&state);
    if(stateStatus || !(state & kSecUnlockStateStatus))s=stateStatus ? -10000002 : -10000001;
    CFRelease(q);CFRelease(list);CFRelease(sv);CFRelease(ac);CFRelease(kc);
    return s;
}
*/
import "C"
import "unsafe"

func nativeAttempt(r Request) (int, error) {
	k, s, a := C.CString(r.Keychain), C.CString(r.Service), C.CString(r.Account)
	defer C.free(unsafe.Pointer(k))
	defer C.free(unsafe.Pointer(s))
	defer C.free(unsafe.Pointer(a))
	return int(C.negative_read(k, s, a)), nil
}
