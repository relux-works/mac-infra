#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>

static CFMutableDictionaryRef dict(void) {
    return CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}

static void probe(SecKeyRef key, const char *name) {
    CFErrorRef error = NULL;
    CFDataRef rep = SecKeyCopyExternalRepresentation(key, &error);
    long repCode = rep ? 0 : (error ? CFErrorGetCode(error) : -1);
    if (rep) CFRelease(rep); if (error) CFRelease(error);
    CFDataRef exported = NULL;
    SecItemImportExportKeyParameters params; memset(&params, 0, sizeof(params));
    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION; params.passphrase = CFSTR("x");
    OSStatus exp = SecItemExport(key, kSecFormatWrappedPKCS8, 0, &params, &exported);
    long expLen = exported ? CFDataGetLength(exported) : 0;
    if (exported) CFRelease(exported);
    SecKeyRef pub = SecKeyCopyPublicKey(key);
    CFErrorRef perr = NULL;
    CFDataRef point = pub ? SecKeyCopyExternalRepresentation(pub, &perr) : NULL;
    printf("   public: pub=%p point=%ld code=%ld\n", (void*)pub, point ? (long)CFDataGetLength(point) : -1L, perr ? (long)CFErrorGetCode(perr) : 0L);
    if (point) CFRelease(point); if (perr) CFRelease(perr); if (pub) CFRelease(pub);
    const CSSM_KEY *cssm = NULL;
    SecKeyGetCSSMKey(key, &cssm);
    unsigned attr = cssm ? cssm->KeyHeader.KeyAttr : 0;
    printf("%-28s rep=%ld export=%d(%ld bytes) keyattr=0x%x extractable=%d sensitive=%d\n", name, repCode, (int)exp, expLen, attr,
           !!(attr & CSSM_KEYATTR_EXTRACTABLE), !!(attr & CSSM_KEYATTR_SENSITIVE));
    // Delete both halves
    CFMutableDictionaryRef q = dict();
    CFDictionarySetValue(q, kSecClass, kSecClassKey);
    CFDictionarySetValue(q, kSecAttrLabel, CFSTR("works.relux.mac-keyvault.test.probe2"));
    while (SecItemDelete(q) == errSecSuccess) {}
    CFRelease(q);
}

static int pubExtractable = -1;
static void variant(const char *name, int topExtractable, int privExtractable, int privSensitive) {
    CFMutableDictionaryRef priv = dict();
    CFDictionarySetValue(priv, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionarySetValue(priv, kSecAttrLabel, CFSTR("works.relux.mac-keyvault.test.probe2"));
    if (privExtractable >= 0) CFDictionarySetValue(priv, kSecAttrIsExtractable, privExtractable ? kCFBooleanTrue : kCFBooleanFalse);
    if (privSensitive >= 0) CFDictionarySetValue(priv, kSecAttrIsSensitive, privSensitive ? kCFBooleanTrue : kCFBooleanFalse);
    CFMutableDictionaryRef attrs = dict();
    CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    int bits = 256; CFNumberRef n = CFNumberCreate(NULL, kCFNumberIntType, &bits);
    CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, n); CFRelease(n);
    CFDictionarySetValue(attrs, kSecAttrLabel, CFSTR("works.relux.mac-keyvault.test.probe2"));
    if (topExtractable >= 0) CFDictionarySetValue(attrs, kSecAttrIsExtractable, topExtractable ? kCFBooleanTrue : kCFBooleanFalse);
    CFDictionarySetValue(attrs, kSecPrivateKeyAttrs, priv);
    if (pubExtractable >= 0) { CFMutableDictionaryRef pd = dict(); CFDictionarySetValue(pd, kSecAttrIsExtractable, kCFBooleanTrue); CFDictionarySetValue(attrs, kSecPublicKeyAttrs, pd); }
    CFErrorRef error = NULL;
    SecKeyRef key = SecKeyCreateRandomKey(attrs, &error);
    if (!key) { printf("%-28s create failed %ld\n", name, error ? CFErrorGetCode(error) : -1); return; }
    probe(key, name);
    CFRelease(key); CFRelease(attrs); CFRelease(priv);
}

int main(void) {
    variant("top extractable=0", 0, -1, -1);
    pubExtractable = 1;
    variant("top extr=0 pub extr=1", 0, -1, -1);
    return 0;
}
