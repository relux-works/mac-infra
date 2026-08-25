#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#include <stdlib.h>

enum {
    MacChromeAXOK = 0,
    MacChromeAXNotAuthorized = 1,
    MacChromeAXProcessUnavailable = 2,
    MacChromeAXWindowMissing = 3,
    MacChromeAXWindowAmbiguous = 4,
    MacChromeAXElementMissing = 5,
    MacChromeAXElementAmbiguous = 6,
    MacChromeAXTreeTooLarge = 7,
    MacChromeAXUnsupported = 8,
    MacChromeAXOperationFailed = 9,
    MacChromeAXFocusUnverified = 10,
    MacChromeAXElementFocusUnverified = 11,
    MacChromeAXFileChooserMissing = 12,
    MacChromeAXFileChooserAmbiguous = 13,
    MacChromeAXFileChooserNavigationFailed = 14,
    MacChromeAXFileChooserSelectionFailed = 15,
    MacChromeAXFileChooserReplaced = 16,
    MacChromeAXFileChooserUnreadable = 17,
};

static CFStringRef MacChromeString(const char *value) {
    if (value == NULL) return NULL;
    return CFStringCreateWithCString(kCFAllocatorDefault, value, kCFStringEncodingUTF8);
}

static int MacChromeRunningApplication(pid_t pid, NSRunningApplication **out) {
    NSArray<NSRunningApplication *> *apps =
        [NSRunningApplication runningApplicationsWithBundleIdentifier:@"com.google.Chrome"];
    NSRunningApplication *match = nil;
    for (NSRunningApplication *app in apps) {
        if (pid <= 0 || app.processIdentifier == pid) {
            if (match != nil) return MacChromeAXProcessUnavailable;
            match = app;
        }
    }
    if (match == nil) return MacChromeAXProcessUnavailable;
    *out = match;
    return MacChromeAXOK;
}

// Chrome's Apple Events window ID is not exposed as a stable Accessibility
// attribute. The exact-ID JXA gate raises the requested window first; native
// interaction then accepts only Chrome's unique AXMain window. A cryptographic
// DOM nonce inside that window correlates the native element back to the exact
// tab without title or coordinate guessing.
static int MacChromeMainWindow(pid_t pid, AXUIElementRef *out) {
    AXUIElementRef app = AXUIElementCreateApplication(pid);
    if (app == NULL) return MacChromeAXProcessUnavailable;
    CFTypeRef rawWindows = NULL;
    AXError error = AXUIElementCopyAttributeValue(app, kAXWindowsAttribute, &rawWindows);
    CFRelease(app);
    if (error != kAXErrorSuccess || rawWindows == NULL || CFGetTypeID(rawWindows) != CFArrayGetTypeID()) {
        if (rawWindows != NULL) CFRelease(rawWindows);
        return MacChromeAXWindowMissing;
    }
    CFArrayRef windows = (CFArrayRef)rawWindows;
    AXUIElementRef match = NULL;
    CFIndex matches = 0;
    for (CFIndex i = 0; i < CFArrayGetCount(windows); i++) {
        AXUIElementRef window = (AXUIElementRef)CFArrayGetValueAtIndex(windows, i);
        CFTypeRef rawMain = NULL;
        if (AXUIElementCopyAttributeValue(window, kAXMainAttribute, &rawMain) == kAXErrorSuccess &&
            rawMain != NULL && CFGetTypeID(rawMain) == CFBooleanGetTypeID() &&
            CFBooleanGetValue((CFBooleanRef)rawMain)) {
            match = window;
            matches++;
        }
        if (rawMain != NULL) CFRelease(rawMain);
    }
    if (matches == 1 && match != NULL) CFRetain(match);
    CFRelease(windows);
    if (matches == 0) return MacChromeAXWindowMissing;
    if (matches != 1) return MacChromeAXWindowAmbiguous;
    *out = match;
    return MacChromeAXOK;
}

typedef struct {
    CFStringRef description;
    CFStringRef requiredRole;
    CFMutableArrayRef matches;
    CFIndex visited;
    Boolean exceeded;
} MacChromeAXSearch;

static void MacChromeCollect(AXUIElementRef element, MacChromeAXSearch *search, CFIndex depth) {
    if (search->exceeded || depth > 64 || ++search->visited > 10000) {
        search->exceeded = true;
        return;
    }
    Boolean roleMatches = search->requiredRole == NULL;
    if (!roleMatches) {
        CFTypeRef rawRole = NULL;
        if (AXUIElementCopyAttributeValue(element, kAXRoleAttribute, &rawRole) == kAXErrorSuccess &&
            rawRole != NULL && CFGetTypeID(rawRole) == CFStringGetTypeID()) {
            roleMatches = CFEqual(rawRole, search->requiredRole);
        }
        if (rawRole != NULL) CFRelease(rawRole);
    }
    if (roleMatches) {
        CFTypeRef rawDescription = NULL;
        if (AXUIElementCopyAttributeValue(element, kAXDescriptionAttribute, &rawDescription) == kAXErrorSuccess &&
            rawDescription != NULL && CFGetTypeID(rawDescription) == CFStringGetTypeID() &&
            CFEqual(rawDescription, search->description)) {
            CFArrayAppendValue(search->matches, element);
        }
        if (rawDescription != NULL) CFRelease(rawDescription);
    }
    CFTypeRef rawChildren = NULL;
    if (AXUIElementCopyAttributeValue(element, kAXChildrenAttribute, &rawChildren) == kAXErrorSuccess &&
        rawChildren != NULL && CFGetTypeID(rawChildren) == CFArrayGetTypeID()) {
        CFArrayRef children = (CFArrayRef)rawChildren;
        for (CFIndex i = 0; i < CFArrayGetCount(children); i++) {
            MacChromeCollect((AXUIElementRef)CFArrayGetValueAtIndex(children, i), search, depth + 1);
            if (search->exceeded) break;
        }
    }
    if (rawChildren != NULL) CFRelease(rawChildren);
}

static int MacChromeElement(AXUIElementRef window, CFStringRef description,
                            CFStringRef requiredRole, AXUIElementRef *out) {
    MacChromeAXSearch search = {
        .description = description,
        .requiredRole = requiredRole,
        .matches = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks),
        .visited = 0,
        .exceeded = false,
    };
    MacChromeCollect(window, &search, 0);
    if (search.exceeded) {
        CFRelease(search.matches);
        return MacChromeAXTreeTooLarge;
    }
    CFIndex count = CFArrayGetCount(search.matches);
    AXUIElementRef match = NULL;
    if (count == 1) {
        match = (AXUIElementRef)CFArrayGetValueAtIndex(search.matches, 0);
        CFRetain(match);
    }
    CFRelease(search.matches);
    if (count == 0) return MacChromeAXElementMissing;
    if (count != 1) return MacChromeAXElementAmbiguous;
    *out = match;
    return MacChromeAXOK;
}

static Boolean MacChromeBooleanAttribute(AXUIElementRef element, CFStringRef attribute) {
    CFTypeRef raw = NULL;
    Boolean result = AXUIElementCopyAttributeValue(element, attribute, &raw) == kAXErrorSuccess &&
        raw != NULL && CFGetTypeID(raw) == CFBooleanGetTypeID() && CFBooleanGetValue((CFBooleanRef)raw);
    if (raw != NULL) CFRelease(raw);
    return result;
}

static Boolean MacChromeApplicationIsFrontmost(pid_t pid) {
    NSRunningApplication *frontmost = [NSWorkspace sharedWorkspace].frontmostApplication;
    return frontmost != nil && frontmost.processIdentifier == pid &&
        [frontmost.bundleIdentifier isEqualToString:@"com.google.Chrome"];
}

// Chrome activation requested through Apple Events is asynchronous. Query the
// workspace's current frontmost process rather than the potentially stale
// NSRunningApplication active snapshot, and give that exact activation a
// short, bounded settle window before refusing. All native element work still
// occurs only after the unique main-window and cryptographic nonce checks.
static Boolean MacChromeWaitUntilFrontmost(pid_t pid) {
    for (int attempt = 0; attempt < 10; attempt++) {
        if (MacChromeApplicationIsFrontmost(pid)) return true;
        usleep(50000);
    }
    return MacChromeApplicationIsFrontmost(pid);
}

static int MacChromeCopySheets(AXUIElementRef window, CFArrayRef *out) {
    CFTypeRef rawSheets = NULL;
    AXError error = AXUIElementCopyAttributeValue(window, CFSTR("AXSheets"), &rawSheets);
    if (error != kAXErrorSuccess || rawSheets == NULL || CFGetTypeID(rawSheets) != CFArrayGetTypeID()) {
        if (rawSheets != NULL) CFRelease(rawSheets);
        return MacChromeAXFileChooserUnreadable;
    }
    *out = (CFArrayRef)rawSheets;
    return MacChromeAXOK;
}

// The pre-press state is evidence, not a best-effort absence check. Only a
// successfully read, correctly typed, empty AXSheets array admits AXPress.
// An unreadable or malformed attribute and every pre-existing sheet refuse.
static int MacChromeRequireNoSheets(AXUIElementRef window) {
    CFArrayRef sheets = NULL;
    int status = MacChromeCopySheets(window, &sheets);
    if (status != MacChromeAXOK) return status;
    CFIndex count = CFArrayGetCount(sheets);
    CFRelease(sheets);
    return count == 0 ? MacChromeAXOK : MacChromeAXFileChooserAmbiguous;
}

static int MacChromeSingleSheet(AXUIElementRef window, AXUIElementRef *out) {
    CFArrayRef sheets = NULL;
    int status = MacChromeCopySheets(window, &sheets);
    if (status != MacChromeAXOK) return status;
    CFIndex count = CFArrayGetCount(sheets);
    AXUIElementRef sheet = NULL;
    if (count == 1) {
        sheet = (AXUIElementRef)CFArrayGetValueAtIndex(sheets, 0);
        CFRetain(sheet);
    }
    CFRelease(sheets);
    if (count == 0) return MacChromeAXFileChooserMissing;
    if (count != 1) return MacChromeAXFileChooserAmbiguous;
    *out = sheet;
    return MacChromeAXOK;
}

// A single sheet is insufficient after the nonce press: it must remain the
// exact retained AX element first observed in the zero-to-one transition.
static int MacChromeRequireSameSheet(AXUIElementRef window, AXUIElementRef expected) {
    if (expected == NULL) return MacChromeAXFileChooserMissing;
    AXUIElementRef current = NULL;
    int status = MacChromeSingleSheet(window, &current);
    if (status != MacChromeAXOK) return status;
    Boolean same = CFEqual(current, expected);
    CFRelease(current);
    return same ? MacChromeAXOK : MacChromeAXFileChooserReplaced;
}

static int MacChromeGuardChooser(pid_t pid, AXUIElementRef window, AXUIElementRef chooser) {
    if (!MacChromeApplicationIsFrontmost(pid) || !MacChromeBooleanAttribute(window, kAXMainAttribute)) {
        return MacChromeAXFocusUnverified;
    }
    return MacChromeRequireSameSheet(window, chooser);
}

static int MacChromeWaitForSingleSheet(AXUIElementRef window, AXUIElementRef *out) {
    int status = MacChromeAXFileChooserMissing;
    for (int attempt = 0; attempt < 40; attempt++) {
        AXUIElementRef sheet = NULL;
        status = MacChromeSingleSheet(window, &sheet);
        if (status == MacChromeAXOK) {
            *out = sheet;
            return MacChromeAXOK;
        }
        // Only a successfully read empty array is a retryable absence. An AX
        // read error, null value, wrong type, or ambiguous sheet set is a
        // terminal refusal: a later valid snapshot cannot establish the
        // claimed zero-to-one transition retroactively.
        if (status != MacChromeAXFileChooserMissing) return status;
        usleep(50000);
    }
    return status;
}

static int MacChromeWaitForNoSheets(AXUIElementRef window, AXUIElementRef chooser) {
    for (int attempt = 0; attempt < 100; attempt++) {
        int status = MacChromeRequireSameSheet(window, chooser);
        // Exact empty-array absence means the retained chooser closed. Every
        // unreadable, malformed, ambiguous, or replacement state is terminal.
        if (status == MacChromeAXFileChooserMissing) return MacChromeAXOK;
        if (status != MacChromeAXOK) return status;
        usleep(50000);
    }
    return MacChromeAXFileChooserSelectionFailed;
}

typedef struct {
    CFStringRef value;
    CFIndex visited;
    Boolean found;
    Boolean exceeded;
} MacChromeAXValueSearch;

static void MacChromeFindExactValue(AXUIElementRef element, MacChromeAXValueSearch *search, CFIndex depth) {
    if (search->found || search->exceeded || depth > 64 || ++search->visited > 10000) {
        if (!search->found && (depth > 64 || search->visited > 10000)) search->exceeded = true;
        return;
    }
    CFStringRef attributes[] = {kAXValueAttribute, kAXDescriptionAttribute};
    for (size_t i = 0; i < sizeof(attributes) / sizeof(attributes[0]); i++) {
        CFTypeRef raw = NULL;
        if (AXUIElementCopyAttributeValue(element, attributes[i], &raw) == kAXErrorSuccess &&
            raw != NULL && CFGetTypeID(raw) == CFStringGetTypeID() && CFEqual(raw, search->value)) {
            search->found = true;
        }
        if (raw != NULL) CFRelease(raw);
        if (search->found) return;
    }
    CFTypeRef rawChildren = NULL;
    if (AXUIElementCopyAttributeValue(element, kAXChildrenAttribute, &rawChildren) == kAXErrorSuccess &&
        rawChildren != NULL && CFGetTypeID(rawChildren) == CFArrayGetTypeID()) {
        CFArrayRef children = (CFArrayRef)rawChildren;
        for (CFIndex i = 0; i < CFArrayGetCount(children); i++) {
            MacChromeFindExactValue((AXUIElementRef)CFArrayGetValueAtIndex(children, i), search, depth + 1);
            if (search->found || search->exceeded) break;
        }
    }
    if (rawChildren != NULL) CFRelease(rawChildren);
}

static Boolean MacChromeWaitForChooserDirectory(AXUIElementRef chooser, CFStringRef directoryName) {
    for (int attempt = 0; attempt < 40; attempt++) {
        MacChromeAXValueSearch search = {
            .value = directoryName,
            .visited = 0,
            .found = false,
            .exceeded = false,
        };
        MacChromeFindExactValue(chooser, &search, 0);
        if (search.found) return true;
        if (search.exceeded) return false;
        usleep(50000);
    }
    return false;
}

static Boolean MacChromePostKey(CGKeyCode keyCode, CGEventFlags flags, CFStringRef text) {
    CGEventSourceRef source = CGEventSourceCreate(kCGEventSourceStateHIDSystemState);
    CGEventRef keyDown = source != NULL ? CGEventCreateKeyboardEvent(source, keyCode, true) : NULL;
    CGEventRef keyUp = source != NULL ? CGEventCreateKeyboardEvent(source, keyCode, false) : NULL;
    if (source == NULL || keyDown == NULL || keyUp == NULL) {
        if (keyDown != NULL) CFRelease(keyDown);
        if (keyUp != NULL) CFRelease(keyUp);
        if (source != NULL) CFRelease(source);
        return false;
    }
    CGEventSetFlags(keyDown, flags);
    CGEventSetFlags(keyUp, flags);
    if (text != NULL) {
        CFIndex length = CFStringGetLength(text);
        UniChar *characters = calloc((size_t)length, sizeof(UniChar));
        if (characters == NULL) {
            CFRelease(keyDown);
            CFRelease(keyUp);
            CFRelease(source);
            return false;
        }
        CFStringGetCharacters(text, CFRangeMake(0, length), characters);
        CGEventKeyboardSetUnicodeString(keyDown, length, characters);
        CGEventKeyboardSetUnicodeString(keyUp, length, characters);
        free(characters);
    }
    CGEventPost(kCGHIDEventTap, keyDown);
    CGEventPost(kCGHIDEventTap, keyUp);
    CFRelease(keyDown);
    CFRelease(keyUp);
    CFRelease(source);
    return true;
}

static void MacChromeCancelChooser(pid_t pid, AXUIElementRef window, AXUIElementRef chooser) {
    // Never send Escape to a pre-existing or replacement sheet. Cleanup may
    // touch only the exact chooser created by this upload's nonce press.
    if (chooser != NULL && MacChromeGuardChooser(pid, window, chooser) == MacChromeAXOK) {
        (void)MacChromePostKey(53, 0, NULL);
    }
}

int macChromeAXProcessID(void) {
    @autoreleasepool {
        if (!AXIsProcessTrusted()) return -MacChromeAXNotAuthorized;
        NSRunningApplication *app = nil;
        int status = MacChromeRunningApplication(0, &app);
        if (status != MacChromeAXOK) return -status;
        return app.processIdentifier;
    }
}

int macChromeAXTypeText(int pid, const char *description, const char *value) {
    @autoreleasepool {
        if (!AXIsProcessTrusted()) return MacChromeAXNotAuthorized;
        CFStringRef marker = MacChromeString(description);
        CFStringRef text = MacChromeString(value);
        if (marker == NULL || text == NULL) {
            if (marker != NULL) CFRelease(marker);
            if (text != NULL) CFRelease(text);
            return MacChromeAXOperationFailed;
        }
        NSRunningApplication *running = nil;
        int status = MacChromeRunningApplication((pid_t)pid, &running);
        AXUIElementRef window = NULL;
        if (status == MacChromeAXOK && !MacChromeWaitUntilFrontmost((pid_t)pid)) status = MacChromeAXFocusUnverified;
        if (status == MacChromeAXOK) status = MacChromeMainWindow((pid_t)pid, &window);
        if (status == MacChromeAXOK && (!MacChromeApplicationIsFrontmost((pid_t)pid) || !MacChromeBooleanAttribute(window, kAXMainAttribute))) {
            status = MacChromeAXFocusUnverified;
        }
        if (status == MacChromeAXOK) {
            AXUIElementRef element = NULL;
            status = MacChromeElement(window, marker, kAXTextFieldRole, &element);
            if (status == MacChromeAXOK) {
                Boolean valueSettable = false;
                Boolean focusSettable = false;
                if (AXUIElementIsAttributeSettable(element, kAXValueAttribute, &valueSettable) != kAXErrorSuccess || !valueSettable ||
                    AXUIElementIsAttributeSettable(element, kAXFocusedAttribute, &focusSettable) != kAXErrorSuccess || !focusSettable) {
                    status = MacChromeAXUnsupported;
                } else {
                    Boolean exactFocus = false;
                    for (int attempt = 0; attempt < 3 && !exactFocus; attempt++) {
                        if (AXUIElementSetAttributeValue(element, kAXFocusedAttribute, kCFBooleanTrue) != kAXErrorSuccess) {
                            status = MacChromeAXOperationFailed;
                            break;
                        }
                        usleep(100000);
                        exactFocus = MacChromeBooleanAttribute(element, kAXFocusedAttribute);
                    }
                    if (!exactFocus) {
                        if (status == MacChromeAXOK) status = MacChromeAXElementFocusUnverified;
                    } else if (!MacChromeApplicationIsFrontmost((pid_t)pid) || !MacChromeBooleanAttribute(window, kAXMainAttribute)) {
                        status = MacChromeAXFocusUnverified;
                    } else {
                        // A trusted input event requires a real HID keystroke, but the
                        // keystroke must not be recoverable-by-deletion: an append/backspace
                        // pulse silently destroys a genuine character whenever the appended
                        // key is dropped, leaving the field short by one. Instead seed the
                        // field with everything except the final character and let the single
                        // HID keystroke produce the final character itself, so a dropped event
                        // can only under-fill the field, never corrupt it. The observed value
                        // is then verified against the request before reporting success.
                        CFIndex length = CFStringGetLength(text);
                        CFIndex tailLength = 0;
                        if (length >= 2 &&
                            CFStringGetCharacterAtIndex(text, length - 2) >= 0xD800 && CFStringGetCharacterAtIndex(text, length - 2) <= 0xDBFF &&
                            CFStringGetCharacterAtIndex(text, length - 1) >= 0xDC00 && CFStringGetCharacterAtIndex(text, length - 1) <= 0xDFFF) {
                            tailLength = 2;
                        } else if (length >= 1) {
                            tailLength = 1;
                        }
                        CFIndex prefixLength = length - tailLength;
                        CFStringRef prefix = tailLength > 0
                            ? CFStringCreateWithSubstring(kCFAllocatorDefault, text, CFRangeMake(0, prefixLength))
                            : NULL;
                        CFRange caretRange = CFRangeMake(prefixLength, 0);
                        AXValueRef selectedRange = AXValueCreate(kAXValueCFRangeType, &caretRange);
                        CGEventSourceRef source = CGEventSourceCreate(kCGEventSourceStateHIDSystemState);
                        CGEventRef keyDown = source != NULL ? CGEventCreateKeyboardEvent(source, 0, true) : NULL;
                        CGEventRef keyUp = source != NULL ? CGEventCreateKeyboardEvent(source, 0, false) : NULL;
                        UniChar tail[2] = {0, 0};
                        if (tailLength > 0) CFStringGetCharacters(text, CFRangeMake(prefixLength, tailLength), tail);
                        if (tailLength <= 0 || prefix == NULL || selectedRange == NULL || source == NULL || keyDown == NULL || keyUp == NULL) {
                            status = MacChromeAXOperationFailed;
                        } else if (AXUIElementSetAttributeValue(element, kAXValueAttribute, prefix) != kAXErrorSuccess) {
                            status = MacChromeAXOperationFailed;
                        } else if (AXUIElementSetAttributeValue(element, kAXSelectedTextRangeAttribute, selectedRange) != kAXErrorSuccess) {
                            status = MacChromeAXUnsupported;
                        } else if (!MacChromeApplicationIsFrontmost((pid_t)pid) || !MacChromeBooleanAttribute(window, kAXMainAttribute) ||
                                   !MacChromeBooleanAttribute(element, kAXFocusedAttribute)) {
                            status = MacChromeAXElementFocusUnverified;
                        } else {
                            CGEventSetIntegerValueField(keyDown, kCGKeyboardEventKeycode, 0);
                            CGEventSetIntegerValueField(keyUp, kCGKeyboardEventKeycode, 0);
                            CGEventKeyboardSetUnicodeString(keyDown, tailLength, tail);
                            CGEventKeyboardSetUnicodeString(keyUp, tailLength, tail);
                            CGEventPost(kCGHIDEventTap, keyDown);
                            CGEventPost(kCGHIDEventTap, keyUp);
                            Boolean typed = false;
                            for (int attempt = 0; attempt < 20 && !typed; attempt++) {
                                usleep(50000);
                                CFTypeRef observed = NULL;
                                if (AXUIElementCopyAttributeValue(element, kAXValueAttribute, &observed) == kAXErrorSuccess &&
                                    observed != NULL && CFGetTypeID(observed) == CFStringGetTypeID()) {
                                    typed = CFStringCompare((CFStringRef)observed, text, 0) == kCFCompareEqualTo;
                                }
                                if (observed != NULL) CFRelease(observed);
                            }
                            if (!typed) {
                                status = MacChromeAXOperationFailed;
                            } else {
                                exactFocus = MacChromeBooleanAttribute(element, kAXFocusedAttribute);
                                if (!exactFocus) status = MacChromeAXElementFocusUnverified;
                            }
                        }
                        if (prefix != NULL) CFRelease(prefix);
                        if (selectedRange != NULL) CFRelease(selectedRange);
                        if (keyDown != NULL) CFRelease(keyDown);
                        if (keyUp != NULL) CFRelease(keyUp);
                        if (source != NULL) CFRelease(source);
                    }
                }
                CFRelease(element);
            }
            CFRelease(window);
        }
        CFRelease(marker);
        CFRelease(text);
        return status;
    }
}

int macChromeAXPress(int pid, const char *description) {
    @autoreleasepool {
        if (!AXIsProcessTrusted()) return MacChromeAXNotAuthorized;
        CFStringRef marker = MacChromeString(description);
        if (marker == NULL) {
            if (marker != NULL) CFRelease(marker);
            return MacChromeAXOperationFailed;
        }
        NSRunningApplication *running = nil;
        int status = MacChromeRunningApplication((pid_t)pid, &running);
        AXUIElementRef window = NULL;
        if (status == MacChromeAXOK && !MacChromeWaitUntilFrontmost((pid_t)pid)) status = MacChromeAXFocusUnverified;
        if (status == MacChromeAXOK) status = MacChromeMainWindow((pid_t)pid, &window);
        if (status == MacChromeAXOK && (!MacChromeApplicationIsFrontmost((pid_t)pid) || !MacChromeBooleanAttribute(window, kAXMainAttribute))) {
            status = MacChromeAXFocusUnverified;
        }
        if (status == MacChromeAXOK) {
            AXUIElementRef element = NULL;
            status = MacChromeElement(window, marker, NULL, &element);
            if (status == MacChromeAXOK) {
                CFArrayRef actions = NULL;
                AXError actionError = AXUIElementCopyActionNames(element, &actions);
                Boolean supportsPress = actionError == kAXErrorSuccess && actions != NULL &&
                    CFArrayContainsValue(actions, CFRangeMake(0, CFArrayGetCount(actions)), kAXPressAction);
                if (!supportsPress) {
                    status = MacChromeAXUnsupported;
                } else if (!MacChromeApplicationIsFrontmost((pid_t)pid) || !MacChromeBooleanAttribute(window, kAXMainAttribute)) {
                    status = MacChromeAXFocusUnverified;
                } else if (AXUIElementPerformAction(element, kAXPressAction) != kAXErrorSuccess) {
                    status = MacChromeAXOperationFailed;
                }
                if (actions != NULL) CFRelease(actions);
                CFRelease(element);
            }
            CFRelease(window);
        }
        CFRelease(marker);
        return status;
    }
}

// Upload uses Chrome's own native file chooser. The caller first correlates one
// visible DOM file input to this process with a cryptographic aria-label nonce
// and stages only the validated files in one private directory. This bridge
// presses only that unique element after proving the main window has no sheet,
// requires a bounded zero-to-one chooser transition, retains that exact AX
// chooser identity through navigation and selection, and waits for it to close.
// There are no coordinates, frontmost-window fallbacks, or System Events
// selectors.
int macChromeAXUploadFiles(int pid, const char *description, const char *stagingDirectory) {
    @autoreleasepool {
        if (!AXIsProcessTrusted()) return MacChromeAXNotAuthorized;
        CFStringRef marker = MacChromeString(description);
        CFStringRef directory = MacChromeString(stagingDirectory);
        CFStringRef directoryName = directory != NULL
            ? CFStringCreateCopy(kCFAllocatorDefault, (CFStringRef)[(NSString *)directory lastPathComponent])
            : NULL;
        if (marker == NULL || directory == NULL || directoryName == NULL || CFStringGetLength(directoryName) == 0) {
            if (marker != NULL) CFRelease(marker);
            if (directory != NULL) CFRelease(directory);
            if (directoryName != NULL) CFRelease(directoryName);
            return MacChromeAXOperationFailed;
        }
        NSRunningApplication *running = nil;
        int status = MacChromeRunningApplication((pid_t)pid, &running);
        AXUIElementRef window = NULL;
        if (status == MacChromeAXOK && !MacChromeWaitUntilFrontmost((pid_t)pid)) status = MacChromeAXFocusUnverified;
        if (status == MacChromeAXOK) status = MacChromeMainWindow((pid_t)pid, &window);
        if (status == MacChromeAXOK && (!MacChromeApplicationIsFrontmost((pid_t)pid) || !MacChromeBooleanAttribute(window, kAXMainAttribute))) {
            status = MacChromeAXFocusUnverified;
        }
        if (status == MacChromeAXOK) {
            AXUIElementRef element = NULL;
            status = MacChromeElement(window, marker, NULL, &element);
            if (status == MacChromeAXOK) {
                CFArrayRef actions = NULL;
                AXError actionError = AXUIElementCopyActionNames(element, &actions);
                Boolean supportsPress = actionError == kAXErrorSuccess && actions != NULL &&
                    CFArrayContainsValue(actions, CFRangeMake(0, CFArrayGetCount(actions)), kAXPressAction);
                if (!supportsPress) {
                    status = MacChromeAXUnsupported;
                } else if (!MacChromeApplicationIsFrontmost((pid_t)pid) || !MacChromeBooleanAttribute(window, kAXMainAttribute)) {
                    status = MacChromeAXFocusUnverified;
                } else if ((status = MacChromeRequireNoSheets(window)) != MacChromeAXOK) {
                    // Preserve the typed refusal. Absence is admitted only
                    // after a successful exact AXSheets read with count zero.
                } else if (AXUIElementPerformAction(element, kAXPressAction) != kAXErrorSuccess) {
                    status = MacChromeAXOperationFailed;
                }
                if (actions != NULL) CFRelease(actions);
                CFRelease(element);
            }
        }
        AXUIElementRef chooser = NULL;
        if (status == MacChromeAXOK) status = MacChromeWaitForSingleSheet(window, &chooser);
        if (status == MacChromeAXOK) status = MacChromeGuardChooser((pid_t)pid, window, chooser);
        if (status == MacChromeAXOK && !MacChromePostKey(5, kCGEventFlagMaskCommand | kCGEventFlagMaskShift, NULL)) {
            status = MacChromeAXFileChooserNavigationFailed;
        }
        if (status == MacChromeAXOK) usleep(200000);
        if (status == MacChromeAXOK) status = MacChromeGuardChooser((pid_t)pid, window, chooser);
        if (status == MacChromeAXOK && !MacChromePostKey(0, 0, directory)) status = MacChromeAXFileChooserNavigationFailed;
        if (status == MacChromeAXOK) status = MacChromeGuardChooser((pid_t)pid, window, chooser);
        if (status == MacChromeAXOK && !MacChromePostKey(36, 0, NULL)) status = MacChromeAXFileChooserNavigationFailed;
        if (status == MacChromeAXOK) usleep(500000);
        if (status == MacChromeAXOK) status = MacChromeGuardChooser((pid_t)pid, window, chooser);
        if (status == MacChromeAXOK && !MacChromeWaitForChooserDirectory(chooser, directoryName)) {
            status = MacChromeAXFileChooserNavigationFailed;
        }
        if (status == MacChromeAXOK) status = MacChromeGuardChooser((pid_t)pid, window, chooser);
        if (status == MacChromeAXOK && !MacChromePostKey(0, kCGEventFlagMaskCommand, NULL)) {
            status = MacChromeAXFileChooserSelectionFailed;
        }
        if (status == MacChromeAXOK) status = MacChromeGuardChooser((pid_t)pid, window, chooser);
        if (status == MacChromeAXOK && !MacChromePostKey(36, 0, NULL)) status = MacChromeAXFileChooserSelectionFailed;
        if (status == MacChromeAXOK) status = MacChromeWaitForNoSheets(window, chooser);
        if (status != MacChromeAXOK && window != NULL) MacChromeCancelChooser((pid_t)pid, window, chooser);
        if (chooser != NULL) CFRelease(chooser);
        if (window != NULL) CFRelease(window);
        CFRelease(marker);
        CFRelease(directory);
        CFRelease(directoryName);
        return status;
    }
}
