//go:build darwin && cgo

package chromectl

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestChromeAXProductionBridgeUsesConcreteNativeCalls(t *testing.T) {
	for name, call := range map[string]func() error{
		"type-text": func() error {
			return chromeAXTypeText(-1, "mac-infra impossible test element", "safe")
		},
		"press": func() error {
			return chromeAXPress(-1, "mac-infra impossible test element")
		},
		"upload": func() error {
			return chromeAXUploadFiles(-1, "mac-infra impossible test element", t.TempDir())
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := call()
			if err == nil {
				t.Fatal("invalid native target unexpectedly succeeded")
			}
			if strings.Contains(err.Error(), "invalid call shape") {
				t.Fatalf("production cgo call was rejected before reaching the native bridge: %v", err)
			}
			if !strings.Contains(err.Error(), "Chrome Accessibility refused:") {
				t.Fatalf("unexpected native bridge error: %v", err)
			}
		})
	}
}

func TestChromeAXUploadBridgeGuardsExactNonceAndChooserBeforeBoundedKeys(t *testing.T) {
	data, err := os.ReadFile("ax_darwin.m")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	start := strings.Index(source, "int macChromeAXUploadFiles")
	if start < 0 {
		t.Fatal("production upload bridge is missing")
	}
	body := source[start:]
	for _, required := range []string{
		"MacChromeElement(window, marker",
		"MacChromeRequireNoSheets(window)",
		"MacChromeWaitForSingleSheet",
		"MacChromeGuardChooser((pid_t)pid, window, chooser)",
		"MacChromeWaitForChooserDirectory(chooser, directoryName)",
		"MacChromeApplicationIsFrontmost((pid_t)pid)",
		"MacChromeWaitForNoSheets",
		"MacChromeCancelChooser",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("native upload bridge missing %q", required)
		}
	}
	for _, forbidden := range []string{"System Events", "CGEventCreateMouseEvent", "kCGMouseButtonLeft", "active tab"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("native upload bridge contains unbounded fallback %q", forbidden)
		}
	}
	press := strings.Index(body, "AXUIElementPerformAction(element, kAXPressAction)")
	empty := strings.Index(body, "MacChromeRequireNoSheets(window)")
	chooser := strings.Index(body, "MacChromeWaitForSingleSheet(window, &chooser)")
	navigate := strings.Index(body, "MacChromePostKey(5, kCGEventFlagMaskCommand | kCGEventFlagMaskShift, NULL)")
	verifiedDirectory := strings.Index(body, "MacChromeWaitForChooserDirectory(chooser, directoryName)")
	selectAll := strings.Index(body, "MacChromePostKey(0, kCGEventFlagMaskCommand, NULL)")
	if empty < 0 || press <= empty || chooser <= press || navigate <= chooser || verifiedDirectory <= navigate || selectAll <= verifiedDirectory {
		t.Fatalf("native upload sequence is not empty-sheet guard -> press -> chooser guard -> navigate -> verify staged directory -> select: empty=%d press=%d chooser=%d navigate=%d verify=%d select=%d", empty, press, chooser, navigate, verifiedDirectory, selectAll)
	}
}

// This test attacks the production macChromeAXUploadFiles decision path, not a
// separately modeled helper. One pre-existing sheet must make the exact
// pre-press branch nonzero before AXPress, and every keyboard event must remain
// behind equality with the retained post-press chooser. Narrowing count == 0 to
// admit one sheet, removing CFEqual, or reacquiring an unbound single sheet
// makes this named test fail.
func TestChromeAXUploadProductionPathRefusesPreexistingAndReplacedChooser(t *testing.T) {
	data, err := os.ReadFile("ax_darwin.m")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	requireNoStart := strings.Index(source, "static int MacChromeRequireNoSheets")
	singleStart := strings.Index(source, "static int MacChromeSingleSheet")
	if requireNoStart < 0 || singleStart <= requireNoStart {
		t.Fatal("production empty-sheet precondition is missing or unbounded")
	}
	requireNo := source[requireNoStart:singleStart]
	for _, required := range []string{
		"MacChromeCopySheets(window, &sheets)",
		"if (status != MacChromeAXOK) return status",
		"return count == 0 ? MacChromeAXOK : MacChromeAXFileChooserAmbiguous",
	} {
		if !strings.Contains(requireNo, required) {
			t.Fatalf("pre-existing chooser refusal is missing %q", required)
		}
	}

	sameStart := strings.Index(source, "static int MacChromeRequireSameSheet")
	guardStart := strings.Index(source, "static int MacChromeGuardChooser")
	if sameStart < 0 || guardStart <= sameStart {
		t.Fatal("production chooser identity gate is missing or unbounded")
	}
	requireSame := source[sameStart:guardStart]
	for _, required := range []string{
		"MacChromeSingleSheet(window, &current)",
		"Boolean same = CFEqual(current, expected)",
		"same ? MacChromeAXOK : MacChromeAXFileChooserReplaced",
	} {
		if !strings.Contains(requireSame, required) {
			t.Fatalf("replacement chooser refusal is missing %q", required)
		}
	}

	uploadStart := strings.Index(source, "int macChromeAXUploadFiles")
	if uploadStart < 0 {
		t.Fatal("production macChromeAXUploadFiles entry is missing")
	}
	upload := source[uploadStart:]
	precondition := strings.Index(upload, "else if ((status = MacChromeRequireNoSheets(window)) != MacChromeAXOK)")
	press := strings.Index(upload, "AXUIElementPerformAction(element, kAXPressAction)")
	firstKey := strings.Index(upload, "MacChromePostKey(")
	if precondition < 0 || press <= precondition || firstKey <= press {
		t.Fatalf("pre-existing chooser can reach press or keyboard events: precondition=%d press=%d firstKey=%d", precondition, press, firstKey)
	}
	if strings.Contains(upload, "MacChromeSingleSheet(window, &verifiedChooser)") {
		t.Fatal("native upload reacquires an unbound chooser after navigation")
	}
	if calls := strings.Count(upload, "MacChromeGuardChooser((pid_t)pid, window, chooser)"); calls != 6 {
		t.Fatalf("chooser identity guards=%d want=6 before five keyboard events and after navigation", calls)
	}

	position := 0
	for keyIndex := 0; ; keyIndex++ {
		relativeKey := strings.Index(upload[position:], "MacChromePostKey(")
		if relativeKey < 0 {
			if keyIndex != 5 {
				t.Fatalf("production upload keyboard events=%d want=5", keyIndex)
			}
			break
		}
		key := position + relativeKey
		guard := strings.LastIndex(upload[:key], "MacChromeGuardChooser((pid_t)pid, window, chooser)")
		previousKey := strings.LastIndex(upload[:key], "MacChromePostKey(")
		if guard < 0 || guard <= previousKey {
			t.Fatalf("keyboard event %d is not immediately preceded by fresh chooser identity evidence: guard=%d previousKey=%d key=%d", keyIndex+1, guard, previousKey, key)
		}
		position = key + len("MacChromePostKey(")
	}

	cancelStart := strings.Index(source, "static void MacChromeCancelChooser")
	processStart := strings.Index(source, "int macChromeAXProcessID")
	if cancelStart < 0 || processStart <= cancelStart {
		t.Fatal("bounded chooser cancellation is missing")
	}
	cancel := source[cancelStart:processStart]
	if !strings.Contains(cancel, "chooser != NULL && MacChromeGuardChooser(pid, window, chooser) == MacChromeAXOK") {
		t.Fatal("failure cleanup can send Escape to a pre-existing or replacement chooser")
	}
}

// TestChromeAXUploadProductionPathRefusesUnreadableSheetSequences calls the
// real macChromeAXUploadFiles entry while intercepting only its OS-facing
// AppKit, Accessibility, sleep, and keyboard dependencies. The production
// entry therefore owns which sheet-wait implementation runs at both call
// sites. Each unreadable appearance sequence includes enough later valid
// evidence to reach chooser keys if that call site is narrowed to retry the
// unreadable state; the test requires refusal at the first unknown snapshot
// with zero keyboard events. The closure sequence similarly supplies a later
// proven empty snapshot and requires the production entry to refuse instead of
// laundering the unreadable observation into successful closure.
func TestChromeAXUploadProductionPathRefusesUnreadableSheetSequences(t *testing.T) {
	sourcePath, err := filepath.Abs("ax_darwin.m")
	if err != nil {
		t.Fatal(err)
	}

	harness := `
#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#include <string.h>

enum {
    TestSheetsReadError = 1,
    TestSheetsNull = 2,
    TestSheetsWrongType = 3,
    TestSheetsEmpty = 4,
    TestSheetsOne = 5,
};

static int MacChromeTestObservations[32];
static int MacChromeTestObservationCount = 0;
static int MacChromeTestObservationIndex = 0;
static int MacChromeTestKeyboardPosts = 0;
static int MacChromeTestPresses = 0;
static CFStringRef MacChromeTestDirectoryName = NULL;

@interface MacChromeTestRunningApplication : NSObject
@property(nonatomic, readonly) pid_t processIdentifier;
@property(nonatomic, readonly) NSString *bundleIdentifier;
+ (NSArray<MacChromeTestRunningApplication *> *)runningApplicationsWithBundleIdentifier:(NSString *)bundleIdentifier;
@end

@implementation MacChromeTestRunningApplication
+ (NSArray<MacChromeTestRunningApplication *> *)runningApplicationsWithBundleIdentifier:(NSString *)bundleIdentifier {
    (void)bundleIdentifier;
    return @[[[MacChromeTestRunningApplication alloc] init]];
}
- (pid_t)processIdentifier { return 4242; }
- (NSString *)bundleIdentifier { return @"com.google.Chrome"; }
@end

@interface MacChromeTestWorkspace : NSObject
@property(nonatomic, readonly) MacChromeTestRunningApplication *frontmostApplication;
+ (MacChromeTestWorkspace *)sharedWorkspace;
@end

@implementation MacChromeTestWorkspace
+ (MacChromeTestWorkspace *)sharedWorkspace {
    static MacChromeTestWorkspace *workspace;
    if (workspace == nil) workspace = [[MacChromeTestWorkspace alloc] init];
    return workspace;
}
- (MacChromeTestRunningApplication *)frontmostApplication {
    return [[MacChromeTestRunningApplication alloc] init];
}
@end

static Boolean MacChromeTestAXIsProcessTrusted(void) { return true; }

static AXUIElementRef MacChromeTestAXUIElementCreateApplication(pid_t pid) {
    (void)pid;
    return (AXUIElementRef)CFRetain(CFSTR("test-application"));
}

static AXError MacChromeTestCopyAttributeValue(AXUIElementRef element, CFStringRef attribute, CFTypeRef *value);
#define AXIsProcessTrusted MacChromeTestAXIsProcessTrusted
#define AXUIElementCreateApplication MacChromeTestAXUIElementCreateApplication
#define AXUIElementCopyAttributeValue MacChromeTestCopyAttributeValue
#define NSRunningApplication MacChromeTestRunningApplication
#define NSWorkspace MacChromeTestWorkspace

static AXError MacChromeTestCopyActionNames(AXUIElementRef element, CFArrayRef *actions) {
    if (!CFEqual(element, CFSTR("test-input")) || actions == NULL) return kAXErrorFailure;
    const void *values[] = {kAXPressAction};
    *actions = CFArrayCreate(kCFAllocatorDefault, values, 1, &kCFTypeArrayCallBacks);
    return kAXErrorSuccess;
}

static AXError MacChromeTestPerformAction(AXUIElementRef element, CFStringRef action) {
    if (!CFEqual(element, CFSTR("test-input")) || !CFEqual(action, kAXPressAction)) return kAXErrorFailure;
    MacChromeTestPresses++;
    return kAXErrorSuccess;
}

static CGEventSourceRef MacChromeTestEventSourceCreate(CGEventSourceStateID stateID) {
    (void)stateID;
    return (CGEventSourceRef)CFRetain(CFSTR("test-event-source"));
}

static CGEventRef MacChromeTestKeyboardEventCreate(CGEventSourceRef source, CGKeyCode keyCode, bool keyDown) {
    (void)source;
    (void)keyCode;
    (void)keyDown;
    return (CGEventRef)CFRetain(CFSTR("test-key-event"));
}

static void MacChromeTestEventSetFlags(CGEventRef event, CGEventFlags flags) {
    (void)event;
    (void)flags;
}

static void MacChromeTestKeyboardEventSetUnicodeString(CGEventRef event, UniCharCount length, const UniChar *string) {
    (void)event;
    (void)length;
    (void)string;
}

static void MacChromeTestEventSetIntegerValueField(CGEventRef event, CGEventField field, int64_t value) {
    (void)event;
    (void)field;
    (void)value;
}

static void MacChromeTestEventPost(CGEventTapLocation tap, CGEventRef event) {
    (void)tap;
    (void)event;
    MacChromeTestKeyboardPosts++;
}

static int MacChromeTestSleep(useconds_t useconds) {
    (void)useconds;
    return 0;
}

#define AXUIElementCopyActionNames MacChromeTestCopyActionNames
#define AXUIElementPerformAction MacChromeTestPerformAction
#define CGEventSourceCreate MacChromeTestEventSourceCreate
#define CGEventCreateKeyboardEvent MacChromeTestKeyboardEventCreate
#define CGEventSetFlags MacChromeTestEventSetFlags
#define CGEventKeyboardSetUnicodeString MacChromeTestKeyboardEventSetUnicodeString
#define CGEventSetIntegerValueField MacChromeTestEventSetIntegerValueField
#define CGEventPost MacChromeTestEventPost
#define usleep MacChromeTestSleep
#include ` + strconv.Quote(sourcePath) + `

#undef usleep
#undef CGEventPost
#undef CGEventSetIntegerValueField
#undef CGEventKeyboardSetUnicodeString
#undef CGEventSetFlags
#undef CGEventCreateKeyboardEvent
#undef CGEventSourceCreate
#undef AXUIElementPerformAction
#undef AXUIElementCopyActionNames
#undef NSWorkspace
#undef NSRunningApplication
#undef AXUIElementCopyAttributeValue
#undef AXUIElementCreateApplication
#undef AXIsProcessTrusted

static void MacChromeTestSetObservations(const int *observations, int count) {
    memcpy(MacChromeTestObservations, observations, (size_t)count * sizeof(int));
    MacChromeTestObservationCount = count;
    MacChromeTestObservationIndex = 0;
    MacChromeTestKeyboardPosts = 0;
    MacChromeTestPresses = 0;
}

static AXError MacChromeTestCopyAttributeValue(AXUIElementRef element, CFStringRef attribute, CFTypeRef *value) {
    if (value == NULL) return kAXErrorFailure;
    *value = NULL;
    if (CFEqual(attribute, CFSTR("AXSheets"))) {
        if (!CFEqual(element, CFSTR("test-window")) ||
            MacChromeTestObservationIndex >= MacChromeTestObservationCount) return kAXErrorFailure;
        int observation = MacChromeTestObservations[MacChromeTestObservationIndex++];
        if (observation == TestSheetsReadError) return kAXErrorFailure;
        if (observation == TestSheetsNull) return kAXErrorSuccess;
        if (observation == TestSheetsWrongType) {
            *value = CFRetain(CFSTR("not-an-array"));
            return kAXErrorSuccess;
        }
        if (observation == TestSheetsEmpty) {
            *value = CFArrayCreate(kCFAllocatorDefault, NULL, 0, &kCFTypeArrayCallBacks);
            return kAXErrorSuccess;
        }
        if (observation == TestSheetsOne) {
            const void *values[] = {CFSTR("test-chooser")};
            *value = CFArrayCreate(kCFAllocatorDefault, values, 1, &kCFTypeArrayCallBacks);
            return kAXErrorSuccess;
        }
        return kAXErrorFailure;
    }
    if (CFEqual(attribute, kAXWindowsAttribute) && CFEqual(element, CFSTR("test-application"))) {
        const void *values[] = {CFSTR("test-window")};
        *value = CFArrayCreate(kCFAllocatorDefault, values, 1, &kCFTypeArrayCallBacks);
        return kAXErrorSuccess;
    }
    if (CFEqual(attribute, kAXMainAttribute) && CFEqual(element, CFSTR("test-window"))) {
        *value = CFRetain(kCFBooleanTrue);
        return kAXErrorSuccess;
    }
    if (CFEqual(attribute, kAXDescriptionAttribute)) {
        if (CFEqual(element, CFSTR("test-input"))) *value = CFRetain(CFSTR("upload-marker"));
        else *value = CFRetain(CFSTR("not-the-marker"));
        return kAXErrorSuccess;
    }
    if (CFEqual(attribute, kAXChildrenAttribute)) {
        if (CFEqual(element, CFSTR("test-window"))) {
            const void *values[] = {CFSTR("test-input")};
            *value = CFArrayCreate(kCFAllocatorDefault, values, 1, &kCFTypeArrayCallBacks);
        } else {
            *value = CFArrayCreate(kCFAllocatorDefault, NULL, 0, &kCFTypeArrayCallBacks);
        }
        return kAXErrorSuccess;
    }
    if (CFEqual(attribute, kAXValueAttribute) && CFEqual(element, CFSTR("test-chooser")) &&
        MacChromeTestDirectoryName != NULL) {
        *value = CFRetain(MacChromeTestDirectoryName);
        return kAXErrorSuccess;
    }
    if (CFEqual(attribute, kAXRoleAttribute)) {
        *value = CFRetain(CFSTR("AXGroup"));
        return kAXErrorSuccess;
    }
    return kAXErrorFailure;
}

static int MacChromeTestRun(const int *observations, int count, const char *directory,
                            int wantStatus, int wantObservationIndex, int wantKeyboardPosts) {
    MacChromeTestSetObservations(observations, count);
    int status = macChromeAXUploadFiles(4242, "upload-marker", directory);
    return status == wantStatus &&
        MacChromeTestObservationIndex == wantObservationIndex &&
        MacChromeTestKeyboardPosts == wantKeyboardPosts &&
        MacChromeTestPresses == 1;
}

static int MacChromeTestAppearanceRefusal(int unreadable, const char *directory) {
    int observations[] = {
        TestSheetsEmpty,
        unreadable,
        TestSheetsOne,
        TestSheetsOne, TestSheetsOne, TestSheetsOne,
        TestSheetsOne, TestSheetsOne, TestSheetsOne,
        TestSheetsEmpty,
    };
    return MacChromeTestRun(
        observations,
        (int)(sizeof(observations) / sizeof(observations[0])),
        directory,
        MacChromeAXFileChooserUnreadable,
        2,
        0
    );
}

static int MacChromeTestClosureRefusal(const char *directory) {
    int observations[] = {
        TestSheetsEmpty,
        TestSheetsOne,
        TestSheetsOne, TestSheetsOne, TestSheetsOne,
        TestSheetsOne, TestSheetsOne, TestSheetsOne,
        TestSheetsReadError,
        TestSheetsEmpty,
    };
    return MacChromeTestRun(
        observations,
        (int)(sizeof(observations) / sizeof(observations[0])),
        directory,
        MacChromeAXFileChooserUnreadable,
        10,
        10
    );
}

static int MacChromeTestValidAppearanceRetry(const char *directory) {
    int observations[] = {
        TestSheetsEmpty,
        TestSheetsEmpty,
        TestSheetsOne,
        TestSheetsOne, TestSheetsOne, TestSheetsOne,
        TestSheetsOne, TestSheetsOne, TestSheetsOne,
        TestSheetsEmpty,
    };
    return MacChromeTestRun(
        observations,
        (int)(sizeof(observations) / sizeof(observations[0])),
        directory,
        MacChromeAXOK,
        10,
        10
    );
}

static int MacChromeTestValidClosureRetry(const char *directory) {
    int observations[] = {
        TestSheetsEmpty,
        TestSheetsOne,
        TestSheetsOne, TestSheetsOne, TestSheetsOne,
        TestSheetsOne, TestSheetsOne, TestSheetsOne,
        TestSheetsOne,
        TestSheetsEmpty,
    };
    return MacChromeTestRun(
        observations,
        (int)(sizeof(observations) / sizeof(observations[0])),
        directory,
        MacChromeAXOK,
        10,
        10
    );
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2) return 10;
        NSString *path = [NSString stringWithUTF8String:argv[1]];
        MacChromeTestDirectoryName = CFStringCreateCopy(
            kCFAllocatorDefault,
            (CFStringRef)[path lastPathComponent]
        );
        if (MacChromeTestDirectoryName == NULL) return 11;
        if (!MacChromeTestAppearanceRefusal(TestSheetsReadError, argv[1])) return 21;
        if (!MacChromeTestAppearanceRefusal(TestSheetsNull, argv[1])) return 22;
        if (!MacChromeTestAppearanceRefusal(TestSheetsWrongType, argv[1])) return 23;
        if (!MacChromeTestClosureRefusal(argv[1])) return 24;
        if (!MacChromeTestValidAppearanceRetry(argv[1])) return 25;
        if (!MacChromeTestValidClosureRetry(argv[1])) return 26;
        CFRelease(MacChromeTestDirectoryName);
        return 0;
    }
}
`
	harnessPath := filepath.Join(t.TempDir(), "sheet_sequence_harness.m")
	if err := os.WriteFile(harnessPath, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(t.TempDir(), "sheet_sequence_harness")
	compile := exec.Command(
		"xcrun", "clang",
		"-framework", "AppKit",
		"-framework", "ApplicationServices",
		"-o", binaryPath,
		harnessPath,
	)
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("compile production AXSheets sequence harness: %v\n%s", err, output)
	}
	if output, err := exec.Command(binaryPath, t.TempDir()).CombinedOutput(); err != nil {
		t.Fatalf("production macChromeAXUploadFiles sheet sequence gate admitted unreadable evidence: %v\n%s", err, output)
	}
}

func TestChromeAXFileChooserUnreadableStatusIsDistinct(t *testing.T) {
	if got := chromeAXStatus(17); got != "file-chooser-unreadable" {
		t.Fatalf("unreadable AXSheets status=%q", got)
	}
	if chromeAXStatus(17) == chromeAXStatus(12) {
		t.Fatal("unreadable AXSheets evidence is collapsed into retryable chooser absence")
	}
}

func TestChromeAXProductionBridgeUsesUniqueMainWindowNonceAndGuardsPress(t *testing.T) {
	data, err := os.ReadFile("ax_darwin.m")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, forbidden := range []string{"kAXTitleAttribute", "CFStringFind"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("native exact-target bridge still correlates windows by title via %q", forbidden)
		}
	}
	for _, required := range []string{"MacChromeMainWindow", "kAXMainAttribute", "MacChromeElement(window, marker", "MacChromeApplicationIsFrontmost((pid_t)pid)"} {
		if !strings.Contains(source, required) {
			t.Fatalf("native exact-target bridge missing %q", required)
		}
	}
	pressStart := strings.Index(source, "int macChromeAXPress")
	if pressStart < 0 {
		t.Fatal("production macChromeAXPress entry is missing")
	}
	press := source[pressStart:]
	perform := strings.Index(press, "AXUIElementPerformAction(element, kAXPressAction)")
	guard := strings.Index(press, "!MacChromeApplicationIsFrontmost((pid_t)pid) || !MacChromeBooleanAttribute(window, kAXMainAttribute)")
	if guard < 0 || perform < 0 || guard >= perform {
		t.Fatalf("production macChromeAXPress must fail closed on active/main-window drift immediately before AXPress: guard=%d perform=%d", guard, perform)
	}
}

func TestChromeAXProductionBridgeBoundsActivationSettleBeforeNativeActions(t *testing.T) {
	data, err := os.ReadFile("ax_darwin.m")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"static Boolean MacChromeApplicationIsFrontmost",
		"frontmost.processIdentifier == pid",
		"static Boolean MacChromeWaitUntilFrontmost",
		"attempt < 10",
		"usleep(50000)",
		"!MacChromeWaitUntilFrontmost((pid_t)pid)",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("native activation settle gate missing %q", required)
		}
	}
	if calls := strings.Count(source, "!MacChromeWaitUntilFrontmost((pid_t)pid)"); calls != 3 {
		t.Fatalf("activation settle gate call count=%d want 3 (type, press, and upload)", calls)
	}
	for _, action := range []string{
		"AXUIElementSetAttributeValue(element, kAXValueAttribute, prefix)",
		"AXUIElementPerformAction(element, kAXPressAction)",
	} {
		if strings.Index(source, "!MacChromeWaitUntilFrontmost((pid_t)pid)") >= strings.Index(source, action) {
			t.Fatalf("activation settle gate must precede native action %q", action)
		}
	}
}

// The type path's last foreground gate before writing the field value must use
// freshly queried frontmost evidence. A cached NSRunningApplication.active
// snapshot taken before activation is stale and was observed admitting native
// typing after Chrome had already lost the foreground.
//
// The keystroke itself must also be non-destructive. An append-then-backspace
// pulse silently deletes a genuine character whenever the appended key is
// dropped: a live fixture requesting "Beta" was left holding "Bet". The bridge
// must instead seed everything but the final character and let one HID
// keystroke produce that character, then verify the observed value equals the
// request before reporting success.
func TestChromeAXProductionBridgeTypesNonDestructivelyBehindFreshFrontmostEvidence(t *testing.T) {
	data, err := os.ReadFile("ax_darwin.m")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	if strings.Contains(source, ".active") {
		t.Fatal("native bridge must not gate native actions on a stale NSRunningApplication.active snapshot")
	}
	typeStart := strings.Index(source, "int macChromeAXTypeText")
	if typeStart < 0 {
		t.Fatal("production macChromeAXTypeText entry is missing")
	}
	typeBody := source[typeStart:]
	if pressStart := strings.Index(typeBody, "int macChromeAXPress"); pressStart > 0 {
		typeBody = typeBody[:pressStart]
	}

	// The value seed must sit behind a fresh frontmost/main-window gate.
	seed := strings.Index(typeBody, "AXUIElementSetAttributeValue(element, kAXValueAttribute, prefix)")
	seedGuard := strings.LastIndex(typeBody[:max(seed, 0)], "!MacChromeApplicationIsFrontmost((pid_t)pid) || !MacChromeBooleanAttribute(window, kAXMainAttribute)")
	if seed < 0 || seedGuard < 0 {
		t.Fatalf("value seed must fail closed on fresh frontmost/main-window drift: guard=%d seed=%d", seedGuard, seed)
	}

	// The HID keystroke must re-verify fresh frontmost, main-window, and
	// element-focus evidence immediately before posting.
	post := strings.Index(typeBody, "CGEventPost(kCGHIDEventTap, keyDown)")
	postGuard := strings.LastIndex(typeBody[:max(post, 0)], "!MacChromeBooleanAttribute(element, kAXFocusedAttribute)")
	if post < 0 || postGuard < 0 || postGuard <= seedGuard {
		t.Fatalf("HID keystroke must re-verify fresh focus evidence before posting: seedGuard=%d postGuard=%d post=%d", seedGuard, postGuard, post)
	}

	// No destructive deletion may be synthesized: keycode 51 is Delete.
	if strings.Contains(typeBody, "kCGKeyboardEventKeycode, 51") {
		t.Fatal("native typing must not synthesize a backspace: a dropped append silently deletes a genuine character")
	}

	// The observed field value must be compared against the request before
	// success is reported, and a mismatch must fail closed.
	verify := strings.Index(typeBody, "CFStringCompare((CFStringRef)observed, text, 0) == kCFCompareEqualTo")
	if verify < 0 || verify < post {
		t.Fatalf("typed value must be verified against the request after the keystroke: verify=%d post=%d", verify, post)
	}
	if !strings.Contains(typeBody, "if (!typed) {\n                                status = MacChromeAXOperationFailed;") {
		t.Fatal("an unverified typed value must fail closed instead of reporting success")
	}
}
