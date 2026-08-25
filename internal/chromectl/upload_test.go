package chromectl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/browsersession"
)

func validUploadRequest(paths ...string) UploadRequest {
	return UploadRequest{
		Version:           UploadVersion,
		InputSelector:     `input[data-testid="attachment"]`,
		Paths:             paths,
		AllowedExtensions: []string{".pdf", ".doc"},
		MaxFileBytes:      1024,
		MaxTotalBytes:     2048,
		TimeoutMS:         1000,
	}
}

func TestDecodeUploadRequestRejectsUnknownAndTrailingJSON(t *testing.T) {
	const privateMarker = "/private/task/private-upload-source.pdf"
	for name, input := range map[string]string{
		"unknown":  `{"version":1,"inputSelector":"#f","paths":["/tmp/a.pdf"],"allowedExtensions":[".pdf"],"maxFileBytes":1,"maxTotalBytes":1,"` + privateMarker + `":true}`,
		"trailing": `{"version":1,"inputSelector":"#f","paths":["/tmp/a.pdf"],"allowedExtensions":[".pdf"],"maxFileBytes":1,"maxTotalBytes":1} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeUploadRequest(strings.NewReader(input)); err == nil {
				t.Fatal("unsafe request accepted")
			} else if strings.Contains(err.Error(), privateMarker) {
				t.Fatalf("private upload request reflected in decoder error: %v", err)
			}
		})
	}
}

func TestPrepareUploadStagesOnlyValidatedRegularFilesPrivately(t *testing.T) {
	sourceDir := t.TempDir()
	first := filepath.Join(sourceDir, "evidence.pdf")
	second := filepath.Join(sourceDir, "order.doc")
	if err := os.WriteFile(first, []byte("pdf-evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("court-order"), 0o600); err != nil {
		t.Fatal(err)
	}
	staged, err := prepareUpload(validUploadRequest(first, second))
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(staged.Directory)
	info, err := os.Stat(staged.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("staging directory mode=%o want 700", info.Mode().Perm())
	}
	for _, file := range staged.Files {
		data, err := os.ReadFile(filepath.Join(staged.Directory, file.Name))
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(data)) != file.Size {
			t.Fatalf("staged %s size=%d want=%d", file.Name, len(data), file.Size)
		}
		stagedInfo, err := os.Stat(filepath.Join(staged.Directory, file.Name))
		if err != nil {
			t.Fatal(err)
		}
		if stagedInfo.Mode().Perm() != 0o600 {
			t.Fatalf("staged %s mode=%o want 600", file.Name, stagedInfo.Mode().Perm())
		}
	}
}

func TestPrepareUploadRejectsSymlinkExtensionSizeAndDuplicateBasename(t *testing.T) {
	dir := t.TempDir()
	pdf := filepath.Join(dir, "a.pdf")
	if err := os.WriteFile(pdf, []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.pdf")
	if err := os.Symlink(pdf, link); err != nil {
		t.Fatal(err)
	}
	otherDir := t.TempDir()
	duplicate := filepath.Join(otherDir, "a.pdf")
	if err := os.WriteFile(duplicate, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	text := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(text, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]UploadRequest{
		"symlink":        validUploadRequest(link),
		"extension":      validUploadRequest(text),
		"file-size":      func() UploadRequest { r := validUploadRequest(pdf); r.MaxFileBytes = 3; return r }(),
		"total-size":     func() UploadRequest { r := validUploadRequest(pdf); r.MaxTotalBytes = 3; return r }(),
		"duplicate-name": validUploadRequest(pdf, duplicate),
	} {
		t.Run(name, func(t *testing.T) {
			if staged, err := prepareUpload(request); err == nil {
				_ = os.RemoveAll(staged.Directory)
				t.Fatal("unsafe upload files accepted")
			}
		})
	}
}

func TestUploadJavaScriptRequiresUniqueVisibleFileInputAndTrustedExactMetadata(t *testing.T) {
	files := []uploadFile{{Name: "a.pdf", Size: 12, MIME: "application/pdf"}, {Name: "b.doc", Size: 34, MIME: "application/msword"}}
	prepare := uploadPrepareJavaScript("#files", files, "nonce", "state")
	for _, required := range []string{
		"querySelectorAll", `toLowerCase()!=="file"`, "node.hidden", `getAttribute("aria-hidden")`,
		"elementFromPoint", "depth>64", "opacity<=0", `filter!=="none"`, "maskImages.length===0", `maskImages.some(value=>value!=="none")`, "input-hidden", `getAttribute("accept")`,
		"input-accept-unsupported", "input-accept-mismatch", `token==="image/*"`,
		"input-not-multiple", "input-not-empty", `event.isTrusted===true`,
	} {
		if !strings.Contains(prepare, required) {
			t.Fatalf("upload prepare missing %q", required)
		}
	}
	inspect := uploadInspectJavaScript("#files", "state")
	for _, required := range []string{"untrusted-change", "file-count-mismatch", "file-metadata-mismatch", "file.name", "file.size", `outcome("selected")`} {
		if !strings.Contains(inspect, required) {
			t.Fatalf("upload inspect missing %q", required)
		}
	}
}

type uploadDOMScenario struct {
	Accept             string `json:"accept"`
	AncestorOpacity    string `json:"ancestorOpacity"`
	AncestorVisibility string `json:"ancestorVisibility"`
	AncestorFilter     string `json:"ancestorFilter"`
	AncestorMaskImage  string `json:"ancestorMaskImage"`
	AncestorWebkitMask string `json:"ancestorWebkitMask"`
	AncestorAriaHidden bool   `json:"ancestorAriaHidden"`
	HitInput           bool   `json:"hitInput"`
}

func executeUploadPageProgram(t *testing.T, source string, scenario uploadDOMScenario) string {
	t.Helper()
	encoded, err := json.Marshal(scenario)
	if err != nil {
		t.Fatal(err)
	}
	program := fmt.Sprintf(`
const scenario=%s;
function HTMLInputElement(){}
const attributes=value=>({
  accept:value,
  "aria-hidden":null,
  "aria-label":null
});
const ancestor={nodeType:1,hidden:false,parentElement:null,_attributes:attributes(null),_style:{display:"block",visibility:scenario.ancestorVisibility,opacity:scenario.ancestorOpacity,pointerEvents:"auto",filter:scenario.ancestorFilter||"none",maskImage:scenario.ancestorMaskImage||"none",webkitMaskImage:scenario.ancestorWebkitMask||"none"}};
ancestor.getAttribute=name=>name==="aria-hidden"&&scenario.ancestorAriaHidden?"true":ancestor._attributes[name];
const input=new HTMLInputElement();
input.nodeType=1;input.type="file";input.disabled=false;input.hidden=false;input.multiple=false;input.files=[];input.parentElement=ancestor;
input._attributes=attributes(scenario.accept);input._style={display:"block",visibility:"visible",opacity:"1",pointerEvents:"auto",filter:"none",maskImage:"none",webkitMaskImage:"none"};
input.getAttribute=name=>Object.prototype.hasOwnProperty.call(input._attributes,name)?input._attributes[name]:null;
input.setAttribute=(name,value)=>{input._attributes[name]=String(value);};input.removeAttribute=name=>{input._attributes[name]=null;};
input.getClientRects=()=>[{left:10,top:10,right:110,bottom:50,width:100,height:40}];input.contains=node=>node===input;
input.addEventListener=()=>{};input.removeEventListener=()=>{};
const document={readyState:"complete",querySelectorAll:()=>[input],elementFromPoint:()=>scenario.hitInput?input:ancestor};
const location={origin:"https://example.com"},innerWidth=1024,innerHeight=768;
function getComputedStyle(node){return node._style;}
%s
`, string(encoded), source)
	cmd := exec.Command("/usr/bin/osascript", "-l", "JavaScript")
	cmd.Stdin = strings.NewReader(program)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("execute generated upload page program: %v: %s", err, output)
	}
	return strings.TrimSpace(string(output))
}

func executeUploadInspectProgram(t *testing.T, source string, expected, actual []uploadFile) string {
	t.Helper()
	return executeUploadBoundInputProgram(t, source, expected, actual, uploadDOMScenario{
		Accept:             ".pdf",
		AncestorOpacity:    "1",
		AncestorVisibility: "visible",
		HitInput:           true,
	}, "file", false, true)
}

func executeUploadBoundInputProgram(t *testing.T, source string, expected, actual []uploadFile, scenario uploadDOMScenario, inputType string, disabled, changed bool) string {
	t.Helper()
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	actualJSON, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	scenarioJSON, err := json.Marshal(scenario)
	if err != nil {
		t.Fatal(err)
	}
	program := fmt.Sprintf(`
const scenario=%s;
function HTMLInputElement(){}
const attributes=value=>({accept:value,"aria-hidden":null,"aria-label":"nonce"});
const ancestor={nodeType:1,hidden:false,parentElement:null,_attributes:attributes(null),_style:{display:"block",visibility:scenario.ancestorVisibility,opacity:scenario.ancestorOpacity,pointerEvents:"auto",filter:scenario.ancestorFilter||"none",maskImage:scenario.ancestorMaskImage||"none",webkitMaskImage:scenario.ancestorWebkitMask||"none"}};
ancestor.getAttribute=name=>name==="aria-hidden"&&scenario.ancestorAriaHidden?"true":ancestor._attributes[name];
const base=new HTMLInputElement();
base.nodeType=1;base.type=%q;base.disabled=%t;base.hidden=false;base.multiple=%t;base.files=%s;base.parentElement=ancestor;
base._attributes=attributes(scenario.accept);base._style={display:"block",visibility:"visible",opacity:"1",pointerEvents:"auto",filter:"none",maskImage:"none",webkitMaskImage:"none"};
base.getAttribute=name=>Object.prototype.hasOwnProperty.call(base._attributes,name)?base._attributes[name]:null;
base.setAttribute=(name,value)=>{base._attributes[name]=String(value);};base.removeAttribute=name=>{base._attributes[name]=null;};
base.getClientRects=()=>[{left:10,top:10,right:110,bottom:50,width:100,height:40}];base.contains=node=>node===input;
base.addEventListener=()=>{};base.removeEventListener=()=>{};
const state={expected:%s,changed:%t,trusted:%t,marker:"nonce",oldAria:null};
const input=new Proxy(base,{get:(target,property,receiver)=>Reflect.has(target,property)?Reflect.get(target,property,receiver):state});
const document={readyState:"complete",querySelectorAll:()=>[input],elementFromPoint:()=>scenario.hitInput?input:ancestor};
const location={origin:"https://example.com"},innerWidth=1024,innerHeight=768;
function getComputedStyle(node){return node._style;}
%s
`, string(scenarioJSON), inputType, disabled, len(expected) > 1, string(actualJSON), string(expectedJSON), changed, changed, source)
	cmd := exec.Command("/usr/bin/osascript", "-l", "JavaScript")
	cmd.Stdin = strings.NewReader(program)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("execute generated upload bound-input program: %v: %s", err, output)
	}
	return strings.TrimSpace(string(output))
}

func fakeExactTargetScript(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(path, []byte(`#!/bin/sh
case "$*" in
  *chrome-exact-target*)
    /usr/bin/jq -cn '{__macChromeExactTarget:"works.relux.mac-infra/chrome-exact-target/v1",outcome:"ok",origin:"https://example.com",active:true}'
    ;;
  *) exit 99 ;;
esac
`), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestUploadPrepareProductionJavaScriptExecutesBoundedAcceptContract(t *testing.T) {
	for _, tc := range []struct {
		name    string
		file    uploadFile
		accept  string
		outcome string
	}{
		{name: "extension", file: uploadFile{Name: "evidence.PDF", Size: 8, MIME: "application/pdf"}, accept: ".pdf", outcome: "ready"},
		{name: "exact-mime", file: uploadFile{Name: "evidence.pdf", Size: 8, MIME: "application/pdf"}, accept: "application/pdf", outcome: "ready"},
		{name: "wildcard-mime", file: uploadFile{Name: "image.png", Size: 8, MIME: "image/png"}, accept: "image/*", outcome: "ready"},
		{name: "empty-means-unrestricted", file: uploadFile{Name: "evidence.pdf", Size: 8, MIME: "application/pdf"}, accept: "", outcome: "ready"},
		{name: "extension-mismatch", file: uploadFile{Name: "evidence.pdf", Size: 8, MIME: "application/pdf"}, accept: ".png", outcome: "input-accept-mismatch"},
		{name: "mime-mismatch", file: uploadFile{Name: "evidence.pdf", Size: 8, MIME: "application/pdf"}, accept: "image/png", outcome: "input-accept-mismatch"},
		{name: "wildcard-mismatch", file: uploadFile{Name: "evidence.pdf", Size: 8, MIME: "application/pdf"}, accept: "image/*", outcome: "input-accept-mismatch"},
		{name: "unsupported-wildcard", file: uploadFile{Name: "evidence.pdf", Size: 8, MIME: "application/pdf"}, accept: "application/*", outcome: "input-accept-unsupported"},
		{name: "mime-parameters", file: uploadFile{Name: "evidence.pdf", Size: 8, MIME: "application/pdf"}, accept: "application/pdf;charset=utf-8", outcome: "input-accept-unsupported"},
		{name: "duplicate-token", file: uploadFile{Name: "evidence.pdf", Size: 8, MIME: "application/pdf"}, accept: ".pdf,.PDF", outcome: "input-accept-unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := uploadPrepareJavaScript("#file", []uploadFile{tc.file}, "nonce", "state")
			got := executeUploadPageProgram(t, source, uploadDOMScenario{Accept: tc.accept, AncestorOpacity: "1", AncestorVisibility: "visible", HitInput: true})
			if got != tc.outcome {
				t.Fatalf("generated upload page gate outcome=%q want=%q", got, tc.outcome)
			}
		})
	}
}

func TestUploadFilesProductionCompositionRefusesDOMAcceptAndEffectiveVisibilityBeforeNativeAccess(t *testing.T) {
	for _, tc := range []struct {
		name     string
		scenario uploadDOMScenario
		outcome  string
	}{
		{name: "accept-extension-mismatch", scenario: uploadDOMScenario{Accept: ".png", AncestorOpacity: "1", AncestorVisibility: "visible", HitInput: true}, outcome: "input-accept-mismatch"},
		{name: "accept-mime-mismatch", scenario: uploadDOMScenario{Accept: "image/png", AncestorOpacity: "1", AncestorVisibility: "visible", HitInput: true}, outcome: "input-accept-mismatch"},
		{name: "accept-unsupported", scenario: uploadDOMScenario{Accept: "application/*", AncestorOpacity: "1", AncestorVisibility: "visible", HitInput: true}, outcome: "input-accept-unsupported"},
		{name: "ancestor-opacity-zero", scenario: uploadDOMScenario{Accept: ".pdf", AncestorOpacity: "0", AncestorVisibility: "visible", HitInput: true}, outcome: "input-hidden"},
		{name: "ancestor-filter-opacity-zero", scenario: uploadDOMScenario{Accept: ".pdf", AncestorOpacity: "1", AncestorVisibility: "visible", AncestorFilter: "opacity(0)", HitInput: true}, outcome: "input-hidden"},
		{name: "ancestor-filter-blur", scenario: uploadDOMScenario{Accept: ".pdf", AncestorOpacity: "1", AncestorVisibility: "visible", AncestorFilter: "blur(1px)", HitInput: true}, outcome: "input-hidden"},
		{name: "ancestor-transparent-mask", scenario: uploadDOMScenario{Accept: ".pdf", AncestorOpacity: "1", AncestorVisibility: "visible", AncestorMaskImage: "linear-gradient(transparent, transparent)", HitInput: true}, outcome: "input-hidden"},
		{name: "ancestor-webkit-transparent-mask", scenario: uploadDOMScenario{Accept: ".pdf", AncestorOpacity: "1", AncestorVisibility: "visible", AncestorWebkitMask: "linear-gradient(transparent, transparent)", HitInput: true}, outcome: "input-hidden"},
		{name: "ancestor-visibility-hidden", scenario: uploadDOMScenario{Accept: ".pdf", AncestorOpacity: "1", AncestorVisibility: "hidden", HitInput: true}, outcome: "input-hidden"},
		{name: "ancestor-aria-hidden", scenario: uploadDOMScenario{Accept: ".pdf", AncestorOpacity: "1", AncestorVisibility: "visible", AncestorAriaHidden: true, HitInput: true}, outcome: "input-hidden"},
		{name: "hit-test-misses-input", scenario: uploadDOMScenario{Accept: ".pdf", AncestorOpacity: "1", AncestorVisibility: "visible", HitInput: false}, outcome: "input-hidden"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "evidence.pdf")
			if err := os.WriteFile(source, []byte("evidence"), 0o600); err != nil {
				t.Fatal(err)
			}
			focusMarker := filepath.Join(t.TempDir(), "focus-reached")
			t.Setenv("UPLOAD_FOCUS_MARKER", focusMarker)
			fake := filepath.Join(t.TempDir(), "osascript")
			if err := os.WriteFile(fake, []byte("#!/bin/sh\ntouch \"$UPLOAD_FOCUS_MARKER\"\nexit 99\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			pageCalls, axCalls := 0, 0
			session := Session{
				OsaScriptPath: fake,
				uploadPageJS: func(_ context.Context, windowID, tabID, origin, pageSource string) (browsersession.ExecutionResult, error) {
					pageCalls++
					if windowID != "11" || tabID != "22" || origin != "https://example.com" {
						t.Fatalf("production upload composition lost exact target: %s/%s %s", windowID, tabID, origin)
					}
					value := executeUploadPageProgram(t, pageSource, tc.scenario)
					return browsersession.ExecutionResult{Value: value, Origin: origin, ReadyState: "complete"}, nil
				},
				AXProcessID:   func() (int, error) { axCalls++; return 123, nil },
				AXUploadFiles: func(int, string, string) error { axCalls++; return nil },
			}
			_, err := session.UploadFiles(context.Background(), "11", "22", "https://example.com", validUploadRequest(source))
			var refusal *UploadRefusalError
			if !errors.As(err, &refusal) || refusal.Kind != tc.outcome {
				t.Fatalf("production upload error=%v want refusal %q", err, tc.outcome)
			}
			if pageCalls != 1 {
				t.Fatalf("generated page gate calls=%d want=1", pageCalls)
			}
			if axCalls != 0 {
				t.Fatalf("refused generated page gate reached native upload: calls=%d", axCalls)
			}
			if _, statErr := os.Stat(focusMarker); !os.IsNotExist(statErr) {
				t.Fatalf("refused generated page gate reached Chrome focus: %v", statErr)
			}
		})
	}
}

func TestUploadFilesProductionPathRejectsNonExactTargetBeforePageOrNativeAccess(t *testing.T) {
	source := filepath.Join(t.TempDir(), "evidence.pdf")
	if err := os.WriteFile(source, []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "browser-contacted")
	t.Setenv("UPLOAD_BROWSER_MARKER", marker)
	fake := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ntouch \"$UPLOAD_BROWSER_MARKER\"\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	axCalls := 0
	session := Session{
		OsaScriptPath: fake,
		AXProcessID: func() (int, error) {
			axCalls++
			return 123, nil
		},
		AXUploadFiles: func(int, string, string) error {
			axCalls++
			return nil
		},
	}
	for name, target := range map[string][3]string{
		"zero-window":          {"0", "22", "https://example.com"},
		"non-canonical-tab":    {"11", "022", "https://example.com"},
		"origin-with-path":     {"11", "22", "https://example.com/form"},
		"origin-with-query":    {"11", "22", "https://example.com?tab=1"},
		"origin-with-fragment": {"11", "22", "https://example.com#upload"},
		"mixed-case-origin":    {"11", "22", "https://Example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := session.UploadFiles(context.Background(), target[0], target[1], target[2], validUploadRequest(source)); err == nil {
				t.Fatal("non-exact target reached the upload path")
			}
		})
	}
	if axCalls != 0 {
		t.Fatalf("non-exact target reached native upload: calls=%d", axCalls)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("non-exact target reached page-context automation: %v", err)
	}
}

func TestUploadFilesProductionPathRejectsInvalidFilesBeforePageOrNativeAccess(t *testing.T) {
	dir := t.TempDir()
	pdf := filepath.Join(dir, "evidence.pdf")
	if err := os.WriteFile(pdf, []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "link.pdf")
	if err := os.Symlink(pdf, symlink); err != nil {
		t.Fatal(err)
	}
	text := filepath.Join(dir, "evidence.txt")
	if err := os.WriteFile(text, []byte("text"), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "browser-contacted")
	t.Setenv("UPLOAD_BROWSER_MARKER", marker)
	fake := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ntouch \"$UPLOAD_BROWSER_MARKER\"\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	axCalls := 0
	session := Session{
		OsaScriptPath: fake,
		AXProcessID: func() (int, error) {
			axCalls++
			return 123, nil
		},
		AXUploadFiles: func(int, string, string) error {
			axCalls++
			return nil
		},
	}
	tooMany := make([]string, maxUploadFiles+1)
	for i := range tooMany {
		tooMany[i] = pdf
	}
	for name, request := range map[string]UploadRequest{
		"symlink":            validUploadRequest(symlink),
		"extension":          validUploadRequest(text),
		"file-size":          func() UploadRequest { r := validUploadRequest(pdf); r.MaxFileBytes = 1; return r }(),
		"total-size":         func() UploadRequest { r := validUploadRequest(pdf); r.MaxTotalBytes = 1; return r }(),
		"too-many-files":     validUploadRequest(tooMany...),
		"empty-allowlist":    func() UploadRequest { r := validUploadRequest(pdf); r.AllowedExtensions = nil; return r }(),
		"widened-file-bound": func() UploadRequest { r := validUploadRequest(pdf); r.MaxFileBytes = maxUploadFileBytes + 1; return r }(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := session.UploadFiles(context.Background(), "11", "22", "https://example.com", request); err == nil {
				t.Fatal("invalid upload file set reached the upload path")
			}
		})
	}
	if axCalls != 0 {
		t.Fatalf("invalid files reached native upload: calls=%d", axCalls)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("invalid files reached page-context automation: %v", err)
	}
}

func TestUploadFilesProductionPathRefusesDOMAndTargetDriftBeforeAttestingSelection(t *testing.T) {
	for _, tc := range []struct {
		name           string
		prepareOutcome string
		inspectOutcome string
		driftAt        string
		inactiveAt     string
		wantError      error
		wantAXCalls    int
	}{
		{name: "missing-input", prepareOutcome: "input-missing", inspectOutcome: "selected", wantError: ErrUploadRefused},
		{name: "ambiguous-input", prepareOutcome: "input-ambiguous", inspectOutcome: "selected", wantError: ErrUploadRefused},
		{name: "non-file-input", prepareOutcome: "input-not-file", inspectOutcome: "selected", wantError: ErrUploadRefused},
		{name: "hidden-input", prepareOutcome: "input-hidden", inspectOutcome: "selected", wantError: ErrUploadRefused},
		{name: "multiple-files-disallowed", prepareOutcome: "input-not-multiple", inspectOutcome: "selected", wantError: ErrUploadRefused},
		{name: "non-empty-input", prepareOutcome: "input-not-empty", inspectOutcome: "selected", wantError: ErrUploadRefused},
		{name: "origin-drift-before-focus", prepareOutcome: "ready", inspectOutcome: "selected", driftAt: "1", wantError: browsersession.ErrOriginMismatch},
		{name: "inactive-after-focus", prepareOutcome: "ready", inspectOutcome: "selected", inactiveAt: "2", wantError: browsersession.ErrTargetMissing},
		{name: "origin-drift-after-native-selection", prepareOutcome: "ready", inspectOutcome: "selected", driftAt: "5", wantError: browsersession.ErrOriginMismatch, wantAXCalls: 1},
		{name: "untrusted-change", prepareOutcome: "ready", inspectOutcome: "untrusted-change", wantError: ErrUploadRefused, wantAXCalls: 1},
		{name: "file-count-mismatch", prepareOutcome: "ready", inspectOutcome: "file-count-mismatch", wantError: ErrUploadRefused, wantAXCalls: 1},
		{name: "file-metadata-mismatch", prepareOutcome: "ready", inspectOutcome: "file-metadata-mismatch", wantError: ErrUploadRefused, wantAXCalls: 1},
		{name: "selected", prepareOutcome: "ready", inspectOutcome: "selected", wantAXCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "evidence.pdf")
			if err := os.WriteFile(source, []byte("evidence"), 0o600); err != nil {
				t.Fatal(err)
			}
			counter := filepath.Join(t.TempDir(), "exact-counter")
			t.Setenv("UPLOAD_EXACT_COUNTER", counter)
			t.Setenv("UPLOAD_PREPARE_OUTCOME", tc.prepareOutcome)
			t.Setenv("UPLOAD_INSPECT_OUTCOME", tc.inspectOutcome)
			t.Setenv("UPLOAD_DRIFT_AT", tc.driftAt)
			t.Setenv("UPLOAD_INACTIVE_AT", tc.inactiveAt)
			fake := filepath.Join(t.TempDir(), "osascript")
			if err := os.WriteFile(fake, []byte(`#!/bin/sh
case "$*" in
  *chrome-exact-target*)
    count=0
    if [ -f "$UPLOAD_EXACT_COUNTER" ]; then count=$(/bin/cat "$UPLOAD_EXACT_COUNTER"); fi
    count=$((count + 1))
    printf '%s' "$count" > "$UPLOAD_EXACT_COUNTER"
    outcome=ok
    origin=https://example.com
    active=true
    if [ "$UPLOAD_DRIFT_AT" = "$count" ]; then outcome=origin-mismatch; origin=https://drift.example; active=false; fi
    if [ "$UPLOAD_INACTIVE_AT" = "$count" ]; then active=false; fi
    /usr/bin/jq -cn --arg outcome "$outcome" --arg origin "$origin" --argjson active "$active" '{__macChromeExactTarget:"works.relux.mac-infra/chrome-exact-target/v1",outcome:$outcome,origin:$origin,active:$active}'
    ;;
  *)
    source=$(/bin/cat)
    case "$source" in
      *cleanup-target-missing*) value=cleaned ;;
      *file-count-mismatch*) value="{\"outcome\":\"$UPLOAD_INSPECT_OUTCOME\"}" ;;
      *input-not-file*) value="$UPLOAD_PREPARE_OUTCOME" ;;
      *) value=unexpected-upload-program ;;
    esac
    guard=$(/usr/bin/jq -cn --arg value "$value" '{__macBrowserSessionGuard:"works.relux.mac-infra/browser-session-guard/v1",outcome:"ok",origin:"https://example.com",readyState:"complete",value:$value}')
    /usr/bin/jq -cn --arg value "$guard" '{__macChromePrivateTransport:"works.relux.mac-infra/chrome-private-transport/v1",outcome:"ok",value:$value}'
    ;;
esac
`), 0o700); err != nil {
				t.Fatal(err)
			}
			axCalls := 0
			session := Session{
				OsaScriptPath: fake,
				AXProcessID:   func() (int, error) { return 123, nil },
				AXUploadFiles: func(_ int, _ string, stagingDirectory string) error {
					axCalls++
					entries, err := os.ReadDir(stagingDirectory)
					if err != nil {
						return err
					}
					if len(entries) != 1 || entries[0].Name() != "evidence.pdf" {
						t.Fatalf("native boundary received unexpected staged entries: %v", entries)
					}
					return nil
				},
			}
			result, err := session.UploadFiles(context.Background(), "11", "22", "https://example.com", validUploadRequest(source))
			if tc.wantError == nil {
				if err != nil {
					t.Fatalf("selected upload failed: %v", err)
				}
				if !result.OK || result.Origin != "https://example.com" || result.Count != 1 || len(result.Files) != 1 || result.Files[0] != "evidence.pdf" {
					t.Fatalf("unsafe or incomplete upload attestation: %#v", result)
				}
			} else if !errors.Is(err, tc.wantError) {
				t.Fatalf("error=%v want classification %v", err, tc.wantError)
			}
			if axCalls != tc.wantAXCalls {
				t.Fatalf("native upload calls=%d want=%d", axCalls, tc.wantAXCalls)
			}
		})
	}
}

func TestUploadFilesProductionPathRevalidatesSameInputBeforeNativeAndAttestation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		beforeAX    uploadDOMScenario
		afterAX     uploadDOMScenario
		afterType   string
		wantOutcome string
		wantAXCalls int
	}{
		{
			name:        "accept-drifts-before-native",
			beforeAX:    uploadDOMScenario{Accept: ".png", AncestorOpacity: "1", AncestorVisibility: "visible", HitInput: true},
			afterAX:     uploadDOMScenario{Accept: ".png", AncestorOpacity: "1", AncestorVisibility: "visible", HitInput: true},
			afterType:   "file",
			wantOutcome: "input-accept-mismatch",
			wantAXCalls: 0,
		},
		{
			name:        "visibility-drifts-after-selection",
			beforeAX:    uploadDOMScenario{Accept: ".pdf", AncestorOpacity: "1", AncestorVisibility: "visible", HitInput: true},
			afterAX:     uploadDOMScenario{Accept: ".pdf", AncestorOpacity: "0", AncestorVisibility: "visible", HitInput: true},
			afterType:   "file",
			wantOutcome: "input-hidden",
			wantAXCalls: 1,
		},
		{
			name:        "type-drifts-after-selection",
			beforeAX:    uploadDOMScenario{Accept: ".pdf", AncestorOpacity: "1", AncestorVisibility: "visible", HitInput: true},
			afterAX:     uploadDOMScenario{Accept: ".pdf", AncestorOpacity: "1", AncestorVisibility: "visible", HitInput: true},
			afterType:   "text",
			wantOutcome: "input-not-file",
			wantAXCalls: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "evidence.pdf")
			if err := os.WriteFile(source, []byte("evidence"), 0o600); err != nil {
				t.Fatal(err)
			}
			expected := []uploadFile{{Name: "evidence.pdf", Size: 8, MIME: "application/pdf"}}
			prepareScenario := uploadDOMScenario{Accept: ".pdf", AncestorOpacity: "1", AncestorVisibility: "visible", HitInput: true}
			pageCalls, axCalls := 0, 0
			session := Session{
				OsaScriptPath: fakeExactTargetScript(t),
				uploadPageJS: func(_ context.Context, windowID, tabID, origin, pageSource string) (browsersession.ExecutionResult, error) {
					pageCalls++
					if windowID != "11" || tabID != "22" || origin != "https://example.com" {
						t.Fatalf("production upload composition lost exact target: %s/%s %s", windowID, tabID, origin)
					}
					value := "cleaned"
					switch {
					case strings.Contains(pageSource, "cleanup-target-missing"):
					case pageCalls == 1:
						value = executeUploadPageProgram(t, pageSource, prepareScenario)
					case axCalls == 0:
						value = executeUploadBoundInputProgram(t, pageSource, expected, nil, tc.beforeAX, "file", false, false)
					default:
						value = executeUploadBoundInputProgram(t, pageSource, expected, expected, tc.afterAX, tc.afterType, false, true)
					}
					return browsersession.ExecutionResult{Value: value, Origin: origin, ReadyState: "complete"}, nil
				},
				AXProcessID: func() (int, error) { return 123, nil },
				AXUploadFiles: func(int, string, string) error {
					axCalls++
					return nil
				},
			}
			result, err := session.UploadFiles(context.Background(), "11", "22", "https://example.com", validUploadRequest(source))
			var refusal *UploadRefusalError
			if !errors.As(err, &refusal) || refusal.Kind != tc.wantOutcome {
				t.Fatalf("DOM drift result=%#v error=%v want refusal %q", result, err, tc.wantOutcome)
			}
			if result.OK || result.Count != 0 || len(result.Files) != 0 {
				t.Fatalf("DOM drift produced success attestation: %#v", result)
			}
			if axCalls != tc.wantAXCalls {
				t.Fatalf("native upload calls=%d want=%d", axCalls, tc.wantAXCalls)
			}
		})
	}
}

func TestUploadFilesProductionPathRequiresOneToOnePostSelectionMetadata(t *testing.T) {
	for _, tc := range []struct {
		name        string
		actual      []uploadFile
		wantOutcome string
		wantOK      bool
	}{
		{
			name:        "duplicate-replaces-expected-file",
			actual:      []uploadFile{{Name: "a.pdf", Size: 12}, {Name: "a.pdf", Size: 12}},
			wantOutcome: "file-metadata-mismatch",
		},
		{
			name:   "reordered-exact-match",
			actual: []uploadFile{{Name: "b.pdf", Size: 34}, {Name: "a.pdf", Size: 12}},
			wantOK: true,
		},
		{
			name:        "wrong-size",
			actual:      []uploadFile{{Name: "a.pdf", Size: 13}, {Name: "b.pdf", Size: 34}},
			wantOutcome: "file-metadata-mismatch",
		},
		{
			name:        "wrong-count",
			actual:      []uploadFile{{Name: "a.pdf", Size: 12}},
			wantOutcome: "file-count-mismatch",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			aPath := filepath.Join(directory, "a.pdf")
			bPath := filepath.Join(directory, "b.pdf")
			if err := os.WriteFile(aPath, []byte(strings.Repeat("a", 12)), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(bPath, []byte(strings.Repeat("b", 34)), 0o600); err != nil {
				t.Fatal(err)
			}
			fake := filepath.Join(t.TempDir(), "osascript")
			if err := os.WriteFile(fake, []byte(`#!/bin/sh
case "$*" in
  *chrome-exact-target*)
    guard=$(/usr/bin/jq -cn '{__macChromeExactTarget:"works.relux.mac-infra/chrome-exact-target/v1",outcome:"ok",origin:"https://example.com",active:true}')
    printf '%s\n' "$guard"
    ;;
  *) exit 99 ;;
esac
`), 0o700); err != nil {
				t.Fatal(err)
			}
			expected := []uploadFile{{Name: "a.pdf", Size: 12}, {Name: "b.pdf", Size: 34}}
			pageCalls := 0
			session := Session{
				OsaScriptPath: fake,
				uploadPageJS: func(_ context.Context, windowID, tabID, origin, pageSource string) (browsersession.ExecutionResult, error) {
					pageCalls++
					if windowID != "11" || tabID != "22" || origin != "https://example.com" {
						t.Fatalf("production upload composition lost exact target: %s/%s %s", windowID, tabID, origin)
					}
					value := "ready"
					switch {
					case strings.Contains(pageSource, "cleanup-target-missing"):
						value = "cleaned"
					case strings.Contains(pageSource, "file-count-mismatch"):
						value = executeUploadInspectProgram(t, pageSource, expected, tc.actual)
					}
					return browsersession.ExecutionResult{Value: value, Origin: origin, ReadyState: "complete"}, nil
				},
				AXProcessID: func() (int, error) { return 123, nil },
				AXUploadFiles: func(_ int, _ string, stagingDirectory string) error {
					entries, err := os.ReadDir(stagingDirectory)
					if err != nil {
						return err
					}
					if len(entries) != 2 {
						t.Fatalf("native boundary staged entries=%d want=2", len(entries))
					}
					return nil
				},
			}
			result, err := session.UploadFiles(context.Background(), "11", "22", "https://example.com", validUploadRequest(aPath, bPath))
			if tc.wantOK {
				if err != nil {
					t.Fatalf("reordered exact metadata refused: %v", err)
				}
				if !result.OK || result.Count != 2 || len(result.Files) != 2 || result.Files[0] != "a.pdf" || result.Files[1] != "b.pdf" {
					t.Fatalf("unexpected exact upload attestation: %#v", result)
				}
			} else {
				var refusal *UploadRefusalError
				if !errors.As(err, &refusal) || refusal.Kind != tc.wantOutcome {
					t.Fatalf("post-selection metadata error=%v want refusal %q", err, tc.wantOutcome)
				}
				if result.OK || result.Count != 0 || len(result.Files) != 0 {
					t.Fatalf("refused metadata produced success attestation: %#v", result)
				}
			}
			if pageCalls != 4 {
				t.Fatalf("page calls=%d want prepare, pre-native revalidation, inspect, cleanup", pageCalls)
			}
		})
	}
}
