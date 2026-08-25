package chromectl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/relux-works/mac-infra/internal/browsersession"
)

const (
	UploadVersion        = 1
	maxUploadRequest     = 32 * 1024
	maxUploadFiles       = 8
	maxUploadSelector    = 512
	maxUploadPathBytes   = 4096
	maxUploadExtensions  = 16
	maxUploadFileBytes   = 32 * 1024 * 1024
	maxUploadTotalBytes  = 64 * 1024 * 1024
	defaultUploadTimeout = 15_000
)

var ErrUploadRefused = errors.New("Chrome file upload was refused")

type UploadRequest struct {
	Version           int      `json:"version"`
	InputSelector     string   `json:"inputSelector"`
	Paths             []string `json:"paths"`
	AllowedExtensions []string `json:"allowedExtensions"`
	MaxFileBytes      int64    `json:"maxFileBytes"`
	MaxTotalBytes     int64    `json:"maxTotalBytes"`
	TimeoutMS         int      `json:"timeoutMs,omitempty"`
}

type UploadResult struct {
	Version int      `json:"version"`
	OK      bool     `json:"ok"`
	Origin  string   `json:"origin"`
	Count   int      `json:"count"`
	Files   []string `json:"files"`
}

type UploadRefusalError struct{ Kind string }

func (e *UploadRefusalError) Error() string {
	return fmt.Sprintf("%v: %s", ErrUploadRefused, e.Kind)
}

func (e *UploadRefusalError) Unwrap() error { return ErrUploadRefused }

type uploadFile struct {
	Path string `json:"-"`
	Name string `json:"name"`
	Size int64  `json:"size"`
	MIME string `json:"mime,omitempty"`
}

var uploadMIMEByExtension = map[string]string{
	".csv":  "text/csv",
	".doc":  "application/msword",
	".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".gif":  "image/gif",
	".heic": "image/heic",
	".heif": "image/heif",
	".jpeg": "image/jpeg",
	".jpg":  "image/jpeg",
	".json": "application/json",
	".m4a":  "audio/mp4",
	".mov":  "video/quicktime",
	".mp3":  "audio/mpeg",
	".mp4":  "video/mp4",
	".ogg":  "audio/ogg",
	".pdf":  "application/pdf",
	".png":  "image/png",
	".svg":  "image/svg+xml",
	".txt":  "text/plain",
	".wav":  "audio/wav",
	".webm": "video/webm",
	".webp": "image/webp",
	".xls":  "application/vnd.ms-excel",
	".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	".xml":  "application/xml",
	".zip":  "application/zip",
}

type stagedUpload struct {
	Directory string
	Files     []uploadFile
}

func DecodeUploadRequest(r io.Reader) (UploadRequest, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxUploadRequest+1))
	if err != nil {
		return UploadRequest{}, errors.New("read upload request")
	}
	if len(data) > maxUploadRequest {
		return UploadRequest{}, errors.New("upload request exceeds 32768 bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request UploadRequest
	if err := decoder.Decode(&request); err != nil {
		return UploadRequest{}, errors.New("decode upload request: malformed or unknown field")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return UploadRequest{}, errors.New("decode upload request: trailing JSON is not allowed")
	}
	if err := request.Validate(); err != nil {
		return UploadRequest{}, err
	}
	return request, nil
}

func (r *UploadRequest) Validate() error {
	if r.Version != UploadVersion {
		return fmt.Errorf("upload request version must be %d", UploadVersion)
	}
	r.InputSelector = strings.TrimSpace(r.InputSelector)
	if r.InputSelector == "" || len(r.InputSelector) > maxUploadSelector || hasControl(r.InputSelector) {
		return errors.New("inputSelector must contain 1..512 printable bytes")
	}
	if len(r.Paths) == 0 || len(r.Paths) > maxUploadFiles {
		return fmt.Errorf("paths must contain 1..%d files", maxUploadFiles)
	}
	if len(r.AllowedExtensions) == 0 || len(r.AllowedExtensions) > maxUploadExtensions {
		return fmt.Errorf("allowedExtensions must contain 1..%d entries", maxUploadExtensions)
	}
	extensions := make(map[string]struct{}, len(r.AllowedExtensions))
	for i, extension := range r.AllowedExtensions {
		extension = strings.ToLower(strings.TrimSpace(extension))
		if extension == "" || extension[0] != '.' || len(extension) > 16 || hasControl(extension) || strings.ContainsAny(extension, `/\\`) {
			return fmt.Errorf("allowedExtensions[%d] must be a dot-prefixed extension of at most 16 bytes", i)
		}
		if _, exists := extensions[extension]; exists {
			return fmt.Errorf("allowedExtensions[%d] duplicates an earlier extension", i)
		}
		extensions[extension] = struct{}{}
		r.AllowedExtensions[i] = extension
	}
	if r.MaxFileBytes <= 0 || r.MaxFileBytes > maxUploadFileBytes {
		return fmt.Errorf("maxFileBytes must be between 1 and %d", maxUploadFileBytes)
	}
	if r.MaxTotalBytes <= 0 || r.MaxTotalBytes > maxUploadTotalBytes {
		return fmt.Errorf("maxTotalBytes must be between 1 and %d", maxUploadTotalBytes)
	}
	if r.TimeoutMS == 0 {
		r.TimeoutMS = defaultUploadTimeout
	}
	if r.TimeoutMS < 1000 || r.TimeoutMS > 30_000 {
		return errors.New("timeoutMs must be between 1000 and 30000")
	}
	for i, path := range r.Paths {
		if path == "" || len(path) > maxUploadPathBytes || !utf8.ValidString(path) || hasControl(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("paths[%d] must be one clean absolute printable path", i)
		}
	}
	return nil
}

func prepareUpload(request UploadRequest) (stagedUpload, error) {
	if err := request.Validate(); err != nil {
		return stagedUpload{}, err
	}
	extensions := make(map[string]struct{}, len(request.AllowedExtensions))
	for _, extension := range request.AllowedExtensions {
		extensions[extension] = struct{}{}
	}
	seenNames := make(map[string]struct{}, len(request.Paths))
	files := make([]uploadFile, 0, len(request.Paths))
	var total int64
	for i, path := range request.Paths {
		info, err := os.Lstat(path)
		if err != nil {
			return stagedUpload{}, fmt.Errorf("file[%d] is unavailable", i)
		}
		if !info.Mode().IsRegular() {
			return stagedUpload{}, fmt.Errorf("file[%d] must be a regular non-symlink file", i)
		}
		name := filepath.Base(path)
		if name == "." || name == string(filepath.Separator) || strings.HasPrefix(name, ".") || hasControl(name) {
			return stagedUpload{}, fmt.Errorf("file[%d] has an unsupported filename", i)
		}
		if _, exists := seenNames[name]; exists {
			return stagedUpload{}, fmt.Errorf("file[%d] duplicates an earlier filename", i)
		}
		seenNames[name] = struct{}{}
		if _, ok := extensions[strings.ToLower(filepath.Ext(name))]; !ok {
			return stagedUpload{}, fmt.Errorf("file[%d] extension is not allowlisted", i)
		}
		if info.Size() > request.MaxFileBytes {
			return stagedUpload{}, fmt.Errorf("file[%d] exceeds maxFileBytes", i)
		}
		total += info.Size()
		if total > request.MaxTotalBytes {
			return stagedUpload{}, errors.New("files exceed maxTotalBytes")
		}
		extension := strings.ToLower(filepath.Ext(name))
		files = append(files, uploadFile{Path: path, Name: name, Size: info.Size(), MIME: uploadMIMEByExtension[extension]})
	}
	directory, err := os.MkdirTemp("", "mac-chrome-upload-*")
	if err != nil {
		return stagedUpload{}, errors.New("create private upload staging directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		return stagedUpload{}, errors.New("secure private upload staging directory")
	}
	staged := stagedUpload{Directory: directory, Files: files}
	for i, file := range files {
		if err := copyUploadFile(file.Path, filepath.Join(directory, file.Name), file.Size); err != nil {
			_ = os.RemoveAll(directory)
			return stagedUpload{}, fmt.Errorf("stage file[%d]", i)
		}
	}
	return staged, nil
}

func copyUploadFile(sourcePath, destinationPath string, expectedSize int64) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	opened, err := source.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() != expectedSize {
		return errors.New("source changed during validation")
	}
	prior, err := os.Lstat(sourcePath)
	if err != nil || !prior.Mode().IsRegular() || !os.SameFile(prior, opened) {
		return errors.New("source changed during validation")
	}
	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	copied, copyErr := io.Copy(destination, io.LimitReader(source, expectedSize+1))
	closeErr := destination.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if copied != expectedSize {
		return errors.New("source changed during staging")
	}
	return nil
}

func (s Session) UploadFiles(ctx context.Context, windowID, tabID, expectedOrigin string, request UploadRequest) (UploadResult, error) {
	if err := validateExactTarget(windowID, tabID, expectedOrigin); err != nil {
		return UploadResult{}, err
	}
	staged, err := prepareUpload(request)
	if err != nil {
		return UploadResult{}, err
	}
	defer os.RemoveAll(staged.Directory)
	marker, err := trustedNonce("upload")
	if err != nil {
		return UploadResult{}, err
	}
	stateKey, err := trustedNonce("upload-state")
	if err != nil {
		return UploadResult{}, err
	}
	prepared, err := s.runUploadPageJavaScript(ctx, windowID, tabID, expectedOrigin, uploadPrepareJavaScript(request.InputSelector, staged.Files, marker, stateKey))
	if err != nil {
		return UploadResult{}, err
	}
	if prepared.Value != "ready" {
		return UploadResult{}, &UploadRefusalError{Kind: prepared.Value}
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = s.runUploadPageJavaScript(cleanupCtx, windowID, tabID, expectedOrigin, uploadCleanupJavaScript(request.InputSelector, stateKey))
	}()
	if _, err := s.focusExactTarget(ctx, windowID, tabID, expectedOrigin); err != nil {
		return UploadResult{}, err
	}
	if err := s.requireExactTargetActive(ctx, windowID, tabID, expectedOrigin); err != nil {
		return UploadResult{}, err
	}
	revalidated, err := s.runUploadPageJavaScript(ctx, windowID, tabID, expectedOrigin, uploadRevalidateJavaScript(request.InputSelector, stateKey))
	if err != nil {
		return UploadResult{}, err
	}
	if revalidated.Value != "ready" {
		return UploadResult{}, &UploadRefusalError{Kind: revalidated.Value}
	}
	if err := s.requireExactTargetActive(ctx, windowID, tabID, expectedOrigin); err != nil {
		return UploadResult{}, err
	}
	pid, err := s.axProcessID()
	if err != nil {
		return UploadResult{}, err
	}
	if err := s.axUploadFiles(pid, marker, staged.Directory); err != nil {
		return UploadResult{}, err
	}
	if err := s.requireExactTargetActive(ctx, windowID, tabID, expectedOrigin); err != nil {
		return UploadResult{}, err
	}
	deadline := time.Now().Add(time.Duration(request.TimeoutMS) * time.Millisecond)
	for {
		state, err := s.readUploadPageState(ctx, windowID, tabID, expectedOrigin, request.InputSelector, stateKey)
		if err != nil {
			return UploadResult{}, err
		}
		switch state.Outcome {
		case "selected":
			names := make([]string, len(staged.Files))
			for i, file := range staged.Files {
				names[i] = file.Name
			}
			return UploadResult{Version: UploadVersion, OK: true, Origin: expectedOrigin, Count: len(names), Files: names}, nil
		case "waiting-change":
			if time.Now().After(deadline) {
				return UploadResult{}, &UploadRefusalError{Kind: "selection-timeout"}
			}
			time.Sleep(100 * time.Millisecond)
		default:
			return UploadResult{}, &UploadRefusalError{Kind: state.Outcome}
		}
	}
}

type uploadPageState struct {
	Outcome string `json:"outcome"`
}

func (s Session) readUploadPageState(ctx context.Context, windowID, tabID, origin, inputSelector, stateKey string) (uploadPageState, error) {
	result, err := s.runUploadPageJavaScript(ctx, windowID, tabID, origin, uploadInspectJavaScript(inputSelector, stateKey))
	if err != nil {
		return uploadPageState{}, err
	}
	var state uploadPageState
	if err := json.Unmarshal([]byte(result.Value), &state); err != nil || strings.TrimSpace(state.Outcome) == "" {
		return uploadPageState{}, errors.New("malformed upload page state")
	}
	return state, nil
}

func uploadPrepareJavaScript(inputSelector string, files []uploadFile, marker, stateKey string) string {
	expected := make([]uploadFile, len(files))
	copy(expected, files)
	selectorJSON, _ := json.Marshal(inputSelector)
	expectedJSON, _ := json.Marshal(expected)
	markerJSON, _ := json.Marshal(marker)
	stateKeyJSON, _ := json.Marshal(stateKey)
	return fmt.Sprintf(`(() => {
  %s
  const selector=%s,expected=%s,marker=%s,stateKey=%s;
  let inputs;try{inputs=document.querySelectorAll(selector);}catch(_){return "invalid-input-selector";}
  if(inputs.length===0)return "input-missing";if(inputs.length!==1)return "input-ambiguous";
  const input=inputs[0],validation=validateUploadInput(input,expected,true);if(validation!=="ready")return validation;
  if(input[stateKey])return "probe-collision";
  const oldAria=input.getAttribute("aria-label"),state={expected,changed:false,trusted:false,oldAria,marker};
  state.onChange=event=>{state.changed=true;state.trusted=event.isTrusted===true;};input.addEventListener("change",state.onChange);
  Object.defineProperty(input,stateKey,{value:state,configurable:true});input.setAttribute("aria-label",marker);return "ready";
})()`, uploadInputGateJavaScript(), string(selectorJSON), string(expectedJSON), string(markerJSON), string(stateKeyJSON))
}

func uploadInputGateJavaScript() string {
	return `const validateUploadInput=(input,expected,requireEmpty)=>{
  if(!(input instanceof HTMLInputElement)||String(input.type||"").toLowerCase()!=="file"||input.disabled)return "input-not-file";
  let depth=0;for(let node=input;node&&node.nodeType===1;node=node.parentElement){
    if(++depth>64)return "input-hidden";const style=getComputedStyle(node),opacity=Number(style.opacity),filter=String(style.filter||"").trim().toLowerCase(),maskImages=[style.maskImage,style.webkitMaskImage].map(value=>String(value||"").trim().toLowerCase()).filter(Boolean);
    if(node.hidden||node.getAttribute("aria-hidden")==="true"||style.visibility==="hidden"||style.visibility==="collapse"||style.display==="none"||style.pointerEvents==="none"||!Number.isFinite(opacity)||opacity<=0||filter!=="none"||maskImages.length===0||maskImages.some(value=>value!=="none"))return "input-hidden";
  }
  const rects=Array.from(input.getClientRects()).slice(0,8),points=[];
  for(const rect of rects){const left=Math.max(0,rect.left),top=Math.max(0,rect.top),right=Math.min(innerWidth,rect.right),bottom=Math.min(innerHeight,rect.bottom);if(right<=left||bottom<=top)continue;const x=(left+right)/2,y=(top+bottom)/2;points.push([x,y],[left+.5,top+.5],[right-.5,top+.5],[left+.5,bottom-.5],[right-.5,bottom-.5]);}
  if(typeof document.elementFromPoint!=="function"||!points.some(point=>{const hit=document.elementFromPoint(point[0],point[1]);return hit===input||(hit&&typeof input.contains==="function"&&input.contains(hit));}))return "input-hidden";
  const acceptValue=input.getAttribute("accept");if(acceptValue!==null&&String(acceptValue).trim()!==""){
    const raw=String(acceptValue);if(raw.length>512)return "input-accept-unsupported";const tokens=raw.split(",").map(value=>value.trim().toLowerCase());
    if(tokens.length===0||tokens.length>32||tokens.some(value=>value===""))return "input-accept-unsupported";
    const seen=new Set(),extension=/^\.[a-z0-9][a-z0-9+_-]{0,15}$/,mime=/^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$/;
    for(const token of tokens){if(seen.has(token))return "input-accept-unsupported";seen.add(token);if(extension.test(token)||mime.test(token)||token==="image/*"||token==="audio/*"||token==="video/*")continue;return "input-accept-unsupported";}
    for(const file of expected){const name=String(file.name||"").toLowerCase(),type=String(file.mime||"").toLowerCase();const matched=tokens.some(token=>token[0]==="."?name.endsWith(token):token.endsWith("/*")?type.startsWith(token.slice(0,-1)):type===token);if(!matched)return "input-accept-mismatch";}
  }
  if(expected.length>1&&!input.multiple)return "input-not-multiple";if(requireEmpty&&input.files&&input.files.length)return "input-not-empty";
  return "ready";
};`
}

func uploadRevalidateJavaScript(inputSelector, stateKey string) string {
	selectorJSON, _ := json.Marshal(inputSelector)
	stateKeyJSON, _ := json.Marshal(stateKey)
	return fmt.Sprintf(`(() => {
  %s
  const selector=%s,stateKey=%s;let inputs;
  try{inputs=document.querySelectorAll(selector);}catch(_){return "invalid-input-selector";}
  if(inputs.length!==1)return inputs.length===0?"input-missing":"input-ambiguous";
  const input=inputs[0],state=input[stateKey];if(!state)return "probe-missing";
  if(input.getAttribute("aria-label")!==state.marker)return "probe-marker-drift";
  const validation=validateUploadInput(input,state.expected,true);if(validation!=="ready")return validation;
  if(state.changed||state.trusted)return "input-state-changed";
  return "ready";
})()`, uploadInputGateJavaScript(), string(selectorJSON), string(stateKeyJSON))
}

func (s Session) runUploadPageJavaScript(ctx context.Context, windowID, tabID, origin, source string) (browsersession.ExecutionResult, error) {
	if s.uploadPageJS != nil {
		return s.uploadPageJS(ctx, windowID, tabID, origin, source)
	}
	return s.runJavaScriptPrivate(ctx, windowID, tabID, origin, source)
}

func uploadInspectJavaScript(inputSelector, stateKey string) string {
	selectorJSON, _ := json.Marshal(inputSelector)
	stateKeyJSON, _ := json.Marshal(stateKey)
	return fmt.Sprintf(`(() => {
  %s
  const selector=%s,stateKey=%s,outcome=value=>JSON.stringify({outcome:value});let inputs;
  try{inputs=document.querySelectorAll(selector);}catch(_){return outcome("invalid-input-selector");}
  if(inputs.length!==1)return outcome(inputs.length===0?"input-missing":"input-ambiguous");
  const input=inputs[0],state=input[stateKey];if(!state)return outcome("probe-missing");
  if(input.getAttribute("aria-label")!==state.marker)return outcome("probe-marker-drift");
  const validation=validateUploadInput(input,state.expected,false);if(validation!=="ready")return outcome(validation);
  if(!state.changed)return outcome("waiting-change");if(!state.trusted)return outcome("untrusted-change");
  const actual=Array.from(input.files||[]).map(file=>({name:String(file.name),size:Number(file.size)}));
  if(actual.length!==state.expected.length)return outcome("file-count-mismatch");
  const expectedByName=new Map(state.expected.map(file=>[file.name,file.size]));
  for(const file of actual){if(!expectedByName.has(file.name)||expectedByName.get(file.name)!==file.size)return outcome("file-metadata-mismatch");expectedByName.delete(file.name);}
  if(expectedByName.size!==0)return outcome("file-metadata-mismatch");
  return outcome("selected");
})()`, uploadInputGateJavaScript(), string(selectorJSON), string(stateKeyJSON))
}

func uploadCleanupJavaScript(inputSelector, stateKey string) string {
	selectorJSON, _ := json.Marshal(inputSelector)
	stateKeyJSON, _ := json.Marshal(stateKey)
	return fmt.Sprintf(`(() => {
  const inputs=document.querySelectorAll(%s);if(inputs.length!==1)return "cleanup-target-missing";const input=inputs[0],state=input[%s];
  if(!state)return "already-clean";input.removeEventListener("change",state.onChange);if(state.oldAria===null)input.removeAttribute("aria-label");else input.setAttribute("aria-label",state.oldAria);delete input[%s];return "cleaned";
})()`, string(selectorJSON), string(stateKeyJSON), string(stateKeyJSON))
}

func (s Session) axUploadFiles(pid int, description, stagingDirectory string) error {
	if s.AXUploadFiles != nil {
		return s.AXUploadFiles(pid, description, stagingDirectory)
	}
	return chromeAXUploadFiles(pid, description, stagingDirectory)
}
