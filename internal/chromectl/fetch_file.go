package chromectl

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// FetchFileVersion is the only accepted sealed fetch-file request envelope version.
	FetchFileVersion = 1
	// MaxFetchFileRequestBytes bounds the private stdin request envelope.
	MaxFetchFileRequestBytes = 8 << 10
	// maxFetchFileResourceBytes bounds the secret-bearing resource reference itself.
	maxFetchFileResourceBytes = 4 << 10

	DefaultFetchFileMaxBytes  int64 = 25 << 20
	MaximumFetchFileMaxBytes  int64 = 100 << 20
	DefaultFetchFileChunkSize       = 128 << 10
	MaximumFetchFileTimeout         = 5 * time.Minute
	minimumFetchFileTimeout         = 10 * time.Millisecond
)

var (
	ErrUnsafeFetchURL = errors.New("fetch resource URL is unsafe")
	ErrFetchSizeLimit = errors.New("fetch response exceeded the configured size limit")
	ErrFetchTimeout   = errors.New("fetch response exceeded the configured timeout")
	ErrFetchBusy      = errors.New("another sealed fetch is already running in the exact tab")
)

type FetchFileRequest struct {
	ResourceURL string
	MaxBytes    int64
	Timeout     time.Duration
	PollEvery   time.Duration
}

// fetchFileWireRequest is the versioned private-stdin envelope. The resource
// reference is carried here, never in the mac-chrome-session process argv.
type fetchFileWireRequest struct {
	Version   int    `json:"version"`
	Resource  string `json:"resource"`
	MaxBytes  int64  `json:"maxBytes,omitempty"`
	TimeoutMS int    `json:"timeoutMs,omitempty"`
}

// DecodeFetchFileRequest reads exactly one bounded versioned JSON envelope from
// r. Every failure returns a fixed message so a malformed or oversized envelope
// can never echo the protected resource reference back to stderr or a log.
func DecodeFetchFileRequest(r io.Reader) (FetchFileRequest, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxFetchFileRequestBytes+1))
	if err != nil {
		return FetchFileRequest{}, errors.New("read fetch-file request")
	}
	if len(data) > MaxFetchFileRequestBytes {
		return FetchFileRequest{}, fmt.Errorf("fetch-file request exceeds %d bytes", MaxFetchFileRequestBytes)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return FetchFileRequest{}, errors.New("fetch-file request body is empty")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var wire fetchFileWireRequest
	if err := decoder.Decode(&wire); err != nil {
		return FetchFileRequest{}, errors.New("fetch-file request must be one JSON envelope with known fields")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return FetchFileRequest{}, errors.New("fetch-file request must contain exactly one JSON envelope")
	}
	if wire.Version != FetchFileVersion {
		return FetchFileRequest{}, fmt.Errorf("fetch-file request version must be %d", FetchFileVersion)
	}
	if len(wire.Resource) > maxFetchFileResourceBytes {
		return FetchFileRequest{}, fmt.Errorf("fetch-file resource must be at most %d bytes", maxFetchFileResourceBytes)
	}
	request := FetchFileRequest{ResourceURL: wire.Resource, MaxBytes: wire.MaxBytes}
	if wire.TimeoutMS != 0 {
		// Compare in integer milliseconds first. time.Duration is int64
		// nanoseconds, so multiplying an attacker-chosen int by
		// time.Millisecond wraps: 288230376151711754 ms becomes 10ms and would
		// pass an after-conversion bound check.
		if wire.TimeoutMS < 0 || int64(wire.TimeoutMS) > MaximumFetchFileTimeout.Milliseconds() {
			return FetchFileRequest{}, fmt.Errorf("fetch-file timeoutMs must be between 0 and %d", MaximumFetchFileTimeout.Milliseconds())
		}
		request.Timeout = time.Duration(wire.TimeoutMS) * time.Millisecond
	}
	return request, nil
}

type FetchFileMeta struct {
	Status      int    `json:"status"`
	Bytes       int64  `json:"bytes"`
	ContentType string `json:"contentType,omitempty"`
}

type fetchFilePageMeta struct {
	State       string `json:"state"`
	Kind        string `json:"kind,omitempty"`
	Status      int    `json:"status,omitempty"`
	Bytes       int64  `json:"bytes,omitempty"`
	ChunkCount  int    `json:"chunkCount,omitempty"`
	ContentType string `json:"contentType,omitempty"`
}

type fetchFilePageChunk struct {
	State string `json:"state"`
	Index int    `json:"index"`
	Data  string `json:"data"`
}

// FetchFile is the package boundary for the sealed transfer and the only place
// a fetch-file error becomes public. Every non-nil error is replaced by a fresh
// FetchFileDiagnostic before it can leave this method, and no payload survives a
// failure. The seal is mandatory even though the branches below already return
// typed codes: it makes an omitted conversion fail closed instead of becoming
// the next bypass.
func (s Session) FetchFile(ctx context.Context, windowID, tabID, expectedOrigin string, request FetchFileRequest) ([]byte, FetchFileMeta, error) {
	data, meta, err := s.fetchFile(ctx, windowID, tabID, expectedOrigin, request)
	if err != nil {
		return nil, FetchFileMeta{}, sealFetchFileError(err)
	}
	return data, meta, nil
}

func (s Session) fetchFile(ctx context.Context, windowID, tabID, expectedOrigin string, request FetchFileRequest) ([]byte, FetchFileMeta, error) {
	// The validation helpers keep descriptive errors for ValidateFetchFileRequest's
	// own callers; on the transfer path they collapse to one fixed refusal so no
	// bound, origin, or identifier detail can be rendered from a failed request.
	resourceURL, request, err := normalizeFetchFileRequest(expectedOrigin, request)
	if err != nil {
		return nil, FetchFileMeta{}, NewFetchFileDiagnostic(FetchFileRequestRefused)
	}
	if err := validateFetchExactTarget(windowID, tabID); err != nil {
		return nil, FetchFileMeta{}, NewFetchFileDiagnostic(FetchFileRequestRefused)
	}
	jobID, err := newFetchFileJobID()
	if err != nil {
		return nil, FetchFileMeta{}, NewFetchFileDiagnostic(FetchFileUnverifiable)
	}

	fetchCtx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	started := false
	defer func() {
		if !started {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cleanupCancel()
		_, _ = s.runJavaScriptPrivate(cleanupCtx, windowID, tabID, expectedOrigin, clearFetchFileJavaScript(jobID))
	}()

	result, err := s.runJavaScriptPrivate(fetchCtx, windowID, tabID, expectedOrigin, startFetchFileJavaScript(jobID, resourceURL, request.MaxBytes, request.Timeout, DefaultFetchFileChunkSize))
	if err != nil {
		return nil, FetchFileMeta{}, classifyFetchContextError(err, fetchCtx)
	}
	switch strings.TrimSpace(result.Value) {
	case "started":
		started = true
	case "busy":
		return nil, FetchFileMeta{}, NewFetchFileDiagnostic(FetchFileBusy)
	default:
		return nil, FetchFileMeta{}, NewFetchFileDiagnostic(FetchFileResponseUnverifiable)
	}

	var pageMeta fetchFilePageMeta
	for {
		result, err = s.runJavaScriptPrivate(fetchCtx, windowID, tabID, expectedOrigin, pollFetchFileJavaScript(jobID))
		if err != nil {
			return nil, FetchFileMeta{}, classifyFetchContextError(err, fetchCtx)
		}
		if err := decodeStrictFetchJSON(result.Value, &pageMeta); err != nil {
			return nil, FetchFileMeta{}, NewFetchFileDiagnostic(FetchFileResponseUnverifiable)
		}
		switch pageMeta.State {
		case "done":
			goto readChunks
		case "error":
			return nil, FetchFileMeta{}, fetchPageError(pageMeta.Kind)
		case "running":
		case "missing":
			return nil, FetchFileMeta{}, NewFetchFileDiagnostic(FetchFileResponseUnverifiable)
		default:
			return nil, FetchFileMeta{}, NewFetchFileDiagnostic(FetchFileResponseUnverifiable)
		}
		timer := time.NewTimer(request.PollEvery)
		select {
		case <-fetchCtx.Done():
			timer.Stop()
			return nil, FetchFileMeta{}, NewFetchFileDiagnostic(FetchFileTimeout)
		case <-timer.C:
		}
	}

readChunks:
	if pageMeta.Bytes < 0 || pageMeta.Bytes > request.MaxBytes {
		return nil, FetchFileMeta{}, NewFetchFileDiagnostic(FetchFileSizeLimit)
	}
	maxChunks := int((request.MaxBytes+DefaultFetchFileChunkSize-1)/DefaultFetchFileChunkSize) + 1
	if pageMeta.ChunkCount < 0 || pageMeta.ChunkCount > maxChunks || (pageMeta.Bytes > 0 && pageMeta.ChunkCount == 0) {
		return nil, FetchFileMeta{}, NewFetchFileDiagnostic(FetchFileResponseUnverifiable)
	}
	data := make([]byte, 0, pageMeta.Bytes)
	for index := 0; index < pageMeta.ChunkCount; index++ {
		result, err = s.runJavaScriptPrivate(fetchCtx, windowID, tabID, expectedOrigin, readFetchFileChunkJavaScript(jobID, index))
		if err != nil {
			return nil, FetchFileMeta{}, classifyFetchContextError(err, fetchCtx)
		}
		var pageChunk fetchFilePageChunk
		if err := decodeStrictFetchJSON(result.Value, &pageChunk); err != nil || pageChunk.State != "chunk" || pageChunk.Index != index {
			return nil, FetchFileMeta{}, NewFetchFileDiagnostic(FetchFileResponseUnverifiable)
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(pageChunk.Data)
		if err != nil {
			return nil, FetchFileMeta{}, NewFetchFileDiagnostic(FetchFileResponseUnverifiable)
		}
		if int64(len(data))+int64(len(decoded)) > request.MaxBytes {
			return nil, FetchFileMeta{}, NewFetchFileDiagnostic(FetchFileSizeLimit)
		}
		data = append(data, decoded...)
	}
	if int64(len(data)) != pageMeta.Bytes {
		return nil, FetchFileMeta{}, NewFetchFileDiagnostic(FetchFileResponseUnverifiable)
	}
	return data, FetchFileMeta{Status: pageMeta.Status, Bytes: int64(len(data)), ContentType: sanitizeFetchContentType(pageMeta.ContentType)}, nil
}

func ValidateFetchFileRequest(expectedOrigin string, request FetchFileRequest) error {
	_, _, err := normalizeFetchFileRequest(expectedOrigin, request)
	return err
}

func validateFetchExactTarget(windowID, tabID string) error {
	for name, value := range map[string]string{"window id": windowID, "tab id": tabID} {
		trimmed := strings.TrimSpace(value)
		number, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil || number <= 0 || strconv.FormatInt(number, 10) != trimmed {
			return fmt.Errorf("%s must be a positive exact Chrome id", name)
		}
	}
	return nil
}

func normalizeFetchFileRequest(expectedOrigin string, request FetchFileRequest) (string, FetchFileRequest, error) {
	expectedOrigin = strings.TrimSpace(expectedOrigin)
	base, err := url.Parse(expectedOrigin)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.Path != "" || base.RawQuery != "" || base.Fragment != "" || base.String() != expectedOrigin {
		return "", request, fmt.Errorf("%w: expected origin must be a canonical HTTPS origin", ErrUnsafeFetchURL)
	}
	resource := strings.TrimSpace(request.ResourceURL)
	if resource == "" || strings.ContainsAny(resource, "\r\n\x00") {
		return "", request, fmt.Errorf("%w: resource is required", ErrUnsafeFetchURL)
	}
	parsed, err := url.Parse(resource)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || (parsed.Scheme == "" && parsed.Host != "") {
		return "", request, fmt.Errorf("%w: resource must not contain credentials or a fragment", ErrUnsafeFetchURL)
	}
	resolved := base.ResolveReference(parsed)
	if resolved.Scheme != "https" || resolved.Host == "" || resolved.User != nil || resolved.Fragment != "" || resolved.Scheme+"://"+resolved.Host != expectedOrigin {
		return "", request, fmt.Errorf("%w: resource must resolve to the guarded origin", ErrUnsafeFetchURL)
	}
	if request.MaxBytes == 0 {
		request.MaxBytes = DefaultFetchFileMaxBytes
	}
	if request.MaxBytes < 1 || request.MaxBytes > MaximumFetchFileMaxBytes {
		return "", request, fmt.Errorf("maximum bytes must be between 1 and %d", MaximumFetchFileMaxBytes)
	}
	if request.Timeout == 0 {
		request.Timeout = 90 * time.Second
	}
	if request.Timeout < minimumFetchFileTimeout || request.Timeout > MaximumFetchFileTimeout {
		return "", request, fmt.Errorf("timeout must be between %s and %s", minimumFetchFileTimeout, MaximumFetchFileTimeout)
	}
	if request.PollEvery == 0 {
		request.PollEvery = 100 * time.Millisecond
	}
	if request.PollEvery < time.Millisecond || request.PollEvery > time.Second {
		return "", request, errors.New("poll interval is outside the sealed fetch bounds")
	}
	return resolved.String(), request, nil
}

// classifyFetchContextError turns a transport failure into a closed code. The
// inspected transport error is consumed for classification only and never
// returned: the stdin program it can quote embeds the protected resource.
func classifyFetchContextError(err error, ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return NewFetchFileDiagnostic(FetchFileTimeout)
	}
	return NewFetchFileDiagnostic(classifyFetchFileErrorCode(err))
}

// fetchPageError maps the page program's own fixed kind vocabulary to a closed
// code. The kind is one of a handful of literals the sealed program emits; no
// page text, status text, or URL is carried with it.
func fetchPageError(kind string) error {
	switch kind {
	case "size-limit":
		return NewFetchFileDiagnostic(FetchFileSizeLimit)
	case "timeout":
		return NewFetchFileDiagnostic(FetchFileTimeout)
	case "http-status":
		return NewFetchFileDiagnostic(FetchFileHTTPStatus)
	case "redirect-refused":
		return NewFetchFileDiagnostic(FetchFileRedirectRefused)
	default:
		return NewFetchFileDiagnostic(FetchFilePageFailed)
	}
}

func decodeStrictFetchJSON(raw string, value any) error {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing or malformed JSON value")
	}
	return nil
}

func sanitizeFetchContentType(raw string) string {
	if len(raw) > 200 {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(raw))
	if err != nil || len(mediaType) > 127 {
		return ""
	}
	return strings.ToLower(mediaType)
}

// fetchFileRandRead is the entropy seam for the sealed job identifier. It is a
// variable so a test can drive the identifier-failure branch through the public
// Session.FetchFile boundary rather than asserting on a helper.
var fetchFileRandRead = rand.Read

func newFetchFileJobID() (string, error) {
	var value [16]byte
	if _, err := fetchFileRandRead(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func startFetchFileJavaScript(jobID, resourceURL string, maxBytes int64, timeout time.Duration, chunkSize int) string {
	jobJSON, _ := json.Marshal(jobID)
	resourceJSON, _ := json.Marshal(resourceURL)
	return fmt.Sprintf(`(() => {
  const jobID=%s,endpoint=%s,maxBytes=%d,timeoutMS=%d,chunkSize=%d,key="__macChromeFetchFileV1";
  const current=window[key];
  if(current&&current.state==="running")return "busy";
  window[key]={state:"running",jobID,status:0,bytes:0,chunkCount:0,contentType:""};
  (async()=>{
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),timeoutMS);
    try{
      const target=new URL(endpoint,location.href);
      if(target.protocol!=="https:"||target.origin!==location.origin||target.username||target.password||target.hash)throw {kind:"unsafe-url"};
      let response;
      try{response=await fetch(target.href,{credentials:"same-origin",redirect:"error",signal:controller.signal,cache:"no-store"});}
      catch(error){throw {kind:error&&error.name==="AbortError"?"timeout":"redirect-refused"};}
      if(!response.ok)throw {kind:"http-status",status:Number(response.status)||0};
      const declared=Number(response.headers.get("content-length")||0);
      if(Number.isFinite(declared)&&declared>maxBytes)throw {kind:"size-limit"};
      const reader=response.body&&response.body.getReader?response.body.getReader():null;
      if(!reader)throw {kind:"unavailable"};
      const parts=[];let total=0;
      for(;;){const item=await reader.read();if(item.done)break;const bytes=item.value||new Uint8Array(0);total+=bytes.byteLength;if(total>maxBytes){try{await reader.cancel();}catch(_){}throw {kind:"size-limit"};}parts.push(bytes);}
      const merged=new Uint8Array(total);let offset=0;for(const part of parts){merged.set(part,offset);offset+=part.byteLength;}
      const chunks=[];
      for(let start=0;start<merged.length;start+=chunkSize){const part=merged.subarray(start,Math.min(start+chunkSize,merged.length));let binary="";for(let i=0;i<part.length;i+=32768)binary+=String.fromCharCode(...part.subarray(i,Math.min(i+32768,part.length)));chunks.push(btoa(binary));}
      const rawType=String(response.headers.get("content-type")||"");
      const contentType=/^[A-Za-z0-9!#$&^_.+\/-]{1,127}(?:\s*;[^\r\n]{0,72})?$/.test(rawType)?rawType:"";
      window[key]={state:"done",jobID,status:Number(response.status)||0,bytes:total,chunkCount:chunks.length,contentType,chunks};
    }catch(error){const kind=String(error&&error.kind||((error&&error.name)==="AbortError"?"timeout":"fetch-failed"));window[key]={state:"error",jobID,kind,status:Number(error&&error.status)||0,bytes:0,chunkCount:0,contentType:""};}
    finally{clearTimeout(timer);}
  })();
  return "started";
})()`, string(jobJSON), string(resourceJSON), maxBytes, timeout.Milliseconds(), chunkSize)
}

func pollFetchFileJavaScript(jobID string) string {
	jobJSON, _ := json.Marshal(jobID)
	return fmt.Sprintf(`(() => {const job=window.__macChromeFetchFileV1;if(!job||job.jobID!==%s)return JSON.stringify({state:"missing"});return JSON.stringify({state:String(job.state||""),kind:String(job.kind||""),status:Number(job.status)||0,bytes:Number(job.bytes)||0,chunkCount:Number(job.chunkCount)||0,contentType:String(job.contentType||"")});})()`, string(jobJSON))
}

func readFetchFileChunkJavaScript(jobID string, index int) string {
	jobJSON, _ := json.Marshal(jobID)
	return fmt.Sprintf(`(() => {const job=window.__macChromeFetchFileV1;if(!job||job.jobID!==%s||job.state!=="done"||!Array.isArray(job.chunks)||%d<0||%d>=job.chunks.length)return JSON.stringify({state:"missing",index:%d,data:""});return JSON.stringify({state:"chunk",index:%d,data:String(job.chunks[%d]||"")});})()`, string(jobJSON), index, index, index, index, index)
}

func clearFetchFileJavaScript(jobID string) string {
	jobJSON, _ := json.Marshal(jobID)
	return fmt.Sprintf(`(() => {const key="__macChromeFetchFileV1",job=window[key];if(!job)return "absent";if(job.jobID!==%s)return "different-job";window[key]=null;return "cleared";})()`, string(jobJSON))
}
