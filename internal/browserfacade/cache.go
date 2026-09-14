package browserfacade

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/relux-works/mac-infra/internal/docsanitize"
)

type Cache struct {
	Root string
}

type GrepOptions struct {
	Pattern     string
	File        string
	Insensitive bool
	Context     int
	MaxMatches  int
}

type GrepMatch struct {
	File   string   `json:"file"`
	Line   int      `json:"line"`
	Text   string   `json:"text"`
	Before []string `json:"before,omitempty"`
	After  []string `json:"after,omitempty"`
}

func DefaultCacheRoot() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", coded("CACHE_IO_FAILED", "resolve user cache root: %v", err)
	}
	return filepath.Join(root, "mac-infra", "browser-site-cache"), nil
}

func (c Cache) Write(site, key string, items []map[string]string) (string, error) {
	lines := make([][]byte, 0, len(items))
	for _, item := range items {
		if err := validateCacheRecord(item); err != nil {
			return "", err
		}
		line, err := marshalCacheRecord(item)
		if err != nil {
			return "", coded("CACHE_IO_FAILED", "encode cache record: %v", err)
		}
		decision, err := EnforceOutbound(string(line))
		if err != nil || decision.State != OutboundClean {
			if err != nil {
				return "", err
			}
			return "", coded("SENSITIVE_RESPONSE_REFUSED", "cache record was not clean at the outbound boundary")
		}
		lines = append(lines, line)
	}
	directory, err := c.openSiteDirectory(site, true)
	if err != nil {
		return "", err
	}
	defer directory.Close()
	digest := sha256.Sum256([]byte(key))
	name := "query-" + hex.EncodeToString(digest[:8]) + ".jsonl"
	temporaryName, err := cacheTemporaryName()
	if err != nil {
		return "", coded("CACHE_IO_FAILED", "name private cache file: %v", err)
	}
	temporary, err := directory.OpenFile(temporaryName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", coded("CACHE_IO_FAILED", "create private cache file: %v", err)
	}
	defer directory.Remove(temporaryName)
	for _, line := range lines {
		if _, err := temporary.Write(append(line, '\n')); err != nil {
			temporary.Close()
			return "", coded("CACHE_IO_FAILED", "write cache record: %v", err)
		}
	}
	if err := temporary.Close(); err != nil {
		return "", coded("CACHE_IO_FAILED", "close cache file: %v", err)
	}
	if err := directory.Rename(temporaryName, name); err != nil {
		return "", coded("CACHE_IO_FAILED", "publish cache file: %v", err)
	}
	return name, nil
}

func (c Cache) Grep(site string, options GrepOptions) ([]GrepMatch, error) {
	if strings.TrimSpace(options.Pattern) == "" || len(options.Pattern) > 512 {
		return nil, coded("GREP_INVALID", "grep pattern must contain 1..512 characters")
	}
	if options.Context < 0 || options.Context > 5 {
		return nil, coded("GREP_INVALID", "context must be between 0 and 5 lines")
	}
	if options.MaxMatches < 1 || options.MaxMatches > 100 {
		return nil, coded("GREP_INVALID", "max matches must be between 1 and 100")
	}
	if options.File != "" {
		if filepath.Base(options.File) != options.File || !strings.HasSuffix(options.File, ".jsonl") || strings.Contains(options.File, "..") {
			return nil, coded("CACHE_SCOPE_REFUSED", "--file must be one cache .jsonl basename")
		}
	}
	pattern := options.Pattern
	if options.Insensitive {
		pattern = "(?i)" + pattern
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, coded("GREP_INVALID", "invalid regular expression: %v", err)
	}
	directory, err := c.openSiteDirectory(site, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []GrepMatch{}, nil
		}
		return nil, err
	}
	defer directory.Close()
	directoryFile, err := directory.Open(".")
	if err != nil {
		return nil, coded("CACHE_SCOPE_REFUSED", "open physical site cache scope: %v", err)
	}
	entries, err := directoryFile.ReadDir(-1)
	directoryFile.Close()
	if err != nil {
		return nil, coded("CACHE_IO_FAILED", "read site cache: %v", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var matches []GrepMatch
	for _, entry := range entries {
		if len(matches) >= options.MaxMatches {
			break
		}
		name := entry.Name()
		if entry.Type()&os.ModeSymlink != 0 {
			if options.File != "" && name == options.File {
				return nil, coded("CACHE_SCOPE_REFUSED", "explicit cache file must not be a symlink")
			}
			continue
		}
		if entry.IsDir() || !strings.HasSuffix(name, ".jsonl") || (options.File != "" && name != options.File) {
			continue
		}
		lines, readErr := readBoundedLines(directory, name)
		if readErr != nil {
			return nil, readErr
		}
		for i, line := range lines {
			if !compiled.MatchString(line) {
				continue
			}
			start, end := max(0, i-options.Context), min(len(lines), i+options.Context+1)
			match := GrepMatch{File: name, Line: i + 1, Text: line}
			match.Before = append(match.Before, lines[start:i]...)
			match.After = append(match.After, lines[i+1:end]...)
			matches = append(matches, match)
			if len(matches) >= options.MaxMatches {
				break
			}
		}
	}
	if err := enforceOutboundValue(matches); err != nil {
		return nil, err
	}
	return matches, nil
}

func (c Cache) openSiteDirectory(site string, create bool) (*os.Root, error) {
	if !safeNamePattern.MatchString(site) {
		return nil, coded("CACHE_SCOPE_REFUSED", "invalid cache site name")
	}
	var anchorPath, relativeRoot string
	rootPath := strings.TrimSpace(c.Root)
	if rootPath == "" {
		var err error
		anchorPath, err = os.UserConfigDir()
		if err != nil {
			return nil, coded("CACHE_IO_FAILED", "resolve user cache anchor: %v", err)
		}
		relativeRoot = filepath.Join("mac-infra", "browser-site-cache")
	} else {
		absoluteRoot, err := filepath.Abs(rootPath)
		if err != nil {
			return nil, coded("CACHE_SCOPE_REFUSED", "resolve cache root: %v", err)
		}
		anchorPath = filepath.Dir(absoluteRoot)
		relativeRoot = filepath.Base(absoluteRoot)
	}
	if create {
		if err := os.MkdirAll(anchorPath, 0o700); err != nil {
			return nil, coded("CACHE_IO_FAILED", "create trusted cache anchor: %v", err)
		}
	}
	anchor, err := os.OpenRoot(anchorPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !create {
			return nil, fs.ErrNotExist
		}
		return nil, coded("CACHE_IO_FAILED", "open trusted cache anchor: %v", err)
	}
	relativeSite := filepath.Join(relativeRoot, site)
	if err := ensurePhysicalDirectories(anchor, relativeSite, create); err != nil {
		anchor.Close()
		return nil, err
	}
	directory, err := anchor.OpenRoot(relativeSite)
	anchor.Close()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !create {
			return nil, fs.ErrNotExist
		}
		return nil, coded("CACHE_SCOPE_REFUSED", "open physical site cache scope: %v", err)
	}
	return directory, nil
}

func ensurePhysicalDirectories(anchor *os.Root, relative string, create bool) error {
	current := ""
	for _, component := range strings.Split(filepath.Clean(relative), string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return coded("CACHE_SCOPE_REFUSED", "invalid physical cache component")
		}
		current = filepath.Join(current, component)
		info, err := anchor.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			if !create {
				return fs.ErrNotExist
			}
			if err := anchor.Mkdir(current, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
				return coded("CACHE_IO_FAILED", "create physical cache component: %v", err)
			}
			info, err = anchor.Lstat(current)
		}
		if err != nil {
			return coded("CACHE_IO_FAILED", "inspect physical cache component: %v", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return coded("CACHE_SCOPE_REFUSED", "cache path component must not be a symlink")
		}
		if !info.IsDir() {
			return coded("CACHE_SCOPE_REFUSED", "cache path component must be a directory")
		}
	}
	return nil
}

func cacheTemporaryName() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return ".cache-" + hex.EncodeToString(random[:]) + ".tmp", nil
}

func readBoundedLines(directory *os.Root, name string) ([]string, error) {
	file, err := directory.Open(name)
	if err != nil {
		return nil, coded("CACHE_SCOPE_REFUSED", "open cache file inside physical scope: %v", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, coded("CACHE_IO_FAILED", "inspect cache file: %v", err)
	}
	if info.Size() > 4*1024*1024 {
		return nil, coded("CACHE_SCOPE_REFUSED", "cache file exceeds 4 MiB search bound")
	}
	var lines []string
	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		decision, boundaryErr := EnforceOutbound(line)
		if boundaryErr != nil {
			return nil, boundaryErr
		}
		if decision.State != OutboundClean || decision.Value != line {
			return nil, coded("SENSITIVE_RESPONSE_REFUSED", "cache contained unsanitized material")
		}
		var record map[string]string
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, coded("CACHE_IO_FAILED", "cache file contains malformed JSONL")
		}
		if err := validateCacheRecord(record); err != nil {
			return nil, err
		}
		canonical, err := marshalCacheRecord(record)
		if err != nil {
			return nil, coded("CACHE_IO_FAILED", "canonicalize cache record")
		}
		canonicalDecision, err := EnforceOutbound(string(canonical))
		if err != nil || canonicalDecision.State != OutboundClean {
			if err != nil {
				return nil, err
			}
			return nil, coded("SENSITIVE_RESPONSE_REFUSED", "cache record was not clean at the outbound boundary")
		}
		lines = append(lines, string(canonical))
		if len(lines) > maximumScannedItems {
			return nil, coded("CACHE_SCOPE_REFUSED", "cache file exceeds %d record search bound", maximumScannedItems)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, coded("CACHE_IO_FAILED", "read cache file: %v", err)
	}
	return lines, nil
}

func marshalCacheRecord(record map[string]string) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(record); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

func validateCacheRecord(record map[string]string) error {
	for key, value := range record {
		if !safePublicField(key) {
			return coded("SENSITIVE_RESPONSE_REFUSED", "cache contained a forbidden field")
		}
		decision, err := EnforceOutbound(value)
		if err != nil || decision.State != OutboundClean || decision.Value != value {
			return coded("SENSITIVE_RESPONSE_REFUSED", "cache contained unsanitized material")
		}
	}
	sanitized, _, err := docsanitize.SanitizeRecords([]map[string]string{record})
	if err != nil {
		return coded("SENSITIVE_RESPONSE_UNKNOWN", "cache record could not be safely depersonalized")
	}
	if len(sanitized) != 1 || !maps.Equal(sanitized[0], record) {
		return coded("SENSITIVE_RESPONSE_REFUSED", "cache contained personal data")
	}
	return nil
}
