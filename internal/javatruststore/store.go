package javatruststore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const manifestSchema = 1

type resolvedOptions struct {
	project     string
	javaHome    string
	keytool     string
	cacerts     string
	fingerprint string
	output      string
}

func (t Tool) Build(ctx context.Context, options Options) (StoreInfo, error) {
	resolved, err := resolveOptions(options, false)
	if err != nil {
		return StoreInfo{}, err
	}
	source := t.Source
	if source == nil {
		source = SystemKeychainSource{Runner: t.Commands}
	}
	certificates, err := source.Certificates(ctx)
	if err != nil {
		return StoreInfo{}, err
	}
	now := t.Now
	if now == nil {
		now = time.Now
	}
	root, err := selectRoot(certificates, resolved.fingerprint, now())
	if err != nil {
		return StoreInfo{}, err
	}
	cacertsBytes, err := os.ReadFile(resolved.cacerts)
	if err != nil {
		return StoreInfo{}, operational(CauseCACertsRead, err)
	}
	cacertsHash := sha256.Sum256(cacertsBytes)
	if err := os.Mkdir(resolved.output, 0700); err != nil {
		if os.IsExist(err) {
			return StoreInfo{}, refusal(CauseOutputExists, err)
		}
		return StoreInfo{}, refusal(CauseParentMissing, err)
	}
	created := true
	defer func() {
		if created {
			_ = os.RemoveAll(resolved.output)
		}
	}()
	if err := os.Chmod(resolved.output, 0700); err != nil {
		return StoreInfo{}, operational(CauseProcessFailed, err)
	}
	storePath := filepath.Join(resolved.output, storeFileName)
	if err := writePrivateFile(storePath, cacertsBytes); err != nil {
		return StoreInfo{}, operational(CauseProcessFailed, err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	rootPath := filepath.Join(resolved.output, rootFileName)
	if err := writePrivateFile(rootPath, rootPEM); err != nil {
		return StoreInfo{}, operational(CauseProcessFailed, err)
	}
	commands := t.Commands
	if commands == nil {
		commands = ExecRunner{}
	}
	importer := t.Importer
	if importer == nil {
		importer = KeytoolImporter{Runner: commands}
	}
	rootHash := fingerprint(root)
	storeType, err := importer.Import(ctx, resolved.keytool, storePath, rootPath, "mac-infra-extra-root-"+rootHash)
	if err != nil {
		return StoreInfo{}, err
	}
	if storeType != "JKS" && storeType != "PKCS12" {
		return StoreInfo{}, operational(CauseStoreType, nil)
	}
	if err := os.Remove(rootPath); err != nil {
		return StoreInfo{}, operational(CauseProcessFailed, err)
	}
	if err := os.Chmod(storePath, 0600); err != nil {
		return StoreInfo{}, operational(CauseProcessFailed, err)
	}
	storeBytes, err := os.ReadFile(storePath)
	if err != nil {
		return StoreInfo{}, operational(CauseProcessFailed, err)
	}
	storeHash := sha256.Sum256(storeBytes)
	currentCACerts, err := os.ReadFile(resolved.cacerts)
	if err != nil {
		return StoreInfo{}, operational(CauseCACertsRead, err)
	}
	currentHash := sha256.Sum256(currentCACerts)
	if !bytes.Equal(cacertsHash[:], currentHash[:]) {
		return StoreInfo{}, refusal(CauseStaleCACerts, nil)
	}
	manifest := Manifest{
		Schema:        manifestSchema,
		CACertsSHA256: hex.EncodeToString(cacertsHash[:]),
		RootSHA256:    resolved.fingerprint,
		StoreSHA256:   hex.EncodeToString(storeHash[:]),
		StoreType:     storeType,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return StoreInfo{}, operational(CauseProcessFailed, err)
	}
	if err := writePrivateFile(filepath.Join(resolved.output, manifestName), append(manifestBytes, '\n')); err != nil {
		return StoreInfo{}, operational(CauseProcessFailed, err)
	}
	created = false
	return storeInfo(resolved, storeType), nil
}

func (t Tool) Verify(ctx context.Context, options Options) (StoreInfo, error) {
	resolved, err := resolveOptions(options, true)
	if err != nil {
		return StoreInfo{}, err
	}
	manifestPath := filepath.Join(resolved.output, manifestName)
	manifestBytes, err := readPrivateRegularFile(manifestPath)
	if err != nil {
		return StoreInfo{}, refusal(CauseStaleManifest, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return StoreInfo{}, refusal(CauseStaleManifest, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return StoreInfo{}, refusal(CauseStaleManifest, err)
	}
	if manifest.Schema != manifestSchema || manifest.StoreType != "JKS" && manifest.StoreType != "PKCS12" || !isSHA256(manifest.CACertsSHA256) || !isSHA256(manifest.RootSHA256) || !isSHA256(manifest.StoreSHA256) {
		return StoreInfo{}, refusal(CauseStaleManifest, nil)
	}
	if manifest.RootSHA256 != resolved.fingerprint {
		return StoreInfo{}, refusal(CauseStaleRoot, nil)
	}
	source := t.Source
	if source == nil {
		source = SystemKeychainSource{Runner: t.Commands}
	}
	certificates, err := source.Certificates(ctx)
	if err != nil {
		return StoreInfo{}, err
	}
	now := t.Now
	if now == nil {
		now = time.Now
	}
	if _, err := selectRoot(certificates, resolved.fingerprint, now()); err != nil {
		return StoreInfo{}, err
	}
	cacerts, err := os.ReadFile(resolved.cacerts)
	if err != nil {
		return StoreInfo{}, operational(CauseCACertsRead, err)
	}
	cacertsHash := sha256.Sum256(cacerts)
	if hex.EncodeToString(cacertsHash[:]) != manifest.CACertsSHA256 {
		return StoreInfo{}, refusal(CauseStaleCACerts, nil)
	}
	storePath := filepath.Join(resolved.output, storeFileName)
	storeBytes, err := readPrivateRegularFile(storePath)
	if err != nil {
		return StoreInfo{}, refusal(CauseStoreModified, err)
	}
	storeHash := sha256.Sum256(storeBytes)
	if hex.EncodeToString(storeHash[:]) != manifest.StoreSHA256 {
		return StoreInfo{}, refusal(CauseStoreModified, nil)
	}
	return storeInfo(resolved, manifest.StoreType), nil
}

func resolveOptions(options Options, outputExists bool) (resolvedOptions, error) {
	fingerprintValue, err := NormalizeFingerprint(options.Fingerprint)
	if err != nil {
		return resolvedOptions{}, err
	}
	project, err := canonicalDirectory(options.ProjectDir)
	if err != nil {
		return resolvedOptions{}, invalid(CauseOutsideProject, err)
	}
	javaHome, err := canonicalDirectory(options.JavaHome)
	if err != nil {
		return resolvedOptions{}, invalid(CauseCACertsRead, err)
	}
	keytool := filepath.Join(javaHome, "bin", "keytool")
	keytoolInfo, err := os.Stat(keytool)
	if err != nil || !keytoolInfo.Mode().IsRegular() || keytoolInfo.Mode().Perm()&0111 == 0 {
		return resolvedOptions{}, invalid(CauseKeytoolFailed, err)
	}
	cacerts := filepath.Join(javaHome, "lib", "security", "cacerts")
	cacertsInfo, err := os.Stat(cacerts)
	if err != nil || !cacertsInfo.Mode().IsRegular() {
		return resolvedOptions{}, operational(CauseCACertsRead, err)
	}
	output, err := resolveOutputPath(project, options.OutputDir, outputExists)
	if err != nil {
		return resolvedOptions{}, err
	}
	return resolvedOptions{
		project: project, javaHome: javaHome, keytool: keytool, cacerts: cacerts,
		fingerprint: fingerprintValue, output: output,
	}, nil
}

func canonicalDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("directory must be absolute")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(canonical)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("path is not a directory")
	}
	return canonical, nil
}

func resolveOutputPath(project, relative string, mustExist bool) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.VolumeName(relative) != "" {
		return "", refusal(CauseOutsideProject, nil)
	}
	clean := filepath.Clean(relative)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean != relative {
		return "", refusal(CauseOutsideProject, nil)
	}
	parts := strings.Split(clean, string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", refusal(CauseOutsideProject, nil)
		}
	}
	current := project
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if index != len(parts)-1 || mustExist {
				return "", refusal(CauseParentMissing, err)
			}
			return current, nil
		}
		if err != nil {
			return "", operational(CauseProcessFailed, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", refusal(CauseSymlink, nil)
		}
		if index != len(parts)-1 && !info.IsDir() {
			return "", refusal(CauseParentMissing, nil)
		}
	}
	if !mustExist {
		return "", refusal(CauseOutputExists, nil)
	}
	info, err := os.Lstat(current)
	if err != nil || !info.IsDir() {
		return "", refusal(CauseParentMissing, err)
	}
	if info.Mode().Perm() != 0700 {
		return "", refusal(CauseStorePermissions, nil)
	}
	return current, nil
}

func writePrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return os.Chmod(path, 0600)
}

func readPrivateRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, refusal(CauseSymlink, nil)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if info.Mode().Perm() != 0600 {
		return nil, refusal(CauseStorePermissions, nil)
	}
	return os.ReadFile(path)
}

func storeInfo(options resolvedOptions, storeType string) StoreInfo {
	return StoreInfo{
		ProjectDir: options.project,
		JavaHome:   options.javaHome,
		OutputDir:  options.output,
		StorePath:  filepath.Join(options.output, storeFileName),
		StoreType:  storeType,
		GradleHome: filepath.Join(options.output, gradleHomeName),
	}
}

func isSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}
