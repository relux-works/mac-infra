package javatruststore

import (
	"context"
	"crypto/x509"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const maximumCommandOutput = 32 << 20

type ExecRunner struct{}

func (ExecRunner) CombinedOutput(ctx context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	output, err := cmd.CombinedOutput()
	if len(output) > maximumCommandOutput {
		return nil, refusal(CauseMalformedSource, nil)
	}
	return output, err
}

func (ExecRunner) Run(ctx context.Context, name string, args []string, dir string, env []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

type SystemKeychainSource struct {
	Runner CommandRunner
}

func (s SystemKeychainSource) Certificates(ctx context.Context) ([]*x509.Certificate, error) {
	if runtime.GOOS != "darwin" {
		return nil, refusal(CauseUnsupportedOS, nil)
	}
	runner := s.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	output, err := runner.CombinedOutput(ctx, "/usr/bin/security", []string{
		"find-certificate", "-a", "-p", "/Library/Keychains/System.keychain",
	}, "", nil)
	if err != nil {
		return nil, operational(CauseKeychainRead, err)
	}
	return ParseCertificatesPEM(output)
}

type KeytoolImporter struct {
	Runner CommandRunner
}

func (k KeytoolImporter) Import(ctx context.Context, keytool, storePath, certificatePath, alias string) (string, error) {
	runner := k.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	var storeType string
	for _, candidate := range []string{"JKS", "PKCS12"} {
		_, err := runner.CombinedOutput(ctx, keytool, []string{
			"-list", "-keystore", storePath, "-storepass", storePassword, "-storetype", candidate,
		}, filepath.Dir(storePath), javaEnvironment(os.Environ(), filepath.Dir(storePath)))
		if err == nil {
			storeType = candidate
			break
		}
	}
	if storeType == "" {
		return "", operational(CauseCACertsRead, nil)
	}
	_, err := runner.CombinedOutput(ctx, keytool, []string{
		"-importcert", "-noprompt", "-alias", alias, "-file", certificatePath,
		"-keystore", storePath, "-storepass", storePassword, "-storetype", storeType,
	}, filepath.Dir(storePath), javaEnvironment(os.Environ(), filepath.Dir(storePath)))
	if err != nil {
		return "", operational(CauseKeytoolFailed, err)
	}
	return storeType, nil
}

func javaEnvironment(base []string, home string) []string {
	drop := map[string]bool{
		"JAVA_TOOL_OPTIONS": true, "_JAVA_OPTIONS": true, "JDK_JAVA_OPTIONS": true,
		"JAVA_OPTS": true, "GRADLE_OPTS": true, "HOME": true,
		"TMPDIR": true, "TMP": true, "TEMP": true,
	}
	env := filterEnvironment(base, drop)
	return append(env, "HOME="+home, "TMPDIR="+home, "TMP="+home, "TEMP="+home)
}

func filterEnvironment(base []string, drop map[string]bool) []string {
	env := make([]string, 0, len(base)+4)
	for _, item := range base {
		key, _, ok := strings.Cut(item, "=")
		if ok && !drop[key] {
			env = append(env, item)
		}
	}
	return env
}
