package javatruststore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var fixtureTime = time.Date(2026, time.November, 18, 12, 0, 0, 0, time.UTC)

type fixture struct {
	options  Options
	root     *x509.Certificate
	cacerts  string
	importer *fixtureImporter
	tool     Tool
}

type fixtureImporter struct {
	storeType string
	err       error
	calls     int
	alias     string
}

func (f *fixtureImporter) Import(_ context.Context, _ string, storePath, certificatePath, alias string) (string, error) {
	f.calls++
	f.alias = alias
	if f.err != nil {
		return "", f.err
	}
	rootPEM, err := os.ReadFile(certificatePath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(rootPEM)
	if block == nil {
		return "", errors.New("missing fixture certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(storePath)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(root.Raw)
	data = append(data, []byte("\nfixture-root="+hex.EncodeToString(sum[:]))...)
	if err := os.WriteFile(storePath, data, 0600); err != nil {
		return "", err
	}
	return f.storeType, nil
}

type processCapture struct {
	name string
	args []string
	dir  string
	env  []string
	err  error
	call int
}

func (p *processCapture) Run(_ context.Context, name string, args []string, dir string, env []string, _ io.Reader, _, _ io.Writer) error {
	p.call++
	p.name, p.dir = name, dir
	p.args = append([]string(nil), args...)
	p.env = append([]string(nil), env...)
	return p.err
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	project := filepath.Join(t.TempDir(), "project space")
	javaHome := filepath.Join(t.TempDir(), "jdk")
	for _, dir := range []string{
		project,
		filepath.Join(project, ".task"),
		filepath.Join(javaHome, "bin"),
		filepath.Join(javaHome, "lib", "security"),
	} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	canonicalProject, err := filepath.EvalSymlinks(project)
	if err != nil {
		t.Fatal(err)
	}
	canonicalJavaHome, err := filepath.EvalSymlinks(javaHome)
	if err != nil {
		t.Fatal(err)
	}
	project, javaHome = canonicalProject, canonicalJavaHome
	keytool := filepath.Join(javaHome, "bin", "keytool")
	if err := os.WriteFile(keytool, []byte("fixture executable"), 0700); err != nil {
		t.Fatal(err)
	}
	cacerts := filepath.Join(javaHome, "lib", "security", "cacerts")
	if err := os.WriteFile(cacerts, []byte("fixture default cacerts"), 0600); err != nil {
		t.Fatal(err)
	}
	root := makeCertificate(t, fixtureTime.Add(-time.Hour), fixtureTime.Add(24*time.Hour), true, "Fixture Root", "Fixture Root")
	fingerprintValue := fingerprint(root)
	importer := &fixtureImporter{storeType: "JKS"}
	tool := Tool{
		Source: CertificateSourceFunc(func(context.Context) ([]*x509.Certificate, error) {
			return []*x509.Certificate{root}, nil
		}),
		Importer: importer,
		Now:      func() time.Time { return fixtureTime },
	}
	return fixture{
		options: Options{
			ProjectDir: project, JavaHome: javaHome, Fingerprint: fingerprintValue, OutputDir: ".task/trust",
		},
		root: root, cacerts: cacerts, importer: importer, tool: tool,
	}
}

func makeCertificate(t *testing.T, notBefore, notAfter time.Time, isCA bool, subject, issuer string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial := big.NewInt(time.Now().UnixNano())
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	parent := template
	if issuer != subject {
		parent = &x509.Certificate{Subject: pkix.Name{CommonName: issuer}, IsCA: true, BasicConstraintsValid: true}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func makeBadSelfSignature(t *testing.T) *x509.Certificate {
	t.Helper()
	valid := makeCertificate(t, fixtureTime.Add(-time.Hour), fixtureTime.Add(time.Hour), true, "Bad Signature Root", "Bad Signature Root")
	der := append([]byte(nil), valid.Raw...)
	der[len(der)-1] ^= 1
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// Claim: a valid pinned CA root is added to a private copy, the source cacerts bytes stay unchanged, and the resulting manifest verifies.
func TestBuildAndVerifyPositive(t *testing.T) {
	f := newFixture(t)
	before, err := os.ReadFile(f.cacerts)
	if err != nil {
		t.Fatal(err)
	}
	beforeHash := sha256.Sum256(before)
	info, err := f.tool.Build(context.Background(), f.options)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if info.StoreType != "JKS" || info.StorePath != filepath.Join(f.projectOutput(), storeFileName) {
		t.Fatalf("unexpected store path or type: type=%q output=%q", info.StoreType, info.StorePath)
	}
	after, err := os.ReadFile(f.cacerts)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(after) != beforeHash || !bytes.Equal(before, after) {
		t.Fatal("build modified the JDK cacerts source")
	}
	if got := fileMode(t, info.OutputDir); got != 0700 {
		t.Fatalf("output mode = %04o, want 0700", got)
	}
	if got := fileMode(t, info.StorePath); got != 0600 {
		t.Fatalf("store mode = %04o, want 0600", got)
	}
	if got := fileMode(t, filepath.Join(info.OutputDir, manifestName)); got != 0600 {
		t.Fatalf("manifest mode = %04o, want 0600", got)
	}
	if _, err := os.Lstat(filepath.Join(info.OutputDir, rootFileName)); !os.IsNotExist(err) {
		t.Fatalf("temporary root certificate remains: %v", err)
	}
	if f.importer.alias != "mac-infra-extra-root-"+fingerprint(f.root) {
		t.Fatalf("unexpected keytool alias: %q", f.importer.alias)
	}
	if _, err := f.tool.Verify(context.Background(), f.options); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func (f fixture) projectOutput() string {
	return filepath.Join(f.options.ProjectDir, f.options.OutputDir)
}

// Claim: selection accepts a valid root and refuses missing, duplicate, non-CA, non-self-signed, expired, and not-yet-valid matches with distinct typed causes.
func TestSelectRootCompatibilityAndRefusals(t *testing.T) {
	valid := makeCertificate(t, fixtureTime.Add(-time.Hour), fixtureTime.Add(time.Hour), true, "Valid Root", "Valid Root")
	nonCA := makeCertificate(t, fixtureTime.Add(-time.Hour), fixtureTime.Add(time.Hour), false, "Leaf", "Leaf")
	nonSelfSigned := makeCertificate(t, fixtureTime.Add(-time.Hour), fixtureTime.Add(time.Hour), true, "Intermediate", "Other Issuer")
	badSelfSignature := makeBadSelfSignature(t)
	expired := makeCertificate(t, fixtureTime.Add(-2*time.Hour), fixtureTime.Add(-time.Hour), true, "Expired Root", "Expired Root")
	notYet := makeCertificate(t, fixtureTime.Add(time.Hour), fixtureTime.Add(2*time.Hour), true, "Future Root", "Future Root")
	tests := []struct {
		name  string
		certs []*x509.Certificate
		pin   string
		want  string
	}{
		{name: "valid-positive", certs: []*x509.Certificate{valid}, pin: fingerprint(valid)},
		{name: "no-match", certs: []*x509.Certificate{valid}, pin: fingerprint(nonCA), want: CauseNoMatch},
		{name: "two-matches", certs: []*x509.Certificate{valid, valid}, pin: fingerprint(valid), want: CauseMultipleMatches},
		{name: "non-ca", certs: []*x509.Certificate{nonCA}, pin: fingerprint(nonCA), want: CauseNotCA},
		{name: "not-self-signed", certs: []*x509.Certificate{nonSelfSigned}, pin: fingerprint(nonSelfSigned), want: CauseNotSelfSigned},
		{name: "bad-self-signature", certs: []*x509.Certificate{badSelfSignature}, pin: fingerprint(badSelfSignature), want: CauseNotSelfSigned},
		{name: "expired", certs: []*x509.Certificate{expired}, pin: fingerprint(expired), want: CauseExpired},
		{name: "not-yet-valid", certs: []*x509.Certificate{notYet}, pin: fingerprint(notYet), want: CauseNotYetValid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := selectRoot(test.certs, test.pin, fixtureTime)
			if test.want == "" {
				if err != nil || got == nil || !bytes.Equal(got.Raw, valid.Raw) {
					t.Fatalf("valid selection got (%v, %v)", got, err)
				}
				return
			}
			if Cause(err) != test.want || ExitCode(err) != ExitRefusal || got != nil {
				t.Fatalf("got root=%v cause=%q exit=%d, want cause=%q", got, Cause(err), ExitCode(err), test.want)
			}
		})
	}
}

// Claim: Build refuses every invalid certificate selection before changing project output or JDK state, while a valid root still builds successfully.
func TestBuildSelectionRefusalsPreserveState(t *testing.T) {
	valid := makeCertificate(t, fixtureTime.Add(-time.Hour), fixtureTime.Add(time.Hour), true, "Valid Root", "Valid Root")
	other := makeCertificate(t, fixtureTime.Add(-time.Hour), fixtureTime.Add(time.Hour), true, "Other Root", "Other Root")
	nonCA := makeCertificate(t, fixtureTime.Add(-time.Hour), fixtureTime.Add(time.Hour), false, "Leaf", "Leaf")
	nonSelfSigned := makeCertificate(t, fixtureTime.Add(-time.Hour), fixtureTime.Add(time.Hour), true, "Intermediate", "Other Issuer")
	badSelfSignature := makeBadSelfSignature(t)
	expired := makeCertificate(t, fixtureTime.Add(-2*time.Hour), fixtureTime.Add(-time.Hour), true, "Expired Root", "Expired Root")
	notYet := makeCertificate(t, fixtureTime.Add(time.Hour), fixtureTime.Add(2*time.Hour), true, "Future Root", "Future Root")
	tests := []struct {
		name  string
		certs []*x509.Certificate
		pin   string
		want  string
	}{
		{name: "valid-positive", certs: []*x509.Certificate{valid}, pin: fingerprint(valid)},
		{name: "no-match", certs: []*x509.Certificate{valid}, pin: fingerprint(other), want: CauseNoMatch},
		{name: "two-matches", certs: []*x509.Certificate{valid, valid}, pin: fingerprint(valid), want: CauseMultipleMatches},
		{name: "non-ca", certs: []*x509.Certificate{nonCA}, pin: fingerprint(nonCA), want: CauseNotCA},
		{name: "not-self-signed", certs: []*x509.Certificate{nonSelfSigned}, pin: fingerprint(nonSelfSigned), want: CauseNotSelfSigned},
		{name: "bad-self-signature", certs: []*x509.Certificate{badSelfSignature}, pin: fingerprint(badSelfSignature), want: CauseNotSelfSigned},
		{name: "expired", certs: []*x509.Certificate{expired}, pin: fingerprint(expired), want: CauseExpired},
		{name: "not-yet-valid", certs: []*x509.Certificate{notYet}, pin: fingerprint(notYet), want: CauseNotYetValid},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			f.options.Fingerprint = test.pin
			f.tool.Source = CertificateSourceFunc(func(context.Context) ([]*x509.Certificate, error) {
				return test.certs, nil
			})
			before := filesystemSnapshot(t, f.options.ProjectDir, f.options.JavaHome)
			info, err := f.tool.Build(context.Background(), f.options)
			if test.want == "" {
				if err != nil {
					t.Fatalf("valid Build failed: %v", err)
				}
				if got := fileMode(t, info.StorePath); got != 0600 {
					t.Fatalf("positive store mode = %04o, want 0600", got)
				}
				return
			}
			if Cause(err) != test.want || ExitCode(err) != ExitRefusal {
				t.Fatalf("Build cause=%q exit=%d, want cause=%q refusal", Cause(err), ExitCode(err), test.want)
			}
			after := filesystemSnapshot(t, f.options.ProjectDir, f.options.JavaHome)
			if !equalFilesystemSnapshots(before, after) {
				t.Fatal("certificate-selection refusal changed project or JDK state")
			}
		})
	}
}

// Claim: fingerprints must be exactly 32 hexadecimal bytes, case-normalized before pin comparison.
func TestNormalizeFingerprint(t *testing.T) {
	valid := strings.Repeat("aB", 32)
	got, err := NormalizeFingerprint(valid)
	if err != nil || got != strings.ToLower(valid) {
		t.Fatalf("NormalizeFingerprint(%q) = %q, %v", valid, got, err)
	}
	for _, value := range []string{"", "abc", strings.Repeat("z", 64), strings.Repeat("a", 66)} {
		if _, err := NormalizeFingerprint(value); Cause(err) != CauseInvalidFingerprint {
			t.Errorf("NormalizeFingerprint(%q) cause = %q", value, Cause(err))
		}
	}
}

// Claim: a project-relative output path succeeds, while outside-project and symlink paths refuse without changing project, JDK, or target state.
func TestOutputPathRefusals(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
		want string
	}{
		{name: "project-relative-positive", path: ".task/trust"},
		{name: "outside-dir", path: "../outside/trust", want: CauseOutsideProject},
		{name: "symlink-target", path: "linked/trust", want: CauseSymlink},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			var extraRoots []string
			if test.want != "" {
				outside := filepath.Join(filepath.Dir(f.options.ProjectDir), "outside")
				if err := os.Mkdir(outside, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(outside, "sentinel"), []byte("outside fixture"), 0600); err != nil {
					t.Fatal(err)
				}
				extraRoots = append(extraRoots, outside)
				if test.name == "symlink-target" {
					if err := os.Symlink(outside, filepath.Join(f.options.ProjectDir, "linked")); err != nil {
						t.Fatal(err)
					}
				}
			}
			options := f.options
			options.OutputDir = test.path
			roots := append([]string{f.options.ProjectDir, f.options.JavaHome}, extraRoots...)
			before := filesystemSnapshot(t, roots...)
			info, err := f.tool.Build(context.Background(), options)
			if test.want == "" {
				if err != nil {
					t.Fatalf("project-relative Build failed: %v", err)
				}
				if info.OutputDir != f.projectOutput() || f.importer.calls != 1 {
					t.Fatalf("positive output=%q importer calls=%d", info.OutputDir, f.importer.calls)
				}
				return
			}
			if Cause(err) != test.want || ExitCode(err) != ExitRefusal {
				t.Fatalf("Build cause=%q exit=%d, want cause=%q refusal", Cause(err), ExitCode(err), test.want)
			}
			if f.importer.calls != 0 {
				t.Fatal("refused output path reached keytool importer")
			}
			after := filesystemSnapshot(t, roots...)
			if !equalFilesystemSnapshots(before, after) {
				t.Fatal("output-path refusal changed project, JDK, or target state")
			}
		})
	}
}

// Claim: an importer failure removes its partial private output and leaves all project files outside that output unchanged.
func TestBuildFailureCleansPartialOutput(t *testing.T) {
	f := newFixture(t)
	f.importer.err = operational(CauseKeytoolFailed, errors.New("fixture failure"))
	projectParent := filepath.Dir(f.options.ProjectDir)
	javaParent := filepath.Dir(f.options.JavaHome)
	beforeProject := treeSnapshot(t, projectParent)
	beforeJava := treeSnapshot(t, javaParent)
	if _, err := f.tool.Build(context.Background(), f.options); Cause(err) != CauseKeytoolFailed {
		t.Fatalf("Build cause = %q", Cause(err))
	}
	if _, err := os.Lstat(f.projectOutput()); !os.IsNotExist(err) {
		t.Fatalf("partial output remains: %v", err)
	}
	afterProject := treeSnapshot(t, projectParent)
	afterJava := treeSnapshot(t, javaParent)
	if !equalTrees(beforeProject, afterProject) || !equalTrees(beforeJava, afterJava) {
		t.Fatalf("failure changed files outside output: project before=%v after=%v; JDK before=%v after=%v", beforeProject, afterProject, beforeJava, afterJava)
	}
}

// Claim: positive verification and stale pin, cacerts, or store refusals preserve project/JDK bytes and mtimes, including store and manifest state, without invoking the importer.
func TestVerifyRefusesStaleInputsWithoutRebuild(t *testing.T) {
	other := makeCertificate(t, fixtureTime.Add(-time.Hour), fixtureTime.Add(time.Hour), true, "Other Root", "Other Root")
	f := newFixture(t)
	if _, err := f.tool.Build(context.Background(), f.options); err != nil {
		t.Fatal(err)
	}
	before := filesystemSnapshot(t, f.options.ProjectDir, f.options.JavaHome)
	if _, err := f.tool.Verify(context.Background(), f.options); err != nil {
		t.Fatalf("unchanged verify failed: %v", err)
	}
	if after := filesystemSnapshot(t, f.options.ProjectDir, f.options.JavaHome); !equalFilesystemSnapshots(before, after) {
		t.Fatal("successful verify changed project or JDK state")
	}
	tests := []struct {
		name    string
		want    string
		prepare func(*testing.T, fixture) Options
	}{
		{name: "stale-pin", want: CauseStaleRoot, prepare: func(_ *testing.T, f fixture) Options {
			options := f.options
			options.Fingerprint = fingerprint(other)
			return options
		}},
		{name: "stale-cacerts", want: CauseStaleCACerts, prepare: func(t *testing.T, f fixture) Options {
			if err := os.WriteFile(f.cacerts, []byte("changed default cacerts"), 0600); err != nil {
				t.Fatal(err)
			}
			return f.options
		}},
		{name: "modified-store", want: CauseStoreModified, prepare: func(t *testing.T, f fixture) Options {
			storePath := filepath.Join(f.projectOutput(), storeFileName)
			if err := os.WriteFile(storePath, []byte("modified store"), 0600); err != nil {
				t.Fatal(err)
			}
			return f.options
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			if _, err := f.tool.Build(context.Background(), f.options); err != nil {
				t.Fatal(err)
			}
			calls := f.importer.calls
			options := test.prepare(t, f)
			before := filesystemSnapshot(t, f.options.ProjectDir, f.options.JavaHome)
			if _, err := f.tool.Verify(context.Background(), options); Cause(err) != test.want || ExitCode(err) != ExitRefusal {
				t.Fatalf("verify cause=%q exit=%d, want cause=%q refusal", Cause(err), ExitCode(err), test.want)
			}
			after := filesystemSnapshot(t, f.options.ProjectDir, f.options.JavaHome)
			if !equalFilesystemSnapshots(before, after) {
				t.Fatal("stale verification changed project or JDK bytes or mtimes")
			}
			if f.importer.calls != calls {
				t.Fatalf("verify called importer %d times; want %d", f.importer.calls, calls)
			}
		})
	}
}

// Claim: project Gradle execution uses only the verified wrapper, selected JDK, private truststore, and an isolated daemon home.
func TestGradleUsesProjectScopedSettings(t *testing.T) {
	f := newFixture(t)
	if _, err := f.tool.Build(context.Background(), f.options); err != nil {
		t.Fatal(err)
	}
	gradleHome := filepath.Join(f.projectOutput(), gradleHomeName)
	if err := os.Mkdir(gradleHome, 0700); err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(f.projectOutput(), storeFileName)
	projectSettings := strings.Join([]string{
		"systemProp.javax.net.ssl.trustStore=" + storePath,
		"systemProp.javax.net.ssl.trustStorePassword=" + storePassword,
		"systemProp.javax.net.ssl.trustStoreType=JKS",
		"systemProp.gradle.user.home=" + gradleHome,
		"systemProp.org.gradle.java.home=" + f.options.JavaHome,
		"org.gradle.java.home=" + f.options.JavaHome,
		"org.gradle.jvmargs=-Xmx1g -Djavax.net.ssl.trustStore=\"" + storePath + "\"",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(f.options.ProjectDir, "gradle.properties"), []byte(projectSettings), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gradleHome, "gradle.properties"), []byte("systemProp.javax.net.ssl.trustStore="+storePath+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(f.options.ProjectDir, "gradlew")
	if err := os.WriteFile(wrapper, []byte("fixture wrapper"), 0700); err != nil {
		t.Fatal(err)
	}
	process := &processCapture{}
	f.tool.Processes = process
	t.Setenv("JAVA_TOOL_OPTIONS", "-Dfixture.previous=1")
	t.Setenv("_JAVA_OPTIONS", "-Dfixture.other=1")
	t.Setenv("JDK_JAVA_OPTIONS", "-Dfixture.third=1")
	t.Setenv("JAVA_HOME", "/wrong/java")
	t.Setenv("GRADLE_OPTS", "-Dfixture.gradle=1")
	t.Setenv("GRADLE_USER_HOME", "/wrong/gradle-home")
	gradleArgs := []string{
		"--offline", "assemble",
		"--gradle-user-home=" + gradleHome,
		"-g", gradleHome,
		"--project-dir=" + f.options.ProjectDir,
		"-p", ".",
		"-Djavax.net.ssl.trustStore=" + storePath,
		"--system-prop=javax.net.ssl.trustStorePassword=" + storePassword,
		"--system-prop", "javax.net.ssl.trustStoreType=JKS",
		"-Dgradle.user.home=" + gradleHome,
		"-Dorg.gradle.java.home=" + f.options.JavaHome,
		"-Dorg.gradle.jvmargs=-Xmx1g '-Djavax.net.ssl.trustStore=" + storePath + "'",
	}
	if err := f.tool.Gradle(context.Background(), f.options, gradleArgs, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if process.call != 1 || process.name != "./gradlew" || process.dir != f.options.ProjectDir {
		t.Fatalf("unexpected process name=%q dir=%q call=%d", process.name, process.dir, process.call)
	}
	joinedArgs := strings.Join(process.args, " ")
	for _, expected := range []string{
		"--gradle-user-home=" + gradleHome,
		"-Dorg.gradle.java.home=" + f.options.JavaHome,
		"-Djavax.net.ssl.trustStore=" + storePath,
		"-Djavax.net.ssl.trustStorePassword=" + storePassword,
		"-Djavax.net.ssl.trustStoreType=JKS",
		"--offline assemble",
		"--project-dir=" + f.options.ProjectDir,
		"-g " + gradleHome,
		"-p .",
	} {
		if !strings.Contains(joinedArgs, expected) {
			t.Errorf("Gradle args %q missing %q", joinedArgs, expected)
		}
	}
	env := strings.Join(process.env, "\n")
	for _, expected := range []string{
		"JAVA_HOME=" + f.options.JavaHome,
		"GRADLE_USER_HOME=" + gradleHome,
		"JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=\"" + storePath + "\"",
	} {
		if !strings.Contains(env, expected) {
			t.Errorf("Gradle environment missing %q", expected)
		}
	}
	for _, forbidden := range []string{"fixture.previous", "fixture.other", "fixture.third", "fixture.gradle", "/wrong/java", "/wrong/gradle-home"} {
		if strings.Contains(env, forbidden) {
			t.Errorf("Gradle environment retained %q", forbidden)
		}
	}
	if got := fileMode(t, filepath.Join(f.projectOutput(), gradleHomeName)); got != 0700 {
		t.Fatalf("Gradle home mode = %04o", got)
	}
}

// Claim: without daemon JVM criteria Gradle launches with the selected settings, while an unprovable criteria file is refused before creating daemon state or starting the wrapper.
func TestGradleDaemonCriteriaRefusalAndPositive(t *testing.T) {
	t.Run("no-criteria-positive", func(t *testing.T) {
		f := newFixture(t)
		if _, err := f.tool.Build(context.Background(), f.options); err != nil {
			t.Fatal(err)
		}
		wrapper := filepath.Join(f.options.ProjectDir, "gradlew")
		if err := os.WriteFile(wrapper, []byte("fixture wrapper"), 0700); err != nil {
			t.Fatal(err)
		}
		process := &processCapture{}
		f.tool.Processes = process
		if err := f.tool.Gradle(context.Background(), f.options, []string{"assemble"}, nil, io.Discard, io.Discard); err != nil {
			t.Fatalf("Gradle without daemon criteria failed: %v", err)
		}
		if process.call != 1 {
			t.Fatalf("Gradle wrapper calls = %d, want 1", process.call)
		}
	})
	t.Run("criteria-refused-before-launch", func(t *testing.T) {
		f := newFixture(t)
		if _, err := f.tool.Build(context.Background(), f.options); err != nil {
			t.Fatal(err)
		}
		wrapper := filepath.Join(f.options.ProjectDir, "gradlew")
		if err := os.WriteFile(wrapper, []byte("fixture wrapper"), 0700); err != nil {
			t.Fatal(err)
		}
		criteriaDir := filepath.Join(f.options.ProjectDir, "gradle")
		if err := os.Mkdir(criteriaDir, 0700); err != nil {
			t.Fatal(err)
		}
		criteria := filepath.Join(criteriaDir, "gradle-daemon-jvm.properties")
		if err := os.WriteFile(criteria, []byte("toolchainVersion=99\n"), 0600); err != nil {
			t.Fatal(err)
		}
		process := &processCapture{}
		f.tool.Processes = process
		before := filesystemSnapshot(t, f.options.ProjectDir, f.options.JavaHome)
		if err := f.tool.Gradle(context.Background(), f.options, []string{"assemble"}, nil, io.Discard, io.Discard); Cause(err) != CauseGradleDaemonCriteria || ExitCode(err) != ExitRefusal {
			t.Fatalf("Gradle cause=%q exit=%d, want daemon-criteria refusal", Cause(err), ExitCode(err))
		}
		if process.call != 0 {
			t.Fatalf("daemon criteria refusal launched Gradle %d times", process.call)
		}
		after := filesystemSnapshot(t, f.options.ProjectDir, f.options.JavaHome)
		if !equalFilesystemSnapshots(before, after) {
			t.Fatal("daemon criteria refusal changed project or JDK state")
		}
		if _, err := os.Lstat(filepath.Join(f.projectOutput(), gradleHomeName)); !os.IsNotExist(err) {
			t.Fatalf("daemon criteria refusal created Gradle home: %v", err)
		}
	})
}

// Claim: a project Gradle truststore override is rejected before creating Gradle state or launching the wrapper.
func TestGradleRefusesConflictingProjectSettings(t *testing.T) {
	f := newFixture(t)
	if _, err := f.tool.Build(context.Background(), f.options); err != nil {
		t.Fatal(err)
	}
	process := &processCapture{}
	f.tool.Processes = process
	settings := []string{
		"systemProp.javax.net.ssl.trustStore=/other/store\n",
		"systemProp.javax.net.ssl.trustStoreProvider=Other\n",
		"systemProp.gradle.user.home=/other/gradle-home\n",
		"org.gradle.java.home=/other/jdk\n",
		"systemProp.javax.net.ssl.trustStore: /other/store\n",
		"systemProp.javax.net.ssl.trustStore /other/store\n",
		"systemProp.javax.net.ssl.trust\\u0053tore=/other/store\n",
		"org.gradle.jvmargs=-Xmx1g -Djavax.net.ssl.trustStore=/other/store\n",
		"org.gradle.jvmargs=-Xmx1g '-Djavax.net.ssl.trustStore=/other/store'\n",
		"org.gradle.jvmargs=-Xmx1g -Djavax.net.ssl.trustStore=\\\n  /other/store\n",
	}
	for _, setting := range settings {
		if err := os.WriteFile(filepath.Join(f.options.ProjectDir, "gradle.properties"), []byte(setting), 0600); err != nil {
			t.Fatal(err)
		}
		if err := f.tool.Gradle(context.Background(), f.options, []string{"assemble"}, nil, io.Discard, io.Discard); Cause(err) != CauseGradleConfig {
			t.Errorf("setting %q Gradle cause = %q", setting, Cause(err))
		}
	}
	if process.call != 0 {
		t.Fatal("conflicting settings launched Gradle")
	}
	if _, err := os.Lstat(filepath.Join(f.projectOutput(), gradleHomeName)); !os.IsNotExist(err) {
		t.Fatalf("conflicting settings created daemon home: %v", err)
	}
}

// Claim: Gradle arguments cannot redirect the project or daemon home, or replace the selected truststore and JDK before the wrapper starts.
func TestGradleRefusesScopeOverridesInArguments(t *testing.T) {
	f := newFixture(t)
	if _, err := f.tool.Build(context.Background(), f.options); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(f.options.ProjectDir, "gradlew")
	if err := os.WriteFile(wrapper, []byte("fixture wrapper"), 0700); err != nil {
		t.Fatal(err)
	}
	process := &processCapture{}
	f.tool.Processes = process
	cases := [][]string{
		{"-Djavax.net.ssl.trustStore=/other/store", "assemble"},
		{"--system-prop=javax.net.ssl.trustStore=/other/store", "assemble"},
		{"-D", "javax.net.ssl.trustStore=/other/store", "assemble"},
		{"--system-prop", "javax.net.ssl.trustStore=/other/store", "assemble"},
		{"-Dorg.gradle.jvmargs=-Xmx1g -Djavax.net.ssl.trustStore=/other/store", "assemble"},
		{"-Dgradle.user.home=/other/gradle-home", "assemble"},
		{"--gradle-user-home=/other/gradle-home", "assemble"},
		{"--gradle-user-home", "/other/gradle-home", "assemble"},
		{"-g/other/gradle-home", "assemble"},
		{"-g", "/other/gradle-home", "assemble"},
		{"-p", "/other/project", "assemble"},
		{"--project-dir=/other/project", "assemble"},
		{"-Dorg.gradle.java.home=/other/jdk", "assemble"},
	}
	for _, args := range cases {
		if err := f.tool.Gradle(context.Background(), f.options, args, nil, io.Discard, io.Discard); Cause(err) != CauseGradleConfig {
			t.Errorf("arguments %q Gradle cause = %q", args, Cause(err))
		}
	}
	if process.call != 0 {
		t.Fatalf("scope override arguments launched Gradle %d times", process.call)
	}
	if _, err := os.Lstat(filepath.Join(f.projectOutput(), gradleHomeName)); !os.IsNotExist(err) {
		t.Fatalf("scope override arguments created Gradle home: %v", err)
	}
}

// Claim: a truststore override in the isolated Gradle user home is refused before the wrapper starts.
func TestGradleRefusesGradleHomeTrustOverride(t *testing.T) {
	f := newFixture(t)
	if _, err := f.tool.Build(context.Background(), f.options); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(f.projectOutput(), gradleHomeName), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.projectOutput(), gradleHomeName, "gradle.properties"), []byte("systemProp.javax.net.ssl.trustStore=/other/store\n"), 0600); err != nil {
		t.Fatal(err)
	}
	process := &processCapture{}
	f.tool.Processes = process
	if err := f.tool.Gradle(context.Background(), f.options, []string{"assemble"}, nil, io.Discard, io.Discard); Cause(err) != CauseGradleConfig {
		t.Fatalf("Gradle cause = %q", Cause(err))
	}
	if process.call != 0 {
		t.Fatal("Gradle user-home conflict launched Gradle")
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func treeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	tree := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		var data []byte
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			data = []byte(target)
		} else {
			data, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		tree[rel] = info.Mode().String() + ":" + string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func equalTrees(first, second map[string]string) bool {
	if len(first) != len(second) {
		return false
	}
	for path, value := range first {
		if second[path] != value {
			return false
		}
	}
	return true
}

type filesystemEntry struct {
	mode          os.FileMode
	modTime       time.Time
	data          []byte
	symlinkTarget string
}

// filesystemSnapshot captures directory and file mtimes and file bytes without following symlinks.
func filesystemSnapshot(t *testing.T, roots ...string) map[string]filesystemEntry {
	t.Helper()
	snapshot := make(map[string]filesystemEntry)
	for _, root := range roots {
		absolute, err := filepath.Abs(root)
		if err != nil {
			t.Fatal(err)
		}
		err = filepath.WalkDir(absolute, func(path string, _ os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			state := filesystemEntry{mode: info.Mode(), modTime: info.ModTime()}
			switch {
			case info.Mode()&os.ModeSymlink != 0:
				state.symlinkTarget, err = os.Readlink(path)
			case info.IsDir():
				// Directory bytes are represented by their entries; mode and mtime capture directory state.
			default:
				state.data, err = os.ReadFile(path)
			}
			if err != nil {
				return err
			}
			snapshot[path] = state
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return snapshot
}

func equalFilesystemSnapshots(first, second map[string]filesystemEntry) bool {
	if len(first) != len(second) {
		return false
	}
	for path, before := range first {
		after, exists := second[path]
		if !exists || before.mode != after.mode || !before.modTime.Equal(after.modTime) || !bytes.Equal(before.data, after.data) || before.symlinkTarget != after.symlinkTarget {
			return false
		}
	}
	return true
}
