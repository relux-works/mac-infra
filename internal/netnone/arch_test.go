package netnone

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func archHarness(t *testing.T, arch string) *harness {
	t.Helper()
	h := newHarness(t)
	h.o.Arch, h.f.arch = arch, arch
	return h
}

// Both architectures explicitly select every build/run platform and Rosetta mode, including all selftest containers.
func TestArchitectureArgv(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			h := archHarness(t, arch)
			h.o.Toolchain = filepath.Join(h.root, "Dockerfile")
			writeFixture(t, h.o.Toolchain, "FROM "+BaseImage+"\nUSER netnone\n", 0600)
			h.exec(t, "prep", 0)
			h.exec(t, "run", 0)
			h.f.fixtureMode = "qualified"
			h.exec(t, "selftest", 0)
			rosetta, opposite := "--vz-rosetta=false", "--vz-rosetta"
			if arch == "amd64" {
				rosetta, opposite = opposite, rosetta
			}
			builds, runs, starts := 0, 0, 0
			for _, c := range h.f.calls {
				if c.Name == "colima" && c.Args[0] == "start" {
					starts++
					if !has(c.Args, rosetta) || has(c.Args, opposite) || !has(c.Args, "--vm-type", "vz") || has(c.Args, "--arch") {
						t.Fatalf("wrong VM architecture/Rosetta: %v", c.Args)
					}
				}
				if c.Name != "docker" {
					continue
				}
				if c.Args[0] == "build" {
					builds++
				} else if c.Args[0] == "run" {
					runs++
				} else {
					continue
				}
				count := 0
				for _, arg := range c.Args {
					if arg == "--platform" {
						count++
					}
				}
				if count != 1 || !has(c.Args, "--platform", "linux/"+arch) {
					t.Fatalf("missing/wrong platform: %v", c.Args)
				}
			}
			if starts != 3 || builds != 4 || runs != 5 { // selftest builds the base and its toolchain fixture
				t.Fatalf("unexpected coverage starts/builds/runs=%d/%d/%d", starts, builds, runs)
			}
			assertPrivate(t, h)
		})
	}
}

// Embedded builds use the independently specified per-arch FROM bytes and arch tag; both immutable build IDs are inspected in order.
func TestArchitectureBuildPinsAndInspection(t *testing.T) {
	for _, row := range []struct{ arch, pin string }{
		{"amd64", "eclipse-temurin:17-jdk@sha256:fc1394dc03c3de483ea03b14ccf0a076f772f7782aaeffc9d5a2cbde2ae5df0e"},
		{"arm64", "eclipse-temurin:17-jdk@sha256:c4378bc2c608f8ca536dc9a60a017a2d675501c55b00b2ac3db9b6a8200a3458"},
	} {
		t.Run(row.arch, func(t *testing.T) {
			h := archHarness(t, row.arch)
			h.o.Toolchain = filepath.Join(h.root, "Dockerfile")
			original := "FROM " + BaseImage + " AS a\nFROM a\nUSER netnone\n"
			writeFixture(t, h.o.Toolchain, original, 0600)
			toolImage := "sha256:" + strings.Repeat("b", 64)
			n := 0
			h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
				if c.Name == "docker" && c.Args[0] == "build" {
					n++
					image := testImage
					if n == 2 {
						image = toolImage
					}
					return Result{Stdout: []byte(image + "\n")}, nil, true
				}
				return Result{}, nil, false
			}
			h.exec(t, "prep", 0)
			builds := callsNamed(h.f.calls, "docker", "build")
			for i, c := range builds {
				data, err := io.ReadAll(c.Stdin)
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					if !strings.HasPrefix(string(data), "FROM "+row.pin+"\n") || !has(c.Args, "-t", "netnone-base:"+row.arch) {
						t.Fatalf("wrong base/tag: %s %v", data, c.Args)
					}
				} else if string(data) != string(pinToolchain([]byte(original), row.arch)) || strings.Contains(string(data), BaseImage) {
					// The validated caller bytes are built with the index pinned to
					// this architecture's manifest, and nothing else changed.
					t.Fatalf("caller bytes not built as validated and arch-pinned: %s", data)
				}
			}
			h.exec(t, "run", 0)
			inspected := []string{}
			for i, c := range h.f.calls {
				if c.Name == "docker" && c.Args[0] == "build" {
					next := h.f.calls[i+1]
					if next.Name != "docker" || !has(next.Args, "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}") {
						t.Fatal("build not immediately inspected")
					}
				}
				if c.Name == "docker" && has(c.Args, "image", "inspect") {
					image := c.Args[len(c.Args)-1]
					if !reflect.DeepEqual(c.Args, []string{"image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image}) {
						t.Fatalf("wrong inspect %v", c.Args)
					}
					inspected = append(inspected, image)
				}
			}
			if !reflect.DeepEqual(inspected, []string{testImage, toolImage, toolImage}) {
				t.Fatalf("wrong immutable IDs: %v", inspected)
			}
		})
	}
}

// Index and matching manifests work with pinned aliases; opposite manifests and tag-only references refuse before all runner calls.
func TestToolchainArchitectureFROM(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		for _, pin := range []string{BaseImage, BaseImageARM64, BaseImageAMD64, "eclipse-temurin:17-jdk"} {
			for _, stage := range []bool{false, true} {
				t.Run(arch+"/"+pin+map[bool]string{true: "/stage", false: "/direct"}[stage], func(t *testing.T) {
					h := archHarness(t, arch)
					content := "FROM " + pin + "\nUSER netnone\n"
					if stage {
						content = "FROM " + BaseImage + " AS first\nFROM " + pin + " AS second\nFROM second\n"
					}
					h.o.Toolchain = filepath.Join(h.root, "Dockerfile")
					writeFixture(t, h.o.Toolchain, content, 0600)
					valid := pin == BaseImage || arch == "arm64" && pin == BaseImageARM64 || arch == "amd64" && pin == BaseImageAMD64
					want := 2
					if valid {
						want = 0
					}
					h.exec(t, "prep", want)
					if !valid && len(h.f.calls) != 0 {
						t.Fatal("invalid FROM reached runner")
					}
				})
			}
		}
	}
}

// Wrong OS/arch or absent inspect evidence at either build refuses with exit 3, writes no record, runs no container and still stops.
func TestBuildArchitectureRefusal(t *testing.T) {
	for _, at := range []int{1, 2} {
		for _, observed := range []string{"linux/arm64", "windows/amd64", ""} {
			t.Run(string(rune('0'+at))+"/"+observed, func(t *testing.T) {
				h := archHarness(t, "amd64")
				h.o.Toolchain = filepath.Join(h.root, "Dockerfile")
				writeFixture(t, h.o.Toolchain, "FROM "+BaseImage+"\n", 0600)
				inspections := 0
				h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
					if c.Name == "docker" && has(c.Args, "image", "inspect") {
						inspections++
						if inspections == at {
							return Result{Stdout: []byte(observed + "\n")}, nil, true
						}
					}
					return Result{}, nil, false
				}
				h.exec(t, "prep", 3)
				if !strings.Contains(h.err.String(), "refused: built image is "+observed+", expected linux/amd64") {
					t.Fatal(h.err.String())
				}
				if _, err := os.Stat(filepath.Join(h.state, "prep-records.json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("mismatched build wrote record")
				}
				if len(callsNamed(h.f.calls, "docker", "run")) != 0 || len(callsNamed(h.f.calls, "colima", "stop")) != 1 {
					t.Fatal("mismatched build ran container or failed stop")
				}
			})
		}
	}
}

// Run rechecks the recorded ID after startup; a mismatch preserves records/output, starts no container and still stops the VM.
func TestRunArchitectureRefusal(t *testing.T) {
	h := archHarness(t, "amd64")
	h.exec(t, "prep", 0)
	path := filepath.Join(h.state, "prep-records.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h.f.calls = nil
	h.f.arch = "arm64"
	h.exec(t, "run", 3)
	if !strings.Contains(h.err.String(), "refused: built image is linux/arm64, expected linux/amd64") {
		t.Fatal(h.err.String())
	}
	if len(h.f.calls) != 4 || h.f.calls[0].Name != "colima" || h.f.calls[0].Args[0] != "list" || h.f.calls[1].Args[0] != "start" || !has(h.f.calls[2].Args, "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", testImage) || h.f.calls[3].Args[0] != "stop" {
		t.Fatalf("wrong mismatch lifecycle %v", h.f.calls)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("run mismatch changed records")
	}
	entries, err := os.ReadDir(h.o.Out)
	if err != nil || len(entries) != 0 {
		t.Fatal("mismatch created output")
	}
}

// Prep records coexist under literal repo/hash/arch keys and status exposes each arch; a missing arch refuses before Colima.
func TestArchitectureRecords(t *testing.T) {
	h := archHarness(t, "amd64")
	h.exec(t, "prep", 0)
	h.o.Arch, h.f.arch = "arm64", "arm64"
	h.f.calls = nil
	h.exec(t, "run", 3)
	if len(h.f.calls) != 0 || !strings.Contains(h.err.String(), "arch=arm64") {
		t.Fatal("wrong-arch record reached runner or refusal omitted arch")
	}
	h.exec(t, "prep", 0)
	data, err := os.ReadFile(filepath.Join(h.state, "prep-records.json"))
	if err != nil {
		t.Fatal(err)
	}
	var records map[string]Record
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("architecture record key collision: %s", data)
	}
	for _, arch := range []string{"arm64", "amd64"} {
		rec, ok := records[h.o.Repo+"\nbase\n"+arch]
		if !ok || rec.Arch != arch {
			t.Fatalf("missing literal arch key/field: %s", data)
		}
		h.o.Arch, h.f.arch = arch, arch
		h.exec(t, "run", 0)
	}
	h.out.Reset()
	h.exec(t, "status", 0)
	if !strings.Contains(h.out.String(), `"arch":"amd64"`) || !strings.Contains(h.out.String(), `"arch":"arm64"`) {
		t.Fatal("status omitted record arch")
	}
}

// A literal pre-arch record works only for arm64, status normalizes it without rewriting disk, and amd64 refusal never calls Colima.
func TestLegacyArchitectureRecord(t *testing.T) {
	h := newHarness(t)
	legacy := map[string]any{h.o.Repo + "\nbase": map[string]string{"repo": h.o.Repo, "toolchain_sha256": "base", "image_id": testImage}}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(h.state, "prep-records.json")
	writeFixture(t, path, string(data), 0600)
	h.exec(t, "run", 0)
	h.exec(t, "status", 0)
	if !strings.Contains(h.out.String(), `"arch":"arm64"`) {
		t.Fatal("legacy status omitted arm64")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(data) {
		t.Fatal("read normalized legacy record on disk")
	}
	h.f.calls = nil
	h.o.Arch = "amd64"
	h.exec(t, "run", 3)
	if len(h.f.calls) != 0 || !strings.Contains(h.err.String(), "arch=amd64") {
		t.Fatal("legacy record authorized amd64")
	}
}

// Only one matching JVM architecture plus ELF machine pair qualifies; missing, duplicate or inconsistent evidence is rejected.
func TestProbeArchitectureParsing(t *testing.T) {
	for _, row := range []struct {
		arch, output string
		pass         bool
	}{
		{"amd64", "arch=amd64\nelf=62\n", true}, {"arm64", "elf=183\narch=aarch64\n", true},
		{"amd64", "arch=amd64\nelf=183\n", false}, {"amd64", "arch=amd64\n", false},
		{"amd64", "elf=62\n", false}, {"amd64", "arch=amd64 elf=62\n", false}, {"amd64", "arch=aarch64\nelf=62\n", false},
		{"amd64", "arch=amd64\nelf=62\nelf=62\n", false}, {"amd64", "arch=amd64\narch=amd64\nelf=62\n", false},
	} {
		if _, _, pass := probeArch(row.output, row.arch); pass != row.pass {
			t.Errorf("%s %q pass=%t", row.arch, row.output, pass)
		}
	}
}

// Both selftest architecture rows require the matching pair from their own probe; wrong/missing ELF fails that row with all prior rows retained.
func TestSelftestArchitectureRows(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		for _, side := range []string{"prep", "run"} {
			for _, mode := range []string{"valid", "wrong-elf", "missing-elf"} {
				t.Run(arch+"/"+side+"/"+mode, func(t *testing.T) {
					h := archHarness(t, arch)
					h.f.fixtureMode = "qualified"
					h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
						target := side == "prep" && has(c.Args, "netnone-prep") || side == "run" && has(c.Args, "/src/Probe.java")
						if c.Name != "docker" || c.Args[0] != "run" || !target {
							return Result{}, nil, false
						}
						output := warmOutput
						if side == "run" {
							output = deniedOutput
						}
						output = h.f.archOutput(output)
						elf, other := "183", "62"
						if arch == "amd64" {
							elf, other = other, elf
						}
						if mode == "wrong-elf" {
							output = strings.Replace(output, "elf="+elf, "elf="+other, 1)
						}
						if mode == "missing-elf" {
							output = strings.Replace(output, "elf="+elf+"\n", "", 1)
						}
						return Result{Stdout: []byte(output)}, nil, true
					}
					want := 0
					mark := "pass"
					if mode != "valid" {
						want, mark = 1, "fail"
					}
					h.exec(t, "selftest", want)
					for _, name := range []string{"prep DNS", "prep TCP", "prep fixture", "run DNS", "run TCP", "run fixture", "OfflineTest", "NetworkTest", "shared state", "lifecycle", "prep arch", "run arch"} {
						found := false
						for _, line := range strings.Split(h.out.String(), "\n") {
							if !strings.HasPrefix(line, "| "+name+" |") {
								continue
							}
							found = true
							expected := "pass"
							if name == side+" arch" {
								expected = mark
							}
							if !strings.HasSuffix(line, "| "+expected+" |") {
								t.Fatalf("wrong row: %s", line)
							}
						}
						if !found {
							t.Fatalf("missing selftest row %s", name)
						}
					}
				})
			}
		}
	}
}

// Invalid architecture values are usage errors before load, filesystem setup or runner calls for every lifecycle action.
func TestInvalidArchitecture(t *testing.T) {
	for _, action := range []string{"prep", "run", "selftest"} {
		h := newHarness(t)
		h.o.Arch = "x86"
		h.e.Load = func(context.Context) ([3]float64, error) {
			t.Fatal("invalid arch reached load gate")
			return [3]float64{}, nil
		}
		h.exec(t, action, 2)
		if len(h.f.calls) != 0 {
			t.Fatal("invalid arch reached runner")
		}
		if _, err := os.Stat(h.state); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid arch created state")
		}
	}
}

// The probe reads a bounded launcher ELF header and decodes bytes 18/19 little-endian; this checks source only, without executing a JVM.
func TestProbeArchitectureSource(t *testing.T) {
	data, err := assets.ReadFile("assets/Probe.java")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{`System.getProperty("os.arch")`, `Path.of("/proc/self/exe")`, `in.readNBytes(20)`, `header.length != 20`, `Byte.toUnsignedInt(header[18]) | (Byte.toUnsignedInt(header[19]) << 8)`, `System.out.println("elf=" + machine)`} {
		if !strings.Contains(string(data), fragment) {
			t.Fatalf("probe contract missing: %s", fragment)
		}
	}
}
