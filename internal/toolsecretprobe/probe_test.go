package toolsecretprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// Claim F5: only authentication/interaction denial is refused; allowed, locked, missing and other errors are distinct failing outcomes.
func TestVerdict(t *testing.T) {
	for _, tc := range []struct {
		s    int
		want string
	}{{0, "allowed"}, {-25293, "refused"}, {-25308, "refused"}, {-25300, "inconclusive"}, {-10000001, "inconclusive"}, {-50, "inconclusive"}, {-128, "inconclusive"}} {
		v, e := Verdict(tc.s)
		if v != tc.want || (e != nil) != (tc.want == "inconclusive") {
			t.Fatalf("%d: %s %v", tc.s, v, e)
		}
	}
}

// Claim F5: refused alone exits zero; allowed and inconclusive exit one in both text and JSON, paired with a refused control.
func TestCLI(t *testing.T) {
	for _, v := range []string{"allowed", "refused", "inconclusive"} {
		for _, j := range []bool{false, true} {
			var out, errout bytes.Buffer
			a := []string{"--keychain", "/temp/test.keychain-db", "--service", "test", "--account", "test"}
			if j {
				a = append(a, "--json")
			}
			want := 1
			if v == "refused" {
				want = 0
			}
			code := Run(context.Background(), a, &out, &errout, func(context.Context, Request) (string, error) {
				if v == "inconclusive" {
					return v, errors.New("timeout")
				}
				return v, nil
			})
			if code != want {
				t.Fatalf("%s exits %d", v, code)
			}
			if j {
				var e map[string]any
				if json.Unmarshal(out.Bytes(), &e) != nil || e["ok"] != (v == "refused") || e["result"] != v {
					t.Fatal(out.String())
				}
			} else if out.String() != v+"\n" {
				t.Fatal(out.String())
			}
		}
	}
	var out, errout bytes.Buffer
	calls := 0
	f := func(context.Context, Request) (string, error) { calls++; return "", errors.New("timeout") }
	if Run(context.Background(), []string{"--json"}, &out, &errout, f) != 2 || calls != 0 {
		t.Fatal("bad usage called native")
	}
	out.Reset()
	if Run(context.Background(), []string{"--json", "--keychain", "/temp/test", "--service", "s", "--account", "a"}, &out, &errout, f) != 1 || calls != 1 {
		t.Fatal("timeout passed")
	}
	var e map[string]any
	json.Unmarshal(out.Bytes(), &e)
	if e["ok"] != false || e["result"] != "inconclusive" {
		t.Fatal(out.String())
	}
}
