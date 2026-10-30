package kekclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as a fake broker: with fakeBrokerEnv set it
// behaves like `mac-keyvault-kek <op> --address A --socket S` and answers
// with the line in fakeAnswerEnv (or, for "echo-kek", a well-formed unwrap
// result for the request's envelope).
const (
	fakeBrokerEnv = "KEKCLIENT_FAKE_BROKER"
	fakeAnswerEnv = "KEKCLIENT_FAKE_ANSWER"
	fakeReadyEnv  = "KEKCLIENT_FAKE_READY"
	fakeLingerEnv = "KEKCLIENT_FAKE_LINGER"
)

func TestMain(m *testing.M) {
	if os.Getenv(fakeBrokerEnv) != "" {
		os.Exit(fakeBroker(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakeBroker(args []string) int {
	fs := flag.NewFlagSet("fake", flag.ContinueOnError)
	address := fs.String("address", "", "")
	sock := fs.String("socket", "", "")
	if len(args) < 1 || fs.Parse(args[1:]) != nil || *address == "" {
		return 2
	}
	l, err := net.Listen("unix", *sock)
	if err != nil {
		return 1
	}
	defer l.Close()
	if linger := os.Getenv(fakeLingerEnv); linger != "" {
		// A descendant that inherits stdout and stderr and outlives us
		// unless its process group is killed.
		child := exec.Command("/bin/sleep", "30")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		child.Start()
		if linger == "silent" {
			time.Sleep(30 * time.Second)
			return 0
		}
	}
	if ready := os.Getenv(fakeReadyEnv); ready != "" {
		fmt.Println(ready)
	} else {
		fmt.Printf("listening %s\n", *sock)
	}
	conn, err := l.Accept()
	if err != nil {
		return 1
	}
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return 1
	}
	answer := os.Getenv(fakeAnswerEnv)
	if answer == "echo-kek" {
		var req Request
		json.Unmarshal(line, &req)
		env, _ := ParseEnvelope(req.Envelope)
		b, _ := json.Marshal(Response{Contract: Contract, OK: true, Result: &Result{Address: env.Address, Generation: env.Generation, Fingerprint: env.Fingerprint, KEK: testKEK()}})
		answer = string(b)
	}
	fmt.Fprintln(conn, answer)
	return 0
}

// shortDir is a private directory with a path short enough for a socket.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func fakeOptions(t *testing.T, answer, ready string) Options {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakeBrokerEnv, "1")
	t.Setenv(fakeAnswerEnv, answer)
	t.Setenv(fakeReadyEnv, ready)
	t.Setenv(fakeLingerEnv, "")
	return Options{Broker: exe, SocketDir: shortDir(t), Timeout: 10 * time.Second}
}

func testEnvelope(t *testing.T) ([]byte, Envelope) {
	t.Helper()
	k := newTestKey(t)
	sealed, err := Wrap(testSpec(k), testKEK())
	if err != nil {
		t.Fatal(err)
	}
	env, _ := ParseEnvelope(sealed)
	return sealed, env
}

// Unwrap runs the broker, waits for its ready line, sends one request and
// returns the KEK of a well-formed answer about the envelope's key whose
// check value matches the envelope's.
func TestUnwrapReturnsTheKEKOfAContractAnswer(t *testing.T) {
	sealed, _ := testEnvelope(t)
	kek, err := Unwrap(context.Background(), fakeOptions(t, "echo-kek", ""), sealed)
	if err != nil || !bytes.Equal(kek, testKEK()) {
		t.Fatalf("kek=%x err=%v", kek, err)
	}
}

// Answers outside the contract are refused as ErrProtocol and a declared
// refusal comes back as *Error with its code; nothing in them is used.
func TestUnwrapRefusesAnswersOutsideTheContract(t *testing.T) {
	sealed, env := testEnvelope(t)
	ok := func(r Result) string {
		b, _ := json.Marshal(Response{Contract: Contract, OK: true, Result: &r})
		return string(b)
	}
	good := Result{Address: env.Address, Generation: env.Generation, Fingerprint: env.Fingerprint, KEK: testKEK()}
	short, otherKey, otherGen, withEnvelope, chosen := good, good, good, good, good
	chosen.KEK = bytes.Repeat([]byte{7}, KEKLen)
	short.KEK = short.KEK[:16]
	otherKey.Fingerprint = "other"
	otherGen.Generation = 2
	withEnvelope.Envelope = json.RawMessage(`{}`)
	protocol := map[string]string{
		"kek of its choice": ok(chosen),
		"short kek":         ok(short),
		"other key":         ok(otherKey),
		"other generation":  ok(otherGen),
		"kek and envelope":  ok(withEnvelope),
		"wrong contract":    `{"contract":"kek-2","ok":true,"result":` + strings.TrimPrefix(ok(good), `{"contract":"kek-1","ok":true,"result":`),
		"undeclared code":   `{"contract":"kek-1","ok":false,"error":{"code":"teapot","message":"x"}}`,
		"refusal no error":  `{"contract":"kek-1","ok":false}`,
		"ok with error":     `{"contract":"kek-1","ok":true,"result":{"address":"` + env.Address + `","generation":1,"fingerprint":"` + env.Fingerprint + `"},"error":{"code":"security","message":"x"}}`,
		"unknown member":    strings.Replace(ok(good), `{"contract"`, `{"debug":1,"contract"`, 1),
		"repeated member":   strings.Replace(ok(good), `{"contract":"kek-1"`, `{"contract":"kek-1","contract":"kek-1"`, 1),
		"not json":          `kek: 0707`,
		"nested repeat":     strings.Replace(ok(good), `"generation":1`, `"generation":999,"generation":1`, 1),
		"escaped repeat":    strings.Replace(ok(good), `"generation":1`, `"gen\u0065ration":999,"generation":1`, 1),
		"case alias":        strings.Replace(ok(good), `"generation":1`, `"GENERATION":1`, 1),
		"error null":        strings.Replace(ok(good), `{"contract":"kek-1","ok":true`, `{"contract":"kek-1","ok":true,"error":null`, 1),
		"refusal no ok":     `{"contract":"kek-1","error":{"code":"caller_refused","message":"x"}}`,
		"ok as string":      strings.Replace(ok(good), `"ok":true`, `"ok":"true"`, 1),
		"error extra":       `{"contract":"kek-1","ok":false,"error":{"code":"caller_refused","message":"x","debug":1}}`,
		"code not string":   `{"contract":"kek-1","ok":false,"error":{"code":7,"message":"x"}}`,
		"result unknown":    strings.Replace(ok(good), `"address"`, `"note":"x","address"`, 1),
		"trailing brace":    ok(good) + `}`,
		"trailing bracket":  ok(good) + `]`,
		"second document":   ok(good) + ` {}`,
	}
	for name, answer := range protocol {
		t.Run(name, func(t *testing.T) {
			kek, err := Unwrap(context.Background(), fakeOptions(t, answer, ""), sealed)
			if kek != nil || !errors.Is(err, ErrProtocol) {
				t.Fatalf("kek=%x err=%v", kek, err)
			}
		})
	}
	t.Run("declared refusal", func(t *testing.T) {
		kek, err := Unwrap(context.Background(), fakeOptions(t, `{"contract":"kek-1","ok":false,"error":{"code":"caller_refused","message":"bound to other code"}}`, ""), sealed)
		var e *Error
		if kek != nil || !errors.As(err, &e) || e.Code != CodeCallerRefused {
			t.Fatalf("kek=%x err=%v", kek, err)
		}
	})
	t.Run("wrong ready line", func(t *testing.T) {
		kek, err := Unwrap(context.Background(), fakeOptions(t, ok(good), "listening /elsewhere"), sealed)
		if kek != nil || !errors.Is(err, ErrProtocol) {
			t.Fatalf("kek=%x err=%v", kek, err)
		}
	})
}

// Limit witness, not a guarantee: the clear KCV is the client's only
// reference, so a rewritten envelope whose KCV matches a chosen KEK, served
// by a substituted broker, is accepted (the service's store check is the
// backstop, see kek.md). The control beside it: the same edited envelope
// with a broker that answers the real KEK is refused, so the KCV check runs.
func TestUnwrapTrustsTheEnvelopeItIsGiven(t *testing.T) {
	sealed, _ := testEnvelope(t)
	chosen := bytes.Repeat([]byte{9}, KEKLen)
	var m map[string]json.RawMessage
	json.Unmarshal(sealed, &m)
	kcv, _ := json.Marshal(KeyCheckValue(chosen))
	m["kcv"] = kcv
	edited, _ := json.Marshal(m)
	env, err := ParseEnvelope(edited)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := json.Marshal(Response{Contract: Contract, OK: true, Result: &Result{Address: env.Address, Generation: env.Generation, Fingerprint: env.Fingerprint, KEK: chosen}})
	kek, err := Unwrap(context.Background(), fakeOptions(t, string(answer), ""), edited)
	if err != nil || !bytes.Equal(kek, chosen) {
		t.Fatalf("limit not as documented: kek=%x err=%v", kek, err)
	}
	if kek, err := Unwrap(context.Background(), fakeOptions(t, "echo-kek", ""), edited); kek != nil || !errors.Is(err, ErrProtocol) {
		t.Fatalf("control: the real KEK against an edited KCV: kek=%x err=%v", kek, err)
	}
}

// A broker whose descendant keeps stdout and stderr open does not hold
// Unwrap past its bound, after a protocol error or at the deadline: the
// broker's process group is killed and the pipes are given up after
// waitDelay. The first case is the reviewer's witness (7.3 s against a 5 s
// timeout before the fix).
func TestUnwrapIsBoundedWhenADescendantHoldsThePipes(t *testing.T) {
	sealed, _ := testEnvelope(t)
	for _, mode := range []string{"bad-ready", "silent"} {
		t.Run(mode, func(t *testing.T) {
			opts := fakeOptions(t, "echo-kek", "not a ready line")
			opts.Timeout = 2 * time.Second
			t.Setenv(fakeLingerEnv, mode)
			start := time.Now()
			kek, err := Unwrap(context.Background(), opts, sealed)
			if kek != nil || err == nil {
				t.Fatalf("kek=%x err=%v", kek, err)
			}
			if elapsed := time.Since(start); elapsed > opts.Timeout+waitDelay+time.Second {
				t.Fatalf("returned after %v (timeout %v, wait delay %v)", elapsed, opts.Timeout, waitDelay)
			}
		})
	}
}

// Unwrap refuses before starting anything when the broker path is relative,
// the socket directory is reachable by others or is a symlink, or the
// envelope is not a contract envelope.
func TestUnwrapRefusesUnsafeOptionsBeforeStarting(t *testing.T) {
	sealed, _ := testEnvelope(t)
	opts := fakeOptions(t, "echo-kek", "")
	open := shortDir(t)
	os.Chmod(open, 0o755)
	link := filepath.Join(shortDir(t), "l")
	os.Symlink(opts.SocketDir, link)
	cases := map[string]Options{
		"relative broker": {Broker: "mac-keyvault-kek", SocketDir: opts.SocketDir},
		"open socket dir": {Broker: opts.Broker, SocketDir: open},
		"symlink dir":     {Broker: opts.Broker, SocketDir: link},
		"relative dir":    {Broker: opts.Broker, SocketDir: "run"},
		"missing dir":     {Broker: opts.Broker, SocketDir: filepath.Join(opts.SocketDir, "none")},
	}
	for name, o := range cases {
		if kek, err := Unwrap(context.Background(), o, sealed); err == nil || kek != nil {
			t.Fatalf("%s: kek=%x err=%v", name, kek, err)
		}
	}
	if kek, err := Unwrap(context.Background(), opts, []byte(`{"format":"x"}`)); err == nil || kek != nil {
		t.Fatalf("bad envelope: kek=%x err=%v", kek, err)
	}
	entries, _ := os.ReadDir(opts.SocketDir)
	if len(entries) != 0 {
		t.Fatalf("a refused call left %v behind", entries)
	}
}
