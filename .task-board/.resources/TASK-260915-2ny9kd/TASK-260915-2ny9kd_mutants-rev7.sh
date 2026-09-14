#!/bin/zsh
# rev7 narrowing mutants: F1 (token-level object reader on both sides) and
# F2 (owned result validators in the client). Each mutant keeps the gate
# installed and admits exactly one class; the named test must fail.
set -u
cd "$(dirname "$0")/../../.."
OBJ=internal/keyvault/signerclient/object.go
ENV=internal/keyvault/signerclient/envelope.go
RES=internal/keyvault/signerclient/result.go
CLI=internal/keyvault/signerclient/client.go
SRV=internal/keyvault/signer.go
for f in $OBJ $ENV $RES $CLI $SRV; do cp "$f" "$f.orig"; done
restore() { for f in $OBJ $ENV $RES $CLI $SRV; do cp "$f.orig" "$f"; done; }
CLIENT_TESTS='TestClientRefusesDuplicateMembers|TestClientRefusesResultNotBoundToRequestOrHello|TestDecodeObject|TestClientRefusesEnvelopeMissingOrNullMembers|TestClientRefusesMalformedEnvelopeBeforeReadingOK'
SERVER_TESTS='TestSignerServeRefusesDuplicateMembers|TestSignerServeGoldenWire'
run() {
  local id="$1" file="$2" desc="$3" py="$4"
  restore
  python3 - "$file" "$py" <<'PY'
import sys
p, edit = sys.argv[1], sys.argv[2]
s = open(p).read()
old, new = edit.split('=>>', 1)
assert old in s, "mutant anchor not found: " + old
open(p, 'w').write(s.replace(old, new, 1))
PY
  if ! go build ./internal/keyvault/... >/dev/null 2>&1; then echo "$id BUILD-FAIL $desc"; restore; return; fi
  local log=".temp/TASK-260915-2ny9kd/rev7/mutant-$id.log"
  MAC_KEYVAULT_SKIP_KEYCHAIN=1 go test -count=1 -run "$CLIENT_TESTS" ./internal/keyvault/signerclient/ >"$log" 2>&1
  local rc1=$?
  MAC_KEYVAULT_SKIP_KEYCHAIN=1 go test -count=1 -run "$SERVER_TESTS" ./internal/keyvault/ >>"$log" 2>&1
  local rc2=$?
  local failing
  failing=$(grep -o -- '--- FAIL: [^ ]*' "$log" | sed 's/--- FAIL: //' | { grep '/' || grep .; } | head -6 | tr '\n' ' ')
  if [ $rc1 -ne 0 ] || [ $rc2 -ne 0 ]; then echo "$id KILLED client=$rc1 server=$rc2 $desc :: ${failing}"; else echo "$id SURVIVED client=$rc1 server=$rc2 $desc"; fi
  restore
}
# F1 — duplicate members
run M1 $OBJ "escape-spelt repeat admitted (only a verbatim repeat refused)" '		if seen[name] {=>>		if seen[name] && bytes.Count(data, []byte("\""+name+"\"")) > 1 {'
run M2 $OBJ "repeat of ok admitted (every other name refused)" '		if seen[name] {=>>		if seen[name] && name != "ok" {'
run M3 $ENV "nested error object read through a map (envelope still token-read)" '	fields, err := DecodeObject(member)
	if err != nil {
		return fmt.Errorf("does not decode: %v", err)
	}
	for _, name := range fields.Names() {=>>	var m map[string]json.RawMessage
	if err := json.Unmarshal(member, &m); err != nil {
		return fmt.Errorf("does not decode: %v", err)
	}
	var fields Object
	for k, v := range m {
		fields = append(fields, Member{Name: k, Value: v})
	}
	for _, name := range fields.Names() {'
run M4 $RES "results (hello and op) read through a map (envelope still token-read)" '	obj, err := DecodeObject(result)
	if err != nil {
		return nil, err
	}=>>	var m map[string]json.RawMessage
	if err := json.Unmarshal(result, &m); err != nil {
		return nil, err
	}
	var obj Object
	for k, v := range m {
		obj = append(obj, Member{Name: k, Value: v})
	}'
run M5 $SRV "server request read through a map (client untouched)" '	members, err := signerclient.DecodeObject(line)
	if err != nil {=>>	var m map[string]json.RawMessage
	err := DecodeSingleJSON(line, &m)
	var members signerclient.Object
	for k, v := range m {
		members = append(members, signerclient.Member{Name: k, Value: v})
	}
	if err != nil {'
run M6 $OBJ "data after the object admitted" '	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("unexpected data after the JSON object")
		}
		return nil, err
	}=>>'
# F2 — result binding
run M7 $RES "fingerprint not bound to the hello (label still is)" '	if err := bound("fingerprint", fingerprint, hello.Fingerprint); err != nil {
		return fmt.Errorf("%v (hello attested another key)", err)
	}=>>'
run M8 $RES "sign: signature not verified under the attested key (shape and low-S still checked)" '	if !ecdsa.Verify(pub, digest, r, s) {
		return errors.New("sign result: signature does not verify under the attested public key")
	}=>>	_ = ecdsa.Verify(pub, digest, r, s)'
run M9 $RES "sign: digest not bound to the request" '	if err := bound("digest", sig.Digest, req.Digest); err != nil {
		return fmt.Errorf("sign result: %v (not the digest requested)", err)
	}=>>'
run M10 $RES "verify: verdict not re-derived with crypto/ecdsa" '	if verified := ecdsa.Verify(pub, digest, r, s); verified != v.Verified {
		return fmt.Errorf("verify result: verified %v, crypto/ecdsa under the attested key says %v", v.Verified, verified)
	}=>>	_ = ecdsa.Verify(pub, digest, r, s)'
run M11 $RES "verify: high_s_allowed not bound to the request" '	if v.HighSAllowed != req.AllowHighS {
		return fmt.Errorf("verify result: high_s_allowed %v, request sent %v", v.HighSAllowed, req.AllowHighS)
	}=>>'
run M12 $RES "pub: the encoding is parsed but not fingerprinted against the hello" '	if got := Fingerprint(der); got != hello.Fingerprint {
		return fmt.Errorf("pub result: %s fingerprints as %s, hello attested %s", encoding, got, hello.Fingerprint)
	}=>>'
run M13 $RES "describe result not validated (other ops still are)" '		return checkDescribe(resp.Result, hello)=>>		return nil'
run M14 $RES "sign result validated but its verdict ignored" '		return checkSign(req, resp.Result, hello, pub)=>>		_ = checkSign(req, resp.Result, hello, pub)
		return nil'
run M15 $RES "verify: a result next to an undocumented refusal admitted" '		if len(resp.Result) != 0 {
			return fmt.Errorf("verify result: a %s refusal carries a result the op does not document", code)
		}
		return nil=>>		return nil'
run M16 $RES "undefined result members admitted (presence and binding still checked)" '	if closed {
		allowed := map[string]bool{}=>>	if closed && false {
		allowed := map[string]bool{}'
run M17 $RES "verify: low_s claim not checked against the signature" '	if v.LowS != IsLowS(s) {
		return fmt.Errorf("verify result: low_s %v, the signature'"'"'s s is low: %v", v.LowS, IsLowS(s))
	}=>>'
run M18 $CLI "Call runs checkResult only on refusals (ok results pass unjudged)" '	if err := checkResult(req, resp, c.hello, c.pub); err != nil {=>>	if err := checkResult(req, resp, c.hello, c.pub); err != nil && !resp.OK {'
restore
for f in $OBJ $ENV $RES $CLI $SRV; do rm "$f.orig"; done
git status --short -- $OBJ $ENV $RES $CLI $SRV
