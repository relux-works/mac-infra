#!/bin/zsh
# rev6 narrowing mutants against internal/keyvault/signerclient/envelope.go.
# Each mutant keeps the raw envelope gate installed and admits exactly one
# member class; TestClientRefusesEnvelopeMissingOrNullMembers must fail.
set -u
cd "$(dirname "$0")/../.."
F=internal/keyvault/signerclient/envelope.go
cp "$F" "$F.orig"
TEST='TestClientRefusesEnvelopeMissingOrNullMembers'
run() {
  local id="$1" desc="$2" py="$3"
  cp "$F.orig" "$F"
  python3 - "$F" "$py" <<'PY'
import sys
p, edit = sys.argv[1], sys.argv[2]
s = open(p).read()
old, new = edit.split('=>>', 1)
assert old in s, "mutant anchor not found: " + old
open(p, 'w').write(s.replace(old, new, 1))
PY
  if ! go build ./internal/keyvault/signerclient/ >/dev/null 2>&1; then echo "$id BUILD-FAIL $desc"; cp "$F.orig" "$F"; return; fi
  local log=".temp/TASK-260915-2ny9kd/mutant-rev6-$id.log"
  MAC_KEYVAULT_SKIP_KEYCHAIN=1 go test -count=1 -run "$TEST" ./internal/keyvault/signerclient/ >"$log" 2>&1
  local rc=$?
  local failing
  failing=$(grep -o -- '--- FAIL: [^ ]*' "$log" | sed 's/--- FAIL: //' | grep '/' | head -3 | tr '\n' ' ')
  if [ $rc -ne 0 ]; then echo "$id KILLED exit=$rc $desc :: ${failing}"; else echo "$id SURVIVED exit=$rc $desc"; fi
  cp "$F.orig" "$F"
}
run M1 "absent ok admitted (read as false), raw gate otherwise intact" '	case !present:
		return Response{}, fmt.Errorf("%s has no ok member", what)=>>	case !present:'
run M2 "error:null read as absent" '	if errMember, present := raw["error"]; present {=>>	if errMember, present := raw["error"]; present && !isLiteral(errMember, "null") {'
run M3 "error.message optional" '	for _, name := range []string{"code", "message", "hint"} {=>>	for _, name := range []string{"code", "hint"} {'
run M4 "error.hint optional" '	for _, name := range []string{"code", "message", "hint"} {=>>	for _, name := range []string{"code", "message"} {'
run M5 "unknown top-level member admitted on responses (hello still strict)" '		if !allowed[name] {=>>		if !allowed[name] && hello {'
run M6 "absent id admitted on a response" '		case !present:
			return Response{}, errors.New("response has no id member")=>>		case !present:'
run M7 "result:null read as absent" '	if result, present := raw["result"]; present && !isObject(result) {=>>	if result, present := raw["result"]; present && !isLiteral(result, "null") && !isObject(result) {'
run M8 "raw gate skipped for the hello (typed decode only), responses still gated" '	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {=>>	var raw map[string]json.RawMessage
	if hello {
		var resp Response
		if err := json.Unmarshal(line, &resp); err != nil {
			return Response{}, err
		}
		return resp, nil
	}
	if err := json.Unmarshal(line, &raw); err != nil {'
run M9 "raw gate skipped for responses (typed decode only), hello still gated" '	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {=>>	var raw map[string]json.RawMessage
	if !hello {
		var resp Response
		if err := json.Unmarshal(line, &resp); err != nil {
			return Response{}, err
		}
		return resp, nil
	}
	if err := json.Unmarshal(line, &raw); err != nil {'
run M10 "error.code:null admitted by the raw gate (typed decode kept)" '		case isLiteral(value, "null"):
			return fmt.Errorf("%s is null", name)=>>		case isLiteral(value, "null") && name != "code":
			return fmt.Errorf("%s is null", name)'
run M11 "os_status as a JSON string admitted by the raw gate (typed decode kept)" '	if status, present := fields["os_status"]; present && !isNumber(status) {=>>	if status, present := fields["os_status"]; present && !isNumber(status) && !isString(status) {'
run M12 "unknown error-object member admitted" '		if !errorMembers[name] {=>>		if !errorMembers[name] && name != "detail" {'
run M13 "result of any JSON type admitted (only null refused)" '	if result, present := raw["result"]; present && !isObject(result) {=>>	if result, present := raw["result"]; present && isLiteral(result, "null") {'
run M14 "ok of any non-null JSON type admitted (typed decode kept)" '	case !isLiteral(ok, "true") && !isLiteral(ok, "false"):=>>	case isLiteral(ok, "null"):'
cp "$F.orig" "$F"; rm "$F.orig"
git diff --stat -- "$F"
