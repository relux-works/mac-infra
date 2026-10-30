package kekclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// jsonKind is the JSON type a contract member must have.
type jsonKind int

const (
	kindString jsonKind = iota
	kindNumber
	kindBool
	kindObject
)

// member describes one contract member: its exact name, its type, and
// whether it must be present. No contract member may be null.
type member struct {
	kind     jsonKind
	required bool
}

// shape is the closed member set of one contract object.
type shape map[string]member

var (
	envelopeShape = shape{
		"format": {kindString, true}, "v": {kindNumber, true}, "address": {kindString, true},
		"generation": {kindNumber, true}, "fingerprint": {kindString, true}, "kcv": {kindString, true}, "ecies": {kindString, true},
	}
	payloadShape = shape{
		"v": {kindNumber, true}, "address": {kindString, true}, "generation": {kindNumber, true}, "fingerprint": {kindString, true},
		"requirement": {kindString, true}, "install_path": {kindString, true}, "kcv": {kindString, true}, "kek": {kindString, true},
	}
	requestShape = shape{
		"contract": {kindString, true}, "op": {kindString, true}, "address": {kindString, true}, "envelope": {kindObject, true},
	}
	responseShape = shape{
		"contract": {kindString, true}, "ok": {kindBool, true}, "result": {kindObject, false}, "error": {kindObject, false},
	}
	resultShape = shape{
		"address": {kindString, true}, "generation": {kindNumber, true}, "fingerprint": {kindString, true},
		"kek": {kindString, false}, "envelope": {kindObject, false},
	}
	errorShape = shape{"code": {kindString, true}, "message": {kindString, true}}
)

// objectMembers reads data as exactly one JSON object and nothing after it,
// and returns its members by their exact (unescaped) names. A repeated name
// is refused before any typed decode can let a later value win.
func objectMembers(data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	members := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := tok.(string)
		if !ok {
			return nil, errors.New("member name is not a string")
		}
		if _, seen := members[name]; seen {
			return nil, fmt.Errorf("member %q repeated", name)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		members[name] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the object")
	}
	return members, nil
}

// checkShape reads data as one object with exactly the members of s: exact
// names (encoding/json would otherwise match names case-insensitively), no
// unknown or missing required member, no null, each of its declared type.
// Nested objects are returned for their own check.
func checkShape(data []byte, s shape) (map[string]json.RawMessage, error) {
	members, err := objectMembers(data)
	if err != nil {
		return nil, err
	}
	for name, value := range members {
		m, ok := s[name]
		if !ok {
			return nil, fmt.Errorf("unknown member %q", name)
		}
		if !hasKind(value, m.kind) {
			return nil, fmt.Errorf("member %q has the wrong type", name)
		}
	}
	for name, m := range s {
		if _, ok := members[name]; m.required && !ok {
			return nil, fmt.Errorf("member %q missing", name)
		}
	}
	return members, nil
}

func hasKind(value json.RawMessage, kind jsonKind) bool {
	v := bytes.TrimSpace(value)
	if len(v) == 0 {
		return false
	}
	switch kind {
	case kindString:
		return v[0] == '"'
	case kindNumber:
		return v[0] == '-' || (v[0] >= '0' && v[0] <= '9')
	case kindBool:
		return bytes.Equal(v, []byte("true")) || bytes.Equal(v, []byte("false"))
	case kindObject:
		return v[0] == '{'
	}
	return false
}

// decodeStrict checks data against s, then decodes it into v. After the
// shape check every name is exact and unique, so the typed decode cannot
// pick a different value than the one checked.
func decodeStrict(data []byte, s shape, v any) (map[string]json.RawMessage, error) {
	members, err := checkShape(data, s)
	if err != nil {
		return nil, err
	}
	return members, json.Unmarshal(data, v)
}

// ParseRequest reads a request line strictly; its envelope is checked by
// ParseEnvelope.
func ParseRequest(data []byte) (Request, Envelope, error) {
	var req Request
	if _, err := decodeStrict(data, requestShape, &req); err != nil {
		return req, Envelope{}, fmt.Errorf("request: %w", err)
	}
	if req.Contract != Contract {
		return req, Envelope{}, fmt.Errorf("request names contract %q, not %s", req.Contract, Contract)
	}
	env, err := ParseEnvelope(req.Envelope)
	return req, env, err
}

// parseResponse reads an answer line strictly, nested result and error
// objects included, and requires exactly one of them, matching ok.
func parseResponse(data []byte) (Response, error) {
	var resp Response
	members, err := decodeStrict(data, responseShape, &resp)
	if err != nil {
		return resp, err
	}
	result, hasResult := members["result"]
	errObj, hasError := members["error"]
	switch {
	case resp.OK && (!hasResult || hasError):
		return resp, errors.New("success without exactly one result")
	case !resp.OK && (hasResult || !hasError):
		return resp, errors.New("refusal without exactly one error")
	}
	if hasResult {
		nested, err := checkShape(result, resultShape)
		if err != nil {
			return resp, fmt.Errorf("result: %w", err)
		}
		if _, ok := nested["kek"]; ok {
			if _, both := nested["envelope"]; both {
				return resp, errors.New("result carries both a KEK and an envelope")
			}
		}
	}
	if hasError {
		if _, err := checkShape(errObj, errorShape); err != nil {
			return resp, fmt.Errorf("error: %w", err)
		}
	}
	return resp, nil
}
