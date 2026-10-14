package security

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// strictJSON rejects duplicate decoded object names at every nesting level,
// multiple documents, and excessive nesting before typed interpretation.
func strictJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON depth limit")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return errors.New("duplicate JSON member")
				}
				seen[key] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return errors.New("invalid JSON object")
			}
		case '[':
			for d.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return errors.New("invalid JSON array")
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
func requiredMembers(data []byte, keys ...string) error {
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) != nil || obj == nil {
		return errors.New("invalid JSON object")
	}
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	if len(keys) > 0 && keys[0] == "schema" {
		allowed["captured_at"] = true
		allowed["evidence"] = true
	}
	if len(keys) > 0 && keys[0] == "source" && len(keys) == 2 {
		allowed["detail"] = true
	}
	for k := range obj {
		if !allowed[k] {
			return errors.New("unknown JSON member")
		}
	}
	for _, k := range keys {
		v, ok := obj[k]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return errors.New("missing baseline member")
		}
	}
	return nil
}
func requiredSnapshot(data []byte) error {
	if err := requiredMembers(data, "schema", "entries", "coverage"); err != nil {
		return err
	}
	var raw struct {
		Entries  []json.RawMessage `json:"entries"`
		Coverage []json.RawMessage `json:"coverage"`
	}
	if json.Unmarshal(data, &raw) != nil {
		return errors.New("invalid snapshot")
	}
	for _, e := range raw.Entries {
		if err := requiredMembers(e, "source", "path", "sha256", "mode"); err != nil {
			return err
		}
	}
	for _, e := range raw.Coverage {
		if err := requiredMembers(e, "source", "status"); err != nil {
			return err
		}
	}
	return nil
}
