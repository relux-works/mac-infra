#!/usr/bin/env python3
"""rev9 narrowing mutants for CheckDocument, the one recursive strict-JSON
pass (signerclient/object.go, called from DecodeObject and DecodeSingleJSON).
Each mutant keeps the walk present and weakens it to admit exactly one class
of duplicate-member document (or detaches it from one entry point); the
behavioural suites on both sides — client fake-signer corpus, server Serve
corpus + goldens, record tag, --meta-json — must name a failing test.
Restores the files after every mutant. Run from the worktree root."""
import subprocess, re
P='internal/keyvault/signerclient/object.go'
R='internal/keyvault/signerclient/record.go'
orig={P:open(P).read(), R:open(R).read()}

def sub(path, old, new):
    def f(files):
        assert old in files[path], (path, old)
        files[path]=files[path].replace(old,new,1)
    return f

# the recursion call inside the '{' arm
RECURSE='''			valueTok, err := dec.Token()
			if err == nil {
				child := name
				if path != "" {
					child = path + "." + name
				}
				err = walkValue(dec, valueTok, child)
			}'''
# M1: the walk stops at depth 0 — a nested object's members are consumed raw, never compared
M1=RECURSE.replace('				err = walkValue(dec, valueTok, child)','''				if _, nested := valueTok.(json.Delim); nested && path == "" {
					_ = child
					err = skipRaw(dec, valueTok)
				} else {
					err = walkValue(dec, valueTok, child)
				}''')
SKIP='''
// MUTANT helper: consume the rest of the container that tok opened without judging it.
func skipRaw(dec *json.Decoder, tok json.Token) error {
	depth := 1
	for depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return unexpectedEOF(err)
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			default:
				depth--
			}
		}
	}
	return nil
}
'''
def m1(files):
    sub(P, RECURSE, M1)(files); files[P]+=SKIP
# M2: arrays are walked over, not into — an object inside an array is consumed raw
ARRAY='''			if err := walkValue(dec, elemTok, path+"["+strconv.Itoa(i)+"]"); err != nil {'''
def m2(files):
    sub(P, ARRAY, '''			_ = strconv.Itoa(i)
			if err := skipRawOrScalar(dec, elemTok); err != nil {''')(files)
    files[P]+=SKIP+'''
func skipRawOrScalar(dec *json.Decoder, tok json.Token) error {
	if _, ok := tok.(json.Delim); !ok {
		return nil
	}
	return skipRaw(dec, tok)
}
'''
# M3: only the FIRST array element is judged; later elements are consumed raw
def m3(files):
    sub(P, ARRAY, '''			if i > 0 {
				if err := skipRawOrScalar(dec, elemTok); err != nil {
					return err
				}
				continue
			}
			if err := walkValue(dec, elemTok, path+"["+strconv.Itoa(i)+"]"); err != nil {''')(files)
    files[P]+=SKIP+'''
func skipRawOrScalar(dec *json.Decoder, tok json.Token) error {
	if _, ok := tok.(json.Delim); !ok {
		return nil
	}
	return skipRaw(dec, tok)
}
'''
# M4: only ADJACENT repeats are refused (seen is the previous name, not the set)
def m4(files):
    sub(P, '''			if seen[name] {''', '''			if seen[name] && seenLast == name {''')(files)
    sub(P, '''			seen[name] = true''', '''			seen[name] = true
			seenLast = name''')(files)
    sub(P, '''		seen := map[string]bool{}''', '''		seen := map[string]bool{}
		seenLast := ""''')(files)
# M5: nested repeats are refused only when spelt verbatim — an escape-spelt nested repeat is admitted.
# (Token() decodes escapes, so the mutant re-reads the raw name from the source: models a reader that compares raw spellings.)
def m5(files):
    sub(P, '''			if seen[name] {''', '''			if seen[name] && (path == "" || !rawEscaped(data, name)) {''')(files)
    sub(P, 'func walkValue(dec *json.Decoder, tok json.Token, path string) error {', 'func walkValue(dec *json.Decoder, tok json.Token, path string) error {\n\tdata := walkData')(files)
    sub(P, '''	if err := walkValue(dec, tok, ""); err != nil {''', '''	walkData = data
	if err := walkValue(dec, tok, ""); err != nil {''')(files)
    files[P]+='''
var walkData []byte

// MUTANT helper: true when the decoded name never appears verbatim twice in the source.
func rawEscaped(data []byte, name string) bool {
	return bytes.Count(data, []byte(`"`+name+`"`)) < 2
}
'''
# M6: the gate is detached from DecodeSingleJSON (record tag, --meta-json): only DecodeObject runs it
def m6(files):
    sub(R, '''	if err := CheckDocument(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))''', '''	decoder := json.NewDecoder(bytes.NewReader(data))''')(files)
# M7: the gate is detached from DecodeObject (client envelope, server request): only DecodeSingleJSON runs it.
# DecodeObject keeps its own TOP-LEVEL check so the rev6 corpus stays green: exactly the nested class is admitted.
def m7(files):
    sub(P, '''	if err := CheckDocument(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}''', '''	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty input, not a JSON object")
		}
		return nil, err
	}
	seen := map[string]bool{}''')(files)
    sub(P, '''		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("member %q: %w", name, err)
		}''', '''		if seen[name] {
			return nil, fmt.Errorf("%w %q", ErrDuplicateMember, name)
		}
		seen[name] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return nil, fmt.Errorf("member %q: %w", name, err)
		}''')(files)
    sub(P, '''	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, err
	}
	return obj, nil''', '''	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, ErrMultipleDocuments
		}
		return nil, err
	}
	return obj, nil''')(files)
# M8: a second document after the first is admitted (the walk still judges the first)
def m8(files):
    sub(P, '''	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return ErrMultipleDocuments
		}
		return err
	}
	return nil
}''', '''	return nil
}''')(files)

mutants={'M1-depth-0-only':m1,'M2-arrays-not-entered':m2,'M3-first-array-element-only':m3,
         'M4-adjacent-repeats-only':m4,'M5-nested-escaped-repeat-admitted':m5,
         'M6-detached-from-DecodeSingleJSON':m6,'M7-detached-from-DecodeObject':m7,'M8-second-document-admitted':m8}
SUITES=[('./internal/keyvault/signerclient/','TestClientRefusesDuplicateMembers|TestCheckDocument|TestDecodeObject|TestClientRefusesMalformedEnvelopeBeforeReadingOK'),
        ('./internal/keyvault/','TestSignerServeRefusesDuplicateMembers|TestSignerServeGolden|TestDecodeRecordRefusesNestedDuplicateMembers|TestRecordEncodingAndLegacyTags'),
        ('./cmd/mac-keyvault/','TestRunMetaJSONRejectsTrailingDocument|Golden')]
results=[]
for name,fn in mutants.items():
    files=dict(orig); fn(files)
    for p,s in files.items(): open(p,'w').write(s)
    fails=[]; status='SURVIVED'; builderr=''
    for pkg,mask in SUITES:
        r=subprocess.run(['go','test','-count=1','-run',mask,pkg],capture_output=True,text=True)
        out=r.stdout+r.stderr
        if 'build failed' in out or '[setup failed]' in out: status='BUILD-ERROR'; builderr=out[:2000]
        f=sorted(set(re.findall(r'--- FAIL: (Test\w+(?:/[^\s]+)?)',out)))
        if r.returncode!=0 and status!='BUILD-ERROR': status='KILLED'
        fails+= [f"{pkg.split('/')[-2]}:{x}" for x in f]
    for p,s in orig.items(): open(p,'w').write(s)
    tops=sorted(set(x.split('/')[0] for x in fails))
    results.append((name,status,tops,len(fails)))
    print(f'{name}: {status} failing_tests={tops} failing_subtests={len(fails)}')
    if builderr: print(builderr)
for p,s in orig.items(): assert open(p).read()==s
print('\n| mutant | status | failing tests (top-level) | failing subtests |')
print('|---|---|---|---|')
for name,status,tops,n in results:
    print(f'| {name} | {status} | {", ".join(tops)} | {n} |')
