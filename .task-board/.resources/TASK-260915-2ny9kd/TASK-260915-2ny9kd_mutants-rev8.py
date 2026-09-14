#!/usr/bin/env python3
"""rev8 narrowing mutants for checkDescribe (signerclient/result.go).
Each mutant keeps checkResult/checkDescribe present and weakens it to admit
exactly one class of malformed describe member; the behavioural suite must
name a failing row. Restores the file after every mutant."""
import subprocess, shutil, sys, re
P='internal/keyvault/signerclient/result.go'
orig=open(P).read()
STRIP='''
// MUTANT: drop one raw member before the typed decode and trust a value for it.
func mutantStrip(result json.RawMessage, name string) json.RawMessage {
	var m map[string]json.RawMessage
	_ = json.Unmarshal(result, &m)
	delete(m, name)
	out, _ := json.Marshal(m)
	return out
}
'''
def strip_member(name, assign):
    def f(s):
        s=s.replace('\tif err := DecodeSingleJSON(result, &d); err != nil {',
                    '\tresult = mutantStrip(result, "%s")\n\tif err := DecodeSingleJSON(result, &d); err != nil {' % name,1)
        s=s.replace('\tif d.Schema != SchemaVersion {', '\t'+assign+'\n\tif d.Schema != SchemaVersion {',1)
        return s+STRIP
    return f
mutants={
 'M1-unmarshal-not-closed': lambda s: s.replace('if err := DecodeSingleJSON(result, &d); err != nil {','if err := json.Unmarshal(result, &d); err != nil {',1),
 'M2-schema-untyped': strip_member('schema','d.Schema = SchemaVersion'),
 'M3-version-untyped': strip_member('version','d.Version = hello.Version'),
 'M4-kind-untyped': strip_member('kind','d.Kind = hello.Kind'),
 'M5-service-untyped': strip_member('service','d.Service = strings.Split(hello.Address, "/")[0]'),
 'M6-purpose-untyped': strip_member('purpose','d.Purpose = strings.Split(hello.Address, "/")[1]'),
 'M7-invariants-skipped': lambda s: s.replace('if err := ValidateStored(d.Label, d.Record); err != nil {','if err := ValidateStored(d.Label, d.Record); err != nil && false {',1),
 'M8-finding-vocab-open': lambda s: s.replace('return d, fmt.Errorf("describe result: finding %q is not one the read vocabulary defines", finding)','_ = finding',1),
 'M9-exposure-vocab-open': lambda s: s.replace('if !Contains(Exposures, d.Exposure) {','if !Contains(Exposures, d.Exposure) && false {',1),
 'M10-exposure-unknown-unbound': lambda s: s.replace('if noRow != (d.Exposure == Unknown) {','if false && noRow != (d.Exposure == Unknown) {',1),
 'M11-operations-unchecked': lambda s: s.replace('if op.Name == "" || op.Via == "" {','if false && (op.Name == "" || op.Via == "") {',1),
 'M12-expired-unbound': lambda s: s.replace('if expired && d.Validity.NotAfter == nil {','if false && expired && d.Validity.NotAfter == nil {',1),
 'M13-schema-value-unbound': lambda s: s.replace('if d.Schema != SchemaVersion {','if false && d.Schema != SchemaVersion {',1),
 'M14-label-derivation-unbound': lambda s: s.replace('if derived := d.Record.Label(); derived != d.Label {','if derived := d.Record.Label(); false && derived != d.Label {',1),
}
results=[]
for name,fn in mutants.items():
    s=fn(orig)
    assert s!=orig, name
    open(P,'w').write(s)
    r=subprocess.run(['go','test','-count=1','-run','TestClientRefusesResultNotBoundToRequestOrHello','./internal/keyvault/signerclient/'],capture_output=True,text=True)
    open(P,'w').write(orig)
    out=r.stdout+r.stderr
    fails=sorted(set(re.findall(r'--- FAIL: TestClientRefusesResultNotBoundToRequestOrHello/(\S+)',out)))
    status='KILLED' if r.returncode!=0 else 'SURVIVED'
    if 'build failed' in out or 'cannot' in out and 'FAIL' in out and not fails: status='BUILD-ERROR'
    results.append((name,status,fails))
    print(f'{name}: {status} exit={r.returncode} failing_rows={fails}')
    if status=='BUILD-ERROR': print(out[:1500])
assert open(P).read()==orig
print('\n| mutant | narrows the gate to | status | failing rows |')
print('|---|---|---|---|')
for name,status,fails in results:
    print(f'| {name} | | {status} | {", ".join(fails)} |')
