"""rev2 mutants for review findings F1 (GuardedStore.Sign) and F2 (high-S refusal order).
Each mutant is applied, the named tests run, and the source restored byte-exact."""
import shutil, subprocess, sys
G='internal/keyvault/security_darwin_test.go'; M='cmd/mac-keyvault/main.go'
EARLY='''	if !sig.IsLowS() && !*allowHighS {
		inputs["verified"] = false'''
LATE_ANCHOR='''	for k, v := range inputs {
		result[k] = v
	}
'''
LATE='''	if !sig.IsLowS() && !*allowHighS {
		result["verified"] = false
		return out.failWith(result, &keyvault.Refusal{Code: keyvault.CodeHighSRefused, Message: "mut", Hint: "mut"})
	}
'''
EARLY_BLOCK='''	if !sig.IsLowS() && !*allowHighS {
		inputs["verified"] = false
		return out.failWith(inputs, &keyvault.Refusal{Code: keyvault.CodeHighSRefused, Message: "signature s is in the high half of the P-256 order (malleable form); the vault only accepts low-S signatures", Hint: "signatures made by mac-keyvault sign are always low-S; pass --allow-high-s to accept this one knowingly"})
	}
'''
SIGN_GUARD='''func (g *GuardedStore) Sign(label string, digest []byte) ([]byte, error) {
	if err := g.guard(label); err != nil {
		return nil, err
	}'''
def sub(s, a, b):
    assert a in s, a
    return s.replace(a, b)
mutants = {
 'M14 GuardedStore.Sign guard admits the key.kvctl.* class': (G, lambda s: sub(s, SIGN_GUARD, '''func (g *GuardedStore) Sign(label string, digest []byte) ([]byte, error) {
	if !strings.HasPrefix(label, LabelPrefix+"key.kvctl.") {
		if err := g.guard(label); err != nil {
			return nil, err
		}
	}'''), './internal/keyvault/', 'TestGuardedStoreRefusesNonTestLabels'),
 'M15 GuardedStore.Sign override deleted (existence only)': (G, lambda s: sub(s, SIGN_GUARD+'''
	return g.Backend.Sign(label, digest)
}
''', ''), './internal/keyvault/', 'TestGuardedStoreRefusesNonTestLabels'),
 'M16 high-S refusal moved after key resolution (rev1 order)': (M, lambda s: sub(sub(s, EARLY_BLOCK, ''), LATE_ANCHOR, LATE_ANCHOR+LATE), './cmd/mac-keyvault/', 'TestRunVerifyHighSRefusedBeforeStore|TestRunVerifyVerdicts'),
 'M17 early refusal only for DER; raw high-S reaches List': (M, lambda s: sub(sub(s, EARLY, EARLY.replace('if !sig', 'if encoding != keyvault.FormatSignatureRaw && !sig')), LATE_ANCHOR, LATE_ANCHOR+LATE), './cmd/mac-keyvault/', 'TestRunVerifyHighSRefusedBeforeStore|TestRunVerifyVerdicts'),
 'M18 early refusal only for --spki; label high-S reaches List': (M, lambda s: sub(sub(s, EARLY, EARLY.replace('if !sig', 'if *spkiPath != "" && !sig')), LATE_ANCHOR, LATE_ANCHOR+LATE), './cmd/mac-keyvault/', 'TestRunVerifyHighSRefusedBeforeStore|TestRunVerifyVerdicts'),
}
survivors = 0
for name, (path, fn, pkg, run) in mutants.items():
    orig = open(path).read()
    open(path, 'w').write(fn(orig))
    try:
        p = subprocess.run(['go', 'test', '-count=1', '-run', run, pkg], capture_output=True, text=True)
    finally:
        open(path, 'w').write(orig)
    killed = p.returncode != 0
    fails = [l.strip() for l in p.stdout.splitlines() if l.strip().startswith('--- FAIL')]
    print(f'{name}: rc={p.returncode} {"KILLED" if killed else "SURVIVED"}')
    for f in fails: print('   ', f)
    if not killed: survivors += 1
print('survivors:', survivors)
sys.exit(1 if survivors else 0)
