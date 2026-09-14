#!/usr/bin/env python3
"""Narrowing-mutant harness for TASK-260915-nl5may (sign/verify).

Each mutant keeps the gate present and weakens it to admit one member of the
class it must reject; the named tests must FAIL. Files are restored from a
byte-exact backup after every mutant. Exit 1 if any mutant survives.
"""
import subprocess, sys, os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
EC = 'internal/keyvault/ecdsa.go'
KV = 'internal/keyvault/keyvault.go'
REG = 'internal/keyvault/registry.go'
MAIN = 'cmd/mac-keyvault/main.go'

MUTANTS = [
 dict(id='M1', file=EC, name='ValidateDigest admits 31..33 bytes',
      narrows='admits off-by-one digests (31, 33) while 0 and 64 stay refused',
      old='	if len(digest) != DigestSize {',
      new='	if len(digest) < DigestSize-1 || len(digest) > DigestSize+1 {',
      tests=[('./cmd/mac-keyvault','TestRunSignVerifyRefuseBadInputBeforeStore/sign_digest_31_hex'),('./internal/keyvault','TestManagerSignGates/mis-sized_digest_before_any_call'),('./internal/keyvault','TestSecurityStoreSign')]),
 dict(id='M2', file=KV, name='Manager.Sign emits the backend signature without low-S folding',
      narrows='admits a high-S signature out of sign (still strict DER, still verifies)',
      old='	result := SignResult{Key: key, Signature: sig.LowS(), Normalized: !sig.IsLowS()}',
      new='	result := SignResult{Key: key, Signature: sig, Normalized: !sig.IsLowS()}',
      tests=[('./cmd/mac-keyvault','TestRunSignFormatsAndInterop'),('./internal/keyvault','TestManagerSignGates/high-S_from_the_backend_is_normalised')]),
 dict(id='M3', file=EC, name='ParseSignature skips the strict re-encode check',
      narrows='admits non-minimal DER (padded integer, long-form length); trailing bytes and ranges still refused',
      old='		if err != nil || !bytes.Equal(canonical, data) {',
      new='		if err != nil || len(canonical) > len(data)+8 {',
      tests=[('./cmd/mac-keyvault','TestRunSignVerifyRefuseBadInputBeforeStore/verify_padded_der'),('./internal/keyvault','TestParseSignatureStrictness/non-minimal_integer')]),
 dict(id='M4', file=MAIN, name='verify high-S gate skipped for raw signatures',
      narrows='admits a high-S r||s signature without --allow-high-s; DER still refused',
      old='	if !sig.IsLowS() && !*allowHighS {',
      new='	if !sig.IsLowS() && !*allowHighS && encoding != keyvault.FormatSignatureRaw {',
      tests=[('./cmd/mac-keyvault','TestRunVerifyVerdicts/high-s_raw_by_label')]),
 dict(id='M5', file=REG, name='usage verify implies usage sign in the operations filter',
      narrows='admits sign on a verify-only record; a wrap-only record still refused',
      old='		if op.requires != "" && !contains(rec.Usages, op.requires) {',
      new='		if op.requires != "" && !contains(rec.Usages, op.requires) && !(op.requires == "sign" && contains(rec.Usages, "verify")) {',
      tests=[('./cmd/mac-keyvault','TestRunSignPolicyGates/verify_only'),('./internal/keyvault','TestManagerSignGates/usages_without_sign')]),
 dict(id='M6', file=REG, name='expiry gets a one-day grace period',
      narrows='admits sign within 24h after not_after; a week-old expiry still refused',
      old='	expired := rec.Validity.NotAfter != nil && !rec.Validity.NotAfter.IsZero() && !now.Before(rec.Validity.NotAfter.Time)',
      new='	expired := rec.Validity.NotAfter != nil && !rec.Validity.NotAfter.IsZero() && now.After(rec.Validity.NotAfter.Time.Add(24*time.Hour))',
      tests=[('./cmd/mac-keyvault','TestRunSignPolicyGates/expired'),('./internal/keyvault','TestManagerSignGates/expired_one_hour')]),
 dict(id='M7', file=KV, name='sign self-check runs only when the value was normalised',
      narrows='admits a low-S signature under another key out of sign',
      old='	if len(key.SPKI) != 0 {\n		// The public half is known',
      new='	if len(key.SPKI) != 0 && result.Normalized {\n		// The public half is known',
      tests=[('./internal/keyvault','TestManagerSignGates/signature_under_another_key_is_refused')]),
 dict(id='M8', file=EC, name='VerifyDigest accepts any low-S signature',
      narrows='admits a tampered low-S signature as verified; high-S verdicts unchanged',
      old='	return ecdsa.Verify(pub, digest, sig.R, sig.S), nil',
      new='	return ecdsa.Verify(pub, digest, sig.R, sig.S) || sig.IsLowS(), nil',
      tests=[('./cmd/mac-keyvault','TestRunVerifyVerdicts/tampered_r'),('./cmd/mac-keyvault','TestRunSignVerifyAgainstLoginKeychain')]),
 dict(id='M9', file=EC, name='ParseSPKI accepts any ECDSA curve',
      narrows='admits a P-384 SPKI file to verify; non-EC keys still refused',
      old='	if !ok || pub.Curve != elliptic.P256() {',
      new='	if !ok {',
      tests=[('./cmd/mac-keyvault','TestRunSignVerifyRefuseBadInputBeforeStore/verify_spki_p384'),('./internal/keyvault','TestParseSPKI/p-384')]),
 dict(id='M10', file=MAIN, name='bytesArg hex-decodes @FILE contents when they look like hex',
      narrows='misreads one raw 32-byte digest file (ASCII hex chars) as 16 bytes',
      old='		return data, nil\n	}\n	decoded, err := hex.DecodeString',
      new='		if decoded, err := hex.DecodeString(strings.TrimSpace(string(data))); err == nil {\n			return decoded, nil\n		}\n		return data, nil\n	}\n	decoded, err := hex.DecodeString',
      tests=[('./cmd/mac-keyvault','TestRunSignVerifyRefuseBadInputBeforeStore/hex-looking_file_is_raw_bytes')]),
 dict(id='M11', file=KV, name='PublicKeyFor skips the operations gate',
      narrows='admits verify by label against a record with no registry row',
      old='	if err := m.authorize(key, OperationVerify); err != nil {\n		return Key{}, err\n	}',
      new='	if err := m.authorize(key, OperationVerify); err != nil && key.RecordProblem != "" {\n		return Key{}, err\n	}',
      tests=[('./cmd/mac-keyvault','TestRunSignPolicyGates/verify_by_label_no_registry_row'),('./internal/keyvault','TestManagerPublicKeyFor/no_registry_row')]),
 dict(id='M12', file=MAIN, name='CLI digest length judged only by the manager (store listed first)',
      narrows='a mis-sized digest is still refused, but after a keychain listing',
      old='		if err := keyvault.ValidateDigest(digest); err != nil {\n			return nil, "", err\n		}\n		return digest, "digest", nil',
      new='		return digest, "digest", nil',
      tests=[('./cmd/mac-keyvault','TestRunSignVerifyRefuseBadInputBeforeStore/sign_digest_31_hex')]),
 dict(id='M12b', file=KV, name='Manager.Sign validates the digest after resolving the address',
      narrows='a mis-sized digest is refused only after the store was listed',
      old='	if err := ValidateDigest(digest); err != nil {\n		return SignResult{}, err\n	}\n	if err := RequireOwnLabel(addr.Label()); err != nil {\n		return SignResult{}, err\n	}\n	key, err := m.resolve(addr)\n	if err != nil {\n		return SignResult{}, err\n	}',
      new='	if err := RequireOwnLabel(addr.Label()); err != nil {\n		return SignResult{}, err\n	}\n	key, err := m.resolve(addr)\n	if err != nil {\n		return SignResult{}, err\n	}\n	if err := ValidateDigest(digest); err != nil {\n		return SignResult{}, err\n	}',
      tests=[('./internal/keyvault','TestManagerSignGates/mis-sized_digest_before_any_call')]),
 dict(id='M12c', file=None, name='both digest-length gates run after the keychain listing (M12 + M12b together)',
      narrows='a mis-sized digest is still refused (exit 3 invalid_digest) but only after the store was listed',
      multi=[(MAIN, '		if err := keyvault.ValidateDigest(digest); err != nil {\n			return nil, "", err\n		}\n		return digest, "digest", nil', '		return digest, "digest", nil'),
             (KV, '	if err := ValidateDigest(digest); err != nil {\n		return SignResult{}, err\n	}\n	if err := RequireOwnLabel(addr.Label()); err != nil {\n		return SignResult{}, err\n	}\n	key, err := m.resolve(addr)\n	if err != nil {\n		return SignResult{}, err\n	}', '	if err := RequireOwnLabel(addr.Label()); err != nil {\n		return SignResult{}, err\n	}\n	key, err := m.resolve(addr)\n	if err != nil {\n		return SignResult{}, err\n	}\n	if err := ValidateDigest(digest); err != nil {\n		return SignResult{}, err\n	}')],
      tests=[('./cmd/mac-keyvault','TestRunSignVerifyRefuseBadInputBeforeStore/sign_digest_31_hex'),('./cmd/mac-keyvault','TestRunSignVerifyRefuseBadInputBeforeStore/verify_digest_31')]),
 dict(id='M13', file=KV, name='forged record allowed into sign (trust gate skips ValidateStored)',
      narrows='admits a record with an invariant violation to the private key; unreadable tags still refused',
      old='	if err := ValidateStored(key.Label, rec); err != nil {\n		return &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s carries a record this revision cannot trust',
      new='	if err := ValidateStored(key.Label, rec); err != nil && false {\n		return &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s carries a record this revision cannot trust',
      tests=[('./cmd/mac-keyvault','TestRunSignPolicyGates/forged_title'),('./internal/keyvault','TestForgedStoredRecordRefusedEverywhere/title_81_characters')]),
]

def sh(*args):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True)

def main():
    survivors = []
    for m in MUTANTS:
        edits = m.get('multi') or [(m['file'], m['old'], m['new'])]
        originals = {}
        for f, old, new in edits:
            path = os.path.join(ROOT, f)
            originals.setdefault(path, open(path, 'rb').read())
            text = open(path, 'rb').read().decode()
            if text.count(old) != 1:
                print(f"{m['id']}: anchor not unique/found in {f} ({text.count(old)})"); sys.exit(2)
            open(path, 'wb').write(text.replace(old, new).encode())
        try:
            build = sh('go', 'vet', './internal/keyvault/', './cmd/mac-keyvault/')
            killed = []
            for pkg, test in m['tests']:
                r = sh('go', 'test', '-count=1', '-run', '^' + test.split('/')[0] + '$', pkg) if build.returncode != 0 else sh('go', 'test', '-count=1', '-run', '^' + test.replace('/', '$/^') + '$', pkg)
                killed.append((test, r.returncode != 0))
            status = 'KILLED' if all(k for _, k in killed) else 'SURVIVED'
            print(f"{m['id']} {status}: {m['name']} | narrows: {m['narrows']} | " + ', '.join(f"{t}={'FAIL' if k else 'pass'}" for t, k in killed) + (f" | build={build.returncode}" if build.returncode else ''))
            if status == 'SURVIVED':
                survivors.append(m['id'])
        finally:
            for path, original in originals.items():
                open(path, 'wb').write(original)
    assert sh('git', 'diff', '--stat').returncode == 0
    print('survivors:', survivors or 'none')
    sys.exit(1 if survivors else 0)

main()
