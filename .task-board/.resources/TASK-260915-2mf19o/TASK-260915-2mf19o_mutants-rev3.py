#!/usr/bin/env python3
"""Narrowing-mutant harness for TASK-260915-2mf19o rev3.

Each mutant keeps the gate present and weakens it to admit one member of the
class it must reject; the named tests must FAIL. Files are restored from a
byte-exact backup after every mutant. Exit code 1 if any mutant survives.
"""
import subprocess, sys, shutil, os, re

ROOT = os.environ.get('MUTANT_ROOT') or os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
REC = 'internal/keyvault/record.go'
KV = 'internal/keyvault/keyvault.go'
REG = 'internal/keyvault/registry.go'
C = 'internal/keyvault/security_darwin.c'
MAIN = 'cmd/mac-keyvault/main.go'

MUTANTS = [
 dict(id='M1', finding='F1', file=REC, name='ParseAddress accepts a full label inside the prefix as an address',
      narrows='admits one raw-label shape (own full label) past the address-only contract',
      old='''	service, purpose, ok := strings.Cut(input, "/")
	if !ok {''',
      new='''	service, purpose, ok := strings.Cut(input, "/")
	if parsed, isLabel := ParseLabel(input); !ok && isLabel {
		return parsed, nil
	}
	if !ok {''',
      tests=[('./cmd/mac-keyvault','TestRunForeignLabelRefusedAtEntry'),('./internal/keyvault','TestParseAddressAndLabel/full_own_label')]),
 dict(id='M2', finding='F2', file=KV, name='lock released after the duplicate check, before Create',
      narrows='admits the concurrent second create of one label',
      old='''	rec.Created = NewTime(m.now())
	tag, err := EncodeRecord(rec)''',
      new='''	release()
	release = func() {}
	rec.Created = NewTime(m.now())
	tag, err := EncodeRecord(rec)''',
      tests=[('./internal/keyvault','TestManagerInitDuplicateRefusalIsAtomic')]),
 dict(id='M3', finding='F3', file=MAIN, name='usage errors bypass the JSON emitter',
      narrows='admits plain-text usage output in --json mode',
      old='''	code, respErr := o.classify(err)
	if o.json {''',
      new='''	code, respErr := o.classify(err)
	if o.json && code != exitUsage {''',
      tests=[('./cmd/mac-keyvault','TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore')]),
 dict(id='M3b', finding='F3', file=MAIN, name='unknown command prints text and exits 2 directly',
      narrows='admits one usage path (unknown command) around the envelope',
      old='''	default:
		return out.fail(usagef("unknown command %q", command))''',
      new='''	default:
		fmt.Fprintf(stderr, "unknown command %q\\n", command)
		return exitUsage''',
      tests=[('./cmd/mac-keyvault','TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore/unknown_command')]),
 dict(id='M4', finding='F4', file=KV, name='rotate maps store unknown to keychain',
      narrows='admits the unknown-store schema-2 record (schema-1/unreadable still refused)',
      old='''	case rec.Store != StoreKeychain && rec.Store != StoreEnclave:
		return RotateResult{}, &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s has store %q; the origin is unknown and the keychain is not assumed, so no generation is created", newest.Label, rec.Store), Hint: hint}''',
      new='''	case rec.Store != StoreKeychain && rec.Store != StoreEnclave:
		rec.Store = StoreKeychain''',
      tests=[('./internal/keyvault','TestManagerRotateRefusesUnknownMetadata/unknown_store'),('./cmd/mac-keyvault','TestRunRotateRefusesUnknownMetadata/unknown_store')]),
 dict(id='M4b', finding='F4', file=KV, name='rotate upgrades a schema-1 record to schema 2 with guessed service/purpose',
      narrows='admits the rev1-tag key',
      old='''	case rec.Schema != SchemaVersion:
		return RotateResult{}, &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s carries record schema %d, not %d; its policy is unknown and is never upgraded silently, so no generation is created", newest.Label, rec.Schema, SchemaVersion), Hint: hint}''',
      new='''	case rec.Schema == 1:
		rec = legacyUpgrade(parsed, rec)
	case rec.Schema != SchemaVersion:
		return RotateResult{}, &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s carries record schema %d, not %d; its policy is unknown and is never upgraded silently, so no generation is created", newest.Label, rec.Schema, SchemaVersion), Hint: hint}''',
      extra='''
func legacyUpgrade(parsed Address, rec Record) Record {
	rec.Schema, rec.Kind, rec.Algorithm, rec.Service, rec.Purpose, rec.Version = SchemaVersion, parsed.Kind, AlgorithmECP256, parsed.Service, parsed.Purpose, parsed.Version
	rec.Extraction, rec.Usages, rec.Format = ExtractionNone, []string{"sign"}, Format{Public: FormatPublicSPKIDER, Signature: FormatSignatureDERLowS}
	return rec
}
''',
      tests=[('./internal/keyvault','TestManagerRotateRefusesUnknownMetadata/schema_1_keychain'),('./cmd/mac-keyvault','TestRunRotateRefusesUnknownMetadata/rev1_keychain')]),
 dict(id='M5', finding='F5', file=C, name='kSecAttrIsExtractable moved back inside kSecPrivateKeyAttrs (rev1 shape)',
      narrows='admits an extractable private key while every other attribute stays',
      old='''    CFDictionarySetValue(attrs, kSecAttrIsExtractable, kCFBooleanFalse);
    CFDictionarySetValue(attrs, kSecPrivateKeyAttrs, privateAttrs);''',
      new='''    CFDictionarySetValue(privateAttrs, kSecAttrIsExtractable, kCFBooleanFalse);
    CFDictionarySetValue(attrs, kSecPrivateKeyAttrs, privateAttrs);''',
      tests=[('./internal/keyvault','TestSecurityStorePrivateKeyIsNotExtractable')]),
 dict(id='M6', finding='F5', file=C, name='ACL trusted-application list gains a second binary (/usr/bin/security)',
      narrows='admits one more application into the private-key ACL',
      old='''    CFArrayRef trusted = CFArrayCreate(kCFAllocatorDefault, (const void **)&self, 1, &kCFTypeArrayCallBacks);
    CFRelease(self);''',
      new='''    SecTrustedApplicationRef other = NULL;
    SecTrustedApplicationCreateFromPath("/usr/bin/security", &other);
    const void *both[2] = { self, other };
    CFArrayRef trusted = CFArrayCreate(kCFAllocatorDefault, both, 2, &kCFTypeArrayCallBacks);
    CFRelease(self);
    if (other != NULL) CFRelease(other);''',
      tests=[('./internal/keyvault','TestSecurityStoreACLTrustsOnlyCallingBinary')]),
 dict(id='M6b', finding='F5', file=C, name='private-key ACL entries rewritten to trust any application (SecACLSetContents NULL)',
      narrows='the SecAccess is still installed but its private entries admit every application',
      old='''    status = SecAccessCreate(CFSTR("mac-keyvault private key"), trusted, out);
    CFRelease(trusted);
    return status;''',
      new='''    status = SecAccessCreate(CFSTR("mac-keyvault private key"), trusted, out);
    CFRelease(trusted);
    if (status != errSecSuccess) return status;
    CFArrayRef acls = NULL;
    if (SecAccessCopyACLList(*out, &acls) == errSecSuccess) {
        for (CFIndex i = 0; i < CFArrayGetCount(acls); i++) {
            SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
            CFArrayRef apps = NULL; CFStringRef desc = NULL; SecKeychainPromptSelector sel = 0;
            if (SecACLCopyContents(acl, &apps, &desc, &sel) == errSecSuccess) {
                if (apps != NULL) { SecACLSetContents(acl, NULL, desc, sel); CFRelease(apps); }
                if (desc != NULL) CFRelease(desc);
            }
        }
        CFRelease(acls);
    }
    return status;''',
      tests=[('./internal/keyvault','TestSecurityStoreACLTrustsOnlyCallingBinary')]),
 dict(id='M7', finding='model', file=REC, name='"fingerprint" dropped from ReservedMetaNames',
      narrows='admits one reserved name inside meta',
      old='"user_presence", "label", "fingerprint", "exposure"',
      new='"user_presence", "label", "exposure"',
      tests=[('./internal/keyvault','TestValidateNew/meta_reserved_fingerprint'),('./cmd/mac-keyvault','TestRunInitValidatesRecordBeforeStore/meta_reserved_json')]),
 dict(id='M8', finding='model', file=REC, name='ed25519 accepted as an algorithm',
      narrows='admits one known-unsupported algorithm',
      old='''	case AlgorithmEd25519:
		return &Refusal{Code: CodeUnsupportedAlgorithm, Message: "algorithm \\"ed25519\\" is refused explicitly: Security.framework SecKey has no Ed25519 support and the vault never maps it to another curve", Hint: "use --algorithm ec-p256"}''',
      new='''	case AlgorithmEd25519:
		// admitted''',
      tests=[('./internal/keyvault','TestValidateNew/algorithm_ed25519'),('./cmd/mac-keyvault','TestRunInitValidatesRecordBeforeStore/algorithm_ed25519')]),
 dict(id='M9', finding='model', file=REC, name='extraction agent admitted on a Secure Enclave key',
      narrows='admits one extraction value the Enclave can never honour',
      old='''	if rec.Extraction != ExtractionNone && rec.Store == StoreEnclave {''',
      new='''	if rec.Extraction == ExtractionHuman && rec.Store == StoreEnclave {''',
      tests=[('./internal/keyvault','TestValidateNew/extraction_agent_enclave')]),
 dict(id='M10', finding='F1', file=KV, name='RequireOwnLabel accepts the prefix without its trailing dot',
      narrows='admits the works.relux.mac-keyvaultX lookalike namespace',
      old='''	if !strings.HasPrefix(label, LabelPrefix) || len(label) == len(LabelPrefix) {''',
      new='''	if !strings.HasPrefix(label, strings.TrimSuffix(LabelPrefix, ".")) || len(label) <= len(LabelPrefix) {''',
      tests=[('./internal/keyvault','TestRequireOwnLabel'),('./internal/keyvault','TestParseAddress/foreign_lookalike_prefix'),('./cmd/mac-keyvault','TestRunForeignLabelRefusedAtEntry')]),
 dict(id='M11', finding='delete', file=KV, name='delete of an explicit version needs no confirmation',
      narrows='admits one unconfirmed delete shape',
      old='''	if !confirmed {
		return "", &Refusal{Code: CodeConfirmationRequired''',
      new='''	if !confirmed && addr.Version == 0 {
		return "", &Refusal{Code: CodeConfirmationRequired''',
      tests=[('./internal/keyvault','TestManagerDeleteGates/own_version_unconfirmed'),('./cmd/mac-keyvault','TestRunJSONEnvelopeAndExitCodes/delete_unconfirmed_versioned')]),
 dict(id='M12', finding='duplicate', file=KV, name='duplicate check ignores rotated generations',
      narrows='admits init of an address that exists only as .vN',
      old='''	if rec.Version == 1 {
		if existing, err := pick(keys, family); err == nil {''',
      new='''	if rec.Version == 1 && false {
		if existing, err := pick(keys, family); err == nil {''',
      tests=[('./internal/keyvault','TestManagerInitValidatesThenGatesDuplicates')]),
 dict(id='M13', finding='model', file=REC, name='v1 tag decoded as schema 2',
      narrows='admits a silent upgrade of the legacy record',
      old='''		rec := unknown
		rec.Schema = 1
''',
      new='''		rec := unknown
		rec.Schema = SchemaVersion
''',
      tests=[('./internal/keyvault','TestRecordEncodingAndLegacyTags'),('./cmd/mac-keyvault','TestRunDescribeOperationsAndLegacy')]),
 dict(id='M14', finding='model', file=REG, name='unknown registry row falls back to the ec-p256 keychain row',
      narrows='admits guessed operations for an unknown primitive',
      old='''	primitive, ok := LookupPrimitive(rec)
	if !ok {
		return ops, []string{CodeUnsupportedPrimitive}
	}''',
      new='''	primitive, ok := LookupPrimitive(rec)
	if !ok {
		primitive = registry[PrimitiveKey{Kind: KindKey, Algorithm: AlgorithmECP256, Store: StoreKeychain}]
	}''',
      tests=[('./internal/keyvault','TestOperationsRegistry'),('./cmd/mac-keyvault','TestRunDescribeOperationsAndLegacy')]),
 dict(id='M15', finding='model', file=KV, name='record validation runs after the store listing',
      narrows='admits a Security call before an invalid record is refused',
      old='''	if err := ValidateNew(rec); err != nil {
		return Key{}, err
	}
	if spec.Generate != "" && rec.Kind != KindSecret {''',
      new='''	if _, err := m.backend.List(); err != nil {
		return Key{}, err
	}
	if err := ValidateNew(rec); err != nil {
		return Key{}, err
	}
	if spec.Generate != "" && rec.Kind != KindSecret {''',
      tests=[('./internal/keyvault','TestManagerInitValidatesThenGatesDuplicates'),('./cmd/mac-keyvault','TestRunInitValidatesRecordBeforeStore')]),
 dict(id='M16', finding='F1', file=MAIN, name='singleAddress accepts a parseable full label before ParseAddress',
      narrows='admits one raw-label shape at the CLI layer around the address gate',
      old='''	return keyvault.ParseAddress(positional[0], kind, version)
}''',
      new='''	if parsed, ok := keyvault.ParseLabel(positional[0]); ok {
		return parsed, nil
	}
	return keyvault.ParseAddress(positional[0], kind, version)
}''',
      tests=[('./cmd/mac-keyvault','TestRunForeignLabelRefusedAtEntry')]),
 dict(id='M17', finding='contract', file=MAIN, name='usage errors emitted without a hint',
      narrows='admits one envelope class that violates {code, message, hint}',
      old='''		return exitUsage, &responseError{Code: "usage", Message: usage.msg, Hint: hint}''',
      new='''		_ = hint
		return exitUsage, &responseError{Code: "usage", Message: usage.msg}''',
      tests=[('./cmd/mac-keyvault','TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore')]),
 dict(id='M18', finding='contract', file=MAIN, name='missing_entitlement reported as a policy refusal (exit 3)',
      narrows='admits one operational failure into the refusal exit class',
      old='''		code := exitRefused
		if refusal.Failure {
			code = exitFailure
		}''',
      new='''		code := exitRefused''',
      tests=[('./cmd/mac-keyvault','TestRunInitMissingEntitlementIsExplicit'),('./cmd/mac-keyvault','TestRunSecurityErrorIsExitOne')]),
 dict(id='M19', finding='model', file=REC, name='format.envelope admitted on a key',
      narrows='admits one format key outside the per-kind allowed set',
      old='''		if format.Envelope != "" {
			return &Refusal{Code: CodeInvalidFormat, Message: fmt.Sprintf("format.envelope is not allowed for kind %s", kind), Hint: "drop --format-envelope; it belongs to kind secret"}
		}''',
      new='''		if format.Envelope != "" && kind != KindKey {
			return &Refusal{Code: CodeInvalidFormat, Message: fmt.Sprintf("format.envelope is not allowed for kind %s", kind), Hint: "drop --format-envelope; it belongs to kind secret"}
		}''',
      tests=[('./internal/keyvault','TestValidateNew/format_envelope_for_key'),('./cmd/mac-keyvault','TestRunInitValidatesRecordBeforeStore/format_envelope_key')]),
 dict(id='M20', finding='model', file=REC, name='address match ignores kind',
      narrows='admits a record of another kind for the same service/purpose (uniqueness tuple loses kind)',
      old='''	return parsed.Kind == a.Kind && parsed.Service == a.Service''',
      new='''	return parsed.Service == a.Service''',
      tests=[('./cmd/mac-keyvault','TestRunJSONEnvelopeAndExitCodes/describe_other_kind'),('./internal/keyvault','TestManagerListAndDescribe')]),
 dict(id='M21', finding='F4', file=KV, name='rotate accepts a record that contradicts its label',
      narrows='admits one metadata mismatch shape',
      old='''	case rec.Kind != parsed.Kind || rec.Service != parsed.Service || rec.Purpose != parsed.Purpose || rec.Version != parsed.Version:''',
      new='''	case rec.Kind != parsed.Kind:''',
      tests=[('./internal/keyvault','TestManagerRotateRefusesUnknownMetadata/label_mismatch')]),
 dict(id='M22', finding='F6', file=MAIN, name='version accepts and ignores extra positionals/flags (JSON emitter kept)',
      narrows='admits one command (version) around the usage gate while every other command keeps it',
      old='''	case "version":
		return runVersion(rest, out)''',
      new='''	case "version":
		return runVersion(nil, out)''',
      tests=[('./cmd/mac-keyvault','TestRunVersionRejectsExtraInput')]),
 dict(id='M22b', finding='F6', file=MAIN, name='version parses flags but drops leftover positionals',
      narrows='admits the positional shape (version extra) while an unknown flag is still refused',
      old='''	if err := requireNoArguments("version", positional); err != nil {
		return out.fail(err)
	}''',
      new='''	_ = positional''',
      tests=[('./cmd/mac-keyvault','TestRunVersionRejectsExtraInput/version_positional')]),
 dict(id='M23', finding='F6', file=MAIN, name='JSON decoding kept, trailing document admitted (EOF check dropped)',
      narrows='admits a second/trailing JSON document after a well-formed first object',
      old='''	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("unexpected data after the JSON document")
		}
		return err
	}
	return nil''',
      new='''	return nil''',
      tests=[('./cmd/mac-keyvault','TestRunMetaJSONRejectsTrailingDocument')]),
 dict(id='M23b', finding='F6', file=MAIN, name='trailing garbage refused but a well-formed second document admitted',
      narrows='admits exactly the second-object shape ({"a":1} {"b":2}); garbage after the first object still fails',
      old='''		if err == nil {
			return errors.New("unexpected data after the JSON document")
		}
		return err''',
      new='''		if err == nil {
			return nil
		}
		return err''',
      tests=[('./cmd/mac-keyvault','TestRunMetaJSONRejectsTrailingDocument/second_object')]),
 dict(id='M24', finding='F7', file=REC, name='title bound restored to bytes (len instead of RuneCountInString)',
      narrows='refuses the valid 80-character non-ASCII title (positive boundary control fails)',
      old='''	if n := utf8.RuneCountInString(rec.Title); n > MaxTitleLength {''',
      new='''	if n := len(rec.Title); n > MaxTitleLength || !utf8.ValidString(rec.Title) {''',
      tests=[('./cmd/mac-keyvault','TestRunTitleCharacterBound'),('./internal/keyvault','TestValidateNew')]),
 dict(id='M24b', finding='F7', file=REC, name='title bound off by one (81 characters admitted)',
      narrows='admits exactly the 81-character title',
      old='''	if n := utf8.RuneCountInString(rec.Title); n > MaxTitleLength {''',
      new='''	if n := utf8.RuneCountInString(rec.Title); n > MaxTitleLength+1 {''',
      tests=[('./cmd/mac-keyvault','TestRunTitleCharacterBound'),('./internal/keyvault','TestValidateNew/title_81_armenian')]),
 dict(id='M25', finding='F8', file=REC, name='issuer with a complete {dn, fingerprint} admitted on a key (only partial issuers refused)',
      narrows='admits one non-null issuer shape (complete) on a non-certificate kind',
      old='''	default:
		if issuer != nil {''',
      new='''	default:
		if issuer != nil && (issuer.DN == "" || issuer.Fingerprint == "") {''',
      tests=[('./internal/keyvault','TestManagerRotateRefusesUnknownMetadata/forged_issuer'),('./cmd/mac-keyvault','TestRunRotateRefusesUnknownMetadata/forged_issuer'),('./internal/keyvault','TestValidateNew/issuer_on_key')]),
 dict(id='M25b', finding='F8', file=KV, name='rotate skips ValidateNew on the reproduced record (init still validates)',
      narrows='admits reproduction of a stored record that init would refuse',
      old='''	if err := ValidateNew(next); err != nil {
		return RotateResult{}, &Refusal{Code: CodeMetadataUnknown''',
      new='''	if err := ValidateNew(next); err != nil && next.Issuer == nil {
		return RotateResult{}, &Refusal{Code: CodeMetadataUnknown''',
      tests=[('./internal/keyvault','TestManagerRotateRefusesUnknownMetadata/forged_issuer'),('./cmd/mac-keyvault','TestRunRotateRefusesUnknownMetadata/forged_issuer')]),
]

def run_tests(tests):
    results = []
    for pkg, name in tests:
        proc = subprocess.run(['go','test','-count=1','-run','^'+name.split('/')[0]+'$/'+ '/'.join(name.split('/')[1:]) if '/' in name else '^'+name+'$', pkg],
                              cwd=ROOT, capture_output=True, text=True)
        results.append((pkg, name, proc.returncode, (proc.stdout+proc.stderr)[-600:]))
    return results

def main():
    only = sys.argv[1:]
    survivors = 0
    rows = []
    for m in MUTANTS:
        if only and m['id'] not in only:
            continue
        path = os.path.join(ROOT, m['file'])
        backup = path + '.mutant-backup'
        shutil.copy2(path, backup)
        src = open(path).read()
        if m['old'] not in src:
            print(f"{m['id']}: PATCH DID NOT APPLY ({m['file']})"); survivors += 1
            os.remove(backup); rows.append((m, 'patch-failed', [])); continue
        mutated = src.replace(m['old'], m['new'], 1) + m.get('extra','')
        open(path,'w').write(mutated)
        try:
            results = run_tests(m['tests'])
        finally:
            shutil.copy2(backup, path); os.remove(backup)
        killed = [r for r in results if r[2] != 0]
        status = 'killed' if killed else 'SURVIVED'
        if not killed: survivors += 1
        rows.append((m, status, results))
        print(f"== {m['id']} [{m['finding']}] {m['name']} -> {status}")
        for pkg, name, rc, out in results:
            print(f"   {pkg} {name}: rc={rc}")
            if rc != 0:
                lines = [l for l in out.splitlines() if '--- FAIL' in l or 'FAIL' in l or '.go:' in l][:4]
                for l in lines: print('      ' + l.strip()[:200])
    # verify baseline restored
    proc = subprocess.run(['git','status','--short','--','internal/keyvault','cmd/mac-keyvault'], cwd=ROOT, capture_output=True, text=True)
    print('\n## Markdown table\n')
    print('| Mutant | Finding | What it narrows the gate to | Named failing test(s) | Result |')
    print('| --- | --- | --- | --- | --- |')
    for m, status, results in rows:
        names = '<br>'.join(f"`{n}` (rc={rc})" for _, n, rc, _ in results if rc != 0) or '—'
        print(f"| {m['id']}: {m['name']} | {m['finding']} | {m['narrows']} | {names} | {status} |")
    print(f"\nsurvivors={survivors}")
    sys.exit(1 if survivors else 0)

if __name__ == '__main__':
    main()
