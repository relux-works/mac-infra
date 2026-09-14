#!/usr/bin/env python3
"""Narrowing-mutant harness for TASK-260915-2mf19o rev6.

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
INV = 'internal/keyvault/invariants.go'

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
      old='''	tag, err := EncodeRecord(rec)
	if err != nil {
		return Key{}, err
	}
	item, err := m.backend.Create(''',
      new='''	release()
	release = func() {}
	tag, err := EncodeRecord(rec)
	if err != nil {
		return Key{}, err
	}
	item, err := m.backend.Create(''',
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
 dict(id='M4', finding='F4', file=KV, name='rotate maps store unknown to keychain before the invariant table runs',
      narrows='admits the unknown-store schema-2 record (schema-1/unreadable still refused)',
      old='''	if err := ValidateStored(newest.Label, rec); err != nil {
		return RotateResult{}, &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s carries a record this revision cannot reproduce (%v); no generation is created", newest.Label, err), Hint: hint}
	}
	next := rec''',
      new='''	if rec.Store == StoreUnknown {
		rec.Store = StoreKeychain
	}
	if err := ValidateStored(newest.Label, rec); err != nil {
		return RotateResult{}, &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s carries a record this revision cannot reproduce (%v); no generation is created", newest.Label, err), Hint: hint}
	}
	next := rec''',
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
 dict(id='M8', finding='model', file=INV, name='ed25519 accepted as an algorithm',
      narrows='admits one known-unsupported algorithm',
      old='''	case AlgorithmEd25519:
		return refuse(CodeUnsupportedAlgorithm, ''',
      new='''	case AlgorithmEd25519:
		return nil
		return refuse(CodeUnsupportedAlgorithm, ''',
      tests=[('./internal/keyvault','TestValidateNew/algorithm_ed25519'),('./cmd/mac-keyvault','TestRunInitValidatesRecordBeforeStore/algorithm_ed25519')]),
 dict(id='M9', finding='model', file=INV, name='extraction agent admitted on a Secure Enclave key',
      narrows='admits one extraction value (agent) on the enclave store; human still refused',
      old='''	if store == StoreEnclave {
		return refuse(CodeInvalidExtraction, "Secure Enclave keys are never extractable", "use --extraction none with --enclave")''',
      new='''	if store == StoreEnclave && extraction == ExtractionHuman {
		return refuse(CodeInvalidExtraction, "Secure Enclave keys are never extractable", "use --extraction none with --enclave")''',
      tests=[('./internal/keyvault','TestValidateNew/extraction_agent_enclave'),('./internal/keyvault','TestForgedStoredRecordRefusedEverywhere/extraction_agent_on_enclave')]),
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
 dict(id='M19', finding='model', file=INV, name='format.envelope admitted on a key',
      narrows='admits one foreign format key (envelope) on kind key; public-key still refuses it',
      old='''		if format.Envelope != "" {
			return refuse(CodeInvalidFormat, fmt.Sprintf("format.envelope is not allowed for kind %s", kind), "drop --format-envelope; it belongs to kind secret")
		}''',
      new='''		if format.Envelope != "" && kind != KindKey {
			return refuse(CodeInvalidFormat, fmt.Sprintf("format.envelope is not allowed for kind %s", kind), "drop --format-envelope; it belongs to kind secret")
		}''',
      tests=[('./internal/keyvault','TestValidateNew/format_envelope_for_key'),('./cmd/mac-keyvault','TestRunInitValidatesRecordBeforeStore/format_envelope_key')]),
 dict(id='M20', finding='model', file=REC, name='address match ignores kind',
      narrows='admits a record of another kind for the same service/purpose (uniqueness tuple loses kind)',
      old='''	return parsed.Kind == a.Kind && parsed.Service == a.Service''',
      new='''	return parsed.Service == a.Service''',
      tests=[('./cmd/mac-keyvault','TestRunJSONEnvelopeAndExitCodes/describe_other_kind'),('./internal/keyvault','TestManagerListAndDescribe')]),
 dict(id='M21', finding='F4', file=INV, name='label agreement ignores the version (kind/service/purpose still compared)',
      narrows='admits a stored record whose version disagrees with its label',
      old='''	if !ok || rec.Kind != parsed.Kind || rec.Service != parsed.Service || rec.Purpose != parsed.Purpose || rec.Version != parsed.Version {''',
      new='''	if !ok || rec.Kind != parsed.Kind || rec.Service != parsed.Service || rec.Purpose != parsed.Purpose {''',
      tests=[('./internal/keyvault','TestForgedStoredRecordRefusedEverywhere/label_mismatch'),('./cmd/mac-keyvault','TestRunForgedStoredRecordRefusedEverywhere/label_mismatch')]),
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
 dict(id='M23', finding='F6', file=REC, name='shared DecodeSingleJSON keeps decoding, trailing document admitted (EOF check dropped)',
      narrows='admits a second/trailing JSON document after a well-formed first object',
      old='''	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("unexpected data after the JSON document")
		}
		return err
	}
	return nil''',
      new='''	return nil''',
      tests=[('./cmd/mac-keyvault','TestRunMetaJSONRejectsTrailingDocument'),('./cmd/mac-keyvault','TestRunRotateRefusesUnknownMetadata/trailing_token')]),
 dict(id='M23b', finding='F6', file=REC, name='shared decoder: trailing garbage refused but a well-formed second document admitted',
      narrows='admits exactly the second-object shape ({"a":1} {"b":2}); garbage after the first object still fails',
      old='''		if err == nil {
			return errors.New("unexpected data after the JSON document")
		}
		return err''',
      new='''		if err == nil {
			return nil
		}
		return err''',
      tests=[('./cmd/mac-keyvault','TestRunMetaJSONRejectsTrailingDocument/second_object'),('./cmd/mac-keyvault','TestRunRotateRefusesUnknownMetadata/trailing_document'),('./internal/keyvault','TestManagerRotateRefusesUnknownMetadata/trailing_document')]),
 dict(id='M24', finding='F7', file=INV, name='title bound restored to bytes (len instead of RuneCountInString)',
      narrows='refuses the valid 80-character non-ASCII title (positive boundary control fails)',
      old='''		if n := utf8.RuneCountInString(r.Title); n > MaxTitleLength {''',
      new='''		if n := len(r.Title); n > MaxTitleLength || !utf8.ValidString(r.Title) {''',
      tests=[('./cmd/mac-keyvault','TestRunTitleCharacterBound'),('./internal/keyvault','TestValidateNew')]),
 dict(id='M24b', finding='F7', file=INV, name='title bound off by one (81 characters admitted)',
      narrows='admits exactly the 81-character title',
      old='''		if n := utf8.RuneCountInString(r.Title); n > MaxTitleLength {''',
      new='''		if n := utf8.RuneCountInString(r.Title); n > MaxTitleLength+1 {''',
      tests=[('./cmd/mac-keyvault','TestRunTitleCharacterBound'),('./internal/keyvault','TestValidateNew/title_81_armenian'),('./internal/keyvault','TestForgedStoredRecordRefusedEverywhere/title_81_characters')]),
 dict(id='M25', finding='F8', file=INV, name='issuer with a complete {dn, fingerprint} admitted on a key (only partial issuers refused)',
      narrows='admits one non-null issuer shape (complete) on a non-certificate kind',
      old='''	default:
		if issuer != nil {''',
      new='''	default:
		if issuer != nil && (issuer.DN == "" || issuer.Fingerprint == "") {''',
      tests=[('./internal/keyvault','TestManagerRotateRefusesUnknownMetadata/forged_issuer'),('./cmd/mac-keyvault','TestRunRotateRefusesUnknownMetadata/forged_issuer'),('./internal/keyvault','TestValidateNew/issuer_on_key')]),
 dict(id='M25b', finding='F8', file=KV, name='rotate skips ValidateStored (ValidateNew on the re-stamped next record kept)',
      narrows='admits exactly the stored fields the next generation overwrites (version 0 -> 1, created null -> now, label disagreement); every policy field is still caught by ValidateNew',
      old='''	if err := ValidateStored(newest.Label, rec); err != nil {
		return RotateResult{}, &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s carries a record this revision cannot reproduce (%v); no generation is created", newest.Label, err), Hint: hint}
	}
	next := rec''',
      new='''	next := rec''',
      tests=[('./internal/keyvault','TestForgedStoredRecordRefusedEverywhere/version_zero'),('./internal/keyvault','TestForgedStoredRecordRefusedEverywhere/created_null'),('./cmd/mac-keyvault','TestRunForgedStoredRecordRefusedEverywhere/label_mismatch')]),
 dict(id='M26', finding='F9', file=MAIN, name='JSON detection narrowed back to string matching of four enumerated spellings (flag pre-parser bypassed)',
      narrows='admits every other flag.Bool true spelling (--json=TRUE, --json=1, -json=t, ...) into text mode on a usage error',
      old='\tfs := flag.NewFlagSet("json-mode", flag.ContinueOnError)\n\tfs.SetOutput(io.Discard)\n\tmode := fs.Bool("json", false, "")\n\tif err := fs.Parse([]string{arg}); err != nil || fs.NFlag() != 1 {\n\t\treturn false, false\n\t}\n\treturn *mode, true',
      new='\tswitch arg {\n\tcase "--json", "-json", "--json=true", "-json=true":\n\t\treturn true, true\n\t}\n\treturn false, false',
      tests=[('./cmd/mac-keyvault','TestRunJSONSpellingsRouteUsageErrors')]),
 dict(id='M26b', finding='F9', file=MAIN, name='flag pre-parser kept, exactly one spelling (--json=1) excluded from detection',
      narrows='admits the single spelling --json=1 into text mode; every other spelling still selects the envelope',
      old='\tif err := fs.Parse([]string{arg}); err != nil || fs.NFlag() != 1 {\n\t\treturn false, false\n\t}',
      new='\tif err := fs.Parse([]string{arg}); err != nil || fs.NFlag() != 1 || arg == "--json=1" {\n\t\treturn false, false\n\t}',
      tests=[('./cmd/mac-keyvault','TestRunJSONSpellingsRouteUsageErrors/--json=1_first')]),
 dict(id='M26c', finding='F9', file=MAIN, name='detector stops scanning at the first non-json token (json-after-command shapes bypass)',
      narrows='admits every "--json after the command" placement into text mode; --json first still detected with every spelling',
      old='\t\tif value, ok := jsonToken(arg); ok {\n\t\t\tjsonMode = value\n\t\t}\n\t}\n\treturn jsonMode',
      new='\t\tvalue, ok := jsonToken(arg)\n\t\tif !ok {\n\t\t\tbreak\n\t\t}\n\t\tjsonMode = value\n\t}\n\treturn jsonMode',
      tests=[('./cmd/mac-keyvault','TestRunJSONSpellingsRouteUsageErrors/--json_after'),('./cmd/mac-keyvault','TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore/list_with_arg')]),
 dict(id='M27', finding='F10', file=MAIN, name='list kind validation admits exactly one unknown kind ("bogus")',
      narrows='admits the single kind value bogus on the list path; the address paths still refuse it',
      old='\tif *kind != "" {\n\t\t// Same closed vocabulary as the address parser, judged before the\n\t\t// manager exists (review F10).\n\t\tif err := keyvault.ValidateKind(*kind); err != nil {',
      new='\tif *kind != "" && *kind != "bogus" {\n\t\tif err := keyvault.ValidateKind(*kind); err != nil {',
      tests=[('./cmd/mac-keyvault','TestRunListRejectsInvalidKindBeforeBackend/json_bogus')]),
 dict(id='M27b', finding='F10', file=MAIN, name='list kind validated only after Backend.List was called',
      narrows='the refusal still happens (exit 3, invalid_kind) but one Security call precedes it',
      old='\tif *kind != "" {\n\t\t// Same closed vocabulary as the address parser, judged before the\n\t\t// manager exists (review F10).\n\t\tif err := keyvault.ValidateKind(*kind); err != nil {\n\t\t\treturn out.fail(err)\n\t\t}\n\t}\n\tmanager, err := newManager()\n\tif err != nil {\n\t\treturn out.fail(err)\n\t}\n\tkeys, err := manager.List(*service, *kind)\n\tif err != nil {\n\t\treturn out.fail(err)\n\t}',
      new='\tmanager, err := newManager()\n\tif err != nil {\n\t\treturn out.fail(err)\n\t}\n\tkeys, err := manager.List(*service, *kind)\n\tif err != nil {\n\t\treturn out.fail(err)\n\t}\n\tif *kind != "" {\n\t\tif err := keyvault.ValidateKind(*kind); err != nil {\n\t\t\treturn out.fail(err)\n\t\t}\n\t}',
      tests=[('./cmd/mac-keyvault','TestRunListRejectsInvalidKindBeforeBackend')]),
 dict(id='M28', finding='F11', file=REC, name='DecodeRecord converts only numeric meta to float64 after the UseNumber decode',
      narrows='strings and bools still round-trip; numbers alone are rounded (2^53+1 -> 2^53)',
      old='\t\tif decoded.Meta == nil {\n\t\t\tdecoded.Meta = map[string]any{}\n\t\t}\n\t\treturn decoded, ""',
      new='\t\tif decoded.Meta == nil {\n\t\t\tdecoded.Meta = map[string]any{}\n\t\t}\n\t\tfor name, value := range decoded.Meta {\n\t\t\tif number, ok := value.(json.Number); ok {\n\t\t\t\tdecoded.Meta[name], _ = number.Float64()\n\t\t\t}\n\t\t}\n\t\treturn decoded, ""',
      tests=[('./internal/keyvault','TestDecodeRecordPreservesNumericMeta'),('./cmd/mac-keyvault','TestRunMetaNumberRoundTrips')]),
 dict(id='M28b', finding='F11', file=MAIN, name='meta set --json-value converts the parsed json.Number to float64 (rev3 shape)',
      narrows='init --meta-json numbers still exact; only the meta set path rounds',
      old='\t\t\tif err := keyvault.DecodeSingleJSON([]byte(positional[2]), &value); err != nil {\n\t\t\t\treturn out.fail(usagef("--json-value: %v", err))\n\t\t\t}\n',
      new='\t\t\tif err := keyvault.DecodeSingleJSON([]byte(positional[2]), &value); err != nil {\n\t\t\t\treturn out.fail(usagef("--json-value: %v", err))\n\t\t\t}\n\t\t\tif number, ok := value.(json.Number); ok {\n\t\t\t\tvalue, _ = number.Float64()\n\t\t\t}\n',
      tests=[('./cmd/mac-keyvault','TestRunMetaNumberRoundTrips')]),
 dict(id='M28c', finding='F11', file=MAIN, name='keyView re-decodes the record without UseNumber (stored tag exact, printed envelope rounded)',
      narrows='the record is persisted digit-exact; only what init/describe/list print is rounded',
      old='\tdecoder := json.NewDecoder(bytes.NewReader(raw))\n\tdecoder.UseNumber() // numeric meta is re-emitted digit-exact (review F11)\n\t_ = decoder.Decode(&view)',
      new='\t_ = json.Unmarshal(raw, &view)',
      tests=[('./cmd/mac-keyvault','TestRunMetaNumberRoundTrips')]),
 dict(id='M29', finding='F12', file=REC, name='DecodeRecord admits exactly a well-formed second JSON document after the record; trailing garbage/token still unreadable; --meta-json boundary untouched',
      narrows='admits the {record} {record} tag shape only (the reviewer probe shape); "{record}}" and "{record} 1" stay read failures and the shared input decoder is unchanged',
      old='\t\tvar decoded Record\n\t\tif err := DecodeSingleJSON([]byte(text), &decoded); err != nil {\n\t\t\treturn unknown, "record tag is not valid JSON: " + err.Error()\n\t\t}',
      new='\t\tvar decoded Record\n\t\tif err := DecodeSingleJSON([]byte(text), &decoded); err != nil {\n\t\t\tdecoded = Record{}\n\t\t\tlenient := json.NewDecoder(strings.NewReader(text))\n\t\t\tlenient.UseNumber()\n\t\t\tvar second map[string]any\n\t\t\tif err1 := lenient.Decode(&decoded); err1 != nil {\n\t\t\t\treturn unknown, "record tag is not valid JSON: " + err1.Error()\n\t\t\t}\n\t\t\tif err2 := lenient.Decode(&second); err2 != nil {\n\t\t\t\treturn unknown, "record tag is not valid JSON: " + err2.Error()\n\t\t\t}\n\t\t\tif _, err3 := lenient.Token(); err3 != io.EOF {\n\t\t\t\treturn unknown, "record tag is not valid JSON: " + err.Error()\n\t\t\t}\n\t\t}',
      tests=[('./internal/keyvault','TestManagerRotateRefusesUnknownMetadata/trailing_document'),('./cmd/mac-keyvault','TestRunRotateRefusesUnknownMetadata/trailing_document'),('./internal/keyvault','TestRecordEncodingAndLegacyTags')]),
 dict(id='M29b', finding='F12', file=REC, name='DecodeRecord bypasses the shared decoder and reads the tag with a bare json.Decoder (rev4 shape)',
      narrows='the persisted-record boundary alone loses the EOF rule; --meta-json and --json-value keep it',
      old='\t\tvar decoded Record\n\t\tif err := DecodeSingleJSON([]byte(text), &decoded); err != nil {\n\t\t\treturn unknown, "record tag is not valid JSON: " + err.Error()\n\t\t}',
      new='\t\tvar decoded Record\n\t\tbare := json.NewDecoder(strings.NewReader(text))\n\t\tbare.UseNumber()\n\t\tif err := bare.Decode(&decoded); err != nil {\n\t\t\treturn unknown, "record tag is not valid JSON: " + err.Error()\n\t\t}',
      tests=[('./internal/keyvault','TestManagerRotateRefusesUnknownMetadata/trailing_garbage'),('./cmd/mac-keyvault','TestRunRotateRefusesUnknownMetadata/trailing_token'),('./internal/keyvault','TestRecordEncodingAndLegacyTags')]),
 dict(id='M30', finding='F13', file=INV, name='validity row admits non-null not_before on a key when not_after is null (reversed-interval refusal kept)',
      narrows='admits exactly the reviewer probe shape {not_before: T, not_after: null} on a key; not_before with not_after and inverted intervals stay refused',
      old='''	default:
		if validity.NotBefore != nil {''',
      new='''	default:
		if validity.NotBefore != nil && validity.NotAfter != nil {''',
      tests=[('./internal/keyvault','TestManagerRotateRefusesUnknownMetadata/forged_not_before'),('./cmd/mac-keyvault','TestRunRotateRefusesUnknownMetadata/forged_not_before'),('./internal/keyvault','TestForgedStoredRecordRefusedEverywhere/validity_not_before_on_key'),('./cmd/mac-keyvault','TestRunForgedStoredRecordRefusedEverywhere/validity_not_before_on_key'),('./internal/keyvault','TestValidateNew/validity_not_before_on_key')]),
 dict(id='M30b', finding='F13', file=INV, name='one table row weakened to a no-op (created); every other row present',
      narrows='admits exactly a null created on a stored record; every other field stays governed',
      old='''	{"created", func(r Record) error {
		if r.Created.IsZero() {
			return refuse(CodeInvalidCreated, "created must be an RFC3339 timestamp, not null", hintFixInputNoSecurityCal)
		}
		return nil
	}},''',
      new='''	{"created", func(r Record) error { return nil }},''',
      tests=[('./internal/keyvault','TestForgedStoredRecordRefusedEverywhere/created_null'),('./cmd/mac-keyvault','TestRunForgedStoredRecordRefusedEverywhere/created_null'),('./internal/keyvault','TestValidateNew/created_null')]),
 dict(id='M30c', finding='F13', file=INV, name='one table row dropped (origin removed from the table; field list shrinks)',
      narrows='admits every origin forgery; the coverage test sees a Record field without a row',
      old='''	{"origin", func(r Record) error { return validateOrigin(r.Origin) }},
''',
      new='',
      tests=[('./internal/keyvault','TestRecordInvariantsCoverEveryField'),('./internal/keyvault','TestForgedStoredRecordRefusedEverywhere/origin_source_bogus'),('./cmd/mac-keyvault','TestRunForgedStoredRecordRefusedEverywhere/origin_user_empty')]),
 dict(id='M30d', finding='F13', file=KV, name='reads hide invariant violations (Findings skips ValidateStored)',
      narrows='writes still refuse; describe/list print a forged record with no record_invalid finding',
      old='''	if k.RecordProblem == "" && k.Record.Schema == SchemaVersion {
		if err := ValidateStored(k.Label, k.Record); err != nil {''',
      new='''	if k.RecordProblem == "" && k.Record.Schema == SchemaVersion && false {
		if err := ValidateStored(k.Label, k.Record); err != nil {''',
      tests=[('./internal/keyvault','TestForgedStoredRecordRefusedEverywhere/issuer_on_key'),('./cmd/mac-keyvault','TestRunForgedStoredRecordRefusedEverywhere/validity_not_before_on_key'),('./cmd/mac-keyvault','TestRunDescribeOperationsAndLegacy')]),
 dict(id='M30e', finding='F13', file=KV, name='meta writes skip ValidateStored (rotate still refuses)',
      narrows='admits re-persisting a forged record through meta set/unset',
      old='''	if err := ValidateStored(key.Label, key.Record); err != nil {
		return Key{}, &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s carries a record this revision cannot reproduce (%v); meta is not rewritten", key.Label, err), Hint: "delete --confirm --version N and init a fresh record; the vault never guesses store or policy"}
	}''',
      new='''	if err := ValidateStored(key.Label, key.Record); err != nil && false {
		return Key{}, &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s carries a record this revision cannot reproduce (%v); meta is not rewritten", key.Label, err), Hint: "delete --confirm --version N and init a fresh record; the vault never guesses store or policy"}
	}''',
      tests=[('./internal/keyvault','TestForgedStoredRecordRefusedEverywhere/validity_not_before_on_key'),('./cmd/mac-keyvault','TestRunForgedStoredRecordRefusedEverywhere/issuer_on_key')]),
 dict(id='M30f', finding='F13', file=INV, name='certificate validity row admits a missing not_before (not_after still required)',
      narrows='admits exactly {not_before: null, not_after: T} on a certificate',
      old='''		if validity.NotBefore == nil || validity.NotAfter == nil {
			return refuse(CodeInvalidValidity, "a certificate must carry validity.not_before and validity.not_after from its X.509", hintFixInputNoSecurityCal)''',
      new='''		if validity.NotAfter == nil {
			return refuse(CodeInvalidValidity, "a certificate must carry validity.not_before and validity.not_after from its X.509", hintFixInputNoSecurityCal)''',
      tests=[('./internal/keyvault','TestValidateRecordPerKind/certificate_no_not_before')]),
 dict(id='M30g', finding='F13', file=INV, name='extraction row admits agent on a public-key (human still refused on public kinds)',
      narrows='admits exactly extraction=agent on kind public-key',
      old='''	if kind != KindKey && kind != KindSecret {''',
      new='''	if kind != KindKey && kind != KindSecret && !(kind == KindPublicKey && extraction == ExtractionAgent) {''',
      tests=[('./internal/keyvault','TestValidateRecordPerKind/public-key_extraction_agent')]),
 dict(id='M30h', finding='F13', file=INV, name='origin.source accepts any imported:<hex> digest length',
      narrows='admits exactly a short imported digest; generated and full sha256 unchanged',
      old='''var importedSourcePattern = regexp.MustCompile(`^imported:[0-9a-f]{64}$`)''',
      new='''var importedSourcePattern = regexp.MustCompile(`^imported:[0-9a-f]+$`)''',
      tests=[('./internal/keyvault','TestForgedStoredRecordRefusedEverywhere/origin_source_short_digest'),('./cmd/mac-keyvault','TestRunForgedStoredRecordRefusedEverywhere/origin_source_short_digest')]),
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
