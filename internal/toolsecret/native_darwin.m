//go:build darwin && cgo

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <dlfcn.h>
#include <unistd.h>
#ifdef TOOLSECRET_TEST_TRACE
#define TS_TRACE(s) fprintf(stderr,"toolsecret-test-phase:%s\n",s)
#else
#define TS_TRACE(s) ((void)0)
#endif

typedef OSStatus (*CopyRequirement)(SecTrustedApplicationRef, SecRequirementRef *);
typedef OSStatus (*CreateRequirement)(const char *, SecRequirementRef, SecTrustedApplicationRef *);
static CopyRequirement copyRequirement;
static CreateRequirement createRequirement;

static id owned(CFTypeRef value) { return [(id)value autorelease]; }
static NSDictionary *failure(OSStatus s, NSString *message) {
    return @{ @"status": @(s), @"message": message ?: @"Security.framework refused operation" };
}
static NSString *reqString(SecRequirementRef req) {
    CFStringRef value = NULL;
    if (!req || SecRequirementCopyString(req, 0, &value)) return @"";
    return owned(value);
}
static NSString *storedRequirement(SecTrustedApplicationRef app) {
    SecRequirementRef req = NULL;
    if (!copyRequirement || copyRequirement(app, &req) || !req) return @"";
    NSString *s = reqString(req); CFRelease(req); return s;
}
static NSString *appPath(SecTrustedApplicationRef app) {
    CFDataRef data = NULL;
    if (SecTrustedApplicationCopyData(app, &data) || !data) return @"";
    const UInt8 *bytes = CFDataGetBytePtr(data);
    CFIndex len = CFDataGetLength(data);
    while (len && bytes[len-1] == 0) len--;
    NSString *s = [[[NSString alloc] initWithBytes:bytes length:len encoding:NSUTF8StringEncoding] autorelease];
    CFRelease(data); return s ?: @"";
}
static NSString *hex(NSData *data) {
    NSMutableString *s = [NSMutableString string];
    const unsigned char *b = [data bytes];
    for (NSUInteger i=0;i<[data length];i++) [s appendFormat:@"%02x", b[i]];
    return s;
}

static NSDictionary *ownerInfo(NSString *path, OSStatus *status) {
    SecStaticCodeRef code = NULL; SecRequirementRef req = NULL; CFDictionaryRef info = NULL;
    *status = SecStaticCodeCreateWithPath((CFURLRef)[NSURL fileURLWithPath:path],0,&code);
    if (*status) return nil;
    *status = SecStaticCodeCheckValidity(code,kSecCSStrictValidate,NULL);
    if (!*status) *status = SecCodeCopyDesignatedRequirement(code,0,&req);
    if (!*status) *status = SecCodeCopySigningInformation(code,kSecCSSigningInformation,&info);
    if (*status) { if(req)CFRelease(req); CFRelease(code); return nil; }
    NSDictionary *i = (NSDictionary *)info;
    uint32_t flags = [i[(id)kSecCodeInfoFlags] unsignedIntValue];
    NSDictionary *ents = i[(id)kSecCodeInfoEntitlementsDict];
    NSMutableArray *keys = [NSMutableArray array];
    for (NSString *k in ents) [keys addObject:k]; // Presence, including false, is refused.
    [keys sortUsingSelector:@selector(compare:)];
    NSString *partition = @"";
    NSString *team = i[(id)kSecCodeInfoTeamIdentifier];
    SecRequirementRef apple = NULL;
    // Match the certificate families used by securityd for team partitions.
    NSString *developer = @"anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.1] and (certificate leaf[field.1.2.840.113635.100.6.1.12] or certificate leaf[field.1.2.840.113635.100.6.1.7])";
    if (!SecRequirementCreateWithString((CFStringRef)developer,0,&apple)) {
        if (!SecStaticCodeCheckValidity(code,0,apple)) {
            // securityd uses certificate OU for these families, not an
            // unverified embedded team string. Check that they agree.
            NSCharacterSet *nonTeam=[[NSCharacterSet alphanumericCharacterSet] invertedSet];
            SecRequirementRef ou=NULL;
            if (!team.length || [team rangeOfCharacterFromSet:nonTeam].location!=NSNotFound) *status=errSecCSReqFailed;
            else {
                NSString *clause=[NSString stringWithFormat:@"certificate leaf[subject.OU] = \"%@\"",team];
                *status=SecRequirementCreateWithString((CFStringRef)clause,0,&ou);
                if (!*status) *status=SecStaticCodeCheckValidity(code,0,ou);
                if(ou)CFRelease(ou);
                if (!*status) partition=[@"teamid:" stringByAppendingString:team];
            }
        }
        CFRelease(apple);
    }
    if (*status) { CFRelease(info); CFRelease(req); CFRelease(code); return nil; }
    if (!partition.length && i[(id)kSecCodeInfoUnique]) partition = [@"cdhash:" stringByAppendingString:hex(i[(id)kSecCodeInfoUnique])];
    NSDictionary *result = @{ @"path":path, @"requirement":reqString(req), @"ad_hoc":(flags & kSecCodeSignatureAdhoc) ? @YES : @NO, @"hardened_runtime":(flags & kSecCodeSignatureRuntime) ? @YES : @NO, @"entitlements":keys, @"partition":partition };
    CFRelease(info); CFRelease(req); CFRelease(code); return result;
}

static BOOL hasAuth(CFArrayRef auths, CFStringRef value) {
    return auths && CFArrayContainsValue(auths,CFRangeMake(0,CFArrayGetCount(auths)),value);
}
static BOOL releasesPlaintext(CFArrayRef a) {
    return hasAuth(a,kSecACLAuthorizationDecrypt) || hasAuth(a,kSecACLAuthorizationExportClear) || hasAuth(a,kSecACLAuthorizationExportWrapped) || hasAuth(a,kSecACLAuthorizationAny);
}
static NSArray *releaseAuthorizations(CFArrayRef a) {
    NSMutableArray *result=[NSMutableArray array];
    if(hasAuth(a,kSecACLAuthorizationDecrypt))[result addObject:@"decrypt"];
    if(hasAuth(a,kSecACLAuthorizationExportClear))[result addObject:@"export_clear"];
    if(hasAuth(a,kSecACLAuthorizationExportWrapped))[result addObject:@"export_wrapped"];
    if(hasAuth(a,kSecACLAuthorizationAny))[result addObject:@"any"];
    return result;
}
static NSArray *writerAuthorizations(CFArrayRef a) {
    NSMutableArray *result=[NSMutableArray array];
    if(hasAuth(a,kSecACLAuthorizationKeychainItemModify))[result addObject:@"item_modify"];
    if(hasAuth(a,kSecACLAuthorizationKeychainItemDelete))[result addObject:@"item_delete"];
    if(hasAuth(a,kSecACLAuthorizationDelete))[result addObject:@"delete"];
    if(hasAuth(a,kSecACLAuthorizationChangeACL))[result addObject:@"change_acl"];
    if(hasAuth(a,kSecACLAuthorizationChangeOwner))[result addObject:@"change_owner"];
    if(hasAuth(a,kSecACLAuthorizationEncrypt))[result addObject:@"encrypt"];
    if(hasAuth(a,kSecACLAuthorizationAny))[result addObject:@"any"];
    return result;
}
static NSString *metadataOrderKey(id value) {
    NSData *data=[NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingSortedKeys error:NULL];
    return [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease];
}
static void sortACLMetadata(NSMutableArray *acls) {
    [acls sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSComparisonResult result=[[a[@"authorizations"] componentsJoinedByString:@"|"] compare:[b[@"authorizations"] componentsJoinedByString:@"|"] options:NSLiteralSearch];
        return result==NSOrderedSame ? [metadataOrderKey(a) compare:metadataOrderKey(b) options:NSLiteralSearch] : result;
    }];
}
static NSDictionary *accessMetadata(SecAccessRef access, NSDictionary *attrs, CFSetRef removed, OSStatus *status) {
    CFArrayRef acls = NULL;
    *status = SecAccessCopyACLList(access,&acls);
    if (*status) return nil;
    NSMutableArray *decrypt = [NSMutableArray array], *writers = [NSMutableArray array], *partitions = [NSMutableArray array];
    BOOL unknown = NO;
    NSUInteger partitionCount = 0;
    for (id raw in (NSArray *)acls) {
        SecACLRef acl = (SecACLRef)raw;
        // SecACLRemove leaves a deleted, unreadable object in this Access map.
        // Only preparation supplies exact pointers it successfully removed.
        if (removed && CFSetContainsValue(removed,acl)) continue;
        CFArrayRef auths = SecACLCopyAuthorizations(acl);
        if (!auths) { *status=errSecDecode; break; }
        NSArray *writerAuths=writerAuthorizations(auths);
        if (releasesPlaintext(auths) || writerAuths.count || hasAuth(auths,kSecACLAuthorizationPartitionID)) {
            CFArrayRef apps = NULL; CFStringRef desc = NULL; SecKeychainPromptSelector selector = 0;
            *status = SecACLCopyContents(acl,&apps,&desc,&selector);
            if (*status) {
                // Unsupported ACL subjects remain visible and cannot pass verify.
                NSDictionary *opaque=@{@"authorizations":writerAuths,@"any_application":@NO,@"applications":@[],@"contents_unverified":@YES};
                if(writerAuths.count)[writers addObject:opaque];
                if(releasesPlaintext(auths)) {
                    NSMutableDictionary *entry=[NSMutableDictionary dictionaryWithDictionary:opaque];
                    entry[@"authorizations"]=releaseAuthorizations(auths);[decrypt addObject:entry];
                }
                if(hasAuth(auths,kSecACLAuthorizationPartitionID))unknown=YES;
                if(apps)CFRelease(apps);if(desc)CFRelease(desc);
                CFRelease(auths);*status=0;continue;
            }
            if (releasesPlaintext(auths) || writerAuths.count) {
                NSMutableArray *list = [NSMutableArray array];
                for (id app in (NSArray *)apps) [list addObject:@{ @"path":appPath((SecTrustedApplicationRef)app), @"requirement":storedRequirement((SecTrustedApplicationRef)app) }];
                [list sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
                    NSComparisonResult result=[a[@"path"] compare:b[@"path"] options:NSLiteralSearch];
                    return result==NSOrderedSame ? [a[@"requirement"] compare:b[@"requirement"] options:NSLiteralSearch] : result;
                }];
                if(releasesPlaintext(auths))[decrypt addObject:@{ @"authorizations":releaseAuthorizations(auths), @"any_application":apps==NULL ? @YES : @NO, @"applications":list }];
                if(writerAuths.count)[writers addObject:@{@"authorizations":writerAuths,@"any_application":apps==NULL ? @YES : @NO,@"applications":list}];
            }
            if (hasAuth(auths,kSecACLAuthorizationPartitionID)) {
                partitionCount++;
                // The partition description is a hex-encoded XML property list.
                NSString *s = (NSString *)desc;
                NSMutableData *data = [NSMutableData data];
                if (!s || s.length%2) unknown=YES;
                for (NSUInteger j=0;j+1<s.length;j+=2) {
                    unsigned v=0; NSString *pair=[s substringWithRange:NSMakeRange(j,2)];
                    NSScanner *scanner=[NSScanner scannerWithString:pair];
                    if (![scanner scanHexInt:&v] || !scanner.isAtEnd) { unknown=YES; break; }
                    unsigned char byte=v; [data appendBytes:&byte length:1];
                }
                id plist=[NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:NULL];
                id p=[plist isKindOfClass:[NSDictionary class]] ? plist[@"Partitions"] : nil;
                if (![p isKindOfClass:[NSArray class]] || [p count]==0 || partitionCount>1) unknown=YES;
                else for (id value in p) { if ([value isKindOfClass:[NSString class]]) [partitions addObject:value]; else unknown=YES; }
            }
            if (apps) CFRelease(apps); if (desc) CFRelease(desc);
        }
        CFRelease(auths);
    }
    CFRelease(acls);
    if (*status) return nil;
    // Access enumerates ACLs by opaque handles, not creation order.
    sortACLMetadata(decrypt);sortACLMetadata(writers);
    [partitions sortUsingSelector:@selector(compare:)];
    return @{ @"service":attrs[(id)kSecAttrService] ?: @"", @"account":attrs[(id)kSecAttrAccount] ?: @"", @"label":attrs[(id)kSecAttrLabel] ?: @"", @"creator":attrs[(id)kSecAttrCreator] ?: @0, @"release_acls":decrypt, @"writer_acls":writers, @"partitions":partitions, @"partition_unknown":unknown ? @YES : @NO };
}
static NSDictionary *metadata(NSDictionary *attrs, OSStatus *status) {
    SecAccessRef access=NULL;
    *status=SecKeychainItemCopyAccess((SecKeychainItemRef)attrs[(id)kSecValueRef],&access);
    if(*status)return nil;
    NSDictionary *m=accessMetadata(access,attrs,NULL,status);
    CFRelease(access);return m;
}

static NSArray *query(SecKeychainRef kc, NSDictionary *before, OSStatus *status) {
    NSMutableDictionary *q=[NSMutableDictionary dictionaryWithDictionary:@{
        (id)kSecClass:(id)kSecClassGenericPassword,
        (id)kSecReturnAttributes:@YES, (id)kSecReturnRef:@YES,
        (id)kSecMatchLimit:(id)kSecMatchLimitAll,
        (id)kSecUseAuthenticationUI:(id)kSecUseAuthenticationUIFail }];
    if (kc) q[(id)kSecMatchSearchList]=@[(id)kc];
    if (before) { q[(id)kSecAttrService]=before[@"service"]; q[(id)kSecAttrAccount]=before[@"account"]; }
    CFTypeRef result=NULL;
    *status=SecItemCopyMatching((CFDictionaryRef)q,&result);
    if (*status==errSecItemNotFound) { *status=0; return @[]; }
    return result ? owned(result) : @[];
}

static OSStatus applyPlan(SecKeychainItemRef item, NSDictionary *plan, BOOL allowUI, BOOL prepareOnly, NSDictionary **prepared) {
    TS_TRACE("prepare-acl");
    SecAccessRef access=NULL; CFArrayRef acls=NULL;
    OSStatus s=SecKeychainItemCopyAccess(item,&access);
    if (s) return s;
    s=SecAccessCopyACLList(access,&acls);
    if (s) { CFRelease(access); return s; }
    CFMutableSetRef removed=CFSetCreateMutable(NULL,0,NULL);
    // Remove every plaintext authorization; wildcard any is removed entirely.
    // Preserve unrelated explicit authorizations on mixed entries.
    for (id raw in (NSArray *)acls) {
        SecACLRef acl=(SecACLRef)raw;
        CFArrayRef auths=SecACLCopyAuthorizations(acl);
        if (!auths) { s=errSecDecode; break; }
        if (hasAuth(auths,kSecACLAuthorizationAny)) { s=SecACLRemove(acl); if(!s)CFSetAddValue(removed,acl); CFRelease(auths); if(s)break; continue; }
        NSMutableArray *remaining=[NSMutableArray arrayWithArray:(NSArray *)auths];
        [remaining removeObject:(id)kSecACLAuthorizationDecrypt];
        [remaining removeObject:(id)kSecACLAuthorizationExportClear];
        [remaining removeObject:(id)kSecACLAuthorizationExportWrapped];
        [remaining removeObject:(id)kSecACLAuthorizationPartitionID];
        if (remaining.count!=CFArrayGetCount(auths)) {
            s=remaining.count ? SecACLUpdateAuthorizations(acl,(CFArrayRef)remaining) : SecACLRemove(acl);
            if(!s && !remaining.count)CFSetAddValue(removed,acl);
        }
        CFRelease(auths);
        if (s) break;
    }
    CFRelease(acls);
    TS_TRACE("create-release-entries");
    NSMutableArray *trusted=[NSMutableArray array];
    if (!s) for (NSDictionary *a in plan[@"after"][@"release_acls"][0][@"applications"]) {
        SecRequirementRef req=NULL; SecTrustedApplicationRef app=NULL;
        s=SecRequirementCreateWithString((CFStringRef)a[@"requirement"],0,&req);
        if (!s) s=createRequirement([a[@"path"] UTF8String],req,&app);
        if(req)CFRelease(req);
        if(s)break;
        [trusted addObject:(id)app]; CFRelease(app);
    }
    SecACLRef acl=NULL;
    if (!s) for(NSDictionary *entry in plan[@"after"][@"release_acls"]) {
        s=SecACLCreateWithSimpleContents(access,(CFArrayRef)trusted,CFSTR("mac-tool-secret owner"),0,&acl);
        if(s)break;
        NSMutableArray *auths=[NSMutableArray array];
        for(NSString *auth in entry[@"authorizations"]) {
            if([auth isEqual:@"decrypt"])[auths addObject:(id)kSecACLAuthorizationDecrypt];
            else if([auth isEqual:@"export_clear"])[auths addObject:(id)kSecACLAuthorizationExportClear];
            else if([auth isEqual:@"export_wrapped"])[auths addObject:(id)kSecACLAuthorizationExportWrapped];
            else {s=errSecParam;break;}
        }
        if(!s)s=SecACLUpdateAuthorizations(acl,(CFArrayRef)auths);
        CFRelease(acl);if(s)break;
    }
    TS_TRACE("create-partition-entry");
    NSData *plist=[NSPropertyListSerialization dataWithPropertyList:@{ @"Partitions":plan[@"after"][@"partitions"] } format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
    if (!s && !plist) s=errSecDecode;
    if (!s) s=SecACLCreateWithSimpleContents(access,(CFArrayRef)@[],(CFStringRef)hex(plist),0,&acl);
    if (!s) { s=SecACLUpdateAuthorizations(acl,(CFArrayRef)@[(id)kSecACLAuthorizationPartitionID]); CFRelease(acl); }
    if (!s && prepared) {
        TS_TRACE("round-trip-prepared-access");
        NSDictionary *before=plan[@"before"];
        NSDictionary *attrs=@{(id)kSecAttrService:before[@"service"],(id)kSecAttrAccount:before[@"account"],(id)kSecAttrLabel:before[@"label"],(id)kSecAttrCreator:before[@"creator"]};
        *prepared=accessMetadata(access,attrs,removed,&s);
        if (!s && ![*prepared isEqual:plan[@"after"]]) s=errSecDecode;
    }
    if (!s && !prepareOnly) {
        // The ONLY UI-enabled region. One call, no retry on cancellation/refusal.
        if (allowUI && (!isatty(3) || !isatty(4))) s=errSecInteractionNotAllowed;
        else {
            s=SecKeychainSetUserInteractionAllowed(allowUI);
            if (!s) { TS_TRACE("set-access"); s=SecKeychainItemSetAccess(item,access); TS_TRACE("set-access-returned"); }
            SecKeychainSetUserInteractionAllowed(false);
        }
    }
    CFRelease(removed); CFRelease(access); return s;
}

char *ts_metadata_call(const char *request) {
    @autoreleasepool {
        OSStatus s=SecKeychainSetUserInteractionAllowed(false);
        NSDictionary *r=[NSJSONSerialization JSONObjectWithData:[[NSString stringWithUTF8String:request] dataUsingEncoding:NSUTF8StringEncoding] options:0 error:NULL];
        NSDictionary *response=nil;
        copyRequirement=(CopyRequirement)dlsym(RTLD_DEFAULT,"SecTrustedApplicationCopyRequirement");
        createRequirement=(CreateRequirement)dlsym(RTLD_DEFAULT,"SecTrustedApplicationCreateFromRequirement");
        if (!copyRequirement || !createRequirement) response=failure(-4,@"required Security.framework SPI unavailable; no current-binary fallback");
        else if (s) response=failure(s,@"cannot disable keychain UI");
        else if ([r[@"operation"] isEqual:@"startup"]) response=@{ @"status":@0 };
        else if ([r[@"operation"] isEqual:@"owner"]) {
            NSDictionary *o=ownerInfo(r[@"path"],&s);
            response=s ? failure(s,@"cannot validate owner signature") : @{ @"status":@0, @"owner":o };
        } else {
            SecKeychainRef kc=NULL;
            NSString *path=r[@"keychain"];
            if (path.length) s=SecKeychainOpen(path.fileSystemRepresentation,&kc);
            if (s) response=failure(s,@"cannot open requested keychain");
            else {
                NSDictionary *plan=r[@"plan"];
                NSArray *found=query(kc,plan[@"before"],&s);
                NSMutableArray *items=[NSMutableArray array];
                NSDictionary *prepared=@{};
                if (!s) for (NSDictionary *attrs in found) {
                    NSDictionary *m=metadata(attrs,&s);
                    if (s) break;
                    [items addObject:m];
                }
                if (!s && ([r[@"operation"] isEqual:@"apply"] || [r[@"operation"] isEqual:@"prepare"])) {
                    if (found.count!=1 || ![items[0] isEqual:plan[@"before"]]) s=errSecDuplicateItem;
                    NSDictionary *owner=nil;
                    if (!s) owner=ownerInfo(plan[@"owner"][@"path"],&s);
                    if (!s && ![owner isEqual:plan[@"owner"]]) s=errSecCSReqFailed;
                    if (!s) for(NSDictionary *kept in plan[@"keep_owners"]) {
                        NSDictionary *current=ownerInfo(kept[@"path"],&s);
                        if(s || ![current isEqual:kept]) {s=errSecCSReqFailed;break;}
                    }
                    if (!s) s=applyPlan((SecKeychainItemRef)found[0][(id)kSecValueRef],plan,[r[@"allow_ui"] boolValue],[r[@"operation"] isEqual:@"prepare"],&prepared);
                }
                response=s ? failure(s,@"operation refused, metadata drifted, or authorization unavailable; no retry") : @{ @"status":@0, @"items":items, @"prepared":prepared };
            }
            if(kc)CFRelease(kc);
        }
        NSData *data=[NSJSONSerialization dataWithJSONObject:response options:NSJSONWritingSortedKeys error:NULL];
        return strdup([[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease].UTF8String);
    }
}
