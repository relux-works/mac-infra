//go:build darwin && cgo

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import "native_prepare.h"
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#ifdef TOOLSECRET_TEST_TRACE
#define TS_TRACE(s) fprintf(stderr,"toolsecret-test-phase:%s\n",s)
#define TS_TRACE_STATUS(s,v) fprintf(stderr,"toolsecret-test-status:%s:%d\n",s,(int)(v))
#define TS_TRACE_AUTHORIZATIONS(a) fprintf(stderr,"toolsecret-test-authorizations:%s\n",[[(NSArray *)(a) description] UTF8String])
#else
#define TS_TRACE(s) ((void)0)
#define TS_TRACE_STATUS(s,v) ((void)0)
#define TS_TRACE_AUTHORIZATIONS(a) ((void)0)
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
static BOOL isModeledAuthorization(id authorization) {
    return [@[(id)kSecACLAuthorizationAny,
              (id)kSecACLAuthorizationDelete,
              (id)kSecACLAuthorizationExportWrapped,
              (id)kSecACLAuthorizationExportClear,
              (id)kSecACLAuthorizationEncrypt,
              (id)kSecACLAuthorizationDecrypt,
              (id)kSecACLAuthorizationKeychainItemModify,
              (id)kSecACLAuthorizationKeychainItemDelete,
              (id)kSecACLAuthorizationChangeACL,
              (id)kSecACLAuthorizationChangeOwner,
              (id)kSecACLAuthorizationPartitionID] containsObject:authorization];
}
static NSArray *unmodeledAuthorizations(CFArrayRef authorizations) {
    NSMutableArray *result=[NSMutableArray array];
    for (id authorization in (NSArray *)authorizations) {
        if (isModeledAuthorization(authorization)) continue;
        if ([authorization isKindOfClass:[NSString class]]) [result addObject:authorization];
        else [result addObject:@"<non-string authorization>"];
    }
    [result sortUsingSelector:@selector(compare:)];
    return result;
}
static NSDictionary *aclMetadata(NSArray *authorizations,
                                 NSArray *unmodeled,
                                 BOOL anyApplication,
                                 NSArray *applications,
                                 BOOL contentsUnverified) {
    NSMutableDictionary *entry=[NSMutableDictionary dictionaryWithDictionary:@{
        @"authorizations":authorizations,
        @"any_application":@(anyApplication),
        @"applications":applications
    }];
    if(contentsUnverified)entry[@"contents_unverified"]=@YES;
    if(unmodeled.count)entry[@"unmodeled_authorizations"]=unmodeled;
    return entry;
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
        NSArray *unmodeled=unmodeledAuthorizations(auths);
        if (releasesPlaintext(auths) || writerAuths.count || unmodeled.count || hasAuth(auths,kSecACLAuthorizationPartitionID)) {
            CFArrayRef apps = NULL; CFStringRef desc = NULL; SecKeychainPromptSelector selector = 0;
            *status = SecACLCopyContents(acl,&apps,&desc,&selector);
            if (*status) {
                // Unsupported ACL subjects remain visible and cannot pass verify.
                NSDictionary *opaque=aclMetadata(writerAuths,unmodeled,NO,@[],YES);
                if(writerAuths.count || unmodeled.count)[writers addObject:opaque];
                if(releasesPlaintext(auths)) {
                    [decrypt addObject:aclMetadata(releaseAuthorizations(auths),unmodeled,NO,@[],YES)];
                }
                if(hasAuth(auths,kSecACLAuthorizationPartitionID))unknown=YES;
                if(apps)CFRelease(apps);if(desc)CFRelease(desc);
                CFRelease(auths);*status=0;continue;
            }
            if (releasesPlaintext(auths) || writerAuths.count || unmodeled.count) {
                NSMutableArray *list = [NSMutableArray array];
                for (id app in (NSArray *)apps) [list addObject:@{ @"path":appPath((SecTrustedApplicationRef)app), @"requirement":storedRequirement((SecTrustedApplicationRef)app) }];
                [list sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
                    NSComparisonResult result=[a[@"path"] compare:b[@"path"] options:NSLiteralSearch];
                    return result==NSOrderedSame ? [a[@"requirement"] compare:b[@"requirement"] options:NSLiteralSearch] : result;
                }];
                if(releasesPlaintext(auths))[decrypt addObject:aclMetadata(releaseAuthorizations(auths),unmodeled,apps==NULL,list,NO)];
                if(writerAuths.count || unmodeled.count)[writers addObject:aclMetadata(writerAuths,unmodeled,apps==NULL,list,NO)];
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

static OSStatus loadRequirementSPI(void) {
    if (!copyRequirement) copyRequirement=(CopyRequirement)dlsym(RTLD_DEFAULT,"SecTrustedApplicationCopyRequirement");
    if (!createRequirement) createRequirement=(CreateRequirement)dlsym(RTLD_DEFAULT,"SecTrustedApplicationCreateFromRequirement");
    return copyRequirement && createRequirement ? 0 : -4;
}

static NSArray *sortedApplications(NSArray *applications) {
    return [applications sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSComparisonResult result=[a[@"path"] compare:b[@"path"] options:NSLiteralSearch];
        return result==NSOrderedSame ? [a[@"requirement"] compare:b[@"requirement"] options:NSLiteralSearch] : result;
    }];
}

static NSArray *plannedEncryptApplications(NSDictionary *plan, NSUInteger targets, OSStatus *status) {
    if (!targets) return @[];
    NSDictionary *owner=plan[@"owner"];
    NSString *ownerPath=owner[@"path"], *ownerRequirement=owner[@"requirement"];
    if (![ownerPath isKindOfClass:[NSString class]] || ![ownerRequirement isKindOfClass:[NSString class]]) {
        *status=errSecDecode; return nil;
    }
    NSMutableArray *expected=[NSMutableArray arrayWithObject:@{@"path":ownerPath,@"requirement":ownerRequirement}];
    NSString *rollbackPath=@"/usr/bin/security";
    BOOL retainsRollback=[plan[@"owner_decision"] isEqual:@"decision:d576-rollback"] &&
        [plan[@"keep"] containsObject:rollbackPath];
    if (retainsRollback) {
        NSDictionary *rollbackOwner=nil;
        for (NSDictionary *candidate in plan[@"keep_owners"]) {
            if ([candidate[@"path"] isEqual:rollbackPath]) {
                if (rollbackOwner) { *status=errSecDecode; return nil; }
                rollbackOwner=candidate;
            }
        }
        NSString *requirement=rollbackOwner[@"requirement"];
        if (!rollbackOwner || ![requirement isKindOfClass:[NSString class]] || requirement.length==0) {
            *status=errSecDecode; return nil;
        }
        [expected addObject:@{@"path":rollbackPath,@"requirement":requirement}];
    }
    expected=(NSMutableArray *)sortedApplications(expected);
    NSUInteger planned=0;
    for (NSDictionary *entry in plan[@"after"][@"writer_acls"]) {
        NSArray *authorizations=entry[@"authorizations"];
        NSArray *applications=entry[@"applications"];
        if (authorizations.count==1 && [authorizations[0] isEqual:@"encrypt"] &&
            ![entry[@"any_application"] boolValue] && ![entry[@"contents_unverified"] boolValue] &&
            [entry[@"unmodeled_authorizations"] count]==0 && [applications isEqual:expected]) planned++;
    }
    if (planned<targets) { *status=errSecDecode; return nil; }
    return expected;
}

static OSStatus trustedApplications(NSArray *descriptions, NSMutableArray *applications) {
    for (NSDictionary *description in descriptions) {
        NSString *path=description[@"path"], *text=description[@"requirement"];
        if (![path isKindOfClass:[NSString class]] || ![text isKindOfClass:[NSString class]] || path.length==0 || text.length==0) return errSecDecode;
        SecRequirementRef requirement=NULL; SecTrustedApplicationRef application=NULL;
        OSStatus status=SecRequirementCreateWithString((CFStringRef)text,0,&requirement);
        if (!status) status=createRequirement([path UTF8String],requirement,&application);
        if (requirement) CFRelease(requirement);
        if (status) { if(application)CFRelease(application); return status; }
        [applications addObject:(id)application];
        CFRelease(application);
    }
    return 0;
}

static OSStatus preflightWriterACLs(SecAccessRef access,
                                    TSACLCopyContents copyContents,
                                    CFArrayRef *aclsOut,
                                    CFMutableSetRef *targetsOut) {
    CFArrayRef acls=NULL;
    OSStatus status=SecAccessCopyACLList(access,&acls);
    if (status) return status;
    CFMutableSetRef targets=CFSetCreateMutable(NULL,0,NULL);
    for (id raw in (NSArray *)acls) {
        SecACLRef acl=(SecACLRef)raw;
        CFArrayRef authorizations=SecACLCopyAuthorizations(acl);
        if (!authorizations) { status=errSecDecode; break; }
        NSArray *writers=writerAuthorizations(authorizations);
        NSArray *unmodeled=unmodeledAuthorizations(authorizations);
        BOOL hasEncrypt=hasAuth(authorizations,kSecACLAuthorizationEncrypt);
        BOOL relevant=releasesPlaintext(authorizations) || writers.count || unmodeled.count || hasAuth(authorizations,kSecACLAuthorizationPartitionID);
        TS_TRACE_AUTHORIZATIONS(authorizations);
        if (relevant && unmodeled.count) status=errSecDecode;
        if (!status && hasEncrypt && CFArrayGetCount(authorizations)!=1) status=errSecDecode;
        if (!status && relevant) {
            CFArrayRef applications=NULL; CFStringRef description=NULL; SecKeychainPromptSelector selector=0;
            status=copyContents(acl,&applications,&description,&selector);
            if (!status && hasEncrypt && applications==NULL && !description) status=errSecDecode;
            if (!status && hasEncrypt && applications==NULL) CFSetAddValue(targets,acl);
            if (applications) CFRelease(applications);
            if (description) CFRelease(description);
        }
        CFRelease(authorizations);
        if (status) break;
    }
    if (status) {
        CFRelease(targets); CFRelease(acls); return status;
    }
    *aclsOut=acls;
    *targetsOut=targets;
    return 0;
}

OSStatus ts_prepare_access_with_copy_contents(SecAccessRef access,
                                              NSDictionary *plan,
                                              NSDictionary **prepared,
                                              TSACLCopyContents copyContents) {
    if (!access || !plan || !copyContents) return errSecParam;
    OSStatus status=loadRequirementSPI();
    TS_TRACE_STATUS("load-requirement-spi",status);
    if (status) return status;
    NSDictionary *before=plan[@"before"];
    NSDictionary *after=plan[@"after"];
    if (![before isKindOfClass:[NSDictionary class]] || ![after isKindOfClass:[NSDictionary class]]) return errSecParam;
    NSDictionary *attrs=@{
        (id)kSecAttrService:before[@"service"] ?: @"",
        (id)kSecAttrAccount:before[@"account"] ?: @"",
        (id)kSecAttrLabel:before[@"label"] ?: @"",
        (id)kSecAttrCreator:before[@"creator"] ?: @0
    };
    status=0;
    NSDictionary *actualBefore=accessMetadata(access,attrs,NULL,&status);
    TS_TRACE_STATUS("read-before-metadata",status);
    if (status) return status;
    if (![actualBefore isEqual:before]) return errSecDecode;

    // Inspect every relevant raw authorization and contents list before the first
    // in-memory ACL edit. Unknown, mixed-encrypt, and opaque entries fail here.
    CFArrayRef acls=NULL; CFMutableSetRef encryptTargets=NULL;
    status=preflightWriterACLs(access,copyContents,&acls,&encryptTargets);
    TS_TRACE_STATUS("writer-preflight",status);
    if (status) return status;
    NSUInteger targetCount=CFSetGetCount(encryptTargets);
    NSArray *expectedEncryptApps=plannedEncryptApplications(plan,targetCount,&status);
    TS_TRACE_STATUS("plan-encrypt-applications",status);
    NSMutableArray *encryptApplications=[NSMutableArray array];
    if (!status && targetCount) status=trustedApplications(expectedEncryptApps,encryptApplications);
    TS_TRACE_STATUS("create-encrypt-applications",status);
    if (status) { CFRelease(encryptTargets); CFRelease(acls); return status; }

    // The only writer mutation is replacing the NULL application list on the
    // exact standalone encrypt ACL with the complete planned trusted list.
    for (id raw in (NSArray *)acls) {
        SecACLRef acl=(SecACLRef)raw;
        if (!CFSetContainsValue(encryptTargets,acl)) continue;
        CFArrayRef originalApplications=NULL; CFStringRef description=NULL; SecKeychainPromptSelector selector=0;
        status=copyContents(acl,&originalApplications,&description,&selector);
        if (!status && originalApplications!=NULL) status=errSecDecode;
        if (!status && !description) status=errSecDecode;
        if (!status) status=SecACLSetContents(acl,(CFArrayRef)encryptApplications,description,selector);
        TS_TRACE_STATUS("set-encrypt-contents",status);
        if (originalApplications) CFRelease(originalApplications);
        if (description) CFRelease(description);
        if (status) break;
    }
    CFRelease(encryptTargets);
    if (status) { CFRelease(acls); return status; }

    CFMutableSetRef removed=CFSetCreateMutable(NULL,0,NULL);
    // Remove every plaintext authorization; wildcard any is removed entirely.
    // Preserve unrelated explicit authorizations on mixed entries.
    for (id raw in (NSArray *)acls) {
        SecACLRef acl=(SecACLRef)raw;
        CFArrayRef authorizations=SecACLCopyAuthorizations(acl);
        if (!authorizations) { status=errSecDecode; break; }
        if (hasAuth(authorizations,kSecACLAuthorizationAny)) {
            status=SecACLRemove(acl);
            if(!status)CFSetAddValue(removed,acl);
            CFRelease(authorizations);
            if(status)break;
            continue;
        }
        NSMutableArray *remaining=[NSMutableArray arrayWithArray:(NSArray *)authorizations];
        [remaining removeObject:(id)kSecACLAuthorizationDecrypt];
        [remaining removeObject:(id)kSecACLAuthorizationExportClear];
        [remaining removeObject:(id)kSecACLAuthorizationExportWrapped];
        [remaining removeObject:(id)kSecACLAuthorizationPartitionID];
        if (remaining.count!=CFArrayGetCount(authorizations)) {
            status=remaining.count ? SecACLUpdateAuthorizations(acl,(CFArrayRef)remaining) : SecACLRemove(acl);
            if(!status && !remaining.count)CFSetAddValue(removed,acl);
        }
        CFRelease(authorizations);
        if (status) break;
    }
    CFRelease(acls);
    TS_TRACE("create-release-entries");
    NSMutableArray *releaseApplications=[NSMutableArray array];
    NSArray *releaseACLs=after[@"release_acls"];
    if (!status && releaseACLs.count==0) status=errSecDecode;
    if (!status) status=trustedApplications(releaseACLs[0][@"applications"],releaseApplications);
    SecACLRef acl=NULL;
    if (!status) for(NSDictionary *entry in releaseACLs) {
        status=SecACLCreateWithSimpleContents(access,(CFArrayRef)releaseApplications,CFSTR("mac-tool-secret owner"),0,&acl);
        if(status)break;
        NSMutableArray *authorizations=[NSMutableArray array];
        for(NSString *authorization in entry[@"authorizations"]) {
            if([authorization isEqual:@"decrypt"])[authorizations addObject:(id)kSecACLAuthorizationDecrypt];
            else if([authorization isEqual:@"export_clear"])[authorizations addObject:(id)kSecACLAuthorizationExportClear];
            else if([authorization isEqual:@"export_wrapped"])[authorizations addObject:(id)kSecACLAuthorizationExportWrapped];
            else {status=errSecParam;break;}
        }
        if(!status)status=SecACLUpdateAuthorizations(acl,(CFArrayRef)authorizations);
        CFRelease(acl);if(status)break;
    }
    TS_TRACE("create-partition-entry");
    NSData *plist=[NSPropertyListSerialization dataWithPropertyList:@{ @"Partitions":after[@"partitions"] } format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
    if (!status && !plist) status=errSecDecode;
    if (!status) status=SecACLCreateWithSimpleContents(access,(CFArrayRef)@[],(CFStringRef)hex(plist),0,&acl);
    if (!status) { status=SecACLUpdateAuthorizations(acl,(CFArrayRef)@[(id)kSecACLAuthorizationPartitionID]); CFRelease(acl); }
    if (!status && prepared) {
        TS_TRACE("round-trip-prepared-access");
        *prepared=accessMetadata(access,attrs,removed,&status);
        TS_TRACE_STATUS("round-trip-metadata",status);
        if (!status && ![*prepared isEqual:after]) status=errSecDecode;
        TS_TRACE_STATUS("round-trip-compare",status);
    }
    CFRelease(removed);
    return status;
}

OSStatus ts_prepare_access(SecAccessRef access, NSDictionary *plan, NSDictionary **prepared) {
    return ts_prepare_access_with_copy_contents(access,plan,prepared,SecACLCopyContents);
}

static OSStatus applyPlan(SecKeychainItemRef item, NSDictionary *plan, BOOL allowUI, BOOL prepareOnly, NSDictionary **prepared) {
    TS_TRACE("prepare-acl");
    SecAccessRef access=NULL;
    OSStatus s=SecKeychainItemCopyAccess(item,&access);
    if (s) return s;
    s=ts_prepare_access(access,plan,prepared);
    if (!s && !prepareOnly) {
        // The ONLY region that may call SecKeychainItemSetAccess, and only with UI
        // allowed. On macOS 26.5.1 SetAccess raises a SecurityAgent dialog even
        // after SecKeychainSetUserInteractionAllowed(false), and that dialog can
        // outlive this process and block securityd host-wide (incident
        // 2026-10-29 11:30Z). So without allowUI this layer refuses before the
        // call and never relies on the CLI gate alone.
        // fds 3 and 4 are the Go parent's own stdin and stdout, passed through
        // exec.Cmd.ExtraFiles (native.go) only when AllowUI is set. Both must be
        // terminals: the owner's attended session, never a pipe or a file.
        // One call, no retry on cancellation or refusal.
        if (!allowUI) s=errSecInteractionNotAllowed;
        else if (!isatty(3) || !isatty(4)) s=errSecInteractionNotAllowed;
        else {
            s=SecKeychainSetUserInteractionAllowed(true);
            if (!s) { TS_TRACE("set-access"); s=SecKeychainItemSetAccess(item,access); TS_TRACE("set-access-returned"); }
            SecKeychainSetUserInteractionAllowed(false);
        }
    }
    CFRelease(access); return s;
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
