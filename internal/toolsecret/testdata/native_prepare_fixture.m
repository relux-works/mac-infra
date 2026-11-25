#import "../native_darwin.m"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static SecACLRef opaqueACL;

static OSStatus copyContentsWithOpaqueACL(SecACLRef acl,
                                          CFArrayRef *applications,
                                          CFStringRef *description,
                                          SecKeychainPromptSelector *selector) {
    if (acl==opaqueACL) return errSecDecode;
    return SecACLCopyContents(acl,applications,description,selector);
}

static SecAccessRef newAccess(void) {
    CFErrorRef error=NULL;
    SecAccessRef access=SecAccessCreateWithOwnerAndACL(getuid(),getgid(),kSecUseOnlyUID,(CFArrayRef)@[],&error);
    if(error)CFRelease(error);
    return access;
}

static OSStatus addEncryptACL(SecAccessRef access, NSString *mode, SecACLRef *created) {
    NSArray *authorizations=@[(id)kSecACLAuthorizationEncrypt];
    if([mode isEqual:@"mixed"]) authorizations=@[(id)kSecACLAuthorizationEncrypt,(id)kSecACLAuthorizationKeychainItemModify];
    if([mode isEqual:@"unsupported"]) authorizations=@[(id)kSecACLAuthorizationEncrypt,(id)kSecACLAuthorizationSign];
    OSStatus status=SecACLCreateWithSimpleContents(access,NULL,CFSTR("in-memory encrypt fixture"),0,created);
    if(!status)status=SecACLUpdateAuthorizations(*created,(CFArrayRef)authorizations);
    return status;
}

static NSDictionary *ownerDescription(void) {
    return @{
        @"path":@"/test/owner",
        @"requirement":@"identifier \"works.relux.test\" and anchor apple generic and certificate leaf[subject.OU] = TESTTEAM and certificate leaf = H\"0123456789012345678901234567890123456789\"",
        @"ad_hoc":@NO,
        @"hardened_runtime":@YES,
        @"entitlements":@[],
        @"partition":@"teamid:TESTTEAM"
    };
}

static NSDictionary *applicationDescription(NSDictionary *owner) {
    return @{@"path":owner[@"path"],@"requirement":owner[@"requirement"]};
}

static NSDictionary *fixtureAttributes(void) {
    return @{
        (id)kSecAttrService:@"works.relux.fixture",
        (id)kSecAttrAccount:@"native-prepare",
        (id)kSecAttrLabel:@"native preparation fixture",
        (id)kSecAttrCreator:@0
    };
}

static NSDictionary *makePlan(SecAccessRef access, NSString *mode, OSStatus *status) {
    NSDictionary *before=accessMetadata(access,fixtureAttributes(),NULL,status);
    if(*status)return nil;
    NSDictionary *owner=ownerDescription();
    NSDictionary *ownerApp=applicationDescription(owner);
    NSMutableArray *apps=[NSMutableArray arrayWithObject:ownerApp];
    NSArray *keep=@[];
    NSArray *keepOwners=@[];
    NSString *decision=@"";
    if([mode isEqual:@"owner-and-rollback"]) {
        NSDictionary *rollback=@{
            @"path":@"/usr/bin/security",
            @"requirement":@"identifier \"com.apple.security\" and anchor apple",
            @"ad_hoc":@NO,
            @"hardened_runtime":@YES,
            @"entitlements":@[],
            @"partition":@"teamid:TESTTEAM"
        };
        [apps addObject:applicationDescription(rollback)];
        keep=@[@"/usr/bin/security"];
        keepOwners=@[rollback];
        decision=@"decision:d576-rollback";
    }
    apps=(NSMutableArray *)sortedApplications(apps);
    NSArray *releaseAuthorizations=@[@"decrypt",@"export_clear",@"export_wrapped"];
    NSMutableArray *releaseACLs=[NSMutableArray array];
    for(NSString *authorization in releaseAuthorizations) {
        [releaseACLs addObject:@{@"authorizations":@[authorization],@"any_application":@NO,@"applications":apps}];
    }
    NSDictionary *writer=@{@"authorizations":@[ @"encrypt" ],@"any_application":@NO,@"applications":apps};
    if([mode isEqual:@"wrong-list"]) writer=@{@"authorizations":@[ @"encrypt" ],@"any_application":@NO,@"applications":@[applicationDescription(@{@"path":@"/test/other",@"requirement":owner[@"requirement"]})]};
    NSMutableArray *writers=[NSMutableArray array];
    for(NSDictionary *entry in before[@"writer_acls"]) {
        NSArray *authorizations=entry[@"authorizations"];
        BOOL targetEncrypt=authorizations.count==1 && [authorizations[0] isEqual:@"encrypt"] &&
            [entry[@"any_application"] boolValue] && [entry[@"applications"] count]==0 &&
            ![entry[@"contents_unverified"] boolValue] && [entry[@"unmodeled_authorizations"] count]==0;
        if(!targetEncrypt)[writers addObject:entry];
    }
    [writers addObject:writer];
    NSMutableDictionary *after=[NSMutableDictionary dictionaryWithDictionary:before];
    after[@"release_acls"]=releaseACLs;
    after[@"writer_acls"]=writers;
    after[@"partitions"]=@[@"teamid:TESTTEAM"];
    after[@"partition_unknown"]=@NO;
    return @{@"before":before,@"after":after,@"owner":owner,@"keep":keep,@"keep_owners":keepOwners,@"owner_decision":decision};
}

static int runFixture(NSString *mode) {
    SecAccessRef access=newAccess();
    if(!access)return 10;
    SecACLRef target=NULL;
    OSStatus status=addEncryptACL(access,mode,&target);
    if(status){if(target)CFRelease(target);CFRelease(access);return 11;}
    if([mode isEqual:@"opaque"]) opaqueACL=target;
    NSDictionary *plan=makePlan(access,mode,&status);
    if(status || !plan){if(target)CFRelease(target);CFRelease(access);return 12;}
    NSDictionary *before=accessMetadata(access,fixtureAttributes(),NULL,&status);
    if(status){if(target)CFRelease(target);CFRelease(access);return 13;}
    NSDictionary *prepared=nil;
    if([mode isEqual:@"opaque"]) {
        status=ts_prepare_access_with_copy_contents(access,plan,&prepared,copyContentsWithOpaqueACL);
    } else {
        status=ts_prepare_access(access,plan,&prepared);
    }
    OSStatus prepareStatus=status;
    if([@[@"mixed",@"unsupported",@"opaque",@"wrong-list"] containsObject:mode]) {
        NSDictionary *after=accessMetadata(access,fixtureAttributes(),NULL,&status);
        if(status || ![before isEqual:after]){if(target)CFRelease(target);CFRelease(access);return 20;}
        if(prepareStatus==0){if(target)CFRelease(target);CFRelease(access);return 21;}
        opaqueACL=NULL;
        if(target)CFRelease(target);
        CFRelease(access);
        return 0;
    }
    if(status || !prepared){
        NSData *debugJSON=prepared ? [NSJSONSerialization dataWithJSONObject:prepared options:NSJSONWritingSortedKeys error:NULL] : nil;
        NSString *debugText=debugJSON ? [[[NSString alloc] initWithData:debugJSON encoding:NSUTF8StringEncoding] autorelease] : @"<nil>";
        fprintf(stderr,"native preparation refused: status=%d prepared=%s\n",(int)status,debugText.UTF8String);
        if(target)CFRelease(target);CFRelease(access);return 30;
    }
    NSData *json=[NSJSONSerialization dataWithJSONObject:prepared options:NSJSONWritingSortedKeys error:NULL];
    if(!json){if(target)CFRelease(target);CFRelease(access);return 31;}
    fwrite(json.bytes,1,json.length,stdout);
    fputc('\n',stdout);
    opaqueACL=NULL;
    if(target)CFRelease(target);
    CFRelease(access);
    return 0;
}

static id reviewAuthorization(NSString *name) {
    NSDictionary *values=@{
        @"decrypt":(id)kSecACLAuthorizationDecrypt,
        @"export_clear":(id)kSecACLAuthorizationExportClear,
        @"export_wrapped":(id)kSecACLAuthorizationExportWrapped,
        @"derive":(id)kSecACLAuthorizationDerive,
        @"mac":(id)kSecACLAuthorizationMAC,
        @"sign":(id)kSecACLAuthorizationSign,
        @"item_modify":(id)kSecACLAuthorizationKeychainItemModify,
        @"encrypt":(id)kSecACLAuthorizationEncrypt,
        @"change_acl":(id)kSecACLAuthorizationChangeACL,
        @"integrity":(id)kSecACLAuthorizationIntegrity,
        @"any":(id)kSecACLAuthorizationAny,
        @"gen_key":(id)kSecACLAuthorizationGenKey
    };
    return values[name];
}

// Review probes create only in-memory ACL objects. They never call item APIs.
static int runPreflightContractProbe(NSString *authNames,
                                     NSString *applicationMode,
                                     NSUInteger aclCopies) {
    SecAccessRef access=newAccess();
    if(!access)return 50;
    NSMutableArray *authorizations=[NSMutableArray array];
    for(NSString *name in [authNames componentsSeparatedByString:@","]) {
        id authorization=reviewAuthorization(name);
        if(!authorization){CFRelease(access);return 51;}
        [authorizations addObject:authorization];
    }
    if(!authorizations.count || aclCopies==0 || aclCopies>2){CFRelease(access);return 52;}

    CFArrayRef applications=[applicationMode isEqual:@"empty"] ? (CFArrayRef)@[] : NULL;
    SecACLRef first=NULL, second=NULL;
    OSStatus status=0;
    for(NSUInteger i=0;i<aclCopies && !status;i++) {
        SecACLRef acl=NULL;
        status=SecACLCreateWithSimpleContents(access,applications,CFSTR("review in-memory ACL"),0,&acl);
        if(!status)status=SecACLUpdateAuthorizations(acl,(CFArrayRef)authorizations);
        if(status){if(acl)CFRelease(acl);break;}
        if(i==0)first=acl;else second=acl;
    }
    if(status){if(first)CFRelease(first);if(second)CFRelease(second);CFRelease(access);return 53;}
    BOOL opaque=[applicationMode isEqual:@"opaque"];
    if(opaque)opaqueACL=first;

    OSStatus metadataStatus=0;
    NSDictionary *before=accessMetadata(access,fixtureAttributes(),NULL,&metadataStatus);
    if(metadataStatus){opaqueACL=NULL;if(first)CFRelease(first);if(second)CFRelease(second);CFRelease(access);return 54;}

    CFArrayRef acls=NULL;
    CFMutableSetRef targets=NULL;
    status=preflightWriterACLs(access,opaque ? copyContentsWithOpaqueACL : SecACLCopyContents,&acls,&targets);
    long targetCount=targets ? (long)CFSetGetCount(targets) : -1L;
    if(targets)CFRelease(targets);
    if(acls)CFRelease(acls);

    NSDictionary *after=accessMetadata(access,fixtureAttributes(),NULL,&metadataStatus);
    BOOL unchanged=!metadataStatus && [before isEqual:after];
    printf("{\"status\":%d,\"targets\":%ld,\"unchanged\":%s}\n",
           (int)status,targetCount,unchanged ? "true" : "false");
    opaqueACL=NULL;
    if(first)CFRelease(first);
    if(second)CFRelease(second);
    CFRelease(access);
    return 0;
}

static OSStatus addReviewACL(SecAccessRef access,
                             NSArray *authorizationNames,
                             NSArray *applicationDescriptions,
                             BOOL anyApplication,
                             NSString *descriptionText) {
    NSMutableArray *applications=[NSMutableArray array];
    OSStatus status=0;
    TS_TRACE("fixture-review-build-trusted-applications");
    if(!anyApplication)status=trustedApplications(applicationDescriptions,applications);
    TS_TRACE_STATUS("fixture-review-trusted-applications",status);
    SecACLRef acl=NULL;
    TS_TRACE("fixture-review-create-acl");
    if(!status)status=SecACLCreateWithSimpleContents(access,
        anyApplication ? NULL : (CFArrayRef)applications,
        (CFStringRef)descriptionText,0,&acl);
    TS_TRACE_STATUS("fixture-review-create-acl",status);
    NSMutableArray *authorizations=[NSMutableArray array];
    for(NSString *name in authorizationNames) {
        id authorization=reviewAuthorization(name);
        if(!authorization){status=errSecDecode;break;}
        [authorizations addObject:authorization];
    }
    TS_TRACE_STATUS("fixture-review-map-authorizations",status);
    TS_TRACE("fixture-review-update-authorizations");
    if(!status)status=SecACLUpdateAuthorizations(acl,(CFArrayRef)authorizations);
    TS_TRACE_STATUS("fixture-review-update-authorizations",status);
    if(acl)CFRelease(acl);
    return status;
}

static OSStatus addInventoryOverlapAccess(SecAccessRef access, NSDictionary *plan) {
    TS_TRACE("fixture-overlap-plan-read");
    NSDictionary *before=plan[@"before"];
    NSArray *releaseACLs=before[@"release_acls"];
    NSArray *writerACLs=before[@"writer_acls"];
    if(![releaseACLs isKindOfClass:[NSArray class]] || releaseACLs.count!=1 ||
       ![writerACLs isKindOfClass:[NSArray class]])return errSecDecode;
    TS_TRACE("fixture-overlap-scan-writers");
    NSDictionary *release=releaseACLs[0];
    NSDictionary *keyUse=nil;
    for(NSDictionary *writer in writerACLs) {
        NSArray *names=writer[@"authorizations"];
        BOOL secretUsing=names.count>0;
        for(NSString *name in names)if(![@[@"derive",@"mac",@"sign"] containsObject:name])secretUsing=NO;
        if(secretUsing) {
            if(keyUse)return errSecDecode;
            keyUse=writer;
        }
    }
    if(!keyUse || ![release[@"authorizations"] isKindOfClass:[NSArray class]] ||
       ![release[@"applications"] isEqual:keyUse[@"applications"]] ||
       ![release[@"any_application"] isEqual:keyUse[@"any_application"]])return errSecDecode;
    TS_TRACE("fixture-overlap-merge-authorizations");

    NSMutableArray *combined=[NSMutableArray arrayWithArray:release[@"authorizations"]];
    [combined addObjectsFromArray:keyUse[@"authorizations"]];
    TS_TRACE("fixture-overlap-create-raw-acl");
    OSStatus status=addReviewACL(access,combined,release[@"applications"],
                                 [release[@"any_application"] boolValue],
                                 @"review combined release and key-use ACL");
    TS_TRACE_STATUS("fixture-add-overlap-acl",status);
    if(status)return status;
    for(NSDictionary *writer in writerACLs) {
        if(writer==keyUse)continue;
        status=addReviewACL(access,writer[@"authorizations"],writer[@"applications"],
                            [writer[@"any_application"] boolValue],
                            @"review writer ACL");
        TS_TRACE_STATUS("fixture-add-writer-acl",status);
        if(status)return status;
    }
    return 0;
}

static int runInventoryOverlapRoundTrip(void) {
    NSData *input=[[NSFileHandle fileHandleWithStandardInput] readDataToEndOfFile];
    NSDictionary *plan=[NSJSONSerialization JSONObjectWithData:input options:0 error:NULL];
    if(![plan isKindOfClass:[NSDictionary class]])return 60;
    SecAccessRef access=newAccess();
    if(!access)return 61;
    OSStatus status=loadRequirementSPI();
    TS_TRACE_STATUS("fixture-load-requirement-spi",status);
    if(status){CFRelease(access);return 64;}
    TS_TRACE("fixture-build-inventory-overlap-access");
    status=addInventoryOverlapAccess(access,plan);
    TS_TRACE_STATUS("fixture-build-inventory-overlap-access",status);
    if(status){CFRelease(access);return 62;}
    NSDictionary *before=plan[@"before"];
    NSDictionary *attrs=@{
        (id)kSecAttrService:before[@"service"] ?: @"",
        (id)kSecAttrAccount:before[@"account"] ?: @"",
        (id)kSecAttrLabel:before[@"label"] ?: @"",
        (id)kSecAttrCreator:before[@"creator"] ?: @0
    };
    OSStatus metadataStatus=0;
    NSDictionary *actualBefore=accessMetadata(access,attrs,NULL,&metadataStatus);
    if(metadataStatus || ![actualBefore isEqual:before]) {
        NSData *actualJSON=[NSJSONSerialization dataWithJSONObject:actualBefore ?: @{} options:NSJSONWritingSortedKeys error:NULL];
        NSData *planJSON=[NSJSONSerialization dataWithJSONObject:before options:NSJSONWritingSortedKeys error:NULL];
        fprintf(stderr,"fixture-before-mismatch status=%d actual=%s expected=%s\n",(int)metadataStatus,
                actualJSON ? [[[NSString alloc] initWithData:actualJSON encoding:NSUTF8StringEncoding] autorelease].UTF8String : "<unavailable>",
                planJSON ? [[[NSString alloc] initWithData:planJSON encoding:NSUTF8StringEncoding] autorelease].UTF8String : "<unavailable>");
    }
    NSDictionary *prepared=nil;
    TS_TRACE("fixture-prepare-inventory-overlap-access");
    status=ts_prepare_access(access,plan,&prepared);
    TS_TRACE_STATUS("fixture-prepare-inventory-overlap-access",status);
    NSData *json=[NSJSONSerialization dataWithJSONObject:@{@"status":@(status),@"prepared":prepared ?: [NSNull null]}
                                                options:NSJSONWritingSortedKeys error:NULL];
    if(!json){CFRelease(access);return 63;}
    fwrite(json.bytes,1,json.length,stdout);
    fputc('\n',stdout);
    CFRelease(access);
    return 0;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if(argc==5 && strcmp(argv[1],"contract")==0) {
            char *end=NULL;
            unsigned long copies=strtoul(argv[4],&end,10);
            if(!end || *end || copies==0 || copies>2)return 2;
            return runPreflightContractProbe([NSString stringWithUTF8String:argv[2]],
                                             [NSString stringWithUTF8String:argv[3]],
                                             (NSUInteger)copies);
        }
        if(argc==2 && strcmp(argv[1],"inventory-overlap-roundtrip")==0)
            return runInventoryOverlapRoundTrip();
        if(argc!=2)return 2;
        return runFixture([NSString stringWithUTF8String:argv[1]]);
    }
}
