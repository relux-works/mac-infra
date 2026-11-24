#import "../native_darwin.m"
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
        @"requirement":@"identifier \"works.relux.test\" and anchor apple generic and certificate leaf[subject.OU] = \"TESTTEAM\" and certificate leaf = H\"0123456789012345678901234567890123456789\"",
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

int main(int argc, char **argv) {
    @autoreleasepool {
        if(argc!=2)return 2;
        return runFixture([NSString stringWithUTF8String:argv[1]]);
    }
}
