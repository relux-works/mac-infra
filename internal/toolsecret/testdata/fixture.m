// Opt-in test fixture only. All input is on stdin; all keychains are disposable.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
extern char *ts_metadata_call(const char *request);
#ifndef VARIANT
#define VARIANT "v1"
#endif

int main(void) {
    @autoreleasepool {
        NSData *input=[[NSFileHandle fileHandleWithStandardInput] readDataToEndOfFile];
        NSDictionary *r=[NSJSONSerialization JSONObjectWithData:input options:0 error:NULL];
        if (SecKeychainSetUserInteractionAllowed(false)) return 1;
        NSString *op=r[@"operation"], *path=r[@"keychain"], *password=r[@"password"];
        SecKeychainRef kc=NULL;
        OSStatus s=0;
        if ([op isEqual:@"create"]) {
            NSData *pw=[password dataUsingEncoding:NSUTF8StringEncoding];
            s=SecKeychainCreate(path.fileSystemRepresentation,(UInt32)pw.length,pw.bytes,false,NULL,&kc);
        } else {
            s=SecKeychainOpen(path.fileSystemRepresentation,&kc);
        }
        if (!s && ![op isEqual:@"delete"]) {
            NSData *pw=[password dataUsingEncoding:NSUTF8StringEncoding];
            s=SecKeychainUnlock(kc,(UInt32)pw.length,pw.bytes,true);
        }
        NSDictionary *out=nil;
        if (!s && [op isEqual:@"delete"]) s=SecKeychainDelete(kc);
        if (!s && [op isEqual:@"lock"]) s=SecKeychainLock(kc);
        if (!s && [op isEqual:@"add"]) {
            SecAccessRef access=NULL; SecTrustedApplicationRef app=NULL;
            NSString *trusted=r[@"trusted"];
            s=SecTrustedApplicationCreateFromPath(trusted.length ? trusted.fileSystemRepresentation : NULL,&app);
            if(!s) s=SecAccessCreate(CFSTR("toolsecret synthetic test"),(CFArrayRef)@[(id)app],&access);
            if(app)CFRelease(app);
            NSString *authorization=r[@"authorization"];
            if (!s && authorization.length) {
                CFArrayRef acls=NULL;s=SecAccessCopyACLList(access,&acls);
                if (!s) for (id raw in (NSArray *)acls) {
                    CFArrayRef auths=SecACLCopyAuthorizations((SecACLRef)raw);
                    BOOL decrypt=auths && CFArrayContainsValue(auths,CFRangeMake(0,CFArrayGetCount(auths)),kSecACLAuthorizationDecrypt);
                    if(auths)CFRelease(auths);
                    if (decrypt) {
                        NSDictionary *tags=@{@"export_clear":(id)kSecACLAuthorizationExportClear,@"export_wrapped":(id)kSecACLAuthorizationExportWrapped,@"any":(id)kSecACLAuthorizationAny,@"item_modify":(id)kSecACLAuthorizationKeychainItemModify,@"item_delete":(id)kSecACLAuthorizationKeychainItemDelete,@"delete":(id)kSecACLAuthorizationDelete,@"change_acl":(id)kSecACLAuthorizationChangeACL,@"change_owner":(id)kSecACLAuthorizationChangeOwner};
                        CFStringRef replacement=[authorization isEqual:@"encrypt"] ? kSecACLAuthorizationEncrypt : (CFStringRef)tags[authorization];
                        if(!replacement){s=errSecParam;break;}
                        s=SecACLUpdateAuthorizations((SecACLRef)raw,(CFArrayRef)@[(id)replacement]);
                        if(s)break;
                    }
                }
                if(acls)CFRelease(acls);
            }
            if(!s) {
                NSData *sv=[r[@"service"] dataUsingEncoding:NSUTF8StringEncoding];
                NSData *ac=[r[@"account"] dataUsingEncoding:NSUTF8StringEncoding];
                NSData *label=[@"toolsecret fixture" dataUsingEncoding:NSUTF8StringEncoding];
                SecKeychainAttribute a[]={{kSecServiceItemAttr,(UInt32)sv.length,(void *)sv.bytes},{kSecAccountItemAttr,(UInt32)ac.length,(void *)ac.bytes},{kSecLabelItemAttr,(UInt32)label.length,(void *)label.bytes}};
                SecKeychainAttributeList attrs={3,a};
                // Public synthetic bytes, never copied back out by a fixture.
                const char *synthetic="non-secret-fixture-" VARIANT;
                SecKeychainItemRef item=NULL;
                s=SecKeychainItemCreateFromContent(kSecGenericPasswordItemClass,&attrs,(UInt32)strlen(synthetic),synthetic,kc,access,&item);
                if(item)CFRelease(item);
            }
            if(access)CFRelease(access);
        }
        if (!s && [op isEqual:@"read"]) {
            NSDictionary *q=@{(id)kSecClass:(id)kSecClassGenericPassword,(id)kSecMatchSearchList:@[(id)kc],(id)kSecAttrService:r[@"service"],(id)kSecAttrAccount:r[@"account"],(id)kSecReturnData:@YES,(id)kSecUseAuthenticationUI:(id)kSecUseAuthenticationUIFail};
            CFTypeRef data=NULL;s=SecItemCopyMatching((CFDictionaryRef)q,&data);if(data)CFRelease(data);
        }
        if (!s && [op isEqual:@"native"]) {
            Boolean interactionAllowed=true;
            s=SecKeychainGetUserInteractionAllowed(&interactionAllowed);
            if(s || interactionAllowed) return 1;
            NSData *request=[NSJSONSerialization dataWithJSONObject:r[@"request"] options:0 error:NULL];
            char *response=ts_metadata_call([[[NSString alloc] initWithData:request encoding:NSUTF8StringEncoding] autorelease].UTF8String);
            out=[NSJSONSerialization JSONObjectWithData:[[NSString stringWithUTF8String:response] dataUsingEncoding:NSUTF8StringEncoding] options:0 error:NULL];
            free(response);
        }
        if(kc)CFRelease(kc);
        if(!out)out=@{@"status":@(s)};
        NSData *data=[NSJSONSerialization dataWithJSONObject:out options:0 error:NULL];
        [[NSFileHandle fileHandleWithStandardOutput] writeData:data];
        return 0;
    }
}
