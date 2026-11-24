#import <Foundation/Foundation.h>
#import <Security/Security.h>

typedef OSStatus (*TSACLCopyContents)(SecACLRef,
                                     CFArrayRef *,
                                     CFStringRef *,
                                     SecKeychainPromptSelector *);

OSStatus ts_prepare_access(SecAccessRef access,
                           NSDictionary *plan,
                           NSDictionary **prepared);
OSStatus ts_prepare_access_with_copy_contents(SecAccessRef access,
                                              NSDictionary *plan,
                                              NSDictionary **prepared,
                                              TSACLCopyContents copyContents);
