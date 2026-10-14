//go:build darwin && cgo

package maccore

/*
#include <sys/acl.h>
#include <errno.h>

static int core_has_write_acl(int fd) {
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    // Darwin returns ENOENT for a valid descriptor with no extended ACL.
    if (acl == NULL) return errno == ENOENT ? 0 : -errno;
    const acl_permset_mask_t reads = ACL_READ_DATA | ACL_EXECUTE |
        ACL_READ_ATTRIBUTES | ACL_READ_EXTATTRIBUTES | ACL_READ_SECURITY |
        ACL_SYNCHRONIZE;
    int entry_id = ACL_FIRST_ENTRY;
    for (int count = 0; count < 1024; count++) {
        acl_entry_t entry;
        if (acl_get_entry(acl, entry_id, &entry) != 0) {
            int result = errno == EINVAL ? 0 : -errno;
            acl_free(acl);
            return result; // Darwin reports end-of-ACL as EINVAL.
        }
        entry_id = ACL_NEXT_ENTRY;
        acl_tag_t tag;
        acl_permset_mask_t permissions;
        if (acl_get_tag_type(entry, &tag) != 0 ||
            acl_get_permset_mask_np(entry, &permissions) != 0) {
            int saved_errno = errno;
            acl_free(acl);
            return -saved_errno;
        }
        if (tag != ACL_EXTENDED_ALLOW && tag != ACL_EXTENDED_DENY) {
            acl_free(acl);
            return -EINVAL;
        }
        // Denials/read-only grants cannot expand modification authority.
        // Conservatively reject every write grant, including inherit-only
        // entries or grants whose principal might currently resolve to root.
        if (tag == ACL_EXTENDED_ALLOW && (permissions & ~reads) != 0) {
            acl_free(acl);
            return 1;
        }
    }
    acl_free(acl);
    return -EOVERFLOW;
}
*/
import "C"

import "fmt"

func requireSafeACL(fd int) error {
	result := int(C.core_has_write_acl(C.int(fd)))
	if result < 0 {
		return fmt.Errorf("cannot inspect extended ACL: errno %d", -result)
	}
	if result != 0 {
		return fmt.Errorf("extended ACL grants modification authority")
	}
	return nil
}
