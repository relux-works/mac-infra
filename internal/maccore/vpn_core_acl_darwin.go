//go:build darwin && cgo

package maccore

/*
#include <sys/acl.h>
#include <errno.h>
static int core_clear_acl(int fd) {
    acl_t acl = acl_init(0);
    if (acl == NULL) return errno;
    int result = acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED);
    int saved = result == 0 ? 0 : errno;
    acl_free(acl);
    return saved;
}
*/
import "C"

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

func secureVPNCoreFile(path string, dir bool, mode os.FileMode) error {
	return secureVPNCoreFileOwned(path, dir, mode, 0, 0)
}

// Tests inject their own uid/gid while exercising the native ACL and mode path.
func secureVPNCoreFileOwned(path string, dir bool, mode os.FileMode, uid, gid int) error {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	if dir {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	if err := file.Chown(uid, gid); err != nil {
		return err
	}
	if result := C.core_clear_acl(C.int(fd)); result != 0 {
		return fmt.Errorf("clear ACL: errno %d", result)
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	return checkTrustedFile(file, dir, uint32(uid))
}
