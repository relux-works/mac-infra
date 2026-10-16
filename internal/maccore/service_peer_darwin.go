//go:build darwin

package maccore

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func requireSocketPeer(conn net.Conn, uid int) error {
	socket, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("peer is not a Unix socket")
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Xucred
	var inspectErr error
	if err := raw.Control(func(fd uintptr) {
		cred, inspectErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return err
	}
	if inspectErr != nil {
		return inspectErr
	}
	// XUCRED_VERSION is 0 in the macOS SDK (sys/ucred.h).
	if cred.Version != 0 || (cred.Uid != uint32(uid) && cred.Uid != 0) {
		return fmt.Errorf("Unix socket peer UID is not authorized")
	}
	return nil
}

// socketPeerPID is audit attribution only; authorization uses the UID check.
func socketPeerPID(conn net.Conn) int {
	socket, ok := conn.(*net.UnixConn)
	if !ok {
		return 0
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return 0
	}
	pid := 0
	_ = raw.Control(func(fd uintptr) {
		if value, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID); err == nil {
			pid = value
		}
	})
	return pid
}
