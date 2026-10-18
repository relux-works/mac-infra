//go:build darwin

package maccore

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func socketPeerUID(conn net.Conn) (int, error) {
	socket, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("peer is not a Unix socket")
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Xucred
	var inspectErr error
	if err := raw.Control(func(fd uintptr) {
		cred, inspectErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if inspectErr != nil {
		return 0, inspectErr
	}
	// XUCRED_VERSION is 0 in the macOS SDK (sys/ucred.h).
	if cred.Version != 0 {
		return 0, fmt.Errorf("unsupported peer credential version")
	}
	return int(cred.Uid), nil
}

func requireSocketPeer(conn net.Conn, uid int) error {
	peerUID, err := socketPeerUID(conn)
	if err != nil {
		return err
	}
	if peerUID != uid && peerUID != 0 {
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
