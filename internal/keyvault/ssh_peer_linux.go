//go:build linux

package keyvault

import (
	"golang.org/x/sys/unix"
	"net"
)

func sshPeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var credentialErr error
	err = raw.Control(func(fd uintptr) {
		credential, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			credentialErr = err
			return
		}
		uid = credential.Uid
	})
	if err != nil {
		return 0, err
	}
	if credentialErr != nil {
		return 0, credentialErr
	}
	return uid, nil
}
