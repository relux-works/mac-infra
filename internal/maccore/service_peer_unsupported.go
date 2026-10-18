//go:build !darwin

package maccore

import (
	"fmt"
	"net"
)

func requireSocketPeer(conn net.Conn, uid int) error {
	return fmt.Errorf("privileged socket peer checks require macOS")
}

func socketPeerPID(conn net.Conn) int {
	return 0
}

func socketPeerUID(conn net.Conn) (int, error) { return 0, fmt.Errorf("peer credentials unsupported") }
