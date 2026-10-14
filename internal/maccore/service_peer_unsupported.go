//go:build !darwin

package maccore

import (
	"fmt"
	"net"
)

func requireSocketPeer(conn net.Conn, uid int) error {
	return fmt.Errorf("privileged socket peer checks require macOS")
}
