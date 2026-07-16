//go:build linux

package nettools

import "syscall"

// setTTL positionne le TTL IP sortant sur le socket brut
// traceroute pour forcer l'expiration à chaque saut.
func setTTL(rc syscall.RawConn, ttl int) error {
	var sockErr error
	ctrlErr := rc.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	return sockErr
}
