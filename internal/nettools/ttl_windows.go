//go:build windows

package nettools

import "syscall"

// setTTL positionne le TTL IP sortant sur le socket brut, utilisé par le
// traceroute pour forcer l'expiration à chaque saut.
func setTTL(rc syscall.RawConn, ttl int) error {
	var sockErr error
	ctrlErr := rc.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	return sockErr
}
