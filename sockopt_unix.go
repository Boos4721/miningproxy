//go:build !windows
// +build !windows

package main

import "syscall"

func setTCPSocketOptions(fd uintptr) error {
	// Unix/Linux平台实现
	i := int(fd)
	err1 := syscall.SetsockoptInt(i, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	err2 := syscall.SetsockoptInt(i, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*1024*1024)
	err3 := syscall.SetsockoptInt(i, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4*1024*1024)

	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return err3
}
