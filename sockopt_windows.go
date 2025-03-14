//go:build windows
// +build windows

package main

import "syscall"

func setTCPSocketOptions(fd uintptr) error {
	// Windows平台实现
	// 这里可以使用syscall.Handle类型，因为此文件只在Windows上编译
	h := syscall.Handle(fd)
	_ = syscall.SetsockoptInt(h, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	_ = syscall.SetsockoptInt(h, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*1024*1024)
	_ = syscall.SetsockoptInt(h, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4*1024*1024)
	return nil
}
