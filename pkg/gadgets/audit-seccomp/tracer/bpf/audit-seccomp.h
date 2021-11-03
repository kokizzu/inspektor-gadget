#ifndef GADGET_AUDIT_SECCOMP_H
#define GADGET_AUDIT_SECCOMP_H

#include "../../../../vmlinux/vmlinux-cgo.h"
// #ifndef __VMLINUX_H__
// typedef long long unsigned int __u64;
// #endif

struct event_t {
	__u64 mntns;
	__u64 pid;
	__u64 syscall;
	int code;
};

#endif
