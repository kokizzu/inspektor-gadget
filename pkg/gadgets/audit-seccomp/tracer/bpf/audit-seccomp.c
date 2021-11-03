// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 The Inspektor Gadget authors */

/* This BPF program uses the GPL-restricted function bpf_probe_read*().
 */

#include <vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "audit-seccomp.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("kprobe/audit_seccomp")
int kprobe__audit_seccomp(struct pt_regs *ctx)
{
	unsigned long syscall = PT_REGS_PARM1(ctx);
	int code = PT_REGS_PARM3(ctx);

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	if (mntns == 0) {
		return 0;
	}

	struct event_t event = {0,};
	event.mntns = mntns;
	event.pid = bpf_get_current_pid_tgid();
	event.syscall = syscall;
	event.code = code;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

char _license[] SEC("license") = "GPL";
