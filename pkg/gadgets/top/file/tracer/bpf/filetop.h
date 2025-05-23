/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FILETOP_H
#define __FILETOP_H

#define GADGET_PATH_MAX 512
#define TASK_COMM_LEN 16

enum op {
	READ,
	WRITE,
};

struct file_id {
	__u64 inode;
	__u32 dev;
	__u32 pid;
	__u32 tid;
};

struct file_stat {
	__u64 reads;
	__u64 read_bytes;
	__u64 writes;
	__u64 write_bytes;
	__u32 pid;
	__u32 tid;
	__u64 mntns_id;
	__u8 filename[GADGET_PATH_MAX];
	__u8 comm[TASK_COMM_LEN];
	char type_;
};

#endif /* __FILETOP_H */
