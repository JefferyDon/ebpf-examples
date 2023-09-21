/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// +build ignore

#define ETH_P_IP 0x800
#define ETH_P_IPV6 0x86dd

#define PF_INET 2   /* IP protocol family.  */
#define PF_INET6 10 /* IP version 6.  */

#define MAX_STACK_TP 20
#define TASK_COMM_LEN 20
#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

#define PERF_MAX_STACK_DEPTH		32