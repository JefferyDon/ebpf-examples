#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

struct packet_value_t {
    u32 pid;
    size_t recv;
    size_t trans;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, u32);
  __type(value, struct packet_value_t);
} pid_packet SEC(".maps");


SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx){
  int pid = bpf_get_current_pid_tgid() >> 32;
  size_t trans_size = (size_t)PT_REGS_PARM3(ctx);
  struct packet_value_t *value;
  struct packet_value_t new_value = {  .pid = pid,
                                       .trans = 0,
                                       .recv = 0 };
  value = bpf_map_lookup_elem(&pid_packet, &pid);
  if (value){
    new_value.trans = value->trans + trans_size;
    new_value.recv = value->recv;
  } else {
    new_value.trans = trans_size;
  }

  bpf_map_update_elem(&pid_packet, &pid, &new_value, BPF_ANY);
  return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int kprobe_tcp_cleanup_rbuf(struct pt_regs *ctx)
{
  int pid = bpf_get_current_pid_tgid() >> 32;
  int recv_size = (int)PT_REGS_PARM2(ctx);

  struct packet_value_t *value;
  struct packet_value_t new_value = {  .pid = pid,
                                         .trans = 0,
                                         .recv = 0 };
  value = bpf_map_lookup_elem(&pid_packet, &pid);
  if (value){
    new_value.recv = value->recv + recv_size;
    new_value.trans = value->trans;
  } else {
    new_value.recv = recv_size;
  }

  bpf_map_update_elem(&pid_packet, &pid, &new_value, BPF_ANY);
  return 0;
}



char LICENSE[] SEC("license") = "Dual BSD/GPL";

