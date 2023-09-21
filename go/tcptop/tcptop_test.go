package main

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"testing"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS  bpf ../bpf/tcptop.c -- -I ../headers -D__TARGET_ARCH_x86

func TestTcpTop(t *testing.T) {

	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	opts := ebpf.CollectionOptions{}

	spec, err := btf.LoadSpec("vmlinux.h")
	if err != nil {
		panic(err)
	}

	opts.Programs = ebpf.ProgramOptions{
		KernelTypes: spec,
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &opts); err != nil {
		panic(err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("tcp_sendmsg", objs.KprobeTcpSendmsg, nil)
	if err != nil {
		panic(err)
	}
	defer kp.Close()

	kp2, err := link.Kprobe("tcp_cleanup_rbuf", objs.KprobeTcpCleanupRbuf, nil)
	if err != nil {
		panic(err)
	}
	defer kp2.Close()

	fmt.Printf("%6s %15s %15s\n", "PID", "RX_KB", "TX_KB")
	lastTime := time.Now()

	time.Sleep(2 * time.Second)

	var (
		value bpfPacketValueT
		key   uint32
	)

	for {
		timeSub := time.Now().Sub(lastTime).Seconds()
		lastTime = time.Now()

		for objs.PidPacket.Iterate().Next(&key, &value) {

			fmt.Printf("%6d %10.2f kB/s %10.2f kB/s\n", key, float64(value.Recv)/1024/timeSub, float64(value.Trans)/1024/timeSub)

			if err = objs.PidPacket.Delete(key); err != nil {
				fmt.Printf("WARN: Delete key error: %s\n", err)
				time.Sleep(1 * time.Second)
				continue
			}
		}
		time.Sleep(2 * time.Second)
	}
}
