#!/usr/bin/env python3

from bcc import BPF
import ctypes as ct

# define BPF program
prog = r"""
#include <linux/mm.h>
BPF_HASH(flag);

int kprobe__btrfs_close_devices(void *ctx){
        u64 key = 1; 
        flag.update(&key, &key);
        return 0;
}


int kprobe__should_failslab(struct pt_regs *ctx) {
        u64 key = 1;
        u64 *res;

        res = flag.lookup(&key);
        if (res != 0) {
            bpf_override_return(ctx, -ENOMEM);        
        }
        return 0;
}
"""

# load BPF program
b = BPF(text=prog)

while 1:
    b.kprobe_poll()
