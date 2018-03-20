#!/usr/bin/python
#
# disksnoop.py	Trace block device I/O: basic version of iosnoop.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing latency.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 11-Aug-2015	Brendan Gregg	Created this.

from __future__ import print_function
from bcc import BPF
import os
from sys import argv
REQ_WRITE = 1		# from include/linux/blk_types.h


entry = argv[1]

rdev = os.stat(entry).st_rdev




# load BPF program
s = r"""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HASH(start, sector_t);

TRACEPOINT_PROBE(block, block_rq_issue) {
      
    u64 ts = bpf_ktime_get_ns();
    sector_t temp = args->sector;
    start.update(&temp, &ts);
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete) {
        
	u64 *tsp, delta;

        sector_t temp = args->sector;
	tsp = start.lookup(&temp);
	if (tsp != 0) {
		delta = bpf_ktime_get_ns() - *tsp;
		//bpf_trace_printk("%d %d\n", args->nr_sector, delta / 1000);
                dev_t d = args->dev;
                //bpf_trace_printk("%d %d\n", d, delta/1000);
                if ( d == MKDEV(MAJOR_PLACEHOLDER,MINOR_PLACEHOLDER)&& temp == 128 && args->nr_sector == 8){
		   bpf_trace_printk("%d %d\n", temp, args->nr_sector);
                }
                


		start.delete(&temp);
	}
        return 0;
}

"""

s = s.replace('MAJOR_PLACEHOLDER', str(os.major(rdev)))
s = s.replace('MINOR_PLACEHOLDER', str(os.minor(rdev)))

b = BPF(text=s)


# header
print("%-18s %-32s %-8s" % ("TIME(s)", "SECTOR", "NUMSECTORS"))

# format output
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    print(msg)
    continue
    (crap, sector, nr_sectors) = msg.split()

    if int(bflags_s, 16) & REQ_WRITE:
        type_s = "W"
    elif bytes_s == "0":    # see blk_fill_rwbs() for logic
        type_s = "M"
    else:
        type_s = "R"
    ms = float(int(us_s, 10)) / 1000

    print("%-18.9f %-32s %-4s" % (ts, bytes_s, ms))
