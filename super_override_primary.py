#!/usr/bin/env python3
#This is a simple script that fails superblock writes

from bcc import BPF
import ctypes as ct

import os
from sys import argv

entry = argv[1]

rdev = os.stat(entry).st_rdev



# define BPF program
prog = r"""
#include <linux/sched.h>
#include <linux/bio.h>
#include <linux/blkdev.h>

struct data_t {
    u64 sector;
};
BPF_PERF_OUTPUT(events);


int fail(struct pt_regs *ctx, struct bio *bio, unsigned int nr_sectors) {

    //Check if correct disk
    struct gendisk *d = bio->bi_disk;
    struct disk_part_tbl *tbl = d->part_tbl;
    struct hd_struct **parts = (void *)tbl + sizeof(struct disk_part_tbl);
    struct hd_struct **partp = parts + bio->bi_partno;
    struct hd_struct *p = *partp;

    dev_t disk = p->__dev.devt;
    
    if(disk != MKDEV(MAJOR_PLACEHOLDER,MINOR_PLACEHOLDER)){
        return 0;
    }
    
    //3 default superblock locations
    if(bio->bi_iter.bi_sector==128){
        struct data_t data = {};
        data.sector = bio->bi_iter.bi_sector;
        events.perf_submit(ctx, &data, sizeof(data));
        bpf_override_return(ctx,-ENOMEM);
    }


    return 0;
}
"""
prog = prog.replace('MAJOR_PLACEHOLDER', str(os.major(rdev)))
prog = prog.replace('MINOR_PLACEHOLDER', str(os.minor(rdev)))


# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event="should_fail_bio", fn_name="fail")

## define output data structure in Python
class Data(ct.Structure):
    _fields_ = [("sector", ct.c_ulonglong)]

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print(event.sector);

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()
