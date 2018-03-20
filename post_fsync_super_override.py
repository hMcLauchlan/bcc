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

struct debug_output {
    u64 code;
};

//lightweight version of the real thing
struct btrfs_trans_handle {
    u64 transid;
};

//for output
BPF_PERF_OUTPUT(events);

//for communicating across kernel calls.
//seperated for clarity
BPF_HASH(fs);
BPF_HASH(trans);

//store pid for identifying fsync transaction commits
int logfsync(struct pt_regs *ctx, struct file *file) {
    u64 val = 1;
    u64 pid = bpf_get_current_pid_tgid();
    fs.update(&pid,&val);   

    return 0;
}

//log the transid if this is a fsync transaction 

int log_trans_start(struct pt_regs *ctx){
    u64 temp =1; 
    //struct btrfs_trans_handle * handle = (struct btrfs_trans_handle *)PT_REGS_RC(ctx);
    struct btrfs_trans_handle tmp;
    u64 ptr = PT_REGS_RC(ctx);

    bpf_probe_read(&tmp, sizeof(tmp), (void*)ptr);
    u64 pid = bpf_get_current_pid_tgid();
    
    u64 *res = fs.lookup(&pid);

    if ( res!= 0){
        u64 id = tmp.transid;
        trans.update(&id,&temp);

        //debug output
        struct debug_output data = {};
        data.code=id;
        events.perf_submit(ctx, &data, sizeof(data));

        fs.delete(&pid);
    }
    return 0;
}

//effectively fail future superblock writes if a fsync trans is committed
int trans_commit(struct pt_regs *ctx, struct btrfs_trans_handle *cur){

    u64 id = cur->transid;

    u64* res = trans.lookup(&id);
    
    //completely arbitrary 
    u64 fail = 10001;

    if( res!=0){

        struct debug_output data = {};
        data.code = fail;
        events.perf_submit(ctx, &data, sizeof(data));

        u64 tempkey = 1;
        trans.update(&tempkey,&id);

        //at this point we can fail future superblock writes => fsync is done
    }

    return 0;
}

//because we can only fail superblock stuff after this commit returns
int trans_commit_return(struct pt_regs *ctx){
   u64 tempkey = 1;
   u64* res = trans.lookup(&tempkey);
   if(res!=0){
        u64 letFail = 2;
        trans.update(&letFail,&letFail);
        trans.delete(&tempkey);
   }
   return 0; 
}

//fails superblock writes
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

    //have we fsync'd?
    u64 key = 2;
    u64 * res = trans.lookup(&key);

    if(bio->bi_iter.bi_sector==128 && res!=0){
        struct debug_output data = {};
        u64 test=4;
        data.code = test;
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
b.attach_kprobe(event="should_fail_bio", fn_name="fail");
b.attach_kprobe(event="btrfs_sync_file", fn_name="logfsync");
b.attach_kprobe(event="btrfs_commit_transaction", fn_name="trans_commit");
b.attach_kretprobe(event="btrfs_commit_transaction", fn_name="trans_commit_return");
b.attach_kretprobe(event="btrfs_start_transaction", fn_name="log_trans_start");

## define output data structure in Python
class Output(ct.Structure):
    _fields_ = [("code", ct.c_ulonglong)]

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Output)).contents
    print(event.code);

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()
