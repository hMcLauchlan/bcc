#!/usr/bin/env python3

from bcc import BPF


# define BPF program
prog = r"""
#include <linux/fs.h>

struct pid_struct {
    u64 curr_call; /* book keeping to handle recursion */
    u64 conds_met; /* stack pointer */
    u64 stack[2];
};
BPF_HASH(m, u32, struct pid_struct);
int d_alloc_parallel_entry(struct pt_regs *ctx, struct dentry *parent, const struct qstr *name,wait_queue_head_t *wq)
{
        u32 pid = bpf_get_current_pid_tgid();
        
        /*
         * Top level function init map
         */
        struct pid_struct p_struct = {0, 0};
        m.insert(&pid, &p_struct);
        

        struct pid_struct *p = m.lookup(&pid);

        if (!p)
                return 0;
        /*
         * Generate entry logic
         */
        
        
        if (p->conds_met >= 2)
                return 0;
        const unsigned char * n = name->name;
        if (p->conds_met == 0 && (*n == '1')){
                p->stack[0] = p->curr_call;
                p->conds_met++;
        }

        p->curr_call++;

        return 0;
}
int d_alloc_parallel_exit(struct pt_regs *ctx)
{
        u32 pid = bpf_get_current_pid_tgid();

        struct pid_struct *p = m.lookup(&pid);

        if (!p)
                return 0;

        p->curr_call--;

        /*
         * Generate exit logic
         */
        
        if (p->conds_met < 1 || p->conds_met >= 3)
                return 0;

        if (p->stack[p->conds_met - 1] == p->curr_call)
                p->conds_met--;
        
        
        /*
         * Top level function clean up map
         */
        m.delete(&pid);
        
        return 0;
}
int should_failslab_entry(struct pt_regs *ctx, struct kmem_cache *s, gfp_t gfpflags)
{
        /*
         * If this is the only call in the chain and predicate passes
         */
        if (2 == 1 && (true)) {
                bpf_override_return(ctx, -ENOMEM);
                return 0;
        }
        u32 pid = bpf_get_current_pid_tgid();

        struct pid_struct *p = m.lookup(&pid);

        if (!p)
                return 0;

        /*
         * If all conds have been met and predicate passes
         */
        if (p->conds_met == 1 && (true))
                bpf_override_return(ctx, -ENOMEM);
        return 0;
}



"""

# load BPF program
b = BPF(text=prog, debug =4)
b.attach_kprobe(event="should_failslab", fn_name="should_failslab_entry")
b.attach_kprobe(event="d_alloc_parallel", fn_name="d_alloc_parallel_entry")
b.attach_kretprobe(event="d_alloc_parallel", fn_name="d_alloc_parallel_exit")

while 1:
    b.kprobe_poll()
