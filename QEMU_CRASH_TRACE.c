

 update_curr+0xdf/0x170
 kvm_vcpu_check_block+0x12/0x60 [kvm
 kvm_vcpu_block+0x191/0x2d0 [kvm
 ? prepare_to_wait_event+0xf0/0xf0
 kvm_arch_vcpu_ioctl_run+0x17e/0x3d0 [kvm
 kvm_vcpu_ioctl+0x2ab/0x640 [kvm
 ? perf_event_context_sched_in+0x87/0xa0
 do_vfs_ioctl+0x2dd/0x4c0
 ? __audit_syscall_entry+0xaf/0x100
 ? do_audit_syscall_entry+0x66/0x70
 SyS_ioctl+0x79/0x90
 entry_SYSCALL_64_fastpath+0x16/0x75

 cpuacct_charge+0x14/0x40


: [28981557.844963]  [<ffffffff810b1a9f>] update_curr+0xdf/0x170
: [28981557.861904]  [<ffffffffc069df72>] kvm_vcpu_check_block+0x12/0x60 [kvm]
: [28981557.880203]  [<ffffffffc069f121>] kvm_vcpu_block+0x191/0x2d0 [kvm]
: [28981557.898039]  [<ffffffff810bddc0>] ? prepare_to_wait_event+0xf0/0xf0
: [28981557.915984]  [<ffffffffc06bb9ee>] kvm_arch_vcpu_ioctl_run+0x17e/0x3d0 [kvm]
: [28981557.934625]  [<ffffffffc06a1f8b>] kvm_vcpu_ioctl+0x2ab/0x640 [kvm]
: [28981557.952472]  [<ffffffff81174517>] ? perf_event_context_sched_in+0x87/0xa0
: [28981557.970998]  [<ffffffff81210d6d>] do_vfs_ioctl+0x2dd/0x4c0
: [28981557.987877]  [<ffffffff8111fa1f>] ? __audit_syscall_entry+0xaf/0x100
: [28981558.005621]  [<ffffffff81003176>] ? do_audit_syscall_entry+0x66/0x70
: [28981558.023253]  [<ffffffff81210fc9>] SyS_ioctl+0x79/0x90
: [28981558.039342]  [<ffffffff817fa4f6>] entry_SYSCALL_64_fastpath+0x16/0x75
: [28981558.056999] Code: 9a 11 00 5b 48 c7 c0 f4 ff ff ff 5d eb df 66 0f 1f 84 00 00 00 00 00 0f 1f 44 00 00 55 48 8b 47 08 48 8b 97 78 07 00 00 48 89 e5 <48> 63 48 10 48 8b 52 60 48 8b 82 b8 00 00 00 48 03 04 cd c0 7a
: [28981558.100049] RIP  [<ffffffff810c3ff4>] cpuacct_charge+0x14/0x40



-------------------------------------------------------------------------------------------------------

[<ffffffff817fa4f6>] entry_SYSCALL_64_fastpath+0x16/0x75

./arch/x86/entry/entry_64.S:182

entry_SYSCALL_64_fastpath:
#if __SYSCALL_MASK == ~0
        cmpq    $__NR_syscall_max, %rax
#else
        andl    $__SYSCALL_MASK, %eax
        cmpl    $__NR_syscall_max, %eax
#endif
        ja      1f                              /* return -ENOSYS (already in pt_regs->ax) */
        movq    %r10, %rcx
#ifdef CONFIG_RETPOLINE
        movq    sys_call_table(, %rax, 8), %rax
        call    __x86_indirect_thunk_rax
#else
        call    *sys_call_table(, %rax, 8)
#endif

        movq    %rax, RAX(%rsp)

-------------------------------------------------------------------------------------------------------

[<ffffffff81210fc9>] SyS_ioctl+0x79/0x90

-------------------------------------------------------------------------------------------------------

[<ffffffff81003176>] ? do_audit_syscall_entry+0x66/0x70

./arch/x86/entry/common.c:50:static void do_audit_syscall_entry(struct pt_regs *regs, u32 arch)

static void do_audit_syscall_entry(struct pt_regs *regs, u32 arch)
{
#ifdef CONFIG_X86_64
        if (arch == AUDIT_ARCH_X86_64) {
                audit_syscall_entry(regs->orig_ax, regs->di,
                                    regs->si, regs->dx, regs->r10);
        } else
#endif
        {
                audit_syscall_entry(regs->orig_ax, regs->bx,
                                    regs->cx, regs->dx, regs->si);
        }
}

-------------------------------------------------------------------------------------------------------

[<ffffffff8111fa1f>] ? __audit_syscall_entry+0xaf/0x100

./kernel/auditsc.c:1490:void __audit_syscall_entry(int major, unsigned long a1, unsigned long a2,

/**
 * audit_syscall_entry - fill in an audit record at syscall entry
 * @major: major syscall type (function)
 * @a1: additional syscall register 1
 * @a2: additional syscall register 2
 * @a3: additional syscall register 3
 * @a4: additional syscall register 4
 *
 * Fill in audit context at syscall entry.  This only happens if the
 * audit context was created when the task was created and the state or
 * filters demand the audit context be built.  If the state from the
 * per-task filter or from the per-syscall filter is AUDIT_RECORD_CONTEXT,
 * then the record will be written at syscall exit time (otherwise, it
 * will only be written if another part of the kernel requests that it
 * be written).
 */
void __audit_syscall_entry(int major, unsigned long a1, unsigned long a2,
                           unsigned long a3, unsigned long a4)
{
        struct task_struct *tsk = current;
        struct audit_context *context = tsk->audit_context;
        enum audit_state     state;

        if (!context)
                return;

        BUG_ON(context->in_syscall || context->name_count);

        if (!audit_enabled)
                return;

        context->arch       = syscall_get_arch();
        context->major      = major;
        context->argv[0]    = a1;
        context->argv[1]    = a2;
        context->argv[2]    = a3;
        context->argv[3]    = a4;

        state = context->state;
        context->dummy = !audit_n_rules;
        if (!context->dummy && state == AUDIT_BUILD_CONTEXT) {
                context->prio = 0;
                state = audit_filter_syscall(tsk, context, &audit_filter_list[AUDIT_FILTER_ENTRY]);
        }
        if (state == AUDIT_DISABLED)
                return;

        context->serial     = 0;
        context->ctime      = CURRENT_TIME;
        context->in_syscall = 1;
        context->current_state  = state;
        context->ppid       = 0;
}
-------------------------------------------------------------------------------------------------------
[<ffffffff81210d6d>] do_vfs_ioctl+0x2dd/0x4c0

./fs/ioctl.c:555:int do_vfs_ioctl(struct file *filp, unsigned int fd, unsigned int cmd,

/*
 * When you add any new common ioctls to the switches above and below
 * please update compat_sys_ioctl() too.
 *
 * do_vfs_ioctl() is not for drivers and not intended to be EXPORT_SYMBOL()'d.
 * It's just a simple helper for sys_ioctl and compat_sys_ioctl.
 */
int do_vfs_ioctl(struct file *filp, unsigned int fd, unsigned int cmd,
             unsigned long arg)
{
        int error = 0;
        int __user *argp = (int __user *)arg;
        struct inode *inode = file_inode(filp);

        switch (cmd) {
        case FIOCLEX:
                set_close_on_exec(fd, 1);
                break;

        case FIONCLEX:
                set_close_on_exec(fd, 0);
                break;

        case FIONBIO:
                error = ioctl_fionbio(filp, argp);
                break;

        case FIOASYNC:
                error = ioctl_fioasync(fd, filp, argp);
                break;

        case FIOQSIZE:
                if (S_ISDIR(inode->i_mode) || S_ISREG(inode->i_mode) ||
                    S_ISLNK(inode->i_mode)) {
                        loff_t res = inode_get_bytes(inode);
                        error = copy_to_user(argp, &res, sizeof(res)) ?
                                        -EFAULT : 0;
                } else
                        error = -ENOTTY;
                break;

        case FIFREEZE:
                error = ioctl_fsfreeze(filp);
                break;

        case FITHAW:
                error = ioctl_fsthaw(filp);
                break;

        case FS_IOC_FIEMAP:
                return ioctl_fiemap(filp, arg);

        case FIGETBSZ:
                return put_user(inode->i_sb->s_blocksize, argp);

        default:
                if (S_ISREG(inode->i_mode))
                        error = file_ioctl(filp, cmd, arg);
                else
                        error = vfs_ioctl(filp, cmd, arg);
                break;
        }
        return error;
}
-------------------------------------------------------------------------------------------------------
 [<ffffffff81174517>] ? perf_event_context_sched_in+0x87/0xa0

./kernel/events/core.c:2839:static void perf_event_context_sched_in(struct perf_event_context *ctx,

static void perf_event_context_sched_in(struct perf_event_context *ctx,
                                        struct task_struct *task)
{
        struct perf_cpu_context *cpuctx;

        cpuctx = __get_cpu_context(ctx);
        if (cpuctx->task_ctx == ctx)
                return;

        perf_ctx_lock(cpuctx, ctx);
        perf_pmu_disable(ctx->pmu);
        /*
         * We want to keep the following priority order:
         * cpu pinned (that don't need to move), task pinned,
         * cpu flexible, task flexible.
         */
        cpu_ctx_sched_out(cpuctx, EVENT_FLEXIBLE);

        if (ctx->nr_events)
                cpuctx->task_ctx = ctx;

        perf_event_sched_in(cpuctx, cpuctx->task_ctx, task);

        perf_pmu_enable(ctx->pmu);
        perf_ctx_unlock(cpuctx, ctx);
}
-------------------------------------------------------------------------------------------------------
kvm_vcpu_ioctl+0x2ab/0x640 [kvm]

./virt/kvm/kvm_main.c:2341:static long kvm_vcpu_ioctl(struct file *filp,

static long kvm_vcpu_ioctl(struct file *filp,
                           unsigned int ioctl, unsigned long arg)
{
        struct kvm_vcpu *vcpu = filp->private_data;
        void __user *argp = (void __user *)arg;
        int r;
        struct kvm_fpu *fpu = NULL;
        struct kvm_sregs *kvm_sregs = NULL;

        if (vcpu->kvm->mm != current->mm)
                return -EIO;

        if (unlikely(_IOC_TYPE(ioctl) != KVMIO))
                return -EINVAL;

#if defined(CONFIG_S390) || defined(CONFIG_PPC) || defined(CONFIG_MIPS)
        /*
         * Special cases: vcpu ioctls that are asynchronous to vcpu execution,
         * so vcpu_load() would break it.
         */
        if (ioctl == KVM_S390_INTERRUPT || ioctl == KVM_S390_IRQ || ioctl == KVM_INTERRUPT)
                return kvm_arch_vcpu_ioctl(filp, ioctl, arg);
#endif


        r = vcpu_load(vcpu);
        if (r)
                return r;
        switch (ioctl) {
        case KVM_RUN:
                r = -EINVAL;
                if (arg)
                        goto out;
                if (unlikely(vcpu->pid != current->pids[PIDTYPE_PID].pid)) {
                        /* The thread running this VCPU changed. */
                        struct pid *oldpid = vcpu->pid;
                        struct pid *newpid = get_task_pid(current, PIDTYPE_PID);

                        rcu_assign_pointer(vcpu->pid, newpid);
                        if (oldpid)
                                synchronize_rcu();
                        put_pid(oldpid);
                }
                r = kvm_arch_vcpu_ioctl_run(vcpu, vcpu->run);
                trace_kvm_userspace_exit(vcpu->run->exit_reason, r);
                break;
        case KVM_GET_REGS: {
                struct kvm_regs *kvm_regs;

                r = -ENOMEM;
                kvm_regs = kzalloc(sizeof(struct kvm_regs), GFP_KERNEL);
                if (!kvm_regs)
                        goto out;
                r = kvm_arch_vcpu_ioctl_get_regs(vcpu, kvm_regs);
                if (r)
                        goto out_free1;
                r = -EFAULT;
                if (copy_to_user(argp, kvm_regs, sizeof(struct kvm_regs)))
                        goto out_free1;
                r = 0;
out_free1:
                kfree(kvm_regs);
                break;
        }
        case KVM_SET_REGS: {
                struct kvm_regs *kvm_regs;

                r = -ENOMEM;
                kvm_regs = memdup_user(argp, sizeof(*kvm_regs));
                if (IS_ERR(kvm_regs)) {
                        r = PTR_ERR(kvm_regs);
                        goto out;
                }
                r = kvm_arch_vcpu_ioctl_set_regs(vcpu, kvm_regs);
                kfree(kvm_regs);
                break;
        }
        case KVM_GET_SREGS: {
                kvm_sregs = kzalloc(sizeof(struct kvm_sregs), GFP_KERNEL);
                r = -ENOMEM;
                if (!kvm_sregs)
                        goto out;
                r = kvm_arch_vcpu_ioctl_get_sregs(vcpu, kvm_sregs);
                if (r)
                        goto out;
                r = -EFAULT;
                if (copy_to_user(argp, kvm_sregs, sizeof(struct kvm_sregs)))
                        goto out;
                r = 0;
                break;
        }
        case KVM_SET_SREGS: {
                kvm_sregs = memdup_user(argp, sizeof(*kvm_sregs));
                if (IS_ERR(kvm_sregs)) {
                        r = PTR_ERR(kvm_sregs);
                        kvm_sregs = NULL;
                        goto out;
                }
                r = kvm_arch_vcpu_ioctl_set_sregs(vcpu, kvm_sregs);
                break;
        }
        case KVM_GET_MP_STATE: {
                struct kvm_mp_state mp_state;

                r = kvm_arch_vcpu_ioctl_get_mpstate(vcpu, &mp_state);
                if (r)
                        goto out;
                r = -EFAULT;
                if (copy_to_user(argp, &mp_state, sizeof(mp_state)))
                        goto out;
                r = 0;
                break;
        }
        case KVM_SET_MP_STATE: {
                struct kvm_mp_state mp_state;

                r = -EFAULT;
                if (copy_from_user(&mp_state, argp, sizeof(mp_state)))
                        goto out;
                r = kvm_arch_vcpu_ioctl_set_mpstate(vcpu, &mp_state);
                break;
        }
        case KVM_TRANSLATE: {
                struct kvm_translation tr;

                r = -EFAULT;
                if (copy_from_user(&tr, argp, sizeof(tr)))
                        goto out;
                r = kvm_arch_vcpu_ioctl_translate(vcpu, &tr);
                if (r)
                        goto out;
                r = -EFAULT;
                if (copy_to_user(argp, &tr, sizeof(tr)))
                        goto out;
                r = 0;
                break;
        }
        case KVM_SET_GUEST_DEBUG: {
                struct kvm_guest_debug dbg;

                r = -EFAULT;
                if (copy_from_user(&dbg, argp, sizeof(dbg)))
                        goto out;
                r = kvm_arch_vcpu_ioctl_set_guest_debug(vcpu, &dbg);
                break;
        }
        case KVM_SET_SIGNAL_MASK: {
                struct kvm_signal_mask __user *sigmask_arg = argp;
                struct kvm_signal_mask kvm_sigmask;
                sigset_t sigset, *p;

                p = NULL;
                if (argp) {
                        r = -EFAULT;
                        if (copy_from_user(&kvm_sigmask, argp,
                                           sizeof(kvm_sigmask)))
                                goto out;
                        r = -EINVAL;
                        if (kvm_sigmask.len != sizeof(sigset))
                                goto out;
                        r = -EFAULT;
                        if (copy_from_user(&sigset, sigmask_arg->sigset,
                                           sizeof(sigset)))
                                goto out;
                        p = &sigset;
                }
                r = kvm_vcpu_ioctl_set_sigmask(vcpu, p);
                break;
        }
        case KVM_GET_FPU: {
                fpu = kzalloc(sizeof(struct kvm_fpu), GFP_KERNEL);
                r = -ENOMEM;
                if (!fpu)
                        goto out;
                r = kvm_arch_vcpu_ioctl_get_fpu(vcpu, fpu);
                if (r)
                        goto out;
                r = -EFAULT;
                if (copy_to_user(argp, fpu, sizeof(struct kvm_fpu)))
                        goto out;
                r = 0;
                break;
        }
        case KVM_SET_FPU: {
                fpu = memdup_user(argp, sizeof(*fpu));
                if (IS_ERR(fpu)) {
                        r = PTR_ERR(fpu);
                        fpu = NULL;
                        goto out;
                }
                r = kvm_arch_vcpu_ioctl_set_fpu(vcpu, fpu);
                break;
        }
        default:
                r = kvm_arch_vcpu_ioctl(filp, ioctl, arg);
        }
out:
        vcpu_put(vcpu);
        kfree(fpu);
        kfree(kvm_sregs);
        return r;
}
-------------------------------------------------------------------------------------------------------
kvm_arch_vcpu_ioctl_run+0x17e/0x3d0 [kvm]

./arch/x86/kvm/x86.c:6891:int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)

int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
        struct fpu *fpu = &current->thread.fpu;
        int r;
        sigset_t sigsaved;

        fpu__activate_curr(fpu);

        if (vcpu->sigset_active)
                sigprocmask(SIG_SETMASK, &vcpu->sigset, &sigsaved);

        if (unlikely(vcpu->arch.mp_state == KVM_MP_STATE_UNINITIALIZED)) {
                kvm_vcpu_block(vcpu);
                kvm_apic_accept_events(vcpu);
                clear_bit(KVM_REQ_UNHALT, &vcpu->requests);
                r = -EAGAIN;
                goto out;
        }

        /* re-sync apic's tpr */
        if (!lapic_in_kernel(vcpu)) {
                if (kvm_set_cr8(vcpu, kvm_run->cr8) != 0) {
                        r = -EINVAL;
                        goto out;
                }
        }

        if (unlikely(vcpu->arch.complete_userspace_io)) {
                int (*cui)(struct kvm_vcpu *) = vcpu->arch.complete_userspace_io;
                vcpu->arch.complete_userspace_io = NULL;
                r = cui(vcpu);
                if (r <= 0)
                        goto out;
        } else
                WARN_ON(vcpu->arch.pio.count || vcpu->mmio_needed);

        r = vcpu_run(vcpu);

out:
        post_kvm_run_save(vcpu);
        if (vcpu->sigset_active)
                sigprocmask(SIG_SETMASK, &sigsaved, NULL);

        return r;
}

-------------------------------------------------------------------------------------------------------
? prepare_to_wait_event+0xf0/0xf0

./kernel/sched/wait.c:199

long prepare_to_wait_event(wait_queue_head_t *q, wait_queue_t *wait, int state)
{
        unsigned long flags;

        if (signal_pending_state(state, current))
                return -ERESTARTSYS;

        wait->private = current;
        wait->func = autoremove_wake_function;

        spin_lock_irqsave(&q->lock, flags);
        if (list_empty(&wait->task_list)) {
                if (wait->flags & WQ_FLAG_EXCLUSIVE)
                        __add_wait_queue_tail(q, wait);
                else
                        __add_wait_queue(q, wait);
        }
        set_current_state(state);
        spin_unlock_irqrestore(&q->lock, flags);

        return 0;
}
EXPORT_SYMBOL(prepare_to_wait_event);

-------------------------------------------------------------------------------------------------------

kvm_vcpu_block+0x191/0x2d0 [kvm]

./virt/kvm/kvm_main.c:2008:void kvm_vcpu_block(struct kvm_vcpu *vcpu)

/*
 * The vCPU has executed a HLT instruction with in-kernel mode enabled.
 */
void kvm_vcpu_block(struct kvm_vcpu *vcpu)
{
        ktime_t start, cur;
        DEFINE_WAIT(wait);
        bool waited = false;
        u64 block_ns;

        start = cur = ktime_get();
        if (vcpu->halt_poll_ns) {
                ktime_t stop = ktime_add_ns(ktime_get(), vcpu->halt_poll_ns);

                ++vcpu->stat.halt_attempted_poll;
                do {
                        /*
                         * This sets KVM_REQ_UNHALT if an interrupt
                         * arrives.
                         */
                        if (kvm_vcpu_check_block(vcpu) < 0) {
                                ++vcpu->stat.halt_successful_poll;
                                goto out;
                        }
                        cur = ktime_get();
                } while (single_task_running() && ktime_before(cur, stop));
        }

        kvm_arch_vcpu_blocking(vcpu);

        for (;;) {
                prepare_to_wait(&vcpu->wq, &wait, TASK_INTERRUPTIBLE);

                if (kvm_vcpu_check_block(vcpu) < 0)
                        break;

                waited = true;
                schedule();
        }

        finish_wait(&vcpu->wq, &wait);
        cur = ktime_get();

        kvm_arch_vcpu_unblocking(vcpu);
out:
        block_ns = ktime_to_ns(cur) - ktime_to_ns(start);

        if (halt_poll_ns) {
                if (block_ns <= vcpu->halt_poll_ns)
                        ;
                /* we had a long block, shrink polling */
                else if (vcpu->halt_poll_ns && block_ns > halt_poll_ns)
                        shrink_halt_poll_ns(vcpu);
                /* we had a short halt and our poll time is too small */
                else if (vcpu->halt_poll_ns < halt_poll_ns &&
                        block_ns < halt_poll_ns)
                        grow_halt_poll_ns(vcpu);
        } else
                vcpu->halt_poll_ns = 0;
                
        trace_kvm_vcpu_wakeup(block_ns, waited);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_block);

-------------------------------------------------------------------------------------------------------

[<ffffffffc069df72>] kvm_vcpu_check_block+0x12/0x60 [kvm]

./virt/kvm/kvm_main.c:1991

static int kvm_vcpu_check_block(struct kvm_vcpu *vcpu)
{
        if (kvm_arch_vcpu_runnable(vcpu)) {
                kvm_make_request(KVM_REQ_UNHALT, vcpu);
                return -EINTR;
        }
        if (kvm_cpu_has_pending_timer(vcpu))
                return -EINTR;
        if (signal_pending(current))
                return -EINTR;

        return 0;
}
-------------------------------------------------------------------------------------------------------
 [<ffffffff810b1a9f>] update_curr+0xdf/0x170

./linux-lts-xenial-4.4.0/kernel/sched/fair.c:699:static void update_curr(struct cfs_rq *cfs_rq)

/*
 * Update the current task's runtime statistics.
 */
static void update_curr(struct cfs_rq *cfs_rq)
{
        struct sched_entity *curr = cfs_rq->curr;
        u64 now = rq_clock_task(rq_of(cfs_rq));
        u64 delta_exec;

        if (unlikely(!curr))
                return;

        delta_exec = now - curr->exec_start;
        if (unlikely((s64)delta_exec <= 0))
                return;

        curr->exec_start = now;

        schedstat_set(curr->statistics.exec_max,
                      max(delta_exec, curr->statistics.exec_max));

        curr->sum_exec_runtime += delta_exec;
        schedstat_add(cfs_rq, exec_clock, delta_exec);

        curr->vruntime += calc_delta_fair(delta_exec, curr);
        update_min_vruntime(cfs_rq);

        if (entity_is_task(curr)) {
                struct task_struct *curtask = task_of(curr);

                trace_sched_stat_runtime(curtask, delta_exec, curr->vruntime);
                cpuacct_charge(curtask, delta_exec);                    ==============>  cpuacct_charge
                account_group_exec_runtime(curtask, delta_exec);
        }

        account_cfs_rq_runtime(cfs_rq, delta_exec);
}

----------------------------------------------------------------------------------------------



: [28981557.844963]  [<ffffffff810b1a9f>] update_curr+0xdf/0x170
: [28981557.861904]  [<ffffffffc069df72>] kvm_vcpu_check_block+0x12/0x60 [kvm]
: [28981557.880203]  [<ffffffffc069f121>] kvm_vcpu_block+0x191/0x2d0 [kvm]
: [28981557.898039]  [<ffffffff810bddc0>] ? prepare_to_wait_event+0xf0/0xf0
: [28981557.915984]  [<ffffffffc06bb9ee>] kvm_arch_vcpu_ioctl_run+0x17e/0x3d0 [kvm]
: [28981557.934625]  [<ffffffffc06a1f8b>] kvm_vcpu_ioctl+0x2ab/0x640 [kvm]
: [28981557.952472]  [<ffffffff81174517>] ? perf_event_context_sched_in+0x87/0xa0
: [28981557.970998]  [<ffffffff81210d6d>] do_vfs_ioctl+0x2dd/0x4c0
: [28981557.987877]  [<ffffffff8111fa1f>] ? __audit_syscall_entry+0xaf/0x100
: [28981558.005621]  [<ffffffff81003176>] ? do_audit_syscall_entry+0x66/0x70
: [28981558.023253]  [<ffffffff81210fc9>] SyS_ioctl+0x79/0x90
: [28981558.039342]  [<ffffffff817fa4f6>] entry_SYSCALL_64_fastpath+0x16/0x75
: [28981558.056999] Code: 9a 11 00 5b 48 c7 c0 f4 ff ff ff 5d eb df 66 0f 1f 84 00 00 00 00 00 0f 1f 44 00 00 55 48 8b 47 08 48 8b 97 78 07 00 00 48 89 e5 <48> 63 48 10 48 8b 52 60 48 8b 82 b8 00 00 00 48 03 04 cd c0 7a
: [28981558.100049] RIP  [<ffffffff810c3ff4>] cpuacct_charge+0x14/0x40


./kvm-all.c:1805:        run_ret = kvm_vcpu_ioctl(cpu, KVM_RUN, 0);

./kvm-all.c:1944:int kvm_vcpu_ioctl(CPUState *cpu, int type, ...)
./kvm-all.c:1954:    trace_kvm_vcpu_ioctl(cpu->cpu_index, type, arg);
./kvm-all.c:2115:    dbg_data->err = kvm_vcpu_ioctl(dbg_data->cpu, KVM_SET_GUEST_DEBUG,
./kvm-all.c:2270:        return kvm_vcpu_ioctl(cpu, KVM_SET_SIGNAL_MASK, NULL);
./kvm-all.c:2277:    r = kvm_vcpu_ioctl(cpu, KVM_SET_SIGNAL_MASK, sigmask);
./kvm-all.c:2335:    r = kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
./kvm-all.c:2349:    r = kvm_vcpu_ioctl(cs, KVM_GET_ONE_REG, &reg);
./include/sysemu/kvm.h:238:int kvm_vcpu_ioctl(CPUState *cpu, int type, ...);
./include/sysemu/kvm.h:419:        kvm_vcpu_ioctl(cpu, KVM_ENABLE_CAP, &cap);                   \

./trace-events:1584:kvm_vcpu_ioctl(int cpu_index, int type, void *arg) "cpu_index %d, type 0x%x, arg %p"



----------------------------------------------------------------------------------------------
./include/qom/cpu.h
/**
 * qemu_init_vcpu:
 * @cpu: The vCPU to initialize.
 *
 * Initializes a vCPU.
 */
void qemu_init_vcpu(CPUState *cpu);



./cpus.c:1376:        qemu_kvm_start_vcpu(cpu);

void qemu_init_vcpu(CPUState *cpu)
{
    cpu->nr_cores = smp_cores;
    cpu->nr_threads = smp_threads;
    cpu->stopped = true;
    if (kvm_enabled()) {
        qemu_kvm_start_vcpu(cpu);
    } else if (tcg_enabled()) {
        qemu_tcg_init_vcpu(cpu);
    } else {
        qemu_dummy_start_vcpu(cpu);
    }
}


----------------------------------------------------------------------------------------------
./cpus.c:1347:    qemu_thread_create(cpu->thread, thread_name, qemu_kvm_cpu_thread_fn,

static void qemu_kvm_start_vcpu(CPUState *cpu)
{
    char thread_name[VCPU_THREAD_NAME_SIZE];

    cpu->thread = g_malloc0(sizeof(QemuThread));
    cpu->halt_cond = g_malloc0(sizeof(QemuCond));
    qemu_cond_init(cpu->halt_cond);
    snprintf(thread_name, VCPU_THREAD_NAME_SIZE, "CPU %d/KVM",
             cpu->cpu_index);
    qemu_thread_create(cpu->thread, thread_name, qemu_kvm_cpu_thread_fn,
                       cpu, QEMU_THREAD_JOINABLE);
    while (!cpu->created) {
        qemu_cond_wait(&qemu_cpu_cond, &qemu_global_mutex);
    }
}

----------------------------------------------------------------------------------------------
./cpus.c:1050:            r = kvm_cpu_exec(cpu);

static void *qemu_kvm_cpu_thread_fn(void *arg)
{
    CPUState *cpu = arg;
    int r;

    rcu_register_thread();

    qemu_mutex_lock_iothread();
    qemu_thread_get_self(cpu->thread);
    cpu->thread_id = qemu_get_thread_id();
    cpu->can_do_io = 1;
    current_cpu = cpu;

    r = kvm_init_vcpu(cpu);
    if (r < 0) {
        fprintf(stderr, "kvm_init_vcpu failed: %s\n", strerror(-r));
        exit(1);
    }

    qemu_kvm_init_cpu_signals(cpu);

    /* signal CPU creation */
    cpu->created = true;
    qemu_cond_signal(&qemu_cpu_cond);

    while (1) {
        if (cpu_can_run(cpu)) {
            r = kvm_cpu_exec(cpu);
            if (r == EXCP_DEBUG) {
                cpu_handle_guest_debug(cpu);
            }
        }
        qemu_kvm_wait_io_event(cpu);
    }

    return NULL;
}


----------------------------------------------------------------------------------------------

./kvm-all.c

int kvm_cpu_exec(CPUState *cpu)
{
    struct kvm_run *run = cpu->kvm_run;
    int ret, run_ret;

    DPRINTF("kvm_cpu_exec()\n");

    if (kvm_arch_process_async_events(cpu)) {
        cpu->exit_request = 0;
        return EXCP_HLT;
    }

    qemu_mutex_unlock_iothread();

    do {
        MemTxAttrs attrs;

        if (cpu->kvm_vcpu_dirty) {
            kvm_arch_put_registers(cpu, KVM_PUT_RUNTIME_STATE);
            cpu->kvm_vcpu_dirty = false;
        }

        kvm_arch_pre_run(cpu, run);
        if (cpu->exit_request) {
            DPRINTF("interrupt exit requested\n");
            /*
             * KVM requires us to reenter the kernel after IO exits to complete
             * instruction emulation. This self-signal will ensure that we
             * leave ASAP again.
             */
            qemu_cpu_kick_self();
        }

        run_ret = kvm_vcpu_ioctl(cpu, KVM_RUN, 0);       <-------------

        attrs = kvm_arch_post_run(cpu, run);

        if (run_ret < 0) {
            if (run_ret == -EINTR || run_ret == -EAGAIN) {
                DPRINTF("io window exit\n");
                ret = EXCP_INTERRUPT;
                break;
            }
            fprintf(stderr, "error: kvm run failed %s\n",
                    strerror(-run_ret));
#ifdef TARGET_PPC
            if (run_ret == -EBUSY) {
                fprintf(stderr,
                        "This is probably because your SMT is enabled.\n"
                        "VCPU can only run on primary threads with all "
                        "secondary threads offline.\n");
            }
#endif
            ret = -1;
            break;
        }

        trace_kvm_run_exit(cpu->cpu_index, run->exit_reason);
        switch (run->exit_reason) {
        case KVM_EXIT_IO:
            DPRINTF("handle_io\n");
            /* Called outside BQL */
            kvm_handle_io(run->io.port, attrs,
                          (uint8_t *)run + run->io.data_offset,
                          run->io.direction,
                          run->io.size,
                          run->io.count);
            ret = 0;
            break;
        case KVM_EXIT_MMIO:
            DPRINTF("handle_mmio\n");
            /* Called outside BQL */
            address_space_rw(&address_space_memory,
                             run->mmio.phys_addr, attrs,
                             run->mmio.data,
                             run->mmio.len,
                             run->mmio.is_write);
            ret = 0;
            break;
        case KVM_EXIT_IRQ_WINDOW_OPEN:
            DPRINTF("irq_window_open\n");
            ret = EXCP_INTERRUPT;
            break;
        case KVM_EXIT_SHUTDOWN:
            DPRINTF("shutdown\n");
            qemu_system_reset_request();
            ret = EXCP_INTERRUPT;
            break;
        case KVM_EXIT_UNKNOWN:
            fprintf(stderr, "KVM: unknown exit, hardware reason %" PRIx64 "\n",
                    (uint64_t)run->hw.hardware_exit_reason);
            ret = -1;
            break;
        case KVM_EXIT_INTERNAL_ERROR:
            ret = kvm_handle_internal_error(cpu, run);
            break;
        case KVM_EXIT_SYSTEM_EVENT:
            switch (run->system_event.type) {
            case KVM_SYSTEM_EVENT_SHUTDOWN:
                qemu_system_shutdown_request();
                ret = EXCP_INTERRUPT;
                break;
            case KVM_SYSTEM_EVENT_RESET:
                qemu_system_reset_request();
                ret = EXCP_INTERRUPT;
                break;
            case KVM_SYSTEM_EVENT_CRASH:
                qemu_mutex_lock_iothread();
                qemu_system_guest_panicked();
                qemu_mutex_unlock_iothread();
                ret = 0;
                break;
            default:
                DPRINTF("kvm_arch_handle_exit\n");
                ret = kvm_arch_handle_exit(cpu, run);
                break;
            }
            break;
        default:
            DPRINTF("kvm_arch_handle_exit\n");
            ret = kvm_arch_handle_exit(cpu, run);
            break;
        }
    } while (ret == 0);

    qemu_mutex_lock_iothread();

    if (ret < 0) {
        cpu_dump_state(cpu, stderr, fprintf, CPU_DUMP_CODE);
        vm_stop(RUN_STATE_INTERNAL_ERROR);
    }

    cpu->exit_request = 0;
    return ret;
}

OR


int kvm_set_signal_mask(CPUState *cpu, const sigset_t *sigset)
{
    KVMState *s = kvm_state;
    struct kvm_signal_mask *sigmask;
    int r;

    if (!sigset) {
        return kvm_vcpu_ioctl(cpu, KVM_SET_SIGNAL_MASK, NULL);
    }

    sigmask = g_malloc(sizeof(*sigmask) + sizeof(*sigset));

    sigmask->len = s->sigmask_len;
    memcpy(sigmask->sigset, sigset, sizeof(*sigset));
    r = kvm_vcpu_ioctl(cpu, KVM_SET_SIGNAL_MASK, sigmask);
    g_free(sigmask);

    return r;
}


----------------------------------------------------------------------------------------------

./kvm-all.c

int kvm_vcpu_ioctl(CPUState *cpu, int type, ...)
{
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    trace_kvm_vcpu_ioctl(cpu->cpu_index, type, arg);
    ret = ioctl(cpu->kvm_fd, type, arg);
    if (ret == -1) {
        ret = -errno;
    }
    return ret;
}

----------------------------------------------------------------------------------------------




