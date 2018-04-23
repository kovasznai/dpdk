
##############################################################################################################################################





2018-03-20T17:37:38.305265+00:00 compute-0-1 kernel: [1625342.861076] INFO: task kworker/u96:0:30946 blocked for more than 120 seconds.
2018-03-20T17:37:38.305278+00:00 compute-0-1 kernel: [1625342.861079]       Not tainted 4.4.0-91-generic #114~14.04.1-Ubuntu
2018-03-20T17:37:38.305280+00:00 compute-0-1 kernel: [1625342.861080] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
2018-03-20T17:37:38.305281+00:00 compute-0-1 kernel: [1625342.861081] kworker/u96:0   D ffff8811b2cb7c58     0 30946      2 0x00000080
2018-03-20T17:37:38.305283+00:00 compute-0-1 kernel: [1625342.861104] Workqueue: kvm-irqfd-cleanup irqfd_shutdown [kvm]
2018-03-20T17:37:38.305289+00:00 compute-0-1 kernel: [1625342.861106]  ffff8811b2cb7c58 ffff881038f12a00 ffff88028d6d8000 ffff8811b2cb8000
2018-03-20T17:37:38.305291+00:00 compute-0-1 kernel: [1625342.861108]  ffff8811b2cb7da8 ffff8811b2cb7da0 ffff88028d6d8000 ffff8812b592eae0
2018-03-20T17:37:38.305292+00:00 compute-0-1 kernel: [1625342.861109]  ffff8811b2cb7c70 ffffffff818094b5 7fffffffffffffff ffff8811b2cb7d18
2018-03-20T17:37:38.305293+00:00 compute-0-1 kernel: [1625342.861111] Call Trace:
2018-03-20T17:37:38.305293+00:00 compute-0-1 kernel: [1625342.861117]  [<ffffffff818094b5>] schedule+0x35/0x80
2018-03-20T17:37:38.305294+00:00 compute-0-1 kernel: [1625342.861119]  [<ffffffff8180be77>] schedule_timeout+0x237/0x2d0
2018-03-20T17:37:38.305294+00:00 compute-0-1 kernel: [1625342.861122]  [<ffffffff810a7309>] ? resched_curr+0xa9/0xd0
2018-03-20T17:37:38.305295+00:00 compute-0-1 kernel: [1625342.861123]  [<ffffffff810a7d45>] ? check_preempt_curr+0x75/0x90
2018-03-20T17:37:38.305296+00:00 compute-0-1 kernel: [1625342.861125]  [<ffffffff810a8919>] ? try_to_wake_up+0x49/0x3d0
2018-03-20T17:37:38.305297+00:00 compute-0-1 kernel: [1625342.861127]  [<ffffffff810b31df>] ? update_curr+0xdf/0x170
2018-03-20T17:37:38.305298+00:00 compute-0-1 kernel: [1625342.861129]  [<ffffffff81809dd4>] wait_for_completion+0xa4/0x110
2018-03-20T17:37:38.305299+00:00 compute-0-1 kernel: [1625342.861130]  [<ffffffff810a8d40>] ? wake_up_q+0x80/0x80
2018-03-20T17:37:38.305299+00:00 compute-0-1 kernel: [1625342.861133]  [<ffffffff81096127>] flush_work+0xf7/0x170
2018-03-20T17:37:38.305300+00:00 compute-0-1 kernel: [1625342.861134]  [<ffffffff81093f80>] ? destroy_worker+0x90/0x90
2018-03-20T17:37:38.305301+00:00 compute-0-1 kernel: [1625342.861142]  [<ffffffffc0450506>] irqfd_shutdown+0x36/0x80 [kvm]
2018-03-20T17:37:38.305302+00:00 compute-0-1 kernel: [1625342.861144]  [<ffffffff81096da0>] process_one_work+0x150/0x3f0
2018-03-20T17:37:38.305303+00:00 compute-0-1 kernel: [1625342.861145]  [<ffffffff8109751a>] worker_thread+0x11a/0x470
2018-03-20T17:37:38.305304+00:00 compute-0-1 kernel: [1625342.861147]  [<ffffffff81097400>] ? rescuer_thread+0x310/0x310
2018-03-20T17:37:38.305304+00:00 compute-0-1 kernel: [1625342.861149]  [<ffffffff8109cdd6>] kthread+0xd6/0xf0
2018-03-20T17:37:38.305305+00:00 compute-0-1 kernel: [1625342.861150]  [<ffffffff8109cd00>] ? kthread_park+0x60/0x60
2018-03-20T17:37:38.305306+00:00 compute-0-1 kernel: [1625342.861151]  [<ffffffff8180d0cf>] ret_from_fork+0x3f/0x70
2018-03-20T17:37:38.305307+00:00 compute-0-1 kernel: [1625342.861152]  [<ffffffff8109cd00>] ? kthread_park+0x60/0x60




./virt/kvm/kvm_main.c

static long kvm_vm_ioctl(struct file *filp,
                           unsigned int ioctl, unsigned long arg)
{
        struct kvm *kvm = filp->private_data;
        void __user *argp = (void __user *)arg;
        int r;

        if (kvm->mm != current->mm)
                return -EIO;
        switch (ioctl) {
        case KVM_CREATE_VCPU:
                r = kvm_vm_ioctl_create_vcpu(kvm, arg);
                break;
        case KVM_SET_USER_MEMORY_REGION: {
                struct kvm_userspace_memory_region kvm_userspace_mem;

                r = -EFAULT;
                if (copy_from_user(&kvm_userspace_mem, argp,
                                                sizeof(kvm_userspace_mem)))
                        goto out;

                r = kvm_vm_ioctl_set_memory_region(kvm, &kvm_userspace_mem);
                break;
        }
        case KVM_GET_DIRTY_LOG: {
                struct kvm_dirty_log log;

                r = -EFAULT;
                if (copy_from_user(&log, argp, sizeof(log)))
                        goto out;
                r = kvm_vm_ioctl_get_dirty_log(kvm, &log);
                break;
        }
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
        case KVM_REGISTER_COALESCED_MMIO: {
                struct kvm_coalesced_mmio_zone zone;

                r = -EFAULT;
                if (copy_from_user(&zone, argp, sizeof(zone)))
                        goto out;
                r = kvm_vm_ioctl_register_coalesced_mmio(kvm, &zone);
                break;
        }
        case KVM_UNREGISTER_COALESCED_MMIO: {
                struct kvm_coalesced_mmio_zone zone;

                r = -EFAULT;
                if (copy_from_user(&zone, argp, sizeof(zone)))
                        goto out;
                r = kvm_vm_ioctl_unregister_coalesced_mmio(kvm, &zone);
                break;
        }
#endif
        case KVM_IRQFD: {
                struct kvm_irqfd data;

                r = -EFAULT;
                if (copy_from_user(&data, argp, sizeof(data)))
                        goto out;
                r = kvm_irqfd(kvm, &data);                 ===========================>  kvm_irqfd
                break;
        }
        case KVM_IOEVENTFD: {
                struct kvm_ioeventfd data;

                r = -EFAULT;
                if (copy_from_user(&data, argp, sizeof(data)))
                        goto out;
                r = kvm_ioeventfd(kvm, &data);
                break;
        }
#ifdef CONFIG_HAVE_KVM_MSI
        case KVM_SIGNAL_MSI: {
                struct kvm_msi msi;

                r = -EFAULT;
                if (copy_from_user(&msi, argp, sizeof(msi)))
                        goto out;
                r = kvm_send_userspace_msi(kvm, &msi);
                break;
        }
#endif
#ifdef __KVM_HAVE_IRQ_LINE
        case KVM_IRQ_LINE_STATUS:
        case KVM_IRQ_LINE: {
                struct kvm_irq_level irq_event;

                r = -EFAULT;
                if (copy_from_user(&irq_event, argp, sizeof(irq_event)))
                        goto out;

                r = kvm_vm_ioctl_irq_line(kvm, &irq_event,
                                        ioctl == KVM_IRQ_LINE_STATUS);
                if (r)
                        goto out;

                r = -EFAULT;
                if (ioctl == KVM_IRQ_LINE_STATUS) {
                        if (copy_to_user(argp, &irq_event, sizeof(irq_event)))
                                goto out;
                }

                r = 0;
                break;
        }
#endif
#ifdef CONFIG_HAVE_KVM_IRQ_ROUTING
        case KVM_SET_GSI_ROUTING: {
                struct kvm_irq_routing routing;
                struct kvm_irq_routing __user *urouting;
                struct kvm_irq_routing_entry *entries;

                r = -EFAULT;
                if (copy_from_user(&routing, argp, sizeof(routing)))
                        goto out;
                r = -EINVAL;
                if (routing.nr > KVM_MAX_IRQ_ROUTES)
                        goto out;
                if (routing.flags)
                        goto out;
                r = -ENOMEM;
                entries = vmalloc(routing.nr * sizeof(*entries));
                if (!entries)
                        goto out;
                r = -EFAULT;
                urouting = argp;
                if (copy_from_user(entries, urouting->entries,
                                   routing.nr * sizeof(*entries)))
                        goto out_free_irq_routing;
                r = kvm_set_irq_routing(kvm, entries, routing.nr,
                                        routing.flags);
out_free_irq_routing:
                vfree(entries);
                break;
        }
#endif /* CONFIG_HAVE_KVM_IRQ_ROUTING */
        case KVM_CREATE_DEVICE: {
                struct kvm_create_device cd;

                r = -EFAULT;
                if (copy_from_user(&cd, argp, sizeof(cd)))
                        goto out;

                r = kvm_ioctl_create_device(kvm, &cd);
                if (r)
                        goto out;

                r = -EFAULT;
                if (copy_to_user(argp, &cd, sizeof(cd)))
                        goto out;

                r = 0;
                break;
        }
        case KVM_CHECK_EXTENSION:
                r = kvm_vm_ioctl_check_extension_generic(kvm, arg);
                break;
        default:
                r = kvm_arch_vm_ioctl(filp, ioctl, arg);
        }
out:
        return r;
}


-----------------------------------------------------------------------------

./virt/kvm/eventfd.c:304:	INIT_WORK(&irqfd->shutdown, irqfd_shutdown);

int
kvm_irqfd(struct kvm *kvm, struct kvm_irqfd *args)
{
        if (args->flags & ~(KVM_IRQFD_FLAG_DEASSIGN | KVM_IRQFD_FLAG_RESAMPLE))
                return -EINVAL;

        if (args->flags & KVM_IRQFD_FLAG_DEASSIGN)
                return kvm_irqfd_deassign(kvm, args);

        return kvm_irqfd_assign(kvm, args);
}

-----------------------------------------------------------------------------

./virt/kvm/eventfd.c

static int
kvm_irqfd_assign(struct kvm *kvm, struct kvm_irqfd *args)
{
        struct kvm_kernel_irqfd *irqfd, *tmp;
        struct fd f;
        struct eventfd_ctx *eventfd = NULL, *resamplefd = NULL;
        int ret;
        unsigned int events;
        int idx;

        if (!kvm_arch_intc_initialized(kvm))
                return -EAGAIN;

        irqfd = kzalloc(sizeof(*irqfd), GFP_KERNEL);
        if (!irqfd)
                return -ENOMEM;

        irqfd->kvm = kvm;
        irqfd->gsi = args->gsi;
        INIT_LIST_HEAD(&irqfd->list);
        INIT_WORK(&irqfd->inject, irqfd_inject);
        INIT_WORK(&irqfd->shutdown, irqfd_shutdown);       ==============> irqfd_shutdown
        seqcount_init(&irqfd->irq_entry_sc);

        f = fdget(args->fd);
        if (!f.file) {
                ret = -EBADF;
                goto out;
        }

        eventfd = eventfd_ctx_fileget(f.file);
        if (IS_ERR(eventfd)) {
                ret = PTR_ERR(eventfd);
                goto fail;
        }

        irqfd->eventfd = eventfd;

        if (args->flags & KVM_IRQFD_FLAG_RESAMPLE) {
                struct kvm_kernel_irqfd_resampler *resampler;

                resamplefd = eventfd_ctx_fdget(args->resamplefd);
                if (IS_ERR(resamplefd)) {
                        ret = PTR_ERR(resamplefd);
                        goto fail;
                }

                irqfd->resamplefd = resamplefd;
                INIT_LIST_HEAD(&irqfd->resampler_link);

                mutex_lock(&kvm->irqfds.resampler_lock);

                list_for_each_entry(resampler,
                                    &kvm->irqfds.resampler_list, link) {
                        if (resampler->notifier.gsi == irqfd->gsi) {
                                irqfd->resampler = resampler;
                                break;
                        }
                }

                if (!irqfd->resampler) {
                        resampler = kzalloc(sizeof(*resampler), GFP_KERNEL);
                        if (!resampler) {
                                ret = -ENOMEM;
                                mutex_unlock(&kvm->irqfds.resampler_lock);
                                goto fail;
                        }

                        resampler->kvm = kvm;
                        INIT_LIST_HEAD(&resampler->list);
                        resampler->notifier.gsi = irqfd->gsi;
                        resampler->notifier.irq_acked = irqfd_resampler_ack;
                        INIT_LIST_HEAD(&resampler->link);

                        list_add(&resampler->link, &kvm->irqfds.resampler_list);
                        kvm_register_irq_ack_notifier(kvm,
                                                      &resampler->notifier);
                        irqfd->resampler = resampler;
                }

                list_add_rcu(&irqfd->resampler_link, &irqfd->resampler->list);
                synchronize_srcu(&kvm->irq_srcu);

                mutex_unlock(&kvm->irqfds.resampler_lock);
        }

        /*
         * Install our own custom wake-up handling so we are notified via
         * a callback whenever someone signals the underlying eventfd
         */
        init_waitqueue_func_entry(&irqfd->wait, irqfd_wakeup);
        init_poll_funcptr(&irqfd->pt, irqfd_ptable_queue_proc);

        spin_lock_irq(&kvm->irqfds.lock);

        ret = 0;
        list_for_each_entry(tmp, &kvm->irqfds.items, list) {
                if (irqfd->eventfd != tmp->eventfd)
                        continue;
                /* This fd is used for another irq already. */
                ret = -EBUSY;
                spin_unlock_irq(&kvm->irqfds.lock);
                goto fail;
        }

        idx = srcu_read_lock(&kvm->irq_srcu);
        irqfd_update(kvm, irqfd);
        srcu_read_unlock(&kvm->irq_srcu, idx);

        list_add_tail(&irqfd->list, &kvm->irqfds.items);

        spin_unlock_irq(&kvm->irqfds.lock);

        /*
         * Check if there was an event already pending on the eventfd
         * before we registered, and trigger it as if we didn't miss it.
         */
        events = f.file->f_op->poll(f.file, &irqfd->pt);

        if (events & POLLIN)
                schedule_work(&irqfd->inject);

        /*
         * do not drop the file until the irqfd is fully initialized, otherwise
         * we might race against the POLLHUP
         */
        fdput(f);
#ifdef CONFIG_HAVE_KVM_IRQ_BYPASS
        irqfd->consumer.token = (void *)irqfd->eventfd;
        irqfd->consumer.add_producer = kvm_arch_irq_bypass_add_producer;
        irqfd->consumer.del_producer = kvm_arch_irq_bypass_del_producer;
        irqfd->consumer.stop = kvm_arch_irq_bypass_stop;
        irqfd->consumer.start = kvm_arch_irq_bypass_start;
        ret = irq_bypass_register_consumer(&irqfd->consumer);
        if (ret)
                pr_info("irq bypass consumer (token %p) registration fails: %d\n",
                                irqfd->consumer.token, ret);
#endif

        return 0;

fail:
        if (irqfd->resampler)
                irqfd_resampler_shutdown(irqfd);

        if (resamplefd && !IS_ERR(resamplefd))
                eventfd_ctx_put(resamplefd);

        if (eventfd && !IS_ERR(eventfd))
                eventfd_ctx_put(eventfd);

        fdput(f);

out:
        kfree(irqfd);
        return ret;
}

-----------------------------------------------------------------------------

./arch/x86/kvm/vmx.c:10981:	int r = kvm_init(&vmx_x86_ops, sizeof(struct vcpu_vmx),

static int __init vmx_init(void)
{
        int r = kvm_init(&vmx_x86_ops, sizeof(struct vcpu_vmx),
                     __alignof__(struct vcpu_vmx), THIS_MODULE);
        if (r)
                return r;

-----------------------------------------------------------------------------

./virt/kvm/kvm_main.c:3563:	r = kvm_irqfd_init();


int kvm_init(void *opaque, unsigned vcpu_size, unsigned vcpu_align,
                  struct module *module)
{
        int r;
        int cpu;

        r = kvm_arch_init(opaque);
        if (r)
                goto out_fail;

        /*
         * kvm_arch_init makes sure there's at most one caller
         * for architectures that support multiple implementations,
         * like intel and amd on x86.
         * kvm_arch_init must be called before kvm_irqfd_init to avoid creating
         * conflicts in case kvm is already setup for another implementation.
         */
        r = kvm_irqfd_init();                       ===========================================>     kvm_irqfd_init
        if (r)
                goto out_irqfd;

        if (!zalloc_cpumask_var(&cpus_hardware_enabled, GFP_KERNEL)) {
                r = -ENOMEM;
                goto out_free_0;
        }

        r = kvm_arch_hardware_setup();
        if (r < 0)
                goto out_free_0a;

        for_each_online_cpu(cpu) {
                smp_call_function_single(cpu,
                                kvm_arch_check_processor_compat,
                                &r, 1);
                if (r < 0)
                        goto out_free_1;
        }

        r = register_cpu_notifier(&kvm_cpu_notifier);
        if (r)
                goto out_free_2;
        register_reboot_notifier(&kvm_reboot_notifier);

        /* A kmem cache lets us meet the alignment requirements of fx_save. */
        if (!vcpu_align)
                vcpu_align = __alignof__(struct kvm_vcpu);
        kvm_vcpu_cache = kmem_cache_create("kvm_vcpu", vcpu_size, vcpu_align,
                                           0, NULL);
        if (!kvm_vcpu_cache) {
                r = -ENOMEM;
                goto out_free_3;
        }

        r = kvm_async_pf_init();
        if (r)
                goto out_free;

        kvm_chardev_ops.owner = module;
        kvm_vm_fops.owner = module;
        kvm_vcpu_fops.owner = module;

        r = misc_register(&kvm_dev);
        if (r) {
                pr_err("kvm: misc device register failed\n");
                goto out_unreg;
        }

        register_syscore_ops(&kvm_syscore_ops);

        kvm_preempt_ops.sched_in = kvm_sched_in;
        kvm_preempt_ops.sched_out = kvm_sched_out;

        r = kvm_init_debug();
        if (r) {
                pr_err("kvm: create debugfs files failed\n");
                goto out_undebugfs;
        }

        r = kvm_vfio_ops_init();
        WARN_ON(r);

        return 0;

out_undebugfs:
        unregister_syscore_ops(&kvm_syscore_ops);
        misc_deregister(&kvm_dev);
out_unreg:
        kvm_async_pf_deinit();
out_free:
        kmem_cache_destroy(kvm_vcpu_cache);
out_free_3:
        unregister_reboot_notifier(&kvm_reboot_notifier);
        unregister_cpu_notifier(&kvm_cpu_notifier);
out_free_2:
out_free_1:
        kvm_arch_hardware_unsetup();
out_free_0a:
        free_cpumask_var(cpus_hardware_enabled);
out_free_0:
        kvm_irqfd_exit();
out_irqfd:
        kvm_arch_exit();
out_fail:
        return r;
}
EXPORT_SYMBOL_GPL(kvm_init);

-----------------------------------------------------------------------------

./virt/kvm/eventfd.c:630:	irqfd_cleanup_wq = create_singlethread_workqueue("kvm-irqfd-cleanup");

/*
 * create a host-wide workqueue for issuing deferred shutdown requests
 * aggregated from all vm* instances. We need our own isolated single-thread
 * queue to prevent deadlock against flushing the normal work-queue.
 */
int kvm_irqfd_init(void)
{
        irqfd_cleanup_wq = create_singlethread_workqueue("kvm-irqfd-cleanup");
        if (!irqfd_cleanup_wq)
                return -ENOMEM;

        return 0;
}



============================================================================


2018-03-20T17:37:38.305265+00:00 compute-0-1 kernel: [1625342.861076] INFO: task kworker/u96:0:30946 blocked for more than 120 seconds.
2018-03-20T17:37:38.305278+00:00 compute-0-1 kernel: [1625342.861079]       Not tainted 4.4.0-91-generic #114~14.04.1-Ubuntu
2018-03-20T17:37:38.305280+00:00 compute-0-1 kernel: [1625342.861080] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
2018-03-20T17:37:38.305281+00:00 compute-0-1 kernel: [1625342.861081] kworker/u96:0   D ffff8811b2cb7c58     0 30946      2 0x00000080
2018-03-20T17:37:38.305283+00:00 compute-0-1 kernel: [1625342.861104] Workqueue: kvm-irqfd-cleanup irqfd_shutdown [kvm]
2018-03-20T17:37:38.305289+00:00 compute-0-1 kernel: [1625342.861106]  ffff8811b2cb7c58 ffff881038f12a00 ffff88028d6d8000 ffff8811b2cb8000
2018-03-20T17:37:38.305291+00:00 compute-0-1 kernel: [1625342.861108]  ffff8811b2cb7da8 ffff8811b2cb7da0 ffff88028d6d8000 ffff8812b592eae0
2018-03-20T17:37:38.305292+00:00 compute-0-1 kernel: [1625342.861109]  ffff8811b2cb7c70 ffffffff818094b5 7fffffffffffffff ffff8811b2cb7d18
2018-03-20T17:37:38.305293+00:00 compute-0-1 kernel: [1625342.861111] Call Trace:
2018-03-20T17:37:38.305293+00:00 compute-0-1 kernel: [1625342.861117]  [<ffffffff818094b5>] schedule+0x35/0x80
2018-03-20T17:37:38.305294+00:00 compute-0-1 kernel: [1625342.861119]  [<ffffffff8180be77>] schedule_timeout+0x237/0x2d0
2018-03-20T17:37:38.305294+00:00 compute-0-1 kernel: [1625342.861122]  [<ffffffff810a7309>] ? resched_curr+0xa9/0xd0
2018-03-20T17:37:38.305295+00:00 compute-0-1 kernel: [1625342.861123]  [<ffffffff810a7d45>] ? check_preempt_curr+0x75/0x90
2018-03-20T17:37:38.305296+00:00 compute-0-1 kernel: [1625342.861125]  [<ffffffff810a8919>] ? try_to_wake_up+0x49/0x3d0
2018-03-20T17:37:38.305297+00:00 compute-0-1 kernel: [1625342.861127]  [<ffffffff810b31df>] ? update_curr+0xdf/0x170
2018-03-20T17:37:38.305298+00:00 compute-0-1 kernel: [1625342.861129]  [<ffffffff81809dd4>] wait_for_completion+0xa4/0x110
2018-03-20T17:37:38.305299+00:00 compute-0-1 kernel: [1625342.861130]  [<ffffffff810a8d40>] ? wake_up_q+0x80/0x80
2018-03-20T17:37:38.305299+00:00 compute-0-1 kernel: [1625342.861133]  [<ffffffff81096127>] flush_work+0xf7/0x170
2018-03-20T17:37:38.305300+00:00 compute-0-1 kernel: [1625342.861134]  [<ffffffff81093f80>] ? destroy_worker+0x90/0x90
2018-03-20T17:37:38.305301+00:00 compute-0-1 kernel: [1625342.861142]  [<ffffffffc0450506>] irqfd_shutdown+0x36/0x80 [kvm]
2018-03-20T17:37:38.305302+00:00 compute-0-1 kernel: [1625342.861144]  [<ffffffff81096da0>] process_one_work+0x150/0x3f0
2018-03-20T17:37:38.305303+00:00 compute-0-1 kernel: [1625342.861145]  [<ffffffff8109751a>] worker_thread+0x11a/0x470
2018-03-20T17:37:38.305304+00:00 compute-0-1 kernel: [1625342.861147]  [<ffffffff81097400>] ? rescuer_thread+0x310/0x310
2018-03-20T17:37:38.305304+00:00 compute-0-1 kernel: [1625342.861149]  [<ffffffff8109cdd6>] kthread+0xd6/0xf0
2018-03-20T17:37:38.305305+00:00 compute-0-1 kernel: [1625342.861150]  [<ffffffff8109cd00>] ? kthread_park+0x60/0x60
2018-03-20T17:37:38.305306+00:00 compute-0-1 kernel: [1625342.861151]  [<ffffffff8180d0cf>] ret_from_fork+0x3f/0x70
2018-03-20T17:37:38.305307+00:00 compute-0-1 kernel: [1625342.861152]  [<ffffffff8109cd00>] ? kthread_park+0x60/0x60




-----------------------------------------------------------------------------
 [<ffffffff81096da0>] process_one_work+0x150/0x3f0

./kernel/workqueue.c:1984:static void process_one_work(struct worker *worker, struct work_struct *work)

/**
 * process_one_work - process single work
 * @worker: self
 * @work: work to process
 *
 * Process @work.  This function contains all the logics necessary to
 * process a single work including synchronization against and
 * interaction with other workers on the same cpu, queueing and
 * flushing.  As long as context requirement is met, any worker can
 * call this function to process a work.
 *
 * CONTEXT:
 * spin_lock_irq(pool->lock) which is released and regrabbed.
 */
static void process_one_work(struct worker *worker, struct work_struct *work)
__releases(&pool->lock)
__acquires(&pool->lock)
{
        struct pool_workqueue *pwq = get_work_pwq(work);
        struct worker_pool *pool = worker->pool;
        bool cpu_intensive = pwq->wq->flags & WQ_CPU_INTENSIVE;
        int work_color;
        struct worker *collision;
#ifdef CONFIG_LOCKDEP
        /*
         * It is permissible to free the struct work_struct from
         * inside the function that is called from it, this we need to
         * take into account for lockdep too.  To avoid bogus "held
         * lock freed" warnings as well as problems when looking into
         * work->lockdep_map, make a copy and use that here.
         */
        struct lockdep_map lockdep_map;

        lockdep_copy_map(&lockdep_map, &work->lockdep_map);
#endif
        /* ensure we're on the correct CPU */
        WARN_ON_ONCE(!(pool->flags & POOL_DISASSOCIATED) &&
                     raw_smp_processor_id() != pool->cpu);

        /*
         * A single work shouldn't be executed concurrently by
         * multiple workers on a single cpu.  Check whether anyone is
         * already processing the work.  If so, defer the work to the
         * currently executing one.
         */
        collision = find_worker_executing_work(pool, work);
        if (unlikely(collision)) {
                move_linked_works(work, &collision->scheduled, NULL);
                return;
        }

        /* claim and dequeue */
        debug_work_deactivate(work);
        hash_add(pool->busy_hash, &worker->hentry, (unsigned long)work);
        worker->current_work = work;
        worker->current_func = work->func;
        worker->current_pwq = pwq;
        work_color = get_work_color(work);

        list_del_init(&work->entry);

        /*
         * CPU intensive works don't participate in concurrency management.
         * They're the scheduler's responsibility.  This takes @worker out
         * of concurrency management and the next code block will chain
         * execution of the pending work items.
         */
        if (unlikely(cpu_intensive))
                worker_set_flags(worker, WORKER_CPU_INTENSIVE);

        /*
         * Wake up another worker if necessary.  The condition is always
         * false for normal per-cpu workers since nr_running would always
         * be >= 1 at this point.  This is used to chain execution of the
         * pending work items for WORKER_NOT_RUNNING workers such as the
         * UNBOUND and CPU_INTENSIVE ones.
         */
        if (need_more_worker(pool))
                wake_up_worker(pool);

        /*
         * Record the last pool and clear PENDING which should be the last
         * update to @work.  Also, do this inside @pool->lock so that
         * PENDING and queued state changes happen together while IRQ is
         * disabled.
         */
        set_work_pool_and_clear_pending(work, pool->id);

        spin_unlock_irq(&pool->lock);

        lock_map_acquire_read(&pwq->wq->lockdep_map);
        lock_map_acquire(&lockdep_map);
        trace_workqueue_execute_start(work);
        worker->current_func(work);
        /*
         * While we must be careful to not use "work" after this, the trace
         * point will only record its address.
         */
        trace_workqueue_execute_end(work);
        lock_map_release(&lockdep_map);
        lock_map_release(&pwq->wq->lockdep_map);

        if (unlikely(in_atomic() || lockdep_depth(current) > 0)) {
                pr_err("BUG: workqueue leaked lock or atomic: %s/0x%08x/%d\n"
                       "     last function: %pf\n",
                       current->comm, preempt_count(), task_pid_nr(current),
                       worker->current_func);
                debug_show_held_locks(current);
                dump_stack();
        }

        /*
         * The following prevents a kworker from hogging CPU on !PREEMPT
         * kernels, where a requeueing work item waiting for something to
         * happen could deadlock with stop_machine as such work item could
         * indefinitely requeue itself while all other CPUs are trapped in
         * stop_machine. At the same time, report a quiescent RCU state so
         * the same condition doesn't freeze RCU.
         */
        cond_resched_rcu_qs();

        spin_lock_irq(&pool->lock);

        /* clear cpu intensive status */
        if (unlikely(cpu_intensive))
                worker_clr_flags(worker, WORKER_CPU_INTENSIVE);

        /* we're done with it, release */
        hash_del(&worker->hentry);
        worker->current_work = NULL;
        worker->current_func = NULL;
        worker->current_pwq = NULL;
        worker->desc_valid = false;
        pwq_dec_nr_in_flight(pwq, work_color);
}
-----------------------------------------------------------------------------

[<ffffffffc0450506>] irqfd_shutdown+0x36/0x80 [kvm]

./virt/kvm/eventfd.c:118:irqfd_shutdown(struct work_struct *work)

/*
 * Race-free decouple logic (ordering is critical)
 */
static void
irqfd_shutdown(struct work_struct *work)
{
        struct kvm_kernel_irqfd *irqfd =
                container_of(work, struct kvm_kernel_irqfd, shutdown);
        u64 cnt;

        /*
         * Synchronize with the wait-queue and unhook ourselves to prevent
         * further events.
         */
        eventfd_ctx_remove_wait_queue(irqfd->eventfd, &irqfd->wait, &cnt);

        /*
         * We know no new events will be scheduled at this point, so block
         * until all previously outstanding events have completed
         */
        flush_work(&irqfd->inject);                   ==================>   flush_work

        if (irqfd->resampler) {
                irqfd_resampler_shutdown(irqfd);
                eventfd_ctx_put(irqfd->resamplefd);
        }

        /*
         * It is now safe to release the object's resources
         */
#ifdef CONFIG_HAVE_KVM_IRQ_BYPASS
        irq_bypass_unregister_consumer(&irqfd->consumer);
#endif
        eventfd_ctx_put(irqfd->eventfd);
        kfree(irqfd);
}

-----------------------------------------------------------------------------
[<ffffffff81096127>] flush_work+0xf7/0x170
./kernel/workqueue.c:2765:bool flush_work(struct work_struct *work)

/**
 * flush_work - wait for a work to finish executing the last queueing instance
 * @work: the work to flush
 *
 * Wait until @work has finished execution.  @work is guaranteed to be idle
 * on return if it hasn't been requeued since flush started.
 *
 * Return:
 * %true if flush_work() waited for the work to finish execution,
 * %false if it was already idle.
 */
bool flush_work(struct work_struct *work)
{
        struct wq_barrier barr;

        lock_map_acquire(&work->lockdep_map);
        lock_map_release(&work->lockdep_map);

        if (start_flush_work(work, &barr)) {
                wait_for_completion(&barr.done);        ================>    wait_for_completion
                destroy_work_on_stack(&barr.work);
                return true;
        } else {
                return false;
        }
}
EXPORT_SYMBOL_GPL(flush_work);

-----------------------------------------------------------------------------

[<ffffffff81809dd4>] wait_for_completion+0xa4/0x110

./kernel/sched/completion.c:120:void __sched wait_for_completion(struct completion *x)

/**
 * wait_for_completion: - waits for completion of a task
 * @x:  holds the state of this particular completion
 *
 * This waits to be signaled for completion of a specific task. It is NOT
 * interruptible and there is no timeout.
 *
 * See also similar routines (i.e. wait_for_completion_timeout()) with timeout
 * and interrupt capability. Also see complete().
 */
void __sched wait_for_completion(struct completion *x)
{
        wait_for_common(x, MAX_SCHEDULE_TIMEOUT, TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(wait_for_completion);

-----------------------------------------------------------------------------

./kernel/sched/completion.c:99:wait_for_common(struct completion *x, long timeout, int state)

static long __sched
wait_for_common(struct completion *x, long timeout, int state)
{
        return __wait_for_common(x, schedule_timeout, timeout, state);
}

-----------------------------------------------------------------------------
./kernel/sched/completion.c

static inline long __sched
__wait_for_common(struct completion *x,
                  long (*action)(long), long timeout, int state)
{
        might_sleep();

        spin_lock_irq(&x->wait.lock);
        timeout = do_wait_for_common(x, action, timeout, state);
        spin_unlock_irq(&x->wait.lock);
        return timeout;
}

-----------------------------------------------------------------------------
./kernel/sched/completion.c

do_wait_for_common(struct completion *x,
                   long (*action)(long), long timeout, int state)
{
        if (!x->done) {
                DECLARE_WAITQUEUE(wait, current);

                __add_wait_queue_tail_exclusive(&x->wait, &wait);
                do {
                        if (signal_pending_state(state, current)) {
                                timeout = -ERESTARTSYS;
                                break;
                        }
                        __set_current_state(state);
                        spin_unlock_irq(&x->wait.lock);
                        timeout = action(timeout);
                        spin_lock_irq(&x->wait.lock);
                } while (!x->done && timeout);
                __remove_wait_queue(&x->wait, &wait);
                if (!x->done)
                        return timeout;
        }
        x->done--;
        return timeout ?: 1;
}


===============================================================================================================================================




2018-03-20T17:37:38.305308+00:00 compute-0-1 kernel: [1625342.861155] INFO: task qemu-system-x86:12636 blocked for more than 120 seconds.
2018-03-20T17:37:38.305309+00:00 compute-0-1 kernel: [1625342.861156]       Not tainted 4.4.0-91-generic #114~14.04.1-Ubuntu
2018-03-20T17:37:38.305309+00:00 compute-0-1 kernel: [1625342.861156] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
2018-03-20T17:37:38.305310+00:00 compute-0-1 kernel: [1625342.861157] qemu-system-x86 D ffff8810fce6fbb8     0 12636      1 0x00000080
2018-03-20T17:37:38.305311+00:00 compute-0-1 kernel: [1625342.861159]  ffff8810fce6fbb8 ffff882038ff8000 ffff8812190b4600 ffff8810fce70000
2018-03-20T17:37:38.305313+00:00 compute-0-1 kernel: [1625342.861160]  ffff8810fce6fd30 ffff8810fce6fd28 ffff8812190b4600 ffff8810fce6fd10
2018-03-20T17:37:38.305313+00:00 compute-0-1 kernel: [1625342.861162]  ffff8810fce6fbd0 ffffffff818094b5 7fffffffffffffff ffff8810fce6fc80
2018-03-20T17:37:38.305314+00:00 compute-0-1 kernel: [1625342.861164] Call Trace:
2018-03-20T17:37:38.305314+00:00 compute-0-1 kernel: [1625342.861165]  [<ffffffff818094b5>] schedule+0x35/0x80
2018-03-20T17:37:38.305315+00:00 compute-0-1 kernel: [1625342.861167]  [<ffffffff8180be77>] schedule_timeout+0x237/0x2d0
2018-03-20T17:37:38.305316+00:00 compute-0-1 kernel: [1625342.861168]  [<ffffffff810a7309>] ? resched_curr+0xa9/0xd0
2018-03-20T17:37:38.305317+00:00 compute-0-1 kernel: [1625342.861170]  [<ffffffff810a7d45>] ? check_preempt_curr+0x75/0x90
2018-03-20T17:37:38.305318+00:00 compute-0-1 kernel: [1625342.861171]  [<ffffffff810a7d79>] ? ttwu_do_wakeup+0x19/0xe0
2018-03-20T17:37:38.305319+00:00 compute-0-1 kernel: [1625342.861173]  [<ffffffff810a7edd>] ? ttwu_do_activate.constprop.92+0x5d/0x70
2018-03-20T17:37:38.305319+00:00 compute-0-1 kernel: [1625342.861174]  [<ffffffff81809dd4>] wait_for_completion+0xa4/0x110
2018-03-20T17:37:38.305320+00:00 compute-0-1 kernel: [1625342.861176]  [<ffffffff810a8d40>] ? wake_up_q+0x80/0x80
2018-03-20T17:37:38.305321+00:00 compute-0-1 kernel: [1625342.861177]  [<ffffffff8109587a>] flush_workqueue+0x11a/0x590
2018-03-20T17:37:38.305322+00:00 compute-0-1 kernel: [1625342.861185]  [<ffffffffc0450979>] kvm_irqfd+0x3b9/0x5f0 [kvm]
2018-03-20T17:37:38.305323+00:00 compute-0-1 kernel: [1625342.861194]  [<ffffffffc04645f6>] ? kvm_put_guest_fpu+0x66/0x140 [kvm]
2018-03-20T17:37:38.305324+00:00 compute-0-1 kernel: [1625342.861203]  [<ffffffffc04646ef>] ? kvm_arch_vcpu_put+0x1f/0x40 [kvm]
2018-03-20T17:37:38.305325+00:00 compute-0-1 kernel: [1625342.861210]  [<ffffffffc044e276>] kvm_vm_ioctl+0x166/0x6e0 [kvm]
2018-03-20T17:37:38.305326+00:00 compute-0-1 kernel: [1625342.861214]  [<ffffffff81120fc7>] ? audit_filter_rules.isra.9+0x6e7/0xe30
2018-03-20T17:37:38.305327+00:00 compute-0-1 kernel: [1625342.861218]  [<ffffffff8121474d>] do_vfs_ioctl+0x2dd/0x4c0
2018-03-20T17:37:38.305328+00:00 compute-0-1 kernel: [1625342.861220]  [<ffffffff8112212f>] ? __audit_syscall_entry+0xaf/0x100
2018-03-20T17:37:38.305328+00:00 compute-0-1 kernel: [1625342.861223]  [<ffffffff81003176>] ? do_audit_syscall_entry+0x66/0x70
2018-03-20T17:37:38.305329+00:00 compute-0-1 kernel: [1625342.861225]  [<ffffffff812149a9>] SyS_ioctl+0x79/0x90
2018-03-20T17:37:38.305329+00:00 compute-0-1 kernel: [1625342.861226]  [<ffffffff8180cd36>] entry_SYSCALL_64_fastpath+0x16/0x75

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

-----------------------------------------------------------------------------
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
./virt/kvm/kvm_main.c:2965:	.compat_ioctl   = kvm_vm_compat_ioctl,

static struct file_operations kvm_vm_fops = {
        .release        = kvm_vm_release,
        .unlocked_ioctl = kvm_vm_ioctl,
#ifdef CONFIG_KVM_COMPAT
        .compat_ioctl   = kvm_vm_compat_ioctl,          ================================> kvm_vm_compat_ioctl
#endif
        .llseek         = noop_llseek,
};

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./virt/kvm/kvm_main.c:2953:		r = kvm_vm_ioctl(filp, ioctl, arg);

static long kvm_vm_compat_ioctl(struct file *filp,
                           unsigned int ioctl, unsigned long arg)
{
        struct kvm *kvm = filp->private_data;
        int r;

        if (kvm->mm != current->mm)
                return -EIO;
        switch (ioctl) {
        case KVM_GET_DIRTY_LOG: {
                struct compat_kvm_dirty_log compat_log;
                struct kvm_dirty_log log;

                r = -EFAULT;
                if (copy_from_user(&compat_log, (void __user *)arg,
                                   sizeof(compat_log)))
                        goto out;
                log.slot         = compat_log.slot;
                log.padding1     = compat_log.padding1;
                log.padding2     = compat_log.padding2;
                log.dirty_bitmap = compat_ptr(compat_log.dirty_bitmap);

                r = kvm_vm_ioctl_get_dirty_log(kvm, &log);
                break;
        }
        default:
                r = kvm_vm_ioctl(filp, ioctl, arg);     ==================================>  kvm_vm_ioctl
        }

out:
        return r;
}
#endif


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
-----------------------------------------------------------------------------

./virt/kvm/kvm_main.c:2753:static long kvm_vm_ioctl(struct file *filp,

static long kvm_vm_ioctl(struct file *filp,
                           unsigned int ioctl, unsigned long arg)
{
        struct kvm *kvm = filp->private_data;
        void __user *argp = (void __user *)arg;
        int r;

        if (kvm->mm != current->mm)
                return -EIO;
        switch (ioctl) {
        case KVM_CREATE_VCPU:
                r = kvm_vm_ioctl_create_vcpu(kvm, arg);
                break;
        case KVM_SET_USER_MEMORY_REGION: {
                struct kvm_userspace_memory_region kvm_userspace_mem;

                r = -EFAULT;
                if (copy_from_user(&kvm_userspace_mem, argp,
                                                sizeof(kvm_userspace_mem)))
                        goto out;

                r = kvm_vm_ioctl_set_memory_region(kvm, &kvm_userspace_mem);
                break;
        }
        case KVM_GET_DIRTY_LOG: {
                struct kvm_dirty_log log;

                r = -EFAULT;
                if (copy_from_user(&log, argp, sizeof(log)))
                        goto out;
                r = kvm_vm_ioctl_get_dirty_log(kvm, &log);
                break;
        }
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
        case KVM_REGISTER_COALESCED_MMIO: {
                struct kvm_coalesced_mmio_zone zone;

                r = -EFAULT;
                if (copy_from_user(&zone, argp, sizeof(zone)))
                        goto out;
                r = kvm_vm_ioctl_register_coalesced_mmio(kvm, &zone);
                break;
        }
        case KVM_UNREGISTER_COALESCED_MMIO: {
                struct kvm_coalesced_mmio_zone zone;

                r = -EFAULT;
                if (copy_from_user(&zone, argp, sizeof(zone)))
                        goto out;
                r = kvm_vm_ioctl_unregister_coalesced_mmio(kvm, &zone);
                break;
        }
#endif
        case KVM_IRQFD: {
                struct kvm_irqfd data;

                r = -EFAULT;
                if (copy_from_user(&data, argp, sizeof(data)))
                        goto out;
                r = kvm_irqfd(kvm, &data);           ==============================>   kvm_irqfd
                break;
        }
        case KVM_IOEVENTFD: {
                struct kvm_ioeventfd data;

                r = -EFAULT;
                if (copy_from_user(&data, argp, sizeof(data)))
                        goto out;
                r = kvm_ioeventfd(kvm, &data);
                break;
        }
#ifdef CONFIG_HAVE_KVM_MSI
        case KVM_SIGNAL_MSI: {
                struct kvm_msi msi;

                r = -EFAULT;
                if (copy_from_user(&msi, argp, sizeof(msi)))
                        goto out;
                r = kvm_send_userspace_msi(kvm, &msi);
                break;
        }
#endif
#ifdef __KVM_HAVE_IRQ_LINE
        case KVM_IRQ_LINE_STATUS:
        case KVM_IRQ_LINE: {
                struct kvm_irq_level irq_event;

                r = -EFAULT;
                if (copy_from_user(&irq_event, argp, sizeof(irq_event)))
                        goto out;

                r = kvm_vm_ioctl_irq_line(kvm, &irq_event,
                                        ioctl == KVM_IRQ_LINE_STATUS);
                if (r)
                        goto out;

                r = -EFAULT;
                if (ioctl == KVM_IRQ_LINE_STATUS) {
                        if (copy_to_user(argp, &irq_event, sizeof(irq_event)))
                                goto out;
                }

                r = 0;
                break;
        }
#endif
#ifdef CONFIG_HAVE_KVM_IRQ_ROUTING
        case KVM_SET_GSI_ROUTING: {
                struct kvm_irq_routing routing;
                struct kvm_irq_routing __user *urouting;
                struct kvm_irq_routing_entry *entries;

                r = -EFAULT;
                if (copy_from_user(&routing, argp, sizeof(routing)))
                        goto out;
                r = -EINVAL;
                if (routing.nr > KVM_MAX_IRQ_ROUTES)
                        goto out;
                if (routing.flags)
                        goto out;
                r = -ENOMEM;
                entries = vmalloc(routing.nr * sizeof(*entries));
                if (!entries)
                        goto out;
                r = -EFAULT;
                urouting = argp;
                if (copy_from_user(entries, urouting->entries,
                                   routing.nr * sizeof(*entries)))
                        goto out_free_irq_routing;
                r = kvm_set_irq_routing(kvm, entries, routing.nr,
                                        routing.flags);
out_free_irq_routing:
                vfree(entries);
                break;
        }
#endif /* CONFIG_HAVE_KVM_IRQ_ROUTING */
        case KVM_CREATE_DEVICE: {
                struct kvm_create_device cd;

                r = -EFAULT;
                if (copy_from_user(&cd, argp, sizeof(cd)))
                        goto out;

                r = kvm_ioctl_create_device(kvm, &cd);
                if (r)
                        goto out;

                r = -EFAULT;
                if (copy_to_user(argp, &cd, sizeof(cd)))
                        goto out;

                r = 0;
                break;
        }
        case KVM_CHECK_EXTENSION:
                r = kvm_vm_ioctl_check_extension_generic(kvm, arg);
                break;
        default:
                r = kvm_arch_vm_ioctl(filp, ioctl, arg);
        }
out:
        return r;
}

-----------------------------------------------------------------------------
./virt/kvm/eventfd.c:562:kvm_irqfd(struct kvm *kvm, struct kvm_irqfd *args)

int
kvm_irqfd(struct kvm *kvm, struct kvm_irqfd *args)
{
        if (args->flags & ~(KVM_IRQFD_FLAG_DEASSIGN | KVM_IRQFD_FLAG_RESAMPLE))
                return -EINVAL;

        if (args->flags & KVM_IRQFD_FLAG_DEASSIGN)
                return kvm_irqfd_deassign(kvm, args);      ======================>  kvm_irqfd_deassign

        return kvm_irqfd_assign(kvm, args);
}

-----------------------------------------------------------------------------
./virt/kvm/eventfd.c:522:kvm_irqfd_deassign(struct kvm *kvm, struct kvm_irqfd *args)

/*
 * shutdown any irqfd's that match fd+gsi
 */
static int
kvm_irqfd_deassign(struct kvm *kvm, struct kvm_irqfd *args)
{
        struct kvm_kernel_irqfd *irqfd, *tmp;
        struct eventfd_ctx *eventfd;

        eventfd = eventfd_ctx_fdget(args->fd);
        if (IS_ERR(eventfd))
                return PTR_ERR(eventfd);

        spin_lock_irq(&kvm->irqfds.lock);

        list_for_each_entry_safe(irqfd, tmp, &kvm->irqfds.items, list) {
                if (irqfd->eventfd == eventfd && irqfd->gsi == args->gsi) {
                        /*
                         * This clearing of irq_entry.type is needed for when
                         * another thread calls kvm_irq_routing_update before
                         * we flush workqueue below (we synchronize with
                         * kvm_irq_routing_update using irqfds.lock).
                         */
                        write_seqcount_begin(&irqfd->irq_entry_sc);
                        irqfd->irq_entry.type = 0;
                        write_seqcount_end(&irqfd->irq_entry_sc);
                        irqfd_deactivate(irqfd);
                }
        }

        spin_unlock_irq(&kvm->irqfds.lock);
        eventfd_ctx_put(eventfd);

        /*
         * Block until we know all outstanding shutdown jobs have completed
         * so that we guarantee there will not be any more interrupts on this
         * gsi once this deassign function returns.
         */
        flush_workqueue(irqfd_cleanup_wq);      ==========================>  flush_workqueue

        return 0;
}


-----------------------------------------------------------------------------

./kernel/workqueue.c:2504:void flush_workqueue(struct workqueue_struct *wq)


/**
 * flush_workqueue - ensure that any scheduled work has run to completion.
 * @wq: workqueue to flush
 *
 * This function sleeps until all work items which were queued on entry
 * have finished execution, but it is not livelocked by new incoming ones.
 */
void flush_workqueue(struct workqueue_struct *wq)
{
        struct wq_flusher this_flusher = {
                .list = LIST_HEAD_INIT(this_flusher.list),
                .flush_color = -1,
                .done = COMPLETION_INITIALIZER_ONSTACK(this_flusher.done),
        };
        int next_color;

        lock_map_acquire(&wq->lockdep_map);
        lock_map_release(&wq->lockdep_map);

        mutex_lock(&wq->mutex);

        /*
         * Start-to-wait phase
         */
        next_color = work_next_color(wq->work_color);

        if (next_color != wq->flush_color) {
                /*
                 * Color space is not full.  The current work_color
                 * becomes our flush_color and work_color is advanced
                 * by one.
                 */
                WARN_ON_ONCE(!list_empty(&wq->flusher_overflow));
                this_flusher.flush_color = wq->work_color;
                wq->work_color = next_color;

                if (!wq->first_flusher) {
                        /* no flush in progress, become the first flusher */
                        WARN_ON_ONCE(wq->flush_color != this_flusher.flush_color);

                        wq->first_flusher = &this_flusher;

                        if (!flush_workqueue_prep_pwqs(wq, wq->flush_color,
                                                       wq->work_color)) {
                                /* nothing to flush, done */
                                wq->flush_color = next_color;
                                wq->first_flusher = NULL;
                                goto out_unlock;
                        }
                } else {
                        /* wait in queue */
                        WARN_ON_ONCE(wq->flush_color == this_flusher.flush_color);
                        list_add_tail(&this_flusher.list, &wq->flusher_queue);
                        flush_workqueue_prep_pwqs(wq, -1, wq->work_color);
                }
        } else {
                /*
                 * Oops, color space is full, wait on overflow queue.
                 * The next flush completion will assign us
                 * flush_color and transfer to flusher_queue.
                 */
                list_add_tail(&this_flusher.list, &wq->flusher_overflow);
        }

        mutex_unlock(&wq->mutex);

        wait_for_completion(&this_flusher.done);        ====================> wait_for_completion

        /*
         * Wake-up-and-cascade phase
         *
         * First flushers are responsible for cascading flushes and
         * handling overflow.  Non-first flushers can simply return.
         */
        if (wq->first_flusher != &this_flusher)
                return;

        mutex_lock(&wq->mutex);

        /* we might have raced, check again with mutex held */
        if (wq->first_flusher != &this_flusher)
                goto out_unlock;

        wq->first_flusher = NULL;

        WARN_ON_ONCE(!list_empty(&this_flusher.list));
        WARN_ON_ONCE(wq->flush_color != this_flusher.flush_color);

        while (true) {
                struct wq_flusher *next, *tmp;

                /* complete all the flushers sharing the current flush color */
                list_for_each_entry_safe(next, tmp, &wq->flusher_queue, list) {
                        if (next->flush_color != wq->flush_color)
                                break;
                        list_del_init(&next->list);
                        complete(&next->done);
                }

                WARN_ON_ONCE(!list_empty(&wq->flusher_overflow) &&
                             wq->flush_color != work_next_color(wq->work_color));

                /* this flush_color is finished, advance by one */
                wq->flush_color = work_next_color(wq->flush_color);

                /* one color has been freed, handle overflow queue */
                if (!list_empty(&wq->flusher_overflow)) {
                        /*
                         * Assign the same color to all overflowed
                         * flushers, advance work_color and append to
                         * flusher_queue.  This is the start-to-wait
                         * phase for these overflowed flushers.
                         */
                        list_for_each_entry(tmp, &wq->flusher_overflow, list)
                                tmp->flush_color = wq->work_color;

                        wq->work_color = work_next_color(wq->work_color);

                        list_splice_tail_init(&wq->flusher_overflow,
                                              &wq->flusher_queue);
                        flush_workqueue_prep_pwqs(wq, -1, wq->work_color);
                }

                if (list_empty(&wq->flusher_queue)) {
                        WARN_ON_ONCE(wq->flush_color != wq->work_color);
                        break;
                }

                /*
                 * Need to flush more colors.  Make the next flusher
                 * the new first flusher and arm pwqs.
                 */
                WARN_ON_ONCE(wq->flush_color == wq->work_color);
                WARN_ON_ONCE(wq->flush_color != next->flush_color);

                list_del_init(&next->list);
                wq->first_flusher = next;

                if (flush_workqueue_prep_pwqs(wq, wq->flush_color, -1))
                        break;

                /*
                 * Meh... this color is already done, clear first
                 * flusher and repeat cascading.
                 */
                wq->first_flusher = NULL;
        }

out_unlock:
        mutex_unlock(&wq->mutex);
}
EXPORT_SYMBOL(flush_workqueue);


-----------------------------------------------------------------------------

./kernel/sched/completion.c:120:void __sched wait_for_completion(struct completion *x)

/**
 * wait_for_completion: - waits for completion of a task
 * @x:  holds the state of this particular completion
 *
 * This waits to be signaled for completion of a specific task. It is NOT
 * interruptible and there is no timeout.
 *
 * See also similar routines (i.e. wait_for_completion_timeout()) with timeout
 * and interrupt capability. Also see complete().
 */
void __sched wait_for_completion(struct completion *x)
{
        wait_for_common(x, MAX_SCHEDULE_TIMEOUT, TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(wait_for_completion);


-----------------------------------------------------------------------------


./Documentation/scheduler/completion.txt:106:calls wait_for_completion() on the initialized completion structure.

completions - wait for completion handling
==========================================

This document was originally written based on 3.18.0 (linux-next)

Introduction:
-------------

If you have one or more threads of execution that must wait for some process
to have reached a point or a specific state, completions can provide a
race-free solution to this problem. Semantically they are somewhat like a
pthread_barrier and have similar use-cases.

Completions are a code synchronization mechanism which is preferable to any
misuse of locks. Any time you think of using yield() or some quirky
msleep(1) loop to allow something else to proceed, you probably want to
look into using one of the wait_for_completion*() calls instead. The
advantage of using completions is clear intent of the code, but also more
efficient code as both threads can continue until the result is actually
needed.

Completions are built on top of the generic event infrastructure in Linux,
with the event reduced to a simple flag (appropriately called "done") in
struct completion that tells the waiting threads of execution if they
can continue safely.

As completions are scheduling related, the code is found in
kernel/sched/completion.c - for details on completion design and
implementation see completions-design.txt



Usage:
------

There are three parts to using completions, the initialization of the
struct completion, the waiting part through a call to one of the variants of
wait_for_completion() and the signaling side through a call to complete()
or complete_all(). Further there are some helper functions for checking the
state of completions.

To use completions one needs to include <linux/completion.h> and
create a variable of type struct completion. The structure used for
handling of completions is:

        struct completion {
                unsigned int done;
                wait_queue_head_t wait;
        };

providing the wait queue to place tasks on for waiting and the flag for
indicating the state of affairs.

Completions should be named to convey the intent of the waiter. A good
example is:

        wait_for_completion(&early_console_added);

        complete(&early_console_added);

Good naming (as always) helps code readability.




Waiting for completions:
------------------------

For a thread of execution to wait for some concurrent work to finish, it
calls wait_for_completion() on the initialized completion structure.
A typical usage scenario is:

	struct completion setup_done;
	init_completion(&setup_done);
	initialize_work(...,&setup_done,...)

	/* run non-dependent code */              /* do setup */

	wait_for_completion(&setup_done);         complete(setup_done)

This is not implying any temporal order on wait_for_completion() and the
call to complete() - if the call to complete() happened before the call
to wait_for_completion() then the waiting side simply will continue
immediately as all dependencies are satisfied if not it will block until
completion is signaled by complete().

Note that wait_for_completion() is calling spin_lock_irq()/spin_unlock_irq(),
so it can only be called safely when you know that interrupts are enabled.
Calling it from hard-irq or irqs-off atomic contexts will result in
hard-to-detect spurious enabling of interrupts.

wait_for_completion():

	void wait_for_completion(struct completion *done):

The default behavior is to wait without a timeout and to mark the task as
uninterruptible. wait_for_completion() and its variants are only safe
in process context (as they can sleep) but not in atomic context,
interrupt context, with disabled irqs. or preemption is disabled - see also
try_wait_for_completion() below for handling completion in atomic/interrupt
context.

As all variants of wait_for_completion() can (obviously) block for a long
time, you probably don't want to call this with held mutexes.





2018-03-20T17:37:38.305314+00:00 compute-0-1 kernel: [1625342.861165]  [<ffffffff818094b5>] schedule+0x35/0x80
2018-03-20T17:37:38.305315+00:00 compute-0-1 kernel: [1625342.861167]  [<ffffffff8180be77>] schedule_timeout+0x237/0x2d0
2018-03-20T17:37:38.305316+00:00 compute-0-1 kernel: [1625342.861168]  [<ffffffff810a7309>] ? resched_curr+0xa9/0xd0
2018-03-20T17:37:38.305317+00:00 compute-0-1 kernel: [1625342.861170]  [<ffffffff810a7d45>] ? check_preempt_curr+0x75/0x90
2018-03-20T17:37:38.305318+00:00 compute-0-1 kernel: [1625342.861171]  [<ffffffff810a7d79>] ? ttwu_do_wakeup+0x19/0xe0
2018-03-20T17:37:38.305319+00:00 compute-0-1 kernel: [1625342.861173]  [<ffffffff810a7edd>] ? ttwu_do_activate.constprop.92+0x5d/0x70
2018-03-20T17:37:38.305319+00:00 compute-0-1 kernel: [1625342.861174]  [<ffffffff81809dd4>] wait_for_completion+0xa4/0x110
2018-03-20T17:37:38.305320+00:00 compute-0-1 kernel: [1625342.861176]  [<ffffffff810a8d40>] ? wake_up_q+0x80/0x80
2018-03-20T17:37:38.305321+00:00 compute-0-1 kernel: [1625342.861177]  [<ffffffff8109587a>] flush_workqueue+0x11a/0x590
2018-03-20T17:37:38.305322+00:00 compute-0-1 kernel: [1625342.861185]  [<ffffffffc0450979>] kvm_irqfd+0x3b9/0x5f0 [kvm]
2018-03-20T17:37:38.305323+00:00 compute-0-1 kernel: [1625342.861194]  [<ffffffffc04645f6>] ? kvm_put_guest_fpu+0x66/0x140 [kvm]
2018-03-20T17:37:38.305324+00:00 compute-0-1 kernel: [1625342.861203]  [<ffffffffc04646ef>] ? kvm_arch_vcpu_put+0x1f/0x40 [kvm]
2018-03-20T17:37:38.305325+00:00 compute-0-1 kernel: [1625342.861210]  [<ffffffffc044e276>] kvm_vm_ioctl+0x166/0x6e0 [kvm]
2018-03-20T17:37:38.305326+00:00 compute-0-1 kernel: [1625342.861214]  [<ffffffff81120fc7>] ? audit_filter_rules.isra.9+0x6e7/0xe30
2018-03-20T17:37:38.305327+00:00 compute-0-1 kernel: [1625342.861218]  [<ffffffff8121474d>] do_vfs_ioctl+0x2dd/0x4c0
2018-03-20T17:37:38.305328+00:00 compute-0-1 kernel: [1625342.861220]  [<ffffffff8112212f>] ? __audit_syscall_entry+0xaf/0x100
2018-03-20T17:37:38.305328+00:00 compute-0-1 kernel: [1625342.861223]  [<ffffffff81003176>] ? do_audit_syscall_entry+0x66/0x70
2018-03-20T17:37:38.305329+00:00 compute-0-1 kernel: [1625342.861225]  [<ffffffff812149a9>] SyS_ioctl+0x79/0x90
2018-03-20T17:37:38.305329+00:00 compute-0-1 kernel: [1625342.861226]  [<ffffffff8180cd36>] entry_SYSCALL_64_fastpath+0x16/0x75





#########################################################################################################################################



2018-04-19T16:51:35.672420+00:00 compute-0-3 kernel: [ 1800.762049] INFO: task ksmd:253 blocked for more than 120 seconds.
2018-04-19T16:51:35.672434+00:00 compute-0-3 kernel: [ 1800.762052]       Tainted: G           OE   4.4.0-91-generic #114~14.04.1-Ubuntu
2018-04-19T16:51:35.672435+00:00 compute-0-3 kernel: [ 1800.762053] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
2018-04-19T16:51:35.672436+00:00 compute-0-3 kernel: [ 1800.762054] ksmd            D ffff8810382d3c18     0   253      2 0x00000000
2018-04-19T16:51:35.672436+00:00 compute-0-3 kernel: [ 1800.762058]  ffff8810382d3c18 ffff881038f0aa00 ffff881038035400 ffff8810382d4000
2018-04-19T16:51:35.672437+00:00 compute-0-3 kernel: [ 1800.762060]  ffff8810382d3d68 ffff8810382d3d60 ffff881038035400 0000000000000200
2018-04-19T16:51:35.672438+00:00 compute-0-3 kernel: [ 1800.762061]  ffff8810382d3c30 ffffffff818094b5 7fffffffffffffff ffff8810382d3cd8
2018-04-19T16:51:35.672446+00:00 compute-0-3 kernel: [ 1800.762063] Call Trace:
2018-04-19T16:51:35.672448+00:00 compute-0-3 kernel: [ 1800.762071]  [<ffffffff818094b5>] schedule+0x35/0x80
2018-04-19T16:51:35.672448+00:00 compute-0-3 kernel: [ 1800.762074]  [<ffffffff8180be77>] schedule_timeout+0x237/0x2d0
2018-04-19T16:51:35.672449+00:00 compute-0-3 kernel: [ 1800.762078]  [<ffffffff810a7d45>] ? check_preempt_curr+0x75/0x90
2018-04-19T16:51:35.672449+00:00 compute-0-3 kernel: [ 1800.762079]  [<ffffffff810a7d79>] ? ttwu_do_wakeup+0x19/0xe0
2018-04-19T16:51:35.672450+00:00 compute-0-3 kernel: [ 1800.762081]  [<ffffffff810a8919>] ? try_to_wake_up+0x49/0x3d0
2018-04-19T16:51:35.672451+00:00 compute-0-3 kernel: [ 1800.762083]  [<ffffffff81809dd4>] wait_for_completion+0xa4/0x110
2018-04-19T16:51:35.672452+00:00 compute-0-3 kernel: [ 1800.762085]  [<ffffffff810a8d40>] ? wake_up_q+0x80/0x80
2018-04-19T16:51:35.672453+00:00 compute-0-3 kernel: [ 1800.762088]  [<ffffffff81096127>] flush_work+0xf7/0x170
2018-04-19T16:51:35.672453+00:00 compute-0-3 kernel: [ 1800.762089]  [<ffffffff81093f80>] ? destroy_worker+0x90/0x90
2018-04-19T16:51:35.672454+00:00 compute-0-3 kernel: [ 1800.762093]  [<ffffffff81194556>] lru_add_drain_all+0x116/0x160
2018-04-19T16:51:35.672455+00:00 compute-0-3 kernel: [ 1800.762096]  [<ffffffff811da27c>] ksm_do_scan+0x65c/0xdb0
2018-04-19T16:51:35.672455+00:00 compute-0-3 kernel: [ 1800.762098]  [<ffffffff811daa49>] ksm_scan_thread+0x79/0x1c0
2018-04-19T16:51:35.672456+00:00 compute-0-3 kernel: [ 1800.762101]  [<ffffffff810bf6e0>] ? prepare_to_wait_event+0xf0/0xf0
2018-04-19T16:51:35.672457+00:00 compute-0-3 kernel: [ 1800.762103]  [<ffffffff811da9d0>] ? ksm_do_scan+0xdb0/0xdb0
2018-04-19T16:51:35.672457+00:00 compute-0-3 kernel: [ 1800.762105]  [<ffffffff8109cdd6>] kthread+0xd6/0xf0
2018-04-19T16:51:35.672458+00:00 compute-0-3 kernel: [ 1800.762106]  [<ffffffff8109cd00>] ? kthread_park+0x60/0x60
2018-04-19T16:51:35.672459+00:00 compute-0-3 kernel: [ 1800.762108]  [<ffffffff8180d0cf>] ret_from_fork+0x3f/0x70
2018-04-19T16:51:35.672459+00:00 compute-0-3 kernel: [ 1800.762109]  [<ffffffff8109cd00>] ? kthread_park+0x60/0x60


./mm/ksm.c:3021:	ksm_thread = kthread_run(ksm_scan_thread, NULL, "ksmd");

static int __init ksm_init(void)
{
        struct task_struct *ksm_thread;
        int err;

        err = ksm_slab_init();
        if (err)
                goto out;

        ksm_thread = kthread_run(ksm_scan_thread, NULL, "ksmd");
        if (IS_ERR(ksm_thread)) {
                pr_err("ksm: creating kthread failed\n");
                err = PTR_ERR(ksm_thread);
                goto out_free;
        }


----------------------------------------------------------------------------------------------------------------

./mm/ksm.c:2297:static int ksm_scan_thread(void *nothing)

static int ksm_scan_thread(void *nothing)
{
        set_freezable();
        set_user_nice(current, 5);

        while (!kthread_should_stop()) {
                mutex_lock(&ksm_thread_mutex);
                wait_while_offlining();
                if (ksmd_should_run())
                        ksm_do_scan(ksm_thread_pages_to_scan);   =====================>   ksm_do_scan
                mutex_unlock(&ksm_thread_mutex);

                try_to_freeze();

                if (ksmd_should_run()) {
                        schedule_timeout_interruptible(
                                msecs_to_jiffies(ksm_thread_sleep_millisecs));
                } else {
                        wait_event_freezable(ksm_thread_wait,
                                ksmd_should_run() || kthread_should_stop());
                }
        }
        return 0;
}

----------------------------------------------------------------------------------------------------------------

./mm/ksm.c:2277:static void ksm_do_scan(unsigned int scan_npages)

/**
 * ksm_do_scan  - the ksm scanner main worker function.
 * @scan_npages - number of pages we want to scan before we return.
 */
static void ksm_do_scan(unsigned int scan_npages)
{
        struct rmap_item *rmap_item;
        struct page *uninitialized_var(page);

        while (scan_npages-- && likely(!freezing(current))) {
                cond_resched();
                rmap_item = scan_get_next_rmap_item(&page);        =================> scan_get_next_rmap_item
                if (!rmap_item)
                        return;
                cmp_and_merge_page(page, rmap_item);
                put_page(page);
        }
}


----------------------------------------------------------------------------------------------------------------

./mm/ksm.c

static struct rmap_item *scan_get_next_rmap_item(struct page **page)
{
        struct mm_struct *mm;
        struct mm_slot *slot;
        struct vm_area_struct *vma;
        struct rmap_item *rmap_item;
        int nid;

        if (list_empty(&ksm_mm_head.mm_list))
                return NULL;

        slot = ksm_scan.mm_slot;
        if (slot == &ksm_mm_head) {
                /*
                 * A number of pages can hang around indefinitely on per-cpu
                 * pagevecs, raised page count preventing write_protect_page
                 * from merging them.  Though it doesn't really matter much,
                 * it is puzzling to see some stuck in pages_volatile until
                 * other activity jostles them out, and they also prevented
                 * LTP's KSM test from succeeding deterministically; so drain
                 * them here (here rather than on entry to ksm_do_scan(),
                 * so we don't IPI too often when pages_to_scan is set low).
                 */
                lru_add_drain_all();     ================================================> lru_add_drain_all

                /*
                 * Whereas stale stable_nodes on the stable_tree itself
                 * get pruned in the regular course of stable_tree_search(),
                 * those moved out to the migrate_nodes list can accumulate:
                 * so prune them once before each full scan.
                 */
                if (!ksm_merge_across_nodes) {
                        struct stable_node *stable_node;
                        struct list_head *this, *next;
                        struct page *page;

                        list_for_each_safe(this, next, &migrate_nodes) {
                                stable_node = list_entry(this,
                                                struct stable_node, list);
                                page = get_ksm_page(stable_node, false);
                                if (page)
                                        put_page(page);
                                cond_resched();
                        }
                }

                for (nid = 0; nid < ksm_nr_node_ids; nid++)
                        root_unstable_tree[nid] = RB_ROOT;

                spin_lock(&ksm_mmlist_lock);
                slot = list_entry(slot->mm_list.next, struct mm_slot, mm_list);
                ksm_scan.mm_slot = slot;
                spin_unlock(&ksm_mmlist_lock);
                /*
                 * Although we tested list_empty() above, a racing __ksm_exit
                 * of the last mm on the list may have removed it since then.
                 */
                if (slot == &ksm_mm_head)
                        return NULL;
next_mm:
                ksm_scan.address = 0;
                ksm_scan.rmap_list = &slot->rmap_list;
        }

        mm = slot->mm;
        down_read(&mm->mmap_sem);
        if (ksm_test_exit(mm))
                vma = NULL;
        else
                vma = find_vma(mm, ksm_scan.address);

        for (; vma; vma = vma->vm_next) {
                if (!(vma->vm_flags & VM_MERGEABLE))
                        continue;
                if (ksm_scan.address < vma->vm_start)
                        ksm_scan.address = vma->vm_start;
                if (!vma->anon_vma)
                        ksm_scan.address = vma->vm_end;

                while (ksm_scan.address < vma->vm_end) {
                        if (ksm_test_exit(mm))
                                break;
                        *page = follow_page(vma, ksm_scan.address, FOLL_GET);
                        if (IS_ERR_OR_NULL(*page)) {
                                ksm_scan.address += PAGE_SIZE;
                                cond_resched();
                                continue;
                        }
                        if (PageAnon(*page) ||
                            page_trans_compound_anon(*page)) {
                                flush_anon_page(vma, *page, ksm_scan.address);
                                flush_dcache_page(*page);
                                rmap_item = get_next_rmap_item(slot,
                                        ksm_scan.rmap_list, ksm_scan.address);
                                if (rmap_item) {
                                        ksm_scan.rmap_list =
                                                        &rmap_item->rmap_list;
                                        ksm_scan.address += PAGE_SIZE;
                                } else
                                        put_page(*page);
                                up_read(&mm->mmap_sem);
                                return rmap_item;
                        }
                        put_page(*page);
                        ksm_scan.address += PAGE_SIZE;
                        cond_resched();
                }
        }

        if (ksm_test_exit(mm)) {
                ksm_scan.address = 0;
                ksm_scan.rmap_list = &slot->rmap_list;
        }
        /*
         * Nuke all the rmap_items that are above this current rmap:
         * because there were no VM_MERGEABLE vmas with such addresses.
         */
        remove_trailing_rmap_items(slot, ksm_scan.rmap_list);

        spin_lock(&ksm_mmlist_lock);
        ksm_scan.mm_slot = list_entry(slot->mm_list.next,
                                                struct mm_slot, mm_list);
        if (ksm_scan.address == 0) {
                /*
                 * We've completed a full scan of all vmas, holding mmap_sem
                 * throughout, and found no VM_MERGEABLE: so do the same as
                 * __ksm_exit does to remove this mm from all our lists now.
                 * This applies either when cleaning up after __ksm_exit
                 * (but beware: we can reach here even before __ksm_exit),
                 * or when all VM_MERGEABLE areas have been unmapped (and
                 * mmap_sem then protects against race with MADV_MERGEABLE).
                 */
                hash_del(&slot->link);
                list_del(&slot->mm_list);
                spin_unlock(&ksm_mmlist_lock);

                free_mm_slot(slot);
                clear_bit(MMF_VM_MERGEABLE, &mm->flags);
                up_read(&mm->mmap_sem);
                mmdrop(mm);
        } else {
                spin_unlock(&ksm_mmlist_lock);
                up_read(&mm->mmap_sem);
        }

        /* Repeat until we've completed scanning the whole list */
        slot = ksm_scan.mm_slot;
        if (slot != &ksm_mm_head)
                goto next_mm;

        ksm_scan.seqnr++;
        return NULL;
}

----------------------------------------------------------------------------------------------------------------

./mm/swap.c:870:void lru_add_drain_all(void)

void lru_add_drain_all(void)
{
        static DEFINE_MUTEX(lock);
        static struct cpumask has_work;
        int cpu;

        mutex_lock(&lock);
        get_online_cpus();
        cpumask_clear(&has_work);

        for_each_online_cpu(cpu) {
                struct work_struct *work = &per_cpu(lru_add_drain_work, cpu);

                if (pagevec_count(&per_cpu(lru_add_pvec, cpu)) ||
                    pagevec_count(&per_cpu(lru_rotate_pvecs, cpu)) ||
                    pagevec_count(&per_cpu(lru_deactivate_file_pvecs, cpu)) ||
                    need_activate_page_drain(cpu)) {
                        INIT_WORK(work, lru_add_drain_per_cpu);
                        schedule_work_on(cpu, work);
                        cpumask_set_cpu(cpu, &has_work);
                }
        }

        for_each_cpu(cpu, &has_work)
                flush_work(&per_cpu(lru_add_drain_work, cpu));     ==========================> flush_work 

        put_online_cpus();
        mutex_unlock(&lock);
}


----------------------------------------------------------------------------------------------------------------

./kernel/workqueue.c:2765:bool flush_work(struct work_struct *work)

/**
 * flush_work - wait for a work to finish executing the last queueing instance
 * @work: the work to flush
 *
 * Wait until @work has finished execution.  @work is guaranteed to be idle
 * on return if it hasn't been requeued since flush started.
 *
 * Return:
 * %true if flush_work() waited for the work to finish execution,
 * %false if it was already idle.
 */
bool flush_work(struct work_struct *work)
{
        struct wq_barrier barr;

        lock_map_acquire(&work->lockdep_map);
        lock_map_release(&work->lockdep_map);

        if (start_flush_work(work, &barr)) {
                wait_for_completion(&barr.done);     =============>  wait_for_completion
                destroy_work_on_stack(&barr.work);
                return true;
        } else {
                return false;
        }
}
EXPORT_SYMBOL_GPL(flush_work);


----------------------------------------------------------------------------------------------------------------

./kernel/sched/completion.c:120:void __sched wait_for_completion(struct completion *x)

/**
 * wait_for_completion: - waits for completion of a task
 * @x:  holds the state of this particular completion
 *
 * This waits to be signaled for completion of a specific task. It is NOT
 * interruptible and there is no timeout.
 *
 * See also similar routines (i.e. wait_for_completion_timeout()) with timeout
 * and interrupt capability. Also see complete().
 */
void __sched wait_for_completion(struct completion *x)
{
        wait_for_common(x, MAX_SCHEDULE_TIMEOUT, TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(wait_for_completion);



2018-04-19T16:51:35.672420+00:00 compute-0-3 kernel: [ 1800.762049] INFO: task ksmd:253 blocked for more than 120 seconds.
2018-04-19T16:51:35.672434+00:00 compute-0-3 kernel: [ 1800.762052]       Tainted: G           OE   4.4.0-91-generic #114~14.04.1-Ubuntu
2018-04-19T16:51:35.672435+00:00 compute-0-3 kernel: [ 1800.762053] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
2018-04-19T16:51:35.672436+00:00 compute-0-3 kernel: [ 1800.762054] ksmd            D ffff8810382d3c18     0   253      2 0x00000000
2018-04-19T16:51:35.672436+00:00 compute-0-3 kernel: [ 1800.762058]  ffff8810382d3c18 ffff881038f0aa00 ffff881038035400 ffff8810382d4000
2018-04-19T16:51:35.672437+00:00 compute-0-3 kernel: [ 1800.762060]  ffff8810382d3d68 ffff8810382d3d60 ffff881038035400 0000000000000200
2018-04-19T16:51:35.672438+00:00 compute-0-3 kernel: [ 1800.762061]  ffff8810382d3c30 ffffffff818094b5 7fffffffffffffff ffff8810382d3cd8
2018-04-19T16:51:35.672446+00:00 compute-0-3 kernel: [ 1800.762063] Call Trace:
2018-04-19T16:51:35.672448+00:00 compute-0-3 kernel: [ 1800.762071]  [<ffffffff818094b5>] schedule+0x35/0x80
2018-04-19T16:51:35.672448+00:00 compute-0-3 kernel: [ 1800.762074]  [<ffffffff8180be77>] schedule_timeout+0x237/0x2d0
2018-04-19T16:51:35.672449+00:00 compute-0-3 kernel: [ 1800.762078]  [<ffffffff810a7d45>] ? check_preempt_curr+0x75/0x90
2018-04-19T16:51:35.672449+00:00 compute-0-3 kernel: [ 1800.762079]  [<ffffffff810a7d79>] ? ttwu_do_wakeup+0x19/0xe0
2018-04-19T16:51:35.672450+00:00 compute-0-3 kernel: [ 1800.762081]  [<ffffffff810a8919>] ? try_to_wake_up+0x49/0x3d0
2018-04-19T16:51:35.672451+00:00 compute-0-3 kernel: [ 1800.762083]  [<ffffffff81809dd4>] wait_for_completion+0xa4/0x110
2018-04-19T16:51:35.672452+00:00 compute-0-3 kernel: [ 1800.762085]  [<ffffffff810a8d40>] ? wake_up_q+0x80/0x80
2018-04-19T16:51:35.672453+00:00 compute-0-3 kernel: [ 1800.762088]  [<ffffffff81096127>] flush_work+0xf7/0x170
2018-04-19T16:51:35.672453+00:00 compute-0-3 kernel: [ 1800.762089]  [<ffffffff81093f80>] ? destroy_worker+0x90/0x90
2018-04-19T16:51:35.672454+00:00 compute-0-3 kernel: [ 1800.762093]  [<ffffffff81194556>] lru_add_drain_all+0x116/0x160
2018-04-19T16:51:35.672455+00:00 compute-0-3 kernel: [ 1800.762096]  [<ffffffff811da27c>] ksm_do_scan+0x65c/0xdb0
2018-04-19T16:51:35.672455+00:00 compute-0-3 kernel: [ 1800.762098]  [<ffffffff811daa49>] ksm_scan_thread+0x79/0x1c0
2018-04-19T16:51:35.672456+00:00 compute-0-3 kernel: [ 1800.762101]  [<ffffffff810bf6e0>] ? prepare_to_wait_event+0xf0/0xf0
2018-04-19T16:51:35.672457+00:00 compute-0-3 kernel: [ 1800.762103]  [<ffffffff811da9d0>] ? ksm_do_scan+0xdb0/0xdb0
2018-04-19T16:51:35.672457+00:00 compute-0-3 kernel: [ 1800.762105]  [<ffffffff8109cdd6>] kthread+0xd6/0xf0
2018-04-19T16:51:35.672458+00:00 compute-0-3 kernel: [ 1800.762106]  [<ffffffff8109cd00>] ? kthread_park+0x60/0x60
2018-04-19T16:51:35.672459+00:00 compute-0-3 kernel: [ 1800.762108]  [<ffffffff8180d0cf>] ret_from_fork+0x3f/0x70
2018-04-19T16:51:35.672459+00:00 compute-0-3 kernel: [ 1800.762109]  [<ffffffff8109cd00>] ? kthread_park+0x60/0x60



===========================================================================================================================================


2018-04-19T16:51:35.672474+00:00 compute-0-3 kernel: [ 1800.762177] INFO: task qemu-system-x86:39347 blocked for more than 120 seconds.
2018-04-19T16:51:35.672474+00:00 compute-0-3 kernel: [ 1800.762178]       Tainted: G           OE   4.4.0-91-generic #114~14.04.1-Ubuntu
2018-04-19T16:51:35.672475+00:00 compute-0-3 kernel: [ 1800.762179] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
2018-04-19T16:51:35.672475+00:00 compute-0-3 kernel: [ 1800.762179] qemu-system-x86 D ffff881015cdfd78     0 39347      1 0x00000084
2018-04-19T16:51:35.672476+00:00 compute-0-3 kernel: [ 1800.762181]  ffff881015cdfd78 ffff88028f137000 ffff88100db3e200 ffff881015ce0000
2018-04-19T16:51:35.672477+00:00 compute-0-3 kernel: [ 1800.762183]  ffffffff81e69ea4 ffff88100db3e200 00000000ffffffff ffffffff81e69ea8
2018-04-19T16:51:35.672478+00:00 compute-0-3 kernel: [ 1800.762184]  ffff881015cdfd90 ffffffff818094b5 ffffffff81e69ea0 ffff881015cdfda0
2018-04-19T16:51:35.672478+00:00 compute-0-3 kernel: [ 1800.762185] Call Trace:
2018-04-19T16:51:35.672479+00:00 compute-0-3 kernel: [ 1800.762187]  [<ffffffff818094b5>] schedule+0x35/0x80
2018-04-19T16:51:35.672479+00:00 compute-0-3 kernel: [ 1800.762189]  [<ffffffff8180974e>] schedule_preempt_disabled+0xe/0x10
2018-04-19T16:51:35.672480+00:00 compute-0-3 kernel: [ 1800.762190]  [<ffffffff8180afb5>] __mutex_lock_slowpath+0x95/0x110
2018-04-19T16:51:35.672481+00:00 compute-0-3 kernel: [ 1800.762192]  [<ffffffff811b487e>] ? handle_pte_fault+0xbae/0x1430
2018-04-19T16:51:35.672482+00:00 compute-0-3 kernel: [ 1800.762193]  [<ffffffff8180b04f>] mutex_lock+0x1f/0x2f
2018-04-19T16:51:35.672482+00:00 compute-0-3 kernel: [ 1800.762195]  [<ffffffff81194472>] lru_add_drain_all+0x32/0x160
2018-04-19T16:51:35.672483+00:00 compute-0-3 kernel: [ 1800.762196]  [<ffffffff811e59be>] migrate_prep+0xe/0x20
2018-04-19T16:51:35.672483+00:00 compute-0-3 kernel: [ 1800.762197]  [<ffffffff811d6aab>] do_mbind+0x19b/0x560
2018-04-19T16:51:35.672484+00:00 compute-0-3 kernel: [ 1800.762199]  [<ffffffff81003176>] ? do_audit_syscall_entry+0x66/0x70
2018-04-19T16:51:35.672485+00:00 compute-0-3 kernel: [ 1800.762200]  [<ffffffff811d7014>] SyS_mbind+0x84/0xa0
2018-04-19T16:51:35.672486+00:00 compute-0-3 kernel: [ 1800.762202]  [<ffffffff8180cd36>] entry_SYSCALL_64_fastpath+0x16/0x75


./mm/mempolicy.c:1311:	return do_mbind(start, len, mode, mode_flags, &nodes, flags);

SYSCALL_DEFINE6(mbind, unsigned long, start, unsigned long, len,
                unsigned long, mode, const unsigned long __user *, nmask,
                unsigned long, maxnode, unsigned, flags)
{
        nodemask_t nodes;
        int err;
        unsigned short mode_flags;

        mode_flags = mode & MPOL_MODE_FLAGS;
        mode &= ~MPOL_MODE_FLAGS;
        if (mode >= MPOL_MAX)
                return -EINVAL;
        if ((mode_flags & MPOL_F_STATIC_NODES) &&
            (mode_flags & MPOL_F_RELATIVE_NODES))
                return -EINVAL;
        err = get_nodes(&nodes, nmask, maxnode);
        if (err)
                return err;
        return do_mbind(start, len, mode, mode_flags, &nodes, flags);        =====================>  do_mbind
}

----------------------------------------------------------------------------------------------------------------

./mm/mempolicy.c:1130:static long do_mbind(unsigned long start, unsigned long len,

static long do_mbind(unsigned long start, unsigned long len,
                     unsigned short mode, unsigned short mode_flags,
                     nodemask_t *nmask, unsigned long flags)
{
        struct mm_struct *mm = current->mm;
        struct mempolicy *new;
        unsigned long end;
        int err;
        LIST_HEAD(pagelist);

        if (flags & ~(unsigned long)MPOL_MF_VALID)
                return -EINVAL;
        if ((flags & MPOL_MF_MOVE_ALL) && !capable(CAP_SYS_NICE))
                return -EPERM;

        if (start & ~PAGE_MASK)
                return -EINVAL;

        if (mode == MPOL_DEFAULT)
                flags &= ~MPOL_MF_STRICT;

        len = (len + PAGE_SIZE - 1) & PAGE_MASK;
        end = start + len;

        if (end < start)
                return -EINVAL;
        if (end == start)
                return 0;

        new = mpol_new(mode, mode_flags, nmask);
        if (IS_ERR(new))
                return PTR_ERR(new);

        if (flags & MPOL_MF_LAZY)
                new->flags |= MPOL_F_MOF;

        /*
         * If we are using the default policy then operation
         * on discontinuous address spaces is okay after all
         */
        if (!new)
                flags |= MPOL_MF_DISCONTIG_OK;

        pr_debug("mbind %lx-%lx mode:%d flags:%d nodes:%lx\n",
                 start, start + len, mode, mode_flags,
                 nmask ? nodes_addr(*nmask)[0] : NUMA_NO_NODE);

        if (flags & (MPOL_MF_MOVE | MPOL_MF_MOVE_ALL)) {

                err = migrate_prep();        =========================> migrate_prep
                if (err)
                        goto mpol_out;
        }
        {
                NODEMASK_SCRATCH(scratch);
                if (scratch) {
                        down_write(&mm->mmap_sem);
                        task_lock(current);
                        err = mpol_set_nodemask(new, nmask, scratch);
                        task_unlock(current);
                        if (err)
                                up_write(&mm->mmap_sem);
                } else
                        err = -ENOMEM;
                NODEMASK_SCRATCH_FREE(scratch);
        }
        if (err)
                goto mpol_out;

        err = queue_pages_range(mm, start, end, nmask,
                          flags | MPOL_MF_INVERT, &pagelist);
        if (!err)
                err = mbind_range(mm, start, end, new);

        if (!err) {
                int nr_failed = 0;

                if (!list_empty(&pagelist)) {
                        WARN_ON_ONCE(flags & MPOL_MF_LAZY);
                        nr_failed = migrate_pages(&pagelist, new_page, NULL,
                                start, MIGRATE_SYNC, MR_MEMPOLICY_MBIND);
                        if (nr_failed)
                                putback_movable_pages(&pagelist);
                }

                if (nr_failed && (flags & MPOL_MF_STRICT))
                        err = -EIO;
        } else
                putback_movable_pages(&pagelist);

        up_write(&mm->mmap_sem);
 mpol_out:
        mpol_put(new);
        return err;
}

----------------------------------------------------------------------------------------------------------------

./mm/migrate.c:55:int migrate_prep(void)


/*
 * migrate_prep() needs to be called before we start compiling a list of pages
 * to be migrated using isolate_lru_page(). If scheduling work on other CPUs is
 * undesirable, use migrate_prep_local()
 */
int migrate_prep(void)
{
        /*
         * Clear the LRU lists so pages can be isolated.
         * Note that pages may be moved off the LRU after we have
         * drained them. Those pages will fail to migrate like other
         * pages that may be busy.
         */
        lru_add_drain_all();    ============================================>   lru_add_drain_all

        return 0;
}

----------------------------------------------------------------------------------------------------------------
./mm/swap.c:870:void lru_add_drain_all(void)

void lru_add_drain_all(void)
{
        static DEFINE_MUTEX(lock);
        static struct cpumask has_work;
        int cpu;

        mutex_lock(&lock);           ==================>   mutex_lock
        get_online_cpus();
        cpumask_clear(&has_work);

        for_each_online_cpu(cpu) {
                struct work_struct *work = &per_cpu(lru_add_drain_work, cpu);

                if (pagevec_count(&per_cpu(lru_add_pvec, cpu)) ||
                    pagevec_count(&per_cpu(lru_rotate_pvecs, cpu)) ||
                    pagevec_count(&per_cpu(lru_deactivate_file_pvecs, cpu)) ||
                    need_activate_page_drain(cpu)) {
                        INIT_WORK(work, lru_add_drain_per_cpu);
                        schedule_work_on(cpu, work);
                        cpumask_set_cpu(cpu, &has_work);
                }
        }

        for_each_cpu(cpu, &has_work)
                flush_work(&per_cpu(lru_add_drain_work, cpu));

        put_online_cpus();
        mutex_unlock(&lock);
}

----------------------------------------------------------------------------------------------------------------

./kernel/locking/mutex.c:102:	__mutex_fastpath_lock(&lock->count, __mutex_lock_slowpath);


/**
 * mutex_lock - acquire the mutex
 * @lock: the mutex to be acquired
 *
 * Lock the mutex exclusively for this task. If the mutex is not
 * available right now, it will sleep until it can get it.
 *
 * The mutex must later on be released by the same task that
 * acquired it. Recursive locking is not allowed. The task
 * may not exit without first unlocking the mutex. Also, kernel
 * memory where the mutex resides must not be freed with
 * the mutex still locked. The mutex must first be initialized
 * (or statically defined) before it can be locked. memset()-ing
 * the mutex to 0 is not allowed.
 *
 * ( The CONFIG_DEBUG_MUTEXES .config option turns on debugging
 *   checks that will enforce the restrictions and will also do
 *   deadlock debugging. )
 *
 * This function is similar to (but not equivalent to) down().
 */
void __sched mutex_lock(struct mutex *lock)
{
        might_sleep();
        /*
         * The locking fastpath is the 1->0 transition from
         * 'unlocked' into 'locked' state.
         */
        __mutex_fastpath_lock(&lock->count, __mutex_lock_slowpath);
        mutex_set_owner(lock);
}


----------------------------------------------------------------------------------------------------------------
./kernel/locking/mutex.c

__visible void __sched
__mutex_lock_slowpath(atomic_t *lock_count)
{
        struct mutex *lock = container_of(lock_count, struct mutex, count);

        __mutex_lock_common(lock, TASK_UNINTERRUPTIBLE, 0,       ==========> __mutex_lock_common
                            NULL, _RET_IP_, NULL, 0);
}



----------------------------------------------------------------------------------------------------------------
./kernel/locking/mutex.c:582:		schedule_preempt_disabled();

/*
 * Lock a mutex (possibly interruptible), slowpath:
 */
static __always_inline int __sched
__mutex_lock_common(struct mutex *lock, long state, unsigned int subclass,
                    struct lockdep_map *nest_lock, unsigned long ip,
                    struct ww_acquire_ctx *ww_ctx, const bool use_ww_ctx)
{
        struct task_struct *task = current;
        struct mutex_waiter waiter;
        unsigned long flags;
        int ret;

        if (use_ww_ctx) {
                struct ww_mutex *ww = container_of(lock, struct ww_mutex, base);
                if (unlikely(ww_ctx == READ_ONCE(ww->ctx)))
                        return -EALREADY;
        }

        preempt_disable();
        mutex_acquire_nest(&lock->dep_map, subclass, 0, nest_lock, ip);

        if (mutex_optimistic_spin(lock, ww_ctx, use_ww_ctx)) {
                /* got the lock, yay! */
                preempt_enable();
                return 0;
        }

        spin_lock_mutex(&lock->wait_lock, flags);

        /*
         * Once more, try to acquire the lock. Only try-lock the mutex if
         * it is unlocked to reduce unnecessary xchg() operations.
         */
        if (!mutex_is_locked(lock) &&
            (atomic_xchg_acquire(&lock->count, 0) == 1))
                goto skip_wait;

        debug_mutex_lock_common(lock, &waiter);
        debug_mutex_add_waiter(lock, &waiter, task_thread_info(task));

        /* add waiting tasks to the end of the waitqueue (FIFO): */
        list_add_tail(&waiter.list, &lock->wait_list);
        waiter.task = task;

        lock_contended(&lock->dep_map, ip);

        for (;;) {
                /*
                 * Lets try to take the lock again - this is needed even if
                 * we get here for the first time (shortly after failing to
                 * acquire the lock), to make sure that we get a wakeup once
                 * it's unlocked. Later on, if we sleep, this is the
                 * operation that gives us the lock. We xchg it to -1, so
                 * that when we release the lock, we properly wake up the
                 * other waiters. We only attempt the xchg if the count is
                 * non-negative in order to avoid unnecessary xchg operations:
                 */
                if (atomic_read(&lock->count) >= 0 &&
                    (atomic_xchg_acquire(&lock->count, -1) == 1))
                        break;

                /*
                 * got a signal? (This code gets eliminated in the
                 * TASK_UNINTERRUPTIBLE case.)
                 */
                if (unlikely(signal_pending_state(state, task))) {
                        ret = -EINTR;
                        goto err;
                }

                if (use_ww_ctx && ww_ctx->acquired > 0) {
                        ret = __ww_mutex_lock_check_stamp(lock, ww_ctx);
                        if (ret)
                                goto err;
                }

                __set_task_state(task, state);

                /* didn't get the lock, go to sleep: */
                spin_unlock_mutex(&lock->wait_lock, flags);
                schedule_preempt_disabled();        =====================> schedule_preempt_disabled
                spin_lock_mutex(&lock->wait_lock, flags);
        }
        __set_task_state(task, TASK_RUNNING);

        mutex_remove_waiter(lock, &waiter, current_thread_info());
        /* set it to 0 if there are no waiters left: */
        if (likely(list_empty(&lock->wait_list)))
                atomic_set(&lock->count, 0);
        debug_mutex_free_waiter(&waiter);

skip_wait:
        /* got the lock - cleanup and rejoice! */
        lock_acquired(&lock->dep_map, ip);
        mutex_set_owner(lock);

        if (use_ww_ctx) {
                struct ww_mutex *ww = container_of(lock, struct ww_mutex, base);
                ww_mutex_set_context_slowpath(ww, ww_ctx);
        }

        spin_unlock_mutex(&lock->wait_lock, flags);
        preempt_enable();
        return 0;

err:
        mutex_remove_waiter(lock, &waiter, task_thread_info(task));
        spin_unlock_mutex(&lock->wait_lock, flags);
        debug_mutex_free_waiter(&waiter);
        mutex_release(&lock->dep_map, 1, ip);
        preempt_enable();
        return ret;
}

----------------------------------------------------------------------------------------------------------------

./kernel/sched/core.c:3265:void __sched schedule_preempt_disabled(void)

 * schedule_preempt_disabled - called with preemption disabled
 *
 * Returns with preemption disabled. Note: preempt_count must be 1
 */
void __sched schedule_preempt_disabled(void)
{
        sched_preempt_enable_no_resched();
        schedule();                    =========================>   schedule
        preempt_disable();
}

----------------------------------------------------------------------------------------------------------------

./kernel/sched/core.c

asmlinkage __visible void __sched schedule(void)
{
        struct task_struct *tsk = current;

        sched_submit_work(tsk);
        do {
                preempt_disable();
                __schedule(false);
                sched_preempt_enable_no_resched();
        } while (need_resched());
}
EXPORT_SYMBOL(schedule);

----------------------------------------------------------------------------------------------------------------

2018-04-19T16:51:35.672474+00:00 compute-0-3 kernel: [ 1800.762177] INFO: task qemu-system-x86:39347 blocked for more than 120 seconds.
2018-04-19T16:51:35.672474+00:00 compute-0-3 kernel: [ 1800.762178]       Tainted: G           OE   4.4.0-91-generic #114~14.04.1-Ubuntu
2018-04-19T16:51:35.672475+00:00 compute-0-3 kernel: [ 1800.762179] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
2018-04-19T16:51:35.672475+00:00 compute-0-3 kernel: [ 1800.762179] qemu-system-x86 D ffff881015cdfd78     0 39347      1 0x00000084
2018-04-19T16:51:35.672476+00:00 compute-0-3 kernel: [ 1800.762181]  ffff881015cdfd78 ffff88028f137000 ffff88100db3e200 ffff881015ce0000
2018-04-19T16:51:35.672477+00:00 compute-0-3 kernel: [ 1800.762183]  ffffffff81e69ea4 ffff88100db3e200 00000000ffffffff ffffffff81e69ea8
2018-04-19T16:51:35.672478+00:00 compute-0-3 kernel: [ 1800.762184]  ffff881015cdfd90 ffffffff818094b5 ffffffff81e69ea0 ffff881015cdfda0
2018-04-19T16:51:35.672478+00:00 compute-0-3 kernel: [ 1800.762185] Call Trace:
2018-04-19T16:51:35.672479+00:00 compute-0-3 kernel: [ 1800.762187]  [<ffffffff818094b5>] schedule+0x35/0x80
2018-04-19T16:51:35.672479+00:00 compute-0-3 kernel: [ 1800.762189]  [<ffffffff8180974e>] schedule_preempt_disabled+0xe/0x10
2018-04-19T16:51:35.672480+00:00 compute-0-3 kernel: [ 1800.762190]  [<ffffffff8180afb5>] __mutex_lock_slowpath+0x95/0x110
2018-04-19T16:51:35.672481+00:00 compute-0-3 kernel: [ 1800.762192]  [<ffffffff811b487e>] ? handle_pte_fault+0xbae/0x1430
2018-04-19T16:51:35.672482+00:00 compute-0-3 kernel: [ 1800.762193]  [<ffffffff8180b04f>] mutex_lock+0x1f/0x2f
2018-04-19T16:51:35.672482+00:00 compute-0-3 kernel: [ 1800.762195]  [<ffffffff81194472>] lru_add_drain_all+0x32/0x160
2018-04-19T16:51:35.672483+00:00 compute-0-3 kernel: [ 1800.762196]  [<ffffffff811e59be>] migrate_prep+0xe/0x20
2018-04-19T16:51:35.672483+00:00 compute-0-3 kernel: [ 1800.762197]  [<ffffffff811d6aab>] do_mbind+0x19b/0x560
2018-04-19T16:51:35.672484+00:00 compute-0-3 kernel: [ 1800.762199]  [<ffffffff81003176>] ? do_audit_syscall_entry+0x66/0x70
2018-04-19T16:51:35.672485+00:00 compute-0-3 kernel: [ 1800.762200]  [<ffffffff811d7014>] SyS_mbind+0x84/0xa0
2018-04-19T16:51:35.672486+00:00 compute-0-3 kernel: [ 1800.762202]  [<ffffffff8180cd36>] entry_SYSCALL_64_fastpath+0x16/0x75
