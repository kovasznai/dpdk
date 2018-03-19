
================ENTRY=======================================================
dequeue_huge_page_node
1519960386578:qemu-system-x86(188689)[init(1)]
page 0xffffea007e000000 _count 1 flags 17fff8000004000 mapping 0x0 _mapcount -1
----------------USER------------------
 0x563b78574f66 : os_mem_prealloc+0xf6/0x1a0 [/usr/bin/qemu-system-x86_64]
 0x563b7836a577 : tpm_backend_thread_end+0x6d7/0xdb0 [/usr/bin/qemu-system-x86_64]
 0x563b7835265e : object_add+0x16e/0x210 [/usr/bin/qemu-system-x86_64]
 0x563b7833f1e4 : dma_acct_start+0xcb4/0x2030 [/usr/bin/qemu-system-x86_64]
 0x563b7858454a : qemu_opts_foreach+0x6a/0xc0 [/usr/bin/qemu-system-x86_64]
 0x563b7820d2cb : main+0xcbb/0x81c8 [/usr/bin/qemu-system-x86_64]
 0x7f6c3fb27f45 : __libc_start_main+0xf5/0x1e0 [/lib/x86_64-linux-gnu/libc-2.19.so]
 0x563b78214801 : _start+0x29/0x1db8 [/usr/bin/qemu-system-x86_64]

---------------KERNEL-----------------
Returning from:  0xffffffff811cb8f0 : dequeue_huge_page_node+0x0/0xe0 [kernel]
Returning to  :  0xffffffff811ce68f : alloc_huge_page+0x29f/0x3f0 [kernel]
 0xffffffff811d0838 : hugetlb_fault+0x2e8/0x7d0 [kernel]
 0xffffffff811b3786 : handle_mm_fault+0x486/0x540 [kernel]
 0xffffffff81067c0a : __do_page_fault+0x19a/0x430 [kernel]
 0xffffffff81067ec2 : do_page_fault+0x22/0x30 [kernel]
 0xffffffff817fc678 : page_fault+0x28/0x30 [kernel]
dequeue_huge_page_node
================EXIT========================================================






================ENTRY=======================================================
free_huge_page
1519961627178:vhost_thread1(188271)[monitor(188268)]
page 0xffffea007e000000 _count 0 flags 17fff8000004004 mapping 0x0 _mapcount -1
----------------USER------------------
 0x7ff7fb5f740d : __close_nocancel+0x24/0x57 [/lib/x86_64-linux-gnu/libpthread-2.19.so]
 0x55fff1 : user_destroy_device+0x141/0x170 [/usr/sbin/ovs-vswitchd]
 0x5517a0 : vserver_message_handler+0x1a0/0x550 [/usr/sbin/ovs-vswitchd]

---------------KERNEL-----------------
 0xffffffff811cced0 : free_huge_page+0x0/0x210 [kernel]
 0xffffffff81190b1b : __put_compound_page+0x2b/0x30 [kernel]
 0xffffffff81190b56 : put_compound_page+0x36/0x1a0 [kernel]
 0xffffffff81190cdd : put_page+0x1d/0x50 [kernel]
 0xffffffff812e7098 : remove_inode_hugepages+0x2a8/0x330 [kernel]
 0xffffffff812e713e : hugetlbfs_evict_inode+0x1e/0x40 [kernel]
 0xffffffff8121820e : evict+0xbe/0x1a0 [kernel]
 0xffffffff81218eab : iput+0x19b/0x200 [kernel]
 0xffffffff812147dc : __dentry_kill+0x17c/0x1e0 [kernel]
 0xffffffff812149e9 : dput+0x1a9/0x210 [kernel]
 0xffffffff811ffda8 : __fput+0x188/0x210 [kernel]
 0xffffffff811ffe6e : ____fput+0xe/0x10 [kernel]
 0xffffffff81099fc6 : task_work_run+0x86/0xb0 [kernel]
 0xffffffff81078806 : exit_to_usermode_loop+0x73/0xa2 [kernel]
 0xffffffff81003a6e : syscall_return_slowpath+0x4e/0x60 [kernel]
 0xffffffff817fa658 : int_ret_from_sys_call+0x25/0x8f [kernel]
free_huge_page
================EXIT========================================================





================ENTRY=======================================================
dequeue_huge_page_node
1519960386578:qemu-system-x86(188689)[init(1)]
page 0xffffea007e000000 _count 1 flags 17fff8000004000 mapping 0x0 _mapcount -1
----------------USER------------------
 0x563b78574f66 : os_mem_prealloc+0xf6/0x1a0 [/usr/bin/qemu-system-x86_64]
 0x563b7836a577 : tpm_backend_thread_end+0x6d7/0xdb0 [/usr/bin/qemu-system-x86_64]
 0x563b7835265e : object_add+0x16e/0x210 [/usr/bin/qemu-system-x86_64]
 0x563b7833f1e4 : dma_acct_start+0xcb4/0x2030 [/usr/bin/qemu-system-x86_64]
 0x563b7858454a : qemu_opts_foreach+0x6a/0xc0 [/usr/bin/qemu-system-x86_64]
 0x563b7820d2cb : main+0xcbb/0x81c8 [/usr/bin/qemu-system-x86_64]
 0x7f6c3fb27f45 : __libc_start_main+0xf5/0x1e0 [/lib/x86_64-linux-gnu/libc-2.19.so]
 0x563b78214801 : _start+0x29/0x1db8 [/usr/bin/qemu-system-x86_64]

---------------KERNEL-----------------
Returning from:  0xffffffff811cb8f0 : dequeue_huge_page_node+0x0/0xe0 [kernel]
Returning to  :  0xffffffff811ce68f : alloc_huge_page+0x29f/0x3f0 [kernel]
 0xffffffff811d0838 : hugetlb_fault+0x2e8/0x7d0 [kernel]
 0xffffffff811b3786 : handle_mm_fault+0x486/0x540 [kernel]
 0xffffffff81067c0a : __do_page_fault+0x19a/0x430 [kernel]
 0xffffffff81067ec2 : do_page_fault+0x22/0x30 [kernel]
 0xffffffff817fc678 : page_fault+0x28/0x30 [kernel]
dequeue_huge_page_node
================EXIT========================================================



###################################################################################################





The closest OVS and DPDK upstream versions in Ericssons OVS and DPDK is the following: 

DPDK version 2.2, last upstream commit seen from Ericsson DPDK is: 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
commit a38e5ec15e3fe615b94f3cc5edca5974dab325ab 
Author: Thomas Monjalon <thomas.monjalon@6wind.com> 
Date: Tue Dec 15 17:42:32 2015 +0100 

version: 2.2.0 

Signed-off-by: Thomas Monjalon <thomas.monjalon@6wind.com> 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 


Openvswitch version 2.5.1, last upstream commit seen from Ericsson Openvswitch is: 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
commit 92a623b9457f254df74fb219c9982e312603fbd7 
Author: Jesse Gross <jesse@kernel.org> 
Date: Thu Aug 18 15:45:25 2016 -0700 

match: Only print external tunnel flags. 

changelog update for branch-2.5 uplift 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 






###################################################################################################

cat Ericsson_OVS_post_migration/daemon.log_processed | grep "VHOST_CONFIG" 

 VHOST_CONFIG: read message VHOST_USER_SET_VRING_ENABLE, 2
 VHOST_CONFIG: set queue enable: 1 to qp idx: 1
 VHOST_CONFIG: read message VHOST_USER_SET_VRING_ADDR, 0
 VHOST_CONFIG: read message VHOST_USER_SET_FEATURES, 1
 VHOST_CONFIG: read message VHOST_USER_SET_FEATURES, 2



 VHOST_CONFIG: read message VHOST_USER_SET_VRING_KICK, 0
 VHOST_CONFIG: vring kick idx:1 file:249
 VHOST_CONFIG: virtio is now ready for processing.

 VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
 VHOST_CONFIG: vring call idx:1 file:256

 VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
 VHOST_CONFIG: vring base idx:0 file:0

 VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
 VHOST_CONFIG: vring base idx:1 file:0


 VHOST_CONFIG: recvmsg failed
 VHOST_CONFIG: vhost peer closed 0


=====================================================================================================
CHECK VIRTIO IS READY

 VHOST_CONFIG: read message VHOST_USER_SET_VRING_KICK, 0
 VHOST_CONFIG: vring kick idx:1 file:249
 VHOST_CONFIG: virtio is now ready for processing.

./lib/librte_vhost/vhost_user/vhost-net-user.c:416


/* callback when there is message on the connfd */
static void
vserver_message_handler(int connfd, void *dat, int *remove)
{
        struct vhost_device_ctx ctx;
        struct connfd_ctx *cfd_ctx = (struct connfd_ctx *)dat;
        struct VhostUserMsg msg;
        uint64_t features;
        int ret;

        ctx.fh = cfd_ctx->fh;
        ret = read_vhost_message(connfd, &msg);              --------------->    read_vhost_message   
        if (ret <= 0 || msg.request >= VHOST_USER_MAX) {
                if (ret < 0)
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "vhost read message failed\n");
                else if (ret == 0)
                        RTE_LOG(INFO, VHOST_CONFIG,
                                "vhost peer closed\n");
                else
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "vhost read incorrect message\n");

                close(connfd);
                *remove = 1;
                free(cfd_ctx);
                user_destroy_device(ctx);        --------------->    user_destroy_device
                ops->destroy_device(ctx);

                return;
        }

        RTE_LOG(INFO, VHOST_CONFIG, "read message %s\n",       ------------>   VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
                vhost_message_str[msg.request]);                               VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
        switch (msg.request) {
        case VHOST_USER_GET_FEATURES:
                ret = ops->get_features(ctx, &features);
                msg.payload.u64 = features;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;
        case VHOST_USER_SET_FEATURES:
                features = msg.payload.u64;
                ops->set_features(ctx, &features);
                break;

        case VHOST_USER_GET_PROTOCOL_FEATURES:
                msg.payload.u64 = VHOST_USER_PROTOCOL_FEATURES;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;
        case VHOST_USER_SET_PROTOCOL_FEATURES:
                user_set_protocol_features(ctx, msg.payload.u64);
                break;

        case VHOST_USER_SET_OWNER:
                ops->set_owner(ctx);
                break;
        case VHOST_USER_RESET_OWNER:
                ops->reset_owner(ctx);
                break;

        case VHOST_USER_SET_MEM_TABLE:
                user_set_mem_table(ctx, &msg);
                break;

        case VHOST_USER_SET_LOG_BASE:
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented.\n");
                break;

        case VHOST_USER_SET_LOG_FD:
                close(msg.fds[0]);
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented.\n");
                break;

        case VHOST_USER_SET_VRING_NUM:
                ops->set_vring_num(ctx, &msg.payload.state);
                break;
        case VHOST_USER_SET_VRING_ADDR:
                ops->set_vring_addr(ctx, &msg.payload.addr);
                break;
        case VHOST_USER_SET_VRING_BASE:
                ops->set_vring_base(ctx, &msg.payload.state);
                break;

        case VHOST_USER_GET_VRING_BASE:                          ------------>  VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
                ret = user_get_vring_base(ctx, &msg.payload.state);
                msg.size = sizeof(msg.payload.state);
                send_vhost_message(connfd, &msg);
                break;

        case VHOST_USER_SET_VRING_KICK:
                user_set_vring_kick(ctx, &msg);          -------------> user_set_vring_kick
                break;
        case VHOST_USER_SET_VRING_CALL:                          ------------>   VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
                user_set_vring_call(ctx, &msg);
                break;

        case VHOST_USER_SET_VRING_ERR:
                if (!(msg.payload.u64 & VHOST_USER_VRING_NOFD_MASK))
                        close(msg.fds[0]);
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented\n");
                break;

        case VHOST_USER_GET_QUEUE_NUM:
                msg.payload.u64 = VHOST_MAX_QUEUE_PAIRS;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;

        case VHOST_USER_SET_VRING_ENABLE:
                user_set_vring_enable(ctx, &msg.payload.state);
                break;

        default:
                break;

        }
}


----------------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/virtio-net-user.c:279

/*
 *  In vhost-user, when we receive kick message, will test whether virtio
 *  device is ready for packet processing.
 */
void
user_set_vring_kick(struct vhost_device_ctx ctx, struct VhostUserMsg *pmsg)
{
        struct vhost_vring_file file;
        struct virtio_net *dev = get_device(ctx);

        file.index = pmsg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
        if (pmsg->payload.u64 & VHOST_USER_VRING_NOFD_MASK)
                file.fd = -1;
        else
                file.fd = pmsg->fds[0];
        RTE_LOG(INFO, VHOST_CONFIG,
                "vring kick idx:%d file:%d\n", file.index, file.fd);        =============>    VHOST_CONFIG: vring kick idx:1 file:249
        ops->set_vring_kick(ctx, &file);

        if (virtio_is_ready(dev) &&                    ----------> virtio_is_ready
                !(dev->flags & VIRTIO_DEV_RUNNING))
                        notify_ops->new_device(dev);
}

----------------------------------------------------------------------------------------------


./lib/librte_vhost/vhost_user/virtio-net-user.c:240

static int
virtio_is_ready(struct virtio_net *dev)
{
        struct vhost_virtqueue *rvq, *tvq;
        uint32_t i;

        for (i = 0; i < dev->virt_qp_nb; i++) {
                rvq = dev->virtqueue[i * VIRTIO_QNUM + VIRTIO_RXQ];
                tvq = dev->virtqueue[i * VIRTIO_QNUM + VIRTIO_TXQ];

                if (!vq_is_ready(rvq) || !vq_is_ready(tvq)) {
                        RTE_LOG(INFO, VHOST_CONFIG,
                                "virtio is not ready for processing.\n");
                        return 0;
                }
        }

        RTE_LOG(INFO, VHOST_CONFIG,
                "virtio is now ready for processing.\n");        ==================>    VHOST_CONFIG: virtio is now ready for processing.
        return 1;
}



=====================================================================================================
READ VHOST MESSAGE

./lib/librte_vhost/vhost_user/vhost-net-user.c

/* callback when there is message on the connfd */
static void
vserver_message_handler(int connfd, void *dat, int *remove)
{
        struct vhost_device_ctx ctx;
        struct connfd_ctx *cfd_ctx = (struct connfd_ctx *)dat;
        struct VhostUserMsg msg;
        uint64_t features;
        int ret;

        ctx.fh = cfd_ctx->fh;
        ret = read_vhost_message(connfd, &msg);              --------------->    read_vhost_message   
        if (ret <= 0 || msg.request >= VHOST_USER_MAX) {
                if (ret < 0)
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "vhost read message failed\n");
                else if (ret == 0)
                        RTE_LOG(INFO, VHOST_CONFIG,
                                "vhost peer closed\n");
                else
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "vhost read incorrect message\n");

                close(connfd);
                *remove = 1;
                free(cfd_ctx);
                user_destroy_device(ctx);
                ops->destroy_device(ctx);

                return;
        }

        RTE_LOG(INFO, VHOST_CONFIG, "read message %s\n",
                vhost_message_str[msg.request]);
        switch (msg.request) {
        case VHOST_USER_GET_FEATURES:
                ret = ops->get_features(ctx, &features);
                msg.payload.u64 = features;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;
        case VHOST_USER_SET_FEATURES:
                features = msg.payload.u64;
                ops->set_features(ctx, &features);
                break;

        case VHOST_USER_GET_PROTOCOL_FEATURES:
                msg.payload.u64 = VHOST_USER_PROTOCOL_FEATURES;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;
        case VHOST_USER_SET_PROTOCOL_FEATURES:
                user_set_protocol_features(ctx, msg.payload.u64);
                break;

        case VHOST_USER_SET_OWNER:
                ops->set_owner(ctx);
                break;
        case VHOST_USER_RESET_OWNER:
                ops->reset_owner(ctx);
                break;

        case VHOST_USER_SET_MEM_TABLE:
                user_set_mem_table(ctx, &msg);
                break;

        case VHOST_USER_SET_LOG_BASE:
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented.\n");
                break;

        case VHOST_USER_SET_LOG_FD:
                close(msg.fds[0]);
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented.\n");
                break;

        case VHOST_USER_SET_VRING_NUM:
                ops->set_vring_num(ctx, &msg.payload.state);
                break;
        case VHOST_USER_SET_VRING_ADDR:
                ops->set_vring_addr(ctx, &msg.payload.addr);
                break;
        case VHOST_USER_SET_VRING_BASE:
                ops->set_vring_base(ctx, &msg.payload.state);
                break;

        case VHOST_USER_GET_VRING_BASE:
                ret = user_get_vring_base(ctx, &msg.payload.state);
                msg.size = sizeof(msg.payload.state);
                send_vhost_message(connfd, &msg);
                break;

        case VHOST_USER_SET_VRING_KICK:
                user_set_vring_kick(ctx, &msg);
                break;
        case VHOST_USER_SET_VRING_CALL:                          ------------>   VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
                user_set_vring_call(ctx, &msg);
                break;

        case VHOST_USER_SET_VRING_ERR:
                if (!(msg.payload.u64 & VHOST_USER_VRING_NOFD_MASK))
                        close(msg.fds[0]);
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented\n");
                break;

        case VHOST_USER_GET_QUEUE_NUM:
                msg.payload.u64 = VHOST_MAX_QUEUE_PAIRS;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;

        case VHOST_USER_SET_VRING_ENABLE:
                user_set_vring_enable(ctx, &msg.payload.state);
                break;

        default:
                break;

        }
}


----------------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/vhost-net-user.c:192

/* return bytes# of read on success or negative val on failure. */
static int
read_vhost_message(int sockfd, struct VhostUserMsg *msg)
{
        int ret;

        ret = read_fd_message(sockfd, (char *)msg, VHOST_USER_HDR_SIZE,    ------->  read_fd_message
                msg->fds, VHOST_MEMORY_MAX_NREGIONS);
        if (ret <= 0)
                return ret;

        if (msg && msg->size) {
                if (msg->size > sizeof(msg->payload)) {
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "invalid msg size: %d\n", msg->size);
                        return -1;
                }
                ret = read(sockfd, &msg->payload, msg->size);
                if (ret <= 0)
                        return ret;
                if (ret != (int)msg->size) {
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "read control message failed\n");
                        return -1;
                }
        }

        return ret;
}


------------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/vhost-net-user.c

/* return bytes# of read on success or negative val on failure. */
static int
read_fd_message(int sockfd, char *buf, int buflen, int *fds, int fd_num)
{
        struct iovec iov;
        struct msghdr msgh;
        size_t fdsize = fd_num * sizeof(int);
        char control[CMSG_SPACE(fdsize)];
        struct cmsghdr *cmsg;
        int ret;

        memset(&msgh, 0, sizeof(msgh));
        iov.iov_base = buf;
        iov.iov_len  = buflen;

        msgh.msg_iov = &iov;
        msgh.msg_iovlen = 1;
        msgh.msg_control = control;
        msgh.msg_controllen = sizeof(control);

        ret = recvmsg(sockfd, &msgh, 0);
        if (ret <= 0) {
                RTE_LOG(ERR, VHOST_CONFIG, "recvmsg failed\n");       ------------>   VHOST_CONFIG: recvmsg failed
                return ret;
        }

        if (msgh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
                RTE_LOG(ERR, VHOST_CONFIG, "truncted msg\n");
                return -1;
        }

        for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
                cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
                if ((cmsg->cmsg_level == SOL_SOCKET) &&
                        (cmsg->cmsg_type == SCM_RIGHTS)) {
                        memcpy(fds, CMSG_DATA(cmsg), fdsize);
                        break;
                }
        }

        return ret;
}

=====================================================================================================
SET VRING CALL

 VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
 VHOST_CONFIG: vring call idx:1 file:256


./lib/librte_vhost/vhost_user/vhost-net-user.c

/* callback when there is message on the connfd */
static void
vserver_message_handler(int connfd, void *dat, int *remove)
{
        struct vhost_device_ctx ctx;
        struct connfd_ctx *cfd_ctx = (struct connfd_ctx *)dat;
        struct VhostUserMsg msg;
        uint64_t features;
        int ret;

        ctx.fh = cfd_ctx->fh;
        ret = read_vhost_message(connfd, &msg);
        if (ret <= 0 || msg.request >= VHOST_USER_MAX) {
                if (ret < 0)
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "vhost read message failed\n");
                else if (ret == 0)
                        RTE_LOG(INFO, VHOST_CONFIG,
                                "vhost peer closed\n");
                else
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "vhost read incorrect message\n");

                close(connfd);
                *remove = 1;
                free(cfd_ctx);
                user_destroy_device(ctx);
                ops->destroy_device(ctx);

                return;
        }

        RTE_LOG(INFO, VHOST_CONFIG, "read message %s\n",       ------------>   VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
                vhost_message_str[msg.request]);  
        switch (msg.request) {
        case VHOST_USER_GET_FEATURES:
                ret = ops->get_features(ctx, &features);
                msg.payload.u64 = features;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;
        case VHOST_USER_SET_FEATURES:
                features = msg.payload.u64;
                ops->set_features(ctx, &features);
                break;

        case VHOST_USER_GET_PROTOCOL_FEATURES:
                msg.payload.u64 = VHOST_USER_PROTOCOL_FEATURES;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;
        case VHOST_USER_SET_PROTOCOL_FEATURES:
                user_set_protocol_features(ctx, msg.payload.u64);
                break;

        case VHOST_USER_SET_OWNER:
                ops->set_owner(ctx);
                break;
        case VHOST_USER_RESET_OWNER:
                ops->reset_owner(ctx);
                break;

        case VHOST_USER_SET_MEM_TABLE:
                user_set_mem_table(ctx, &msg);
                break;

        case VHOST_USER_SET_LOG_BASE:
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented.\n");
                break;

        case VHOST_USER_SET_LOG_FD:
                close(msg.fds[0]);
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented.\n");
                break;

        case VHOST_USER_SET_VRING_NUM:
                ops->set_vring_num(ctx, &msg.payload.state);
                break;
        case VHOST_USER_SET_VRING_ADDR:
                ops->set_vring_addr(ctx, &msg.payload.addr);
                break;
        case VHOST_USER_SET_VRING_BASE:
                ops->set_vring_base(ctx, &msg.payload.state);
                break;

        case VHOST_USER_GET_VRING_BASE:
                ret = user_get_vring_base(ctx, &msg.payload.state);
                msg.size = sizeof(msg.payload.state);
                send_vhost_message(connfd, &msg);
                break;

        case VHOST_USER_SET_VRING_KICK:
                user_set_vring_kick(ctx, &msg);
                break;
        case VHOST_USER_SET_VRING_CALL:                          ------------>   VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
                user_set_vring_call(ctx, &msg);
                break;

        case VHOST_USER_SET_VRING_ERR:
                if (!(msg.payload.u64 & VHOST_USER_VRING_NOFD_MASK))
                        close(msg.fds[0]);
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented\n");
                break;

        case VHOST_USER_GET_QUEUE_NUM:
                msg.payload.u64 = VHOST_MAX_QUEUE_PAIRS;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;

        case VHOST_USER_SET_VRING_ENABLE:
                user_set_vring_enable(ctx, &msg.payload.state);
                break;

        default:
                break;

        }
}


------------------------------------------------------------------------------------------
ls  ./lib/librte_vhost/vhost_user

fd_man.c  
fd_man.h  
vhost-net-user.c  
vhost-net-user.h  
virtio-net-user.c  
virtio-net-user.h



./lib/librte_vhost/vhost_user/virtio-net-user.c:245

void
user_set_vring_call(struct vhost_device_ctx ctx, struct VhostUserMsg *pmsg)
{
        struct vhost_vring_file file;

        file.index = pmsg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
        if (pmsg->payload.u64 & VHOST_USER_VRING_NOFD_MASK)
                file.fd = -1;
        else
                file.fd = pmsg->fds[0];
        RTE_LOG(INFO, VHOST_CONFIG,
                "vring call idx:%d file:%d\n", file.index, file.fd);
        ops->set_vring_call(ctx, &file);                      --------->   set_vring_call
}



------------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/vhost-net-user.c:454


/**
 * Creates and initialise the vhost server.
 */
int
rte_vhost_driver_register(const char *path)
{
        struct vhost_server *vserver;

        pthread_mutex_lock(&g_vhost_server.server_mutex);
        if (ops == NULL)
                ops = get_virtio_net_callbacks();               --------->   ops

        if (g_vhost_server.vserver_cnt == MAX_VHOST_SERVER) {
                RTE_LOG(ERR, VHOST_CONFIG,
                        "error: the number of servers reaches maximum\n");
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver = calloc(sizeof(struct vhost_server), 1);
        if (vserver == NULL) {
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver->listenfd = uds_socket(path);
        if (vserver->listenfd < 0) {
                free(vserver);
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver->path = strdup(path);

        fdset_add(&g_vhost_server.fdset, vserver->listenfd,
                vserver_new_vq_conn, NULL, vserver);

        g_vhost_server.server[g_vhost_server.vserver_cnt++] = vserver;
        pthread_mutex_unlock(&g_vhost_server.server_mutex);

        return 0;
}

------------------------------------------------------------------------------------------
./lib/librte_vhost/virtio-net.c:852
/*
 * Called by main to setup callbacks when registering CUSE device.
 */
struct vhost_net_device_ops const *
get_virtio_net_callbacks(void)
{
        return &vhost_device_ops;        -------------->  vhost_device_ops
}


------------------------------------------------------------------------------------------

./lib/librte_vhost/virtio-net.c
/*
 * Function pointers are set for the device operations to allow CUSE to call
 * functions when an IOCTL, device_add or device_release is received.
 */
static const struct vhost_net_device_ops vhost_device_ops = {            <------------- vhost_device_ops
        .new_device = new_device,
        .destroy_device = destroy_device,

        .set_ifname = set_ifname,

        .get_features = get_features,
        .set_features = set_features,

        .set_vring_num = set_vring_num,
        .set_vring_addr = set_vring_addr,
        .set_vring_base = set_vring_base,
        .get_vring_base = get_vring_base,

        .set_vring_kick = set_vring_kick,
        .set_vring_call = set_vring_call,       <------------

        .set_backend = set_backend,

        .set_owner = set_owner,
        .reset_owner = reset_owner,
};


------------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/virtio-net-user.c:245

void
user_set_vring_call(struct vhost_device_ctx ctx, struct VhostUserMsg *pmsg)
{
        struct vhost_vring_file file;

        file.index = pmsg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
        if (pmsg->payload.u64 & VHOST_USER_VRING_NOFD_MASK)
                file.fd = -1;
        else
                file.fd = pmsg->fds[0];
        RTE_LOG(INFO, VHOST_CONFIG,
                "vring call idx:%d file:%d\n", file.index, file.fd);
        ops->set_vring_call(ctx, &file);                      --------->   set_vring_call
}


------------------------------------------------------------------------------------------

./lib/librte_vhost/virtio-net.c:727
/*
 * Called from CUSE IOCTL: VHOST_SET_VRING_CALL
 * The virtio device sends an eventfd to interrupt the guest. This fd gets
 * copied into our process space.
 */
static int
set_vring_call(struct vhost_device_ctx ctx, struct vhost_vring_file *file)
{
        struct virtio_net *dev;
        struct vhost_virtqueue *vq;
        uint32_t cur_qp_idx = file->index / VIRTIO_QNUM;

        dev = get_device(ctx);
        if (dev == NULL)
                return -1;

        /*
         * FIXME: VHOST_SET_VRING_CALL is the first per-vring message
         * we get, so we do vring queue pair allocation here.
         */
        if (cur_qp_idx + 1 > dev->virt_qp_nb) {
                if (alloc_vring_queue_pair(dev, cur_qp_idx) < 0)
                        return -1;
        }

        /* file->index refers to the queue index. The txq is 1, rxq is 0. */
        vq = dev->virtqueue[file->index];
        assert(vq != NULL);

        if (vq->callfd >= 0)
                close(vq->callfd);

        vq->callfd = file->fd;

        return 0;
}

------------------------------------------------------------------------------------------


./lib/librte_vhost/virtio-net.c:304


static int
alloc_vring_queue_pair(struct virtio_net *dev, uint32_t qp_idx)
{
        struct vhost_virtqueue *virtqueue = NULL;
        uint32_t virt_rx_q_idx = qp_idx * VIRTIO_QNUM + VIRTIO_RXQ;
        uint32_t virt_tx_q_idx = qp_idx * VIRTIO_QNUM + VIRTIO_TXQ;

        virtqueue = rte_malloc(NULL,
                               sizeof(struct vhost_virtqueue) * VIRTIO_QNUM, 0);
        if (virtqueue == NULL) {
                RTE_LOG(ERR, VHOST_CONFIG,
                        "Failed to allocate memory for virt qp:%d.\n", qp_idx);
                return -1;
        }

        dev->virtqueue[virt_rx_q_idx] = virtqueue;
        dev->virtqueue[virt_tx_q_idx] = virtqueue + VIRTIO_TXQ;

        init_vring_queue_pair(dev, qp_idx);

        dev->virt_qp_nb += 1;

        return 0;
}



===================================================================================

GET VRING BASE

 VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
 VHOST_CONFIG: vring base idx:0 file:0


./lib/librte_vhost/vhost_user/vhost-net-user.c


/* callback when there is message on the connfd */
static void
vserver_message_handler(int connfd, void *dat, int *remove)
{
        struct vhost_device_ctx ctx;
        struct connfd_ctx *cfd_ctx = (struct connfd_ctx *)dat;
        struct VhostUserMsg msg;
        uint64_t features;
        int ret;

        ctx.fh = cfd_ctx->fh;
        ret = read_vhost_message(connfd, &msg);              --------------->    read_vhost_message   
        if (ret <= 0 || msg.request >= VHOST_USER_MAX) {
                if (ret < 0)
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "vhost read message failed\n");
                else if (ret == 0)
                        RTE_LOG(INFO, VHOST_CONFIG,
                                "vhost peer closed\n");
                else
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "vhost read incorrect message\n");

                close(connfd);
                *remove = 1;
                free(cfd_ctx);
                user_destroy_device(ctx);        --------------->    user_destroy_device
                ops->destroy_device(ctx);

                return;
        }

        RTE_LOG(INFO, VHOST_CONFIG, "read message %s\n",       ------------>   VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
                vhost_message_str[msg.request]);
        switch (msg.request) {
        case VHOST_USER_GET_FEATURES:
                ret = ops->get_features(ctx, &features);
                msg.payload.u64 = features;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;
        case VHOST_USER_SET_FEATURES:
                features = msg.payload.u64;
                ops->set_features(ctx, &features);
                break;

        case VHOST_USER_GET_PROTOCOL_FEATURES:
                msg.payload.u64 = VHOST_USER_PROTOCOL_FEATURES;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;
        case VHOST_USER_SET_PROTOCOL_FEATURES:
                user_set_protocol_features(ctx, msg.payload.u64);
                break;

        case VHOST_USER_SET_OWNER:
                ops->set_owner(ctx);
                break;
        case VHOST_USER_RESET_OWNER:
                ops->reset_owner(ctx);
                break;

        case VHOST_USER_SET_MEM_TABLE:
                user_set_mem_table(ctx, &msg);
                break;

        case VHOST_USER_SET_LOG_BASE:
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented.\n");
                break;

        case VHOST_USER_SET_LOG_FD:
                close(msg.fds[0]);
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented.\n");
                break;

        case VHOST_USER_SET_VRING_NUM:
                ops->set_vring_num(ctx, &msg.payload.state);
                break;
        case VHOST_USER_SET_VRING_ADDR:
                ops->set_vring_addr(ctx, &msg.payload.addr);
                break;
        case VHOST_USER_SET_VRING_BASE:
                ops->set_vring_base(ctx, &msg.payload.state);
                break;

        case VHOST_USER_GET_VRING_BASE:                          ------------>  VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
                ret = user_get_vring_base(ctx, &msg.payload.state);
                msg.size = sizeof(msg.payload.state);
                send_vhost_message(connfd, &msg);
                break;

        case VHOST_USER_SET_VRING_KICK:
                user_set_vring_kick(ctx, &msg);
                break;
        case VHOST_USER_SET_VRING_CALL:
                user_set_vring_call(ctx, &msg);
                break;

        case VHOST_USER_SET_VRING_ERR:
                if (!(msg.payload.u64 & VHOST_USER_VRING_NOFD_MASK))
                        close(msg.fds[0]);
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented\n");
                break;

        case VHOST_USER_GET_QUEUE_NUM:
                msg.payload.u64 = VHOST_MAX_QUEUE_PAIRS;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;

        case VHOST_USER_SET_VRING_ENABLE:
                user_set_vring_enable(ctx, &msg.payload.state);
                break;

        default:
                break;

        }
}

------------------------------------------------------------------------------------------

 VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
 VHOST_CONFIG: vring base idx:1 file:0

./lib/librte_vhost/vhost_user/virtio-net-user.c:288


/*
 * when virtio is stopped, qemu will send us the GET_VRING_BASE message.
 */
int
user_get_vring_base(struct vhost_device_ctx ctx,
        struct vhost_vring_state *state)
{
        struct virtio_net *dev = get_device(ctx);          ---------> get_device

        if (dev == NULL)
                return -1;
        /* We have to stop the queue (virtio) if it is running. */
        if (dev->flags & VIRTIO_DEV_RUNNING)
                notify_ops->destroy_device(dev);           ------------> destroy_device

        /* Here we are safe to get the last used index */
        ops->get_vring_base(ctx, state->index, state);         -----------> get_vring_base

        RTE_LOG(INFO, VHOST_CONFIG,
                "vring base idx:%d file:%d\n", state->index, state->num);
        /*
         * Based on current qemu vhost-user implementation, this message is
         * sent and only sent in vhost_vring_stop.
         * TODO: cleanup the vring, it isn't usable since here.
         */
        if (dev->virtqueue[state->index]->kickfd >= 0) {
                close(dev->virtqueue[state->index]->kickfd);
                dev->virtqueue[state->index]->kickfd = -1;
        }

        return 0;
}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/vhost-net-user.c:419:		user_set_vring_call(ctx, &msg);



/* callback when there is message on the connfd */
static void
vserver_message_handler(int connfd, void *dat, int *remove)
{

        ret = read_vhost_message(connfd, &msg);


        RTE_LOG(INFO, VHOST_CONFIG, "read message %s\n",
                vhost_message_str[msg.request]);
        switch (msg.request) {

        case VHOST_USER_SET_VRING_CALL:
                user_set_vring_call(ctx, &msg);
                break;


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


./lib/librte_vhost/vhost_user/virtio-net-user.c:256

void
user_set_vring_call(struct vhost_device_ctx ctx, struct VhostUserMsg *pmsg)
{
        struct vhost_vring_file file;

        file.index = pmsg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
        if (pmsg->payload.u64 & VHOST_USER_VRING_NOFD_MASK)
                file.fd = -1;
        else
                file.fd = pmsg->fds[0];
        RTE_LOG(INFO, VHOST_CONFIG,
                "vring call idx:%d file:%d\n", file.index, file.fd);
        ops->set_vring_call(ctx, &file);
}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/virtio-net.c:742


/*
 * Called from CUSE IOCTL: VHOST_SET_VRING_CALL
 * The virtio device sends an eventfd to interrupt the guest. This fd gets
 * copied into our process space.
 */
static int
set_vring_call(struct vhost_device_ctx ctx, struct vhost_vring_file *file)
{
        struct virtio_net *dev;
        struct vhost_virtqueue *vq;
        uint32_t cur_qp_idx = file->index / VIRTIO_QNUM;

        dev = get_device(ctx);
        if (dev == NULL)
                return -1;

        /*
         * FIXME: VHOST_SET_VRING_CALL is the first per-vring message
         * we get, so we do vring queue pair allocation here.
         */
        if (cur_qp_idx + 1 > dev->virt_qp_nb) {
                if (alloc_vring_queue_pair(dev, cur_qp_idx) < 0)          -------------->   alloc_vring_queue_pair
                        return -1;
        }

        /* file->index refers to the queue index. The txq is 1, rxq is 0. */
        vq = dev->virtqueue[file->index];
        assert(vq != NULL);

        if (vq->callfd >= 0)
                close(vq->callfd);

        vq->callfd = file->fd;

        return 0;
}


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/virtio-net.c

static int
alloc_vring_queue_pair(struct virtio_net *dev, uint32_t qp_idx)
{
        struct vhost_virtqueue *virtqueue = NULL;
        uint32_t virt_rx_q_idx = qp_idx * VIRTIO_QNUM + VIRTIO_RXQ;
        uint32_t virt_tx_q_idx = qp_idx * VIRTIO_QNUM + VIRTIO_TXQ;

        virtqueue = rte_malloc(NULL,
                               sizeof(struct vhost_virtqueue) * VIRTIO_QNUM, 0);
        if (virtqueue == NULL) {
                RTE_LOG(ERR, VHOST_CONFIG,
                        "Failed to allocate memory for virt qp:%d.\n", qp_idx);
                return -1;
        }

        dev->virtqueue[virt_rx_q_idx] = virtqueue;
        dev->virtqueue[virt_tx_q_idx] = virtqueue + VIRTIO_TXQ;

        init_vring_queue_pair(dev, qp_idx);

        dev->virt_qp_nb += 1;

        return 0;
}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/rte_virtio_net.h
/**
 * Device structure contains all configuration information relating to the device.
 */
struct virtio_net {
        struct virtio_memory    *mem;           /**< QEMU memory and memory region information. */
        uint64_t                features;       /**< Negotiated feature set. */
        uint64_t                protocol_features;      /**< Negotiated protocol feature set. */
        uint64_t                device_fh;      /**< device identifier. */
        uint32_t                flags;          /**< Device flags. Only used to check if device is running on data core. */
#define IF_NAME_SZ (PATH_MAX > IFNAMSIZ ? PATH_MAX : IFNAMSIZ)
        char                    ifname[IF_NAME_SZ];     /**< Name of the tap device or socket path. */
        uint32_t                virt_qp_nb;     /**< number of queue pair we have allocated */
        void                    *priv;          /**< private context */
        uint64_t                reserved[64];   /**< Reserve some spaces for future extension. */
        struct vhost_virtqueue  *virtqueue[VHOST_MAX_QUEUE_PAIRS * 2];  /**< Contains all virtqueue information. */
} __rte_cache_aligned;


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

/**
 * Structure contains variables relevant to RX/TX virtqueues.
 */
struct vhost_virtqueue {
        struct vring_desc       *desc;                  /**< Virtqueue descriptor ring. */
        struct vring_avail      *avail;                 /**< Virtqueue available ring. */
        struct vring_used       *used;                  /**< Virtqueue used ring. */
        uint32_t                size;                   /**< Size of descriptor ring. */
        uint32_t                backend;                /**< Backend value to determine if device should started/stopped. */
        uint16_t                vhost_hlen;             /**< Vhost header length (varies depending on RX merge buffers. */
        volatile uint16_t       last_used_idx;          /**< Last index used on the available ring */
        volatile uint16_t       last_used_idx_res;      /**< Used for multiple devices reserving buffers. */
        int                     callfd;                 /**< Used to notify the guest (trigger interrupt). */
        int                     kickfd;                 /**< Currently unused as polling mode is enabled. */    ----------------> kickfd
        int                     enabled;
        uint64_t                reserved[16];           /**< Reserve some spaces for future extension. */
        struct buf_vector       buf_vec[BUF_VECTOR_MAX];        /**< for scatter RX. */
} __rte_cache_aligned;




~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

------------------------------------------------------------------------------------------

./lib/librte_vhost/virtio-net.c:134

/*
 * Searches the configuration core linked list and
 * retrieves the device if it exists.
 */
struct virtio_net *
get_device(struct vhost_device_ctx ctx)
{
        struct virtio_net_config_ll *ll_dev;

        ll_dev = get_config_ll_entry(ctx);

        if (ll_dev)
                return &ll_dev->dev;

        RTE_LOG(ERR, VHOST_CONFIG,
                "(%"PRIu64") Device not found in linked list.\n", ctx.fh);
        return NULL;
}



------------------------------------------------------------------------------------------

./lib/librte_vhost/virtio-net.c

/*
 * Function is called from the CUSE release function. This function will
 * cleanup the device and remove it from device configuration linked list.
 */
static void
destroy_device(struct vhost_device_ctx ctx)
{
        struct virtio_net_config_ll *ll_dev_cur_ctx, *ll_dev_last = NULL;
        struct virtio_net_config_ll *ll_dev_cur = ll_root;

        /* Find the linked list entry for the device to be removed. */
        ll_dev_cur_ctx = get_config_ll_entry(ctx);
        while (ll_dev_cur != NULL) {
                /*
                 * If the device is found or
                 * a device that doesn't exist is found then it is removed.
                 */
                if (ll_dev_cur == ll_dev_cur_ctx) {
                        /*
                         * If the device is running on a data core then call
                         * the function to remove it from the data core.
                         */
                        if ((ll_dev_cur->dev.flags & VIRTIO_DEV_RUNNING))
                                notify_ops->destroy_device(&(ll_dev_cur->dev));
                        ll_dev_cur = rm_config_ll_entry(ll_dev_cur,
                                        ll_dev_last);
                } else {
                        ll_dev_last = ll_dev_cur;
                        ll_dev_cur = ll_dev_cur->next;
                }
        }
}


------------------------------------------------------------------------------------------
./lib/librte_vhost/virtio-net.c:704

/*
 * Called from CUSE IOCTL: VHOST_GET_VRING_BASE
 * We send the virtio device our available ring last used index.
 */
static int
get_vring_base(struct vhost_device_ctx ctx, uint32_t index,
        struct vhost_vring_state *state)
{
        struct virtio_net *dev;

        dev = get_device(ctx);
        if (dev == NULL)
                return -1;

        state->index = index;
        /* State->index refers to the queue index. The txq is 1, rxq is 0. */
        state->num = dev->virtqueue[state->index]->last_used_idx;

        return 0;
}




===================================================================================

./lib/librte_vhost/rte_vhost_version.map:6


DPDK_2.0 {
        global:

        rte_vhost_dequeue_burst;
        rte_vhost_driver_callback_register;
        rte_vhost_driver_register;         <----------
        rte_vhost_driver_session_start;
        rte_vhost_enable_guest_notification;
        rte_vhost_enqueue_burst;
        rte_vhost_feature_disable;
        rte_vhost_feature_enable;
        rte_vhost_feature_get;

        local: *;
};

DPDK_2.1 {
        global:

        rte_vhost_driver_unregister;

} DPDK_2.0;



------------------------------------------------------------------------------------------

./doc/guides/prog_guide/vhost_lib.rst:46

*   Vhost driver registration

      rte_vhost_driver_register registers the vhost driver into the system.
      For vhost-cuse, character device file will be created under the /dev directory.
      Character device name is specified as the parameter.
      For vhost-user, a Unix domain socket server will be created with the parameter as the local socket path.  ===>   /var/run/openvswitch/vhue0fdfafa-c7 


------------------------------------------------------------------------------------------
http://dpdk.readthedocs.io/en/v16.04/sample_app_ug/vhost.html


For vhost cuse:

qemu-system-x86_64 ... \
-netdev tap,id=hostnet1,vhost=on,vhostfd=<open fd> \
-device virtio-net-pci, netdev=hostnet1,id=net1 \
-netdev tap,id=hostnet2,vhost=on,vhostfd=<open fd> \
-device virtio-net-pci, netdev=hostnet2,id=net1



For vhost user:

qemu-system-x86_64 ... \
-chardev socket,id=char1,path=<sock_path> \

-netdev type=vhost-user,id=hostnet1,chardev=char1 \
-device virtio-net-pci,netdev=hostnet1,id=net1 \

-chardev socket,id=char2,path=<sock_path> \        <=========== sock_path is the path for the socket file created by vhost.
-netdev type=vhost-user,id=hostnet2,chardev=char2 \

-device virtio-net-pci,netdev=hostnet2,id=net2



qemu-system-x86_64 -enable-kvm -name instance-00000522 -S -machine pc-i440fx-xenial,accel=kvm,usb=off -cpu host -m 32768 -realtime mlock=off -smp 8,sockets=4,cores=1,threads=2 -object memory-backend-file,id=ram-node0,prealloc=yes,mem-path=/mnt/huge_qemu_1G/libvirt/qemu,share=yes,size=34359738368,host-nodes=0,policy=bind -numa node,nodeid=0,cpus=0-7,memdev=ram-node0 -uuid bdc81ffb-ca45-46ee-9d41-3d2c3f4840a3 -smbios type=1,manufacturer=OpenStack Foundation,product=OpenStack Nova,version=13.0.0,serial=4c4c4544-0042-4b10-8058-c8c04f5a4732,uuid=bdc81ffb-ca45-46ee-9d41-3d2c3f4840a3,family=Virtual Machine -no-user-config -nodefaults -chardev socket,id=charmonitor,path=/var/lib/libvirt/qemu/domain-instance-00000522/monitor.sock,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=discard -no-hpet -no-shutdown -boot strict=on -device piix3-usb-uhci,id=usb,bus=pci.0,addr=0x1.0x2 -drive file=/var/lib/nova/instances/bdc81ffb-ca45-46ee-9d41-3d2c3f4840a3/disk,format=qcow2,if=none,id=drive-virtio-disk0,cache=directsync -device virtio-blk-pci,scsi=off,bus=pci.0,addr=0x4,drive=drive-virtio-disk0,id=virtio-disk0,bootindex=1 

-chardev socket,id=charnet0,path=/var/run/openvswitch/vhue0fdfafa-c7 
-netdev type=vhost-user,id=hostnet0,chardev=charnet0 
-device virtio-net-pci,netdev=hostnet0,id=net0,mac=fa:16:3e:08:c3:8d,bus=pci.0,addr=0x3 

-chardev file,id=charserial0,path=/var/lib/nova/instances/bdc81ffb-ca45-46ee-9d41-3d2c3f4840a3/console.log -device isa-serial,chardev=charserial0,id=serial0 -chardev pty,id=charserial1 -device isa-serial,chardev=charserial1,id=serial1 -device usb-tablet,id=input0 -vnc 160.6.88.55:0 -k en-us -device cirrus-vga,id=video0,bus=pci.0,addr=0x2 -device i6300esb,id=watchdog0,


------------------------------------------------------------------------------------------



path = /var/run/openvswitch/vhue0fdfafa-c7   <===== For vhost-user, a Unix domain socket server will be created with the parameter as the local socket path.




./lib/librte_vhost/vhost_user/vhost-net-user.c:448

/**
 * Creates and initialise the vhost server.
 */
int
rte_vhost_driver_register(const char *path)
{
        struct vhost_server *vserver;

        pthread_mutex_lock(&g_vhost_server.server_mutex);
        if (ops == NULL)
                ops = get_virtio_net_callbacks();

        if (g_vhost_server.vserver_cnt == MAX_VHOST_SERVER) {
                RTE_LOG(ERR, VHOST_CONFIG,
                        "error: the number of servers reaches maximum\n");
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver = calloc(sizeof(struct vhost_server), 1);
        if (vserver == NULL) {
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver->listenfd = uds_socket(path);
        if (vserver->listenfd < 0) {
                free(vserver);
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver->path = strdup(path);

        fdset_add(&g_vhost_server.fdset, vserver->listenfd,
                vserver_new_vq_conn, NULL, vserver);               --------------------->  vserver_new_vq_conn

        g_vhost_server.server[g_vhost_server.vserver_cnt++] = vserver;
        pthread_mutex_unlock(&g_vhost_server.server_mutex);

        return 0;
}



https://linux.die.net/man/3/strdup
The strdup() function returns a pointer to a new string which is a duplicate of the string s.



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/fd_man.c:142

/**
 * Register the fd in the fdset with read/write handler and context.
 */
int
fdset_add(struct fdset *pfdset, int fd, fd_cb rcb, fd_cb wcb, void *dat)
{
        int i;

        if (pfdset == NULL || fd == -1)
                return -1;

        pthread_mutex_lock(&pfdset->fd_mutex);

        /* Find a free slot in the list. */
        i = fdset_find_free_slot(pfdset);
        if (i == -1) {
                pthread_mutex_unlock(&pfdset->fd_mutex);
                return -2;
        }

        fdset_add_fd(pfdset, i, fd, rcb, wcb, dat);          fd - filedescriptor   rcb - read callback    wcb - writecallback
        pfdset->num++;

        pthread_mutex_unlock(&pfdset->fd_mutex);

        return 0;
}


~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/fd_man.c

static void
fdset_add_fd(struct fdset  *pfdset, int idx, int fd,
        fd_cb rcb, fd_cb wcb, void *dat)
{
        struct fdentry *pfdentry;

        if (pfdset == NULL || idx >= MAX_FDS)
                return;

        pfdentry = &pfdset->fd[idx];
        pfdentry->fd = fd;
        pfdentry->rcb = rcb;
        pfdentry->wcb = wcb;
        pfdentry->dat = dat;
}

~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/vhost-net-user.c

#define MAX_VHOST_SERVER 1024
struct _vhost_server {
        struct vhost_server *server[MAX_VHOST_SERVER];
        struct fdset fdset;
        int vserver_cnt;
        pthread_mutex_t server_mutex;
};



static struct _vhost_server g_vhost_server = {
        .fdset = {
                .fd = { [0 ... MAX_FDS - 1] = {-1, NULL, NULL, NULL, 0} },
                .fd_mutex = PTHREAD_MUTEX_INITIALIZER,
                .num = 0
        },
        .vserver_cnt = 0,
        .server_mutex = PTHREAD_MUTEX_INITIALIZER,
};

~~~~~~~~~~~~~~~~~


./lib/librte_vhost/vhost_user/vhost-net-user.h:43

struct vhost_server {
        char *path; /**< The path the uds is bind to. */
        int listenfd;     /**< The listener sockfd. */
};

~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/fd_man.h:43

struct fdentry {
        int fd;         /* -1 indicates this entry is empty */
        fd_cb rcb;      /* callback when this fd is readable. */
        fd_cb wcb;      /* callback when this fd is writeable.*/
        void *dat;      /* fd context */
        int busy;       /* whether this entry is being used in cb. */
};


~~~~~~~~~~~~~~~~~

./lib/librte_vhost/virtio-net.c:852

/*
 * Called by main to setup callbacks when registering CUSE device.
 */
struct vhost_net_device_ops const *
get_virtio_net_callbacks(void)
{
        return &vhost_device_ops;
}

~~~~~~~~~~~~~~~~~

./lib/librte_vhost/virtio-net.c

/*
 * Function pointers are set for the device operations to allow CUSE to call
 * functions when an IOCTL, device_add or device_release is received.
 */
static const struct vhost_net_device_ops vhost_device_ops = {
        .new_device = new_device,
        .destroy_device = destroy_device,

        .set_ifname = set_ifname,

        .get_features = get_features,
        .set_features = set_features,

        .set_vring_num = set_vring_num,
        .set_vring_addr = set_vring_addr,
        .set_vring_base = set_vring_base,
        .get_vring_base = get_vring_base,

        .set_vring_kick = set_vring_kick,
        .set_vring_call = set_vring_call,

        .set_backend = set_backend,

        .set_owner = set_owner,
        .reset_owner = reset_owner,
};

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~




------------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/vhost-net-user.c:321

/* call back when there is new virtio connection.  */
static void
vserver_new_vq_conn(int fd, void *dat, __rte_unused int *remove)
{
        struct vhost_server *vserver = (struct vhost_server *)dat;
        int conn_fd;
        struct connfd_ctx *ctx;
        int fh;
        struct vhost_device_ctx vdev_ctx = { (pid_t)0, 0 };
        unsigned int size;

        conn_fd = accept(fd, NULL, NULL);
        RTE_LOG(INFO, VHOST_CONFIG,
                "new virtio connection is %d\n", conn_fd);
        if (conn_fd < 0)
                return;

        ctx = calloc(1, sizeof(*ctx));
        if (ctx == NULL) {
                close(conn_fd);
                return;
        }

        fh = ops->new_device(vdev_ctx);
        if (fh == -1) {
                free(ctx);
                close(conn_fd);
                return;
        }

        vdev_ctx.fh = fh;
        size = strnlen(vserver->path, PATH_MAX);
        ops->set_ifname(vdev_ctx, vserver->path,
                size);

        RTE_LOG(INFO, VHOST_CONFIG, "new device, handle is %d\n", fh);

        ctx->vserver = vserver;
        ctx->fh = fh;
        fdset_add(&g_vhost_server.fdset,
                conn_fd, vserver_message_handler, NULL, ctx);        ------------------>  vserver_message_handler
}





###################################################################################################


1519961627178:vhost_thread1(188271)[monitor(188268)]
page 0xffffea007e000000 _count 0 flags 17fff8000004004 mapping 0x0 _mapcount -1
----------------USER------------------
 0x7ff7fb5f740d : __close_nocancel+0x24/0x57 [/lib/x86_64-linux-gnu/libpthread-2.19.so]
 0x55fff1 : user_destroy_device+0x141/0x170 [/usr/sbin/ovs-vswitchd]
 0x5517a0 : vserver_message_handler+0x1a0/0x550 [/usr/sbin/ovs-vswitchd]

---------------KERNEL-----------------
 0xffffffff811cced0 : free_huge_page+0x0/0x210 [kernel]
 0xffffffff81190b1b : __put_compound_page+0x2b/0x30 [kernel]
 0xffffffff81190b56 : put_compound_page+0x36/0x1a0 [kernel]
 0xffffffff81190cdd : put_page+0x1d/0x50 [kernel]
 0xffffffff812e7098 : remove_inode_hugepages+0x2a8/0x330 [kernel]
 0xffffffff812e713e : hugetlbfs_evict_inode+0x1e/0x40 [kernel]
 0xffffffff8121820e : evict+0xbe/0x1a0 [kernel]
 0xffffffff81218eab : iput+0x19b/0x200 [kernel]
 0xffffffff812147dc : __dentry_kill+0x17c/0x1e0 [kernel]
 0xffffffff812149e9 : dput+0x1a9/0x210 [kernel]
 0xffffffff811ffda8 : __fput+0x188/0x210 [kernel]
 0xffffffff811ffe6e : ____fput+0xe/0x10 [kernel]
 0xffffffff81099fc6 : task_work_run+0x86/0xb0 [kernel]
 0xffffffff81078806 : exit_to_usermode_loop+0x73/0xa2 [kernel]
 0xffffffff81003a6e : syscall_return_slowpath+0x4e/0x60 [kernel]
 0xffffffff817fa658 : int_ret_from_sys_call+0x25/0x8f [kernel]




./lib/librte_vhost/vhost_user/vhost-net-user.c


/* callback when there is message on the connfd */
static void
vserver_message_handler(int connfd, void *dat, int *remove)
{
        struct vhost_device_ctx ctx;
        struct connfd_ctx *cfd_ctx = (struct connfd_ctx *)dat;
        struct VhostUserMsg msg;
        uint64_t features;
        int ret;

        ctx.fh = cfd_ctx->fh;
        ret = read_vhost_message(connfd, &msg);
        if (ret <= 0 || msg.request >= VHOST_USER_MAX) {
                if (ret < 0)
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "vhost read message failed\n");
                else if (ret == 0)
                        RTE_LOG(INFO, VHOST_CONFIG,
                                "vhost peer closed\n");
                else
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "vhost read incorrect message\n");

                close(connfd);
                *remove = 1;
                free(cfd_ctx);
                user_destroy_device(ctx);        =============>    user_destroy_device
                ops->destroy_device(ctx);

                return;
        }

        RTE_LOG(INFO, VHOST_CONFIG, "read message %s\n",       ------------>   VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
                vhost_message_str[msg.request]);                               VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
        switch (msg.request) {
        case VHOST_USER_GET_FEATURES:
                ret = ops->get_features(ctx, &features);
                msg.payload.u64 = features;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;
        case VHOST_USER_SET_FEATURES:
                features = msg.payload.u64;
                ops->set_features(ctx, &features);
                break;

        case VHOST_USER_GET_PROTOCOL_FEATURES:
                msg.payload.u64 = VHOST_USER_PROTOCOL_FEATURES;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;
        case VHOST_USER_SET_PROTOCOL_FEATURES:
                user_set_protocol_features(ctx, msg.payload.u64);
                break;

        case VHOST_USER_SET_OWNER:
                ops->set_owner(ctx);
                break;
        case VHOST_USER_RESET_OWNER:
                ops->reset_owner(ctx);
                break;

        case VHOST_USER_SET_MEM_TABLE:
                user_set_mem_table(ctx, &msg);
                break;

        case VHOST_USER_SET_LOG_BASE:
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented.\n");
                break;

        case VHOST_USER_SET_LOG_FD:
                close(msg.fds[0]);
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented.\n");
                break;

        case VHOST_USER_SET_VRING_NUM:
                ops->set_vring_num(ctx, &msg.payload.state);
                break;
        case VHOST_USER_SET_VRING_ADDR:
                ops->set_vring_addr(ctx, &msg.payload.addr);
                break;
        case VHOST_USER_SET_VRING_BASE:
                ops->set_vring_base(ctx, &msg.payload.state);
                break;

        case VHOST_USER_GET_VRING_BASE:                          ------------>  VHOST_CONFIG: read message VHOST_USER_GET_VRING_BASE, 0
                ret = user_get_vring_base(ctx, &msg.payload.state);
                msg.size = sizeof(msg.payload.state);
                send_vhost_message(connfd, &msg);
                break;

        case VHOST_USER_SET_VRING_KICK:
                user_set_vring_kick(ctx, &msg);
                break;
        case VHOST_USER_SET_VRING_CALL:                          ------------>   VHOST_CONFIG: read message VHOST_USER_SET_VRING_CALL, 0
                user_set_vring_call(ctx, &msg);
                break;

        case VHOST_USER_SET_VRING_ERR:
                if (!(msg.payload.u64 & VHOST_USER_VRING_NOFD_MASK))
                        close(msg.fds[0]);
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented\n");
                break;

        case VHOST_USER_GET_QUEUE_NUM:
                msg.payload.u64 = VHOST_MAX_QUEUE_PAIRS;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;

        case VHOST_USER_SET_VRING_ENABLE:
                user_set_vring_enable(ctx, &msg.payload.state);
                break;

        default:
                break;

        }
}




------------------------------------------------------------------------------------------

lib/librte_vhost/vhost_user/virtio-net-user.c



void
user_destroy_device(struct vhost_device_ctx ctx)
{
        struct virtio_net *dev = get_device(ctx);

        if (dev && (dev->flags & VIRTIO_DEV_RUNNING))
                notify_ops->destroy_device(dev);

        if (dev && dev->mem) {
                free_mem_region(dev);         ============>   free_mem_region 
                free(dev->mem);
                dev->mem = NULL;
        }
}



lib/librte_vhost/vhost_user/virtio-net-user.c

static void
free_mem_region(struct virtio_net *dev)
{
        struct orig_region_map *region;
        unsigned int idx;

        if (!dev || !dev->mem)
                return;

        region = orig_region(dev->mem, dev->mem->nregions);
        for (idx = 0; idx < dev->mem->nregions; idx++) {
                if (region[idx].mapped_address) {
                        munmap((void *)(uintptr_t)region[idx].mapped_address,          <======= Gabors debug check here
                                        region[idx].mapped_size);
                        close(region[idx].fd);
                }
        }
}


------------------------------------------------------------------------------------------


cat Ericsson_OVS_post_migration/daemon.log | cut -d':' -f5-

 VHOST_CONFIG: vhost peer closed 0

 VHOST_CONFIG: device /var/run/openvswitch/vhue0fdfafa-c7 is to be destroyed flags 0
 VHOST_CONFIG: free 3 regions
 VHOST_CONFIG: about to free region:7fee40000000 size:800000000 fd:251
 VHOST_CONFIG: munmap res=0 close res=0
 VHOST_CONFIG: about to free region:7fee00000000 size:40000000 fd:252
 VHOST_CONFIG: munmap res=0 close res=0
 VHOST_CONFIG: about to free region:7fed40000000 size:c0000000 fd:253
 VHOST_CONFIG: munmap res=0 close res=0




vhost_thread1(188271)




7fed40000000-7fee00000000   3145728 kB
7fee00000000-7fee40000000   1048576 kB
7fee40000000-7ff640000000   33554432 kB



PRE_MIG/P/188271/smaps

7fed40000000-7fee00000000 rw-s 00000000 00:1b 3458052                    /mnt/huge_qemu_1G/libvirt/qemu/qemu_back_mem._objects_ram-node0.XKa2oY (deleted)
Size:            3145728 kB
Rss:                   0 kB
Pss:                   0 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:            0 kB
Anonymous:             0 kB
AnonHugePages:         0 kB
Shared_Hugetlb:  3145728 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
KernelPageSize:  1048576 kB
MMUPageSize:     1048576 kB
Locked:                0 kB
VmFlags: rd wr sh mr mw me ms de ht sd
7fee00000000-7fee40000000 rw-s 00000000 00:1b 3458052                    /mnt/huge_qemu_1G/libvirt/qemu/qemu_back_mem._objects_ram-node0.XKa2oY (deleted)
Size:            1048576 kB
Rss:                   0 kB
Pss:                   0 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:            0 kB
Anonymous:             0 kB
AnonHugePages:         0 kB
Shared_Hugetlb:  1048576 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
KernelPageSize:  1048576 kB
MMUPageSize:     1048576 kB
Locked:                0 kB
VmFlags: rd wr sh mr mw me ms de ht sd
7fee40000000-7ff640000000 rw-s 00000000 00:1b 3458052                    /mnt/huge_qemu_1G/libvirt/qemu/qemu_back_mem._objects_ram-node0.XKa2oY (deleted)
Size:           33554432 kB
Rss:                   0 kB
Pss:                   0 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:            0 kB
Anonymous:             0 kB
AnonHugePages:         0 kB
Shared_Hugetlb: 33554432 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
KernelPageSize:  1048576 kB
MMUPageSize:     1048576 kB
Locked:                0 kB
VmFlags: rd wr sh mr mw me ms de ht sd



########################################################################################################################



vi Ericsson_OVS_post_migration/daemon.log

 VHOST_CONFIG: read message VHOST_USER_SET_MEM_TABLE, 0
 VHOST_CONFIG: mapped region 0 fd:251 to:0x7fee40000000 sz:0x800000000 off:0xc0000000 align:0x40000000
 VHOST_CONFIG: mapped region 1 fd:252 to:0x7fee00000000 sz:0x40000000 off:0x0 align:0x40000000
 VHOST_CONFIG: mapped region 2 fd:253 to:0x7fed40000000 sz:0xc0000000 off:0xc0000 align:0x40000000

------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/vhost-net-user.c:479

/**
 * Creates and initialise the vhost server.
 */
int
rte_vhost_driver_register(const char *path)
{
        struct vhost_server *vserver;

        pthread_mutex_lock(&g_vhost_server.server_mutex);
        if (ops == NULL)
                ops = get_virtio_net_callbacks();

        if (g_vhost_server.vserver_cnt == MAX_VHOST_SERVER) {
                RTE_LOG(ERR, VHOST_CONFIG,
                        "error: the number of servers reaches maximum\n");
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver = calloc(sizeof(struct vhost_server), 1);
        if (vserver == NULL) {
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver->listenfd = uds_socket(path);
        if (vserver->listenfd < 0) {
                free(vserver);
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver->path = strdup(path);

        fdset_add(&g_vhost_server.fdset, vserver->listenfd,
                vserver_new_vq_conn, NULL, vserver);      ------------------>  vserver_new_vq_conn

        g_vhost_server.server[g_vhost_server.vserver_cnt++] = vserver;
        pthread_mutex_unlock(&g_vhost_server.server_mutex);

        return 0;
}



==============================================================================================
http://dpdk.org/doc/guides/prog_guide/glossary.html

RTE - Run Time Environment. Provides a fast and simple framework for fast packet processing, in a lightweight environment as a Linux* application and using Poll Mode Drivers (PMDs) to increase speed.



./doc/guides/prog_guide/vhost_lib.rst:54


*   Vhost session start

      rte_vhost_driver_session_start starts the vhost session loop.
      Vhost session is an infinite blocking loop.
      Put the session in a dedicate DPDK thread.


./doc/guides/prog_guide/vhost_lib.rst

*   Vhost driver registration

      rte_vhost_driver_register registers the vhost driver into the system.
      For vhost-cuse, character device file will be created under the /dev directory.
      Character device name is specified as the parameter.
      For vhost-user, a Unix domain socket server will be created with the parameter as
      the local socket path.


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/rte_vhost_version.map

DPDK_2.0 {
        global:

        rte_vhost_dequeue_burst;
        rte_vhost_driver_callback_register;
        rte_vhost_driver_register;         ------------> rte_vhost_driver_register
        rte_vhost_driver_session_start;       --------------> rte_vhost_driver_session_start
        rte_vhost_enable_guest_notification;
        rte_vhost_enqueue_burst;
        rte_vhost_feature_disable;
        rte_vhost_feature_enable;
        rte_vhost_feature_get;

        local: *;
};

DPDK_2.1 {
        global:

        rte_vhost_driver_unregister;

} DPDK_2.0;

         
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ovs/lib/netdev-dpdk.c
static char *vhost_sock_dir = NULL;   /* Location of vhost-user sockets */

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ovs/lib/netdev-dpdk.c


int
dpdk_init(int argc, char **argv)
{
    int result;
    int base = 0;
    char *pragram_name = argv[0];

    if (argc < 2 || strcmp(argv[1], "--dpdk"))
        return 0;

    /* Remove the --dpdk argument from arg list.*/
    argc--;
    argv++;

    /* Reject --user option */
    int i;
    for (i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--user")) {
            VLOG_ERR("Can not mix --dpdk and --user options, aborting.");
        }
    }

#ifdef VHOST_CUSE
    if (process_vhost_flags("-cuse_dev_name", strdup("vhost-net"),
                            PATH_MAX, argv, &cuse_dev_name)) {
#else
    if (process_vhost_flags("-vhost_sock_dir", strdup(ovs_rundir()),         -------> process_vhost_flags
                            NAME_MAX, argv, &vhost_sock_dir)) {          
        struct stat s;
        int err;

        err = stat(vhost_sock_dir, &s);
        if (err) {
            VLOG_ERR("vHostUser socket DIR '%s' does not exist.",
                     vhost_sock_dir);
            return err;
        }
#endif
        /* Remove the vhost flag configuration parameters from the argument
         * list, so that the correct elements are passed to the DPDK
         * initialization function
         */
        argc -= 2;
        argv += 2;    /* Increment by two to bypass the vhost flag arguments */
        base = 2;
    }

    /* Keep the program name argument as this is needed for call to
     * rte_eal_init()
     */
    argv[0] = pragram_name;

    /* Make sure things are initialized ... */
    result = rte_eal_init(argc, argv);
    if (result < 0) {
        ovs_abort(result, "Cannot init EAL");
    }

    rte_memzone_dump(stdout);
    rte_eal_init_ret = 0;

    if (argc > result) {
        argv[result] = argv[0];
    }

    /* We are called from the main thread here */
    RTE_PER_LCORE(_lcore_id) = NON_PMD_CORE_ID;

    return result + 1 + base;
}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./var/log/upstart/openvswitch-switch.log
No -vhost_sock_dir provided - defaulting to /var/run/openvswitch


qemu-system-x86_64 -enable-kvm -name instance-00000522 -S -machine pc-i440fx-xenial,accel=kvm,usb=off -cpu host -m 32768 -realtime mlock=off -smp 8,sockets=4,cores=1,threads=2 -object memory-backend-file,id=ram-node0,prealloc=yes,mem-path=/mnt/huge_qemu_1G/libvirt/qemu,share=yes,size=34359738368,host-nodes=0,policy=bind -numa node,nodeid=0,cpus=0-7,memdev=ram-node0 -uuid bdc81ffb-ca45-46ee-9d41-3d2c3f4840a3 -smbios type=1,manufacturer=OpenStack Foundation,product=OpenStack Nova,version=13.0.0,serial=4c4c4544-0042-4b10-8058-c8c04f5a4732,uuid=bdc81ffb-ca45-46ee-9d41-3d2c3f4840a3,family=Virtual Machine -no-user-config -nodefaults -chardev socket,id=charmonitor,path=/var/lib/libvirt/qemu/domain-instance-00000522/monitor.sock,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=discard -no-hpet -no-shutdown -boot strict=on -device piix3-usb-uhci,id=usb,bus=pci.0,addr=0x1.0x2 -drive file=/var/lib/nova/instances/bdc81ffb-ca45-46ee-9d41-3d2c3f4840a3/disk,format=qcow2,if=none,id=drive-virtio-disk0,cache=directsync -device virtio-blk-pci,scsi=off,bus=pci.0,addr=0x4,drive=drive-virtio-disk0,id=virtio-disk0,bootindex=1 

-chardev socket,id=charnet0,path=/var/run/openvswitch/vhue0fdfafa-c7 
-netdev type=vhost-user,id=hostnet0,chardev=charnet0 
-device virtio-net-pci,netdev=hostnet0,id=net0,mac=fa:16:3e:08:c3:8d,bus=pci.0,addr=0x3 

-chardev file,id=charserial0,path=/var/lib/nova/instances/bdc81ffb-ca45-46ee-9d41-3d2c3f4840a3/console.log -device isa-serial,chardev=charserial0,id=serial0 -chardev pty,id=charserial1 -device isa-serial,chardev=charserial1,id=serial1 -device usb-tablet,id=input0 -vnc 160.6.88.55:0 -k en-us -device cirrus-vga,id=video0,bus=pci.0,addr=0x2 -device i6300esb,id=watchdog0,bus=pci.0,addr=0x6 -watchdog-action reset -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x5 -msg timestamp=on




~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/netdev-dpdk.c


static int
process_vhost_flags(char *flag, char *default_val, int size,
                    char **argv, char **new_val)
{
    int changed = 0;

    /* Depending on which version of vhost is in use, process the vhost-specific
     * flag if it is provided on the vswitchd command line, otherwise resort to
     * a default value.
     *
     * For vhost-user: Process "-vhost_sock_dir" to set the custom location of
     * the vhost-user socket(s).
     * For vhost-cuse: Process "-cuse_dev_name" to set the custom name of the
     * vhost-cuse character device.
     */
    if (!strcmp(argv[1], flag) && (strlen(argv[2]) <= size)) {
        changed = 1;
        *new_val = strdup(argv[2]);
        VLOG_INFO("User-provided %s in use: %s", flag, *new_val);
    } else {
        VLOG_INFO("No %s provided - defaulting to %s", flag, default_val);  ----------> defaulting to /var/run/openvswitch
        *new_val = default_val;
    }

    return changed;
}


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


./sos_commands/openvswitch/ovs-vsctl_-t_5_show:69:                type: dpdkvhostuser

    Bridge br-int

        Port "vhue0fdfafa-c7"
            tag: 1
            Interface "vhue0fdfafa-c7"
                type: dpdkvhostuser



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ovs/lib/netdev-dpdk.c

static const struct netdev_class OVS_UNUSED dpdk_vhost_user_class =
    NETDEV_DPDK_CLASS(
        "dpdkvhostuser",
        dpdk_vhost_user_class_init,
        netdev_dpdk_vhost_user_construct,
        netdev_dpdk_vhost_destruct,
        netdev_dpdk_vhost_set_multiq,
        netdev_dpdk_vhost_send,
        netdev_dpdk_vhost_get_carrier,
        netdev_dpdk_vhost_get_stats,
        NULL,
        NULL,
        netdev_dpdk_vhost_rxq_recv);


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/netdev-dpdk.c:2250

#define NETDEV_DPDK_CLASS(NAME, INIT, CONSTRUCT, DESTRUCT, MULTIQ, SEND, \
    GET_CARRIER, GET_STATS, GET_FEATURES, GET_STATUS, RXQ_RECV)          \
{                                                             \
    NAME,                                                     \
    INIT,                       /* init */                    \
    NULL,                       /* netdev_dpdk_run */         \
    NULL,                       /* netdev_dpdk_wait */        \
                                                              \
    netdev_dpdk_alloc,                                        \
    CONSTRUCT,                                                \
    DESTRUCT,                                                 \
    netdev_dpdk_dealloc,                                      \
    netdev_dpdk_get_config,                                   \
    NULL,                       /* netdev_dpdk_set_config */  \
    NULL,                       /* get_tunnel_config */       \
    NULL,                       /* build header */            \
    NULL,                       /* push header */             \
    NULL,                       /* pop header */              \
    netdev_dpdk_get_numa_id,    /* get_numa_id */             \
    MULTIQ,                     /* set_multiq */              \
                                                              \
    SEND,                       /* send */                    \
    NULL,                       /* send_wait */               \
                                                              \
    netdev_dpdk_set_etheraddr,                                \
    netdev_dpdk_get_etheraddr,                                \
    netdev_dpdk_get_mtu,                                      \
    netdev_dpdk_set_mtu,                                      \
    netdev_dpdk_get_ifindex,                                  \
    GET_CARRIER,                                              \
    netdev_dpdk_get_carrier_resets,                           \
    netdev_dpdk_set_miimon,                                   \
    GET_STATS,                                                \
    GET_FEATURES,                                             \
    NULL,                       /* set_advertisements */      \
                                                              \
    NULL,                       /* set_policing */            \
    NULL,                       /* get_qos_types */           \
    NULL,                       /* get_qos_capabilities */    \
    NULL,                       /* get_qos */                 \
    NULL,                       /* set_qos */                 \
    NULL,                       /* get_queue */               \
    NULL,                       /* set_queue */               \
    NULL,                       /* delete_queue */            \
    NULL,                       /* get_queue_stats */         \
    NULL,                       /* queue_dump_start */        \
    NULL,                       /* queue_dump_next */         \
    NULL,                       /* queue_dump_done */         \
    NULL,                       /* dump_queue_stats */        \
                                                              \
    NULL,                       /* get_in4 */                 \
    NULL,                       /* set_in4 */                 \
    NULL,                       /* get_in6 */                 \
    NULL,                       /* add_router */              \
    NULL,                       /* get_next_hop */            \
    GET_STATUS,                                               \
    NULL,                       /* arp_lookup */              \
                                                              \
    netdev_dpdk_update_flags,                                 \
                                                              \
    netdev_dpdk_rxq_alloc,                                    \
    netdev_dpdk_rxq_construct,                                \
    netdev_dpdk_rxq_destruct,                                 \
    netdev_dpdk_rxq_dealloc,                                  \
    RXQ_RECV,                                                 \
    NULL,                       /* rx_wait */                 \
    NULL,                       /* rxq_drain */               \
}




~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


ovs/lib/netdev-dpdk.c


static int
netdev_dpdk_vhost_user_construct(struct netdev *netdev_)
{
    struct netdev_dpdk *netdev = netdev_dpdk_cast(netdev_);       <---------
    const char *name = netdev_->name;
    int err;

    /* 'name' is appended to 'vhost_sock_dir' and used to create a socket in
     * the file system. '/' or '\' would traverse directories, so they're not
     * acceptable in 'name'. */
    if (strchr(name, '/') || strchr(name, '\\')) {
        VLOG_ERR("\"%s\" is not a valid name for a vhost-user port. "
                 "A valid name must not include '/' or '\\'",
                 name);
        return EINVAL;
    }

    ovs_mutex_lock(&dpdk_mutex);
    /* Take the name of the vhost-user port and append it to the location where
     * the socket is to be created, then register the socket.
     */
    snprintf(netdev->vhost_id, sizeof(netdev->vhost_id), "%s/%s",
             vhost_sock_dir, name);

    err = rte_vhost_driver_register(netdev->vhost_id);         --------------->  rte_vhost_driver_register
    if (err) {
        VLOG_ERR("vhost-user socket device setup failure for socket %s\n",
                 netdev->vhost_id);
    } else {
        fatal_signal_add_file_to_unlink(netdev->vhost_id);
        VLOG_INFO("Socket %s created for vhost-user port %s\n",
                  netdev->vhost_id, name);
        err = vhost_construct_helper(netdev_);
    }

    ovs_mutex_unlock(&dpdk_mutex);
    return err;
}


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/netdev-dpdk.c

static struct netdev_dpdk *
netdev_dpdk_cast(const struct netdev *netdev)
{
    return CONTAINER_OF(netdev, struct netdev_dpdk, up);
}


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


./lib/util.h:207


/* Given POINTER, the address of the given MEMBER in a STRUCT object, returns
   the STRUCT object. */
#define CONTAINER_OF(POINTER, STRUCT, MEMBER)                           \
        ((STRUCT *) (void *) ((char *) (POINTER) - offsetof (STRUCT, MEMBER)))


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


./lib/netdev-provider.h

/* A network device (e.g. an Ethernet device).
 *
 * Network device implementations may read these members but should not modify
 * them. */
struct netdev {
    /* The following do not change during the lifetime of a struct netdev. */
    char *name;                         /* Name of network device. */      -------->  name
    const struct netdev_class *netdev_class; /* Functions to control
                                                this device. */

    /* A sequence number which indicates changes in one of 'netdev''s
     * properties.   It must be nonzero so that users have a value which
     * they may use as a reset when tracking 'netdev'.
     *
     * Minimally, the sequence number is required to change whenever
     * 'netdev''s flags, features, ethernet address, or carrier changes. */
    uint64_t change_seq;

    /* The following are protected by 'netdev_mutex' (internal to netdev.c). */
    int n_txq;
    int n_rxq;
    int ref_cnt;                        /* Times this devices was opened. */
    struct shash_node *node;            /* Pointer to element in global map. */
    struct ovs_list saved_flags_list; /* Contains "struct netdev_saved_flags". */
};


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


./lib/netdev-dpdk.c

struct netdev_dpdk {
    struct netdev up;
    int port_id;
    int max_packet_len;
    enum dpdk_dev_type type;

    struct dpdk_tx_queue *tx_q;

    struct ovs_mutex mutex OVS_ACQ_AFTER(dpdk_mutex);

    struct dpdk_mp *dpdk_mp;
    int mtu;
    int socket_id;
    int buf_size;
    struct netdev_stats stats;
    /* Protects stats */
    rte_spinlock_t stats_lock;

    struct eth_addr hwaddr;
    enum netdev_flags flags;

    struct rte_eth_link link;
    int link_reset_cnt;

    /* The user might request more txqs than the NIC has.  We remap those
     * ('up.n_txq') on these ('real_n_txq').
     * If the numbers match, 'txq_needs_locking' is false, otherwise it is
     * true and we will take a spinlock on transmission */
    int real_n_txq;
    int real_n_rxq;
    bool txq_needs_locking;

    /* virtio-net structure for vhost device */
    OVSRCU_TYPE(struct virtio_net *) virtio_dev;

    /* Identifier used to distinguish vhost devices from each other */
    char vhost_id[PATH_MAX];

    /* In dpdk_list. */
    struct ovs_list list_node OVS_GUARDED_BY(dpdk_mutex);
};







##################################################################################################
=========================================== DPDK =================================================


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

https://linux.die.net/man/3/pthread_mutex_init
the macro PTHREAD_MUTEX_INITIALIZER can be used to initialize mutexes that are statically allocated. 


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/vhost-net-user.c


static struct _vhost_server g_vhost_server = {
        .fdset = {
                .fd = { [0 ... MAX_FDS - 1] = {-1, NULL, NULL, NULL, 0} },
                .fd_mutex = PTHREAD_MUTEX_INITIALIZER,
                .num = 0
        },
        .vserver_cnt = 0,
        .server_mutex = PTHREAD_MUTEX_INITIALIZER,
};


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
OVS

ovs/lib/netdev-dpdk.c

static int
netdev_dpdk_vhost_user_construct(struct netdev *netdev_)
{
    struct netdev_dpdk *netdev = netdev_dpdk_cast(netdev_);
    const char *name = netdev_->name;
    int err;

    /* 'name' is appended to 'vhost_sock_dir' and used to create a socket in
     * the file system. '/' or '\' would traverse directories, so they're not
     * acceptable in 'name'. */
    if (strchr(name, '/') || strchr(name, '\\')) {
        VLOG_ERR("\"%s\" is not a valid name for a vhost-user port. "
                 "A valid name must not include '/' or '\\'",
                 name);
        return EINVAL;
    }

    ovs_mutex_lock(&dpdk_mutex);
    /* Take the name of the vhost-user port and append it to the location where
     * the socket is to be created, then register the socket.
     */
    snprintf(netdev->vhost_id, sizeof(netdev->vhost_id), "%s/%s",
             vhost_sock_dir, name);

    err = rte_vhost_driver_register(netdev->vhost_id);
    if (err) {
        VLOG_ERR("vhost-user socket device setup failure for socket %s\n",
                 netdev->vhost_id);
    } else {
        fatal_signal_add_file_to_unlink(netdev->vhost_id);
        VLOG_INFO("Socket %s created for vhost-user port %s\n",
                  netdev->vhost_id, name);
        err = vhost_construct_helper(netdev_);
    }

    ovs_mutex_unlock(&dpdk_mutex);
    return err;
}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
DPDK


./lib/librte_vhost/vhost_user/vhost-net-user.c

/**
 * Create a unix domain socket, bind to path and listen for connection.
 * @return
 *  socket fd or -1 on failure
 */
static int
uds_socket(const char *path)
{
        struct sockaddr_un un;
        int sockfd;
        int ret;

        if (path == NULL)
                return -1;

        sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sockfd < 0)
                return -1;
        RTE_LOG(INFO, VHOST_CONFIG, "socket created, fd:%d\n", sockfd);

        memset(&un, 0, sizeof(un));
        un.sun_family = AF_UNIX;
        snprintf(un.sun_path, sizeof(un.sun_path), "%s", path);
        ret = bind(sockfd, (struct sockaddr *)&un, sizeof(un));
        if (ret == -1) {
                RTE_LOG(ERR, VHOST_CONFIG, "fail to bind fd:%d, remove file:%s and try again.\n",
                        sockfd, path);
                goto err;
        }
        RTE_LOG(INFO, VHOST_CONFIG, "bind to %s\n", path);

        ret = listen(sockfd, MAX_VIRTIO_BACKLOG);
        if (ret == -1)
                goto err;

        return sockfd;

err:
        close(sockfd);
        return -1;
}


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


./lib/librte_vhost/vhost_user/vhost-net-user.h

struct vhost_server {
        char *path; /**< The path the uds is bind to. */
        int listenfd;     /**< The listener sockfd. */
};


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/vhost-net-user.c:478


/**
 * Creates and initialise the vhost server.
 */
int
rte_vhost_driver_register(const char *path)
{
        struct vhost_server *vserver;

        pthread_mutex_lock(&g_vhost_server.server_mutex);
        if (ops == NULL)
                ops = get_virtio_net_callbacks();

        if (g_vhost_server.vserver_cnt == MAX_VHOST_SERVER) {
                RTE_LOG(ERR, VHOST_CONFIG,
                        "error: the number of servers reaches maximum\n");
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver = calloc(sizeof(struct vhost_server), 1);
        if (vserver == NULL) {
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver->listenfd = uds_socket(path);         ------------>  uds_socket  create unix socket
        if (vserver->listenfd < 0) {                                   path: /var/run/openvswitch/vhue0fdfafa-c7
                free(vserver);
                pthread_mutex_unlock(&g_vhost_server.server_mutex);
                return -1;
        }

        vserver->path = strdup(path);

        fdset_add(&g_vhost_server.fdset, vserver->listenfd,         -----------> fdset_add
                vserver_new_vq_conn, NULL, vserver);                            adds rcb  vserver_new_vq_conn

        g_vhost_server.server[g_vhost_server.vserver_cnt++] = vserver;
        pthread_mutex_unlock(&g_vhost_server.server_mutex);

        return 0;
}




fdset_add(struct fdset *pfdset, int fd, fd_cb rcb, fd_cb wcb, void *dat)

fdset_add(&g_vhost_server.fdset, vserver->listenfd, vserver_new_vq_conn, NULL, vserver);  

rcb => vserver_new_vq_conn

/* call back when there is new virtio connection.  */
static void vserver_new_vq_conn(int fd, void *dat, __rte_unused int *remove)




~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/fd_man.h

#define MAX_FDS 1024

struct fdset {
        struct fdentry fd[MAX_FDS];
        pthread_mutex_t fd_mutex;
        int num;        /* current fd number of this fdset */
};

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/fd_man.h

struct fdentry {
        int fd;         /* -1 indicates this entry is empty */
        fd_cb rcb;      /* callback when this fd is readable. */
        fd_cb wcb;      /* callback when this fd is writeable.*/
        void *dat;      /* fd context */
        int busy;       /* whether this entry is being used in cb. */
};

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/fd_man.c

/**
 * Register the fd in the fdset with read/write handler and context.
 */
int
fdset_add(struct fdset *pfdset, int fd, fd_cb rcb, fd_cb wcb, void *dat)
{
        int i;

        if (pfdset == NULL || fd == -1)
                return -1;

        pthread_mutex_lock(&pfdset->fd_mutex);

        /* Find a free slot in the list. */
        i = fdset_find_free_slot(pfdset);
        if (i == -1) {
                pthread_mutex_unlock(&pfdset->fd_mutex);
                return -2;
        }

        fdset_add_fd(pfdset, i, fd, rcb, wcb, dat);
        pfdset->num++;

        pthread_mutex_unlock(&pfdset->fd_mutex);

        return 0;
}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/fd_man.c

static void
fdset_add_fd(struct fdset  *pfdset, int idx, int fd,
        fd_cb rcb, fd_cb wcb, void *dat)
{
        struct fdentry *pfdentry;

        if (pfdset == NULL || idx >= MAX_FDS)
                return;

        pfdentry = &pfdset->fd[idx];
        pfdentry->fd = fd;
        pfdentry->rcb = rcb;
        pfdentry->wcb = wcb;
        pfdentry->dat = dat;
}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

##############################################################################################

OVS

vi ./ovs/lib/netdev-dpdk.c

static void *
start_vhost_loop(void *dummy OVS_UNUSED)
{
     pthread_detach(pthread_self());
     /* Put the cuse thread into quiescent state. */
     ovsrcu_quiesce_start();
     rte_vhost_driver_session_start();
     return NULL;
}



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
DPDK

dpdk/lib/librte_vhost/vhost_user/vhost-net-user.c

int
rte_vhost_driver_session_start(void)
{
        fdset_event_dispatch(&g_vhost_server.fdset);      --------->   fdset_event_dispatch
        return 0;
}


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/fd_man.h

#define MAX_FDS 1024

struct fdset {
        struct fdentry fd[MAX_FDS];
        pthread_mutex_t fd_mutex;
        int num;        /* current fd number of this fdset */
};

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/fd_man.h

struct fdentry {
        int fd;         /* -1 indicates this entry is empty */
        fd_cb rcb;      /* callback when this fd is readable. */
        fd_cb wcb;      /* callback when this fd is writeable.*/
        void *dat;      /* fd context */
        int busy;       /* whether this entry is being used in cb. */
};


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

lib/librte_vhost/vhost_user/fd_man.c

/**
 * This functions runs in infinite blocking loop until there is no fd in
 * pfdset. It calls corresponding r/w handler if there is event on the fd.
 *
 * Before the callback is called, we set the flag to busy status; If other
 * thread(now rte_vhost_driver_unregister) calls fdset_del concurrently, it
 * will wait until the flag is reset to zero(which indicates the callback is
 * finished), then it could free the context after fdset_del.
 */
void
fdset_event_dispatch(struct fdset *pfdset)
{
        fd_set rfds, wfds;
        int i, maxfds;
        struct fdentry *pfdentry;   // pointer file descriptor entry
        int num = MAX_FDS;
        fd_cb rcb, wcb;           // rcb - read call back  wcb - write call back     fd_cb - file descriptor call back
        void *dat;
        int fd;
        int remove1, remove2;
        int ret;

        if (pfdset == NULL)
                return;

        while (1) {
                struct timeval tv;
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                FD_ZERO(&rfds);        // read file descriptors
                FD_ZERO(&wfds);        // write file descriptors
                pthread_mutex_lock(&pfdset->fd_mutex);

                maxfds = fdset_fill(&rfds, &wfds, pfdset);

                pthread_mutex_unlock(&pfdset->fd_mutex);

                /*
                 * When select is blocked, other threads might unregister
                 * listenfds from and register new listenfds into fdset.
                 * When select returns, the entries for listenfds in the fdset
                 * might have been updated. It is ok if there is unwanted call
                 * for new listenfds.
                 */
                ret = select(maxfds + 1, &rfds, &wfds, NULL, &tv);         // tv - timeval
                if (ret <= 0)
                        continue;

                for (i = 0; i < num; i++) {
                        remove1 = remove2 = 0;
                        pthread_mutex_lock(&pfdset->fd_mutex);
                        pfdentry = &pfdset->fd[i];
                        fd = pfdentry->fd;
                        rcb = pfdentry->rcb;
                        wcb = pfdentry->wcb;
                        dat = pfdentry->dat;
                        pfdentry->busy = 1;
                        pthread_mutex_unlock(&pfdset->fd_mutex);
                        if (fd >= 0 && FD_ISSET(fd, &rfds) && rcb)
                                rcb(fd, dat, &remove1);
                        if (fd >= 0 && FD_ISSET(fd, &wfds) && wcb)
                                wcb(fd, dat, &remove2);
                        pfdentry->busy = 0;
                        /*
                         * fdset_del needs to check busy flag.
                         * We don't allow fdset_del to be called in callback
                         * directly.
                         */
                        /*
                         * When we are to clean up the fd from fdset,
                         * because the fd is closed in the cb,
                         * the old fd val could be reused by when creates new
                         * listen fd in another thread, we couldn't call
                         * fd_set_del.
                         */
                        if (remove1 || remove2)
                                fdset_del_slot(pfdset, i);
                }
        }

}



fdset_add(struct fdset *pfdset, int fd, fd_cb rcb, fd_cb wcb, void *dat)

fdset_add(&g_vhost_server.fdset, conn_fd, vserver_message_handler, NULL, ctx); 

rcb => vserver_message_handler


/* callback when there is message on the connfd */
static void vserver_message_handler(int connfd, void *dat, int *remove)


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

https://linux.die.net/man/3/fd_set

select() and pselect() allow a program to monitor multiple file descriptors, waiting until one or more of the file descriptors become "ready" for some class of I/O operation (e.g., input possible). A file descriptor is considered ready if it is possible to perform the corresponding I/O operation (e.g., read(2)) without blocking.

int select(int nfds, fd_set *readfds, fd_set *writefds,
           fd_set *exceptfds, struct timeval *timeout);


FD_ISSET() tests to see if a file descriptor is part of the set; this is useful after select() returns.

select() uses a timeout that is a struct timeval (with seconds and microseconds

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/fd_man.c

/**
 * Register the fd in the fdset with read/write handler and context.
 */
int
fdset_add(struct fdset *pfdset, int fd, fd_cb rcb, fd_cb wcb, void *dat)
{
        int i;

        if (pfdset == NULL || fd == -1)
                return -1;

        pthread_mutex_lock(&pfdset->fd_mutex);

        /* Find a free slot in the list. */
        i = fdset_find_free_slot(pfdset);
        if (i == -1) {
                pthread_mutex_unlock(&pfdset->fd_mutex);
                return -2;
        }

        fdset_add_fd(pfdset, i, fd, rcb, wcb, dat);
        pfdset->num++;

        pthread_mutex_unlock(&pfdset->fd_mutex);

        return 0;
}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./lib/librte_vhost/vhost_user/fd_man.c

static void
fdset_add_fd(struct fdset  *pfdset, int idx, int fd,
        fd_cb rcb, fd_cb wcb, void *dat)
{
        struct fdentry *pfdentry;

        if (pfdset == NULL || idx >= MAX_FDS)
                return;

        pfdentry = &pfdset->fd[idx];
        pfdentry->fd = fd;
        pfdentry->rcb = rcb;
        pfdentry->wcb = wcb;
        pfdentry->dat = dat;
}



==============================================================================================



------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/vhost-net-user.c:321

/* call back when there is new virtio connection.  */
static void
vserver_new_vq_conn(int fd, void *dat, __rte_unused int *remove)
{
        struct vhost_server *vserver = (struct vhost_server *)dat;
        int conn_fd;
        struct connfd_ctx *ctx;
        int fh;
        struct vhost_device_ctx vdev_ctx = { (pid_t)0, 0 };
        unsigned int size;

        conn_fd = accept(fd, NULL, NULL);
        RTE_LOG(INFO, VHOST_CONFIG,
                "new virtio connection is %d\n", conn_fd);
        if (conn_fd < 0)
                return;

        ctx = calloc(1, sizeof(*ctx));
        if (ctx == NULL) {
                close(conn_fd);
                return;
        }

        fh = ops->new_device(vdev_ctx);
        if (fh == -1) {
                free(ctx);
                close(conn_fd);
                return;
        }

        vdev_ctx.fh = fh;
        size = strnlen(vserver->path, PATH_MAX);
        ops->set_ifname(vdev_ctx, vserver->path,
                size);

        RTE_LOG(INFO, VHOST_CONFIG, "new device, handle is %d\n", fh);

        ctx->vserver = vserver;
        ctx->fh = fh;
        fdset_add(&g_vhost_server.fdset,
                conn_fd, vserver_message_handler, NULL, ctx);         ---------------> vserver_message_handler
}



------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/vhost-net-user.c

/* callback when there is message on the connfd */
static void
vserver_message_handler(int connfd, void *dat, int *remove)
{
        struct vhost_device_ctx ctx;
        struct connfd_ctx *cfd_ctx = (struct connfd_ctx *)dat;
        struct VhostUserMsg msg;
        uint64_t features;
        int ret;

        ctx.fh = cfd_ctx->fh;
        ret = read_vhost_message(connfd, &msg);
        if (ret <= 0 || msg.request >= VHOST_USER_MAX) {
                if (ret < 0)
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "vhost read message failed\n");
                else if (ret == 0)
                        RTE_LOG(INFO, VHOST_CONFIG,
                                "vhost peer closed\n");
                else
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "vhost read incorrect message\n");

                close(connfd);
                *remove = 1;
                free(cfd_ctx);
                user_destroy_device(ctx);
                ops->destroy_device(ctx);

                return;
        }

        RTE_LOG(INFO, VHOST_CONFIG, "read message %s\n",
                vhost_message_str[msg.request]);
        switch (msg.request) {
        case VHOST_USER_GET_FEATURES:
                ret = ops->get_features(ctx, &features);
                msg.payload.u64 = features;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;
        case VHOST_USER_SET_FEATURES:
                features = msg.payload.u64;
                ops->set_features(ctx, &features);
                break;

        case VHOST_USER_GET_PROTOCOL_FEATURES:
                msg.payload.u64 = VHOST_USER_PROTOCOL_FEATURES;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;
        case VHOST_USER_SET_PROTOCOL_FEATURES:
                user_set_protocol_features(ctx, msg.payload.u64);
                break;

        case VHOST_USER_SET_OWNER:
                ops->set_owner(ctx);
                break;

        case VHOST_USER_RESET_OWNER:
                ops->reset_owner(ctx);
                break;

        case VHOST_USER_SET_MEM_TABLE:
                user_set_mem_table(ctx, &msg);           ---------------->  user_set_mem_table
                break;

        case VHOST_USER_SET_LOG_BASE:
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented.\n");
                break;

        case VHOST_USER_SET_LOG_FD:
                close(msg.fds[0]);
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented.\n");
                break;

        case VHOST_USER_SET_VRING_NUM:
                ops->set_vring_num(ctx, &msg.payload.state);
                break;
        case VHOST_USER_SET_VRING_ADDR:
                ops->set_vring_addr(ctx, &msg.payload.addr);
                break;
        case VHOST_USER_SET_VRING_BASE:
                ops->set_vring_base(ctx, &msg.payload.state);
                break;

        case VHOST_USER_GET_VRING_BASE:
                ret = user_get_vring_base(ctx, &msg.payload.state);
                msg.size = sizeof(msg.payload.state);
                send_vhost_message(connfd, &msg);
                break;

        case VHOST_USER_SET_VRING_KICK:
                user_set_vring_kick(ctx, &msg);
                break;
        case VHOST_USER_SET_VRING_CALL:
                user_set_vring_call(ctx, &msg);
                break;

        case VHOST_USER_SET_VRING_ERR:
                if (!(msg.payload.u64 & VHOST_USER_VRING_NOFD_MASK))
                        close(msg.fds[0]);
                RTE_LOG(INFO, VHOST_CONFIG, "not implemented\n");
                break;

        case VHOST_USER_GET_QUEUE_NUM:
                msg.payload.u64 = VHOST_MAX_QUEUE_PAIRS;
                msg.size = sizeof(msg.payload.u64);
                send_vhost_message(connfd, &msg);
                break;

        case VHOST_USER_SET_VRING_ENABLE:
                user_set_vring_enable(ctx, &msg.payload.state);
                break;

        default:
                break;

        }
}

------------------------------------------------------------------------------------

./lib/librte_vhost/vhost_user/virtio-net-user.c

int
user_set_mem_table(struct vhost_device_ctx ctx, struct VhostUserMsg *pmsg)
{
        struct VhostUserMemory memory = pmsg->payload.memory;
        struct virtio_memory_regions *pregion;
        uint64_t mapped_address, mapped_size;
        struct virtio_net *dev;
        unsigned int idx = 0;
        struct orig_region_map *pregion_orig;
        uint64_t alignment;

        /* unmap old memory regions one by one*/
        dev = get_device(ctx);         ----------> returns struct virtio_net 
        if (dev == NULL)
                return -1;

        /* Remove from the data plane. */
        if (dev->flags & VIRTIO_DEV_RUNNING)
                notify_ops->destroy_device(dev);

        if (dev->mem) {
                free_mem_region(dev);
                free(dev->mem);
                dev->mem = NULL;
        }

        dev->mem = calloc(1,
                sizeof(struct virtio_memory) +
                sizeof(struct virtio_memory_regions) * memory.nregions +
                sizeof(struct orig_region_map) * memory.nregions);
        if (dev->mem == NULL) {
                RTE_LOG(ERR, VHOST_CONFIG,
                        "(%"PRIu64") Failed to allocate memory for dev->mem\n",
                        dev->device_fh);
                return -1;
        }
        dev->mem->nregions = memory.nregions;

        pregion_orig = orig_region(dev->mem, memory.nregions);
        for (idx = 0; idx < memory.nregions; idx++) {
                pregion = &dev->mem->regions[idx];
                pregion->guest_phys_address =
                        memory.regions[idx].guest_phys_addr;
                pregion->guest_phys_address_end =
                        memory.regions[idx].guest_phys_addr +
                        memory.regions[idx].memory_size;
                pregion->memory_size =
                        memory.regions[idx].memory_size;
                pregion->userspace_address =
                        memory.regions[idx].userspace_addr;

                /* This is ugly */
                mapped_size = memory.regions[idx].memory_size +
                        memory.regions[idx].mmap_offset;

                /* mmap() without flag of MAP_ANONYMOUS, should be called
                 * with length argument aligned with hugepagesz at older
                 * longterm version Linux, like 2.6.32 and 3.2.72, or
                 * mmap() will fail with EINVAL.
                 *
                 * to avoid failure, make sure in caller to keep length
                 * aligned.
                 */
                alignment = get_blk_size(pmsg->fds[idx]);
                mapped_size = RTE_ALIGN_CEIL(mapped_size, alignment);

                mapped_address = (uint64_t)(uintptr_t)mmap(NULL,
                        mapped_size,
                        PROT_READ | PROT_WRITE, MAP_SHARED,
                        pmsg->fds[idx],
                        0);

                RTE_LOG(INFO, VHOST_CONFIG,
                        "mapped region %d fd:%d to:%p sz:0x%"PRIx64" "
                        "off:0x%"PRIx64" align:0x%"PRIx64"\n",
                        idx, pmsg->fds[idx], (void *)(uintptr_t)mapped_address,
                        mapped_size, memory.regions[idx].mmap_offset,
                        alignment);

                if (mapped_address == (uint64_t)(uintptr_t)MAP_FAILED) {
                        RTE_LOG(ERR, VHOST_CONFIG,
                                "mmap qemu guest failed.\n");
                        goto err_mmap;
                }

                pregion_orig[idx].mapped_address = mapped_address;
                pregion_orig[idx].mapped_size = mapped_size;
                pregion_orig[idx].blksz = alignment;
                pregion_orig[idx].fd = pmsg->fds[idx];

                mapped_address +=  memory.regions[idx].mmap_offset;

                pregion->address_offset = mapped_address -
                        pregion->guest_phys_address;

                if (memory.regions[idx].guest_phys_addr == 0) {
                        dev->mem->base_address =
                                memory.regions[idx].userspace_addr;
                        dev->mem->mapped_address =
                                pregion->address_offset;
                }

                LOG_DEBUG(VHOST_CONFIG,
                        "REGION: %u GPA: %p QEMU VA: %p SIZE (%"PRIu64")\n",
                        idx,
                        (void *)(uintptr_t)pregion->guest_phys_address,
                        (void *)(uintptr_t)pregion->userspace_address,
                         pregion->memory_size);
        }

        return 0;

err_mmap:
        while (idx--) {
                munmap((void *)(uintptr_t)pregion_orig[idx].mapped_address,
                                pregion_orig[idx].mapped_size);
                close(pregion_orig[idx].fd);
        }
        free(dev->mem);
        dev->mem = NULL;
        return -1;
}


------------------------------------------------------------------------------------


./lib/librte_vhost/vhost_user/virtio-net-user.c *dev)


static void
free_mem_region(struct virtio_net *dev)
{
        struct orig_region_map *region;
        unsigned int idx;

        if (!dev || !dev->mem)
                return;

        region = orig_region(dev->mem, dev->mem->nregions);
        for (idx = 0; idx < dev->mem->nregions; idx++) {
                if (region[idx].mapped_address) {
                        munmap((void *)(uintptr_t)region[idx].mapped_address,
                                        region[idx].mapped_size);
                        close(region[idx].fd);
                }
        }
}

