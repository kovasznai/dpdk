

./lib/librte_vhost/vhost_user/vhost-net-user.h


typedef struct VhostUserMsg {
        VhostUserRequest request;

#define VHOST_USER_VERSION_MASK     0x3
#define VHOST_USER_REPLY_MASK       (0x1 << 2)
        uint32_t flags;
        uint32_t size; /* the following payload size */
        union {
#define VHOST_USER_VRING_IDX_MASK   0xff
#define VHOST_USER_VRING_NOFD_MASK  (0x1<<8)
                uint64_t u64;
                struct vhost_vring_state state;
                struct vhost_vring_addr addr;
                VhostUserMemory memory;
        } payload;
        int fds[VHOST_MEMORY_MAX_NREGIONS];
} __attribute((packed)) VhostUserMsg;



---------------------------------------------------------------

./lib/librte_vhost/vhost-net.h


/*
 * Structure used to identify device context.
 */
struct vhost_device_ctx {
        pid_t           pid;    /* PID of process calling the IOCTL. */
        uint64_t        fh;     /* Populated with fi->fh to track the device index. */
};


---------------------------------------------------------------

./lib/librte_vhost/vhost_user/vhost-net-user.h

typedef struct VhostUserMemory {
        uint32_t nregions;
        uint32_t padding;
        VhostUserMemoryRegion regions[VHOST_MEMORY_MAX_NREGIONS];
} VhostUserMemory;


---------------------------------------------------------------

./lib/librte_vhost/rte_virtio_net.h

/**
 * Information relating to memory regions including offsets to addresses in QEMUs memory file.
 */
struct virtio_memory_regions {
        uint64_t        guest_phys_address;     /**< Base guest physical address of region. */
        uint64_t        guest_phys_address_end; /**< End guest physical address of region. */
        uint64_t        memory_size;            /**< Size of region. */
        uint64_t        userspace_address;      /**< Base userspace address of region. */
        uint64_t        address_offset;         /**< Offset of region for address translation. */
};

---------------------------------------------------------------

./lib/librte_vhost/vhost_user/virtio-net-user.c

struct orig_region_map {
        int fd;
        uint64_t mapped_address;
        uint64_t mapped_size;
        uint64_t blksz;
};


---------------------------------------------------------------


./linux-lts-xenial-4.4.0/Documentation/driver-model/device.txt:25:

struct device * get_device(struct device * dev);

get_device() will return a pointer to the struct device passed to it
if the reference is not already 0 (if its in the process of being
removed already).


get_device — increment reference count for device.

struct device * get_device(struct device * dev);


./linux-lts-xenial-4.4.0/include/linux/device.h:1078
/*
 * get_device - atomically increment the reference count for the device.
 *
 */
extern struct device *get_device(struct device *dev);


---------------------------------------------------------------

./lib/librte_vhost/rte_virtio_net.h:122


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


---------------------------------------------------------------

./lib/librte_vhost/rte_virtio_net.h

/**
 * Memory structure includes region and mapping information.
 */
struct virtio_memory {
        uint64_t        base_address;   /**< Base QEMU userspace address of the memory file. */
        uint64_t        mapped_address; /**< Mapped address of memory file base in our applications memory space. */
        uint64_t        mapped_size;    /**< Total size of memory file. */
        uint32_t        nregions;       /**< Number of memory regions. */
        struct virtio_memory_regions      regions[0]; /**< Memory region information. */
};


---------------------------------------------------------------

./lib/librte_vhost/rte_virtio_net.h:57

#define VIRTIO_DEV_RUNNING 1


---------------------------------------------------------------


/*
 * Searches the configuration core linked list and
 * retrieves the device if it exists.
 */
struct virtio_net *
get_device(struct vhost_device_ctx ctx)
{
        struct virtio_net_config_ll *ll_dev;   ------------>    dev linked list

        ll_dev = get_config_ll_entry(ctx);

        if (ll_dev)
                return &ll_dev->dev;

        RTE_LOG(ERR, VHOST_CONFIG,
                "(%"PRIu64") Device not found in linked list.\n", ctx.fh);
        return NULL;
}

---------------------------------------------------------------


./lib/librte_vhost/virtio-net.c:61


/*
 * Device linked list structure for configuration.
 */
struct virtio_net_config_ll {
        struct virtio_net dev;                  /* Virtio device.*/
        struct virtio_net_config_ll *next;      /* Next dev on linked list.*/
};


---------------------------------------------------------------


./lib/librte_vhost/vhost-net.h:83


/*
 * Structure used to identify device context.
 */
struct vhost_device_ctx {
        pid_t           pid;    /* PID of process calling the IOCTL. */
        uint64_t        fh;     /* Populated with fi->fh to track the device index. */
};

---------------------------------------------------------------

./lib/librte_vhost/virtio-net.c:115


/* root address of the linked list of managed virtio devices */
static struct virtio_net_config_ll *ll_root;


/*
 * Retrieves an entry from the devices configuration linked list.
 */
static struct virtio_net_config_ll *
get_config_ll_entry(struct vhost_device_ctx ctx)
{
        struct virtio_net_config_ll *ll_dev = ll_root;

        /* Loop through linked list until the device_fh is found. */
        while (ll_dev != NULL) {
                if (ll_dev->dev.device_fh == ctx.fh)    struct virtio_net => device_fh: device identifier
                        return ll_dev;
                ll_dev = ll_dev->next;
        }

        return NULL;
}


---------------------------------------------------------------


