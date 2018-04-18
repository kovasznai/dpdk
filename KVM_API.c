cat ./linux-lts-xenial-4.4.0/Documentation/virtual/kvm/api.txt
The Definitive KVM (Kernel-based Virtual Machine) API Documentation
===================================================================

1. General description
----------------------

The kvm API is a set of ioctls that are issued to control various aspects
of a virtual machine.  The ioctls belong to three classes

 - System ioctls: These query and set global attributes which affect the
   whole kvm subsystem.  In addition a system ioctl is used to create
   virtual machines

 - VM ioctls: These query and set attributes that affect an entire virtual
   machine, for example memory layout.  In addition a VM ioctl is used to
   create virtual cpus (vcpus).

   Only run VM ioctls from the same process (address space) that was used
   to create the VM.

 - vcpu ioctls: These query and set attributes that control the operation
   of a single virtual cpu.

   Only run vcpu ioctls from the same thread that was used to create the
   vcpu.


2. File descriptors
-------------------

The kvm API is centered around file descriptors.  An initial
open("/dev/kvm") obtains a handle to the kvm subsystem; this handle
can be used to issue system ioctls.  A KVM_CREATE_VM ioctl on this
handle will create a VM file descriptor which can be used to issue VM
ioctls.  A KVM_CREATE_VCPU ioctl on a VM fd will create a virtual cpu
and return a file descriptor pointing to it.  Finally, ioctls on a vcpu
fd can be used to control the vcpu, including the important task of
actually running guest code.

In general file descriptors can be migrated among processes by means
of fork() and the SCM_RIGHTS facility of unix domain socket.  These
kinds of tricks are explicitly not supported by kvm.  While they will
not cause harm to the host, their actual behavior is not guaranteed by
the API.  The only supported use is one virtual machine per process,
and one vcpu per thread.


3. Extensions
-------------

As of Linux 2.6.22, the KVM ABI has been stabilized: no backward
incompatible change are allowed.  However, there is an extension
facility that allows backward-compatible extensions to the API to be
queried and used.

The extension mechanism is not based on the Linux version number.
Instead, kvm defines extension identifiers and a facility to query
whether a particular extension identifier is available.  If it is, a
set of ioctls is available for application use.


4. API description
------------------

This section describes ioctls that can be used to control kvm guests.
For each ioctl, the following information is provided along with a
description:

  Capability: which KVM extension provides this ioctl.  Can be 'basic',
      which means that is will be provided by any kernel that supports
      API version 12 (see section 4.1), a KVM_CAP_xyz constant, which
      means availability needs to be checked with KVM_CHECK_EXTENSION
      (see section 4.4), or 'none' which means that while not all kernels
      support this ioctl, there's no capability bit to check its
      availability: for kernels that don't support the ioctl,
      the ioctl returns -ENOTTY.

  Architectures: which instruction set architectures provide this ioctl.
      x86 includes both i386 and x86_64.

  Type: system, vm, or vcpu.

  Parameters: what parameters are accepted by the ioctl.

  Returns: the return value.  General error numbers (EBADF, ENOMEM, EINVAL)
      are not detailed, but errors with specific meanings are.


4.1 KVM_GET_API_VERSION

Capability: basic
Architectures: all
Type: system ioctl
Parameters: none
Returns: the constant KVM_API_VERSION (=12)

This identifies the API version as the stable kvm API. It is not
expected that this number will change.  However, Linux 2.6.20 and
2.6.21 report earlier versions; these are not documented and not
supported.  Applications should refuse to run if KVM_GET_API_VERSION
returns a value other than 12.  If this check passes, all ioctls
described as 'basic' will be available.


4.2 KVM_CREATE_VM

Capability: basic
Architectures: all
Type: system ioctl
Parameters: machine type identifier (KVM_VM_*)
Returns: a VM fd that can be used to control the new virtual machine.

The new VM has no virtual cpus and no memory.  An mmap() of a VM fd
will access the virtual machine's physical address space; offset zero
corresponds to guest physical address zero.  Use of mmap() on a VM fd
is discouraged if userspace memory allocation (KVM_CAP_USER_MEMORY) is
available.
You most certainly want to use 0 as machine type.

In order to create user controlled virtual machines on S390, check
KVM_CAP_S390_UCONTROL and use the flag KVM_VM_S390_UCONTROL as
privileged user (CAP_SYS_ADMIN).


4.3 KVM_GET_MSR_INDEX_LIST

Capability: basic
Architectures: x86
Type: system
Parameters: struct kvm_msr_list (in/out)
Returns: 0 on success; -1 on error
Errors:
  E2BIG:     the msr index list is to be to fit in the array specified by
             the user.

struct kvm_msr_list {
	__u32 nmsrs; /* number of msrs in entries */
	__u32 indices[0];
};

This ioctl returns the guest msrs that are supported.  The list varies
by kvm version and host processor, but does not change otherwise.  The
user fills in the size of the indices array in nmsrs, and in return
kvm adjusts nmsrs to reflect the actual number of msrs and fills in
the indices array with their numbers.

Note: if kvm indicates supports MCE (KVM_CAP_MCE), then the MCE bank MSRs are
not returned in the MSR list, as different vcpus can have a different number
of banks, as set via the KVM_X86_SETUP_MCE ioctl.


4.4 KVM_CHECK_EXTENSION

Capability: basic, KVM_CAP_CHECK_EXTENSION_VM for vm ioctl
Architectures: all
Type: system ioctl, vm ioctl
Parameters: extension identifier (KVM_CAP_*)
Returns: 0 if unsupported; 1 (or some other positive integer) if supported

The API allows the application to query about extensions to the core
kvm API.  Userspace passes an extension identifier (an integer) and
receives an integer that describes the extension availability.
Generally 0 means no and 1 means yes, but some extensions may report
additional information in the integer return value.

Based on their initialization different VMs may have different capabilities.
It is thus encouraged to use the vm ioctl to query for capabilities (available
with KVM_CAP_CHECK_EXTENSION_VM on the vm fd)

4.5 KVM_GET_VCPU_MMAP_SIZE

Capability: basic
Architectures: all
Type: system ioctl
Parameters: none
Returns: size of vcpu mmap area, in bytes

The KVM_RUN ioctl (cf.) communicates with userspace via a shared
memory region.  This ioctl returns the size of that region.  See the
KVM_RUN documentation for details.


4.6 KVM_SET_MEMORY_REGION

Capability: basic
Architectures: all
Type: vm ioctl
Parameters: struct kvm_memory_region (in)
Returns: 0 on success, -1 on error

This ioctl is obsolete and has been removed.


4.7 KVM_CREATE_VCPU

Capability: basic
Architectures: all
Type: vm ioctl
Parameters: vcpu id (apic id on x86)
Returns: vcpu fd on success, -1 on error

This API adds a vcpu to a virtual machine.  The vcpu id is a small integer
in the range [0, max_vcpus).

The recommended max_vcpus value can be retrieved using the KVM_CAP_NR_VCPUS of
the KVM_CHECK_EXTENSION ioctl() at run-time.
The maximum possible value for max_vcpus can be retrieved using the
KVM_CAP_MAX_VCPUS of the KVM_CHECK_EXTENSION ioctl() at run-time.

If the KVM_CAP_NR_VCPUS does not exist, you should assume that max_vcpus is 4
cpus max.
If the KVM_CAP_MAX_VCPUS does not exist, you should assume that max_vcpus is
same as the value returned from KVM_CAP_NR_VCPUS.

On powerpc using book3s_hv mode, the vcpus are mapped onto virtual
threads in one or more virtual CPU cores.  (This is because the
hardware requires all the hardware threads in a CPU core to be in the
same partition.)  The KVM_CAP_PPC_SMT capability indicates the number
of vcpus per virtual core (vcore).  The vcore id is obtained by
dividing the vcpu id by the number of vcpus per vcore.  The vcpus in a
given vcore will always be in the same physical core as each other
(though that might be a different physical core from time to time).
Userspace can control the threading (SMT) mode of the guest by its
allocation of vcpu ids.  For example, if userspace wants
single-threaded guest vcpus, it should make all vcpu ids be a multiple
of the number of vcpus per vcore.

For virtual cpus that have been created with S390 user controlled virtual
machines, the resulting vcpu fd can be memory mapped at page offset
KVM_S390_SIE_PAGE_OFFSET in order to obtain a memory map of the virtual
cpu's hardware control block.


4.8 KVM_GET_DIRTY_LOG (vm ioctl)

Capability: basic
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_dirty_log (in/out)
Returns: 0 on success, -1 on error

/* for KVM_GET_DIRTY_LOG */
struct kvm_dirty_log {
	__u32 slot;
	__u32 padding;
	union {
		void __user *dirty_bitmap; /* one bit per page */
		__u64 padding;
	};
};

Given a memory slot, return a bitmap containing any pages dirtied
since the last call to this ioctl.  Bit 0 is the first page in the
memory slot.  Ensure the entire structure is cleared to avoid padding
issues.

If KVM_CAP_MULTI_ADDRESS_SPACE is available, bits 16-31 specifies
the address space for which you want to return the dirty bitmap.
They must be less than the value that KVM_CHECK_EXTENSION returns for
the KVM_CAP_MULTI_ADDRESS_SPACE capability.


4.9 KVM_SET_MEMORY_ALIAS

Capability: basic
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_memory_alias (in)
Returns: 0 (success), -1 (error)

This ioctl is obsolete and has been removed.


4.10 KVM_RUN

Capability: basic
Architectures: all
Type: vcpu ioctl
Parameters: none
Returns: 0 on success, -1 on error
Errors:
  EINTR:     an unmasked signal is pending

This ioctl is used to run a guest virtual cpu.  While there are no
explicit parameters, there is an implicit parameter block that can be
obtained by mmap()ing the vcpu fd at offset 0, with the size given by
KVM_GET_VCPU_MMAP_SIZE.  The parameter block is formatted as a 'struct
kvm_run' (see below).


4.11 KVM_GET_REGS

Capability: basic
Architectures: all except ARM, arm64
Type: vcpu ioctl
Parameters: struct kvm_regs (out)
Returns: 0 on success, -1 on error

Reads the general purpose registers from the vcpu.

/* x86 */
struct kvm_regs {
	/* out (KVM_GET_REGS) / in (KVM_SET_REGS) */
	__u64 rax, rbx, rcx, rdx;
	__u64 rsi, rdi, rsp, rbp;
	__u64 r8,  r9,  r10, r11;
	__u64 r12, r13, r14, r15;
	__u64 rip, rflags;
};

/* mips */
struct kvm_regs {
	/* out (KVM_GET_REGS) / in (KVM_SET_REGS) */
	__u64 gpr[32];
	__u64 hi;
	__u64 lo;
	__u64 pc;
};


4.12 KVM_SET_REGS

Capability: basic
Architectures: all except ARM, arm64
Type: vcpu ioctl
Parameters: struct kvm_regs (in)
Returns: 0 on success, -1 on error

Writes the general purpose registers into the vcpu.

See KVM_GET_REGS for the data structure.


4.13 KVM_GET_SREGS

Capability: basic
Architectures: x86, ppc
Type: vcpu ioctl
Parameters: struct kvm_sregs (out)
Returns: 0 on success, -1 on error

Reads special registers from the vcpu.

/* x86 */
struct kvm_sregs {
	struct kvm_segment cs, ds, es, fs, gs, ss;
	struct kvm_segment tr, ldt;
	struct kvm_dtable gdt, idt;
	__u64 cr0, cr2, cr3, cr4, cr8;
	__u64 efer;
	__u64 apic_base;
	__u64 interrupt_bitmap[(KVM_NR_INTERRUPTS + 63) / 64];
};

/* ppc -- see arch/powerpc/include/uapi/asm/kvm.h */

interrupt_bitmap is a bitmap of pending external interrupts.  At most
one bit may be set.  This interrupt has been acknowledged by the APIC
but not yet injected into the cpu core.


4.14 KVM_SET_SREGS

Capability: basic
Architectures: x86, ppc
Type: vcpu ioctl
Parameters: struct kvm_sregs (in)
Returns: 0 on success, -1 on error

Writes special registers into the vcpu.  See KVM_GET_SREGS for the
data structures.


4.15 KVM_TRANSLATE

Capability: basic
Architectures: x86
Type: vcpu ioctl
Parameters: struct kvm_translation (in/out)
Returns: 0 on success, -1 on error

Translates a virtual address according to the vcpu's current address
translation mode.

struct kvm_translation {
	/* in */
	__u64 linear_address;

	/* out */
	__u64 physical_address;
	__u8  valid;
	__u8  writeable;
	__u8  usermode;
	__u8  pad[5];
};


4.16 KVM_INTERRUPT

Capability: basic
Architectures: x86, ppc, mips
Type: vcpu ioctl
Parameters: struct kvm_interrupt (in)
Returns: 0 on success, negative on failure.

Queues a hardware interrupt vector to be injected.

/* for KVM_INTERRUPT */
struct kvm_interrupt {
	/* in */
	__u32 irq;
};

X86:

Returns: 0 on success,
	 -EEXIST if an interrupt is already enqueued
	 -EINVAL the the irq number is invalid
	 -ENXIO if the PIC is in the kernel
	 -EFAULT if the pointer is invalid

Note 'irq' is an interrupt vector, not an interrupt pin or line. This
ioctl is useful if the in-kernel PIC is not used.

PPC:

Queues an external interrupt to be injected. This ioctl is overleaded
with 3 different irq values:

a) KVM_INTERRUPT_SET

  This injects an edge type external interrupt into the guest once it's ready
  to receive interrupts. When injected, the interrupt is done.

b) KVM_INTERRUPT_UNSET

  This unsets any pending interrupt.

  Only available with KVM_CAP_PPC_UNSET_IRQ.

c) KVM_INTERRUPT_SET_LEVEL

  This injects a level type external interrupt into the guest context. The
  interrupt stays pending until a specific ioctl with KVM_INTERRUPT_UNSET
  is triggered.

  Only available with KVM_CAP_PPC_IRQ_LEVEL.

Note that any value for 'irq' other than the ones stated above is invalid
and incurs unexpected behavior.

MIPS:

Queues an external interrupt to be injected into the virtual CPU. A negative
interrupt number dequeues the interrupt.


4.17 KVM_DEBUG_GUEST

Capability: basic
Architectures: none
Type: vcpu ioctl
Parameters: none)
Returns: -1 on error

Support for this has been removed.  Use KVM_SET_GUEST_DEBUG instead.


4.18 KVM_GET_MSRS

Capability: basic
Architectures: x86
Type: vcpu ioctl
Parameters: struct kvm_msrs (in/out)
Returns: 0 on success, -1 on error

Reads model-specific registers from the vcpu.  Supported msr indices can
be obtained using KVM_GET_MSR_INDEX_LIST.

struct kvm_msrs {
	__u32 nmsrs; /* number of msrs in entries */
	__u32 pad;

	struct kvm_msr_entry entries[0];
};

struct kvm_msr_entry {
	__u32 index;
	__u32 reserved;
	__u64 data;
};

Application code should set the 'nmsrs' member (which indicates the
size of the entries array) and the 'index' member of each array entry.
kvm will fill in the 'data' member.


4.19 KVM_SET_MSRS

Capability: basic
Architectures: x86
Type: vcpu ioctl
Parameters: struct kvm_msrs (in)
Returns: 0 on success, -1 on error

Writes model-specific registers to the vcpu.  See KVM_GET_MSRS for the
data structures.

Application code should set the 'nmsrs' member (which indicates the
size of the entries array), and the 'index' and 'data' members of each
array entry.


4.20 KVM_SET_CPUID

Capability: basic
Architectures: x86
Type: vcpu ioctl
Parameters: struct kvm_cpuid (in)
Returns: 0 on success, -1 on error

Defines the vcpu responses to the cpuid instruction.  Applications
should use the KVM_SET_CPUID2 ioctl if available.


struct kvm_cpuid_entry {
	__u32 function;
	__u32 eax;
	__u32 ebx;
	__u32 ecx;
	__u32 edx;
	__u32 padding;
};

/* for KVM_SET_CPUID */
struct kvm_cpuid {
	__u32 nent;
	__u32 padding;
	struct kvm_cpuid_entry entries[0];
};


4.21 KVM_SET_SIGNAL_MASK

Capability: basic
Architectures: all
Type: vcpu ioctl
Parameters: struct kvm_signal_mask (in)
Returns: 0 on success, -1 on error

Defines which signals are blocked during execution of KVM_RUN.  This
signal mask temporarily overrides the threads signal mask.  Any
unblocked signal received (except SIGKILL and SIGSTOP, which retain
their traditional behaviour) will cause KVM_RUN to return with -EINTR.

Note the signal will only be delivered if not blocked by the original
signal mask.

/* for KVM_SET_SIGNAL_MASK */
struct kvm_signal_mask {
	__u32 len;
	__u8  sigset[0];
};


4.22 KVM_GET_FPU

Capability: basic
Architectures: x86
Type: vcpu ioctl
Parameters: struct kvm_fpu (out)
Returns: 0 on success, -1 on error

Reads the floating point state from the vcpu.

/* for KVM_GET_FPU and KVM_SET_FPU */
struct kvm_fpu {
	__u8  fpr[8][16];
	__u16 fcw;
	__u16 fsw;
	__u8  ftwx;  /* in fxsave format */
	__u8  pad1;
	__u16 last_opcode;
	__u64 last_ip;
	__u64 last_dp;
	__u8  xmm[16][16];
	__u32 mxcsr;
	__u32 pad2;
};


4.23 KVM_SET_FPU

Capability: basic
Architectures: x86
Type: vcpu ioctl
Parameters: struct kvm_fpu (in)
Returns: 0 on success, -1 on error

Writes the floating point state to the vcpu.

/* for KVM_GET_FPU and KVM_SET_FPU */
struct kvm_fpu {
	__u8  fpr[8][16];
	__u16 fcw;
	__u16 fsw;
	__u8  ftwx;  /* in fxsave format */
	__u8  pad1;
	__u16 last_opcode;
	__u64 last_ip;
	__u64 last_dp;
	__u8  xmm[16][16];
	__u32 mxcsr;
	__u32 pad2;
};


4.24 KVM_CREATE_IRQCHIP

Capability: KVM_CAP_IRQCHIP, KVM_CAP_S390_IRQCHIP (s390)
Architectures: x86, ARM, arm64, s390
Type: vm ioctl
Parameters: none
Returns: 0 on success, -1 on error

Creates an interrupt controller model in the kernel.
On x86, creates a virtual ioapic, a virtual PIC (two PICs, nested), and sets up
future vcpus to have a local APIC.  IRQ routing for GSIs 0-15 is set to both
PIC and IOAPIC; GSI 16-23 only go to the IOAPIC.
On ARM/arm64, a GICv2 is created. Any other GIC versions require the usage of
KVM_CREATE_DEVICE, which also supports creating a GICv2.  Using
KVM_CREATE_DEVICE is preferred over KVM_CREATE_IRQCHIP for GICv2.
On s390, a dummy irq routing table is created.

Note that on s390 the KVM_CAP_S390_IRQCHIP vm capability needs to be enabled
before KVM_CREATE_IRQCHIP can be used.


4.25 KVM_IRQ_LINE

Capability: KVM_CAP_IRQCHIP
Architectures: x86, arm, arm64
Type: vm ioctl
Parameters: struct kvm_irq_level
Returns: 0 on success, -1 on error

Sets the level of a GSI input to the interrupt controller model in the kernel.
On some architectures it is required that an interrupt controller model has
been previously created with KVM_CREATE_IRQCHIP.  Note that edge-triggered
interrupts require the level to be set to 1 and then back to 0.

On real hardware, interrupt pins can be active-low or active-high.  This
does not matter for the level field of struct kvm_irq_level: 1 always
means active (asserted), 0 means inactive (deasserted).

x86 allows the operating system to program the interrupt polarity
(active-low/active-high) for level-triggered interrupts, and KVM used
to consider the polarity.  However, due to bitrot in the handling of
active-low interrupts, the above convention is now valid on x86 too.
This is signaled by KVM_CAP_X86_IOAPIC_POLARITY_IGNORED.  Userspace
should not present interrupts to the guest as active-low unless this
capability is present (or unless it is not using the in-kernel irqchip,
of course).


ARM/arm64 can signal an interrupt either at the CPU level, or at the
in-kernel irqchip (GIC), and for in-kernel irqchip can tell the GIC to
use PPIs designated for specific cpus.  The irq field is interpreted
like this:

  bits:  | 31 ... 24 | 23  ... 16 | 15    ...    0 |
  field: | irq_type  | vcpu_index |     irq_id     |

The irq_type field has the following values:
- irq_type[0]: out-of-kernel GIC: irq_id 0 is IRQ, irq_id 1 is FIQ
- irq_type[1]: in-kernel GIC: SPI, irq_id between 32 and 1019 (incl.)
               (the vcpu_index field is ignored)
- irq_type[2]: in-kernel GIC: PPI, irq_id between 16 and 31 (incl.)

(The irq_id field thus corresponds nicely to the IRQ ID in the ARM GIC specs)

In both cases, level is used to assert/deassert the line.

struct kvm_irq_level {
	union {
		__u32 irq;     /* GSI */
		__s32 status;  /* not used for KVM_IRQ_LEVEL */
	};
	__u32 level;           /* 0 or 1 */
};


4.26 KVM_GET_IRQCHIP

Capability: KVM_CAP_IRQCHIP
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_irqchip (in/out)
Returns: 0 on success, -1 on error

Reads the state of a kernel interrupt controller created with
KVM_CREATE_IRQCHIP into a buffer provided by the caller.

struct kvm_irqchip {
	__u32 chip_id;  /* 0 = PIC1, 1 = PIC2, 2 = IOAPIC */
	__u32 pad;
        union {
		char dummy[512];  /* reserving space */
		struct kvm_pic_state pic;
		struct kvm_ioapic_state ioapic;
	} chip;
};


4.27 KVM_SET_IRQCHIP

Capability: KVM_CAP_IRQCHIP
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_irqchip (in)
Returns: 0 on success, -1 on error

Sets the state of a kernel interrupt controller created with
KVM_CREATE_IRQCHIP from a buffer provided by the caller.

struct kvm_irqchip {
	__u32 chip_id;  /* 0 = PIC1, 1 = PIC2, 2 = IOAPIC */
	__u32 pad;
        union {
		char dummy[512];  /* reserving space */
		struct kvm_pic_state pic;
		struct kvm_ioapic_state ioapic;
	} chip;
};


4.28 KVM_XEN_HVM_CONFIG

Capability: KVM_CAP_XEN_HVM
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_xen_hvm_config (in)
Returns: 0 on success, -1 on error

Sets the MSR that the Xen HVM guest uses to initialize its hypercall
page, and provides the starting address and size of the hypercall
blobs in userspace.  When the guest writes the MSR, kvm copies one
page of a blob (32- or 64-bit, depending on the vcpu mode) to guest
memory.

struct kvm_xen_hvm_config {
	__u32 flags;
	__u32 msr;
	__u64 blob_addr_32;
	__u64 blob_addr_64;
	__u8 blob_size_32;
	__u8 blob_size_64;
	__u8 pad2[30];
};


4.29 KVM_GET_CLOCK

Capability: KVM_CAP_ADJUST_CLOCK
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_clock_data (out)
Returns: 0 on success, -1 on error

Gets the current timestamp of kvmclock as seen by the current guest. In
conjunction with KVM_SET_CLOCK, it is used to ensure monotonicity on scenarios
such as migration.

struct kvm_clock_data {
	__u64 clock;  /* kvmclock current value */
	__u32 flags;
	__u32 pad[9];
};


4.30 KVM_SET_CLOCK

Capability: KVM_CAP_ADJUST_CLOCK
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_clock_data (in)
Returns: 0 on success, -1 on error

Sets the current timestamp of kvmclock to the value specified in its parameter.
In conjunction with KVM_GET_CLOCK, it is used to ensure monotonicity on scenarios
such as migration.

struct kvm_clock_data {
	__u64 clock;  /* kvmclock current value */
	__u32 flags;
	__u32 pad[9];
};


4.31 KVM_GET_VCPU_EVENTS

Capability: KVM_CAP_VCPU_EVENTS
Extended by: KVM_CAP_INTR_SHADOW
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_vcpu_event (out)
Returns: 0 on success, -1 on error

Gets currently pending exceptions, interrupts, and NMIs as well as related
states of the vcpu.

struct kvm_vcpu_events {
	struct {
		__u8 injected;
		__u8 nr;
		__u8 has_error_code;
		__u8 pad;
		__u32 error_code;
	} exception;
	struct {
		__u8 injected;
		__u8 nr;
		__u8 soft;
		__u8 shadow;
	} interrupt;
	struct {
		__u8 injected;
		__u8 pending;
		__u8 masked;
		__u8 pad;
	} nmi;
	__u32 sipi_vector;
	__u32 flags;
	struct {
		__u8 smm;
		__u8 pending;
		__u8 smm_inside_nmi;
		__u8 latched_init;
	} smi;
};

Only two fields are defined in the flags field:

- KVM_VCPUEVENT_VALID_SHADOW may be set in the flags field to signal that
  interrupt.shadow contains a valid state.

- KVM_VCPUEVENT_VALID_SMM may be set in the flags field to signal that
  smi contains a valid state.

4.32 KVM_SET_VCPU_EVENTS

Capability: KVM_CAP_VCPU_EVENTS
Extended by: KVM_CAP_INTR_SHADOW
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_vcpu_event (in)
Returns: 0 on success, -1 on error

Set pending exceptions, interrupts, and NMIs as well as related states of the
vcpu.

See KVM_GET_VCPU_EVENTS for the data structure.

Fields that may be modified asynchronously by running VCPUs can be excluded
from the update. These fields are nmi.pending, sipi_vector, smi.smm,
smi.pending. Keep the corresponding bits in the flags field cleared to
suppress overwriting the current in-kernel state. The bits are:

KVM_VCPUEVENT_VALID_NMI_PENDING - transfer nmi.pending to the kernel
KVM_VCPUEVENT_VALID_SIPI_VECTOR - transfer sipi_vector
KVM_VCPUEVENT_VALID_SMM         - transfer the smi sub-struct.

If KVM_CAP_INTR_SHADOW is available, KVM_VCPUEVENT_VALID_SHADOW can be set in
the flags field to signal that interrupt.shadow contains a valid state and
shall be written into the VCPU.

KVM_VCPUEVENT_VALID_SMM can only be set if KVM_CAP_X86_SMM is available.


4.33 KVM_GET_DEBUGREGS

Capability: KVM_CAP_DEBUGREGS
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_debugregs (out)
Returns: 0 on success, -1 on error

Reads debug registers from the vcpu.

struct kvm_debugregs {
	__u64 db[4];
	__u64 dr6;
	__u64 dr7;
	__u64 flags;
	__u64 reserved[9];
};


4.34 KVM_SET_DEBUGREGS

Capability: KVM_CAP_DEBUGREGS
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_debugregs (in)
Returns: 0 on success, -1 on error

Writes debug registers into the vcpu.

See KVM_GET_DEBUGREGS for the data structure. The flags field is unused
yet and must be cleared on entry.


4.35 KVM_SET_USER_MEMORY_REGION

Capability: KVM_CAP_USER_MEM
Architectures: all
Type: vm ioctl
Parameters: struct kvm_userspace_memory_region (in)
Returns: 0 on success, -1 on error

struct kvm_userspace_memory_region {
	__u32 slot;
	__u32 flags;
	__u64 guest_phys_addr;
	__u64 memory_size; /* bytes */
	__u64 userspace_addr; /* start of the userspace allocated memory */
};

/* for kvm_memory_region::flags */
#define KVM_MEM_LOG_DIRTY_PAGES	(1UL << 0)
#define KVM_MEM_READONLY	(1UL << 1)

This ioctl allows the user to create or modify a guest physical memory
slot.  When changing an existing slot, it may be moved in the guest
physical memory space, or its flags may be modified.  It may not be
resized.  Slots may not overlap in guest physical address space.

If KVM_CAP_MULTI_ADDRESS_SPACE is available, bits 16-31 of "slot"
specifies the address space which is being modified.  They must be
less than the value that KVM_CHECK_EXTENSION returns for the
KVM_CAP_MULTI_ADDRESS_SPACE capability.  Slots in separate address spaces
are unrelated; the restriction on overlapping slots only applies within
each address space.

Memory for the region is taken starting at the address denoted by the
field userspace_addr, which must point at user addressable memory for
the entire memory slot size.  Any object may back this memory, including
anonymous memory, ordinary files, and hugetlbfs.

It is recommended that the lower 21 bits of guest_phys_addr and userspace_addr
be identical.  This allows large pages in the guest to be backed by large
pages in the host.

The flags field supports two flags: KVM_MEM_LOG_DIRTY_PAGES and
KVM_MEM_READONLY.  The former can be set to instruct KVM to keep track of
writes to memory within the slot.  See KVM_GET_DIRTY_LOG ioctl to know how to
use it.  The latter can be set, if KVM_CAP_READONLY_MEM capability allows it,
to make a new slot read-only.  In this case, writes to this memory will be
posted to userspace as KVM_EXIT_MMIO exits.

When the KVM_CAP_SYNC_MMU capability is available, changes in the backing of
the memory region are automatically reflected into the guest.  For example, an
mmap() that affects the region will be made visible immediately.  Another
example is madvise(MADV_DROP).

It is recommended to use this API instead of the KVM_SET_MEMORY_REGION ioctl.
The KVM_SET_MEMORY_REGION does not allow fine grained control over memory
allocation and is deprecated.


4.36 KVM_SET_TSS_ADDR

Capability: KVM_CAP_SET_TSS_ADDR
Architectures: x86
Type: vm ioctl
Parameters: unsigned long tss_address (in)
Returns: 0 on success, -1 on error

This ioctl defines the physical address of a three-page region in the guest
physical address space.  The region must be within the first 4GB of the
guest physical address space and must not conflict with any memory slot
or any mmio address.  The guest may malfunction if it accesses this memory
region.

This ioctl is required on Intel-based hosts.  This is needed on Intel hardware
because of a quirk in the virtualization implementation (see the internals
documentation when it pops into existence).


4.37 KVM_ENABLE_CAP

Capability: KVM_CAP_ENABLE_CAP, KVM_CAP_ENABLE_CAP_VM
Architectures: x86 (only KVM_CAP_ENABLE_CAP_VM),
	       mips (only KVM_CAP_ENABLE_CAP), ppc, s390
Type: vcpu ioctl, vm ioctl (with KVM_CAP_ENABLE_CAP_VM)
Parameters: struct kvm_enable_cap (in)
Returns: 0 on success; -1 on error

+Not all extensions are enabled by default. Using this ioctl the application
can enable an extension, making it available to the guest.

On systems that do not support this ioctl, it always fails. On systems that
do support it, it only works for extensions that are supported for enablement.

To check if a capability can be enabled, the KVM_CHECK_EXTENSION ioctl should
be used.

struct kvm_enable_cap {
       /* in */
       __u32 cap;

The capability that is supposed to get enabled.

       __u32 flags;

A bitfield indicating future enhancements. Has to be 0 for now.

       __u64 args[4];

Arguments for enabling a feature. If a feature needs initial values to
function properly, this is the place to put them.

       __u8  pad[64];
};

The vcpu ioctl should be used for vcpu-specific capabilities, the vm ioctl
for vm-wide capabilities.

4.38 KVM_GET_MP_STATE

Capability: KVM_CAP_MP_STATE
Architectures: x86, s390, arm, arm64
Type: vcpu ioctl
Parameters: struct kvm_mp_state (out)
Returns: 0 on success; -1 on error

struct kvm_mp_state {
	__u32 mp_state;
};

Returns the vcpu's current "multiprocessing state" (though also valid on
uniprocessor guests).

Possible values are:

 - KVM_MP_STATE_RUNNABLE:        the vcpu is currently running [x86,arm/arm64]
 - KVM_MP_STATE_UNINITIALIZED:   the vcpu is an application processor (AP)
                                 which has not yet received an INIT signal [x86]
 - KVM_MP_STATE_INIT_RECEIVED:   the vcpu has received an INIT signal, and is
                                 now ready for a SIPI [x86]
 - KVM_MP_STATE_HALTED:          the vcpu has executed a HLT instruction and
                                 is waiting for an interrupt [x86]
 - KVM_MP_STATE_SIPI_RECEIVED:   the vcpu has just received a SIPI (vector
                                 accessible via KVM_GET_VCPU_EVENTS) [x86]
 - KVM_MP_STATE_STOPPED:         the vcpu is stopped [s390,arm/arm64]
 - KVM_MP_STATE_CHECK_STOP:      the vcpu is in a special error state [s390]
 - KVM_MP_STATE_OPERATING:       the vcpu is operating (running or halted)
                                 [s390]
 - KVM_MP_STATE_LOAD:            the vcpu is in a special load/startup state
                                 [s390]

On x86, this ioctl is only useful after KVM_CREATE_IRQCHIP. Without an
in-kernel irqchip, the multiprocessing state must be maintained by userspace on
these architectures.

For arm/arm64:

The only states that are valid are KVM_MP_STATE_STOPPED and
KVM_MP_STATE_RUNNABLE which reflect if the vcpu is paused or not.

4.39 KVM_SET_MP_STATE

Capability: KVM_CAP_MP_STATE
Architectures: x86, s390, arm, arm64
Type: vcpu ioctl
Parameters: struct kvm_mp_state (in)
Returns: 0 on success; -1 on error

Sets the vcpu's current "multiprocessing state"; see KVM_GET_MP_STATE for
arguments.

On x86, this ioctl is only useful after KVM_CREATE_IRQCHIP. Without an
in-kernel irqchip, the multiprocessing state must be maintained by userspace on
these architectures.

For arm/arm64:

The only states that are valid are KVM_MP_STATE_STOPPED and
KVM_MP_STATE_RUNNABLE which reflect if the vcpu should be paused or not.

4.40 KVM_SET_IDENTITY_MAP_ADDR

Capability: KVM_CAP_SET_IDENTITY_MAP_ADDR
Architectures: x86
Type: vm ioctl
Parameters: unsigned long identity (in)
Returns: 0 on success, -1 on error

This ioctl defines the physical address of a one-page region in the guest
physical address space.  The region must be within the first 4GB of the
guest physical address space and must not conflict with any memory slot
or any mmio address.  The guest may malfunction if it accesses this memory
region.

This ioctl is required on Intel-based hosts.  This is needed on Intel hardware
because of a quirk in the virtualization implementation (see the internals
documentation when it pops into existence).


4.41 KVM_SET_BOOT_CPU_ID

Capability: KVM_CAP_SET_BOOT_CPU_ID
Architectures: x86
Type: vm ioctl
Parameters: unsigned long vcpu_id
Returns: 0 on success, -1 on error

Define which vcpu is the Bootstrap Processor (BSP).  Values are the same
as the vcpu id in KVM_CREATE_VCPU.  If this ioctl is not called, the default
is vcpu 0.


4.42 KVM_GET_XSAVE

Capability: KVM_CAP_XSAVE
Architectures: x86
Type: vcpu ioctl
Parameters: struct kvm_xsave (out)
Returns: 0 on success, -1 on error

struct kvm_xsave {
	__u32 region[1024];
};

This ioctl would copy current vcpu's xsave struct to the userspace.


4.43 KVM_SET_XSAVE

Capability: KVM_CAP_XSAVE
Architectures: x86
Type: vcpu ioctl
Parameters: struct kvm_xsave (in)
Returns: 0 on success, -1 on error

struct kvm_xsave {
	__u32 region[1024];
};

This ioctl would copy userspace's xsave struct to the kernel.


4.44 KVM_GET_XCRS

Capability: KVM_CAP_XCRS
Architectures: x86
Type: vcpu ioctl
Parameters: struct kvm_xcrs (out)
Returns: 0 on success, -1 on error

struct kvm_xcr {
	__u32 xcr;
	__u32 reserved;
	__u64 value;
};

struct kvm_xcrs {
	__u32 nr_xcrs;
	__u32 flags;
	struct kvm_xcr xcrs[KVM_MAX_XCRS];
	__u64 padding[16];
};

This ioctl would copy current vcpu's xcrs to the userspace.


4.45 KVM_SET_XCRS

Capability: KVM_CAP_XCRS
Architectures: x86
Type: vcpu ioctl
Parameters: struct kvm_xcrs (in)
Returns: 0 on success, -1 on error

struct kvm_xcr {
	__u32 xcr;
	__u32 reserved;
	__u64 value;
};

struct kvm_xcrs {
	__u32 nr_xcrs;
	__u32 flags;
	struct kvm_xcr xcrs[KVM_MAX_XCRS];
	__u64 padding[16];
};

This ioctl would set vcpu's xcr to the value userspace specified.


4.46 KVM_GET_SUPPORTED_CPUID

Capability: KVM_CAP_EXT_CPUID
Architectures: x86
Type: system ioctl
Parameters: struct kvm_cpuid2 (in/out)
Returns: 0 on success, -1 on error

struct kvm_cpuid2 {
	__u32 nent;
	__u32 padding;
	struct kvm_cpuid_entry2 entries[0];
};

#define KVM_CPUID_FLAG_SIGNIFCANT_INDEX		BIT(0)
#define KVM_CPUID_FLAG_STATEFUL_FUNC		BIT(1)
#define KVM_CPUID_FLAG_STATE_READ_NEXT		BIT(2)

struct kvm_cpuid_entry2 {
	__u32 function;
	__u32 index;
	__u32 flags;
	__u32 eax;
	__u32 ebx;
	__u32 ecx;
	__u32 edx;
	__u32 padding[3];
};

This ioctl returns x86 cpuid features which are supported by both the hardware
and kvm.  Userspace can use the information returned by this ioctl to
construct cpuid information (for KVM_SET_CPUID2) that is consistent with
hardware, kernel, and userspace capabilities, and with user requirements (for
example, the user may wish to constrain cpuid to emulate older hardware,
or for feature consistency across a cluster).

Userspace invokes KVM_GET_SUPPORTED_CPUID by passing a kvm_cpuid2 structure
with the 'nent' field indicating the number of entries in the variable-size
array 'entries'.  If the number of entries is too low to describe the cpu
capabilities, an error (E2BIG) is returned.  If the number is too high,
the 'nent' field is adjusted and an error (ENOMEM) is returned.  If the
number is just right, the 'nent' field is adjusted to the number of valid
entries in the 'entries' array, which is then filled.

The entries returned are the host cpuid as returned by the cpuid instruction,
with unknown or unsupported features masked out.  Some features (for example,
x2apic), may not be present in the host cpu, but are exposed by kvm if it can
emulate them efficiently. The fields in each entry are defined as follows:

  function: the eax value used to obtain the entry
  index: the ecx value used to obtain the entry (for entries that are
         affected by ecx)
  flags: an OR of zero or more of the following:
        KVM_CPUID_FLAG_SIGNIFCANT_INDEX:
           if the index field is valid
        KVM_CPUID_FLAG_STATEFUL_FUNC:
           if cpuid for this function returns different values for successive
           invocations; there will be several entries with the same function,
           all with this flag set
        KVM_CPUID_FLAG_STATE_READ_NEXT:
           for KVM_CPUID_FLAG_STATEFUL_FUNC entries, set if this entry is
           the first entry to be read by a cpu
   eax, ebx, ecx, edx: the values returned by the cpuid instruction for
         this function/index combination

The TSC deadline timer feature (CPUID leaf 1, ecx[24]) is always returned
as false, since the feature depends on KVM_CREATE_IRQCHIP for local APIC
support.  Instead it is reported via

  ioctl(KVM_CHECK_EXTENSION, KVM_CAP_TSC_DEADLINE_TIMER)

if that returns true and you use KVM_CREATE_IRQCHIP, or if you emulate the
feature in userspace, then you can enable the feature for KVM_SET_CPUID2.


4.47 KVM_PPC_GET_PVINFO

Capability: KVM_CAP_PPC_GET_PVINFO
Architectures: ppc
Type: vm ioctl
Parameters: struct kvm_ppc_pvinfo (out)
Returns: 0 on success, !0 on error

struct kvm_ppc_pvinfo {
	__u32 flags;
	__u32 hcall[4];
	__u8  pad[108];
};

This ioctl fetches PV specific information that need to be passed to the guest
using the device tree or other means from vm context.

The hcall array defines 4 instructions that make up a hypercall.

If any additional field gets added to this structure later on, a bit for that
additional piece of information will be set in the flags bitmap.

The flags bitmap is defined as:

   /* the host supports the ePAPR idle hcall
   #define KVM_PPC_PVINFO_FLAGS_EV_IDLE   (1<<0)

4.48 KVM_ASSIGN_PCI_DEVICE (deprecated)

Capability: none
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_assigned_pci_dev (in)
Returns: 0 on success, -1 on error

Assigns a host PCI device to the VM.

struct kvm_assigned_pci_dev {
	__u32 assigned_dev_id;
	__u32 busnr;
	__u32 devfn;
	__u32 flags;
	__u32 segnr;
	union {
		__u32 reserved[11];
	};
};

The PCI device is specified by the triple segnr, busnr, and devfn.
Identification in succeeding service requests is done via assigned_dev_id. The
following flags are specified:

/* Depends on KVM_CAP_IOMMU */
#define KVM_DEV_ASSIGN_ENABLE_IOMMU	(1 << 0)
/* The following two depend on KVM_CAP_PCI_2_3 */
#define KVM_DEV_ASSIGN_PCI_2_3		(1 << 1)
#define KVM_DEV_ASSIGN_MASK_INTX	(1 << 2)

If KVM_DEV_ASSIGN_PCI_2_3 is set, the kernel will manage legacy INTx interrupts
via the PCI-2.3-compliant device-level mask, thus enable IRQ sharing with other
assigned devices or host devices. KVM_DEV_ASSIGN_MASK_INTX specifies the
guest's view on the INTx mask, see KVM_ASSIGN_SET_INTX_MASK for details.

The KVM_DEV_ASSIGN_ENABLE_IOMMU flag is a mandatory option to ensure
isolation of the device.  Usages not specifying this flag are deprecated.

Only PCI header type 0 devices with PCI BAR resources are supported by
device assignment.  The user requesting this ioctl must have read/write
access to the PCI sysfs resource files associated with the device.

Errors:
  ENOTTY: kernel does not support this ioctl

  Other error conditions may be defined by individual device types or
  have their standard meanings.


4.49 KVM_DEASSIGN_PCI_DEVICE (deprecated)

Capability: none
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_assigned_pci_dev (in)
Returns: 0 on success, -1 on error

Ends PCI device assignment, releasing all associated resources.

See KVM_ASSIGN_PCI_DEVICE for the data structure. Only assigned_dev_id is
used in kvm_assigned_pci_dev to identify the device.

Errors:
  ENOTTY: kernel does not support this ioctl

  Other error conditions may be defined by individual device types or
  have their standard meanings.

4.50 KVM_ASSIGN_DEV_IRQ (deprecated)

Capability: KVM_CAP_ASSIGN_DEV_IRQ
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_assigned_irq (in)
Returns: 0 on success, -1 on error

Assigns an IRQ to a passed-through device.

struct kvm_assigned_irq {
	__u32 assigned_dev_id;
	__u32 host_irq; /* ignored (legacy field) */
	__u32 guest_irq;
	__u32 flags;
	union {
		__u32 reserved[12];
	};
};

The following flags are defined:

#define KVM_DEV_IRQ_HOST_INTX    (1 << 0)
#define KVM_DEV_IRQ_HOST_MSI     (1 << 1)
#define KVM_DEV_IRQ_HOST_MSIX    (1 << 2)

#define KVM_DEV_IRQ_GUEST_INTX   (1 << 8)
#define KVM_DEV_IRQ_GUEST_MSI    (1 << 9)
#define KVM_DEV_IRQ_GUEST_MSIX   (1 << 10)

It is not valid to specify multiple types per host or guest IRQ. However, the
IRQ type of host and guest can differ or can even be null.

Errors:
  ENOTTY: kernel does not support this ioctl

  Other error conditions may be defined by individual device types or
  have their standard meanings.


4.51 KVM_DEASSIGN_DEV_IRQ (deprecated)

Capability: KVM_CAP_ASSIGN_DEV_IRQ
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_assigned_irq (in)
Returns: 0 on success, -1 on error

Ends an IRQ assignment to a passed-through device.

See KVM_ASSIGN_DEV_IRQ for the data structure. The target device is specified
by assigned_dev_id, flags must correspond to the IRQ type specified on
KVM_ASSIGN_DEV_IRQ. Partial deassignment of host or guest IRQ is allowed.


4.52 KVM_SET_GSI_ROUTING

Capability: KVM_CAP_IRQ_ROUTING
Architectures: x86 s390
Type: vm ioctl
Parameters: struct kvm_irq_routing (in)
Returns: 0 on success, -1 on error

Sets the GSI routing table entries, overwriting any previously set entries.

struct kvm_irq_routing {
	__u32 nr;
	__u32 flags;
	struct kvm_irq_routing_entry entries[0];
};

No flags are specified so far, the corresponding field must be set to zero.

struct kvm_irq_routing_entry {
	__u32 gsi;
	__u32 type;
	__u32 flags;
	__u32 pad;
	union {
		struct kvm_irq_routing_irqchip irqchip;
		struct kvm_irq_routing_msi msi;
		struct kvm_irq_routing_s390_adapter adapter;
		struct kvm_irq_routing_hv_sint hv_sint;
		__u32 pad[8];
	} u;
};

/* gsi routing entry types */
#define KVM_IRQ_ROUTING_IRQCHIP 1
#define KVM_IRQ_ROUTING_MSI 2
#define KVM_IRQ_ROUTING_S390_ADAPTER 3
#define KVM_IRQ_ROUTING_HV_SINT 4

No flags are specified so far, the corresponding field must be set to zero.

struct kvm_irq_routing_irqchip {
	__u32 irqchip;
	__u32 pin;
};

struct kvm_irq_routing_msi {
	__u32 address_lo;
	__u32 address_hi;
	__u32 data;
	__u32 pad;
};

struct kvm_irq_routing_s390_adapter {
	__u64 ind_addr;
	__u64 summary_addr;
	__u64 ind_offset;
	__u32 summary_offset;
	__u32 adapter_id;
};

struct kvm_irq_routing_hv_sint {
	__u32 vcpu;
	__u32 sint;
};

4.53 KVM_ASSIGN_SET_MSIX_NR (deprecated)

Capability: none
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_assigned_msix_nr (in)
Returns: 0 on success, -1 on error

Set the number of MSI-X interrupts for an assigned device. The number is
reset again by terminating the MSI-X assignment of the device via
KVM_DEASSIGN_DEV_IRQ. Calling this service more than once at any earlier
point will fail.

struct kvm_assigned_msix_nr {
	__u32 assigned_dev_id;
	__u16 entry_nr;
	__u16 padding;
};

#define KVM_MAX_MSIX_PER_DEV		256


4.54 KVM_ASSIGN_SET_MSIX_ENTRY (deprecated)

Capability: none
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_assigned_msix_entry (in)
Returns: 0 on success, -1 on error

Specifies the routing of an MSI-X assigned device interrupt to a GSI. Setting
the GSI vector to zero means disabling the interrupt.

struct kvm_assigned_msix_entry {
	__u32 assigned_dev_id;
	__u32 gsi;
	__u16 entry; /* The index of entry in the MSI-X table */
	__u16 padding[3];
};

Errors:
  ENOTTY: kernel does not support this ioctl

  Other error conditions may be defined by individual device types or
  have their standard meanings.


4.55 KVM_SET_TSC_KHZ

Capability: KVM_CAP_TSC_CONTROL
Architectures: x86
Type: vcpu ioctl
Parameters: virtual tsc_khz
Returns: 0 on success, -1 on error

Specifies the tsc frequency for the virtual machine. The unit of the
frequency is KHz.


4.56 KVM_GET_TSC_KHZ

Capability: KVM_CAP_GET_TSC_KHZ
Architectures: x86
Type: vcpu ioctl
Parameters: none
Returns: virtual tsc-khz on success, negative value on error

Returns the tsc frequency of the guest. The unit of the return value is
KHz. If the host has unstable tsc this ioctl returns -EIO instead as an
error.


4.57 KVM_GET_LAPIC

Capability: KVM_CAP_IRQCHIP
Architectures: x86
Type: vcpu ioctl
Parameters: struct kvm_lapic_state (out)
Returns: 0 on success, -1 on error

#define KVM_APIC_REG_SIZE 0x400
struct kvm_lapic_state {
	char regs[KVM_APIC_REG_SIZE];
};

Reads the Local APIC registers and copies them into the input argument.  The
data format and layout are the same as documented in the architecture manual.


4.58 KVM_SET_LAPIC

Capability: KVM_CAP_IRQCHIP
Architectures: x86
Type: vcpu ioctl
Parameters: struct kvm_lapic_state (in)
Returns: 0 on success, -1 on error

#define KVM_APIC_REG_SIZE 0x400
struct kvm_lapic_state {
	char regs[KVM_APIC_REG_SIZE];
};

Copies the input argument into the Local APIC registers.  The data format
and layout are the same as documented in the architecture manual.


4.59 KVM_IOEVENTFD

Capability: KVM_CAP_IOEVENTFD
Architectures: all
Type: vm ioctl
Parameters: struct kvm_ioeventfd (in)
Returns: 0 on success, !0 on error

This ioctl attaches or detaches an ioeventfd to a legal pio/mmio address
within the guest.  A guest write in the registered address will signal the
provided event instead of triggering an exit.

struct kvm_ioeventfd {
	__u64 datamatch;
	__u64 addr;        /* legal pio/mmio address */
	__u32 len;         /* 0, 1, 2, 4, or 8 bytes    */
	__s32 fd;
	__u32 flags;
	__u8  pad[36];
};

For the special case of virtio-ccw devices on s390, the ioevent is matched
to a subchannel/virtqueue tuple instead.

The following flags are defined:

#define KVM_IOEVENTFD_FLAG_DATAMATCH (1 << kvm_ioeventfd_flag_nr_datamatch)
#define KVM_IOEVENTFD_FLAG_PIO       (1 << kvm_ioeventfd_flag_nr_pio)
#define KVM_IOEVENTFD_FLAG_DEASSIGN  (1 << kvm_ioeventfd_flag_nr_deassign)
#define KVM_IOEVENTFD_FLAG_VIRTIO_CCW_NOTIFY \
	(1 << kvm_ioeventfd_flag_nr_virtio_ccw_notify)

If datamatch flag is set, the event will be signaled only if the written value
to the registered address is equal to datamatch in struct kvm_ioeventfd.

For virtio-ccw devices, addr contains the subchannel id and datamatch the
virtqueue index.

With KVM_CAP_IOEVENTFD_ANY_LENGTH, a zero length ioeventfd is allowed, and
the kernel will ignore the length of guest write and may get a faster vmexit.
The speedup may only apply to specific architectures, but the ioeventfd will
work anyway.

4.60 KVM_DIRTY_TLB

Capability: KVM_CAP_SW_TLB
Architectures: ppc
Type: vcpu ioctl
Parameters: struct kvm_dirty_tlb (in)
Returns: 0 on success, -1 on error

struct kvm_dirty_tlb {
	__u64 bitmap;
	__u32 num_dirty;
};

This must be called whenever userspace has changed an entry in the shared
TLB, prior to calling KVM_RUN on the associated vcpu.

The "bitmap" field is the userspace address of an array.  This array
consists of a number of bits, equal to the total number of TLB entries as
determined by the last successful call to KVM_CONFIG_TLB, rounded up to the
nearest multiple of 64.

Each bit corresponds to one TLB entry, ordered the same as in the shared TLB
array.

The array is little-endian: the bit 0 is the least significant bit of the
first byte, bit 8 is the least significant bit of the second byte, etc.
This avoids any complications with differing word sizes.

The "num_dirty" field is a performance hint for KVM to determine whether it
should skip processing the bitmap and just invalidate everything.  It must
be set to the number of set bits in the bitmap.


4.61 KVM_ASSIGN_SET_INTX_MASK (deprecated)

Capability: KVM_CAP_PCI_2_3
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_assigned_pci_dev (in)
Returns: 0 on success, -1 on error

Allows userspace to mask PCI INTx interrupts from the assigned device.  The
kernel will not deliver INTx interrupts to the guest between setting and
clearing of KVM_ASSIGN_SET_INTX_MASK via this interface.  This enables use of
and emulation of PCI 2.3 INTx disable command register behavior.

This may be used for both PCI 2.3 devices supporting INTx disable natively and
older devices lacking this support. Userspace is responsible for emulating the
read value of the INTx disable bit in the guest visible PCI command register.
When modifying the INTx disable state, userspace should precede updating the
physical device command register by calling this ioctl to inform the kernel of
the new intended INTx mask state.

Note that the kernel uses the device INTx disable bit to internally manage the
device interrupt state for PCI 2.3 devices.  Reads of this register may
therefore not match the expected value.  Writes should always use the guest
intended INTx disable value rather than attempting to read-copy-update the
current physical device state.  Races between user and kernel updates to the
INTx disable bit are handled lazily in the kernel.  It's possible the device
may generate unintended interrupts, but they will not be injected into the
guest.

See KVM_ASSIGN_DEV_IRQ for the data structure.  The target device is specified
by assigned_dev_id.  In the flags field, only KVM_DEV_ASSIGN_MASK_INTX is
evaluated.


4.62 KVM_CREATE_SPAPR_TCE

Capability: KVM_CAP_SPAPR_TCE
Architectures: powerpc
Type: vm ioctl
Parameters: struct kvm_create_spapr_tce (in)
Returns: file descriptor for manipulating the created TCE table

This creates a virtual TCE (translation control entry) table, which
is an IOMMU for PAPR-style virtual I/O.  It is used to translate
logical addresses used in virtual I/O into guest physical addresses,
and provides a scatter/gather capability for PAPR virtual I/O.

/* for KVM_CAP_SPAPR_TCE */
struct kvm_create_spapr_tce {
	__u64 liobn;
	__u32 window_size;
};

The liobn field gives the logical IO bus number for which to create a
TCE table.  The window_size field specifies the size of the DMA window
which this TCE table will translate - the table will contain one 64
bit TCE entry for every 4kiB of the DMA window.

When the guest issues an H_PUT_TCE hcall on a liobn for which a TCE
table has been created using this ioctl(), the kernel will handle it
in real mode, updating the TCE table.  H_PUT_TCE calls for other
liobns will cause a vm exit and must be handled by userspace.

The return value is a file descriptor which can be passed to mmap(2)
to map the created TCE table into userspace.  This lets userspace read
the entries written by kernel-handled H_PUT_TCE calls, and also lets
userspace update the TCE table directly which is useful in some
circumstances.


4.63 KVM_ALLOCATE_RMA

Capability: KVM_CAP_PPC_RMA
Architectures: powerpc
Type: vm ioctl
Parameters: struct kvm_allocate_rma (out)
Returns: file descriptor for mapping the allocated RMA

This allocates a Real Mode Area (RMA) from the pool allocated at boot
time by the kernel.  An RMA is a physically-contiguous, aligned region
of memory used on older POWER processors to provide the memory which
will be accessed by real-mode (MMU off) accesses in a KVM guest.
POWER processors support a set of sizes for the RMA that usually
includes 64MB, 128MB, 256MB and some larger powers of two.

/* for KVM_ALLOCATE_RMA */
struct kvm_allocate_rma {
	__u64 rma_size;
};

The return value is a file descriptor which can be passed to mmap(2)
to map the allocated RMA into userspace.  The mapped area can then be
passed to the KVM_SET_USER_MEMORY_REGION ioctl to establish it as the
RMA for a virtual machine.  The size of the RMA in bytes (which is
fixed at host kernel boot time) is returned in the rma_size field of
the argument structure.

The KVM_CAP_PPC_RMA capability is 1 or 2 if the KVM_ALLOCATE_RMA ioctl
is supported; 2 if the processor requires all virtual machines to have
an RMA, or 1 if the processor can use an RMA but doesn't require it,
because it supports the Virtual RMA (VRMA) facility.


4.64 KVM_NMI

Capability: KVM_CAP_USER_NMI
Architectures: x86
Type: vcpu ioctl
Parameters: none
Returns: 0 on success, -1 on error

Queues an NMI on the thread's vcpu.  Note this is well defined only
when KVM_CREATE_IRQCHIP has not been called, since this is an interface
between the virtual cpu core and virtual local APIC.  After KVM_CREATE_IRQCHIP
has been called, this interface is completely emulated within the kernel.

To use this to emulate the LINT1 input with KVM_CREATE_IRQCHIP, use the
following algorithm:

  - pause the vcpu
  - read the local APIC's state (KVM_GET_LAPIC)
  - check whether changing LINT1 will queue an NMI (see the LVT entry for LINT1)
  - if so, issue KVM_NMI
  - resume the vcpu

Some guests configure the LINT1 NMI input to cause a panic, aiding in
debugging.


4.65 KVM_S390_UCAS_MAP

Capability: KVM_CAP_S390_UCONTROL
Architectures: s390
Type: vcpu ioctl
Parameters: struct kvm_s390_ucas_mapping (in)
Returns: 0 in case of success

The parameter is defined like this:
	struct kvm_s390_ucas_mapping {
		__u64 user_addr;
		__u64 vcpu_addr;
		__u64 length;
	};

This ioctl maps the memory at "user_addr" with the length "length" to
the vcpu's address space starting at "vcpu_addr". All parameters need to
be aligned by 1 megabyte.


4.66 KVM_S390_UCAS_UNMAP

Capability: KVM_CAP_S390_UCONTROL
Architectures: s390
Type: vcpu ioctl
Parameters: struct kvm_s390_ucas_mapping (in)
Returns: 0 in case of success

The parameter is defined like this:
	struct kvm_s390_ucas_mapping {
		__u64 user_addr;
		__u64 vcpu_addr;
		__u64 length;
	};

This ioctl unmaps the memory in the vcpu's address space starting at
"vcpu_addr" with the length "length". The field "user_addr" is ignored.
All parameters need to be aligned by 1 megabyte.


4.67 KVM_S390_VCPU_FAULT

Capability: KVM_CAP_S390_UCONTROL
Architectures: s390
Type: vcpu ioctl
Parameters: vcpu absolute address (in)
Returns: 0 in case of success

This call creates a page table entry on the virtual cpu's address space
(for user controlled virtual machines) or the virtual machine's address
space (for regular virtual machines). This only works for minor faults,
thus it's recommended to access subject memory page via the user page
table upfront. This is useful to handle validity intercepts for user
controlled virtual machines to fault in the virtual cpu's lowcore pages
prior to calling the KVM_RUN ioctl.


4.68 KVM_SET_ONE_REG

Capability: KVM_CAP_ONE_REG
Architectures: all
Type: vcpu ioctl
Parameters: struct kvm_one_reg (in)
Returns: 0 on success, negative value on failure

struct kvm_one_reg {
       __u64 id;
       __u64 addr;
};

Using this ioctl, a single vcpu register can be set to a specific value
defined by user space with the passed in struct kvm_one_reg, where id
refers to the register identifier as described below and addr is a pointer
to a variable with the respective size. There can be architecture agnostic
and architecture specific registers. Each have their own range of operation
and their own constants and width. To keep track of the implemented
registers, find a list below:

  Arch  |           Register            | Width (bits)
        |                               |
  PPC   | KVM_REG_PPC_HIOR              | 64
  PPC   | KVM_REG_PPC_IAC1              | 64
  PPC   | KVM_REG_PPC_IAC2              | 64
  PPC   | KVM_REG_PPC_IAC3              | 64
  PPC   | KVM_REG_PPC_IAC4              | 64
  PPC   | KVM_REG_PPC_DAC1              | 64
  PPC   | KVM_REG_PPC_DAC2              | 64
  PPC   | KVM_REG_PPC_DABR              | 64
  PPC   | KVM_REG_PPC_DSCR              | 64
  PPC   | KVM_REG_PPC_PURR              | 64
  PPC   | KVM_REG_PPC_SPURR             | 64
  PPC   | KVM_REG_PPC_DAR               | 64
  PPC   | KVM_REG_PPC_DSISR             | 32
  PPC   | KVM_REG_PPC_AMR               | 64
  PPC   | KVM_REG_PPC_UAMOR             | 64
  PPC   | KVM_REG_PPC_MMCR0             | 64
  PPC   | KVM_REG_PPC_MMCR1             | 64
  PPC   | KVM_REG_PPC_MMCRA             | 64
  PPC   | KVM_REG_PPC_MMCR2             | 64
  PPC   | KVM_REG_PPC_MMCRS             | 64
  PPC   | KVM_REG_PPC_SIAR              | 64
  PPC   | KVM_REG_PPC_SDAR              | 64
  PPC   | KVM_REG_PPC_SIER              | 64
  PPC   | KVM_REG_PPC_PMC1              | 32
  PPC   | KVM_REG_PPC_PMC2              | 32
  PPC   | KVM_REG_PPC_PMC3              | 32
  PPC   | KVM_REG_PPC_PMC4              | 32
  PPC   | KVM_REG_PPC_PMC5              | 32
  PPC   | KVM_REG_PPC_PMC6              | 32
  PPC   | KVM_REG_PPC_PMC7              | 32
  PPC   | KVM_REG_PPC_PMC8              | 32
  PPC   | KVM_REG_PPC_FPR0              | 64
          ...
  PPC   | KVM_REG_PPC_FPR31             | 64
  PPC   | KVM_REG_PPC_VR0               | 128
          ...
  PPC   | KVM_REG_PPC_VR31              | 128
  PPC   | KVM_REG_PPC_VSR0              | 128
          ...
  PPC   | KVM_REG_PPC_VSR31             | 128
  PPC   | KVM_REG_PPC_FPSCR             | 64
  PPC   | KVM_REG_PPC_VSCR              | 32
  PPC   | KVM_REG_PPC_VPA_ADDR          | 64
  PPC   | KVM_REG_PPC_VPA_SLB           | 128
  PPC   | KVM_REG_PPC_VPA_DTL           | 128
  PPC   | KVM_REG_PPC_EPCR              | 32
  PPC   | KVM_REG_PPC_EPR               | 32
  PPC   | KVM_REG_PPC_TCR               | 32
  PPC   | KVM_REG_PPC_TSR               | 32
  PPC   | KVM_REG_PPC_OR_TSR            | 32
  PPC   | KVM_REG_PPC_CLEAR_TSR         | 32
  PPC   | KVM_REG_PPC_MAS0              | 32
  PPC   | KVM_REG_PPC_MAS1              | 32
  PPC   | KVM_REG_PPC_MAS2              | 64
  PPC   | KVM_REG_PPC_MAS7_3            | 64
  PPC   | KVM_REG_PPC_MAS4              | 32
  PPC   | KVM_REG_PPC_MAS6              | 32
  PPC   | KVM_REG_PPC_MMUCFG            | 32
  PPC   | KVM_REG_PPC_TLB0CFG           | 32
  PPC   | KVM_REG_PPC_TLB1CFG           | 32
  PPC   | KVM_REG_PPC_TLB2CFG           | 32
  PPC   | KVM_REG_PPC_TLB3CFG           | 32
  PPC   | KVM_REG_PPC_TLB0PS            | 32
  PPC   | KVM_REG_PPC_TLB1PS            | 32
  PPC   | KVM_REG_PPC_TLB2PS            | 32
  PPC   | KVM_REG_PPC_TLB3PS            | 32
  PPC   | KVM_REG_PPC_EPTCFG            | 32
  PPC   | KVM_REG_PPC_ICP_STATE         | 64
  PPC   | KVM_REG_PPC_TB_OFFSET         | 64
  PPC   | KVM_REG_PPC_SPMC1             | 32
  PPC   | KVM_REG_PPC_SPMC2             | 32
  PPC   | KVM_REG_PPC_IAMR              | 64
  PPC   | KVM_REG_PPC_TFHAR             | 64
  PPC   | KVM_REG_PPC_TFIAR             | 64
  PPC   | KVM_REG_PPC_TEXASR            | 64
  PPC   | KVM_REG_PPC_FSCR              | 64
  PPC   | KVM_REG_PPC_PSPB              | 32
  PPC   | KVM_REG_PPC_EBBHR             | 64
  PPC   | KVM_REG_PPC_EBBRR             | 64
  PPC   | KVM_REG_PPC_BESCR             | 64
  PPC   | KVM_REG_PPC_TAR               | 64
  PPC   | KVM_REG_PPC_DPDES             | 64
  PPC   | KVM_REG_PPC_DAWR              | 64
  PPC   | KVM_REG_PPC_DAWRX             | 64
  PPC   | KVM_REG_PPC_CIABR             | 64
  PPC   | KVM_REG_PPC_IC                | 64
  PPC   | KVM_REG_PPC_VTB               | 64
  PPC   | KVM_REG_PPC_CSIGR             | 64
  PPC   | KVM_REG_PPC_TACR              | 64
  PPC   | KVM_REG_PPC_TCSCR             | 64
  PPC   | KVM_REG_PPC_PID               | 64
  PPC   | KVM_REG_PPC_ACOP              | 64
  PPC   | KVM_REG_PPC_VRSAVE            | 32
  PPC   | KVM_REG_PPC_LPCR              | 32
  PPC   | KVM_REG_PPC_LPCR_64           | 64
  PPC   | KVM_REG_PPC_PPR               | 64
  PPC   | KVM_REG_PPC_ARCH_COMPAT       | 32
  PPC   | KVM_REG_PPC_DABRX             | 32
  PPC   | KVM_REG_PPC_WORT              | 64
  PPC	| KVM_REG_PPC_SPRG9             | 64
  PPC	| KVM_REG_PPC_DBSR              | 32
  PPC   | KVM_REG_PPC_TM_GPR0           | 64
          ...
  PPC   | KVM_REG_PPC_TM_GPR31          | 64
  PPC   | KVM_REG_PPC_TM_VSR0           | 128
          ...
  PPC   | KVM_REG_PPC_TM_VSR63          | 128
  PPC   | KVM_REG_PPC_TM_CR             | 64
  PPC   | KVM_REG_PPC_TM_LR             | 64
  PPC   | KVM_REG_PPC_TM_CTR            | 64
  PPC   | KVM_REG_PPC_TM_FPSCR          | 64
  PPC   | KVM_REG_PPC_TM_AMR            | 64
  PPC   | KVM_REG_PPC_TM_PPR            | 64
  PPC   | KVM_REG_PPC_TM_VRSAVE         | 64
  PPC   | KVM_REG_PPC_TM_VSCR           | 32
  PPC   | KVM_REG_PPC_TM_DSCR           | 64
  PPC   | KVM_REG_PPC_TM_TAR            | 64
  PPC   | KVM_REG_PPC_TM_XER            | 64
        |                               |
  MIPS  | KVM_REG_MIPS_R0               | 64
          ...
  MIPS  | KVM_REG_MIPS_R31              | 64
  MIPS  | KVM_REG_MIPS_HI               | 64
  MIPS  | KVM_REG_MIPS_LO               | 64
  MIPS  | KVM_REG_MIPS_PC               | 64
  MIPS  | KVM_REG_MIPS_CP0_INDEX        | 32
  MIPS  | KVM_REG_MIPS_CP0_CONTEXT      | 64
  MIPS  | KVM_REG_MIPS_CP0_USERLOCAL    | 64
  MIPS  | KVM_REG_MIPS_CP0_PAGEMASK     | 32
  MIPS  | KVM_REG_MIPS_CP0_WIRED        | 32
  MIPS  | KVM_REG_MIPS_CP0_HWRENA       | 32
  MIPS  | KVM_REG_MIPS_CP0_BADVADDR     | 64
  MIPS  | KVM_REG_MIPS_CP0_COUNT        | 32
  MIPS  | KVM_REG_MIPS_CP0_ENTRYHI      | 64
  MIPS  | KVM_REG_MIPS_CP0_COMPARE      | 32
  MIPS  | KVM_REG_MIPS_CP0_STATUS       | 32
  MIPS  | KVM_REG_MIPS_CP0_CAUSE        | 32
  MIPS  | KVM_REG_MIPS_CP0_EPC          | 64
  MIPS  | KVM_REG_MIPS_CP0_PRID         | 32
  MIPS  | KVM_REG_MIPS_CP0_CONFIG       | 32
  MIPS  | KVM_REG_MIPS_CP0_CONFIG1      | 32
  MIPS  | KVM_REG_MIPS_CP0_CONFIG2      | 32
  MIPS  | KVM_REG_MIPS_CP0_CONFIG3      | 32
  MIPS  | KVM_REG_MIPS_CP0_CONFIG4      | 32
  MIPS  | KVM_REG_MIPS_CP0_CONFIG5      | 32
  MIPS  | KVM_REG_MIPS_CP0_CONFIG7      | 32
  MIPS  | KVM_REG_MIPS_CP0_ERROREPC     | 64
  MIPS  | KVM_REG_MIPS_COUNT_CTL        | 64
  MIPS  | KVM_REG_MIPS_COUNT_RESUME     | 64
  MIPS  | KVM_REG_MIPS_COUNT_HZ         | 64
  MIPS  | KVM_REG_MIPS_FPR_32(0..31)    | 32
  MIPS  | KVM_REG_MIPS_FPR_64(0..31)    | 64
  MIPS  | KVM_REG_MIPS_VEC_128(0..31)   | 128
  MIPS  | KVM_REG_MIPS_FCR_IR           | 32
  MIPS  | KVM_REG_MIPS_FCR_CSR          | 32
  MIPS  | KVM_REG_MIPS_MSA_IR           | 32
  MIPS  | KVM_REG_MIPS_MSA_CSR          | 32

ARM registers are mapped using the lower 32 bits.  The upper 16 of that
is the register group type, or coprocessor number:

ARM core registers have the following id bit patterns:
  0x4020 0000 0010 <index into the kvm_regs struct:16>

ARM 32-bit CP15 registers have the following id bit patterns:
  0x4020 0000 000F <zero:1> <crn:4> <crm:4> <opc1:4> <opc2:3>

ARM 64-bit CP15 registers have the following id bit patterns:
  0x4030 0000 000F <zero:1> <zero:4> <crm:4> <opc1:4> <zero:3>

ARM CCSIDR registers are demultiplexed by CSSELR value:
  0x4020 0000 0011 00 <csselr:8>

ARM 32-bit VFP control registers have the following id bit patterns:
  0x4020 0000 0012 1 <regno:12>

ARM 64-bit FP registers have the following id bit patterns:
  0x4030 0000 0012 0 <regno:12>


arm64 registers are mapped using the lower 32 bits. The upper 16 of
that is the register group type, or coprocessor number:

arm64 core/FP-SIMD registers have the following id bit patterns. Note
that the size of the access is variable, as the kvm_regs structure
contains elements ranging from 32 to 128 bits. The index is a 32bit
value in the kvm_regs structure seen as a 32bit array.
  0x60x0 0000 0010 <index into the kvm_regs struct:16>

arm64 CCSIDR registers are demultiplexed by CSSELR value:
  0x6020 0000 0011 00 <csselr:8>

arm64 system registers have the following id bit patterns:
  0x6030 0000 0013 <op0:2> <op1:3> <crn:4> <crm:4> <op2:3>


MIPS registers are mapped using the lower 32 bits.  The upper 16 of that is
the register group type:

MIPS core registers (see above) have the following id bit patterns:
  0x7030 0000 0000 <reg:16>

MIPS CP0 registers (see KVM_REG_MIPS_CP0_* above) have the following id bit
patterns depending on whether they're 32-bit or 64-bit registers:
  0x7020 0000 0001 00 <reg:5> <sel:3>   (32-bit)
  0x7030 0000 0001 00 <reg:5> <sel:3>   (64-bit)

MIPS KVM control registers (see above) have the following id bit patterns:
  0x7030 0000 0002 <reg:16>

MIPS FPU registers (see KVM_REG_MIPS_FPR_{32,64}() above) have the following
id bit patterns depending on the size of the register being accessed. They are
always accessed according to the current guest FPU mode (Status.FR and
Config5.FRE), i.e. as the guest would see them, and they become unpredictable
if the guest FPU mode is changed. MIPS SIMD Architecture (MSA) vector
registers (see KVM_REG_MIPS_VEC_128() above) have similar patterns as they
overlap the FPU registers:
  0x7020 0000 0003 00 <0:3> <reg:5> (32-bit FPU registers)
  0x7030 0000 0003 00 <0:3> <reg:5> (64-bit FPU registers)
  0x7040 0000 0003 00 <0:3> <reg:5> (128-bit MSA vector registers)

MIPS FPU control registers (see KVM_REG_MIPS_FCR_{IR,CSR} above) have the
following id bit patterns:
  0x7020 0000 0003 01 <0:3> <reg:5>

MIPS MSA control registers (see KVM_REG_MIPS_MSA_{IR,CSR} above) have the
following id bit patterns:
  0x7020 0000 0003 02 <0:3> <reg:5>


4.69 KVM_GET_ONE_REG

Capability: KVM_CAP_ONE_REG
Architectures: all
Type: vcpu ioctl
Parameters: struct kvm_one_reg (in and out)
Returns: 0 on success, negative value on failure

This ioctl allows to receive the value of a single register implemented
in a vcpu. The register to read is indicated by the "id" field of the
kvm_one_reg struct passed in. On success, the register value can be found
at the memory location pointed to by "addr".

The list of registers accessible using this interface is identical to the
list in 4.68.


4.70 KVM_KVMCLOCK_CTRL

Capability: KVM_CAP_KVMCLOCK_CTRL
Architectures: Any that implement pvclocks (currently x86 only)
Type: vcpu ioctl
Parameters: None
Returns: 0 on success, -1 on error

This signals to the host kernel that the specified guest is being paused by
userspace.  The host will set a flag in the pvclock structure that is checked
from the soft lockup watchdog.  The flag is part of the pvclock structure that
is shared between guest and host, specifically the second bit of the flags
field of the pvclock_vcpu_time_info structure.  It will be set exclusively by
the host and read/cleared exclusively by the guest.  The guest operation of
checking and clearing the flag must an atomic operation so
load-link/store-conditional, or equivalent must be used.  There are two cases
where the guest will clear the flag: when the soft lockup watchdog timer resets
itself or when a soft lockup is detected.  This ioctl can be called any time
after pausing the vcpu, but before it is resumed.


4.71 KVM_SIGNAL_MSI

Capability: KVM_CAP_SIGNAL_MSI
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_msi (in)
Returns: >0 on delivery, 0 if guest blocked the MSI, and -1 on error

Directly inject a MSI message. Only valid with in-kernel irqchip that handles
MSI messages.

struct kvm_msi {
	__u32 address_lo;
	__u32 address_hi;
	__u32 data;
	__u32 flags;
	__u8  pad[16];
};

No flags are defined so far. The corresponding field must be 0.


4.71 KVM_CREATE_PIT2

Capability: KVM_CAP_PIT2
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_pit_config (in)
Returns: 0 on success, -1 on error

Creates an in-kernel device model for the i8254 PIT. This call is only valid
after enabling in-kernel irqchip support via KVM_CREATE_IRQCHIP. The following
parameters have to be passed:

struct kvm_pit_config {
	__u32 flags;
	__u32 pad[15];
};

Valid flags are:

#define KVM_PIT_SPEAKER_DUMMY     1 /* emulate speaker port stub */

PIT timer interrupts may use a per-VM kernel thread for injection. If it
exists, this thread will have a name of the following pattern:

kvm-pit/<owner-process-pid>

When running a guest with elevated priorities, the scheduling parameters of
this thread may have to be adjusted accordingly.

This IOCTL replaces the obsolete KVM_CREATE_PIT.


4.72 KVM_GET_PIT2

Capability: KVM_CAP_PIT_STATE2
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_pit_state2 (out)
Returns: 0 on success, -1 on error

Retrieves the state of the in-kernel PIT model. Only valid after
KVM_CREATE_PIT2. The state is returned in the following structure:

struct kvm_pit_state2 {
	struct kvm_pit_channel_state channels[3];
	__u32 flags;
	__u32 reserved[9];
};

Valid flags are:

/* disable PIT in HPET legacy mode */
#define KVM_PIT_FLAGS_HPET_LEGACY  0x00000001

This IOCTL replaces the obsolete KVM_GET_PIT.


4.73 KVM_SET_PIT2

Capability: KVM_CAP_PIT_STATE2
Architectures: x86
Type: vm ioctl
Parameters: struct kvm_pit_state2 (in)
Returns: 0 on success, -1 on error

Sets the state of the in-kernel PIT model. Only valid after KVM_CREATE_PIT2.
See KVM_GET_PIT2 for details on struct kvm_pit_state2.

This IOCTL replaces the obsolete KVM_SET_PIT.


4.74 KVM_PPC_GET_SMMU_INFO

Capability: KVM_CAP_PPC_GET_SMMU_INFO
Architectures: powerpc
Type: vm ioctl
Parameters: None
Returns: 0 on success, -1 on error

This populates and returns a structure describing the features of
the "Server" class MMU emulation supported by KVM.
This can in turn be used by userspace to generate the appropriate
device-tree properties for the guest operating system.

The structure contains some global information, followed by an
array of supported segment page sizes:

      struct kvm_ppc_smmu_info {
	     __u64 flags;
	     __u32 slb_size;
	     __u32 pad;
	     struct kvm_ppc_one_seg_page_size sps[KVM_PPC_PAGE_SIZES_MAX_SZ];
      };

The supported flags are:

    - KVM_PPC_PAGE_SIZES_REAL:
        When that flag is set, guest page sizes must "fit" the backing
        store page sizes. When not set, any page size in the list can
        be used regardless of how they are backed by userspace.

    - KVM_PPC_1T_SEGMENTS
        The emulated MMU supports 1T segments in addition to the
        standard 256M ones.

The "slb_size" field indicates how many SLB entries are supported

The "sps" array contains 8 entries indicating the supported base
page sizes for a segment in increasing order. Each entry is defined
as follow:

   struct kvm_ppc_one_seg_page_size {
	__u32 page_shift;	/* Base page shift of segment (or 0) */
	__u32 slb_enc;		/* SLB encoding for BookS */
	struct kvm_ppc_one_page_size enc[KVM_PPC_PAGE_SIZES_MAX_SZ];
   };

An entry with a "page_shift" of 0 is unused. Because the array is
organized in increasing order, a lookup can stop when encoutering
such an entry.

The "slb_enc" field provides the encoding to use in the SLB for the
page size. The bits are in positions such as the value can directly
be OR'ed into the "vsid" argument of the slbmte instruction.

The "enc" array is a list which for each of those segment base page
size provides the list of supported actual page sizes (which can be
only larger or equal to the base page size), along with the
corresponding encoding in the hash PTE. Similarly, the array is
8 entries sorted by increasing sizes and an entry with a "0" shift
is an empty entry and a terminator:

   struct kvm_ppc_one_page_size {
	__u32 page_shift;	/* Page shift (or 0) */
	__u32 pte_enc;		/* Encoding in the HPTE (>>12) */
   };

The "pte_enc" field provides a value that can OR'ed into the hash
PTE's RPN field (ie, it needs to be shifted left by 12 to OR it
into the hash PTE second double word).

4.75 KVM_IRQFD

Capability: KVM_CAP_IRQFD
Architectures: x86 s390 arm arm64
Type: vm ioctl
Parameters: struct kvm_irqfd (in)
Returns: 0 on success, -1 on error

Allows setting an eventfd to directly trigger a guest interrupt.
kvm_irqfd.fd specifies the file descriptor to use as the eventfd and
kvm_irqfd.gsi specifies the irqchip pin toggled by this event.  When
an event is triggered on the eventfd, an interrupt is injected into
the guest using the specified gsi pin.  The irqfd is removed using
the KVM_IRQFD_FLAG_DEASSIGN flag, specifying both kvm_irqfd.fd
and kvm_irqfd.gsi.

With KVM_CAP_IRQFD_RESAMPLE, KVM_IRQFD supports a de-assert and notify
mechanism allowing emulation of level-triggered, irqfd-based
interrupts.  When KVM_IRQFD_FLAG_RESAMPLE is set the user must pass an
additional eventfd in the kvm_irqfd.resamplefd field.  When operating
in resample mode, posting of an interrupt through kvm_irq.fd asserts
the specified gsi in the irqchip.  When the irqchip is resampled, such
as from an EOI, the gsi is de-asserted and the user is notified via
kvm_irqfd.resamplefd.  It is the user's responsibility to re-queue
the interrupt if the device making use of it still requires service.
Note that closing the resamplefd is not sufficient to disable the
irqfd.  The KVM_IRQFD_FLAG_RESAMPLE is only necessary on assignment
and need not be specified with KVM_IRQFD_FLAG_DEASSIGN.

On ARM/ARM64, the gsi field in the kvm_irqfd struct specifies the Shared
Peripheral Interrupt (SPI) index, such that the GIC interrupt ID is
given by gsi + 32.

4.76 KVM_PPC_ALLOCATE_HTAB

Capability: KVM_CAP_PPC_ALLOC_HTAB
Architectures: powerpc
Type: vm ioctl
Parameters: Pointer to u32 containing hash table order (in/out)
Returns: 0 on success, -1 on error

This requests the host kernel to allocate an MMU hash table for a
guest using the PAPR paravirtualization interface.  This only does
anything if the kernel is configured to use the Book 3S HV style of
virtualization.  Otherwise the capability doesn't exist and the ioctl
returns an ENOTTY error.  The rest of this description assumes Book 3S
HV.

There must be no vcpus running when this ioctl is called; if there
are, it will do nothing and return an EBUSY error.

The parameter is a pointer to a 32-bit unsigned integer variable
containing the order (log base 2) of the desired size of the hash
table, which must be between 18 and 46.  On successful return from the
ioctl, it will have been updated with the order of the hash table that
was allocated.

If no hash table has been allocated when any vcpu is asked to run
(with the KVM_RUN ioctl), the host kernel will allocate a
default-sized hash table (16 MB).

If this ioctl is called when a hash table has already been allocated,
the kernel will clear out the existing hash table (zero all HPTEs) and
return the hash table order in the parameter.  (If the guest is using
the virtualized real-mode area (VRMA) facility, the kernel will
re-create the VMRA HPTEs on the next KVM_RUN of any vcpu.)

4.77 KVM_S390_INTERRUPT

Capability: basic
Architectures: s390
Type: vm ioctl, vcpu ioctl
Parameters: struct kvm_s390_interrupt (in)
Returns: 0 on success, -1 on error

Allows to inject an interrupt to the guest. Interrupts can be floating
(vm ioctl) or per cpu (vcpu ioctl), depending on the interrupt type.

Interrupt parameters are passed via kvm_s390_interrupt:

struct kvm_s390_interrupt {
	__u32 type;
	__u32 parm;
	__u64 parm64;
};

type can be one of the following:

KVM_S390_SIGP_STOP (vcpu) - sigp stop; optional flags in parm
KVM_S390_PROGRAM_INT (vcpu) - program check; code in parm
KVM_S390_SIGP_SET_PREFIX (vcpu) - sigp set prefix; prefix address in parm
KVM_S390_RESTART (vcpu) - restart
KVM_S390_INT_CLOCK_COMP (vcpu) - clock comparator interrupt
KVM_S390_INT_CPU_TIMER (vcpu) - CPU timer interrupt
KVM_S390_INT_VIRTIO (vm) - virtio external interrupt; external interrupt
			   parameters in parm and parm64
KVM_S390_INT_SERVICE (vm) - sclp external interrupt; sclp parameter in parm
KVM_S390_INT_EMERGENCY (vcpu) - sigp emergency; source cpu in parm
KVM_S390_INT_EXTERNAL_CALL (vcpu) - sigp external call; source cpu in parm
KVM_S390_INT_IO(ai,cssid,ssid,schid) (vm) - compound value to indicate an
    I/O interrupt (ai - adapter interrupt; cssid,ssid,schid - subchannel);
    I/O interruption parameters in parm (subchannel) and parm64 (intparm,
    interruption subclass)
KVM_S390_MCHK (vm, vcpu) - machine check interrupt; cr 14 bits in parm,
                           machine check interrupt code in parm64 (note that
                           machine checks needing further payload are not
                           supported by this ioctl)

Note that the vcpu ioctl is asynchronous to vcpu execution.

4.78 KVM_PPC_GET_HTAB_FD

Capability: KVM_CAP_PPC_HTAB_FD
Architectures: powerpc
Type: vm ioctl
Parameters: Pointer to struct kvm_get_htab_fd (in)
Returns: file descriptor number (>= 0) on success, -1 on error

This returns a file descriptor that can be used either to read out the
entries in the guest's hashed page table (HPT), or to write entries to
initialize the HPT.  The returned fd can only be written to if the
KVM_GET_HTAB_WRITE bit is set in the flags field of the argument, and
can only be read if that bit is clear.  The argument struct looks like
this:

/* For KVM_PPC_GET_HTAB_FD */
struct kvm_get_htab_fd {
	__u64	flags;
	__u64	start_index;
	__u64	reserved[2];
};

/* Values for kvm_get_htab_fd.flags */
#define KVM_GET_HTAB_BOLTED_ONLY	((__u64)0x1)
#define KVM_GET_HTAB_WRITE		((__u64)0x2)

The `start_index' field gives the index in the HPT of the entry at
which to start reading.  It is ignored when writing.

Reads on the fd will initially supply information about all
"interesting" HPT entries.  Interesting entries are those with the
bolted bit set, if the KVM_GET_HTAB_BOLTED_ONLY bit is set, otherwise
all entries.  When the end of the HPT is reached, the read() will
return.  If read() is called again on the fd, it will start again from
the beginning of the HPT, but will only return HPT entries that have
changed since they were last read.

Data read or written is structured as a header (8 bytes) followed by a
series of valid HPT entries (16 bytes) each.  The header indicates how
many valid HPT entries there are and how many invalid entries follow
the valid entries.  The invalid entries are not represented explicitly
in the stream.  The header format is:

struct kvm_get_htab_header {
	__u32	index;
	__u16	n_valid;
	__u16	n_invalid;
};

Writes to the fd create HPT entries starting at the index given in the
header; first `n_valid' valid entries with contents from the data
written, then `n_invalid' invalid entries, invalidating any previously
valid entries found.

4.79 KVM_CREATE_DEVICE

Capability: KVM_CAP_DEVICE_CTRL
Type: vm ioctl
Parameters: struct kvm_create_device (in/out)
Returns: 0 on success, -1 on error
Errors:
  ENODEV: The device type is unknown or unsupported
  EEXIST: Device already created, and this type of device may not
          be instantiated multiple times

  Other error conditions may be defined by individual device types or
  have their standard meanings.

Creates an emulated device in the kernel.  The file descriptor returned
in fd can be used with KVM_SET/GET/HAS_DEVICE_ATTR.

If the KVM_CREATE_DEVICE_TEST flag is set, only test whether the
device type is supported (not necessarily whether it can be created
in the current vm).

Individual devices should not define flags.  Attributes should be used
for specifying any behavior that is not implied by the device type
number.

struct kvm_create_device {
	__u32	type;	/* in: KVM_DEV_TYPE_xxx */
	__u32	fd;	/* out: device handle */
	__u32	flags;	/* in: KVM_CREATE_DEVICE_xxx */
};

4.80 KVM_SET_DEVICE_ATTR/KVM_GET_DEVICE_ATTR

Capability: KVM_CAP_DEVICE_CTRL, KVM_CAP_VM_ATTRIBUTES for vm device
Type: device ioctl, vm ioctl
Parameters: struct kvm_device_attr
Returns: 0 on success, -1 on error
Errors:
  ENXIO:  The group or attribute is unknown/unsupported for this device
  EPERM:  The attribute cannot (currently) be accessed this way
          (e.g. read-only attribute, or attribute that only makes
          sense when the device is in a different state)

  Other error conditions may be defined by individual device types.

Gets/sets a specified piece of device configuration and/or state.  The
semantics are device-specific.  See individual device documentation in
the "devices" directory.  As with ONE_REG, the size of the data
transferred is defined by the particular attribute.

struct kvm_device_attr {
	__u32	flags;		/* no flags currently defined */
	__u32	group;		/* device-defined */
	__u64	attr;		/* group-defined */
	__u64	addr;		/* userspace address of attr data */
};

4.81 KVM_HAS_DEVICE_ATTR

Capability: KVM_CAP_DEVICE_CTRL, KVM_CAP_VM_ATTRIBUTES for vm device
Type: device ioctl, vm ioctl
Parameters: struct kvm_device_attr
Returns: 0 on success, -1 on error
Errors:
  ENXIO:  The group or attribute is unknown/unsupported for this device

Tests whether a device supports a particular attribute.  A successful
return indicates the attribute is implemented.  It does not necessarily
indicate that the attribute can be read or written in the device's
current state.  "addr" is ignored.

4.82 KVM_ARM_VCPU_INIT

Capability: basic
Architectures: arm, arm64
Type: vcpu ioctl
Parameters: struct kvm_vcpu_init (in)
Returns: 0 on success; -1 on error
Errors:
  EINVAL:    the target is unknown, or the combination of features is invalid.
  ENOENT:    a features bit specified is unknown.

This tells KVM what type of CPU to present to the guest, and what
optional features it should have.  This will cause a reset of the cpu
registers to their initial values.  If this is not called, KVM_RUN will
return ENOEXEC for that vcpu.

Note that because some registers reflect machine topology, all vcpus
should be created before this ioctl is invoked.

Userspace can call this function multiple times for a given vcpu, including
after the vcpu has been run. This will reset the vcpu to its initial
state. All calls to this function after the initial call must use the same
target and same set of feature flags, otherwise EINVAL will be returned.

Possible features:
	- KVM_ARM_VCPU_POWER_OFF: Starts the CPU in a power-off state.
	  Depends on KVM_CAP_ARM_PSCI.  If not set, the CPU will be powered on
	  and execute guest code when KVM_RUN is called.
	- KVM_ARM_VCPU_EL1_32BIT: Starts the CPU in a 32bit mode.
	  Depends on KVM_CAP_ARM_EL1_32BIT (arm64 only).
	- KVM_ARM_VCPU_PSCI_0_2: Emulate PSCI v0.2 for the CPU.
	  Depends on KVM_CAP_ARM_PSCI_0_2.


4.83 KVM_ARM_PREFERRED_TARGET

Capability: basic
Architectures: arm, arm64
Type: vm ioctl
Parameters: struct struct kvm_vcpu_init (out)
Returns: 0 on success; -1 on error
Errors:
  ENODEV:    no preferred target available for the host

This queries KVM for preferred CPU target type which can be emulated
by KVM on underlying host.

The ioctl returns struct kvm_vcpu_init instance containing information
about preferred CPU target type and recommended features for it.  The
kvm_vcpu_init->features bitmap returned will have feature bits set if
the preferred target recommends setting these features, but this is
not mandatory.

The information returned by this ioctl can be used to prepare an instance
of struct kvm_vcpu_init for KVM_ARM_VCPU_INIT ioctl which will result in
in VCPU matching underlying host.


4.84 KVM_GET_REG_LIST

Capability: basic
Architectures: arm, arm64, mips
Type: vcpu ioctl
Parameters: struct kvm_reg_list (in/out)
Returns: 0 on success; -1 on error
Errors:
  E2BIG:     the reg index list is too big to fit in the array specified by
             the user (the number required will be written into n).

struct kvm_reg_list {
	__u64 n; /* number of registers in reg[] */
	__u64 reg[0];
};

This ioctl returns the guest registers that are supported for the
KVM_GET_ONE_REG/KVM_SET_ONE_REG calls.


4.85 KVM_ARM_SET_DEVICE_ADDR (deprecated)

Capability: KVM_CAP_ARM_SET_DEVICE_ADDR
Architectures: arm, arm64
Type: vm ioctl
Parameters: struct kvm_arm_device_address (in)
Returns: 0 on success, -1 on error
Errors:
  ENODEV: The device id is unknown
  ENXIO:  Device not supported on current system
  EEXIST: Address already set
  E2BIG:  Address outside guest physical address space
  EBUSY:  Address overlaps with other device range

struct kvm_arm_device_addr {
	__u64 id;
	__u64 addr;
};

Specify a device address in the guest's physical address space where guests
can access emulated or directly exposed devices, which the host kernel needs
to know about. The id field is an architecture specific identifier for a
specific device.

ARM/arm64 divides the id field into two parts, a device id and an
address type id specific to the individual device.

  bits:  | 63        ...       32 | 31    ...    16 | 15    ...    0 |
  field: |        0x00000000      |     device id   |  addr type id  |

ARM/arm64 currently only require this when using the in-kernel GIC
support for the hardware VGIC features, using KVM_ARM_DEVICE_VGIC_V2
as the device id.  When setting the base address for the guest's
mapping of the VGIC virtual CPU and distributor interface, the ioctl
must be called after calling KVM_CREATE_IRQCHIP, but before calling
KVM_RUN on any of the VCPUs.  Calling this ioctl twice for any of the
base addresses will return -EEXIST.

Note, this IOCTL is deprecated and the more flexible SET/GET_DEVICE_ATTR API
should be used instead.


4.86 KVM_PPC_RTAS_DEFINE_TOKEN

Capability: KVM_CAP_PPC_RTAS
Architectures: ppc
Type: vm ioctl
Parameters: struct kvm_rtas_token_args
Returns: 0 on success, -1 on error

Defines a token value for a RTAS (Run Time Abstraction Services)
service in order to allow it to be handled in the kernel.  The
argument struct gives the name of the service, which must be the name
of a service that has a kernel-side implementation.  If the token
value is non-zero, it will be associated with that service, and
subsequent RTAS calls by the guest specifying that token will be
handled by the kernel.  If the token value is 0, then any token
associated with the service will be forgotten, and subsequent RTAS
calls by the guest for that service will be passed to userspace to be
handled.

4.87 KVM_SET_GUEST_DEBUG

Capability: KVM_CAP_SET_GUEST_DEBUG
Architectures: x86, s390, ppc, arm64
Type: vcpu ioctl
Parameters: struct kvm_guest_debug (in)
Returns: 0 on success; -1 on error

struct kvm_guest_debug {
       __u32 control;
       __u32 pad;
       struct kvm_guest_debug_arch arch;
};

Set up the processor specific debug registers and configure vcpu for
handling guest debug events. There are two parts to the structure, the
first a control bitfield indicates the type of debug events to handle
when running. Common control bits are:

  - KVM_GUESTDBG_ENABLE:        guest debugging is enabled
  - KVM_GUESTDBG_SINGLESTEP:    the next run should single-step

The top 16 bits of the control field are architecture specific control
flags which can include the following:

  - KVM_GUESTDBG_USE_SW_BP:     using software breakpoints [x86, arm64]
  - KVM_GUESTDBG_USE_HW_BP:     using hardware breakpoints [x86, s390, arm64]
  - KVM_GUESTDBG_INJECT_DB:     inject DB type exception [x86]
  - KVM_GUESTDBG_INJECT_BP:     inject BP type exception [x86]
  - KVM_GUESTDBG_EXIT_PENDING:  trigger an immediate guest exit [s390]

For example KVM_GUESTDBG_USE_SW_BP indicates that software breakpoints
are enabled in memory so we need to ensure breakpoint exceptions are
correctly trapped and the KVM run loop exits at the breakpoint and not
running off into the normal guest vector. For KVM_GUESTDBG_USE_HW_BP
we need to ensure the guest vCPUs architecture specific registers are
updated to the correct (supplied) values.

The second part of the structure is architecture specific and
typically contains a set of debug registers.

For arm64 the number of debug registers is implementation defined and
can be determined by querying the KVM_CAP_GUEST_DEBUG_HW_BPS and
KVM_CAP_GUEST_DEBUG_HW_WPS capabilities which return a positive number
indicating the number of supported registers.

When debug events exit the main run loop with the reason
KVM_EXIT_DEBUG with the kvm_debug_exit_arch part of the kvm_run
structure containing architecture specific debug information.

4.88 KVM_GET_EMULATED_CPUID

Capability: KVM_CAP_EXT_EMUL_CPUID
Architectures: x86
Type: system ioctl
Parameters: struct kvm_cpuid2 (in/out)
Returns: 0 on success, -1 on error

struct kvm_cpuid2 {
	__u32 nent;
	__u32 flags;
	struct kvm_cpuid_entry2 entries[0];
};

The member 'flags' is used for passing flags from userspace.

#define KVM_CPUID_FLAG_SIGNIFCANT_INDEX		BIT(0)
#define KVM_CPUID_FLAG_STATEFUL_FUNC		BIT(1)
#define KVM_CPUID_FLAG_STATE_READ_NEXT		BIT(2)

struct kvm_cpuid_entry2 {
	__u32 function;
	__u32 index;
	__u32 flags;
	__u32 eax;
	__u32 ebx;
	__u32 ecx;
	__u32 edx;
	__u32 padding[3];
};

This ioctl returns x86 cpuid features which are emulated by
kvm.Userspace can use the information returned by this ioctl to query
which features are emulated by kvm instead of being present natively.

Userspace invokes KVM_GET_EMULATED_CPUID by passing a kvm_cpuid2
structure with the 'nent' field indicating the number of entries in
the variable-size array 'entries'. If the number of entries is too low
to describe the cpu capabilities, an error (E2BIG) is returned. If the
number is too high, the 'nent' field is adjusted and an error (ENOMEM)
is returned. If the number is just right, the 'nent' field is adjusted
to the number of valid entries in the 'entries' array, which is then
filled.

The entries returned are the set CPUID bits of the respective features
which kvm emulates, as returned by the CPUID instruction, with unknown
or unsupported feature bits cleared.

Features like x2apic, for example, may not be present in the host cpu
but are exposed by kvm in KVM_GET_SUPPORTED_CPUID because they can be
emulated efficiently and thus not included here.

The fields in each entry are defined as follows:

  function: the eax value used to obtain the entry
  index: the ecx value used to obtain the entry (for entries that are
         affected by ecx)
  flags: an OR of zero or more of the following:
        KVM_CPUID_FLAG_SIGNIFCANT_INDEX:
           if the index field is valid
        KVM_CPUID_FLAG_STATEFUL_FUNC:
           if cpuid for this function returns different values for successive
           invocations; there will be several entries with the same function,
           all with this flag set
        KVM_CPUID_FLAG_STATE_READ_NEXT:
           for KVM_CPUID_FLAG_STATEFUL_FUNC entries, set if this entry is
           the first entry to be read by a cpu
   eax, ebx, ecx, edx: the values returned by the cpuid instruction for
         this function/index combination

4.89 KVM_S390_MEM_OP

Capability: KVM_CAP_S390_MEM_OP
Architectures: s390
Type: vcpu ioctl
Parameters: struct kvm_s390_mem_op (in)
Returns: = 0 on success,
         < 0 on generic error (e.g. -EFAULT or -ENOMEM),
         > 0 if an exception occurred while walking the page tables

Read or write data from/to the logical (virtual) memory of a VCPU.

Parameters are specified via the following structure:

struct kvm_s390_mem_op {
	__u64 gaddr;		/* the guest address */
	__u64 flags;		/* flags */
	__u32 size;		/* amount of bytes */
	__u32 op;		/* type of operation */
	__u64 buf;		/* buffer in userspace */
	__u8 ar;		/* the access register number */
	__u8 reserved[31];	/* should be set to 0 */
};

The type of operation is specified in the "op" field. It is either
KVM_S390_MEMOP_LOGICAL_READ for reading from logical memory space or
KVM_S390_MEMOP_LOGICAL_WRITE for writing to logical memory space. The
KVM_S390_MEMOP_F_CHECK_ONLY flag can be set in the "flags" field to check
whether the corresponding memory access would create an access exception
(without touching the data in the memory at the destination). In case an
access exception occurred while walking the MMU tables of the guest, the
ioctl returns a positive error number to indicate the type of exception.
This exception is also raised directly at the corresponding VCPU if the
flag KVM_S390_MEMOP_F_INJECT_EXCEPTION is set in the "flags" field.

The start address of the memory region has to be specified in the "gaddr"
field, and the length of the region in the "size" field. "buf" is the buffer
supplied by the userspace application where the read data should be written
to for KVM_S390_MEMOP_LOGICAL_READ, or where the data that should be written
is stored for a KVM_S390_MEMOP_LOGICAL_WRITE. "buf" is unused and can be NULL
when KVM_S390_MEMOP_F_CHECK_ONLY is specified. "ar" designates the access
register number to be used.

The "reserved" field is meant for future extensions. It is not used by
KVM with the currently defined set of flags.

4.90 KVM_S390_GET_SKEYS

Capability: KVM_CAP_S390_SKEYS
Architectures: s390
Type: vm ioctl
Parameters: struct kvm_s390_skeys
Returns: 0 on success, KVM_S390_GET_KEYS_NONE if guest is not using storage
         keys, negative value on error

This ioctl is used to get guest storage key values on the s390
architecture. The ioctl takes parameters via the kvm_s390_skeys struct.

struct kvm_s390_skeys {
	__u64 start_gfn;
	__u64 count;
	__u64 skeydata_addr;
	__u32 flags;
	__u32 reserved[9];
};

The start_gfn field is the number of the first guest frame whose storage keys
you want to get.

The count field is the number of consecutive frames (starting from start_gfn)
whose storage keys to get. The count field must be at least 1 and the maximum
allowed value is defined as KVM_S390_SKEYS_ALLOC_MAX. Values outside this range
will cause the ioctl to return -EINVAL.

The skeydata_addr field is the address to a buffer large enough to hold count
bytes. This buffer will be filled with storage key data by the ioctl.

4.91 KVM_S390_SET_SKEYS

Capability: KVM_CAP_S390_SKEYS
Architectures: s390
Type: vm ioctl
Parameters: struct kvm_s390_skeys
Returns: 0 on success, negative value on error

This ioctl is used to set guest storage key values on the s390
architecture. The ioctl takes parameters via the kvm_s390_skeys struct.
See section on KVM_S390_GET_SKEYS for struct definition.

The start_gfn field is the number of the first guest frame whose storage keys
you want to set.

The count field is the number of consecutive frames (starting from start_gfn)
whose storage keys to get. The count field must be at least 1 and the maximum
allowed value is defined as KVM_S390_SKEYS_ALLOC_MAX. Values outside this range
will cause the ioctl to return -EINVAL.

The skeydata_addr field is the address to a buffer containing count bytes of
storage keys. Each byte in the buffer will be set as the storage key for a
single frame starting at start_gfn for count frames.

Note: If any architecturally invalid key value is found in the given data then
the ioctl will return -EINVAL.

4.92 KVM_S390_IRQ

Capability: KVM_CAP_S390_INJECT_IRQ
Architectures: s390
Type: vcpu ioctl
Parameters: struct kvm_s390_irq (in)
Returns: 0 on success, -1 on error
Errors:
  EINVAL: interrupt type is invalid
          type is KVM_S390_SIGP_STOP and flag parameter is invalid value
          type is KVM_S390_INT_EXTERNAL_CALL and code is bigger
            than the maximum of VCPUs
  EBUSY:  type is KVM_S390_SIGP_SET_PREFIX and vcpu is not stopped
          type is KVM_S390_SIGP_STOP and a stop irq is already pending
          type is KVM_S390_INT_EXTERNAL_CALL and an external call interrupt
            is already pending

Allows to inject an interrupt to the guest.

Using struct kvm_s390_irq as a parameter allows
to inject additional payload which is not
possible via KVM_S390_INTERRUPT.

Interrupt parameters are passed via kvm_s390_irq:

struct kvm_s390_irq {
	__u64 type;
	union {
		struct kvm_s390_io_info io;
		struct kvm_s390_ext_info ext;
		struct kvm_s390_pgm_info pgm;
		struct kvm_s390_emerg_info emerg;
		struct kvm_s390_extcall_info extcall;
		struct kvm_s390_prefix_info prefix;
		struct kvm_s390_stop_info stop;
		struct kvm_s390_mchk_info mchk;
		char reserved[64];
	} u;
};

type can be one of the following:

KVM_S390_SIGP_STOP - sigp stop; parameter in .stop
KVM_S390_PROGRAM_INT - program check; parameters in .pgm
KVM_S390_SIGP_SET_PREFIX - sigp set prefix; parameters in .prefix
KVM_S390_RESTART - restart; no parameters
KVM_S390_INT_CLOCK_COMP - clock comparator interrupt; no parameters
KVM_S390_INT_CPU_TIMER - CPU timer interrupt; no parameters
KVM_S390_INT_EMERGENCY - sigp emergency; parameters in .emerg
KVM_S390_INT_EXTERNAL_CALL - sigp external call; parameters in .extcall
KVM_S390_MCHK - machine check interrupt; parameters in .mchk


Note that the vcpu ioctl is asynchronous to vcpu execution.

4.94 KVM_S390_GET_IRQ_STATE

Capability: KVM_CAP_S390_IRQ_STATE
Architectures: s390
Type: vcpu ioctl
Parameters: struct kvm_s390_irq_state (out)
Returns: >= number of bytes copied into buffer,
         -EINVAL if buffer size is 0,
         -ENOBUFS if buffer size is too small to fit all pending interrupts,
         -EFAULT if the buffer address was invalid

This ioctl allows userspace to retrieve the complete state of all currently
pending interrupts in a single buffer. Use cases include migration
and introspection. The parameter structure contains the address of a
userspace buffer and its length:

struct kvm_s390_irq_state {
	__u64 buf;
	__u32 flags;
	__u32 len;
	__u32 reserved[4];
};

Userspace passes in the above struct and for each pending interrupt a
struct kvm_s390_irq is copied to the provided buffer.

If -ENOBUFS is returned the buffer provided was too small and userspace
may retry with a bigger buffer.

4.95 KVM_S390_SET_IRQ_STATE

Capability: KVM_CAP_S390_IRQ_STATE
Architectures: s390
Type: vcpu ioctl
Parameters: struct kvm_s390_irq_state (in)
Returns: 0 on success,
         -EFAULT if the buffer address was invalid,
         -EINVAL for an invalid buffer length (see below),
         -EBUSY if there were already interrupts pending,
         errors occurring when actually injecting the
          interrupt. See KVM_S390_IRQ.

This ioctl allows userspace to set the complete state of all cpu-local
interrupts currently pending for the vcpu. It is intended for restoring
interrupt state after a migration. The input parameter is a userspace buffer
containing a struct kvm_s390_irq_state:

struct kvm_s390_irq_state {
	__u64 buf;
	__u32 len;
	__u32 pad;
};

The userspace memory referenced by buf contains a struct kvm_s390_irq
for each interrupt to be injected into the guest.
If one of the interrupts could not be injected for some reason the
ioctl aborts.

len must be a multiple of sizeof(struct kvm_s390_irq). It must be > 0
and it must not exceed (max_vcpus + 32) * sizeof(struct kvm_s390_irq),
which is the maximum number of possibly pending cpu-local interrupts.

4.90 KVM_SMI

Capability: KVM_CAP_X86_SMM
Architectures: x86
Type: vcpu ioctl
Parameters: none
Returns: 0 on success, -1 on error

Queues an SMI on the thread's vcpu.

5. The kvm_run structure
------------------------

Application code obtains a pointer to the kvm_run structure by
mmap()ing a vcpu fd.  From that point, application code can control
execution by changing fields in kvm_run prior to calling the KVM_RUN
ioctl, and obtain information about the reason KVM_RUN returned by
looking up structure members.

struct kvm_run {
	/* in */
	__u8 request_interrupt_window;

Request that KVM_RUN return when it becomes possible to inject external
interrupts into the guest.  Useful in conjunction with KVM_INTERRUPT.

	__u8 padding1[7];

	/* out */
	__u32 exit_reason;

When KVM_RUN has returned successfully (return value 0), this informs
application code why KVM_RUN has returned.  Allowable values for this
field are detailed below.

	__u8 ready_for_interrupt_injection;

If request_interrupt_window has been specified, this field indicates
an interrupt can be injected now with KVM_INTERRUPT.

	__u8 if_flag;

The value of the current interrupt flag.  Only valid if in-kernel
local APIC is not used.

	__u16 flags;

More architecture-specific flags detailing state of the VCPU that may
affect the device's behavior.  The only currently defined flag is
KVM_RUN_X86_SMM, which is valid on x86 machines and is set if the
VCPU is in system management mode.

	/* in (pre_kvm_run), out (post_kvm_run) */
	__u64 cr8;

The value of the cr8 register.  Only valid if in-kernel local APIC is
not used.  Both input and output.

	__u64 apic_base;

The value of the APIC BASE msr.  Only valid if in-kernel local
APIC is not used.  Both input and output.

	union {
		/* KVM_EXIT_UNKNOWN */
		struct {
			__u64 hardware_exit_reason;
		} hw;

If exit_reason is KVM_EXIT_UNKNOWN, the vcpu has exited due to unknown
reasons.  Further architecture-specific information is available in
hardware_exit_reason.

		/* KVM_EXIT_FAIL_ENTRY */
		struct {
			__u64 hardware_entry_failure_reason;
		} fail_entry;

If exit_reason is KVM_EXIT_FAIL_ENTRY, the vcpu could not be run due
to unknown reasons.  Further architecture-specific information is
available in hardware_entry_failure_reason.

		/* KVM_EXIT_EXCEPTION */
		struct {
			__u32 exception;
			__u32 error_code;
		} ex;

Unused.

		/* KVM_EXIT_IO */
		struct {
#define KVM_EXIT_IO_IN  0
#define KVM_EXIT_IO_OUT 1
			__u8 direction;
			__u8 size; /* bytes */
			__u16 port;
			__u32 count;
			__u64 data_offset; /* relative to kvm_run start */
		} io;

If exit_reason is KVM_EXIT_IO, then the vcpu has
executed a port I/O instruction which could not be satisfied by kvm.
data_offset describes where the data is located (KVM_EXIT_IO_OUT) or
where kvm expects application code to place the data for the next
KVM_RUN invocation (KVM_EXIT_IO_IN).  Data format is a packed array.

		/* KVM_EXIT_DEBUG */
		struct {
			struct kvm_debug_exit_arch arch;
		} debug;

If the exit_reason is KVM_EXIT_DEBUG, then a vcpu is processing a debug event
for which architecture specific information is returned.

		/* KVM_EXIT_MMIO */
		struct {
			__u64 phys_addr;
			__u8  data[8];
			__u32 len;
			__u8  is_write;
		} mmio;

If exit_reason is KVM_EXIT_MMIO, then the vcpu has
executed a memory-mapped I/O instruction which could not be satisfied
by kvm.  The 'data' member contains the written data if 'is_write' is
true, and should be filled by application code otherwise.

The 'data' member contains, in its first 'len' bytes, the value as it would
appear if the VCPU performed a load or store of the appropriate width directly
to the byte array.

NOTE: For KVM_EXIT_IO, KVM_EXIT_MMIO, KVM_EXIT_OSI, KVM_EXIT_PAPR and
      KVM_EXIT_EPR the corresponding
operations are complete (and guest state is consistent) only after userspace
has re-entered the kernel with KVM_RUN.  The kernel side will first finish
incomplete operations and then check for pending signals.  Userspace
can re-enter the guest with an unmasked signal pending to complete
pending operations.

		/* KVM_EXIT_HYPERCALL */
		struct {
			__u64 nr;
			__u64 args[6];
			__u64 ret;
			__u32 longmode;
			__u32 pad;
		} hypercall;

Unused.  This was once used for 'hypercall to userspace'.  To implement
such functionality, use KVM_EXIT_IO (x86) or KVM_EXIT_MMIO (all except s390).
Note KVM_EXIT_IO is significantly faster than KVM_EXIT_MMIO.

		/* KVM_EXIT_TPR_ACCESS */
		struct {
			__u64 rip;
			__u32 is_write;
			__u32 pad;
		} tpr_access;

To be documented (KVM_TPR_ACCESS_REPORTING).

		/* KVM_EXIT_S390_SIEIC */
		struct {
			__u8 icptcode;
			__u64 mask; /* psw upper half */
			__u64 addr; /* psw lower half */
			__u16 ipa;
			__u32 ipb;
		} s390_sieic;

s390 specific.

		/* KVM_EXIT_S390_RESET */
#define KVM_S390_RESET_POR       1
#define KVM_S390_RESET_CLEAR     2
#define KVM_S390_RESET_SUBSYSTEM 4
#define KVM_S390_RESET_CPU_INIT  8
#define KVM_S390_RESET_IPL       16
		__u64 s390_reset_flags;

s390 specific.

		/* KVM_EXIT_S390_UCONTROL */
		struct {
			__u64 trans_exc_code;
			__u32 pgm_code;
		} s390_ucontrol;

s390 specific. A page fault has occurred for a user controlled virtual
machine (KVM_VM_S390_UNCONTROL) on it's host page table that cannot be
resolved by the kernel.
The program code and the translation exception code that were placed
in the cpu's lowcore are presented here as defined by the z Architecture
Principles of Operation Book in the Chapter for Dynamic Address Translation
(DAT)

		/* KVM_EXIT_DCR */
		struct {
			__u32 dcrn;
			__u32 data;
			__u8  is_write;
		} dcr;

Deprecated - was used for 440 KVM.

		/* KVM_EXIT_OSI */
		struct {
			__u64 gprs[32];
		} osi;

MOL uses a special hypercall interface it calls 'OSI'. To enable it, we catch
hypercalls and exit with this exit struct that contains all the guest gprs.

If exit_reason is KVM_EXIT_OSI, then the vcpu has triggered such a hypercall.
Userspace can now handle the hypercall and when it's done modify the gprs as
necessary. Upon guest entry all guest GPRs will then be replaced by the values
in this struct.

		/* KVM_EXIT_PAPR_HCALL */
		struct {
			__u64 nr;
			__u64 ret;
			__u64 args[9];
		} papr_hcall;

This is used on 64-bit PowerPC when emulating a pSeries partition,
e.g. with the 'pseries' machine type in qemu.  It occurs when the
guest does a hypercall using the 'sc 1' instruction.  The 'nr' field
contains the hypercall number (from the guest R3), and 'args' contains
the arguments (from the guest R4 - R12).  Userspace should put the
return code in 'ret' and any extra returned values in args[].
The possible hypercalls are defined in the Power Architecture Platform
Requirements (PAPR) document available from www.power.org (free
developer registration required to access it).

		/* KVM_EXIT_S390_TSCH */
		struct {
			__u16 subchannel_id;
			__u16 subchannel_nr;
			__u32 io_int_parm;
			__u32 io_int_word;
			__u32 ipb;
			__u8 dequeued;
		} s390_tsch;

s390 specific. This exit occurs when KVM_CAP_S390_CSS_SUPPORT has been enabled
and TEST SUBCHANNEL was intercepted. If dequeued is set, a pending I/O
interrupt for the target subchannel has been dequeued and subchannel_id,
subchannel_nr, io_int_parm and io_int_word contain the parameters for that
interrupt. ipb is needed for instruction parameter decoding.

		/* KVM_EXIT_EPR */
		struct {
			__u32 epr;
		} epr;

On FSL BookE PowerPC chips, the interrupt controller has a fast patch
interrupt acknowledge path to the core. When the core successfully
delivers an interrupt, it automatically populates the EPR register with
the interrupt vector number and acknowledges the interrupt inside
the interrupt controller.

In case the interrupt controller lives in user space, we need to do
the interrupt acknowledge cycle through it to fetch the next to be
delivered interrupt vector using this exit.

It gets triggered whenever both KVM_CAP_PPC_EPR are enabled and an
external interrupt has just been delivered into the guest. User space
should put the acknowledged interrupt vector into the 'epr' field.

		/* KVM_EXIT_SYSTEM_EVENT */
		struct {
#define KVM_SYSTEM_EVENT_SHUTDOWN       1
#define KVM_SYSTEM_EVENT_RESET          2
#define KVM_SYSTEM_EVENT_CRASH          3
			__u32 type;
			__u64 flags;
		} system_event;

If exit_reason is KVM_EXIT_SYSTEM_EVENT then the vcpu has triggered
a system-level event using some architecture specific mechanism (hypercall
or some special instruction). In case of ARM/ARM64, this is triggered using
HVC instruction based PSCI call from the vcpu. The 'type' field describes
the system-level event type. The 'flags' field describes architecture
specific flags for the system-level event.

Valid values for 'type' are:
  KVM_SYSTEM_EVENT_SHUTDOWN -- the guest has requested a shutdown of the
   VM. Userspace is not obliged to honour this, and if it does honour
   this does not need to destroy the VM synchronously (ie it may call
   KVM_RUN again before shutdown finally occurs).
  KVM_SYSTEM_EVENT_RESET -- the guest has requested a reset of the VM.
   As with SHUTDOWN, userspace can choose to ignore the request, or
   to schedule the reset to occur in the future and may call KVM_RUN again.
  KVM_SYSTEM_EVENT_CRASH -- the guest crash occurred and the guest
   has requested a crash condition maintenance. Userspace can choose
   to ignore the request, or to gather VM memory core dump and/or
   reset/shutdown of the VM.

		/* KVM_EXIT_IOAPIC_EOI */
		struct {
			__u8 vector;
		} eoi;

Indicates that the VCPU's in-kernel local APIC received an EOI for a
level-triggered IOAPIC interrupt.  This exit only triggers when the
IOAPIC is implemented in userspace (i.e. KVM_CAP_SPLIT_IRQCHIP is enabled);
the userspace IOAPIC should process the EOI and retrigger the interrupt if
it is still asserted.  Vector is the LAPIC interrupt vector for which the
EOI was received.

		struct kvm_hyperv_exit {
#define KVM_EXIT_HYPERV_SYNIC          1
			__u32 type;
			union {
				struct {
					__u32 msr;
					__u64 control;
					__u64 evt_page;
					__u64 msg_page;
				} synic;
			} u;
		};
		/* KVM_EXIT_HYPERV */
                struct kvm_hyperv_exit hyperv;
Indicates that the VCPU exits into userspace to process some tasks
related to Hyper-V emulation.
Valid values for 'type' are:
	KVM_EXIT_HYPERV_SYNIC -- synchronously notify user-space about
Hyper-V SynIC state change. Notification is used to remap SynIC
event/message pages and to enable/disable SynIC messages/events processing
in userspace.

		/* Fix the size of the union. */
		char padding[256];
	};

	/*
	 * shared registers between kvm and userspace.
	 * kvm_valid_regs specifies the register classes set by the host
	 * kvm_dirty_regs specified the register classes dirtied by userspace
	 * struct kvm_sync_regs is architecture specific, as well as the
	 * bits for kvm_valid_regs and kvm_dirty_regs
	 */
	__u64 kvm_valid_regs;
	__u64 kvm_dirty_regs;
	union {
		struct kvm_sync_regs regs;
		char padding[1024];
	} s;

If KVM_CAP_SYNC_REGS is defined, these fields allow userspace to access
certain guest registers without having to call SET/GET_*REGS. Thus we can
avoid some system call overhead if userspace has to handle the exit.
Userspace can query the validity of the structure by checking
kvm_valid_regs for specific bits. These bits are architecture specific
and usually define the validity of a groups of registers. (e.g. one bit
 for general purpose registers)

Please note that the kernel is allowed to use the kvm_run structure as the
primary storage for certain register types. Therefore, the kernel may use the
values in kvm_run even if the corresponding bit in kvm_dirty_regs is not set.

};



6. Capabilities that can be enabled on vCPUs
--------------------------------------------

There are certain capabilities that change the behavior of the virtual CPU or
the virtual machine when enabled. To enable them, please see section 4.37.
Below you can find a list of capabilities and what their effect on the vCPU or
the virtual machine is when enabling them.

The following information is provided along with the description:

  Architectures: which instruction set architectures provide this ioctl.
      x86 includes both i386 and x86_64.

  Target: whether this is a per-vcpu or per-vm capability.

  Parameters: what parameters are accepted by the capability.

  Returns: the return value.  General error numbers (EBADF, ENOMEM, EINVAL)
      are not detailed, but errors with specific meanings are.


6.1 KVM_CAP_PPC_OSI

Architectures: ppc
Target: vcpu
Parameters: none
Returns: 0 on success; -1 on error

This capability enables interception of OSI hypercalls that otherwise would
be treated as normal system calls to be injected into the guest. OSI hypercalls
were invented by Mac-on-Linux to have a standardized communication mechanism
between the guest and the host.

When this capability is enabled, KVM_EXIT_OSI can occur.


6.2 KVM_CAP_PPC_PAPR

Architectures: ppc
Target: vcpu
Parameters: none
Returns: 0 on success; -1 on error

This capability enables interception of PAPR hypercalls. PAPR hypercalls are
done using the hypercall instruction "sc 1".

It also sets the guest privilege level to "supervisor" mode. Usually the guest
runs in "hypervisor" privilege mode with a few missing features.

In addition to the above, it changes the semantics of SDR1. In this mode, the
HTAB address part of SDR1 contains an HVA instead of a GPA, as PAPR keeps the
HTAB invisible to the guest.

When this capability is enabled, KVM_EXIT_PAPR_HCALL can occur.


6.3 KVM_CAP_SW_TLB

Architectures: ppc
Target: vcpu
Parameters: args[0] is the address of a struct kvm_config_tlb
Returns: 0 on success; -1 on error

struct kvm_config_tlb {
	__u64 params;
	__u64 array;
	__u32 mmu_type;
	__u32 array_len;
};

Configures the virtual CPU's TLB array, establishing a shared memory area
between userspace and KVM.  The "params" and "array" fields are userspace
addresses of mmu-type-specific data structures.  The "array_len" field is an
safety mechanism, and should be set to the size in bytes of the memory that
userspace has reserved for the array.  It must be at least the size dictated
by "mmu_type" and "params".

While KVM_RUN is active, the shared region is under control of KVM.  Its
contents are undefined, and any modification by userspace results in
boundedly undefined behavior.

On return from KVM_RUN, the shared region will reflect the current state of
the guest's TLB.  If userspace makes any changes, it must call KVM_DIRTY_TLB
to tell KVM which entries have been changed, prior to calling KVM_RUN again
on this vcpu.

For mmu types KVM_MMU_FSL_BOOKE_NOHV and KVM_MMU_FSL_BOOKE_HV:
 - The "params" field is of type "struct kvm_book3e_206_tlb_params".
 - The "array" field points to an array of type "struct
   kvm_book3e_206_tlb_entry".
 - The array consists of all entries in the first TLB, followed by all
   entries in the second TLB.
 - Within a TLB, entries are ordered first by increasing set number.  Within a
   set, entries are ordered by way (increasing ESEL).
 - The hash for determining set number in TLB0 is: (MAS2 >> 12) & (num_sets - 1)
   where "num_sets" is the tlb_sizes[] value divided by the tlb_ways[] value.
 - The tsize field of mas1 shall be set to 4K on TLB0, even though the
   hardware ignores this value for TLB0.

6.4 KVM_CAP_S390_CSS_SUPPORT

Architectures: s390
Target: vcpu
Parameters: none
Returns: 0 on success; -1 on error

This capability enables support for handling of channel I/O instructions.

TEST PENDING INTERRUPTION and the interrupt portion of TEST SUBCHANNEL are
handled in-kernel, while the other I/O instructions are passed to userspace.

When this capability is enabled, KVM_EXIT_S390_TSCH will occur on TEST
SUBCHANNEL intercepts.

Note that even though this capability is enabled per-vcpu, the complete
virtual machine is affected.

6.5 KVM_CAP_PPC_EPR

Architectures: ppc
Target: vcpu
Parameters: args[0] defines whether the proxy facility is active
Returns: 0 on success; -1 on error

This capability enables or disables the delivery of interrupts through the
external proxy facility.

When enabled (args[0] != 0), every time the guest gets an external interrupt
delivered, it automatically exits into user space with a KVM_EXIT_EPR exit
to receive the topmost interrupt vector.

When disabled (args[0] == 0), behavior is as if this facility is unsupported.

When this capability is enabled, KVM_EXIT_EPR can occur.

6.6 KVM_CAP_IRQ_MPIC

Architectures: ppc
Parameters: args[0] is the MPIC device fd
            args[1] is the MPIC CPU number for this vcpu

This capability connects the vcpu to an in-kernel MPIC device.

6.7 KVM_CAP_IRQ_XICS

Architectures: ppc
Target: vcpu
Parameters: args[0] is the XICS device fd
            args[1] is the XICS CPU number (server ID) for this vcpu

This capability connects the vcpu to an in-kernel XICS device.

6.8 KVM_CAP_S390_IRQCHIP

Architectures: s390
Target: vm
Parameters: none

This capability enables the in-kernel irqchip for s390. Please refer to
"4.24 KVM_CREATE_IRQCHIP" for details.

6.9 KVM_CAP_MIPS_FPU

Architectures: mips
Target: vcpu
Parameters: args[0] is reserved for future use (should be 0).

This capability allows the use of the host Floating Point Unit by the guest. It
allows the Config1.FP bit to be set to enable the FPU in the guest. Once this is
done the KVM_REG_MIPS_FPR_* and KVM_REG_MIPS_FCR_* registers can be accessed
(depending on the current guest FPU register mode), and the Status.FR,
Config5.FRE bits are accessible via the KVM API and also from the guest,
depending on them being supported by the FPU.

6.10 KVM_CAP_MIPS_MSA

Architectures: mips
Target: vcpu
Parameters: args[0] is reserved for future use (should be 0).

This capability allows the use of the MIPS SIMD Architecture (MSA) by the guest.
It allows the Config3.MSAP bit to be set to enable the use of MSA by the guest.
Once this is done the KVM_REG_MIPS_VEC_* and KVM_REG_MIPS_MSA_* registers can be
accessed, and the Config5.MSAEn bit is accessible via the KVM API and also from
the guest.

7. Capabilities that can be enabled on VMs
------------------------------------------

There are certain capabilities that change the behavior of the virtual
machine when enabled. To enable them, please see section 4.37. Below
you can find a list of capabilities and what their effect on the VM
is when enabling them.

The following information is provided along with the description:

  Architectures: which instruction set architectures provide this ioctl.
      x86 includes both i386 and x86_64.

  Parameters: what parameters are accepted by the capability.

  Returns: the return value.  General error numbers (EBADF, ENOMEM, EINVAL)
      are not detailed, but errors with specific meanings are.


7.1 KVM_CAP_PPC_ENABLE_HCALL

Architectures: ppc
Parameters: args[0] is the sPAPR hcall number
	    args[1] is 0 to disable, 1 to enable in-kernel handling

This capability controls whether individual sPAPR hypercalls (hcalls)
get handled by the kernel or not.  Enabling or disabling in-kernel
handling of an hcall is effective across the VM.  On creation, an
initial set of hcalls are enabled for in-kernel handling, which
consists of those hcalls for which in-kernel handlers were implemented
before this capability was implemented.  If disabled, the kernel will
not to attempt to handle the hcall, but will always exit to userspace
to handle it.  Note that it may not make sense to enable some and
disable others of a group of related hcalls, but KVM does not prevent
userspace from doing that.

If the hcall number specified is not one that has an in-kernel
implementation, the KVM_ENABLE_CAP ioctl will fail with an EINVAL
error.

7.2 KVM_CAP_S390_USER_SIGP

Architectures: s390
Parameters: none

This capability controls which SIGP orders will be handled completely in user
space. With this capability enabled, all fast orders will be handled completely
in the kernel:
- SENSE
- SENSE RUNNING
- EXTERNAL CALL
- EMERGENCY SIGNAL
- CONDITIONAL EMERGENCY SIGNAL

All other orders will be handled completely in user space.

Only privileged operation exceptions will be checked for in the kernel (or even
in the hardware prior to interception). If this capability is not enabled, the
old way of handling SIGP orders is used (partially in kernel and user space).

7.3 KVM_CAP_S390_VECTOR_REGISTERS

Architectures: s390
Parameters: none
Returns: 0 on success, negative value on error

Allows use of the vector registers introduced with z13 processor, and
provides for the synchronization between host and user space.  Will
return -EINVAL if the machine does not support vectors.

7.4 KVM_CAP_S390_USER_STSI

Architectures: s390
Parameters: none

This capability allows post-handlers for the STSI instruction. After
initial handling in the kernel, KVM exits to user space with
KVM_EXIT_S390_STSI to allow user space to insert further data.

Before exiting to userspace, kvm handlers should fill in s390_stsi field of
vcpu->run:
struct {
	__u64 addr;
	__u8 ar;
	__u8 reserved;
	__u8 fc;
	__u8 sel1;
	__u16 sel2;
} s390_stsi;

@addr - guest address of STSI SYSIB
@fc   - function code
@sel1 - selector 1
@sel2 - selector 2
@ar   - access register number

KVM handlers should exit to userspace with rc = -EREMOTE.

7.5 KVM_CAP_SPLIT_IRQCHIP

Architectures: x86
Parameters: args[0] - number of routes reserved for userspace IOAPICs
Returns: 0 on success, -1 on error

Create a local apic for each processor in the kernel. This can be used
instead of KVM_CREATE_IRQCHIP if the userspace VMM wishes to emulate the
IOAPIC and PIC (and also the PIT, even though this has to be enabled
separately).

This capability also enables in kernel routing of interrupt requests;
when KVM_CAP_SPLIT_IRQCHIP only routes of KVM_IRQ_ROUTING_MSI type are
used in the IRQ routing table.  The first args[0] MSI routes are reserved
for the IOAPIC pins.  Whenever the LAPIC receives an EOI for these routes,
a KVM_EXIT_IOAPIC_EOI vmexit will be reported to userspace.

Fails if VCPU has already been created, or if the irqchip is already in the
kernel (i.e. KVM_CREATE_IRQCHIP has already been called).


8. Other capabilities.
----------------------

This section lists capabilities that give information about other
features of the KVM implementation.

8.1 KVM_CAP_PPC_HWRNG

Architectures: ppc

This capability, if KVM_CHECK_EXTENSION indicates that it is
available, means that that the kernel has an implementation of the
H_RANDOM hypercall backed by a hardware random-number generator.
If present, the kernel H_RANDOM handler can be enabled for guest use
with the KVM_CAP_PPC_ENABLE_HCALL capability.

8.2 KVM_CAP_HYPERV_SYNIC

Architectures: x86
This capability, if KVM_CHECK_EXTENSION indicates that it is
available, means that that the kernel has an implementation of the
Hyper-V Synthetic interrupt controller(SynIC). Hyper-V SynIC is
used to support Windows Hyper-V based guest paravirt drivers(VMBus).

In order to use SynIC, it has to be activated by setting this
capability via KVM_ENABLE_CAP ioctl on the vcpu fd. Note that this
will disable the use of APIC hardware virtualization even if supported
by the CPU, as it's incompatible with SynIC auto-EOI behavior.
