/*
 * Copyright 2014 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef KFD_IOCTL_H_INCLUDED
#define KFD_IOCTL_H_INCLUDED

#include <libdrm/drm.h>
#include <linux/ioctl.h>

/*
 * - 1.1 - initial version
 * - 1.3 - Add SMI events support
 * - 1.4 - Indicate new SRAM EDC bit in device properties
 * - 1.5 - Add SVM API
 * - 1.6 - Query clear flags in SVM get_attr API
 * - 1.7 - Checkpoint Restore (CRIU) API
 * - 1.8 - CRIU - Support for SDMA transfers with GTT BOs
 */
#define KFD_IOCTL_MAJOR_VERSION 1
#define KFD_IOCTL_MINOR_VERSION 8

struct kfd_ioctl_get_version_args {
	uint32_t major_version; /* from KFD */
	uint32_t minor_version; /* from KFD */
};

/* For kfd_ioctl_create_queue_args.queue_type. */
#define KFD_IOC_QUEUE_TYPE_COMPUTE     0x0
#define KFD_IOC_QUEUE_TYPE_SDMA	       0x1
#define KFD_IOC_QUEUE_TYPE_COMPUTE_AQL 0x2
#define KFD_IOC_QUEUE_TYPE_SDMA_XGMI   0x3

#define KFD_MAX_QUEUE_PERCENTAGE 100
#define KFD_MAX_QUEUE_PRIORITY	 15

struct kfd_ioctl_create_queue_args {
	uint64_t ring_base_address;	/* to KFD */
	uint64_t write_pointer_address; /* from KFD */
	uint64_t read_pointer_address;	/* from KFD */
	uint64_t doorbell_offset;	/* from KFD */

	uint32_t ring_size;	   /* to KFD */
	uint32_t gpu_id;	   /* to KFD */
	uint32_t queue_type;	   /* to KFD */
	uint32_t queue_percentage; /* to KFD */
	uint32_t queue_priority;   /* to KFD */
	uint32_t queue_id;	   /* from KFD */

	uint64_t eop_buffer_address;	   /* to KFD */
	uint64_t eop_buffer_size;	   /* to KFD */
	uint64_t ctx_save_restore_address; /* to KFD */
	uint32_t ctx_save_restore_size;	   /* to KFD */
	uint32_t ctl_stack_size;	   /* to KFD */
};

struct kfd_ioctl_destroy_queue_args {
	uint32_t queue_id; /* to KFD */
	uint32_t pad;
};

struct kfd_ioctl_update_queue_args {
	uint64_t ring_base_address; /* to KFD */

	uint32_t queue_id;	   /* to KFD */
	uint32_t ring_size;	   /* to KFD */
	uint32_t queue_percentage; /* to KFD */
	uint32_t queue_priority;   /* to KFD */
};

struct kfd_ioctl_set_cu_mask_args {
	uint32_t queue_id;    /* to KFD */
	uint32_t num_cu_mask; /* to KFD */
	uint64_t cu_mask_ptr; /* to KFD */
};

struct kfd_ioctl_get_queue_wave_state_args {
	uint64_t ctl_stack_address;   /* to KFD */
	uint32_t ctl_stack_used_size; /* from KFD */
	uint32_t save_area_used_size; /* from KFD */
	uint32_t queue_id;	      /* to KFD */
	uint32_t pad;
};

/* For kfd_ioctl_set_memory_policy_args.default_policy and alternate_policy */
#define KFD_IOC_CACHE_POLICY_COHERENT	 0
#define KFD_IOC_CACHE_POLICY_NONCOHERENT 1

struct kfd_ioctl_set_memory_policy_args {
	uint64_t alternate_aperture_base; /* to KFD */
	uint64_t alternate_aperture_size; /* to KFD */

	uint32_t gpu_id;	   /* to KFD */
	uint32_t default_policy;   /* to KFD */
	uint32_t alternate_policy; /* to KFD */
	uint32_t pad;
};

/*
 * All counters are monotonic. They are used for profiling of compute jobs.
 * The profiling is done by userspace.
 *
 * In case of GPU reset, the counter should not be affected.
 */

struct kfd_ioctl_get_clock_counters_args {
	uint64_t gpu_clock_counter;    /* from KFD */
	uint64_t cpu_clock_counter;    /* from KFD */
	uint64_t system_clock_counter; /* from KFD */
	uint64_t system_clock_freq;    /* from KFD */

	uint32_t gpu_id; /* to KFD */
	uint32_t pad;
};

struct kfd_process_device_apertures {
	uint64_t lds_base;	/* from KFD */
	uint64_t lds_limit;	/* from KFD */
	uint64_t scratch_base;	/* from KFD */
	uint64_t scratch_limit; /* from KFD */
	uint64_t gpuvm_base;	/* from KFD */
	uint64_t gpuvm_limit;	/* from KFD */
	uint32_t gpu_id;	/* from KFD */
	uint32_t pad;
};

/*
 * AMDKFD_IOC_GET_PROCESS_APERTURES is deprecated. Use
 * AMDKFD_IOC_GET_PROCESS_APERTURES_NEW instead, which supports an
 * unlimited number of GPUs.
 */
#define NUM_OF_SUPPORTED_GPUS 7
struct kfd_ioctl_get_process_apertures_args {
	struct kfd_process_device_apertures process_apertures[NUM_OF_SUPPORTED_GPUS]; /* from KFD */

	/* from KFD, should be in the range [1 - NUM_OF_SUPPORTED_GPUS] */
	uint32_t num_of_nodes;
	uint32_t pad;
};

struct kfd_ioctl_get_process_apertures_new_args {
	/* User allocated. Pointer to struct kfd_process_device_apertures
	 * filled in by Kernel
	 */
	uint64_t kfd_process_device_apertures_ptr;
	/* to KFD - indicates amount of memory present in kfd_process_device_apertures_ptr
	 * from KFD - Number of entries filled by KFD.
	 */
	uint32_t num_of_nodes;
	uint32_t pad;
};

#define MAX_ALLOWED_NUM_POINTS	  100
#define MAX_ALLOWED_AW_BUFF_SIZE  4096
#define MAX_ALLOWED_WAC_BUFF_SIZE 128

struct kfd_ioctl_dbg_register_args {
	uint32_t gpu_id; /* to KFD */
	uint32_t pad;
};

struct kfd_ioctl_dbg_unregister_args {
	uint32_t gpu_id; /* to KFD */
	uint32_t pad;
};

struct kfd_ioctl_dbg_address_watch_args {
	uint64_t content_ptr;	    /* a pointer to the actual content */
	uint32_t gpu_id;	    /* to KFD */
	uint32_t buf_size_in_bytes; /*including gpu_id and buf_size */
};

struct kfd_ioctl_dbg_wave_control_args {
	uint64_t content_ptr;	    /* a pointer to the actual content */
	uint32_t gpu_id;	    /* to KFD */
	uint32_t buf_size_in_bytes; /*including gpu_id and buf_size */
};

#define KFD_INVALID_FD 0xffffffff

/* Matching HSA_EVENTTYPE */
#define KFD_IOC_EVENT_SIGNAL		0
#define KFD_IOC_EVENT_NODECHANGE	1
#define KFD_IOC_EVENT_DEVICESTATECHANGE 2
#define KFD_IOC_EVENT_HW_EXCEPTION	3
#define KFD_IOC_EVENT_SYSTEM_EVENT	4
#define KFD_IOC_EVENT_DEBUG_EVENT	5
#define KFD_IOC_EVENT_PROFILE_EVENT	6
#define KFD_IOC_EVENT_QUEUE_EVENT	7
#define KFD_IOC_EVENT_MEMORY		8

#define KFD_IOC_WAIT_RESULT_COMPLETE 0
#define KFD_IOC_WAIT_RESULT_TIMEOUT  1
#define KFD_IOC_WAIT_RESULT_FAIL     2

#define KFD_SIGNAL_EVENT_LIMIT 4096

/* For kfd_event_data.hw_exception_data.reset_type. */
#define KFD_HW_EXCEPTION_WHOLE_GPU_RESET  0
#define KFD_HW_EXCEPTION_PER_ENGINE_RESET 1

/* For kfd_event_data.hw_exception_data.reset_cause. */
#define KFD_HW_EXCEPTION_GPU_HANG 0
#define KFD_HW_EXCEPTION_ECC	  1

/* For kfd_hsa_memory_exception_data.ErrorType */
#define KFD_MEM_ERR_NO_RAS	    0
#define KFD_MEM_ERR_SRAM_ECC	    1
#define KFD_MEM_ERR_POISON_CONSUMED 2
#define KFD_MEM_ERR_GPU_HANG	    3

struct kfd_ioctl_create_event_args {
	uint64_t event_page_offset;  /* from KFD */
	uint32_t event_trigger_data; /* from KFD - signal events only */
	uint32_t event_type;	     /* to KFD */
	uint32_t auto_reset;	     /* to KFD */
	uint32_t node_id;	     /* to KFD - only valid for certain event types */
	uint32_t event_id;	     /* from KFD */
	uint32_t event_slot_index;   /* from KFD */
};

struct kfd_ioctl_destroy_event_args {
	uint32_t event_id; /* to KFD */
	uint32_t pad;
};

struct kfd_ioctl_set_event_args {
	uint32_t event_id; /* to KFD */
	uint32_t pad;
};

struct kfd_ioctl_reset_event_args {
	uint32_t event_id; /* to KFD */
	uint32_t pad;
};

struct kfd_memory_exception_failure {
	uint32_t NotPresent; /* Page not present or supervisor privilege */
	uint32_t ReadOnly;   /* Write access to a read-only page */
	uint32_t NoExecute;  /* Execute access to a page marked NX */
	uint32_t imprecise;  /* Can't determine the exact fault address */
};

/* memory exception data */
struct kfd_hsa_memory_exception_data {
	struct kfd_memory_exception_failure failure;
	uint64_t va;
	uint32_t gpu_id;
	uint32_t ErrorType; /* 0 = no RAS error,
			  * 1 = ECC_SRAM,
			  * 2 = Link_SYNFLOOD (poison),
			  * 3 = GPU hang (not attributable to a specific cause),
			  * other values reserved
			  */
};

/* hw exception data */
struct kfd_hsa_hw_exception_data {
	uint32_t reset_type;
	uint32_t reset_cause;
	uint32_t memory_lost;
	uint32_t gpu_id;
};

/* Event data */
struct kfd_event_data {
	union {
		struct kfd_hsa_memory_exception_data memory_exception_data;
		struct kfd_hsa_hw_exception_data hw_exception_data;
	};			  /* From KFD */
	uint64_t kfd_event_data_ext; /* pointer to an extension structure for future exception types */
	uint32_t event_id;	     /* to KFD */
	uint32_t pad;
};

struct kfd_ioctl_wait_events_args {
	uint64_t events_ptr;   /* pointed to struct kfd_event_data array, to KFD */
	uint32_t num_events;   /* to KFD */
	uint32_t wait_for_all; /* to KFD */
	uint32_t timeout;      /* to KFD */
	uint32_t wait_result;  /* from KFD */
};

struct kfd_ioctl_set_scratch_backing_va_args {
	uint64_t va_addr; /* to KFD */
	uint32_t gpu_id;  /* to KFD */
	uint32_t pad;
};

struct kfd_ioctl_get_tile_config_args {
	/* to KFD: pointer to tile array */
	uint64_t tile_config_ptr;
	/* to KFD: pointer to macro tile array */
	uint64_t macro_tile_config_ptr;
	/* to KFD: array size allocated by user mode
	 * from KFD: array size filled by kernel
	 */
	uint32_t num_tile_configs;
	/* to KFD: array size allocated by user mode
	 * from KFD: array size filled by kernel
	 */
	uint32_t num_macro_tile_configs;

	uint32_t gpu_id;	 /* to KFD */
	uint32_t gb_addr_config; /* from KFD */
	uint32_t num_banks;	 /* from KFD */
	uint32_t num_ranks;	 /* from KFD */

	/* struct size can be extended later if needed without breaking ABI compatibility */
};

struct kfd_ioctl_set_trap_handler_args {
	uint64_t tba_addr; /* to KFD */
	uint64_t tma_addr; /* to KFD */
	uint32_t gpu_id;   /* to KFD */
	uint32_t pad;
};

struct kfd_ioctl_acquire_vm_args {
	uint32_t drm_fd; /* to KFD */
	uint32_t gpu_id; /* to KFD */
};

/* Allocation flags: memory types */
#define KFD_IOC_ALLOC_MEM_FLAGS_VRAM	   (1 << 0)
#define KFD_IOC_ALLOC_MEM_FLAGS_GTT	   (1 << 1)
#define KFD_IOC_ALLOC_MEM_FLAGS_USERPTR	   (1 << 2)
#define KFD_IOC_ALLOC_MEM_FLAGS_DOORBELL   (1 << 3)
#define KFD_IOC_ALLOC_MEM_FLAGS_MMIO_REMAP (1 << 4)
/* Allocation flags: attributes/access options */
#define KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE      (1 << 31)
#define KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE    (1 << 30)
#define KFD_IOC_ALLOC_MEM_FLAGS_PUBLIC	      (1 << 29)
#define KFD_IOC_ALLOC_MEM_FLAGS_NO_SUBSTITUTE (1 << 28)
#define KFD_IOC_ALLOC_MEM_FLAGS_AQL_QUEUE_MEM (1 << 27)
#define KFD_IOC_ALLOC_MEM_FLAGS_COHERENT      (1 << 26)
#define KFD_IOC_ALLOC_MEM_FLAGS_UNCACHED      (1 << 25)

/* Allocate memory for later SVM (shared virtual memory) mapping.
 *
 * @va_addr:     virtual address of the memory to be allocated
 *               all later mappings on all GPUs will use this address
 * @size:        size in bytes
 * @handle:      buffer handle returned to user mode, used to refer to
 *               this allocation for mapping, unmapping and freeing
 * @mmap_offset: for CPU-mapping the allocation by mmapping a render node
 *               for userptrs this is overloaded to specify the CPU address
 * @gpu_id:      device identifier
 * @flags:       memory type and attributes. See KFD_IOC_ALLOC_MEM_FLAGS above
 */
struct kfd_ioctl_alloc_memory_of_gpu_args {
	uint64_t va_addr;     /* to KFD */
	uint64_t size;	      /* to KFD */
	uint64_t handle;      /* from KFD */
	uint64_t mmap_offset; /* to KFD (userptr), from KFD (mmap offset) */
	uint32_t gpu_id;      /* to KFD */
	uint32_t flags;
};

/* Free memory allocated with kfd_ioctl_alloc_memory_of_gpu
 *
 * @handle: memory handle returned by alloc
 */
struct kfd_ioctl_free_memory_of_gpu_args {
	uint64_t handle; /* to KFD */
};

/* Map memory to one or more GPUs
 *
 * @handle:                memory handle returned by alloc
 * @device_ids_array_ptr:  array of gpu_ids (uint32_t per device)
 * @n_devices:             number of devices in the array
 * @n_success:             number of devices mapped successfully
 *
 * @n_success returns information to the caller how many devices from
 * the start of the array have mapped the buffer successfully. It can
 * be passed into a subsequent retry call to skip those devices. For
 * the first call the caller should initialize it to 0.
 *
 * If the ioctl completes with return code 0 (success), n_success ==
 * n_devices.
 */
struct kfd_ioctl_map_memory_to_gpu_args {
	uint64_t handle;	       /* to KFD */
	uint64_t device_ids_array_ptr; /* to KFD */
	uint32_t n_devices;	       /* to KFD */
	uint32_t n_success;	       /* to/from KFD */
};

/* Unmap memory from one or more GPUs
 *
 * same arguments as for mapping
 */
struct kfd_ioctl_unmap_memory_from_gpu_args {
	uint64_t handle;	       /* to KFD */
	uint64_t device_ids_array_ptr; /* to KFD */
	uint32_t n_devices;	       /* to KFD */
	uint32_t n_success;	       /* to/from KFD */
};

/* Allocate GWS for specific queue
 *
 * @queue_id:    queue's id that GWS is allocated for
 * @num_gws:     how many GWS to allocate
 * @first_gws:   index of the first GWS allocated.
 *               only support contiguous GWS allocation
 */
struct kfd_ioctl_alloc_queue_gws_args {
	uint32_t queue_id;  /* to KFD */
	uint32_t num_gws;   /* to KFD */
	uint32_t first_gws; /* from KFD */
	uint32_t pad;
};

struct kfd_ioctl_get_dmabuf_info_args {
	uint64_t size;		/* from KFD */
	uint64_t metadata_ptr;	/* to KFD */
	uint32_t metadata_size; /* to KFD (space allocated by user)
			      * from KFD (actual metadata size)
			      */
	uint32_t gpu_id;	/* from KFD */
	uint32_t flags;		/* from KFD (KFD_IOC_ALLOC_MEM_FLAGS) */
	uint32_t dmabuf_fd;	/* to KFD */
};

struct kfd_ioctl_import_dmabuf_args {
	uint64_t va_addr;   /* to KFD */
	uint64_t handle;    /* from KFD */
	uint32_t gpu_id;    /* to KFD */
	uint32_t dmabuf_fd; /* to KFD */
};

/*
 * KFD SMI(System Management Interface) events
 */
enum kfd_smi_event {
	KFD_SMI_EVENT_NONE = 0,	   /* not used */
	KFD_SMI_EVENT_VMFAULT = 1, /* event start counting at 1 */
	KFD_SMI_EVENT_THERMAL_THROTTLE = 2,
	KFD_SMI_EVENT_GPU_PRE_RESET = 3,
	KFD_SMI_EVENT_GPU_POST_RESET = 4,
};

#define KFD_SMI_EVENT_MASK_FROM_INDEX(i) (1ULL << ((i)-1))
#define KFD_SMI_EVENT_MSG_SIZE		 96

struct kfd_ioctl_smi_events_args {
	uint32_t gpuid;	  /* to KFD */
	uint32_t anon_fd; /* from KFD */
};

/**************************************************************************************************
 * CRIU IOCTLs (Checkpoint Restore In Userspace)
 *
 * When checkpointing a process, the userspace application will perform:
 * 1. PROCESS_INFO op to determine current process information. This pauses execution and evicts
 *    all the queues.
 * 2. CHECKPOINT op to checkpoint process contents (BOs, queues, events, svm-ranges)
 * 3. UNPAUSE op to un-evict all the queues
 *
 * When restoring a process, the CRIU userspace application will perform:
 *
 * 1. RESTORE op to restore process contents
 * 2. RESUME op to start the process
 *
 * Note: Queues are forced into an evicted state after a successful PROCESS_INFO. User
 * application needs to perform an UNPAUSE operation after calling PROCESS_INFO.
 */

enum kfd_criu_op {
	KFD_CRIU_OP_PROCESS_INFO,
	KFD_CRIU_OP_CHECKPOINT,
	KFD_CRIU_OP_UNPAUSE,
	KFD_CRIU_OP_RESTORE,
	KFD_CRIU_OP_RESUME,
};

/**
 * kfd_ioctl_criu_args - Arguments perform CRIU operation
 * @devices:		[in/out] User pointer to memory location for devices information.
 * 			This is an array of type kfd_criu_device_bucket.
 * @bos:		[in/out] User pointer to memory location for BOs information
 * 			This is an array of type kfd_criu_bo_bucket.
 * @priv_data:		[in/out] User pointer to memory location for private data
 * @priv_data_size:	[in/out] Size of priv_data in bytes
 * @num_devices:	[in/out] Number of GPUs used by process. Size of @devices array.
 * @num_bos		[in/out] Number of BOs used by process. Size of @bos array.
 * @num_objects:	[in/out] Number of objects used by process. Objects are opaque to user application.
 * @pid:		[in/out] PID of the process being checkpointed
 * @op			[in] Type of operation (kfd_criu_op)
 *
 * Return: 0 on success, -errno on failure
 */
struct kfd_ioctl_criu_args {
	uint64_t devices;	 /* Used during ops: CHECKPOINT, RESTORE */
	uint64_t bos;		 /* Used during ops: CHECKPOINT, RESTORE */
	uint64_t priv_data;	 /* Used during ops: CHECKPOINT, RESTORE */
	uint64_t priv_data_size; /* Used during ops: PROCESS_INFO, RESTORE */
	uint32_t num_devices;	 /* Used during ops: PROCESS_INFO, RESTORE */
	uint32_t num_bos;	 /* Used during ops: PROCESS_INFO, RESTORE */
	uint32_t num_objects;	 /* Used during ops: PROCESS_INFO, RESTORE */
	uint32_t pid;		 /* Used during ops: PROCESS_INFO, RESUME */
	uint32_t op;
};

struct kfd_criu_device_bucket {
	uint32_t user_gpu_id;
	uint32_t actual_gpu_id;
	uint32_t drm_fd;
	uint32_t pad;
};

struct kfd_criu_bo_bucket {
	uint64_t addr;
	uint64_t size;
	uint64_t offset;
	uint64_t restored_offset; /* During restore, updated offset for BO */
	uint32_t gpu_id;	  /* This is the user_gpu_id */
	uint32_t alloc_flags;
	uint32_t dmabuf_fd;
	uint32_t pad;
};

/* CRIU IOCTLs - END */
/**************************************************************************************************/

/* Register offset inside the remapped mmio page
 */
enum kfd_mmio_remap {
	KFD_MMIO_REMAP_HDP_MEM_FLUSH_CNTL = 0,
	KFD_MMIO_REMAP_HDP_REG_FLUSH_CNTL = 4,
};

/* Guarantee host access to memory */
#define KFD_IOCTL_SVM_FLAG_HOST_ACCESS 0x00000001
/* Fine grained coherency between all devices with access */
#define KFD_IOCTL_SVM_FLAG_COHERENT 0x00000002
/* Use any GPU in same hive as preferred device */
#define KFD_IOCTL_SVM_FLAG_HIVE_LOCAL 0x00000004
/* GPUs only read, allows replication */
#define KFD_IOCTL_SVM_FLAG_GPU_RO 0x00000008
/* Allow execution on GPU */
#define KFD_IOCTL_SVM_FLAG_GPU_EXEC 0x00000010
/* GPUs mostly read, may allow similar optimizations as RO, but writes fault */
#define KFD_IOCTL_SVM_FLAG_GPU_READ_MOSTLY 0x00000020

/**
 * kfd_ioctl_svm_op - SVM ioctl operations
 *
 * @KFD_IOCTL_SVM_OP_SET_ATTR: Modify one or more attributes
 * @KFD_IOCTL_SVM_OP_GET_ATTR: Query one or more attributes
 */
enum kfd_ioctl_svm_op { KFD_IOCTL_SVM_OP_SET_ATTR, KFD_IOCTL_SVM_OP_GET_ATTR };

/** kfd_ioctl_svm_location - Enum for preferred and prefetch locations
 *
 * GPU IDs are used to specify GPUs as preferred and prefetch locations.
 * Below definitions are used for system memory or for leaving the preferred
 * location unspecified.
 */
enum kfd_ioctl_svm_location { KFD_IOCTL_SVM_LOCATION_SYSMEM = 0, KFD_IOCTL_SVM_LOCATION_UNDEFINED = 0xffffffff };

/**
 * kfd_ioctl_svm_attr_type - SVM attribute types
 *
 * @KFD_IOCTL_SVM_ATTR_PREFERRED_LOC: gpuid of the preferred location, 0 for
 *                                    system memory
 * @KFD_IOCTL_SVM_ATTR_PREFETCH_LOC: gpuid of the prefetch location, 0 for
 *                                   system memory. Setting this triggers an
 *                                   immediate prefetch (migration).
 * @KFD_IOCTL_SVM_ATTR_ACCESS:
 * @KFD_IOCTL_SVM_ATTR_ACCESS_IN_PLACE:
 * @KFD_IOCTL_SVM_ATTR_NO_ACCESS: specify memory access for the gpuid given
 *                                by the attribute value
 * @KFD_IOCTL_SVM_ATTR_SET_FLAGS: bitmask of flags to set (see
 *                                KFD_IOCTL_SVM_FLAG_...)
 * @KFD_IOCTL_SVM_ATTR_CLR_FLAGS: bitmask of flags to clear
 * @KFD_IOCTL_SVM_ATTR_GRANULARITY: migration granularity
 *                                  (log2 num pages)
 */
enum kfd_ioctl_svm_attr_type {
	KFD_IOCTL_SVM_ATTR_PREFERRED_LOC,
	KFD_IOCTL_SVM_ATTR_PREFETCH_LOC,
	KFD_IOCTL_SVM_ATTR_ACCESS,
	KFD_IOCTL_SVM_ATTR_ACCESS_IN_PLACE,
	KFD_IOCTL_SVM_ATTR_NO_ACCESS,
	KFD_IOCTL_SVM_ATTR_SET_FLAGS,
	KFD_IOCTL_SVM_ATTR_CLR_FLAGS,
	KFD_IOCTL_SVM_ATTR_GRANULARITY
};

/**
 * kfd_ioctl_svm_attribute - Attributes as pairs of type and value
 *
 * The meaning of the @value depends on the attribute type.
 *
 * @type: attribute type (see enum @kfd_ioctl_svm_attr_type)
 * @value: attribute value
 */
struct kfd_ioctl_svm_attribute {
	uint32_t type;
	uint32_t value;
};

/**
 * kfd_ioctl_svm_args - Arguments for SVM ioctl
 *
 * @op specifies the operation to perform (see enum
 * @kfd_ioctl_svm_op).  @start_addr and @size are common for all
 * operations.
 *
 * A variable number of attributes can be given in @attrs.
 * @nattr specifies the number of attributes. New attributes can be
 * added in the future without breaking the ABI. If unknown attributes
 * are given, the function returns -EINVAL.
 *
 * @KFD_IOCTL_SVM_OP_SET_ATTR sets attributes for a virtual address
 * range. It may overlap existing virtual address ranges. If it does,
 * the existing ranges will be split such that the attribute changes
 * only apply to the specified address range.
 *
 * @KFD_IOCTL_SVM_OP_GET_ATTR returns the intersection of attributes
 * over all memory in the given range and returns the result as the
 * attribute value. If different pages have different preferred or
 * prefetch locations, 0xffffffff will be returned for
 * @KFD_IOCTL_SVM_ATTR_PREFERRED_LOC or
 * @KFD_IOCTL_SVM_ATTR_PREFETCH_LOC resepctively. For
 * @KFD_IOCTL_SVM_ATTR_SET_FLAGS, flags of all pages will be
 * aggregated by bitwise AND. That means, a flag will be set in the
 * output, if that flag is set for all pages in the range. For
 * @KFD_IOCTL_SVM_ATTR_CLR_FLAGS, flags of all pages will be
 * aggregated by bitwise NOR. That means, a flag will be set in the
 * output, if that flag is clear for all pages in the range.
 * The minimum migration granularity throughout the range will be
 * returned for @KFD_IOCTL_SVM_ATTR_GRANULARITY.
 *
 * Querying of accessibility attributes works by initializing the
 * attribute type to @KFD_IOCTL_SVM_ATTR_ACCESS and the value to the
 * GPUID being queried. Multiple attributes can be given to allow
 * querying multiple GPUIDs. The ioctl function overwrites the
 * attribute type to indicate the access for the specified GPU.
 */
struct kfd_ioctl_svm_args {
	uint64_t start_addr;
	uint64_t size;
	uint32_t op;
	uint32_t nattr;
	/* Variable length array of attributes */
	struct kfd_ioctl_svm_attribute attrs[0];
};

/**
 * kfd_ioctl_set_xnack_mode_args - Arguments for set_xnack_mode
 *
 * @xnack_enabled:       [in/out] Whether to enable XNACK mode for this process
 *
 * @xnack_enabled indicates whether recoverable page faults should be
 * enabled for the current process. 0 means disabled, positive means
 * enabled, negative means leave unchanged. If enabled, virtual address
 * translations on GFXv9 and later AMD GPUs can return XNACK and retry
 * the access until a valid PTE is available. This is used to implement
 * device page faults.
 *
 * On output, @xnack_enabled returns the (new) current mode (0 or
 * positive). Therefore, a negative input value can be used to query
 * the current mode without changing it.
 *
 * The XNACK mode fundamentally changes the way SVM managed memory works
 * in the driver, with subtle effects on application performance and
 * functionality.
 *
 * Enabling XNACK mode requires shader programs to be compiled
 * differently. Furthermore, not all GPUs support changing the mode
 * per-process. Therefore changing the mode is only allowed while no
 * user mode queues exist in the process. This ensure that no shader
 * code is running that may be compiled for the wrong mode. And GPUs
 * that cannot change to the requested mode will prevent the XNACK
 * mode from occurring. All GPUs used by the process must be in the
 * same XNACK mode.
 *
 * GFXv8 or older GPUs do not support 48 bit virtual addresses or SVM.
 * Therefore those GPUs are not considered for the XNACK mode switch.
 *
 * Return: 0 on success, -errno on failure
 */
struct kfd_ioctl_set_xnack_mode_args {
	__s32 xnack_enabled;
};

#define AMDKFD_IOCTL_BASE     'K'
#define AMDKFD_IO(nr)	      _IO(AMDKFD_IOCTL_BASE, nr)
#define AMDKFD_IOR(nr, type)  _IOR(AMDKFD_IOCTL_BASE, nr, type)
#define AMDKFD_IOW(nr, type)  _IOW(AMDKFD_IOCTL_BASE, nr, type)
#define AMDKFD_IOWR(nr, type) _IOWR(AMDKFD_IOCTL_BASE, nr, type)

#define AMDKFD_IOC_GET_VERSION AMDKFD_IOR(0x01, struct kfd_ioctl_get_version_args)

#define AMDKFD_IOC_CREATE_QUEUE AMDKFD_IOWR(0x02, struct kfd_ioctl_create_queue_args)

#define AMDKFD_IOC_DESTROY_QUEUE AMDKFD_IOWR(0x03, struct kfd_ioctl_destroy_queue_args)

#define AMDKFD_IOC_SET_MEMORY_POLICY AMDKFD_IOW(0x04, struct kfd_ioctl_set_memory_policy_args)

#define AMDKFD_IOC_GET_CLOCK_COUNTERS AMDKFD_IOWR(0x05, struct kfd_ioctl_get_clock_counters_args)

#define AMDKFD_IOC_GET_PROCESS_APERTURES AMDKFD_IOR(0x06, struct kfd_ioctl_get_process_apertures_args)

#define AMDKFD_IOC_UPDATE_QUEUE AMDKFD_IOW(0x07, struct kfd_ioctl_update_queue_args)

#define AMDKFD_IOC_CREATE_EVENT AMDKFD_IOWR(0x08, struct kfd_ioctl_create_event_args)

#define AMDKFD_IOC_DESTROY_EVENT AMDKFD_IOW(0x09, struct kfd_ioctl_destroy_event_args)

#define AMDKFD_IOC_SET_EVENT AMDKFD_IOW(0x0A, struct kfd_ioctl_set_event_args)

#define AMDKFD_IOC_RESET_EVENT AMDKFD_IOW(0x0B, struct kfd_ioctl_reset_event_args)

#define AMDKFD_IOC_WAIT_EVENTS AMDKFD_IOWR(0x0C, struct kfd_ioctl_wait_events_args)

#define AMDKFD_IOC_DBG_REGISTER_DEPRECATED AMDKFD_IOW(0x0D, struct kfd_ioctl_dbg_register_args)

#define AMDKFD_IOC_DBG_UNREGISTER_DEPRECATED AMDKFD_IOW(0x0E, struct kfd_ioctl_dbg_unregister_args)

#define AMDKFD_IOC_DBG_ADDRESS_WATCH_DEPRECATED AMDKFD_IOW(0x0F, struct kfd_ioctl_dbg_address_watch_args)

#define AMDKFD_IOC_DBG_WAVE_CONTROL_DEPRECATED AMDKFD_IOW(0x10, struct kfd_ioctl_dbg_wave_control_args)

#define AMDKFD_IOC_SET_SCRATCH_BACKING_VA AMDKFD_IOWR(0x11, struct kfd_ioctl_set_scratch_backing_va_args)

#define AMDKFD_IOC_GET_TILE_CONFIG AMDKFD_IOWR(0x12, struct kfd_ioctl_get_tile_config_args)

#define AMDKFD_IOC_SET_TRAP_HANDLER AMDKFD_IOW(0x13, struct kfd_ioctl_set_trap_handler_args)

#define AMDKFD_IOC_GET_PROCESS_APERTURES_NEW AMDKFD_IOWR(0x14, struct kfd_ioctl_get_process_apertures_new_args)

#define AMDKFD_IOC_ACQUIRE_VM AMDKFD_IOW(0x15, struct kfd_ioctl_acquire_vm_args)

#define AMDKFD_IOC_ALLOC_MEMORY_OF_GPU AMDKFD_IOWR(0x16, struct kfd_ioctl_alloc_memory_of_gpu_args)

#define AMDKFD_IOC_FREE_MEMORY_OF_GPU AMDKFD_IOW(0x17, struct kfd_ioctl_free_memory_of_gpu_args)

#define AMDKFD_IOC_MAP_MEMORY_TO_GPU AMDKFD_IOWR(0x18, struct kfd_ioctl_map_memory_to_gpu_args)

#define AMDKFD_IOC_UNMAP_MEMORY_FROM_GPU AMDKFD_IOWR(0x19, struct kfd_ioctl_unmap_memory_from_gpu_args)

#define AMDKFD_IOC_SET_CU_MASK AMDKFD_IOW(0x1A, struct kfd_ioctl_set_cu_mask_args)

#define AMDKFD_IOC_GET_QUEUE_WAVE_STATE AMDKFD_IOWR(0x1B, struct kfd_ioctl_get_queue_wave_state_args)

#define AMDKFD_IOC_GET_DMABUF_INFO AMDKFD_IOWR(0x1C, struct kfd_ioctl_get_dmabuf_info_args)

#define AMDKFD_IOC_IMPORT_DMABUF AMDKFD_IOWR(0x1D, struct kfd_ioctl_import_dmabuf_args)

#define AMDKFD_IOC_ALLOC_QUEUE_GWS AMDKFD_IOWR(0x1E, struct kfd_ioctl_alloc_queue_gws_args)

#define AMDKFD_IOC_SMI_EVENTS AMDKFD_IOWR(0x1F, struct kfd_ioctl_smi_events_args)

#define AMDKFD_IOC_SVM AMDKFD_IOWR(0x20, struct kfd_ioctl_svm_args)

#define AMDKFD_IOC_SET_XNACK_MODE AMDKFD_IOWR(0x21, struct kfd_ioctl_set_xnack_mode_args)

#define AMDKFD_IOC_CRIU_OP AMDKFD_IOWR(0x22, struct kfd_ioctl_criu_args)

#define AMDKFD_COMMAND_START 0x01
#define AMDKFD_COMMAND_END   0x23

#endif
