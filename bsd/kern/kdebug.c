/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
 *
 * @Apple_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc_internal.h>
#include <sys/vm.h>
#include <sys/sysctl.h>
#include <sys/kdebug.h>
#include <sys/kauth.h>
#include <sys/ktrace.h>
#include <sys/sysproto.h>
#include <sys/bsdtask_info.h>
#include <sys/random.h>

#include <mach/clock_types.h>
#include <mach/mach_types.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <machine/atomic.h>
#include <machine/machine_routines.h>

#include <mach/machine.h>
#include <mach/vm_map.h>

#if defined(__i386__) || defined(__x86_64__)
#include <i386/rtclock_protos.h>
#include <i386/mp.h>
#include <i386/machine_routines.h>
#include <i386/tsc.h>
#endif

#include <kern/clock.h>

#include <kern/thread.h>
#include <kern/task.h>
#include <kern/debug.h>
#include <kern/kalloc.h>
#include <kern/cpu_data.h>
#include <kern/assert.h>
#include <kern/telemetry.h>
#include <kern/sched_prim.h>
#include <vm/vm_kern.h>
#include <sys/lock.h>
#include <kperf/kperf.h>
#include <pexpert/device_tree.h>

#include <sys/malloc.h>
#include <sys/mcache.h>

#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/fcntl.h>
#include <sys/file_internal.h>
#include <sys/ubc.h>
#include <sys/param.h>                  /* for isset() */

#include <mach/mach_host.h>             /* for host_info() */
#include <libkern/OSAtomic.h>

#include <machine/pal_routines.h>
#include <machine/atomic.h>

/*
 * IOP(s)
 *
 * https://coreoswiki.apple.com/wiki/pages/U6z3i0q9/Consistent_Logging_Implementers_Guide.html
 *
 * IOP(s) are auxiliary cores that want to participate in kdebug event logging.
 * They are registered dynamically. Each is assigned a cpu_id at registration.
 *
 * NOTE: IOP trace events may not use the same clock hardware as "normal"
 * cpus. There is an effort made to synchronize the IOP timebase with the
 * AP, but it should be understood that there may be discrepancies.
 *
 * Once registered, an IOP is permanent, it cannot be unloaded/unregistered.
 * The current implementation depends on this for thread safety.
 *
 * New registrations occur by allocating an kd_iop struct and assigning
 * a provisional cpu_id of list_head->cpu_id + 1. Then a CAS to claim the
 * list_head pointer resolves any races.
 *
 * You may safely walk the kd_iops list at any time, without holding locks.
 *
 * When allocating buffers, the current kd_iops head is captured. Any operations
 * that depend on the buffer state (such as flushing IOP traces on reads,
 * etc.) should use the captured list head. This will allow registrations to
 * take place while trace is in use.
 */

typedef struct kd_iop {
	kd_callback_t   callback;
	uint32_t        cpu_id;
	uint64_t        last_timestamp; /* Prevent timer rollback */
	struct kd_iop*  next;
} kd_iop_t;

static kd_iop_t* kd_iops = NULL;

/*
 * Typefilter(s)
 *
 * A typefilter is a 8KB bitmap that is used to selectively filter events
 * being recorded. It is able to individually address every class & subclass.
 *
 * There is a shared typefilter in the kernel which is lazily allocated. Once
 * allocated, the shared typefilter is never deallocated. The shared typefilter
 * is also mapped on demand into userspace processes that invoke kdebug_trace
 * API from Libsyscall. When mapped into a userspace process, the memory is
 * read only, and does not have a fixed address.
 *
 * It is a requirement that the kernel's shared typefilter always pass DBG_TRACE
 * events. This is enforced automatically, by having the needed bits set any
 * time the shared typefilter is mutated.
 */

typedef uint8_t* typefilter_t;

static typefilter_t kdbg_typefilter;
static mach_port_t  kdbg_typefilter_memory_entry;

/*
 * There are 3 combinations of page sizes:
 *
 *  4KB /  4KB
 *  4KB / 16KB
 * 16KB / 16KB
 *
 * The typefilter is exactly 8KB. In the first two scenarios, we would like
 * to use 2 pages exactly; in the third scenario we must make certain that
 * a full page is allocated so we do not inadvertantly share 8KB of random
 * data to userspace. The round_page_32 macro rounds to kernel page size.
 */
#define TYPEFILTER_ALLOC_SIZE MAX(round_page_32(KDBG_TYPEFILTER_BITMAP_SIZE), KDBG_TYPEFILTER_BITMAP_SIZE)

static typefilter_t
typefilter_create(void)
{
	typefilter_t tf;
	if (KERN_SUCCESS == kmem_alloc(kernel_map, (vm_offset_t*)&tf, TYPEFILTER_ALLOC_SIZE, VM_KERN_MEMORY_DIAG)) {
		memset(&tf[KDBG_TYPEFILTER_BITMAP_SIZE], 0, TYPEFILTER_ALLOC_SIZE - KDBG_TYPEFILTER_BITMAP_SIZE);
		return tf;
	}
	return NULL;
}

static void
typefilter_deallocate(typefilter_t tf)
{
	assert(tf != NULL);
	assert(tf != kdbg_typefilter);
	kmem_free(kernel_map, (vm_offset_t)tf, TYPEFILTER_ALLOC_SIZE);
}

static void
typefilter_copy(typefilter_t dst, typefilter_t src)
{
	assert(src != NULL);
	assert(dst != NULL);
	memcpy(dst, src, KDBG_TYPEFILTER_BITMAP_SIZE);
}

static void
typefilter_reject_all(typefilter_t tf)
{
	assert(tf != NULL);
	memset(tf, 0, KDBG_TYPEFILTER_BITMAP_SIZE);
}

static void
typefilter_allow_all(typefilter_t tf)
{
	assert(tf != NULL);
	memset(tf, ~0, KDBG_TYPEFILTER_BITMAP_SIZE);
}

static void
typefilter_allow_class(typefilter_t tf, uint8_t class)
{
	assert(tf != NULL);
	const uint32_t BYTES_PER_CLASS = 256 / 8; // 256 subclasses, 1 bit each
	memset(&tf[class * BYTES_PER_CLASS], 0xFF, BYTES_PER_CLASS);
}

static void
typefilter_allow_csc(typefilter_t tf, uint16_t csc)
{
	assert(tf != NULL);
	setbit(tf, csc);
}

static bool
typefilter_is_debugid_allowed(typefilter_t tf, uint32_t id)
{
	assert(tf != NULL);
	return isset(tf, KDBG_EXTRACT_CSC(id));
}

static mach_port_t
typefilter_create_memory_entry(typefilter_t tf)
{
	assert(tf != NULL);

	mach_port_t memory_entry = MACH_PORT_NULL;
	memory_object_size_t size = TYPEFILTER_ALLOC_SIZE;

	mach_make_memory_entry_64(kernel_map,
	    &size,
	    (memory_object_offset_t)tf,
	    VM_PROT_READ,
	    &memory_entry,
	    MACH_PORT_NULL);

	return memory_entry;
}

static int  kdbg_copyin_typefilter(user_addr_t addr, size_t size);
static void kdbg_enable_typefilter(void);
static void kdbg_disable_typefilter(void);

/*
 * External prototypes
 */

void task_act_iterate_wth_args(task_t, void (*)(thread_t, void *), void *);
int cpu_number(void);   /* XXX <machine/...> include path broken */
void commpage_update_kdebug_state(void); /* XXX sign */

extern int log_leaks;

/*
 * This flag is for testing purposes only -- it's highly experimental and tools
 * have not been updated to support it.
 */
static bool kdbg_continuous_time = false;

static inline uint64_t
kdbg_timestamp(void)
{
	if (kdbg_continuous_time) {
		return mach_continuous_time();
	} else {
		return mach_absolute_time();
	}
}

static int kdbg_debug = 0;

#if KDEBUG_MOJO_TRACE
#include <sys/kdebugevents.h>
static void kdebug_serial_print( /* forward */
	uint32_t, uint32_t, uint64_t,
	uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
#endif

int kdbg_control(int *, u_int, user_addr_t, size_t *);

static int kdbg_read(user_addr_t, size_t *, vnode_t, vfs_context_t, uint32_t);
static int kdbg_readcpumap(user_addr_t, size_t *);
static int kdbg_readthrmap_v3(user_addr_t, size_t, int);
static int kdbg_readcurthrmap(user_addr_t, size_t *);
static int kdbg_setreg(kd_regtype *);
static int kdbg_setpidex(kd_regtype *);
static int kdbg_setpid(kd_regtype *);
static void kdbg_thrmap_init(void);
static int kdbg_reinit(bool);
static int kdbg_bootstrap(bool);
static int kdbg_test(size_t flavor);

static int kdbg_write_v1_header(bool write_thread_map, vnode_t vp, vfs_context_t ctx);
static int kdbg_write_thread_map(vnode_t vp, vfs_context_t ctx);
static int kdbg_copyout_thread_map(user_addr_t buffer, size_t *buffer_size);
static void kdbg_clear_thread_map(void);

static bool kdbg_wait(uint64_t timeout_ms, bool locked_wait);
static void kdbg_wakeup(void);

int kdbg_cpumap_init_internal(kd_iop_t* iops, uint32_t cpu_count,
    uint8_t** cpumap, uint32_t* cpumap_size);

static kd_threadmap *kdbg_thrmap_init_internal(unsigned int count,
    unsigned int *mapsize,
    unsigned int *mapcount);

static bool kdebug_current_proc_enabled(uint32_t debugid);
static errno_t kdebug_check_trace_string(uint32_t debugid, uint64_t str_id);

int kdbg_write_v3_header(user_addr_t, size_t *, int);
int kdbg_write_v3_chunk_header(user_addr_t buffer, uint32_t tag,
    uint32_t sub_tag, uint64_t length,
    vnode_t vp, vfs_context_t ctx);

user_addr_t kdbg_write_v3_event_chunk_header(user_addr_t buffer, uint32_t tag,
    uint64_t length, vnode_t vp,
    vfs_context_t ctx);

// Helper functions

static int create_buffers(bool);
static void delete_buffers(void);

extern int tasks_count;
extern int threads_count;
extern void IOSleep(int);

/* trace enable status */
unsigned int kdebug_enable = 0;

/* A static buffer to record events prior to the start of regular logging */

#define KD_EARLY_BUFFER_SIZE (16 * 1024)
#define KD_EARLY_BUFFER_NBUFS (KD_EARLY_BUFFER_SIZE / sizeof(kd_buf))
#if CONFIG_EMBEDDED
/*
 * On embedded, the space for this is carved out by osfmk/arm/data.s -- clang
 * has problems aligning to greater than 4K.
 */
extern kd_buf kd_early_buffer[KD_EARLY_BUFFER_NBUFS];
#else /* CONFIG_EMBEDDED */
__attribute__((aligned(KD_EARLY_BUFFER_SIZE)))
static kd_buf kd_early_buffer[KD_EARLY_BUFFER_NBUFS];
#endif /* !CONFIG_EMBEDDED */

static unsigned int kd_early_index = 0;
static bool kd_early_overflow = false;
static bool kd_early_done = false;

#define SLOW_NOLOG  0x01
#define SLOW_CHECKS 0x02

#define EVENTS_PER_STORAGE_UNIT         2048
#define MIN_STORAGE_UNITS_PER_CPU       4

#define POINTER_FROM_KDS_PTR(x) (&kd_bufs[x.buffer_index].kdsb_addr[x.offset])

union kds_ptr {
	struct {
		uint32_t buffer_index:21;
		uint16_t offset:11;
	};
	uint32_t raw;
};

struct kd_storage {
	union   kds_ptr kds_next;
	uint32_t kds_bufindx;
	uint32_t kds_bufcnt;
	uint32_t kds_readlast;
	bool kds_lostevents;
	uint64_t  kds_timestamp;

	kd_buf  kds_records[EVENTS_PER_STORAGE_UNIT];
};

#define MAX_BUFFER_SIZE            (1024 * 1024 * 128)
#define N_STORAGE_UNITS_PER_BUFFER (MAX_BUFFER_SIZE / sizeof(struct kd_storage))
static_assert(N_STORAGE_UNITS_PER_BUFFER <= 0x7ff,
    "shoudn't overflow kds_ptr.offset");

struct kd_storage_buffers {
	struct  kd_storage      *kdsb_addr;
	uint32_t                kdsb_size;
};

#define KDS_PTR_NULL 0xffffffff
struct kd_storage_buffers *kd_bufs = NULL;
int n_storage_units = 0;
unsigned int n_storage_buffers = 0;
int n_storage_threshold = 0;
int kds_waiter = 0;

#pragma pack(0)
struct kd_bufinfo {
	union  kds_ptr kd_list_head;
	union  kds_ptr kd_list_tail;
	bool kd_lostevents;
	uint32_t _pad;
	uint64_t kd_prev_timebase;
	uint32_t num_bufs;
} __attribute__((aligned(MAX_CPU_CACHE_LINE_SIZE)));


/*
 * In principle, this control block can be shared in DRAM with other
 * coprocessors and runtimes, for configuring what tracing is enabled.
 */
struct kd_ctrl_page_t {
	union kds_ptr kds_free_list;
	uint32_t enabled        :1;
	uint32_t _pad0          :31;
	int                     kds_inuse_count;
	uint32_t kdebug_flags;
	uint32_t kdebug_slowcheck;
	uint64_t oldest_time;
	/*
	 * The number of kd_bufinfo structs allocated may not match the current
	 * number of active cpus. We capture the iops list head at initialization
	 * which we could use to calculate the number of cpus we allocated data for,
	 * unless it happens to be null. To avoid that case, we explicitly also
	 * capture a cpu count.
	 */
	kd_iop_t* kdebug_iops;
	uint32_t kdebug_cpus;
} kd_ctrl_page = {
	.kds_free_list = {.raw = KDS_PTR_NULL},
	.kdebug_slowcheck = SLOW_NOLOG,
	.oldest_time = 0
};

#pragma pack()

struct kd_bufinfo *kdbip = NULL;

#define KDCOPYBUF_COUNT 8192
#define KDCOPYBUF_SIZE  (KDCOPYBUF_COUNT * sizeof(kd_buf))

#define PAGE_4KB        4096
#define PAGE_16KB       16384

kd_buf *kdcopybuf = NULL;

unsigned int nkdbufs = 0;
unsigned int kdlog_beg = 0;
unsigned int kdlog_end = 0;
unsigned int kdlog_value1 = 0;
unsigned int kdlog_value2 = 0;
unsigned int kdlog_value3 = 0;
unsigned int kdlog_value4 = 0;

static lck_spin_t * kdw_spin_lock;
static lck_spin_t * kds_spin_lock;

kd_threadmap *kd_mapptr = 0;
unsigned int kd_mapsize = 0;
unsigned int kd_mapcount = 0;

off_t   RAW_file_offset = 0;
int     RAW_file_written = 0;

#define RAW_FLUSH_SIZE  (2 * 1024 * 1024)

/*
 * A globally increasing counter for identifying strings in trace.  Starts at
 * 1 because 0 is a reserved return value.
 */
__attribute__((aligned(MAX_CPU_CACHE_LINE_SIZE)))
static uint64_t g_curr_str_id = 1;

#define STR_ID_SIG_OFFSET (48)
#define STR_ID_MASK       ((1ULL << STR_ID_SIG_OFFSET) - 1)
#define STR_ID_SIG_MASK   (~STR_ID_MASK)

/*
 * A bit pattern for identifying string IDs generated by
 * kdebug_trace_string(2).
 */
static uint64_t g_str_id_signature = (0x70acULL << STR_ID_SIG_OFFSET);

#define INTERRUPT       0x01050000
#define MACH_vmfault    0x01300008
#define BSC_SysCall     0x040c0000
#define MACH_SysCall    0x010c0000

/* task to string structure */
struct tts {
	task_t    task;      /* from procs task */
	pid_t     pid;       /* from procs p_pid  */
	char      task_comm[20];/* from procs p_comm */
};

typedef struct tts tts_t;

struct krt {
	kd_threadmap *map;    /* pointer to the map buffer */
	int count;
	int maxcount;
	struct tts *atts;
};

/*
 * TRACE file formats...
 *
 * RAW_VERSION0
 *
 * uint32_t #threadmaps
 * kd_threadmap[]
 * kd_buf[]
 *
 * RAW_VERSION1
 *
 * RAW_header, with version_no set to RAW_VERSION1
 * kd_threadmap[]
 * Empty space to pad alignment to the nearest page boundary.
 * kd_buf[]
 *
 * RAW_VERSION1+
 *
 * RAW_header, with version_no set to RAW_VERSION1
 * kd_threadmap[]
 * kd_cpumap_header, with version_no set to RAW_VERSION1
 * kd_cpumap[]
 * Empty space to pad alignment to the nearest page boundary.
 * kd_buf[]
 *
 * V1+ implementation details...
 *
 * It would have been nice to add the cpumap data "correctly", but there were
 * several obstacles. Existing code attempts to parse both V1 and V0 files.
 * Due to the fact that V0 has no versioning or header, the test looks like
 * this:
 *
 * // Read header
 * if (header.version_no != RAW_VERSION1) { // Assume V0 }
 *
 * If we add a VERSION2 file format, all existing code is going to treat that
 * as a VERSION0 file when reading it, and crash terribly when trying to read
 * RAW_VERSION2 threadmap entries.
 *
 * To differentiate between a V1 and V1+ file, read as V1 until you reach
 * the padding bytes. Then:
 *
 * boolean_t is_v1plus = FALSE;
 * if (padding_bytes >= sizeof(kd_cpumap_header)) {
 *     kd_cpumap_header header = // read header;
 *     if (header.version_no == RAW_VERSION1) {
 *         is_v1plus = TRUE;
 *     }
 * }
 *
 */

#define RAW_VERSION3    0x00001000

// Version 3 header
// The header chunk has the tag 0x00001000 which also serves as a magic word
// that identifies the file as a version 3 trace file. The header payload is
// a set of fixed fields followed by a variable number of sub-chunks:
/*
 *  ____________________________________________________________________________
 | Offset | Size | Field                                                    |
 |  ----------------------------------------------------------------------------
 |    0   |  4   | Tag (0x00001000)                                         |
 |    4   |  4   | Sub-tag. Represents the version of the header.           |
 |    8   |  8   | Length of header payload (40+8x)                         |
 |   16   |  8   | Time base info. Two 32-bit numbers, numer/denom,         |
 |        |      | for converting timestamps to nanoseconds.                |
 |   24   |  8   | Timestamp of trace start.                                |
 |   32   |  8   | Wall time seconds since Unix epoch.                      |
 |        |      | As returned by gettimeofday().                           |
 |   40   |  4   | Wall time microseconds. As returned by gettimeofday().   |
 |   44   |  4   | Local time zone offset in minutes. ( " )                 |
 |   48   |  4   | Type of daylight savings time correction to apply. ( " ) |
 |   52   |  4   | Flags. 1 = 64-bit. Remaining bits should be written      |
 |        |      | as 0 and ignored when reading.                           |
 |   56   |  8x  | Variable number of sub-chunks. None are required.        |
 |        |      | Ignore unknown chunks.                                   |
 |  ----------------------------------------------------------------------------
 */
// NOTE: The header sub-chunks are considered part of the header chunk,
// so they must be included in the header chunk’s length field.
// The CPU map is an optional sub-chunk of the header chunk. It provides
// information about the CPUs that are referenced from the trace events.
typedef struct {
	uint32_t tag;
	uint32_t sub_tag;
	uint64_t length;
	uint32_t timebase_numer;
	uint32_t timebase_denom;
	uint64_t timestamp;
	uint64_t walltime_secs;
	uint32_t walltime_usecs;
	uint32_t timezone_minuteswest;
	uint32_t timezone_dst;
	uint32_t flags;
} __attribute__((packed)) kd_header_v3;

typedef struct {
	uint32_t tag;
	uint32_t sub_tag;
	uint64_t length;
} __attribute__((packed)) kd_chunk_header_v3;

#define V3_CONFIG       0x00001b00
#define V3_CPU_MAP      0x00001c00
#define V3_THREAD_MAP   0x00001d00
#define V3_RAW_EVENTS   0x00001e00
#define V3_NULL_CHUNK   0x00002000

// The current version of all kernel managed chunks is 1. The
// V3_CURRENT_CHUNK_VERSION is added to ease the simple case
// when most/all the kernel managed chunks have the same version.

#define V3_CURRENT_CHUNK_VERSION 1
#define V3_HEADER_VERSION     V3_CURRENT_CHUNK_VERSION
#define V3_CPUMAP_VERSION     V3_CURRENT_CHUNK_VERSION
#define V3_THRMAP_VERSION     V3_CURRENT_CHUNK_VERSION
#define V3_EVENT_DATA_VERSION V3_CURRENT_CHUNK_VERSION

typedef struct krt krt_t;

static uint32_t
kdbg_cpu_count(bool early_trace)
{
	if (early_trace) {
#if CONFIG_EMBEDDED
		return ml_get_cpu_count();
#else
		return max_ncpus;
#endif
	}

	host_basic_info_data_t hinfo;
	mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
	host_info((host_t)1 /* BSD_HOST */, HOST_BASIC_INFO, (host_info_t)&hinfo, &count);
	assert(hinfo.logical_cpu_max > 0);
	return hinfo.logical_cpu_max;
}

#if MACH_ASSERT
#if CONFIG_EMBEDDED
static bool
kdbg_iop_list_is_valid(kd_iop_t* iop)
{
	if (iop) {
		/* Is list sorted by cpu_id? */
		kd_iop_t* temp = iop;
		do {
			assert(!temp->next || temp->next->cpu_id == temp->cpu_id - 1);
			assert(temp->next || (temp->cpu_id == kdbg_cpu_count(false) || temp->cpu_id == kdbg_cpu_count(true)));
		} while ((temp = temp->next));

		/* Does each entry have a function and a name? */
		temp = iop;
		do {
			assert(temp->callback.func);
			assert(strlen(temp->callback.iop_name) < sizeof(temp->callback.iop_name));
		} while ((temp = temp->next));
	}

	return true;
}

static bool
kdbg_iop_list_contains_cpu_id(kd_iop_t* list, uint32_t cpu_id)
{
	while (list) {
		if (list->cpu_id == cpu_id) {
			return true;
		}
		list = list->next;
	}

	return false;
}
#endif /* CONFIG_EMBEDDED */
#endif /* MACH_ASSERT */

static void
kdbg_iop_list_callback(kd_iop_t* iop, kd_callback_type type, void* arg)
{
	while (iop) {
		iop->callback.func(iop->callback.context, type, arg);
		iop = iop->next;
	}
}

static lck_grp_t *kdebug_lck_grp = NULL;

static void
kdbg_set_tracing_enabled(bool enabled, uint32_t trace_type)
{
	/*
	 * Drain any events from IOPs before making the state change.  On
	 * enabling, this removes any stale events from before tracing.  On
	 * disabling, this saves any events up to the point tracing is disabled.
	 */
	kdbg_iop_list_callback(kd_ctrl_page.kdebug_iops, KD_CALLBACK_SYNC_FLUSH,
	    NULL);

	int s = ml_set_interrupts_enabled(false);
	lck_spin_lock_grp(kds_spin_lock, kdebug_lck_grp);

	if (enabled) {
		/*
		 * The oldest valid time is now; reject past events from IOPs.
		 */
		kd_ctrl_page.oldest_time = kdbg_timestamp();
		kdebug_enable |= trace_type;
		kd_ctrl_page.kdebug_slowcheck &= ~SLOW_NOLOG;
		kd_ctrl_page.enabled = 1;
		commpage_update_kdebug_state();
	} else {
		kdebug_enable &= ~(KDEBUG_ENABLE_TRACE | KDEBUG_ENABLE_PPT);
		kd_ctrl_page.kdebug_slowcheck |= SLOW_NOLOG;
		kd_ctrl_page.enabled = 0;
		commpage_update_kdebug_state();
	}
	lck_spin_unlock(kds_spin_lock);
	ml_set_interrupts_enabled(s);

	if (enabled) {
		kdbg_iop_list_callback(kd_ctrl_page.kdebug_iops,
		    KD_CALLBACK_KDEBUG_ENABLED, NULL);
	} else {
		kdbg_iop_list_callback(kd_ctrl_page.kdebug_iops,
		    KD_CALLBACK_KDEBUG_DISABLED, NULL);
	}
}

static void
kdbg_set_flags(int slowflag, int enableflag, bool enabled)
{
	int s = ml_set_interrupts_enabled(false);
	lck_spin_lock_grp(kds_spin_lock, kdebug_lck_grp);

	if (enabled) {
		kd_ctrl_page.kdebug_slowcheck |= slowflag;
		kdebug_enable |= enableflag;
	} else {
		kd_ctrl_page.kdebug_slowcheck &= ~slowflag;
		kdebug_enable &= ~enableflag;
	}

	lck_spin_unlock(kds_spin_lock);
	ml_set_interrupts_enabled(s);
}

/*
 * Disable wrapping and return true if trace wrapped, false otherwise.
 */
static bool
disable_wrap(uint32_t *old_slowcheck, uint32_t *old_flags)
{
	bool wrapped;
	int s = ml_set_interrupts_enabled(false);
	lck_spin_lock_grp(kds_spin_lock, kdebug_lck_grp);

	*old_slowcheck = kd_ctrl_page.kdebug_slowcheck;
	*old_flags = kd_ctrl_page.kdebug_flags;

	wrapped = kd_ctrl_page.kdebug_flags & KDBG_WRAPPED;
	kd_ctrl_page.kdebug_flags &= ~KDBG_WRAPPED;
	kd_ctrl_page.kdebug_flags |= KDBG_NOWRAP;

	lck_spin_unlock(kds_spin_lock);
	ml_set_interrupts_enabled(s);

	return wrapped;
}

static void
enable_wrap(uint32_t old_slowcheck)
{
	int s = ml_set_interrupts_enabled(false);
	lck_spin_lock_grp(kds_spin_lock, kdebug_lck_grp);

	kd_ctrl_page.kdebug_flags &= ~KDBG_NOWRAP;

	if (!(old_slowcheck & SLOW_NOLOG)) {
		kd_ctrl_page.kdebug_slowcheck &= ~SLOW_NOLOG;
	}

	lck_spin_unlock(kds_spin_lock);
	ml_set_interrupts_enabled(s);
}

static int
create_buffers(bool early_trace)
{
	unsigned int i;
	unsigned int p_buffer_size;
	unsigned int f_buffer_size;
	unsigned int f_buffers;
	int error = 0;

	/*
	 * For the duration of this allocation, trace code will only reference
	 * kdebug_iops. Any iops registered after this enabling will not be
	 * messaged until the buffers are reallocated.
	 *
	 * TLDR; Must read kd_iops once and only once!
	 */
	kd_ctrl_page.kdebug_iops = kd_iops;

#if CONFIG_EMBEDDED
	assert(kdbg_iop_list_is_valid(kd_ctrl_page.kdebug_iops));
#endif

	/*
	 * If the list is valid, it is sorted, newest -> oldest. Each iop entry
	 * has a cpu_id of "the older entry + 1", so the highest cpu_id will
	 * be the list head + 1.
	 */

	kd_ctrl_page.kdebug_cpus = kd_ctrl_page.kdebug_iops ? kd_ctrl_page.kdebug_iops->cpu_id + 1 : kdbg_cpu_count(early_trace);

	if (kmem_alloc(kernel_map, (vm_offset_t *)&kdbip, sizeof(struct kd_bufinfo) * kd_ctrl_page.kdebug_cpus, VM_KERN_MEMORY_DIAG) != KERN_SUCCESS) {
		error = ENOSPC;
		goto out;
	}

	if (nkdbufs < (kd_ctrl_page.kdebug_cpus * EVENTS_PER_STORAGE_UNIT * MIN_STORAGE_UNITS_PER_CPU)) {
		n_storage_units = kd_ctrl_page.kdebug_cpus * MIN_STORAGE_UNITS_PER_CPU;
	} else {
		n_storage_units = nkdbufs / EVENTS_PER_STORAGE_UNIT;
	}

	nkdbufs = n_storage_units * EVENTS_PER_STORAGE_UNIT;

	f_buffers = n_storage_units / N_STORAGE_UNITS_PER_BUFFER;
	n_storage_buffers = f_buffers;

	f_buffer_size = N_STORAGE_UNITS_PER_BUFFER * sizeof(struct kd_storage);
	p_buffer_size = (n_storage_units % N_STORAGE_UNITS_PER_BUFFER) * sizeof(struct kd_storage);

	if (p_buffer_size) {
		n_storage_buffers++;
	}

	kd_bufs = NULL;

	if (kdcopybuf == 0) {
		if (kmem_alloc(kernel_map, (vm_offset_t *)&kdcopybuf, (vm_size_t)KDCOPYBUF_SIZE, VM_KERN_MEMORY_DIAG) != KERN_SUCCESS) {
			error = ENOSPC;
			goto out;
		}
	}
	if (kmem_alloc(kernel_map, (vm_offset_t *)&kd_bufs, (vm_size_t)(n_storage_buffers * sizeof(struct kd_storage_buffers)), VM_KERN_MEMORY_DIAG) != KERN_SUCCESS) {
		error = ENOSPC;
		goto out;
	}
	bzero(kd_bufs, n_storage_buffers * sizeof(struct kd_storage_buffers));

	for (i = 0; i < f_buffers; i++) {
		if (kmem_alloc(kernel_map, (vm_offset_t *)&kd_bufs[i].kdsb_addr, (vm_size_t)f_buffer_size, VM_KERN_MEMORY_DIAG) != KERN_SUCCESS) {
			error = ENOSPC;
			goto out;
		}
		bzero(kd_bufs[i].kdsb_addr, f_buffer_size);

		kd_bufs[i].kdsb_size = f_buffer_size;
	}
	if (p_buffer_size) {
		if (kmem_alloc(kernel_map, (vm_offset_t *)&kd_bufs[i].kdsb_addr, (vm_size_t)p_buffer_size, VM_KERN_MEMORY_DIAG) != KERN_SUCCESS) {
			error = ENOSPC;
			goto out;
		}
		bzero(kd_bufs[i].kdsb_addr, p_buffer_size);

		kd_bufs[i].kdsb_size = p_buffer_size;
	}
	n_storage_units = 0;

	for (i = 0; i < n_storage_buffers; i++) {
		struct kd_storage *kds;
		int     n_elements;
		int     n;

		n_elements = kd_bufs[i].kdsb_size / sizeof(struct kd_storage);
		kds = kd_bufs[i].kdsb_addr;

		for (n = 0; n < n_elements; n++) {
			kds[n].kds_next.buffer_index = kd_ctrl_page.kds_free_list.buffer_index;
			kds[n].kds_next.offset = kd_ctrl_page.kds_free_list.offset;

			kd_ctrl_page.kds_free_list.buffer_index = i;
			kd_ctrl_page.kds_free_list.offset = n;
		}
		n_storage_units += n_elements;
	}

	bzero((char *)kdbip, sizeof(struct kd_bufinfo) * kd_ctrl_page.kdebug_cpus);

	for (i = 0; i < kd_ctrl_page.kdebug_cpus; i++) {
		kdbip[i].kd_list_head.raw = KDS_PTR_NULL;
		kdbip[i].kd_list_tail.raw = KDS_PTR_NULL;
		kdbip[i].kd_lostevents = false;
		kdbip[i].num_bufs = 0;
	}

	kd_ctrl_page.kdebug_flags |= KDBG_BUFINIT;

	kd_ctrl_page.kds_inuse_count = 0;
	n_storage_threshold = n_storage_units / 2;
out:
	if (error) {
		delete_buffers();
	}

	return error;
}

static void
delete_buffers(void)
{
	unsigned int i;

	if (kd_bufs) {
		for (i = 0; i < n_storage_buffers; i++) {
			if (kd_bufs[i].kdsb_addr) {
				kmem_free(kernel_map, (vm_offset_t)kd_bufs[i].kdsb_addr, (vm_size_t)kd_bufs[i].kdsb_size);
			}
		}
		kmem_free(kernel_map, (vm_offset_t)kd_bufs, (vm_size_t)(n_storage_buffers * sizeof(struct kd_storage_buffers)));

		kd_bufs = NULL;
		n_storage_buffers = 0;
	}
	if (kdcopybuf) {
		kmem_free(kernel_map, (vm_offset_t)kdcopybuf, KDCOPYBUF_SIZE);

		kdcopybuf = NULL;
	}
	kd_ctrl_page.kds_free_list.raw = KDS_PTR_NULL;

	if (kdbip) {
		kmem_free(kernel_map, (vm_offset_t)kdbip, sizeof(struct kd_bufinfo) * kd_ctrl_page.kdebug_cpus);

		kdbip = NULL;
	}
	kd_ctrl_page.kdebug_iops = NULL;
	kd_ctrl_page.kdebug_cpus = 0;
	kd_ctrl_page.kdebug_flags &= ~KDBG_BUFINIT;
}

void
release_storage_unit(int cpu, uint32_t kdsp_raw)
{
	int s = 0;
	struct  kd_storage *kdsp_actual;
	struct kd_bufinfo *kdbp;
	union kds_ptr kdsp;

	kdsp.raw = kdsp_raw;

	s = ml_set_interrupts_enabled(false);
	lck_spin_lock_grp(kds_spin_lock, kdebug_lck_grp);

	kdbp = &kdbip[cpu];

	if (kdsp.raw == kdbp->kd_list_head.raw) {
		/*
		 * it's possible for the storage unit pointed to
		 * by kdsp to have already been stolen... so
		 * check to see if it's still the head of the list
		 * now that we're behind the lock that protects
		 * adding and removing from the queue...
		 * since we only ever release and steal units from
		 * that position, if it's no longer the head
		 * we having nothing to do in this context
		 */
		kdsp_actual = POINTER_FROM_KDS_PTR(kdsp);
		kdbp->kd_list_head = kdsp_actual->kds_next;

		kdsp_actual->kds_next = kd_ctrl_page.kds_free_list;
		kd_ctrl_page.kds_free_list = kdsp;

		kd_ctrl_page.kds_inuse_count--;
	}
	lck_spin_unlock(kds_spin_lock);
	ml_set_interrupts_enabled(s);
}

bool
allocate_storage_unit(int cpu)
{
	union kds_ptr kdsp;
	struct kd_storage *kdsp_actual, *kdsp_next_actual;
	struct kd_bufinfo *kdbp, *kdbp_vict, *kdbp_try;
	uint64_t oldest_ts, ts;
	bool retval = true;
	int s = 0;

	s = ml_set_interrupts_enabled(false);
	lck_spin_lock_grp(kds_spin_lock, kdebug_lck_grp);

	kdbp = &kdbip[cpu];

	/* If someone beat us to the allocate, return success */
	if (kdbp->kd_list_tail.raw != KDS_PTR_NULL) {
		kdsp_actual = POINTER_FROM_KDS_PTR(kdbp->kd_list_tail);

		if (kdsp_actual->kds_bufindx < EVENTS_PER_STORAGE_UNIT) {
			goto out;
		}
	}

	if ((kdsp = kd_ctrl_page.kds_free_list).raw != KDS_PTR_NULL) {
		/*
		 * If there's a free page, grab it from the free list.
		 */
		kdsp_actual = POINTER_FROM_KDS_PTR(kdsp);
		kd_ctrl_page.kds_free_list = kdsp_actual->kds_next;

		kd_ctrl_page.kds_inuse_count++;
	} else {
		/*
		 * Otherwise, we're going to lose events and repurpose the oldest
		 * storage unit we can find.
		 */
		if (kd_ctrl_page.kdebug_flags & KDBG_NOWRAP) {
			kd_ctrl_page.kdebug_slowcheck |= SLOW_NOLOG;
			kdbp->kd_lostevents = true;
			retval = false;
			goto out;
		}
		kdbp_vict = NULL;
		oldest_ts = UINT64_MAX;

		for (kdbp_try = &kdbip[0]; kdbp_try < &kdbip[kd_ctrl_page.kdebug_cpus]; kdbp_try++) {
			if (kdbp_try->kd_list_head.raw == KDS_PTR_NULL) {
				/*
				 * no storage unit to steal
				 */
				continue;
			}

			kdsp_actual = POINTER_FROM_KDS_PTR(kdbp_try->kd_list_head);

			if (kdsp_actual->kds_bufcnt < EVENTS_PER_STORAGE_UNIT) {
				/*
				 * make sure we don't steal the storage unit
				 * being actively recorded to...  need to
				 * move on because we don't want an out-of-order
				 * set of events showing up later
				 */
				continue;
			}

			/*
			 * When wrapping, steal the storage unit with the
			 * earliest timestamp on its last event, instead of the
			 * earliest timestamp on the first event.  This allows a
			 * storage unit with more recent events to be preserved,
			 * even if the storage unit contains events that are
			 * older than those found in other CPUs.
			 */
			ts = kdbg_get_timestamp(&kdsp_actual->kds_records[EVENTS_PER_STORAGE_UNIT - 1]);
			if (ts < oldest_ts) {
				oldest_ts = ts;
				kdbp_vict = kdbp_try;
			}
		}
		if (kdbp_vict == NULL) {
			kdebug_enable = 0;
			kd_ctrl_page.enabled = 0;
			commpage_update_kdebug_state();
			retval = false;
			goto out;
		}
		kdsp = kdbp_vict->kd_list_head;
		kdsp_actual = POINTER_FROM_KDS_PTR(kdsp);
		kdbp_vict->kd_list_head = kdsp_actual->kds_next;

		if (kdbp_vict->kd_list_head.raw != KDS_PTR_NULL) {
			kdsp_next_actual = POINTER_FROM_KDS_PTR(kdbp_vict->kd_list_head);
			kdsp_next_actual->kds_lostevents = true;
		} else {
			kdbp_vict->kd_lostevents = true;
		}

		if (kd_ctrl_page.oldest_time < oldest_ts) {
			kd_ctrl_page.oldest_time = oldest_ts;
		}
		kd_ctrl_page.kdebug_flags |= KDBG_WRAPPED;
	}
	kdsp_actual->kds_timestamp = kdbg_timestamp();
	kdsp_actual->kds_next.raw = KDS_PTR_NULL;
	kdsp_actual->kds_bufcnt   = 0;
	kdsp_actual->kds_readlast = 0;

	kdsp_actual->kds_lostevents = kdbp->kd_lostevents;
	kdbp->kd_lostevents = false;
	kdsp_actual->kds_bufindx = 0;

	if (kdbp->kd_list_head.raw == KDS_PTR_NULL) {
		kdbp->kd_list_head = kdsp;
	} else {
		POINTER_FROM_KDS_PTR(kdbp->kd_list_tail)->kds_next = kdsp;
	}
	kdbp->kd_list_tail = kdsp;
out:
	lck_spin_unlock(kds_spin_lock);
	ml_set_interrupts_enabled(s);

	return retval;
}

int
kernel_debug_register_callback(kd_callback_t callback)
{
	kd_iop_t* iop;
	if (kmem_alloc(kernel_map, (vm_offset_t *)&iop, sizeof(kd_iop_t), VM_KERN_MEMORY_DIAG) == KERN_SUCCESS) {
		memcpy(&iop->callback, &callback, sizeof(kd_callback_t));

		/*
		 * <rdar://problem/13351477> Some IOP clients are not providing a name.
		 *
		 * Remove when fixed.
		 */
		{
			bool is_valid_name = false;
			for (uint32_t length = 0; length < sizeof(callback.iop_name); ++length) {
				/* This is roughly isprintable(c) */
				if (callback.iop_name[length] > 0x20 && callback.iop_name[length] < 0x7F) {
					continue;
				}
				if (callback.iop_name[length] == 0) {
					if (length) {
						is_valid_name = true;
					}
					break;
				}
			}

			if (!is_valid_name) {
				strlcpy(iop->callback.iop_name, "IOP-???", sizeof(iop->callback.iop_name));
			}
		}

		iop->last_timestamp = 0;

		do {
			/*
			 * We use two pieces of state, the old list head
			 * pointer, and the value of old_list_head->cpu_id.
			 * If we read kd_iops more than once, it can change
			 * between reads.
			 *
			 * TLDR; Must not read kd_iops more than once per loop.
			 */
			iop->next = kd_iops;
			iop->cpu_id = iop->next ? (iop->next->cpu_id + 1) : kdbg_cpu_count(false);

			/*
			 * Header says OSCompareAndSwapPtr has a memory barrier
			 */
		} while (!OSCompareAndSwapPtr(iop->next, iop, (void* volatile*)&kd_iops));

		return iop->cpu_id;
	}

	return 0;
}

void
kernel_debug_enter(
	uint32_t        coreid,
	uint32_t        debugid,
	uint64_t        timestamp,
	uintptr_t       arg1,
	uintptr_t       arg2,
	uintptr_t       arg3,
	uintptr_t       arg4,
	uintptr_t       threadid
	)
{
	uint32_t        bindx;
	kd_buf          *kd;
	struct kd_bufinfo *kdbp;
	struct kd_storage *kdsp_actual;
	union  kds_ptr kds_raw;

	if (kd_ctrl_page.kdebug_slowcheck) {
		if ((kd_ctrl_page.kdebug_slowcheck & SLOW_NOLOG) || !(kdebug_enable & (KDEBUG_ENABLE_TRACE | KDEBUG_ENABLE_PPT))) {
			goto out1;
		}

		if (kd_ctrl_page.kdebug_flags & KDBG_TYPEFILTER_CHECK) {
			if (typefilter_is_debugid_allowed(kdbg_typefilter, debugid)) {
				goto record_event;
			}
			goto out1;
		} else if (kd_ctrl_page.kdebug_flags & KDBG_RANGECHECK) {
			if (debugid >= kdlog_beg && debugid <= kdlog_end) {
				goto record_event;
			}
			goto out1;
		} else if (kd_ctrl_page.kdebug_flags & KDBG_VALCHECK) {
			if ((debugid & KDBG_EVENTID_MASK) != kdlog_value1 &&
			    (debugid & KDBG_EVENTID_MASK) != kdlog_value2 &&
			    (debugid & KDBG_EVENTID_MASK) != kdlog_value3 &&
			    (debugid & KDBG_EVENTID_MASK) != kdlog_value4) {
				goto out1;
			}
		}
	}

record_event:
	if (timestamp < kd_ctrl_page.oldest_time) {
		goto out1;
	}

#if CONFIG_EMBEDDED
	/*
	 * When start_kern_tracing is called by the kernel to trace very
	 * early kernel events, it saves data to a secondary buffer until
	 * it is possible to initialize ktrace, and then dumps the events
	 * into the ktrace buffer using this method. In this case, iops will
	 * be NULL, and the coreid will be zero. It is not possible to have
	 * a valid IOP coreid of zero, so pass if both iops is NULL and coreid
	 * is zero.
	 */
	assert(kdbg_iop_list_contains_cpu_id(kd_ctrl_page.kdebug_iops, coreid) || (kd_ctrl_page.kdebug_iops == NULL && coreid == 0));
#endif

	disable_preemption();

	if (kd_ctrl_page.enabled == 0) {
		goto out;
	}

	kdbp = &kdbip[coreid];
	timestamp &= KDBG_TIMESTAMP_MASK;

#if KDEBUG_MOJO_TRACE
	if (kdebug_enable & KDEBUG_ENABLE_SERIAL) {
		kdebug_serial_print(coreid, debugid, timestamp,
		    arg1, arg2, arg3, arg4, threadid);
	}
#endif

retry_q:
	kds_raw = kdbp->kd_list_tail;

	if (kds_raw.raw != KDS_PTR_NULL) {
		kdsp_actual = POINTER_FROM_KDS_PTR(kds_raw);
		bindx = kdsp_actual->kds_bufindx;
	} else {
		kdsp_actual = NULL;
		bindx = EVENTS_PER_STORAGE_UNIT;
	}

	if (kdsp_actual == NULL || bindx >= EVENTS_PER_STORAGE_UNIT) {
		if (allocate_storage_unit(coreid) == false) {
			/*
			 * this can only happen if wrapping
			 * has been disabled
			 */
			goto out;
		}
		goto retry_q;
	}
	if (!OSCompareAndSwap(bindx, bindx + 1, &kdsp_actual->kds_bufindx)) {
		goto retry_q;
	}

	// IOP entries can be allocated before xnu allocates and inits the buffer
	if (timestamp < kdsp_actual->kds_timestamp) {
		kdsp_actual->kds_timestamp = timestamp;
	}

	kd = &kdsp_actual->kds_records[bindx];

	kd->debugid = debugid;
	kd->arg1 = arg1;
	kd->arg2 = arg2;
	kd->arg3 = arg3;
	kd->arg4 = arg4;
	kd->arg5 = threadid;

	kdbg_set_timestamp_and_cpu(kd, timestamp, coreid);

	OSAddAtomic(1, &kdsp_actual->kds_bufcnt);
out:
	enable_preemption();
out1:
	if ((kds_waiter && kd_ctrl_page.kds_inuse_count >= n_storage_threshold)) {
		kdbg_wakeup();
	}
}

/*
 * Check if the given debug ID is allowed to be traced on the current process.
 *
 * Returns true if allowed and false otherwise.
 */
static inline bool
kdebug_debugid_procfilt_allowed(uint32_t debugid)
{
	uint32_t procfilt_flags = kd_ctrl_page.kdebug_flags &
	    (KDBG_PIDCHECK | KDBG_PIDEXCLUDE);

	if (!procfilt_flags) {
		return true;
	}

	/*
	 * DBG_TRACE and MACH_SCHED tracepoints ignore the process filter.
	 */
	if ((debugid & 0xffff0000) == MACHDBG_CODE(DBG_MACH_SCHED, 0) ||
	    (debugid >> 24 == DBG_TRACE)) {
		return true;
	}

	struct proc *curproc = current_proc();
	/*
	 * If the process is missing (early in boot), allow it.
	 */
	if (!curproc) {
		return true;
	}

	if (procfilt_flags & KDBG_PIDCHECK) {
		/*
		 * Allow only processes marked with the kdebug bit.
		 */
		return curproc->p_kdebug;
	} else if (procfilt_flags & KDBG_PIDEXCLUDE) {
		/*
		 * Exclude any process marked with the kdebug bit.
		 */
		return !curproc->p_kdebug;
	} else {
		panic("kdebug: invalid procfilt flags %x", kd_ctrl_page.kdebug_flags);
		__builtin_unreachable();
	}
}

static void
kernel_debug_internal(
	uint32_t debugid,
	uintptr_t arg1,
	uintptr_t arg2,
	uintptr_t arg3,
	uintptr_t arg4,
	uintptr_t arg5,
	uint64_t flags)
{
	uint64_t now;
	uint32_t bindx;
	kd_buf *kd;
	int cpu;
	struct kd_bufinfo *kdbp;
	struct kd_storage *kdsp_actual;
	union kds_ptr kds_raw;
	bool only_filter = flags & KDBG_FLAG_FILTERED;
	bool observe_procfilt = !(flags & KDBG_FLAG_NOPROCFILT);

	if (kd_ctrl_page.kdebug_slowcheck) {
		if ((kd_ctrl_page.kdebug_slowcheck & SLOW_NOLOG) ||
		    !(kdebug_enable & (KDEBUG_ENABLE_TRACE | KDEBUG_ENABLE_PPT))) {
			goto out1;
		}

		if (!ml_at_interrupt_context() && observe_procfilt &&
		    !kdebug_debugid_procfilt_allowed(debugid)) {
			goto out1;
		}

		if (kd_ctrl_page.kdebug_flags & KDBG_TYPEFILTER_CHECK) {
			if (typefilter_is_debugid_allowed(kdbg_typefilter, debugid)) {
				goto record_event;
			}

			goto out1;
		} else if (only_filter) {
			goto out1;
		} else if (kd_ctrl_page.kdebug_flags & KDBG_RANGECHECK) {
			/* Always record trace system info */
			if (KDBG_EXTRACT_CLASS(debugid) == DBG_TRACE) {
				goto record_event;
			}

			if (debugid < kdlog_beg || debugid > kdlog_end) {
				goto out1;
			}
		} else if (kd_ctrl_page.kdebug_flags & KDBG_VALCHECK) {
			/* Always record trace system info */
			if (KDBG_EXTRACT_CLASS(debugid) == DBG_TRACE) {
				goto record_event;
			}

			if ((debugid & KDBG_EVENTID_MASK) != kdlog_value1 &&
			    (debugid & KDBG_EVENTID_MASK) != kdlog_value2 &&
			    (debugid & KDBG_EVENTID_MASK) != kdlog_value3 &&
			    (debugid & KDBG_EVENTID_MASK) != kdlog_value4) {
				goto out1;
			}
		}
	} else if (only_filter) {
		goto out1;
	}

record_event:
	disable_preemption();

	if (kd_ctrl_page.enabled == 0) {
		goto out;
	}

	cpu = cpu_number();
	kdbp = &kdbip[cpu];

#if KDEBUG_MOJO_TRACE
	if (kdebug_enable & KDEBUG_ENABLE_SERIAL) {
		kdebug_serial_print(cpu, debugid,
		    kdbg_timestamp() & KDBG_TIMESTAMP_MASK,
		    arg1, arg2, arg3, arg4, arg5);
	}
#endif

retry_q:
	kds_raw = kdbp->kd_list_tail;

	if (kds_raw.raw != KDS_PTR_NULL) {
		kdsp_actual = POINTER_FROM_KDS_PTR(kds_raw);
		bindx = kdsp_actual->kds_bufindx;
	} else {
		kdsp_actual = NULL;
		bindx = EVENTS_PER_STORAGE_UNIT;
	}

	if (kdsp_actual == NULL || bindx >= EVENTS_PER_STORAGE_UNIT) {
		if (allocate_storage_unit(cpu) == false) {
			/*
			 * this can only happen if wrapping
			 * has been disabled
			 */
			goto out;
		}
		goto retry_q;
	}

	now = kdbg_timestamp() & KDBG_TIMESTAMP_MASK;

	if (!OSCompareAndSwap(bindx, bindx + 1, &kdsp_actual->kds_bufindx)) {
		goto retry_q;
	}

	kd = &kdsp_actual->kds_records[bindx];

	kd->debugid = debugid;
	kd->arg1 = arg1;
	kd->arg2 = arg2;
	kd->arg3 = arg3;
	kd->arg4 = arg4;
	kd->arg5 = arg5;

	kdbg_set_timestamp_and_cpu(kd, now, cpu);

	OSAddAtomic(1, &kdsp_actual->kds_bufcnt);

#if KPERF
	kperf_kdebug_callback(debugid, __builtin_frame_address(0));
#endif
out:
	enable_preemption();
out1:
	if (kds_waiter && kd_ctrl_page.kds_inuse_count >= n_storage_threshold) {
		uint32_t        etype;
		uint32_t        stype;

		etype = debugid & KDBG_EVENTID_MASK;
		stype = debugid & KDBG_CSC_MASK;

		if (etype == INTERRUPT || etype == MACH_vmfault ||
		    stype == BSC_SysCall || stype == MACH_SysCall) {
			kdbg_wakeup();
		}
	}
}

__attribute__((noinline))
void
kernel_debug(
	uint32_t        debugid,
	uintptr_t       arg1,
	uintptr_t       arg2,
	uintptr_t       arg3,
	uintptr_t       arg4,
	__unused uintptr_t arg5)
{
	kernel_debug_internal(debugid, arg1, arg2, arg3, arg4,
	    (uintptr_t)thread_tid(current_thread()), 0);
}

__attribute__((noinline))
void
kernel_debug1(
	uint32_t        debugid,
	uintptr_t       arg1,
	uintptr_t       arg2,
	uintptr_t       arg3,
	uintptr_t       arg4,
	uintptr_t       arg5)
{
	kernel_debug_internal(debugid, arg1, arg2, arg3, arg4, arg5, 0);
}

__attribute__((noinline))
void
kernel_debug_flags(
	uint32_t debugid,
	uintptr_t arg1,
	uintptr_t arg2,
	uintptr_t arg3,
	uintptr_t arg4,
	uint64_t flags)
{
	kernel_debug_internal(debugid, arg1, arg2, arg3, arg4,
	    (uintptr_t)thread_tid(current_thread()), flags);
}

__attribute__((noinline))
void
kernel_debug_filtered(
	uint32_t debugid,
	uintptr_t arg1,
	uintptr_t arg2,
	uintptr_t arg3,
	uintptr_t arg4)
{
	kernel_debug_flags(debugid, arg1, arg2, arg3, arg4, KDBG_FLAG_FILTERED);
}

void
kernel_debug_string_early(const char *message)
{
	uintptr_t arg[4] = {0, 0, 0, 0};

	/* Stuff the message string in the args and log it. */
	strncpy((char *)arg, message, MIN(sizeof(arg), strlen(message)));
	KERNEL_DEBUG_EARLY(
		TRACE_INFO_STRING,
		arg[0], arg[1], arg[2], arg[3]);
}

#define SIMPLE_STR_LEN (64)
static_assert(SIMPLE_STR_LEN % sizeof(uintptr_t) == 0);

void
kernel_debug_string_simple(uint32_t eventid, const char *str)
{
	if (!kdebug_enable) {
		return;
	}

	/* array of uintptr_ts simplifies emitting the string as arguments */
	uintptr_t str_buf[(SIMPLE_STR_LEN / sizeof(uintptr_t)) + 1] = { 0 };
	size_t len = strlcpy((char *)str_buf, str, SIMPLE_STR_LEN + 1);

	uintptr_t thread_id = (uintptr_t)thread_tid(current_thread());
	uint32_t debugid = eventid | DBG_FUNC_START;

	/* string can fit in a single tracepoint */
	if (len <= (4 * sizeof(uintptr_t))) {
		debugid |= DBG_FUNC_END;
	}

	kernel_debug_internal(debugid, str_buf[0],
	    str_buf[1],
	    str_buf[2],
	    str_buf[3], thread_id, 0);

	debugid &= KDBG_EVENTID_MASK;
	int i = 4;
	size_t written = 4 * sizeof(uintptr_t);

	for (; written < len; i += 4, written += 4 * sizeof(uintptr_t)) {
		/* if this is the last tracepoint to be emitted */
		if ((written + (4 * sizeof(uintptr_t))) >= len) {
			debugid |= DBG_FUNC_END;
		}
		kernel_debug_internal(debugid, str_buf[i],
		    str_buf[i + 1],
		    str_buf[i + 2],
		    str_buf[i + 3], thread_id, 0);
	}
}

extern int      master_cpu;             /* MACH_KERNEL_PRIVATE */
/*
 * Used prior to start_kern_tracing() being called.
 * Log temporarily into a static buffer.
 */
void
kernel_debug_early(
	uint32_t        debugid,
	uintptr_t       arg1,
	uintptr_t       arg2,
	uintptr_t       arg3,
	uintptr_t       arg4)
{
#if defined(__x86_64__)
	extern int early_boot;
	/*
	 * Note that "early" isn't early enough in some cases where
	 * we're invoked before gsbase is set on x86, hence the
	 * check of "early_boot".
	 */
	if (early_boot) {
		return;
	}
#endif

	/* If early tracing is over, use the normal path. */
	if (kd_early_done) {
		KERNEL_DEBUG_CONSTANT(debugid, arg1, arg2, arg3, arg4, 0);
		return;
	}

	/* Do nothing if the buffer is full or we're not on the boot cpu. */
	kd_early_overflow = kd_early_index >= KD_EARLY_BUFFER_NBUFS;
	if (kd_early_overflow || cpu_number() != master_cpu) {
		return;
	}

	kd_early_buffer[kd_early_index].debugid = debugid;
	kd_early_buffer[kd_early_index].timestamp = mach_absolute_time();
	kd_early_buffer[kd_early_index].arg1 = arg1;
	kd_early_buffer[kd_early_index].arg2 = arg2;
	kd_early_buffer[kd_early_index].arg3 = arg3;
	kd_early_buffer[kd_early_index].arg4 = arg4;
	kd_early_buffer[kd_early_index].arg5 = 0;
	kd_early_index++;
}

/*
 * Transfer the contents of the temporary buffer into the trace buffers.
 * Precede that by logging the rebase time (offset) - the TSC-based time (in ns)
 * when mach_absolute_time is set to 0.
 */
static void
kernel_debug_early_end(void)
{
	if (cpu_number() != master_cpu) {
		panic("kernel_debug_early_end() not call on boot processor");
	}

	/* reset the current oldest time to allow early events */
	kd_ctrl_page.oldest_time = 0;

#if !CONFIG_EMBEDDED
	/* Fake sentinel marking the start of kernel time relative to TSC */
	kernel_debug_enter(0,
	    TRACE_TIMESTAMPS,
	    0,
	    (uint32_t)(tsc_rebase_abs_time >> 32),
	    (uint32_t)tsc_rebase_abs_time,
	    tsc_at_boot,
	    0,
	    0);
#endif
	for (unsigned int i = 0; i < kd_early_index; i++) {
		kernel_debug_enter(0,
		    kd_early_buffer[i].debugid,
		    kd_early_buffer[i].timestamp,
		    kd_early_buffer[i].arg1,
		    kd_early_buffer[i].arg2,
		    kd_early_buffer[i].arg3,
		    kd_early_buffer[i].arg4,
		    0);
	}

	/* Cut events-lost event on overflow */
	if (kd_early_overflow) {
		KDBG_RELEASE(TRACE_LOST_EVENTS, 1);
	}

	kd_early_done = true;

	/* This trace marks the start of kernel tracing */
	kernel_debug_string_early("early trace done");
}

void
kernel_debug_disable(void)
{
	if (kdebug_enable) {
		kdbg_set_tracing_enabled(false, 0);
	}
}

/*
 * Returns non-zero if debugid is in a reserved class.
 */
static int
kdebug_validate_debugid(uint32_t debugid)
{
	uint8_t debugid_class;

	debugid_class = KDBG_EXTRACT_CLASS(debugid);
	switch (debugid_class) {
	case DBG_TRACE:
		return EPERM;
	}

	return 0;
}

/*
 * Support syscall SYS_kdebug_typefilter.
 */
int
kdebug_typefilter(__unused struct proc* p,
    struct kdebug_typefilter_args* uap,
    __unused int *retval)
{
	int ret = KERN_SUCCESS;

	if (uap->addr == USER_ADDR_NULL ||
	    uap->size == USER_ADDR_NULL) {
		return EINVAL;
	}

	/*
	 * The atomic load is to close a race window with setting the typefilter
	 * and memory entry values. A description follows:
	 *
	 * Thread 1 (writer)
	 *
	 * Allocate Typefilter
	 * Allocate MemoryEntry
	 * Write Global MemoryEntry Ptr
	 * Atomic Store (Release) Global Typefilter Ptr
	 *
	 * Thread 2 (reader, AKA us)
	 *
	 * if ((Atomic Load (Acquire) Global Typefilter Ptr) == NULL)
	 *     return;
	 *
	 * Without the atomic store, it isn't guaranteed that the write of
	 * Global MemoryEntry Ptr is visible before we can see the write of
	 * Global Typefilter Ptr.
	 *
	 * Without the atomic load, it isn't guaranteed that the loads of
	 * Global MemoryEntry Ptr aren't speculated.
	 *
	 * The global pointers transition from NULL -> valid once and only once,
	 * and never change after becoming valid. This means that having passed
	 * the first atomic load test of Global Typefilter Ptr, this function
	 * can then safely use the remaining global state without atomic checks.
	 */
	if (!os_atomic_load(&kdbg_typefilter, acquire)) {
		return EINVAL;
	}

	assert(kdbg_typefilter_memory_entry);

	mach_vm_offset_t user_addr = 0;
	vm_map_t user_map = current_map();

	ret = mach_to_bsd_errno(
		mach_vm_map_kernel(user_map,                                    // target map
		&user_addr,                                             // [in, out] target address
		TYPEFILTER_ALLOC_SIZE,                                  // initial size
		0,                                                      // mask (alignment?)
		VM_FLAGS_ANYWHERE,                                      // flags
		VM_MAP_KERNEL_FLAGS_NONE,
		VM_KERN_MEMORY_NONE,
		kdbg_typefilter_memory_entry,                           // port (memory entry!)
		0,                                                      // offset (in memory entry)
		false,                                                  // should copy
		VM_PROT_READ,                                           // cur_prot
		VM_PROT_READ,                                           // max_prot
		VM_INHERIT_SHARE));                                     // inherit behavior on fork

	if (ret == KERN_SUCCESS) {
		vm_size_t user_ptr_size = vm_map_is_64bit(user_map) ? 8 : 4;
		ret = copyout(CAST_DOWN(void *, &user_addr), uap->addr, user_ptr_size );

		if (ret != KERN_SUCCESS) {
			mach_vm_deallocate(user_map, user_addr, TYPEFILTER_ALLOC_SIZE);
		}
	}

	return ret;
}

/*
 * Support syscall SYS_kdebug_trace. U64->K32 args may get truncated in kdebug_trace64
 */
int
kdebug_trace(struct proc *p, struct kdebug_trace_args *uap, int32_t *retval)
{
	struct kdebug_trace64_args uap64;

	uap64.code = uap->code;
	uap64.arg1 = uap->arg1;
	uap64.arg2 = uap->arg2;
	uap64.arg3 = uap->arg3;
	uap64.arg4 = uap->arg4;

	return kdebug_trace64(p, &uap64, retval);
}

/*
 * Support syscall SYS_kdebug_trace64. 64-bit args on K32 will get truncated
 * to fit in 32-bit record format.
 *
 * It is intentional that error conditions are not checked until kdebug is
 * enabled. This is to match the userspace wrapper behavior, which is optimizing
 * for non-error case performance.
 */
int
kdebug_trace64(__unused struct proc *p, struct kdebug_trace64_args *uap, __unused int32_t *retval)
{
	int err;

	if (__probable(kdebug_enable == 0)) {
		return 0;
	}

	if ((err = kdebug_validate_debugid(uap->code)) != 0) {
		return err;
	}

	kernel_debug_internal(uap->code, (uintptr_t)uap->arg1,
	    (uintptr_t)uap->arg2, (uintptr_t)uap->arg3, (uintptr_t)uap->arg4,
	    (uintptr_t)thread_tid(current_thread()), 0);

	return 0;
}

/*
 * Adding enough padding to contain a full tracepoint for the last
 * portion of the string greatly simplifies the logic of splitting the
 * string between tracepoints.  Full tracepoints can be generated using
 * the buffer itself, without having to manually add zeros to pad the
 * arguments.
 */

/* 2 string args in first tracepoint and 9 string data tracepoints */
#define STR_BUF_ARGS (2 + (9 * 4))
/* times the size of each arg on K64 */
#define MAX_STR_LEN  (STR_BUF_ARGS * sizeof(uint64_t))
/* on K32, ending straddles a tracepoint, so reserve blanks */
#define STR_BUF_SIZE (MAX_STR_LEN + (2 * sizeof(uint32_t)))

/*
 * This function does no error checking and assumes that it is called with
 * the correct arguments, including that the buffer pointed to by str is at
 * least STR_BUF_SIZE bytes.  However, str must be aligned to word-size and
 * be NUL-terminated.  In cases where a string can fit evenly into a final
 * tracepoint without its NUL-terminator, this function will not end those
 * strings with a NUL in trace.  It's up to clients to look at the function
 * qualifier for DBG_FUNC_END in this case, to end the string.
 */
static uint64_t
kernel_debug_string_internal(uint32_t debugid, uint64_t str_id, void *vstr,
    size_t str_len)
{
	/* str must be word-aligned */
	uintptr_t *str = vstr;
	size_t written = 0;
	uintptr_t thread_id;
	int i;
	uint32_t trace_debugid = TRACEDBG_CODE(DBG_TRACE_STRING,
	    TRACE_STRING_GLOBAL);

	thread_id = (uintptr_t)thread_tid(current_thread());

	/* if the ID is being invalidated, just emit that */
	if (str_id != 0 && str_len == 0) {
		kernel_debug_internal(trace_debugid | DBG_FUNC_START | DBG_FUNC_END,
		    (uintptr_t)debugid, (uintptr_t)str_id, 0, 0, thread_id, 0);
		return str_id;
	}

	/* generate an ID, if necessary */
	if (str_id == 0) {
		str_id = OSIncrementAtomic64((SInt64 *)&g_curr_str_id);
		str_id = (str_id & STR_ID_MASK) | g_str_id_signature;
	}

	trace_debugid |= DBG_FUNC_START;
	/* string can fit in a single tracepoint */
	if (str_len <= (2 * sizeof(uintptr_t))) {
		trace_debugid |= DBG_FUNC_END;
	}

	kernel_debug_internal(trace_debugid, (uintptr_t)debugid, (uintptr_t)str_id,
	    str[0], str[1], thread_id, 0);

	trace_debugid &= KDBG_EVENTID_MASK;
	i = 2;
	written += 2 * sizeof(uintptr_t);

	for (; written < str_len; i += 4, written += 4 * sizeof(uintptr_t)) {
		if ((written + (4 * sizeof(uintptr_t))) >= str_len) {
			trace_debugid |= DBG_FUNC_END;
		}
		kernel_debug_internal(trace_debugid, str[i],
		    str[i + 1],
		    str[i + 2],
		    str[i + 3], thread_id, 0);
	}

	return str_id;
}

/*
 * Returns true if the current process can emit events, and false otherwise.
 * Trace system and scheduling events circumvent this check, as do events
 * emitted in interrupt context.
 */
static bool
kdebug_current_proc_enabled(uint32_t debugid)
{
	/* can't determine current process in interrupt context */
	if (ml_at_interrupt_context()) {
		return true;
	}

	/* always emit trace system and scheduling events */
	if ((KDBG_EXTRACT_CLASS(debugid) == DBG_TRACE ||
	    (debugid & KDBG_CSC_MASK) == MACHDBG_CODE(DBG_MACH_SCHED, 0))) {
		return true;
	}

	if (kd_ctrl_page.kdebug_flags & KDBG_PIDCHECK) {
		proc_t cur_proc = current_proc();

		/* only the process with the kdebug bit set is allowed */
		if (cur_proc && !(cur_proc->p_kdebug)) {
			return false;
		}
	} else if (kd_ctrl_page.kdebug_flags & KDBG_PIDEXCLUDE) {
		proc_t cur_proc = current_proc();

		/* every process except the one with the kdebug bit set is allowed */
		if (cur_proc && cur_proc->p_kdebug) {
			return false;
		}
	}

	return true;
}

bool
kdebug_debugid_enabled(uint32_t debugid)
{
	/* if no filtering is enabled */
	if (!kd_ctrl_page.kdebug_slowcheck) {
		return true;
	}

	return kdebug_debugid_explicitly_enabled(debugid);
}

bool
kdebug_debugid_explicitly_enabled(uint32_t debugid)
{
	if (kd_ctrl_page.kdebug_flags & KDBG_TYPEFILTER_CHECK) {
		return typefilter_is_debugid_allowed(kdbg_typefilter, debugid);
	} else if (KDBG_EXTRACT_CLASS(debugid) == DBG_TRACE) {
		return true;
	} else if (kd_ctrl_page.kdebug_flags & KDBG_RANGECHECK) {
		if (debugid < kdlog_beg || debugid > kdlog_end) {
			return false;
		}
	} else if (kd_ctrl_page.kdebug_flags & KDBG_VALCHECK) {
		if ((debugid & KDBG_EVENTID_MASK) != kdlog_value1 &&
		    (debugid & KDBG_EVENTID_MASK) != kdlog_value2 &&
		    (debugid & KDBG_EVENTID_MASK) != kdlog_value3 &&
		    (debugid & KDBG_EVENTID_MASK) != kdlog_value4) {
			return false;
		}
	}

	return true;
}

bool
kdebug_using_continuous_time(void)
{
	return kdebug_enable & KDEBUG_ENABLE_CONT_TIME;
}

/*
 * Returns 0 if a string can be traced with these arguments.  Returns errno
 * value if error occurred.
 */
static errno_t
kdebug_check_trace_string(uint32_t debugid, uint64_t str_id)
{
	/* if there are function qualifiers on the debugid */
	if (debugid & ~KDBG_EVENTID_MASK) {
		return EINVAL;
	}

	if (kdebug_validate_debugid(debugid)) {
		return EPERM;
	}

	if (str_id != 0 && (str_id & STR_ID_SIG_MASK) != g_str_id_signature) {
		return EINVAL;
	}

	return 0;
}

/*
 * Implementation of KPI kernel_debug_string.
 */
int
kernel_debug_string(uint32_t debugid, uint64_t *str_id, const char *str)
{
	/* arguments to tracepoints must be word-aligned */
	__attribute__((aligned(sizeof(uintptr_t)))) char str_buf[STR_BUF_SIZE];
	static_assert(sizeof(str_buf) > MAX_STR_LEN);
	vm_size_t len_copied;
	int err;

	assert(str_id);

	if (__probable(kdebug_enable == 0)) {
		return 0;
	}

	if (!kdebug_current_proc_enabled(debugid)) {
		return 0;
	}

	if (!kdebug_debugid_enabled(debugid)) {
		return 0;
	}

	if ((err = kdebug_check_trace_string(debugid, *str_id)) != 0) {
		return err;
	}

	if (str == NULL) {
		if (str_id == 0) {
			return EINVAL;
		}

		*str_id = kernel_debug_string_internal(debugid, *str_id, NULL, 0);
		return 0;
	}

	memset(str_buf, 0, sizeof(str_buf));
	len_copied = strlcpy(str_buf, str, MAX_STR_LEN + 1);
	*str_id = kernel_debug_string_internal(debugid, *str_id, str_buf,
	    len_copied);
	return 0;
}

/*
 * Support syscall kdebug_trace_string.
 */
int
kdebug_trace_string(__unused struct proc *p,
    struct kdebug_trace_string_args *uap,
    uint64_t *retval)
{
	__attribute__((aligned(sizeof(uintptr_t)))) char str_buf[STR_BUF_SIZE];
	static_assert(sizeof(str_buf) > MAX_STR_LEN);
	size_t len_copied;
	int err;

	if (__probable(kdebug_enable == 0)) {
		return 0;
	}

	if (!kdebug_current_proc_enabled(uap->debugid)) {
		return 0;
	}

	if (!kdebug_debugid_enabled(uap->debugid)) {
		return 0;
	}

	if ((err = kdebug_check_trace_string(uap->debugid, uap->str_id)) != 0) {
		return err;
	}

	if (uap->str == USER_ADDR_NULL) {
		if (uap->str_id == 0) {
			return EINVAL;
		}

		*retval = kernel_debug_string_internal(uap->debugid, uap->str_id,
		    NULL, 0);
		return 0;
	}

	memset(str_buf, 0, sizeof(str_buf));
	err = copyinstr(uap->str, str_buf, MAX_STR_LEN + 1, &len_copied);

	/* it's alright to truncate the string, so allow ENAMETOOLONG */
	if (err == ENAMETOOLONG) {
		str_buf[MAX_STR_LEN] = '\0';
	} else if (err) {
		return err;
	}

	if (len_copied <= 1) {
		return EINVAL;
	}

	/* convert back to a length */
	len_copied--;

	*retval = kernel_debug_string_internal(uap->debugid, uap->str_id, str_buf,
	    len_copied);
	return 0;
}

static void
kdbg_lock_init(void)
{
	static lck_grp_attr_t *kdebug_lck_grp_attr = NULL;
	static lck_attr_t     *kdebug_lck_attr     = NULL;

	if (kd_ctrl_page.kdebug_flags & KDBG_LOCKINIT) {
		return;
	}

	assert(kdebug_lck_grp_attr == NULL);
	kdebug_lck_grp_attr = lck_grp_attr_alloc_init();
	kdebug_lck_grp = lck_grp_alloc_init("kdebug", kdebug_lck_grp_attr);
	kdebug_lck_attr = lck_attr_alloc_init();

	kds_spin_lock = lck_spin_alloc_init(kdebug_lck_grp, kdebug_lck_attr);
	kdw_spin_lock = lck_spin_alloc_init(kdebug_lck_grp, kdebug_lck_attr);

	kd_ctrl_page.kdebug_flags |= KDBG_LOCKINIT;
}

int
kdbg_bootstrap(bool early_trace)
{
	kd_ctrl_page.kdebug_flags &= ~KDBG_WRAPPED;

	return create_buffers(early_trace);
}

int
kdbg_reinit(bool early_trace)
{
	int ret = 0;

	/*
	 * Disable trace collecting
	 * First make sure we're not in
	 * the middle of cutting a trace
	 */
	kernel_debug_disable();

	/*
	 * make sure the SLOW_NOLOG is seen
	 * by everyone that might be trying
	 * to cut a trace..
	 */
	IOSleep(100);

	delete_buffers();

	kdbg_clear_thread_map();
	ret = kdbg_bootstrap(early_trace);

	RAW_file_offset = 0;
	RAW_file_written = 0;

	return ret;
}

void
kdbg_trace_data(struct proc *proc, long *arg_pid, long *arg_uniqueid)
{
	if (!proc) {
		*arg_pid = 0;
		*arg_uniqueid = 0;
	} else {
		*arg_pid = proc->p_pid;
		*arg_uniqueid = proc->p_uniqueid;
		if ((uint64_t) *arg_uniqueid != proc->p_uniqueid) {
			*arg_uniqueid = 0;
		}
	}
}


void
kdbg_trace_string(struct proc *proc, long *arg1, long *arg2, long *arg3,
    long *arg4)
{
	if (!proc) {
		*arg1 = 0;
		*arg2 = 0;
		*arg3 = 0;
		*arg4 = 0;
		return;
	}

	const char *procname = proc_best_name(proc);
	size_t namelen = strlen(procname);

	long args[4] = { 0 };

	if (namelen > sizeof(args)) {
		namelen = sizeof(args);
	}

	strncpy((char *)args, procname, namelen);

	*arg1 = args[0];
	*arg2 = args[1];
	*arg3 = args[2];
	*arg4 = args[3];
}

static void
kdbg_resolve_map(thread_t th_act, void *opaque)
{
	kd_threadmap *mapptr;
	krt_t *t = (krt_t *)opaque;

	if (t->count < t->maxcount) {
		mapptr = &t->map[t->count];
		mapptr->thread  = (uintptr_t)thread_tid(th_act);

		(void) strlcpy(mapptr->command, t->atts->task_comm,
		    sizeof(t->atts->task_comm));
		/*
		 * Some kernel threads have no associated pid.
		 * We still need to mark the entry as valid.
		 */
		if (t->atts->pid) {
			mapptr->valid = t->atts->pid;
		} else {
			mapptr->valid = 1;
		}

		t->count++;
	}
}

/*
 *
 * Writes a cpumap for the given iops_list/cpu_count to the provided buffer.
 *
 * You may provide a buffer and size, or if you set the buffer to NULL, a
 * buffer of sufficient size will be allocated.
 *
 * If you provide a buffer and it is too small, sets cpumap_size to the number
 * of bytes required and returns EINVAL.
 *
 * On success, if you provided a buffer, cpumap_size is set to the number of
 * bytes written. If you did not provide a buffer, cpumap is set to the newly
 * allocated buffer and cpumap_size is set to the number of bytes allocated.
 *
 * NOTE: It may seem redundant to pass both iops and a cpu_count.
 *
 * We may be reporting data from "now", or from the "past".
 *
 * The "past" data would be for kdbg_readcpumap().
 *
 * If we do not pass both iops and cpu_count, and iops is NULL, this function
 * will need to read "now" state to get the number of cpus, which would be in
 * error if we were reporting "past" state.
 */

int
kdbg_cpumap_init_internal(kd_iop_t* iops, uint32_t cpu_count, uint8_t** cpumap, uint32_t* cpumap_size)
{
	assert(cpumap);
	assert(cpumap_size);
	assert(cpu_count);
	assert(!iops || iops->cpu_id + 1 == cpu_count);

	uint32_t bytes_needed = sizeof(kd_cpumap_header) + cpu_count * sizeof(kd_cpumap);
	uint32_t bytes_available = *cpumap_size;
	*cpumap_size = bytes_needed;

	if (*cpumap == NULL) {
		if (kmem_alloc(kernel_map, (vm_offset_t*)cpumap, (vm_size_t)*cpumap_size, VM_KERN_MEMORY_DIAG) != KERN_SUCCESS) {
			return ENOMEM;
		}
		bzero(*cpumap, *cpumap_size);
	} else if (bytes_available < bytes_needed) {
		return EINVAL;
	}

	kd_cpumap_header* header = (kd_cpumap_header*)(uintptr_t)*cpumap;

	header->version_no = RAW_VERSION1;
	header->cpu_count = cpu_count;

	kd_cpumap* cpus = (kd_cpumap*)&header[1];

	int32_t index = cpu_count - 1;
	while (iops) {
		cpus[index].cpu_id = iops->cpu_id;
		cpus[index].flags = KDBG_CPUMAP_IS_IOP;
		strlcpy(cpus[index].name, iops->callback.iop_name, sizeof(cpus->name));

		iops = iops->next;
		index--;
	}

	while (index >= 0) {
		cpus[index].cpu_id = index;
		cpus[index].flags = 0;
		strlcpy(cpus[index].name, "AP", sizeof(cpus->name));

		index--;
	}

	return KERN_SUCCESS;
}

void
kdbg_thrmap_init(void)
{
	ktrace_assert_lock_held();

	if (kd_ctrl_page.kdebug_flags & KDBG_MAPINIT) {
		return;
	}

	kd_mapptr = kdbg_thrmap_init_internal(0, &kd_mapsize, &kd_mapcount);

	if (kd_mapptr) {
		kd_ctrl_page.kdebug_flags |= KDBG_MAPINIT;
	}
}

static kd_threadmap *
kdbg_thrmap_init_internal(unsigned int count, unsigned int *mapsize, unsigned int *mapcount)
{
	kd_threadmap *mapptr;
	proc_t p;
	struct krt akrt;
	int tts_count = 0;    /* number of task-to-string structures */
	struct tts *tts_mapptr;
	unsigned int tts_mapsize = 0;
	vm_offset_t kaddr;

	assert(mapsize != NULL);
	assert(mapcount != NULL);

	*mapcount = threads_count;
	tts_count = tasks_count;

	/*
	 * The proc count could change during buffer allocation,
	 * so introduce a small fudge factor to bump up the
	 * buffer sizes. This gives new tasks some chance of
	 * making into the tables.  Bump up by 25%.
	 */
	*mapcount += *mapcount / 4;
	tts_count += tts_count / 4;

	*mapsize = *mapcount * sizeof(kd_threadmap);

	if (count && count < *mapcount) {
		return 0;
	}

	if ((kmem_alloc(kernel_map, &kaddr, (vm_size_t)*mapsize, VM_KERN_MEMORY_DIAG) == KERN_SUCCESS)) {
		bzero((void *)kaddr, *mapsize);
		mapptr = (kd_threadmap *)kaddr;
	} else {
		return 0;
	}

	tts_mapsize = tts_count * sizeof(struct tts);

	if ((kmem_alloc(kernel_map, &kaddr, (vm_size_t)tts_mapsize, VM_KERN_MEMORY_DIAG) == KERN_SUCCESS)) {
		bzero((void *)kaddr, tts_mapsize);
		tts_mapptr = (struct tts *)kaddr;
	} else {
		kmem_free(kernel_map, (vm_offset_t)mapptr, *mapsize);

		return 0;
	}

	/*
	 * Save the proc's name and take a reference for each task associated
	 * with a valid process.
	 */
	proc_list_lock();

	int i = 0;
	ALLPROC_FOREACH(p) {
		if (i >= tts_count) {
			break;
		}
		if (p->p_lflag & P_LEXIT) {
			continue;
		}
		if (p->task) {
			task_reference(p->task);
			tts_mapptr[i].task = p->task;
			tts_mapptr[i].pid = p->p_pid;
			(void)strlcpy(tts_mapptr[i].task_comm, proc_best_name(p), sizeof(tts_mapptr[i].task_comm));
			i++;
		}
	}
	tts_count = i;

	proc_list_unlock();

	/*
	 * Initialize thread map data
	 */
	akrt.map = mapptr;
	akrt.count = 0;
	akrt.maxcount = *mapcount;

	for (i = 0; i < tts_count; i++) {
		akrt.atts = &tts_mapptr[i];
		task_act_iterate_wth_args(tts_mapptr[i].task, kdbg_resolve_map, &akrt);
		task_deallocate((task_t)tts_mapptr[i].task);
	}
	kmem_free(kernel_map, (vm_offset_t)tts_mapptr, tts_mapsize);

	*mapcount = akrt.count;

	return mapptr;
}

static void
kdbg_clear(void)
{
	/*
	 * Clean up the trace buffer
	 * First make sure we're not in
	 * the middle of cutting a trace
	 */
	kernel_debug_disable();
	kdbg_disable_typefilter();

	/*
	 * make sure the SLOW_NOLOG is seen
	 * by everyone that might be trying
	 * to cut a trace..
	 */
	IOSleep(100);

	/* reset kdebug state for each process */
	if (kd_ctrl_page.kdebug_flags & (KDBG_PIDCHECK | KDBG_PIDEXCLUDE)) {
		proc_list_lock();
		proc_t p;
		ALLPROC_FOREACH(p) {
			p->p_kdebug = 0;
		}
		proc_list_unlock();
	}

	kd_ctrl_page.kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
	kd_ctrl_page.kdebug_flags &= ~(KDBG_NOWRAP | KDBG_RANGECHECK | KDBG_VALCHECK);
	kd_ctrl_page.kdebug_flags &= ~(KDBG_PIDCHECK | KDBG_PIDEXCLUDE);

	kd_ctrl_page.oldest_time = 0;

	delete_buffers();
	nkdbufs = 0;

	/* Clean up the thread map buffer */
	kdbg_clear_thread_map();

	RAW_file_offset = 0;
	RAW_file_written = 0;
}

void
kdebug_reset(void)
{
	ktrace_assert_lock_held();

	kdbg_lock_init();

	kdbg_clear();
	if (kdbg_typefilter) {
		typefilter_reject_all(kdbg_typefilter);
		typefilter_allow_class(kdbg_typefilter, DBG_TRACE);
	}
}

void
kdebug_free_early_buf(void)
{
#if !CONFIG_EMBEDDED
	/* Must be done with the buffer, so release it back to the VM.
	 * On embedded targets this buffer is freed when the BOOTDATA segment is freed. */
	ml_static_mfree((vm_offset_t)&kd_early_buffer, sizeof(kd_early_buffer));
#endif
}

int
kdbg_setpid(kd_regtype *kdr)
{
	pid_t pid;
	int flag, ret = 0;
	struct proc *p;

	pid = (pid_t)kdr->value1;
	flag = (int)kdr->value2;

	if (pid >= 0) {
		if ((p = proc_find(pid)) == NULL) {
			ret = ESRCH;
		} else {
			if (flag == 1) {
				/*
				 * turn on pid check for this and all pids
				 */
				kd_ctrl_page.kdebug_flags |= KDBG_PIDCHECK;
				kd_ctrl_page.kdebug_flags &= ~KDBG_PIDEXCLUDE;
				kdbg_set_flags(SLOW_CHECKS, 0, true);

				p->p_kdebug = 1;
			} else {
				/*
				 * turn off pid check for this pid value
				 * Don't turn off all pid checking though
				 *
				 * kd_ctrl_page.kdebug_flags &= ~KDBG_PIDCHECK;
				 */
				p->p_kdebug = 0;
			}
			proc_rele(p);
		}
	} else {
		ret = EINVAL;
	}

	return ret;
}

/* This is for pid exclusion in the trace buffer */
int
kdbg_setpidex(kd_regtype *kdr)
{
	pid_t pid;
	int flag, ret = 0;
	struct proc *p;

	pid = (pid_t)kdr->value1;
	flag = (int)kdr->value2;

	if (pid >= 0) {
		if ((p = proc_find(pid)) == NULL) {
			ret = ESRCH;
		} else {
			if (flag == 1) {
				/*
				 * turn on pid exclusion
				 */
				kd_ctrl_page.kdebug_flags |= KDBG_PIDEXCLUDE;
				kd_ctrl_page.kdebug_flags &= ~KDBG_PIDCHECK;
				kdbg_set_flags(SLOW_CHECKS, 0, true);

				p->p_kdebug = 1;
			} else {
				/*
				 * turn off pid exclusion for this pid value
				 * Don't turn off all pid exclusion though
				 *
				 * kd_ctrl_page.kdebug_flags &= ~KDBG_PIDEXCLUDE;
				 */
				p->p_kdebug = 0;
			}
			proc_rele(p);
		}
	} else {
		ret = EINVAL;
	}

	return ret;
}

/*
 * The following functions all operate on the "global" typefilter singleton.
 */

/*
 * The tf param is optional, you may pass either a valid typefilter or NULL.
 * If you pass a valid typefilter, you release ownership of that typefilter.
 */
static int
kdbg_initialize_typefilter(typefilter_t tf)
{
	ktrace_assert_lock_held();
	assert(!kdbg_typefilter);
	assert(!kdbg_typefilter_memory_entry);
	typefilter_t deallocate_tf = NULL;

	if (!tf && ((tf = deallocate_tf = typefilter_create()) == NULL)) {
		return ENOMEM;
	}

	if ((kdbg_typefilter_memory_entry = typefilter_create_memory_entry(tf)) == MACH_PORT_NULL) {
		if (deallocate_tf) {
			typefilter_deallocate(deallocate_tf);
		}
		return ENOMEM;
	}

	/*
	 * The atomic store closes a race window with
	 * the kdebug_typefilter syscall, which assumes
	 * that any non-null kdbg_typefilter means a
	 * valid memory_entry is available.
	 */
	os_atomic_store(&kdbg_typefilter, tf, release);

	return KERN_SUCCESS;
}

static int
kdbg_copyin_typefilter(user_addr_t addr, size_t size)
{
	int ret = ENOMEM;
	typefilter_t tf;

	ktrace_assert_lock_held();

	if (size != KDBG_TYPEFILTER_BITMAP_SIZE) {
		return EINVAL;
	}

	if ((tf = typefilter_create())) {
		if ((ret = copyin(addr, tf, KDBG_TYPEFILTER_BITMAP_SIZE)) == 0) {
			/* The kernel typefilter must always allow DBG_TRACE */
			typefilter_allow_class(tf, DBG_TRACE);

			/*
			 * If this is the first typefilter; claim it.
			 * Otherwise copy and deallocate.
			 *
			 * Allocating a typefilter for the copyin allows
			 * the kernel to hold the invariant that DBG_TRACE
			 * must always be allowed.
			 */
			if (!kdbg_typefilter) {
				if ((ret = kdbg_initialize_typefilter(tf))) {
					return ret;
				}
				tf = NULL;
			} else {
				typefilter_copy(kdbg_typefilter, tf);
			}

			kdbg_enable_typefilter();
			kdbg_iop_list_callback(kd_ctrl_page.kdebug_iops, KD_CALLBACK_TYPEFILTER_CHANGED, kdbg_typefilter);
		}

		if (tf) {
			typefilter_deallocate(tf);
		}
	}

	return ret;
}

/*
 * Enable the flags in the control page for the typefilter.  Assumes that
 * kdbg_typefilter has already been allocated, so events being written
 * don't see a bad typefilter.
 */
static void
kdbg_enable_typefilter(void)
{
	assert(kdbg_typefilter);
	kd_ctrl_page.kdebug_flags &= ~(KDBG_RANGECHECK | KDBG_VALCHECK);
	kd_ctrl_page.kdebug_flags |= KDBG_TYPEFILTER_CHECK;
	kdbg_set_flags(SLOW_CHECKS, 0, true);
	commpage_update_kdebug_state();
}

/*
 * Disable the flags in the control page for the typefilter.  The typefilter
 * may be safely deallocated shortly after this function returns.
 */
static void
kdbg_disable_typefilter(void)
{
	bool notify_iops = kd_ctrl_page.kdebug_flags & KDBG_TYPEFILTER_CHECK;
	kd_ctrl_page.kdebug_flags &= ~KDBG_TYPEFILTER_CHECK;

	if ((kd_ctrl_page.kdebug_flags & (KDBG_PIDCHECK | KDBG_PIDEXCLUDE))) {
		kdbg_set_flags(SLOW_CHECKS, 0, true);
	} else {
		kdbg_set_flags(SLOW_CHECKS, 0, false);
	}
	commpage_update_kdebug_state();

	if (notify_iops) {
		/*
		 * Notify IOPs that the typefilter will now allow everything.
		 * Otherwise, they won't know a typefilter is no longer in
		 * effect.
		 */
		typefilter_allow_all(kdbg_typefilter);
		kdbg_iop_list_callback(kd_ctrl_page.kdebug_iops,
		    KD_CALLBACK_TYPEFILTER_CHANGED, kdbg_typefilter);
	}
}

uint32_t
kdebug_commpage_state(void)
{
	if (kdebug_enable) {
		if (kd_ctrl_page.kdebug_flags & KDBG_TYPEFILTER_CHECK) {
			return KDEBUG_COMMPAGE_ENABLE_TYPEFILTER | KDEBUG_COMMPAGE_ENABLE_TRACE;
		}

		return KDEBUG_COMMPAGE_ENABLE_TRACE;
	}

	return 0;
}

int
kdbg_setreg(kd_regtype * kdr)
{
	int ret = 0;
	unsigned int val_1, val_2, val;
	switch (kdr->type) {
	case KDBG_CLASSTYPE:
		val_1 = (kdr->value1 & 0xff);
		val_2 = (kdr->value2 & 0xff);
		kdlog_beg = (val_1 << 24);
		kdlog_end = (val_2 << 24);
		kd_ctrl_page.kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
		kd_ctrl_page.kdebug_flags &= ~KDBG_VALCHECK;       /* Turn off specific value check  */
		kd_ctrl_page.kdebug_flags |= (KDBG_RANGECHECK | KDBG_CLASSTYPE);
		kdbg_set_flags(SLOW_CHECKS, 0, true);
		break;
	case KDBG_SUBCLSTYPE:
		val_1 = (kdr->value1 & 0xff);
		val_2 = (kdr->value2 & 0xff);
		val = val_2 + 1;
		kdlog_beg = ((val_1 << 24) | (val_2 << 16));
		kdlog_end = ((val_1 << 24) | (val << 16));
		kd_ctrl_page.kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
		kd_ctrl_page.kdebug_flags &= ~KDBG_VALCHECK;       /* Turn off specific value check  */
		kd_ctrl_page.kdebug_flags |= (KDBG_RANGECHECK | KDBG_SUBCLSTYPE);
		kdbg_set_flags(SLOW_CHECKS, 0, true);
		break;
	case KDBG_RANGETYPE:
		kdlog_beg = (kdr->value1);
		kdlog_end = (kdr->value2);
		kd_ctrl_page.kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
		kd_ctrl_page.kdebug_flags &= ~KDBG_VALCHECK;       /* Turn off specific value check  */
		kd_ctrl_page.kdebug_flags |= (KDBG_RANGECHECK | KDBG_RANGETYPE);
		kdbg_set_flags(SLOW_CHECKS, 0, true);
		break;
	case KDBG_VALCHECK:
		kdlog_value1 = (kdr->value1);
		kdlog_value2 = (kdr->value2);
		kdlog_value3 = (kdr->value3);
		kdlog_value4 = (kdr->value4);
		kd_ctrl_page.kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
		kd_ctrl_page.kdebug_flags &= ~KDBG_RANGECHECK;    /* Turn off range check */
		kd_ctrl_page.kdebug_flags |= KDBG_VALCHECK;       /* Turn on specific value check  */
		kdbg_set_flags(SLOW_CHECKS, 0, true);
		break;
	case KDBG_TYPENONE:
		kd_ctrl_page.kdebug_flags &= (unsigned int)~KDBG_CKTYPES;

		if ((kd_ctrl_page.kdebug_flags & (KDBG_RANGECHECK | KDBG_VALCHECK   |
		    KDBG_PIDCHECK   | KDBG_PIDEXCLUDE |
		    KDBG_TYPEFILTER_CHECK))) {
			kdbg_set_flags(SLOW_CHECKS, 0, true);
		} else {
			kdbg_set_flags(SLOW_CHECKS, 0, false);
		}

		kdlog_beg = 0;
		kdlog_end = 0;
		break;
	default:
		ret = EINVAL;
		break;
	}
	return ret;
}

static int
kdbg_write_to_vnode(caddr_t buffer, size_t size, vnode_t vp, vfs_context_t ctx, off_t file_offset)
{
	return vn_rdwr(UIO_WRITE, vp, buffer, size, file_offset, UIO_SYSSPACE, IO_NODELOCKED | IO_UNIT,
	           vfs_context_ucred(ctx), (int *) 0, vfs_context_proc(ctx));
}

int
kdbg_write_v3_chunk_header(user_addr_t buffer, uint32_t tag, uint32_t sub_tag, uint64_t length, vnode_t vp, vfs_context_t ctx)
{
	int ret = KERN_SUCCESS;
	kd_chunk_header_v3 header = {
		.tag = tag,
		.sub_tag = sub_tag,
		.length = length,
	};

	// Check that only one of them is valid
	assert(!buffer ^ !vp);
	assert((vp == NULL) || (ctx != NULL));

	// Write the 8-byte future_chunk_timestamp field in the payload
	if (buffer || vp) {
		if (vp) {
			ret = kdbg_write_to_vnode((caddr_t)&header, sizeof(kd_chunk_header_v3), vp, ctx, RAW_file_offset);
			if (ret) {
				goto write_error;
			}
			RAW_file_offset  += (sizeof(kd_chunk_header_v3));
		} else {
			ret = copyout(&header, buffer, sizeof(kd_chunk_header_v3));
			if (ret) {
				goto write_error;
			}
		}
	}
write_error:
	return ret;
}

static int
kdbg_write_v3_chunk_to_fd(uint32_t tag, uint32_t sub_tag, uint64_t length, void *payload, uint64_t payload_size, int fd)
{
	proc_t p;
	struct vfs_context context;
	struct fileproc *fp;
	vnode_t vp;
	p = current_proc();

	proc_fdlock(p);
	if ((fp_lookup(p, fd, &fp, 1))) {
		proc_fdunlock(p);
		return EFAULT;
	}

	context.vc_thread = current_thread();
	context.vc_ucred = fp->f_fglob->fg_cred;

	if (FILEGLOB_DTYPE(fp->f_fglob) != DTYPE_VNODE) {
		fp_drop(p, fd, fp, 1);
		proc_fdunlock(p);
		return EBADF;
	}
	vp = (struct vnode *) fp->f_fglob->fg_data;
	proc_fdunlock(p);

	if ((vnode_getwithref(vp)) == 0) {
		RAW_file_offset = fp->f_fglob->fg_offset;

		kd_chunk_header_v3 chunk_header = {
			.tag = tag,
			.sub_tag = sub_tag,
			.length = length,
		};

		int ret = kdbg_write_to_vnode((caddr_t)  &chunk_header, sizeof(kd_chunk_header_v3), vp, &context, RAW_file_offset);
		if (!ret) {
			RAW_file_offset += sizeof(kd_chunk_header_v3);
		}

		ret = kdbg_write_to_vnode((caddr_t) payload, (size_t) payload_size, vp, &context, RAW_file_offset);
		if (!ret) {
			RAW_file_offset  += payload_size;
		}

		fp->f_fglob->fg_offset = RAW_file_offset;
		vnode_put(vp);
	}

	fp_drop(p, fd, fp, 0);
	return KERN_SUCCESS;
}

user_addr_t
kdbg_write_v3_event_chunk_header(user_addr_t buffer, uint32_t tag, uint64_t length, vnode_t vp, vfs_context_t ctx)
{
	uint64_t future_chunk_timestamp = 0;
	length += sizeof(uint64_t);

	if (kdbg_write_v3_chunk_header(buffer, tag, V3_EVENT_DATA_VERSION, length, vp, ctx)) {
		return 0;
	}
	if (buffer) {
		buffer += sizeof(kd_chunk_header_v3);
	}

	// Check that only one of them is valid
	assert(!buffer ^ !vp);
	assert((vp == NULL) || (ctx != NULL));

	// Write the 8-byte future_chunk_timestamp field in the payload
	if (buffer || vp) {
		if (vp) {
			int ret = kdbg_write_to_vnode((caddr_t)&future_chunk_timestamp, sizeof(uint64_t), vp, ctx, RAW_file_offset);
			if (!ret) {
				RAW_file_offset  += (sizeof(uint64_t));
			}
		} else {
			if (copyout(&future_chunk_timestamp, buffer, sizeof(uint64_t))) {
				return 0;
			}
		}
	}

	return buffer + sizeof(uint64_t);
}

int
kdbg_write_v3_header(user_addr_t user_header, size_t *user_header_size, int fd)
{
	int ret = KERN_SUCCESS;

	uint8_t* cpumap = 0;
	uint32_t cpumap_size = 0;
	uint32_t thrmap_size = 0;

	size_t bytes_needed = 0;

	// Check that only one of them is valid
	assert(!user_header ^ !fd);
	assert(user_header_size);

	if (!(kd_ctrl_page.kdebug_flags & KDBG_BUFINIT)) {
		ret = EINVAL;
		goto bail;
	}

	if (!(user_header || fd)) {
		ret = EINVAL;
		goto bail;
	}

	// Initialize the cpu map
	ret = kdbg_cpumap_init_internal(kd_ctrl_page.kdebug_iops, kd_ctrl_page.kdebug_cpus, &cpumap, &cpumap_size);
	if (ret != KERN_SUCCESS) {
		goto bail;
	}

	// Check if a thread map is initialized
	if (!kd_mapptr) {
		ret = EINVAL;
		goto bail;
	}
	thrmap_size = kd_mapcount * sizeof(kd_threadmap);

	mach_timebase_info_data_t timebase = {0, 0};
	clock_timebase_info(&timebase);

	// Setup the header.
	// See v3 header description in sys/kdebug.h for more inforamtion.
	kd_header_v3 header = {
		.tag = RAW_VERSION3,
		.sub_tag = V3_HEADER_VERSION,
		.length = (sizeof(kd_header_v3) + cpumap_size - sizeof(kd_cpumap_header)),
		.timebase_numer = timebase.numer,
		.timebase_denom = timebase.denom,
		.timestamp = 0, /* FIXME rdar://problem/22053009 */
		.walltime_secs = 0,
		.walltime_usecs = 0,
		.timezone_minuteswest = 0,
		.timezone_dst = 0,
#if defined(__LP64__)
		.flags = 1,
#else
		.flags = 0,
#endif
	};

	// If its a buffer, check if we have enough space to copy the header and the maps.
	if (user_header) {
		bytes_needed = header.length + thrmap_size + (2 * sizeof(kd_chunk_header_v3));
		if (*user_header_size < bytes_needed) {
			ret = EINVAL;
			goto bail;
		}
	}

	// Start writing the header
	if (fd) {
		void *hdr_ptr = (void *)(((uintptr_t) &header) + sizeof(kd_chunk_header_v3));
		size_t payload_size = (sizeof(kd_header_v3) - sizeof(kd_chunk_header_v3));

		ret = kdbg_write_v3_chunk_to_fd(RAW_VERSION3, V3_HEADER_VERSION, header.length, hdr_ptr, payload_size, fd);
		if (ret) {
			goto bail;
		}
	} else {
		if (copyout(&header, user_header, sizeof(kd_header_v3))) {
			ret = EFAULT;
			goto bail;
		}
		// Update the user pointer
		user_header += sizeof(kd_header_v3);
	}

	// Write a cpu map. This is a sub chunk of the header
	cpumap = (uint8_t*)((uintptr_t) cpumap + sizeof(kd_cpumap_header));
	size_t payload_size = (size_t)(cpumap_size - sizeof(kd_cpumap_header));
	if (fd) {
		ret = kdbg_write_v3_chunk_to_fd(V3_CPU_MAP, V3_CPUMAP_VERSION, payload_size, (void *)cpumap, payload_size, fd);
		if (ret) {
			goto bail;
		}
	} else {
		ret = kdbg_write_v3_chunk_header(user_header, V3_CPU_MAP, V3_CPUMAP_VERSION, payload_size, NULL, NULL);
		if (ret) {
			goto bail;
		}
		user_header += sizeof(kd_chunk_header_v3);
		if (copyout(cpumap, user_header, payload_size)) {
			ret = EFAULT;
			goto bail;
		}
		// Update the user pointer
		user_header += payload_size;
	}

	// Write a thread map
	if (fd) {
		ret = kdbg_write_v3_chunk_to_fd(V3_THREAD_MAP, V3_THRMAP_VERSION, thrmap_size, (void *)kd_mapptr, thrmap_size, fd);
		if (ret) {
			goto bail;
		}
	} else {
		ret = kdbg_write_v3_chunk_header(user_header, V3_THREAD_MAP, V3_THRMAP_VERSION, thrmap_size, NULL, NULL);
		if (ret) {
			goto bail;
		}
		user_header += sizeof(kd_chunk_header_v3);
		if (copyout(kd_mapptr, user_header, thrmap_size)) {
			ret = EFAULT;
			goto bail;
		}
		user_header += thrmap_size;
	}

	if (fd) {
		RAW_file_written += bytes_needed;
	}

	*user_header_size = bytes_needed;
bail:
	if (cpumap) {
		kmem_free(kernel_map, (vm_offset_t)cpumap, cpumap_size);
	}
	return ret;
}

int
kdbg_readcpumap(user_addr_t user_cpumap, size_t *user_cpumap_size)
{
	uint8_t* cpumap = NULL;
	uint32_t cpumap_size = 0;
	int ret = KERN_SUCCESS;

	if (kd_ctrl_page.kdebug_flags & KDBG_BUFINIT) {
		if (kdbg_cpumap_init_internal(kd_ctrl_page.kdebug_iops, kd_ctrl_page.kdebug_cpus, &cpumap, &cpumap_size) == KERN_SUCCESS) {
			if (user_cpumap) {
				size_t bytes_to_copy = (*user_cpumap_size >= cpumap_size) ? cpumap_size : *user_cpumap_size;
				if (copyout(cpumap, user_cpumap, (size_t)bytes_to_copy)) {
					ret = EFAULT;
				}
			}
			*user_cpumap_size = cpumap_size;
			kmem_free(kernel_map, (vm_offset_t)cpumap, cpumap_size);
		} else {
			ret = EINVAL;
		}
	} else {
		ret = EINVAL;
	}

	return ret;
}

int
kdbg_readcurthrmap(user_addr_t buffer, size_t *bufsize)
{
	kd_threadmap *mapptr;
	unsigned int mapsize;
	unsigned int mapcount;
	unsigned int count = 0;
	int ret = 0;

	count = *bufsize / sizeof(kd_threadmap);
	*bufsize = 0;

	if ((mapptr = kdbg_thrmap_init_internal(count, &mapsize, &mapcount))) {
		if (copyout(mapptr, buffer, mapcount * sizeof(kd_threadmap))) {
			ret = EFAULT;
		} else {
			*bufsize = (mapcount * sizeof(kd_threadmap));
		}

		kmem_free(kernel_map, (vm_offset_t)mapptr, mapsize);
	} else {
		ret = EINVAL;
	}

	return ret;
}

static int
kdbg_write_v1_header(bool write_thread_map, vnode_t vp, vfs_context_t ctx)
{
	int ret = 0;
	RAW_header header;
	clock_sec_t secs;
	clock_usec_t usecs;
	char *pad_buf;
	uint32_t pad_size;
	uint32_t extra_thread_count = 0;
	uint32_t cpumap_size;
	size_t map_size = 0;
	size_t map_count = 0;

	if (write_thread_map) {
		assert(kd_ctrl_page.kdebug_flags & KDBG_MAPINIT);
		map_count = kd_mapcount;
		map_size = map_count * sizeof(kd_threadmap);
	}

	/*
	 * Without the buffers initialized, we cannot construct a CPU map or a
	 * thread map, and cannot write a header.
	 */
	if (!(kd_ctrl_page.kdebug_flags & KDBG_BUFINIT)) {
		return EINVAL;
	}

	/*
	 * To write a RAW_VERSION1+ file, we must embed a cpumap in the
	 * "padding" used to page align the events following the threadmap. If
	 * the threadmap happens to not require enough padding, we artificially
	 * increase its footprint until it needs enough padding.
	 */

	assert(vp);
	assert(ctx);

	pad_size = PAGE_16KB - ((sizeof(RAW_header) + map_size) & PAGE_MASK_64);
	cpumap_size = sizeof(kd_cpumap_header) + kd_ctrl_page.kdebug_cpus * sizeof(kd_cpumap);

	if (cpumap_size > pad_size) {
		/* If the cpu map doesn't fit in the current available pad_size,
		 * we increase the pad_size by 16K. We do this so that the event
		 * data is always  available on a page aligned boundary for both
		 * 4k and 16k systems. We enforce this alignment for the event
		 * data so that we can take advantage of optimized file/disk writes.
		 */
		pad_size += PAGE_16KB;
	}

	/* The way we are silently embedding a cpumap in the "padding" is by artificially
	 * increasing the number of thread entries. However, we'll also need to ensure that
	 * the cpumap is embedded in the last 4K page before when the event data is expected.
	 * This way the tools can read the data starting the next page boundary on both
	 * 4K and 16K systems preserving compatibility with older versions of the tools
	 */
	if (pad_size > PAGE_4KB) {
		pad_size -= PAGE_4KB;
		extra_thread_count = (pad_size / sizeof(kd_threadmap)) + 1;
	}

	memset(&header, 0, sizeof(header));
	header.version_no = RAW_VERSION1;
	header.thread_count = map_count + extra_thread_count;

	clock_get_calendar_microtime(&secs, &usecs);
	header.TOD_secs = secs;
	header.TOD_usecs = usecs;

	ret = vn_rdwr(UIO_WRITE, vp, (caddr_t)&header, sizeof(RAW_header), RAW_file_offset,
	    UIO_SYSSPACE, IO_NODELOCKED | IO_UNIT, vfs_context_ucred(ctx), (int *) 0, vfs_context_proc(ctx));
	if (ret) {
		goto write_error;
	}
	RAW_file_offset += sizeof(RAW_header);
	RAW_file_written += sizeof(RAW_header);

	if (write_thread_map) {
		ret = vn_rdwr(UIO_WRITE, vp, (caddr_t)kd_mapptr, map_size, RAW_file_offset,
		    UIO_SYSSPACE, IO_NODELOCKED | IO_UNIT, vfs_context_ucred(ctx), (int *) 0, vfs_context_proc(ctx));
		if (ret) {
			goto write_error;
		}

		RAW_file_offset += map_size;
		RAW_file_written += map_size;
	}

	if (extra_thread_count) {
		pad_size = extra_thread_count * sizeof(kd_threadmap);
		pad_buf = kalloc(pad_size);
		if (!pad_buf) {
			ret = ENOMEM;
			goto write_error;
		}
		memset(pad_buf, 0, pad_size);

		ret = vn_rdwr(UIO_WRITE, vp, (caddr_t)pad_buf, pad_size, RAW_file_offset,
		    UIO_SYSSPACE, IO_NODELOCKED | IO_UNIT, vfs_context_ucred(ctx), (int *) 0, vfs_context_proc(ctx));
		kfree(pad_buf, pad_size);
		if (ret) {
			goto write_error;
		}

		RAW_file_offset += pad_size;
		RAW_file_written += pad_size;
	}

	pad_size = PAGE_SIZE - (RAW_file_offset & PAGE_MASK_64);
	if (pad_size) {
		pad_buf = (char *)kalloc(pad_size);
		if (!pad_buf) {
			ret = ENOMEM;
			goto write_error;
		}
		memset(pad_buf, 0, pad_size);

		/*
		 * embed a cpumap in the padding bytes.
		 * older code will skip this.
		 * newer code will know how to read it.
		 */
		uint32_t temp = pad_size;
		if (kdbg_cpumap_init_internal(kd_ctrl_page.kdebug_iops, kd_ctrl_page.kdebug_cpus, (uint8_t**)&pad_buf, &temp) != KERN_SUCCESS) {
			memset(pad_buf, 0, pad_size);
		}

		ret = vn_rdwr(UIO_WRITE, vp, (caddr_t)pad_buf, pad_size, RAW_file_offset,
		    UIO_SYSSPACE, IO_NODELOCKED | IO_UNIT, vfs_context_ucred(ctx), (int *) 0, vfs_context_proc(ctx));
		kfree(pad_buf, pad_size);
		if (ret) {
			goto write_error;
		}

		RAW_file_offset += pad_size;
		RAW_file_written += pad_size;
	}

write_error:
	return ret;
}

static void
kdbg_clear_thread_map(void)
{
	ktrace_assert_lock_held();

	if (kd_ctrl_page.kdebug_flags & KDBG_MAPINIT) {
		assert(kd_mapptr != NULL);
		kmem_free(kernel_map, (vm_offset_t)kd_mapptr, kd_mapsize);
		kd_mapptr = NULL;
		kd_mapsize = 0;
		kd_mapcount = 0;
		kd_ctrl_page.kdebug_flags &= ~KDBG_MAPINIT;
	}
}

/*
 * Write out a version 1 header and the thread map, if it is initialized, to a
 * vnode.  Used by KDWRITEMAP and kdbg_dump_trace_to_file.
 *
 * Returns write errors from vn_rdwr if a write fails.  Returns ENODATA if the
 * thread map has not been initialized, but the header will still be written.
 * Returns ENOMEM if padding could not be allocated.  Returns 0 otherwise.
 */
static int
kdbg_write_thread_map(vnode_t vp, vfs_context_t ctx)
{
	int ret = 0;
	bool map_initialized;

	ktrace_assert_lock_held();
	assert(ctx != NULL);

	map_initialized = (kd_ctrl_page.kdebug_flags & KDBG_MAPINIT);

	ret = kdbg_write_v1_header(map_initialized, vp, ctx);
	if (ret == 0) {
		if (map_initialized) {
			kdbg_clear_thread_map();
		} else {
			ret = ENODATA;
		}
	}

	return ret;
}

/*
 * Copy out the thread map to a user space buffer.  Used by KDTHRMAP.
 *
 * Returns copyout errors if the copyout fails.  Returns ENODATA if the thread
 * map has not been initialized.  Returns EINVAL if the buffer provided is not
 * large enough for the entire thread map.  Returns 0 otherwise.
 */
static int
kdbg_copyout_thread_map(user_addr_t buffer, size_t *buffer_size)
{
	bool map_initialized;
	size_t map_size;
	int ret = 0;

	ktrace_assert_lock_held();
	assert(buffer_size != NULL);

	map_initialized = (kd_ctrl_page.kdebug_flags & KDBG_MAPINIT);
	if (!map_initialized) {
		return ENODATA;
	}

	map_size = kd_mapcount * sizeof(kd_threadmap);
	if (*buffer_size < map_size) {
		return EINVAL;
	}

	ret = copyout(kd_mapptr, buffer, map_size);
	if (ret == 0) {
		kdbg_clear_thread_map();
	}

	return ret;
}

int
kdbg_readthrmap_v3(user_addr_t buffer, size_t buffer_size, int fd)
{
	int ret = 0;
	bool map_initialized;
	size_t map_size;

	ktrace_assert_lock_held();

	if ((!fd && !buffer) || (fd && buffer)) {
		return EINVAL;
	}

	map_initialized = (kd_ctrl_page.kdebug_flags & KDBG_MAPINIT);
	map_size = kd_mapcount * sizeof(kd_threadmap);

	if (map_initialized && (buffer_size >= map_size)) {
		ret = kdbg_write_v3_header(buffer, &buffer_size, fd);

		if (ret == 0) {
			kdbg_clear_thread_map();
		}
	} else {
		ret = EINVAL;
	}

	return ret;
}

static void
kdbg_set_nkdbufs(unsigned int req_nkdbufs)
{
	/*
	 * Only allow allocation up to half the available memory (sane_size).
	 */
	uint64_t max_nkdbufs = (sane_size / 2) / sizeof(kd_buf);
	nkdbufs = (req_nkdbufs > max_nkdbufs) ? max_nkdbufs : req_nkdbufs;
}

/*
 * Block until there are `n_storage_threshold` storage units filled with
 * events or `timeout_ms` milliseconds have passed.  If `locked_wait` is true,
 * `ktrace_lock` is held while waiting.  This is necessary while waiting to
 * write events out of the buffers.
 *
 * Returns true if the threshold was reached and false otherwise.
 *
 * Called with `ktrace_lock` locked and interrupts enabled.
 */
static bool
kdbg_wait(uint64_t timeout_ms, bool locked_wait)
{
	int wait_result = THREAD_AWAKENED;
	uint64_t abstime = 0;

	ktrace_assert_lock_held();

	if (timeout_ms != 0) {
		uint64_t ns = timeout_ms * NSEC_PER_MSEC;
		nanoseconds_to_absolutetime(ns, &abstime);
		clock_absolutetime_interval_to_deadline(abstime, &abstime);
	}

	bool s = ml_set_interrupts_enabled(false);
	if (!s) {
		panic("kdbg_wait() called with interrupts disabled");
	}
	lck_spin_lock_grp(kdw_spin_lock, kdebug_lck_grp);

	if (!locked_wait) {
		/* drop the mutex to allow others to access trace */
		ktrace_unlock();
	}

	while (wait_result == THREAD_AWAKENED &&
	    kd_ctrl_page.kds_inuse_count < n_storage_threshold) {
		kds_waiter = 1;

		if (abstime) {
			wait_result = lck_spin_sleep_deadline(kdw_spin_lock, 0, &kds_waiter, THREAD_ABORTSAFE, abstime);
		} else {
			wait_result = lck_spin_sleep(kdw_spin_lock, 0, &kds_waiter, THREAD_ABORTSAFE);
		}

		kds_waiter = 0;
	}

	/* check the count under the spinlock */
	bool threshold_exceeded = (kd_ctrl_page.kds_inuse_count >= n_storage_threshold);

	lck_spin_unlock(kdw_spin_lock);
	ml_set_interrupts_enabled(s);

	if (!locked_wait) {
		/* pick the mutex back up again */
		ktrace_lock();
	}

	/* write out whether we've exceeded the threshold */
	return threshold_exceeded;
}

/*
 * Wakeup a thread waiting using `kdbg_wait` if there are at least
 * `n_storage_threshold` storage units in use.
 */
static void
kdbg_wakeup(void)
{
	bool need_kds_wakeup = false;

	/*
	 * Try to take the lock here to synchronize with the waiter entering
	 * the blocked state.  Use the try mode to prevent deadlocks caused by
	 * re-entering this routine due to various trace points triggered in the
	 * lck_spin_sleep_xxxx routines used to actually enter one of our 2 wait
	 * conditions.  No problem if we fail, there will be lots of additional
	 * events coming in that will eventually succeed in grabbing this lock.
	 */
	bool s = ml_set_interrupts_enabled(false);

	if (lck_spin_try_lock(kdw_spin_lock)) {
		if (kds_waiter &&
		    (kd_ctrl_page.kds_inuse_count >= n_storage_threshold)) {
			kds_waiter = 0;
			need_kds_wakeup = true;
		}
		lck_spin_unlock(kdw_spin_lock);
	}

	ml_set_interrupts_enabled(s);

	if (need_kds_wakeup == true) {
		wakeup(&kds_waiter);
	}
}

int
kdbg_control(int *name, u_int namelen, user_addr_t where, size_t *sizep)
{
	int ret = 0;
	size_t size = *sizep;
	unsigned int value = 0;
	kd_regtype kd_Reg;
	kbufinfo_t kd_bufinfo;
	proc_t p;

	if (name[0] == KERN_KDWRITETR ||
	    name[0] == KERN_KDWRITETR_V3 ||
	    name[0] == KERN_KDWRITEMAP ||
	    name[0] == KERN_KDWRITEMAP_V3 ||
	    name[0] == KERN_KDEFLAGS ||
	    name[0] == KERN_KDDFLAGS ||
	    name[0] == KERN_KDENABLE ||
	    name[0] == KERN_KDSETBUF) {
		if (namelen < 2) {
			return EINVAL;
		}
		value = name[1];
	}

	kdbg_lock_init();
	assert(kd_ctrl_page.kdebug_flags & KDBG_LOCKINIT);

	ktrace_lock();

	/*
	 * Some requests only require "read" access to kdebug trace.  Regardless,
	 * tell ktrace that a configuration or read is occurring (and see if it's
	 * allowed).
	 */
	if (name[0] != KERN_KDGETBUF &&
	    name[0] != KERN_KDGETREG &&
	    name[0] != KERN_KDREADCURTHRMAP) {
		if ((ret = ktrace_configure(KTRACE_KDEBUG))) {
			goto out;
		}
	} else {
		if ((ret = ktrace_read_check())) {
			goto out;
		}
	}

	switch (name[0]) {
	case KERN_KDGETBUF:
		if (size < sizeof(kd_bufinfo.nkdbufs)) {
			/*
			 * There is not enough room to return even
			 * the first element of the info structure.
			 */
			ret = EINVAL;
			break;
		}

		memset(&kd_bufinfo, 0, sizeof(kd_bufinfo));

		kd_bufinfo.nkdbufs = nkdbufs;
		kd_bufinfo.nkdthreads = kd_mapcount;

		if ((kd_ctrl_page.kdebug_slowcheck & SLOW_NOLOG)) {
			kd_bufinfo.nolog = 1;
		} else {
			kd_bufinfo.nolog = 0;
		}

		kd_bufinfo.flags = kd_ctrl_page.kdebug_flags;
#if defined(__LP64__)
		kd_bufinfo.flags |= KDBG_LP64;
#endif
		{
			int pid = ktrace_get_owning_pid();
			kd_bufinfo.bufid = (pid == 0 ? -1 : pid);
		}

		if (size >= sizeof(kd_bufinfo)) {
			/*
			 * Provide all the info we have
			 */
			if (copyout(&kd_bufinfo, where, sizeof(kd_bufinfo))) {
				ret = EINVAL;
			}
		} else {
			/*
			 * For backwards compatibility, only provide
			 * as much info as there is room for.
			 */
			if (copyout(&kd_bufinfo, where, size)) {
				ret = EINVAL;
			}
		}
		break;

	case KERN_KDREADCURTHRMAP:
		ret = kdbg_readcurthrmap(where, sizep);
		break;

	case KERN_KDEFLAGS:
		value &= KDBG_USERFLAGS;
		kd_ctrl_page.kdebug_flags |= value;
		break;

	case KERN_KDDFLAGS:
		value &= KDBG_USERFLAGS;
		kd_ctrl_page.kdebug_flags &= ~value;
		break;

	case KERN_KDENABLE:
		/*
		 * Enable tracing mechanism.  Two types:
		 * KDEBUG_TRACE is the standard one,
		 * and KDEBUG_PPT which is a carefully
		 * chosen subset to avoid performance impact.
		 */
		if (value) {
			/*
			 * enable only if buffer is initialized
			 */
			if (!(kd_ctrl_page.kdebug_flags & KDBG_BUFINIT) ||
			    !(value == KDEBUG_ENABLE_TRACE || value == KDEBUG_ENABLE_PPT)) {
				ret = EINVAL;
				break;
			}
			kdbg_thrmap_init();

			kdbg_set_tracing_enabled(true, value);
		} else {
			if (!kdebug_enable) {
				break;
			}

			kernel_debug_disable();
		}
		break;

	case KERN_KDSETBUF:
		kdbg_set_nkdbufs(value);
		break;

	case KERN_KDSETUP:
		ret = kdbg_reinit(false);
		break;

	case KERN_KDREMOVE:
		ktrace_reset(KTRACE_KDEBUG);
		break;

	case KERN_KDSETREG:
		if (size < sizeof(kd_regtype)) {
			ret = EINVAL;
			break;
		}
		if (copyin(where, &kd_Reg, sizeof(kd_regtype))) {
			ret = EINVAL;
			break;
		}

		ret = kdbg_setreg(&kd_Reg);
		break;

	case KERN_KDGETREG:
		ret = EINVAL;
		break;

	case KERN_KDREADTR:
		ret = kdbg_read(where, sizep, NULL, NULL, RAW_VERSION1);
		break;

	case KERN_KDWRITETR:
	case KERN_KDWRITETR_V3:
	case KERN_KDWRITEMAP:
	case KERN_KDWRITEMAP_V3:
	{
		struct  vfs_context context;
		struct  fileproc *fp;
		size_t  number;
		vnode_t vp;
		int     fd;

		if (name[0] == KERN_KDWRITETR || name[0] == KERN_KDWRITETR_V3) {
			(void)kdbg_wait(size, true);
		}
		p = current_proc();
		fd = value;

		proc_fdlock(p);
		if ((ret = fp_lookup(p, fd, &fp, 1))) {
			proc_fdunlock(p);
			break;
		}
		context.vc_thread = current_thread();
		context.vc_ucred = fp->f_fglob->fg_cred;

		if (FILEGLOB_DTYPE(fp->f_fglob) != DTYPE_VNODE) {
			fp_drop(p, fd, fp, 1);
			proc_fdunlock(p);

			ret = EBADF;
			break;
		}
		vp = (struct vnode *)fp->f_fglob->fg_data;
		proc_fdunlock(p);

		if ((ret = vnode_getwithref(vp)) == 0) {
			RAW_file_offset = fp->f_fglob->fg_offset;
			if (name[0] == KERN_KDWRITETR || name[0] == KERN_KDWRITETR_V3) {
				number = nkdbufs * sizeof(kd_buf);

				KDBG_RELEASE(TRACE_WRITING_EVENTS | DBG_FUNC_START);
				if (name[0] == KERN_KDWRITETR_V3) {
					ret = kdbg_read(0, &number, vp, &context, RAW_VERSION3);
				} else {
					ret = kdbg_read(0, &number, vp, &context, RAW_VERSION1);
				}
				KDBG_RELEASE(TRACE_WRITING_EVENTS | DBG_FUNC_END, number);

				*sizep = number;
			} else {
				number = kd_mapcount * sizeof(kd_threadmap);
				if (name[0] == KERN_KDWRITEMAP_V3) {
					ret = kdbg_readthrmap_v3(0, number, fd);
				} else {
					ret = kdbg_write_thread_map(vp, &context);
				}
			}
			fp->f_fglob->fg_offset = RAW_file_offset;
			vnode_put(vp);
		}
		fp_drop(p, fd, fp, 0);

		break;
	}
	case KERN_KDBUFWAIT:
		*sizep = kdbg_wait(size, false);
		break;

	case KERN_KDPIDTR:
		if (size < sizeof(kd_regtype)) {
			ret = EINVAL;
			break;
		}
		if (copyin(where, &kd_Reg, sizeof(kd_regtype))) {
			ret = EINVAL;
			break;
		}

		ret = kdbg_setpid(&kd_Reg);
		break;

	case KERN_KDPIDEX:
		if (size < sizeof(kd_regtype)) {
			ret = EINVAL;
			break;
		}
		if (copyin(where, &kd_Reg, sizeof(kd_regtype))) {
			ret = EINVAL;
			break;
		}

		ret = kdbg_setpidex(&kd_Reg);
		break;

	case KERN_KDCPUMAP:
		ret = kdbg_readcpumap(where, sizep);
		break;

	case KERN_KDTHRMAP:
		ret = kdbg_copyout_thread_map(where, sizep);
		break;

	case KERN_KDSET_TYPEFILTER: {
		ret = kdbg_copyin_typefilter(where, size);
		break;
	}

	case KERN_KDTEST:
		ret = kdbg_test(size);
		break;

	default:
		ret = EINVAL;
		break;
	}
out:
	ktrace_unlock();

	return ret;
}


/*
 * This code can run for the most part concurrently with kernel_debug_internal()...
 * 'release_storage_unit' will take the kds_spin_lock which may cause us to briefly
 * synchronize with the recording side of this puzzle... otherwise, we are able to
 * move through the lists w/o use of any locks
 */
int
kdbg_read(user_addr_t buffer, size_t *number, vnode_t vp, vfs_context_t ctx, uint32_t file_version)
{
	unsigned int count;
	unsigned int cpu, min_cpu;
	uint64_t barrier_min = 0, barrier_max = 0, t, earliest_time;
	int error = 0;
	kd_buf *tempbuf;
	uint32_t rcursor;
	kd_buf lostevent;
	union kds_ptr kdsp;
	bool traced_retrograde = false;
	struct kd_storage *kdsp_actual;
	struct kd_bufinfo *kdbp;
	struct kd_bufinfo *min_kdbp;
	uint32_t tempbuf_count;
	uint32_t tempbuf_number;
	uint32_t old_kdebug_flags;
	uint32_t old_kdebug_slowcheck;
	bool out_of_events = false;
	bool wrapped = false;

	assert(number);
	count = *number / sizeof(kd_buf);
	*number = 0;

	ktrace_assert_lock_held();

	if (count == 0 || !(kd_ctrl_page.kdebug_flags & KDBG_BUFINIT) || kdcopybuf == 0) {
		return EINVAL;
	}

	thread_set_eager_preempt(current_thread());

	memset(&lostevent, 0, sizeof(lostevent));
	lostevent.debugid = TRACE_LOST_EVENTS;

	/*
	 * Request each IOP to provide us with up to date entries before merging
	 * buffers together.
	 */
	kdbg_iop_list_callback(kd_ctrl_page.kdebug_iops, KD_CALLBACK_SYNC_FLUSH, NULL);

	/*
	 * Capture the current time.  Only sort events that have occured
	 * before now.  Since the IOPs are being flushed here, it is possible
	 * that events occur on the AP while running live tracing.
	 */
	barrier_max = kdbg_timestamp() & KDBG_TIMESTAMP_MASK;

	/*
	 * Disable wrap so storage units cannot be stolen out from underneath us
	 * while merging events.
	 *
	 * Because we hold ktrace_lock, no other control threads can be playing
	 * with kdebug_flags.  The code that emits new events could be running,
	 * but it grabs kds_spin_lock if it needs to acquire a new storage
	 * chunk, which is where it examines kdebug_flags.  If it is adding to
	 * the same chunk we're reading from, check for that below.
	 */
	wrapped = disable_wrap(&old_kdebug_slowcheck, &old_kdebug_flags);

	if (count > nkdbufs) {
		count = nkdbufs;
	}

	if ((tempbuf_count = count) > KDCOPYBUF_COUNT) {
		tempbuf_count = KDCOPYBUF_COUNT;
	}

	/*
	 * If the buffers have wrapped, do not emit additional lost events for the
	 * oldest storage units.
	 */
	if (wrapped) {
		kd_ctrl_page.kdebug_flags &= ~KDBG_WRAPPED;

		for (cpu = 0, kdbp = &kdbip[0]; cpu < kd_ctrl_page.kdebug_cpus; cpu++, kdbp++) {
			if ((kdsp = kdbp->kd_list_head).raw == KDS_PTR_NULL) {
				continue;
			}
			kdsp_actual = POINTER_FROM_KDS_PTR(kdsp);
			kdsp_actual->kds_lostevents = false;
		}
	}
	/*
	 * Capture the earliest time where there are events for all CPUs and don't
	 * emit events with timestamps prior.
	 */
	barrier_min = kd_ctrl_page.oldest_time;

	while (count) {
		tempbuf = kdcopybuf;
		tempbuf_number = 0;

		if (wrapped) {
			/*
			 * Emit a lost events tracepoint to indicate that previous events
			 * were lost -- the thread map cannot be trusted.  A new one must
			 * be taken so tools can analyze the trace in a backwards-facing
			 * fashion.
			 */
			kdbg_set_timestamp_and_cpu(&lostevent, barrier_min, 0);
			*tempbuf = lostevent;
			wrapped = false;
			goto nextevent;
		}

		/* While space left in merged events scratch buffer. */
		while (tempbuf_count) {
			bool lostevents = false;
			int lostcpu = 0;
			earliest_time = UINT64_MAX;
			min_kdbp = NULL;
			min_cpu = 0;

			/* Check each CPU's buffers for the earliest event. */
			for (cpu = 0, kdbp = &kdbip[0]; cpu < kd_ctrl_page.kdebug_cpus; cpu++, kdbp++) {
				/* Skip CPUs without data in their oldest storage unit. */
				if ((kdsp = kdbp->kd_list_head).raw == KDS_PTR_NULL) {
next_cpu:
					continue;
				}
				/* From CPU data to buffer header to buffer. */
				kdsp_actual = POINTER_FROM_KDS_PTR(kdsp);

next_event:
				/* The next event to be read from this buffer. */
				rcursor = kdsp_actual->kds_readlast;

				/* Skip this buffer if there are no events left. */
				if (rcursor == kdsp_actual->kds_bufindx) {
					continue;
				}

				/*
				 * Check that this storage unit wasn't stolen and events were
				 * lost.  This must have happened while wrapping was disabled
				 * in this function.
				 */
				if (kdsp_actual->kds_lostevents) {
					lostevents = true;
					kdsp_actual->kds_lostevents = false;

					/*
					 * The earliest event we can trust is the first one in this
					 * stolen storage unit.
					 */
					uint64_t lost_time =
					    kdbg_get_timestamp(&kdsp_actual->kds_records[0]);
					if (kd_ctrl_page.oldest_time < lost_time) {
						/*
						 * If this is the first time we've seen lost events for
						 * this gap, record its timestamp as the oldest
						 * timestamp we're willing to merge for the lost events
						 * tracepoint.
						 */
						kd_ctrl_page.oldest_time = barrier_min = lost_time;
						lostcpu = cpu;
					}
				}

				t = kdbg_get_timestamp(&kdsp_actual->kds_records[rcursor]);

				if (t > barrier_max) {
					if (kdbg_debug) {
						printf("kdebug: FUTURE EVENT: debugid %#8x: "
						    "time %lld from CPU %u "
						    "(barrier at time %lld, read %lu events)\n",
						    kdsp_actual->kds_records[rcursor].debugid,
						    t, cpu, barrier_max, *number + tempbuf_number);
					}
					goto next_cpu;
				}
				if (t < kdsp_actual->kds_timestamp) {
					/*
					 * This indicates the event emitter hasn't completed
					 * filling in the event (becuase we're looking at the
					 * buffer that the record head is using).  The max barrier
					 * timestamp should have saved us from seeing these kinds
					 * of things, but other CPUs might be slow on the up-take.
					 *
					 * Bail out so we don't get out-of-order events by
					 * continuing to read events from other CPUs' events.
					 */
					out_of_events = true;
					break;
				}

				/*
				 * Ignore events that have aged out due to wrapping or storage
				 * unit exhaustion while merging events.
				 */
				if (t < barrier_min) {
					kdsp_actual->kds_readlast++;
					if (kdbg_debug) {
						printf("kdebug: PAST EVENT: debugid %#8x: "
						    "time %lld from CPU %u "
						    "(barrier at time %lld)\n",
						    kdsp_actual->kds_records[rcursor].debugid,
						    t, cpu, barrier_min);
					}

					if (kdsp_actual->kds_readlast >= EVENTS_PER_STORAGE_UNIT) {
						release_storage_unit(cpu, kdsp.raw);

						if ((kdsp = kdbp->kd_list_head).raw == KDS_PTR_NULL) {
							goto next_cpu;
						}
						kdsp_actual = POINTER_FROM_KDS_PTR(kdsp);
					}

					goto next_event;
				}

				/*
				 * Don't worry about merging any events -- just walk through
				 * the CPUs and find the latest timestamp of lost events.
				 */
				if (lostevents) {
					continue;
				}

				if (t < earliest_time) {
					earliest_time = t;
					min_kdbp = kdbp;
					min_cpu = cpu;
				}
			}
			if (lostevents) {
				/*
				 * If any lost events were hit in the buffers, emit an event
				 * with the latest timestamp.
				 */
				kdbg_set_timestamp_and_cpu(&lostevent, barrier_min, lostcpu);
				*tempbuf = lostevent;
				tempbuf->arg1 = 1;
				goto nextevent;
			}
			if (min_kdbp == NULL) {
				/* All buffers ran empty. */
				out_of_events = true;
			}
			if (out_of_events) {
				break;
			}

			kdsp = min_kdbp->kd_list_head;
			kdsp_actual = POINTER_FROM_KDS_PTR(kdsp);

			/* Copy earliest event into merged events scratch buffer. */
			*tempbuf = kdsp_actual->kds_records[kdsp_actual->kds_readlast++];

			if (kdsp_actual->kds_readlast == EVENTS_PER_STORAGE_UNIT) {
				release_storage_unit(min_cpu, kdsp.raw);
			}

			/*
			 * Watch for out of order timestamps (from IOPs).
			 */
			if (earliest_time < min_kdbp->kd_prev_timebase) {
				/*
				 * If we haven't already, emit a retrograde events event.
				 * Otherwise, ignore this event.
				 */
				if (traced_retrograde) {
					continue;
				}

				kdbg_set_timestamp_and_cpu(tempbuf, min_kdbp->kd_prev_timebase, kdbg_get_cpu(tempbuf));
				tempbuf->arg1 = tempbuf->debugid;
				tempbuf->arg2 = earliest_time;
				tempbuf->arg3 = 0;
				tempbuf->arg4 = 0;
				tempbuf->debugid = TRACE_RETROGRADE_EVENTS;
				traced_retrograde = true;
			} else {
				min_kdbp->kd_prev_timebase = earliest_time;
			}
nextevent:
			tempbuf_count--;
			tempbuf_number++;
			tempbuf++;

			if ((RAW_file_written += sizeof(kd_buf)) >= RAW_FLUSH_SIZE) {
				break;
			}
		}
		if (tempbuf_number) {
			/*
			 * Remember the latest timestamp of events that we've merged so we
			 * don't think we've lost events later.
			 */
			uint64_t latest_time = kdbg_get_timestamp(tempbuf - 1);
			if (kd_ctrl_page.oldest_time < latest_time) {
				kd_ctrl_page.oldest_time = latest_time;
			}
			if (file_version == RAW_VERSION3) {
				if (!(kdbg_write_v3_event_chunk_header(buffer, V3_RAW_EVENTS, (tempbuf_number * sizeof(kd_buf)), vp, ctx))) {
					error = EFAULT;
					goto check_error;
				}
				if (buffer) {
					buffer += (sizeof(kd_chunk_header_v3) + sizeof(uint64_t));
				}

				assert(count >= (sizeof(kd_chunk_header_v3) + sizeof(uint64_t)));
				count -= (sizeof(kd_chunk_header_v3) + sizeof(uint64_t));
				*number += (sizeof(kd_chunk_header_v3) + sizeof(uint64_t));
			}
			if (vp) {
				size_t write_size = tempbuf_number * sizeof(kd_buf);
				error = kdbg_write_to_vnode((caddr_t)kdcopybuf, write_size, vp, ctx, RAW_file_offset);
				if (!error) {
					RAW_file_offset += write_size;
				}

				if (RAW_file_written >= RAW_FLUSH_SIZE) {
					error = VNOP_FSYNC(vp, MNT_NOWAIT, ctx);

					RAW_file_written = 0;
				}
			} else {
				error = copyout(kdcopybuf, buffer, tempbuf_number * sizeof(kd_buf));
				buffer += (tempbuf_number * sizeof(kd_buf));
			}
check_error:
			if (error) {
				*number = 0;
				error = EINVAL;
				break;
			}
			count   -= tempbuf_number;
			*number += tempbuf_number;
		}
		if (out_of_events == true) {
			/*
			 * all trace buffers are empty
			 */
			break;
		}

		if ((tempbuf_count = count) > KDCOPYBUF_COUNT) {
			tempbuf_count = KDCOPYBUF_COUNT;
		}
	}
	if (!(old_kdebug_flags & KDBG_NOWRAP)) {
		enable_wrap(old_kdebug_slowcheck);
	}
	thread_clear_eager_preempt(current_thread());
	return error;
}

#define KDEBUG_TEST_CODE(code) BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, (code))

/*
 * A test IOP for the SYNC_FLUSH callback.
 */

static int sync_flush_iop = 0;

static void
sync_flush_callback(void * __unused context, kd_callback_type reason,
    void * __unused arg)
{
	assert(sync_flush_iop > 0);

	if (reason == KD_CALLBACK_SYNC_FLUSH) {
		kernel_debug_enter(sync_flush_iop, KDEBUG_TEST_CODE(0xff),
		    kdbg_timestamp(), 0, 0, 0, 0, 0);
	}
}

static struct kd_callback sync_flush_kdcb = {
	.func = sync_flush_callback,
	.iop_name = "test_sf",
};

static int
kdbg_test(size_t flavor)
{
	int code = 0;
	int dummy_iop = 0;

	switch (flavor) {
	case 1:
		/* try each macro */
		KDBG(KDEBUG_TEST_CODE(code)); code++;
		KDBG(KDEBUG_TEST_CODE(code), 1); code++;
		KDBG(KDEBUG_TEST_CODE(code), 1, 2); code++;
		KDBG(KDEBUG_TEST_CODE(code), 1, 2, 3); code++;
		KDBG(KDEBUG_TEST_CODE(code), 1, 2, 3, 4); code++;

		KDBG_RELEASE(KDEBUG_TEST_CODE(code)); code++;
		KDBG_RELEASE(KDEBUG_TEST_CODE(code), 1); code++;
		KDBG_RELEASE(KDEBUG_TEST_CODE(code), 1, 2); code++;
		KDBG_RELEASE(KDEBUG_TEST_CODE(code), 1, 2, 3); code++;
		KDBG_RELEASE(KDEBUG_TEST_CODE(code), 1, 2, 3, 4); code++;

		KDBG_FILTERED(KDEBUG_TEST_CODE(code)); code++;
		KDBG_FILTERED(KDEBUG_TEST_CODE(code), 1); code++;
		KDBG_FILTERED(KDEBUG_TEST_CODE(code), 1, 2); code++;
		KDBG_FILTERED(KDEBUG_TEST_CODE(code), 1, 2, 3); code++;
		KDBG_FILTERED(KDEBUG_TEST_CODE(code), 1, 2, 3, 4); code++;

		KDBG_RELEASE_NOPROCFILT(KDEBUG_TEST_CODE(code)); code++;
		KDBG_RELEASE_NOPROCFILT(KDEBUG_TEST_CODE(code), 1); code++;
		KDBG_RELEASE_NOPROCFILT(KDEBUG_TEST_CODE(code), 1, 2); code++;
		KDBG_RELEASE_NOPROCFILT(KDEBUG_TEST_CODE(code), 1, 2, 3); code++;
		KDBG_RELEASE_NOPROCFILT(KDEBUG_TEST_CODE(code), 1, 2, 3, 4); code++;

		KDBG_DEBUG(KDEBUG_TEST_CODE(code)); code++;
		KDBG_DEBUG(KDEBUG_TEST_CODE(code), 1); code++;
		KDBG_DEBUG(KDEBUG_TEST_CODE(code), 1, 2); code++;
		KDBG_DEBUG(KDEBUG_TEST_CODE(code), 1, 2, 3); code++;
		KDBG_DEBUG(KDEBUG_TEST_CODE(code), 1, 2, 3, 4); code++;
		break;

	case 2:
		if (kd_ctrl_page.kdebug_iops) {
			/* avoid the assertion in kernel_debug_enter for a valid IOP */
			dummy_iop = kd_ctrl_page.kdebug_iops[0].cpu_id;
		}

		/* ensure old timestamps are not emitted from kernel_debug_enter */
		kernel_debug_enter(dummy_iop, KDEBUG_TEST_CODE(code),
		    100 /* very old timestamp */, 0, 0, 0, 0, 0);
		code++;
		kernel_debug_enter(dummy_iop, KDEBUG_TEST_CODE(code),
		    kdbg_timestamp(), 0, 0, 0, 0, 0);
		code++;
		break;

	case 3:
		if (kd_ctrl_page.kdebug_iops) {
			dummy_iop = kd_ctrl_page.kdebug_iops[0].cpu_id;
		}
		kernel_debug_enter(dummy_iop, KDEBUG_TEST_CODE(code),
		    kdbg_timestamp() * 2 /* !!! */, 0, 0, 0, 0, 0);
		break;

	case 4:
		if (!sync_flush_iop) {
			sync_flush_iop = kernel_debug_register_callback(
				sync_flush_kdcb);
			assert(sync_flush_iop > 0);
		}
		break;

	default:
		return ENOTSUP;
	}

	return 0;
}

#undef KDEBUG_TEST_CODE

void
kdebug_init(unsigned int n_events, char *filter_desc, bool wrapping)
{
	assert(filter_desc != NULL);

#if defined(__x86_64__)
	/* only trace MACH events when outputting kdebug to serial */
	if (kdebug_serial) {
		n_events = 1;
		if (filter_desc[0] == '\0') {
			filter_desc[0] = 'C';
			filter_desc[1] = '1';
			filter_desc[2] = '\0';
		}
	}
#endif /* defined(__x86_64__) */

	if (log_leaks && n_events == 0) {
		n_events = 200000;
	}

	kdebug_trace_start(n_events, filter_desc, wrapping, false);
}

static void
kdbg_set_typefilter_string(const char *filter_desc)
{
	char *end = NULL;

	ktrace_assert_lock_held();

	assert(filter_desc != NULL);

	typefilter_reject_all(kdbg_typefilter);
	typefilter_allow_class(kdbg_typefilter, DBG_TRACE);

	/* if the filter description starts with a number, assume it's a csc */
	if (filter_desc[0] >= '0' && filter_desc[0] <= '9') {
		unsigned long csc = strtoul(filter_desc, NULL, 0);
		if (filter_desc != end && csc <= KDBG_CSC_MAX) {
			typefilter_allow_csc(kdbg_typefilter, csc);
		}
		return;
	}

	while (filter_desc[0] != '\0') {
		unsigned long allow_value;

		char filter_type = filter_desc[0];
		if (filter_type != 'C' && filter_type != 'S') {
			return;
		}
		filter_desc++;

		allow_value = strtoul(filter_desc, &end, 0);
		if (filter_desc == end) {
			/* cannot parse as integer */
			return;
		}

		switch (filter_type) {
		case 'C':
			if (allow_value <= KDBG_CLASS_MAX) {
				typefilter_allow_class(kdbg_typefilter, allow_value);
			} else {
				/* illegal class */
				return;
			}
			break;
		case 'S':
			if (allow_value <= KDBG_CSC_MAX) {
				typefilter_allow_csc(kdbg_typefilter, allow_value);
			} else {
				/* illegal class subclass */
				return;
			}
			break;
		default:
			return;
		}

		/* advance to next filter entry */
		filter_desc = end;
		if (filter_desc[0] == ',') {
			filter_desc++;
		}
	}
}

/*
 * This function is meant to be called from the bootstrap thread or coming out
 * of acpi_idle_kernel.
 */
void
kdebug_trace_start(unsigned int n_events, const char *filter_desc,
    bool wrapping, bool at_wake)
{
	if (!n_events) {
		kd_early_done = true;
		return;
	}

	ktrace_start_single_threaded();

	kdbg_lock_init();

	ktrace_kernel_configure(KTRACE_KDEBUG);

	kdbg_set_nkdbufs(n_events);

	kernel_debug_string_early("start_kern_tracing");

	if (kdbg_reinit(true)) {
		printf("error from kdbg_reinit, kernel tracing not started\n");
		goto out;
	}

	/*
	 * Wrapping is disabled because boot and wake tracing is interested in
	 * the earliest events, at the expense of later ones.
	 */
	if (!wrapping) {
		uint32_t old1, old2;
		(void)disable_wrap(&old1, &old2);
	}

	if (filter_desc && filter_desc[0] != '\0') {
		if (kdbg_initialize_typefilter(NULL) == KERN_SUCCESS) {
			kdbg_set_typefilter_string(filter_desc);
			kdbg_enable_typefilter();
		}
	}

	/*
	 * Hold off interrupts between getting a thread map and enabling trace
	 * and until the early traces are recorded.
	 */
	bool s = ml_set_interrupts_enabled(false);

	if (at_wake) {
		kdbg_thrmap_init();
	}

	kdbg_set_tracing_enabled(true, KDEBUG_ENABLE_TRACE | (kdebug_serial ?
	    KDEBUG_ENABLE_SERIAL : 0));

	if (!at_wake) {
		/*
		 * Transfer all very early events from the static buffer into the real
		 * buffers.
		 */
		kernel_debug_early_end();
	}

	ml_set_interrupts_enabled(s);

	printf("kernel tracing started with %u events\n", n_events);

#if KDEBUG_MOJO_TRACE
	if (kdebug_serial) {
		printf("serial output enabled with %lu named events\n",
		    sizeof(kd_events) / sizeof(kd_event_t));
	}
#endif /* KDEBUG_MOJO_TRACE */

out:
	ktrace_end_single_threaded();
}

void
kdbg_dump_trace_to_file(const char *filename)
{
	vfs_context_t ctx;
	vnode_t vp;
	size_t write_size;
	int ret;

	ktrace_lock();

	if (!(kdebug_enable & KDEBUG_ENABLE_TRACE)) {
		goto out;
	}

	if (ktrace_get_owning_pid() != 0) {
		/*
		 * Another process owns ktrace and is still active, disable tracing to
		 * prevent wrapping.
		 */
		kdebug_enable = 0;
		kd_ctrl_page.enabled = 0;
		commpage_update_kdebug_state();
		goto out;
	}

	KDBG_RELEASE(TRACE_WRITING_EVENTS | DBG_FUNC_START);

	kdebug_enable = 0;
	kd_ctrl_page.enabled = 0;
	commpage_update_kdebug_state();

	ctx = vfs_context_kernel();

	if (vnode_open(filename, (O_CREAT | FWRITE | O_NOFOLLOW), 0600, 0, &vp, ctx)) {
		goto out;
	}

	kdbg_write_thread_map(vp, ctx);

	write_size = nkdbufs * sizeof(kd_buf);
	ret = kdbg_read(0, &write_size, vp, ctx, RAW_VERSION1);
	if (ret) {
		goto out_close;
	}

	/*
	 * Wait to synchronize the file to capture the I/O in the
	 * TRACE_WRITING_EVENTS interval.
	 */
	ret = VNOP_FSYNC(vp, MNT_WAIT, ctx);

	/*
	 * Balance the starting TRACE_WRITING_EVENTS tracepoint manually.
	 */
	kd_buf end_event = {
		.debugid = TRACE_WRITING_EVENTS | DBG_FUNC_END,
		.arg1 = write_size,
		.arg2 = ret,
		.arg5 = thread_tid(current_thread()),
	};
	kdbg_set_timestamp_and_cpu(&end_event, kdbg_timestamp(),
	    cpu_number());

	/* this is best effort -- ignore any errors */
	(void)kdbg_write_to_vnode((caddr_t)&end_event, sizeof(kd_buf), vp, ctx,
	    RAW_file_offset);

out_close:
	vnode_close(vp, FWRITE, ctx);
	sync(current_proc(), (void *)NULL, (int *)NULL);

out:
	ktrace_unlock();
}

static int
kdbg_sysctl_continuous SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int value = kdbg_continuous_time;
	int ret = sysctl_io_number(req, value, sizeof(value), &value, NULL);

	if (ret || !req->newptr) {
		return ret;
	}

	kdbg_continuous_time = value;
	return 0;
}

SYSCTL_NODE(_kern, OID_AUTO, kdbg, CTLFLAG_RD | CTLFLAG_LOCKED, 0,
    "kdbg");

SYSCTL_PROC(_kern_kdbg, OID_AUTO, experimental_continuous,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    sizeof(int), kdbg_sysctl_continuous, "I",
    "Set kdebug to use mach_continuous_time");

SYSCTL_INT(_kern_kdbg, OID_AUTO, debug,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &kdbg_debug, 0, "Set kdebug debug mode");

SYSCTL_QUAD(_kern_kdbg, OID_AUTO, oldest_time,
    CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_LOCKED,
    &kd_ctrl_page.oldest_time,
    "Find the oldest timestamp still in trace");

#if KDEBUG_MOJO_TRACE
static kd_event_t *
binary_search(uint32_t id)
{
	int low, high, mid;

	low = 0;
	high = (int)(sizeof(kd_events) / sizeof(kd_event_t)) - 1;

	while (true) {
		mid = (low + high) / 2;

		if (low > high) {
			return NULL; /* failed */
		} else if (low + 1 >= high) {
			/* We have a match */
			if (kd_events[high].id == id) {
				return &kd_events[high];
			} else if (kd_events[low].id == id) {
				return &kd_events[low];
			} else {
				return NULL;  /* search failed */
			}
		} else if (id < kd_events[mid].id) {
			high = mid;
		} else {
			low = mid;
		}
	}
}

/*
 * Look up event id to get name string.
 * Using a per-cpu cache of a single entry
 * before resorting to a binary search of the full table.
 */
#define NCACHE  1
static kd_event_t       *last_hit[MAX_CPUS];
static kd_event_t *
event_lookup_cache(uint32_t cpu, uint32_t id)
{
	if (last_hit[cpu] == NULL || last_hit[cpu]->id != id) {
		last_hit[cpu] = binary_search(id);
	}
	return last_hit[cpu];
}

static uint64_t kd_last_timstamp;

static void
kdebug_serial_print(
	uint32_t        cpunum,
	uint32_t        debugid,
	uint64_t        timestamp,
	uintptr_t       arg1,
	uintptr_t       arg2,
	uintptr_t       arg3,
	uintptr_t       arg4,
	uintptr_t       threadid
	)
{
	char            kprintf_line[192];
	char            event[40];
	uint64_t        us = timestamp / NSEC_PER_USEC;
	uint64_t        us_tenth = (timestamp % NSEC_PER_USEC) / 100;
	uint64_t        delta = timestamp - kd_last_timstamp;
	uint64_t        delta_us = delta / NSEC_PER_USEC;
	uint64_t        delta_us_tenth = (delta % NSEC_PER_USEC) / 100;
	uint32_t        event_id = debugid & KDBG_EVENTID_MASK;
	const char      *command;
	const char      *bra;
	const char      *ket;
	kd_event_t      *ep;

	/* event time and delta from last */
	snprintf(kprintf_line, sizeof(kprintf_line),
	    "%11llu.%1llu %8llu.%1llu ",
	    us, us_tenth, delta_us, delta_us_tenth);


	/* event (id or name) - start prefixed by "[", end postfixed by "]" */
	bra = (debugid & DBG_FUNC_START) ? "[" : " ";
	ket = (debugid & DBG_FUNC_END)   ? "]" : " ";
	ep = event_lookup_cache(cpunum, event_id);
	if (ep) {
		if (strlen(ep->name) < sizeof(event) - 3) {
			snprintf(event, sizeof(event), "%s%s%s",
			    bra, ep->name, ket);
		} else {
			snprintf(event, sizeof(event), "%s%x(name too long)%s",
			    bra, event_id, ket);
		}
	} else {
		snprintf(event, sizeof(event), "%s%x%s",
		    bra, event_id, ket);
	}
	snprintf(kprintf_line + strlen(kprintf_line),
	    sizeof(kprintf_line) - strlen(kprintf_line),
	    "%-40s  ", event);

	/* arg1 .. arg4 with special cases for strings */
	switch (event_id) {
	case VFS_LOOKUP:
	case VFS_LOOKUP_DONE:
		if (debugid & DBG_FUNC_START) {
			/* arg1 hex then arg2..arg4 chars */
			snprintf(kprintf_line + strlen(kprintf_line),
			    sizeof(kprintf_line) - strlen(kprintf_line),
			    "%-16lx %-8s%-8s%-8s                          ",
			    arg1, (char*)&arg2, (char*)&arg3, (char*)&arg4);
			break;
		}
	/* else fall through for arg1..arg4 chars */
	case TRACE_STRING_EXEC:
	case TRACE_STRING_NEWTHREAD:
	case TRACE_INFO_STRING:
		snprintf(kprintf_line + strlen(kprintf_line),
		    sizeof(kprintf_line) - strlen(kprintf_line),
		    "%-8s%-8s%-8s%-8s                                   ",
		    (char*)&arg1, (char*)&arg2, (char*)&arg3, (char*)&arg4);
		break;
	default:
		snprintf(kprintf_line + strlen(kprintf_line),
		    sizeof(kprintf_line) - strlen(kprintf_line),
		    "%-16lx %-16lx %-16lx %-16lx",
		    arg1, arg2, arg3, arg4);
	}

	/* threadid, cpu and command name */
	if (threadid == (uintptr_t)thread_tid(current_thread()) &&
	    current_proc() &&
	    current_proc()->p_comm[0]) {
		command = current_proc()->p_comm;
	} else {
		command = "-";
	}
	snprintf(kprintf_line + strlen(kprintf_line),
	    sizeof(kprintf_line) - strlen(kprintf_line),
	    "  %-16lx  %-2d %s\n",
	    threadid, cpunum, command);

	kprintf("%s", kprintf_line);
	kd_last_timstamp = timestamp;
}

#endif
