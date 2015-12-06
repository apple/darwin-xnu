/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#ifndef	_KERN_DEBUG_H_
#define _KERN_DEBUG_H_

#include <sys/cdefs.h>
#include <stdint.h>
#include <uuid/uuid.h>
#include <mach/boolean.h>

#ifndef XNU_KERNEL_PRIVATE
#include <TargetConditionals.h>
#endif

#ifdef __APPLE_API_PRIVATE
#ifdef __APPLE_API_UNSTABLE

/* This value must always match IO_NUM_PRIORITIES defined in thread_info.h */
#define STACKSHOT_IO_NUM_PRIORITIES 	4
/* This value must always match MAXTHREADNAMESIZE used in bsd */
#define STACKSHOT_MAX_THREAD_NAME_SIZE	64

struct thread_snapshot {
	uint32_t 		snapshot_magic;
	uint32_t 		nkern_frames;
	uint32_t 		nuser_frames;
	uint64_t 		wait_event;
	uint64_t 	 	continuation;
	uint64_t 		thread_id;
	uint64_t 		user_time;
	uint64_t 		system_time;
	int32_t  		state;
	int32_t			priority;    /*	static priority */
	int32_t			sched_pri;   /* scheduled (current) priority */
	int32_t			sched_flags; /* scheduler flags */
	char			ss_flags;
	char			ts_qos;      /* effective qos */
	char			ts_rqos;     /* requested qos */
	char			ts_rqos_override; /* requested qos override */
	char			io_tier;
	char			_reserved[3]; /* pad for 4 byte alignement packing */

	/*
	 * I/O Statistics
	 * XXX: These fields must be together
	 */
	uint64_t 		disk_reads_count;
	uint64_t 		disk_reads_size;
	uint64_t 		disk_writes_count;
	uint64_t 		disk_writes_size;
	uint64_t 		io_priority_count[STACKSHOT_IO_NUM_PRIORITIES];
	uint64_t 		io_priority_size[STACKSHOT_IO_NUM_PRIORITIES];
	uint64_t 		paging_count;
	uint64_t 		paging_size;
	uint64_t 		non_paging_count;
	uint64_t 		non_paging_size;
	uint64_t 		data_count;
	uint64_t 		data_size;
	uint64_t 		metadata_count;
	uint64_t 		metadata_size;
	/* XXX: I/O Statistics end */

	uint64_t		voucher_identifier; /* obfuscated voucher identifier */
	uint64_t		total_syscalls;
	char			pth_name[STACKSHOT_MAX_THREAD_NAME_SIZE];

} __attribute__ ((packed));

struct thread_snapshot_v2 {
	uint64_t  ths_thread_id;
	uint64_t  ths_wait_event;
	uint64_t  ths_continuation;
	uint64_t  ths_total_syscalls;
	uint64_t  ths_voucher_identifier;
	uint64_t  ths_dqserialnum;
	uint64_t  ths_user_time;
	uint64_t  ths_sys_time;
	uint64_t  ths_ss_flags;
	uint64_t  ths_last_run_time;
	uint64_t  ths_last_made_runnable_time;
	uint32_t  ths_state;
	uint32_t  ths_sched_flags;
	int16_t   ths_base_priority;
	int16_t   ths_sched_priority;
	uint8_t   ths_eqos;
	uint8_t   ths_rqos;
	uint8_t   ths_rqos_override;
	uint8_t   ths_io_tier;
} __attribute__ ((packed));

struct task_snapshot {
	uint32_t		snapshot_magic;
	int32_t			pid;
	uint64_t		uniqueid;
	uint64_t		user_time_in_terminated_threads;
	uint64_t		system_time_in_terminated_threads;
	uint8_t			shared_cache_identifier[16];
	uint64_t		shared_cache_slide;
	uint32_t		nloadinfos;
	int			suspend_count; 
	int			task_size;	/* pages */
	int			faults;		/* number of page faults */
	int			pageins;	/* number of actual pageins */
	int			cow_faults;	/* number of copy-on-write faults */
	uint32_t		ss_flags;
	uint64_t		p_start_sec;	/* from the bsd proc struct */
	uint64_t		p_start_usec;	/* from the bsd proc struct */

	/* 
	 * We restrict ourselves to a statically defined
	 * (current as of 2009) length for the
	 * p_comm string, due to scoping issues (osfmk/bsd and user/kernel
	 * binary compatibility).
	 */
	char			p_comm[17];
	uint32_t 		was_throttled;
	uint32_t 		did_throttle;
	uint32_t		latency_qos;
	/*
	 * I/O Statistics
	 * XXX: These fields must be together.
	 */
	uint64_t 		disk_reads_count;
	uint64_t 		disk_reads_size;
	uint64_t 		disk_writes_count;
	uint64_t 		disk_writes_size;
	uint64_t 		io_priority_count[STACKSHOT_IO_NUM_PRIORITIES];
	uint64_t 		io_priority_size[STACKSHOT_IO_NUM_PRIORITIES];
	uint64_t 		paging_count;
	uint64_t 		paging_size;
	uint64_t 		non_paging_count;
	uint64_t 		non_paging_size;
	uint64_t 		data_count;
	uint64_t 		data_size;
	uint64_t 		metadata_count;
	uint64_t 		metadata_size;
	/* XXX: I/O Statistics end */

	uint32_t		donating_pid_count;

} __attribute__ ((packed));

struct io_stats_snapshot
{
	/*
	 * I/O Statistics
	 * XXX: These fields must be together.
	 */
	uint64_t         ss_disk_reads_count;
	uint64_t         ss_disk_reads_size;
	uint64_t         ss_disk_writes_count;
	uint64_t         ss_disk_writes_size;
	uint64_t         ss_io_priority_count[STACKSHOT_IO_NUM_PRIORITIES];
	uint64_t         ss_io_priority_size[STACKSHOT_IO_NUM_PRIORITIES];
	uint64_t         ss_paging_count;
	uint64_t         ss_paging_size;
	uint64_t         ss_non_paging_count;
	uint64_t         ss_non_paging_size;
	uint64_t         ss_data_count;
	uint64_t         ss_data_size;
	uint64_t         ss_metadata_count;
	uint64_t         ss_metadata_size;
	/* XXX: I/O Statistics end */

} __attribute__ ((packed));

struct task_snapshot_v2 {
	uint64_t  ts_unique_pid;
	uint64_t  ts_ss_flags;
	uint64_t  ts_user_time_in_terminated_threads;
	uint64_t  ts_system_time_in_terminated_threads;
	uint64_t  ts_p_start_sec;
	uint64_t  ts_task_size;
	uint64_t  ts_max_resident_size;
	uint32_t  ts_suspend_count;
	uint32_t  ts_faults;
	uint32_t  ts_pageins;
	uint32_t  ts_cow_faults;
	uint32_t  ts_was_throttled;
	uint32_t  ts_did_throttle;
	uint32_t  ts_latency_qos;
	int32_t   ts_pid;
	char      ts_p_comm[32];
} __attribute__ ((packed));

struct micro_snapshot {
	uint32_t		snapshot_magic;
	uint32_t		ms_cpu;	 /* cpu number this snapshot was recorded on */
	uint64_t		ms_time; /* time at sample (seconds) */
	uint64_t		ms_time_microsecs;
	uint8_t			ms_flags;
	uint16_t		ms_opaque_flags;	/* managed by external entity, e.g. fdrmicrod */
} __attribute__ ((packed));

struct mem_and_io_snapshot {
	uint32_t	snapshot_magic;
	uint32_t	free_pages;
	uint32_t	active_pages;
	uint32_t	inactive_pages;
	uint32_t	purgeable_pages;
	uint32_t	wired_pages;
	uint32_t	speculative_pages;
	uint32_t	throttled_pages;
	uint32_t	filebacked_pages;
	uint32_t 	compressions;
	uint32_t	decompressions;
	uint32_t	compressor_size;
	int     	busy_buffer_count;
	uint32_t	pages_wanted;
	uint32_t	pages_reclaimed;
	uint8_t		pages_wanted_reclaimed_valid; // did mach_vm_pressure_monitor succeed?
} __attribute__((packed));

struct stack_snapshot_frame32 {
	uint32_t lr;
    uint32_t sp;
};

struct stack_snapshot_frame64 {
    uint64_t lr;
    uint64_t sp;
};

struct _dyld_cache_header
{
    char    	magic[16];				// e.g. "dyld_v0    i386"
    uint32_t	mappingOffset;          // file offset to first dyld_cache_mapping_info
    uint32_t    mappingCount;           // number of dyld_cache_mapping_info entries
    uint32_t    imagesOffset;           // file offset to first dyld_cache_image_info
    uint32_t    imagesCount;            // number of dyld_cache_image_info entries
    uint64_t    dyldBaseAddress;        // base address of dyld when cache was built
    uint64_t    codeSignatureOffset;    // file offset of code signature blob
    uint64_t    codeSignatureSize;     	// size of code signature blob (zero means to end of file)
    uint64_t    slideInfoOffset;        // file offset of kernel slid info
    uint64_t    slideInfoSize;          // size of kernel slid info
    uint64_t    localSymbolsOffset;     // file offset of where local symbols are stored
    uint64_t    localSymbolsSize;       // size of local symbols information
    uint8_t     uuid[16];               // unique value for each shared cache file
};

struct dyld_uuid_info_32 {
    uint32_t imageLoadAddress; /* base address image is mapped at */
	uuid_t	 imageUUID;
};

struct dyld_uuid_info_64 {
    uint64_t imageLoadAddress; /* base address image is mapped at */
    uuid_t   imageUUID;
};

enum micro_snapshot_flags {
	kInterruptRecord	= 0x1,
	kTimerArmingRecord	= 0x2,
	kUserMode 			= 0x4, /* interrupted usermode, or armed by usermode */
};

/*
 * Flags used in the following assortment of snapshots.
 */
enum generic_snapshot_flags {
	kUser64_p 			= 0x1,
	kKernel64_p 		= 0x2
};

enum task_snapshot_flags {
	kTaskRsrcFlagged      = 0x4, // In the EXC_RESOURCE danger zone?
	kTerminatedSnapshot   = 0x8,
	kPidSuspended         = 0x10, // true for suspended task
	kFrozen               = 0x20, // true for hibernated task (along with pidsuspended)
	kTaskDarwinBG         = 0x40,
	kTaskExtDarwinBG      = 0x80,
	kTaskVisVisible       = 0x100,
	kTaskVisNonvisible    = 0x200,
	kTaskIsForeground     = 0x400,
	kTaskIsBoosted        = 0x800,
	kTaskIsSuppressed     = 0x1000,
	kTaskIsTimerThrottled = 0x2000, /* deprecated */
	kTaskIsImpDonor       = 0x4000,
	kTaskIsLiveImpDonor   = 0x8000
};

enum thread_snapshot_flags {
	kHasDispatchSerial = 0x4,
	kStacksPCOnly      = 0x8,  /* Stack traces have no frame pointers. */
	kThreadDarwinBG    = 0x10, /* Thread is darwinbg */
	kThreadIOPassive   = 0x20, /* Thread uses passive IO */
	kThreadSuspended   = 0x40, /* Thread is suspended */
	kThreadTruncatedBT = 0x80, /* Unmapped pages caused truncated backtrace */
	kGlobalForcedIdle  = 0x100, /* Thread performs global forced idle */
	kThreadDecompressedBT = 0x200,   /* Some thread stack pages were decompressed as part of BT */
	kThreadFaultedBT = 0x400   /* Some thread stack pages were faulted in as part of BT */
};

#define VM_PRESSURE_TIME_WINDOW 5 /* seconds */

enum {
	STACKSHOT_GET_DQ							= 0x01,
	STACKSHOT_SAVE_LOADINFO						= 0x02,
	STACKSHOT_GET_GLOBAL_MEM_STATS				= 0x04,
	STACKSHOT_SAVE_KEXT_LOADINFO				= 0x08,
	STACKSHOT_GET_MICROSTACKSHOT				= 0x10,
	STACKSHOT_GLOBAL_MICROSTACKSHOT_ENABLE		= 0x20,
	STACKSHOT_GLOBAL_MICROSTACKSHOT_DISABLE		= 0x40,
	STACKSHOT_SET_MICROSTACKSHOT_MARK			= 0x80,
	STACKSHOT_SAVE_KERNEL_FRAMES_ONLY			= 0x100,
	STACKSHOT_GET_BOOT_PROFILE					= 0x200,
	STACKSHOT_GET_WINDOWED_MICROSTACKSHOTS		= 0x400,
	STACKSHOT_WINDOWED_MICROSTACKSHOTS_ENABLE	= 0x800,
	STACKSHOT_WINDOWED_MICROSTACKSHOTS_DISABLE	= 0x1000,
	STACKSHOT_SAVE_IMP_DONATION_PIDS		= 0x2000,
	STACKSHOT_SAVE_IN_KERNEL_BUFFER			= 0x4000,
	STACKSHOT_RETRIEVE_EXISTING_BUFFER		= 0x8000,
	STACKSHOT_KCDATA_FORMAT				= 0x10000,
	STACKSHOT_ENABLE_FAULTING			= 0x20000
};

/*
 * NOTE: Please update libkdd/kcdata/kcdtypes.c if you make any changes
 * in STACKSHOT_KCTYPE_* types.
 */
#define STACKSHOT_KCTYPE_IOSTATS                0x901  /* io_stats_snapshot */
#define STACKSHOT_KCTYPE_GLOBAL_MEM_STATS       0x902  /* struct mem_and_io_snapshot */
#define STACKSHOT_KCCONTAINER_TASK              0x903
#define STACKSHOT_KCCONTAINER_THREAD            0x904
#define STACKSHOT_KCTYPE_TASK_SNAPSHOT          0x905  /* task_snapshot_v2 */
#define STACKSHOT_KCTYPE_THREAD_SNAPSHOT        0x906  /* thread_snapshot_v2 */
#define STASKSHOT_KCTYPE_DONATING_PIDS          0x907  /* int[] */
#define STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO   0x908  /* same as KCDATA_TYPE_LIBRARY_LOADINFO64 */
#define STACKSHOT_KCTYPE_THREAD_NAME            0x909  /* char[] */
#define STACKSHOT_KCTYPE_KERN_STACKFRAME        0x90A  /* struct stack_snapshot_frame32 */
#define STACKSHOT_KCTYPE_KERN_STACKFRAME64      0x90B  /* struct stack_snapshot_frame64 */
#define STACKSHOT_KCTYPE_USER_STACKFRAME        0x90C  /* struct stack_snapshot_frame32 */
#define STACKSHOT_KCTYPE_USER_STACKFRAME64      0x90D  /* struct stack_snapshot_frame64 */
#define STACKSHOT_KCTYPE_BOOTARGS               0x90E  /* boot args string */
#define STACKSHOT_KCTYPE_OSVERSION              0x90F  /* os version string */
#define STACKSHOT_KCTYPE_KERN_PAGE_SIZE         0x910  /* kernel page size in uint32_t */
#define STACKSHOT_KCTYPE_JETSAM_LEVEL           0x911  /* jetsam level in uint32_t */


#define STACKSHOT_THREAD_SNAPSHOT_MAGIC 	0xfeedface
#define STACKSHOT_TASK_SNAPSHOT_MAGIC   	0xdecafbad
#define STACKSHOT_MEM_AND_IO_SNAPSHOT_MAGIC	0xbfcabcde
#define STACKSHOT_MICRO_SNAPSHOT_MAGIC		0x31c54011

#endif /* __APPLE_API_UNSTABLE */
#endif /* __APPLE_API_PRIVATE */

#ifdef	KERNEL_PRIVATE

extern unsigned int	systemLogDiags;
#if (!defined(__arm64__) && !defined(NAND_PANIC_DEVICE)) || defined(LEGACY_PANIC_LOGS)
extern char debug_buf[];
#endif
extern char *debug_buf_addr;
extern unsigned int	debug_boot_arg;
extern unsigned char *kernel_uuid;
extern char kernel_uuid_string[];

#ifdef MACH_KERNEL_PRIVATE

extern boolean_t	doprnt_hide_pointers;

extern unsigned int	halt_in_debugger;

extern unsigned int     switch_debugger;

extern unsigned int     current_debugger;
#define NO_CUR_DB       0x0
#define KDP_CUR_DB      0x1
#define KDB_CUR_DB      0x2

extern unsigned int 	active_debugger;
extern unsigned int 	debug_mode; 
extern unsigned int 	disable_debug_output; 

extern unsigned int 	panicDebugging;
extern unsigned int 	logPanicDataToScreen;
extern unsigned int 	kdebug_serial;

extern int db_run_mode;

/* modes the system may be running in */

#define	STEP_NONE	0
#define	STEP_ONCE	1
#define	STEP_RETURN	2
#define	STEP_CALLT	3
#define	STEP_CONTINUE	4
#define STEP_INVISIBLE	5
#define	STEP_COUNT	6
#define STEP_TRACE	7	/* Show all calls to functions and returns */

extern const char		*panicstr;
extern volatile unsigned int	nestedpanic;
extern int unsigned long panic_caller;

extern char *debug_buf_ptr;
extern unsigned int debug_buf_size;

extern void	debug_log_init(void);
extern void	debug_putc(char);

extern void	panic_init(void);

int	packA(char *inbuf, uint32_t length, uint32_t buflen);
void	unpackA(char *inbuf, uint32_t length);

void	panic_display_system_configuration(void);
void	panic_display_zprint(void);
void	panic_display_kernel_aslr(void);
void	panic_display_hibb(void);
void	panic_display_model_name(void);
void	panic_display_kernel_uuid(void);
#if CONFIG_ZLEAKS
void	panic_display_ztrace(void);
#endif /* CONFIG_ZLEAKS */
#if CONFIG_ECC_LOGGING
void 	panic_display_ecc_errors(void);
#endif /* CONFIG_ECC_LOGGING */
#endif /* MACH_KERNEL_PRIVATE */

#define DB_HALT		0x1
#define DB_PRT		0x2
#define DB_NMI		0x4
#define DB_KPRT		0x8
#define DB_KDB		0x10
#define DB_SLOG		0x20
#define DB_ARP          0x40
#define DB_KDP_BP_DIS   0x80
#define DB_LOG_PI_SCRN	0x100
#define DB_KDP_GETC_ENA 0x200

#define DB_KERN_DUMP_ON_PANIC		0x400 /* Trigger core dump on panic*/
#define DB_KERN_DUMP_ON_NMI		0x800 /* Trigger core dump on NMI */
#define DB_DBG_POST_CORE		0x1000 /*Wait in debugger after NMI core */
#define DB_PANICLOG_DUMP		0x2000 /* Send paniclog on panic,not core*/
#define DB_REBOOT_POST_CORE		0x4000 /* Attempt to reboot after
						* post-panic crashdump/paniclog
						* dump.
						*/
#define DB_NMI_BTN_ENA  	0x8000  /* Enable button to directly trigger NMI */
#define DB_PRT_KDEBUG   	0x10000 /* kprintf KDEBUG traces */
#define DB_DISABLE_LOCAL_CORE   0x20000 /* ignore local core dump support */

#if DEBUG
/*
 * For the DEBUG kernel, support the following:
 *	sysctl -w debug.kprint_syscall=<syscall_mask> 
 *	sysctl -w debug.kprint_syscall_process=<p_comm>
 * <syscall_mask> should be an OR of the masks below
 * for UNIX, MACH, MDEP, or IPC. This debugging aid
 * assumes the task/process is locked/wired and will
 * not go away during evaluation. If no process is
 * specified, all processes will be traced
 */
extern int debug_kprint_syscall;
extern int debug_kprint_current_process(const char **namep);
#define DEBUG_KPRINT_SYSCALL_PREDICATE_INTERNAL(mask, namep)			\
	( (debug_kprint_syscall & (mask)) && debug_kprint_current_process(namep) )
#define DEBUG_KPRINT_SYSCALL_MASK(mask, fmt, args...)	do { 			\
		const char *dks_name = NULL;									\
		if (DEBUG_KPRINT_SYSCALL_PREDICATE_INTERNAL(mask, &dks_name)) {	\
			kprintf("[%s%s%p]" fmt, dks_name ? dks_name : "",			\
					dks_name ? "@" : "", current_thread(), args);			\
		}																\
	} while (0)
#else /* !DEBUG */
#define DEBUG_KPRINT_SYSCALL_PREDICATE_INTERNAL(mask, namep) (0)
#define DEBUG_KPRINT_SYSCALL_MASK(mask, fmt, args...) do { } while (0) /* kprintf(fmt, args) */
#endif /* !DEBUG */

enum {
	DEBUG_KPRINT_SYSCALL_UNIX_MASK = 1 << 0,
	DEBUG_KPRINT_SYSCALL_MACH_MASK = 1 << 1,
	DEBUG_KPRINT_SYSCALL_MDEP_MASK = 1 << 2,
	DEBUG_KPRINT_SYSCALL_IPC_MASK  = 1 << 3
};

#define DEBUG_KPRINT_SYSCALL_PREDICATE(mask)				\
	DEBUG_KPRINT_SYSCALL_PREDICATE_INTERNAL(mask, NULL)
#define DEBUG_KPRINT_SYSCALL_UNIX(fmt, args...)				\
	DEBUG_KPRINT_SYSCALL_MASK(DEBUG_KPRINT_SYSCALL_UNIX_MASK,fmt,args)
#define DEBUG_KPRINT_SYSCALL_MACH(fmt, args...)				\
	DEBUG_KPRINT_SYSCALL_MASK(DEBUG_KPRINT_SYSCALL_MACH_MASK,fmt,args)
#define DEBUG_KPRINT_SYSCALL_MDEP(fmt, args...)				\
	DEBUG_KPRINT_SYSCALL_MASK(DEBUG_KPRINT_SYSCALL_MDEP_MASK,fmt,args)
#define DEBUG_KPRINT_SYSCALL_IPC(fmt, args...)				\
	DEBUG_KPRINT_SYSCALL_MASK(DEBUG_KPRINT_SYSCALL_IPC_MASK,fmt,args)

#endif	/* KERNEL_PRIVATE */

#ifdef KERNEL

__BEGIN_DECLS

extern void panic(const char *string, ...) __printflike(1,2);

#if KERNEL_PRIVATE
void _consume_panic_args(int, ...);
void panic_context(unsigned int reason, void *ctx, const char *string, ...);
#endif

#if CONFIG_NO_PANIC_STRINGS
#if KERNEL_PRIVATE
#define panic_plain(x, ...) _consume_panic_args( 0, ## __VA_ARGS__ )
#define panic(x, ...) _consume_panic_args( 0, ## __VA_ARGS__ )
#else
#define panic_plain(...) (panic)((char *)0)
#define panic(...)  (panic)((char *)0)
#endif
#else /* CONFIGS_NO_PANIC_STRINGS */
#define panic_plain(ex, ...) \
	(panic)(ex, ## __VA_ARGS__)
#define __STRINGIFY(x) #x
#define LINE_NUMBER(x) __STRINGIFY(x)
#define PANIC_LOCATION __FILE__ ":" LINE_NUMBER(__LINE__)
#define panic(ex, ...) \
	(panic)(# ex "@" PANIC_LOCATION, ## __VA_ARGS__)
#endif /* CONFIGS_NO_PANIC_STRINGS */

#ifdef KERNEL_PRIVATE
void 		populate_model_name(char *);
unsigned	panic_active(void);
#endif

__END_DECLS

#endif /* KERNEL */

#endif	/* _KERN_DEBUG_H_ */
