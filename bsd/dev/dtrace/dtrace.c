/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Portions Copyright (c) 2013, 2016, Joyent, Inc. All rights reserved.
 * Portions Copyright (c) 2013 by Delphix. All rights reserved.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* #pragma ident	"@(#)dtrace.c	1.65	08/07/02 SMI" */

/*
 * DTrace - Dynamic Tracing for Solaris
 *
 * This is the implementation of the Solaris Dynamic Tracing framework
 * (DTrace).  The user-visible interface to DTrace is described at length in
 * the "Solaris Dynamic Tracing Guide".  The interfaces between the libdtrace
 * library, the in-kernel DTrace framework, and the DTrace providers are
 * described in the block comments in the <sys/dtrace.h> header file.  The
 * internal architecture of DTrace is described in the block comments in the
 * <sys/dtrace_impl.h> header file.  The comments contained within the DTrace
 * implementation very much assume mastery of all of these sources; if one has
 * an unanswered question about the implementation, one should consult them
 * first.
 *
 * The functions here are ordered roughly as follows:
 *
 *   - Probe context functions
 *   - Probe hashing functions
 *   - Non-probe context utility functions
 *   - Matching functions
 *   - Provider-to-Framework API functions
 *   - Probe management functions
 *   - DIF object functions
 *   - Format functions
 *   - Predicate functions
 *   - ECB functions
 *   - Buffer functions
 *   - Enabling functions
 *   - DOF functions
 *   - Anonymous enabling functions
 *   - Process functions
 *   - Consumer state functions
 *   - Helper functions
 *   - Hook functions
 *   - Driver cookbook functions
 *
 * Each group of functions begins with a block comment labelled the "DTrace
 * [Group] Functions", allowing one to find each block by searching forward
 * on capital-f functions.
 */
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/dtrace_impl.h>
#include <sys/param.h>
#include <sys/proc_internal.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <miscfs/devfs/devfs.h>
#include <sys/malloc.h>
#include <sys/kernel_types.h>
#include <sys/proc_internal.h>
#include <sys/uio_internal.h>
#include <sys/kauth.h>
#include <vm/pmap.h>
#include <sys/user.h>
#include <mach/exception_types.h>
#include <sys/signalvar.h>
#include <mach/task.h>
#include <kern/zalloc.h>
#include <kern/ast.h>
#include <kern/sched_prim.h>
#include <kern/task.h>
#include <netinet/in.h>
#include <libkern/sysctl.h>
#include <sys/kdebug.h>

#include <kern/cpu_data.h>
extern uint32_t pmap_find_phys(void *, uint64_t);
extern boolean_t pmap_valid_page(uint32_t);
extern void OSKextRegisterKextsWithDTrace(void);
extern kmod_info_t g_kernel_kmod_info;

/* Solaris proc_t is the struct. Darwin's proc_t is a pointer to it. */
#define proc_t struct proc /* Steer clear of the Darwin typedef for proc_t */

#define t_predcache t_dtrace_predcache /* Cosmetic. Helps readability of thread.h */

extern void dtrace_suspend(void);
extern void dtrace_resume(void);
extern void dtrace_init(void);
extern void helper_init(void);
extern void fasttrap_init(void);

static int  dtrace_lazy_dofs_duplicate(proc_t *, proc_t *);
extern void dtrace_lazy_dofs_destroy(proc_t *);
extern void dtrace_postinit(void);

extern void dtrace_proc_fork(proc_t*, proc_t*, int);
extern void dtrace_proc_exec(proc_t*);
extern void dtrace_proc_exit(proc_t*);
/*
 * DTrace Tunable Variables
 *
 * The following variables may be dynamically tuned by using sysctl(8), the
 * variables being stored in the kern.dtrace namespace.  For example:
 * 	sysctl kern.dtrace.dof_maxsize = 1048575 	# 1M
 *
 * In general, the only variables that one should be tuning this way are those
 * that affect system-wide DTrace behavior, and for which the default behavior
 * is undesirable.  Most of these variables are tunable on a per-consumer
 * basis using DTrace options, and need not be tuned on a system-wide basis.
 * When tuning these variables, avoid pathological values; while some attempt
 * is made to verify the integrity of these variables, they are not considered
 * part of the supported interface to DTrace, and they are therefore not
 * checked comprehensively.
 */
uint64_t	dtrace_buffer_memory_maxsize = 0;		/* initialized in dtrace_init */
uint64_t	dtrace_buffer_memory_inuse = 0;
int		dtrace_destructive_disallow = 0;
dtrace_optval_t	dtrace_nonroot_maxsize = (16 * 1024 * 1024);
size_t		dtrace_difo_maxsize = (256 * 1024);
dtrace_optval_t	dtrace_dof_maxsize = (384 * 1024);
dtrace_optval_t	dtrace_statvar_maxsize = (16 * 1024);
dtrace_optval_t	dtrace_statvar_maxsize_max = (16 * 10 * 1024);
size_t		dtrace_actions_max = (16 * 1024);
size_t		dtrace_retain_max = 1024;
dtrace_optval_t	dtrace_helper_actions_max = 32;
dtrace_optval_t	dtrace_helper_providers_max = 64;
dtrace_optval_t	dtrace_dstate_defsize = (1 * 1024 * 1024);
size_t		dtrace_strsize_default = 256;
dtrace_optval_t	dtrace_strsize_min = 8;
dtrace_optval_t	dtrace_strsize_max = 65536;
dtrace_optval_t	dtrace_cleanrate_default = 990099000;		/* 1.1 hz */
dtrace_optval_t	dtrace_cleanrate_min = 20000000;			/* 50 hz */
dtrace_optval_t	dtrace_cleanrate_max = (uint64_t)60 * NANOSEC;	/* 1/minute */
dtrace_optval_t	dtrace_aggrate_default = NANOSEC;		/* 1 hz */
dtrace_optval_t	dtrace_statusrate_default = NANOSEC;		/* 1 hz */
dtrace_optval_t dtrace_statusrate_max = (hrtime_t)10 * NANOSEC;	 /* 6/minute */
dtrace_optval_t	dtrace_switchrate_default = NANOSEC;		/* 1 hz */
dtrace_optval_t	dtrace_nspec_default = 1;
dtrace_optval_t	dtrace_specsize_default = 32 * 1024;
dtrace_optval_t dtrace_stackframes_default = 20;
dtrace_optval_t dtrace_ustackframes_default = 20;
dtrace_optval_t dtrace_jstackframes_default = 50;
dtrace_optval_t dtrace_jstackstrsize_default = 512;
dtrace_optval_t dtrace_buflimit_default = 75;
dtrace_optval_t dtrace_buflimit_min = 1;
dtrace_optval_t dtrace_buflimit_max = 99;
int		dtrace_msgdsize_max = 128;
hrtime_t	dtrace_chill_max = 500 * (NANOSEC / MILLISEC);	/* 500 ms */
hrtime_t	dtrace_chill_interval = NANOSEC;		/* 1000 ms */
int		dtrace_devdepth_max = 32;
int		dtrace_err_verbose;
int		dtrace_provide_private_probes = 0;
hrtime_t	dtrace_deadman_interval = NANOSEC;
hrtime_t	dtrace_deadman_timeout = (hrtime_t)10 * NANOSEC;
hrtime_t	dtrace_deadman_user = (hrtime_t)30 * NANOSEC;

/*
 * DTrace External Variables
 *
 * As dtrace(7D) is a kernel module, any DTrace variables are obviously
 * available to DTrace consumers via the backtick (`) syntax.  One of these,
 * dtrace_zero, is made deliberately so:  it is provided as a source of
 * well-known, zero-filled memory.  While this variable is not documented,
 * it is used by some translators as an implementation detail.
 */
const char	dtrace_zero[256] = { 0 };	/* zero-filled memory */
unsigned int	dtrace_max_cpus = 0;		/* number of enabled cpus */
/*
 * DTrace Internal Variables
 */
static dev_info_t	*dtrace_devi;		/* device info */
static vmem_t		*dtrace_arena;		/* probe ID arena */
static taskq_t		*dtrace_taskq;		/* task queue */
static dtrace_probe_t	**dtrace_probes;	/* array of all probes */
static int		dtrace_nprobes;		/* number of probes */
static dtrace_provider_t *dtrace_provider;	/* provider list */
static dtrace_meta_t	*dtrace_meta_pid;	/* user-land meta provider */
static int		dtrace_opens;		/* number of opens */
static int		dtrace_helpers;		/* number of helpers */
static dtrace_hash_t	*dtrace_bymod;		/* probes hashed by module */
static dtrace_hash_t	*dtrace_byfunc;		/* probes hashed by function */
static dtrace_hash_t	*dtrace_byname;		/* probes hashed by name */
static dtrace_toxrange_t *dtrace_toxrange;	/* toxic range array */
static int		dtrace_toxranges;	/* number of toxic ranges */
static int		dtrace_toxranges_max;	/* size of toxic range array */
static dtrace_anon_t	dtrace_anon;		/* anonymous enabling */
static kmem_cache_t	*dtrace_state_cache;	/* cache for dynamic state */
static uint64_t		dtrace_vtime_references; /* number of vtimestamp refs */
static kthread_t	*dtrace_panicked;	/* panicking thread */
static dtrace_ecb_t	*dtrace_ecb_create_cache; /* cached created ECB */
static dtrace_genid_t	dtrace_probegen;	/* current probe generation */
static dtrace_helpers_t *dtrace_deferred_pid;	/* deferred helper list */
static dtrace_enabling_t *dtrace_retained;	/* list of retained enablings */
static dtrace_genid_t   dtrace_retained_gen;    /* current retained enab gen */
static dtrace_dynvar_t	dtrace_dynhash_sink;	/* end of dynamic hash chains */

static int		dtrace_dof_mode;	/* See dtrace_impl.h for a description of Darwin's dof modes. */

			/*
			 * This does't quite fit as an internal variable, as it must be accessed in
			 * fbt_provide and sdt_provide. Its clearly not a dtrace tunable variable either...
			 */
int			dtrace_kernel_symbol_mode;	/* See dtrace_impl.h for a description of Darwin's kernel symbol modes. */
static uint32_t		dtrace_wake_clients;


/*
 * To save memory, some common memory allocations are given a
 * unique zone. For example, dtrace_probe_t is 72 bytes in size,
 * which means it would fall into the kalloc.128 bucket. With
 * 20k elements allocated, the space saved is substantial.
 */

struct zone *dtrace_probe_t_zone;

static int dtrace_module_unloaded(struct kmod_info *kmod);

/*
 * DTrace Locking
 * DTrace is protected by three (relatively coarse-grained) locks:
 *
 * (1) dtrace_lock is required to manipulate essentially any DTrace state,
 *     including enabling state, probes, ECBs, consumer state, helper state,
 *     etc.  Importantly, dtrace_lock is _not_ required when in probe context;
 *     probe context is lock-free -- synchronization is handled via the
 *     dtrace_sync() cross call mechanism.
 *
 * (2) dtrace_provider_lock is required when manipulating provider state, or
 *     when provider state must be held constant.
 *
 * (3) dtrace_meta_lock is required when manipulating meta provider state, or
 *     when meta provider state must be held constant.
 *
 * The lock ordering between these three locks is dtrace_meta_lock before
 * dtrace_provider_lock before dtrace_lock.  (In particular, there are
 * several places where dtrace_provider_lock is held by the framework as it
 * calls into the providers -- which then call back into the framework,
 * grabbing dtrace_lock.)
 *
 * There are two other locks in the mix:  mod_lock and cpu_lock.  With respect
 * to dtrace_provider_lock and dtrace_lock, cpu_lock continues its historical
 * role as a coarse-grained lock; it is acquired before both of these locks.
 * With respect to dtrace_meta_lock, its behavior is stranger:  cpu_lock must
 * be acquired _between_ dtrace_meta_lock and any other DTrace locks.
 * mod_lock is similar with respect to dtrace_provider_lock in that it must be
 * acquired _between_ dtrace_provider_lock and dtrace_lock.
 */


/*
 * APPLE NOTE:
 *
 * For porting purposes, all kmutex_t vars have been changed
 * to lck_mtx_t, which require explicit initialization.
 *
 * kmutex_t becomes lck_mtx_t
 * mutex_enter() becomes lck_mtx_lock()
 * mutex_exit() becomes lck_mtx_unlock()
 *
 * Lock asserts are changed like this:
 *
 * ASSERT(MUTEX_HELD(&cpu_lock));
 *	becomes:
 * lck_mtx_assert(&cpu_lock, LCK_MTX_ASSERT_OWNED);
 *
 */
static lck_mtx_t	dtrace_lock;		/* probe state lock */
static lck_mtx_t	dtrace_provider_lock;	/* provider state lock */
static lck_mtx_t	dtrace_meta_lock;	/* meta-provider state lock */
static lck_rw_t		dtrace_dof_mode_lock;	/* dof mode lock */

/*
 * DTrace Provider Variables
 *
 * These are the variables relating to DTrace as a provider (that is, the
 * provider of the BEGIN, END, and ERROR probes).
 */
static dtrace_pattr_t	dtrace_provider_attr = {
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
};

static void
dtrace_nullop(void)
{}

static int
dtrace_enable_nullop(void)
{
    return (0);
}

static dtrace_pops_t	dtrace_provider_ops = {
	(void (*)(void *, const dtrace_probedesc_t *))dtrace_nullop,
	(void (*)(void *, struct modctl *))dtrace_nullop,
	(int (*)(void *, dtrace_id_t, void *))dtrace_enable_nullop,
	(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
	(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
	(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
	NULL,
	NULL,
	NULL,
	(void (*)(void *, dtrace_id_t, void *))dtrace_nullop
};

static dtrace_id_t	dtrace_probeid_begin;	/* special BEGIN probe */
static dtrace_id_t	dtrace_probeid_end;	/* special END probe */
dtrace_id_t		dtrace_probeid_error;	/* special ERROR probe */

/*
 * DTrace Helper Tracing Variables
 */
uint32_t dtrace_helptrace_next = 0;
uint32_t dtrace_helptrace_nlocals;
char	*dtrace_helptrace_buffer;
size_t	dtrace_helptrace_bufsize = 512 * 1024;

#if DEBUG
int	dtrace_helptrace_enabled = 1;
#else
int	dtrace_helptrace_enabled = 0;
#endif


/*
 * DTrace Error Hashing
 *
 * On DEBUG kernels, DTrace will track the errors that has seen in a hash
 * table.  This is very useful for checking coverage of tests that are
 * expected to induce DIF or DOF processing errors, and may be useful for
 * debugging problems in the DIF code generator or in DOF generation .  The
 * error hash may be examined with the ::dtrace_errhash MDB dcmd.
 */
#if DEBUG
static dtrace_errhash_t	dtrace_errhash[DTRACE_ERRHASHSZ];
static const char *dtrace_errlast;
static kthread_t *dtrace_errthread;
static lck_mtx_t dtrace_errlock;
#endif

/*
 * DTrace Macros and Constants
 *
 * These are various macros that are useful in various spots in the
 * implementation, along with a few random constants that have no meaning
 * outside of the implementation.  There is no real structure to this cpp
 * mishmash -- but is there ever?
 */
#define	DTRACE_HASHSTR(hash, probe)	\
	dtrace_hash_str(*((char **)((uintptr_t)(probe) + (hash)->dth_stroffs)))

#define	DTRACE_HASHNEXT(hash, probe)	\
	(dtrace_probe_t **)((uintptr_t)(probe) + (hash)->dth_nextoffs)

#define	DTRACE_HASHPREV(hash, probe)	\
	(dtrace_probe_t **)((uintptr_t)(probe) + (hash)->dth_prevoffs)

#define	DTRACE_HASHEQ(hash, lhs, rhs)	\
	(strcmp(*((char **)((uintptr_t)(lhs) + (hash)->dth_stroffs)), \
	    *((char **)((uintptr_t)(rhs) + (hash)->dth_stroffs))) == 0)

#define	DTRACE_AGGHASHSIZE_SLEW		17

#define	DTRACE_V4MAPPED_OFFSET		(sizeof (uint32_t) * 3)

/*
 * The key for a thread-local variable consists of the lower 61 bits of the
 * current_thread(), plus the 3 bits of the highest active interrupt above LOCK_LEVEL.
 * We add DIF_VARIABLE_MAX to t_did to assure that the thread key is never
 * equal to a variable identifier.  This is necessary (but not sufficient) to
 * assure that global associative arrays never collide with thread-local
 * variables.  To guarantee that they cannot collide, we must also define the
 * order for keying dynamic variables.  That order is:
 *
 *   [ key0 ] ... [ keyn ] [ variable-key ] [ tls-key ]
 *
 * Because the variable-key and the tls-key are in orthogonal spaces, there is
 * no way for a global variable key signature to match a thread-local key
 * signature.
 */
#if defined (__x86_64__)
/* FIXME: two function calls!! */
#define	DTRACE_TLS_THRKEY(where) { \
	uint_t intr = ml_at_interrupt_context(); /* Note: just one measly bit */ \
	uint64_t thr = (uintptr_t)current_thread(); \
	ASSERT(intr < (1 << 3)); \
	(where) = ((thr + DIF_VARIABLE_MAX) & \
	    (((uint64_t)1 << 61) - 1)) | ((uint64_t)intr << 61); \
}
#else
#error Unknown architecture
#endif

#define	DT_BSWAP_8(x)	((x) & 0xff)
#define	DT_BSWAP_16(x)	((DT_BSWAP_8(x) << 8) | DT_BSWAP_8((x) >> 8))
#define	DT_BSWAP_32(x)	((DT_BSWAP_16(x) << 16) | DT_BSWAP_16((x) >> 16))
#define	DT_BSWAP_64(x)	((DT_BSWAP_32(x) << 32) | DT_BSWAP_32((x) >> 32))

#define	DT_MASK_LO 0x00000000FFFFFFFFULL

#define	DTRACE_STORE(type, tomax, offset, what) \
	*((type *)((uintptr_t)(tomax) + (uintptr_t)offset)) = (type)(what);


#define	DTRACE_ALIGNCHECK(addr, size, flags)				\
	if (addr & (MIN(size,4) - 1)) {					\
		*flags |= CPU_DTRACE_BADALIGN;				\
		cpu_core[CPU->cpu_id].cpuc_dtrace_illval = addr;	\
		return (0);						\
	}

#define	DTRACE_RANGE_REMAIN(remp, addr, baseaddr, basesz)		\
do {									\
	if ((remp) != NULL) {						\
		*(remp) = (uintptr_t)(baseaddr) + (basesz) - (addr);	\
	}								\
} while (0)


/*
 * Test whether a range of memory starting at testaddr of size testsz falls
 * within the range of memory described by addr, sz.  We take care to avoid
 * problems with overflow and underflow of the unsigned quantities, and
 * disallow all negative sizes.  Ranges of size 0 are allowed.
 */
#define	DTRACE_INRANGE(testaddr, testsz, baseaddr, basesz) \
	((testaddr) - (baseaddr) < (basesz) && \
	(testaddr) + (testsz) - (baseaddr) <= (basesz) && \
	(testaddr) + (testsz) >= (testaddr))

/*
 * Test whether alloc_sz bytes will fit in the scratch region.  We isolate
 * alloc_sz on the righthand side of the comparison in order to avoid overflow
 * or underflow in the comparison with it.  This is simpler than the INRANGE
 * check above, because we know that the dtms_scratch_ptr is valid in the
 * range.  Allocations of size zero are allowed.
 */
#define	DTRACE_INSCRATCH(mstate, alloc_sz) \
	((mstate)->dtms_scratch_base + (mstate)->dtms_scratch_size - \
	(mstate)->dtms_scratch_ptr >= (alloc_sz))

#define RECOVER_LABEL(bits) dtraceLoadRecover##bits:

#if defined (__x86_64__) || (defined (__arm__) || defined (__arm64__))
#define	DTRACE_LOADFUNC(bits)						\
/*CSTYLED*/								\
uint##bits##_t dtrace_load##bits(uintptr_t addr);			\
									\
uint##bits##_t								\
dtrace_load##bits(uintptr_t addr)					\
{									\
	size_t size = bits / NBBY;					\
	/*CSTYLED*/							\
	uint##bits##_t rval = 0;					\
	int i;								\
	volatile uint16_t *flags = (volatile uint16_t *)		\
	    &cpu_core[CPU->cpu_id].cpuc_dtrace_flags;			\
									\
	DTRACE_ALIGNCHECK(addr, size, flags);				\
									\
	for (i = 0; i < dtrace_toxranges; i++) {			\
		if (addr >= dtrace_toxrange[i].dtt_limit)		\
			continue;					\
									\
		if (addr + size <= dtrace_toxrange[i].dtt_base)		\
			continue;					\
									\
		/*							\
		 * This address falls within a toxic region; return 0.	\
		 */							\
		*flags |= CPU_DTRACE_BADADDR;				\
		cpu_core[CPU->cpu_id].cpuc_dtrace_illval = addr;	\
		return (0);						\
	}								\
									\
	{								\
	volatile vm_offset_t recover = (vm_offset_t)&&dtraceLoadRecover##bits;		\
	*flags |= CPU_DTRACE_NOFAULT;					\
	recover = dtrace_set_thread_recover(current_thread(), recover);	\
	/*CSTYLED*/							\
	/*                                                              \
	* PR6394061 - avoid device memory that is unpredictably		\
	* mapped and unmapped                                   	\
	*/								\
        if (pmap_valid_page(pmap_find_phys(kernel_pmap, addr)))		\
	    rval = *((volatile uint##bits##_t *)addr);			\
	else {								\
		*flags |= CPU_DTRACE_BADADDR;				\
		cpu_core[CPU->cpu_id].cpuc_dtrace_illval = addr;	\
		return (0);						\
	}								\
									\
	RECOVER_LABEL(bits);						\
	(void)dtrace_set_thread_recover(current_thread(), recover);	\
	*flags &= ~CPU_DTRACE_NOFAULT;					\
	}								\
									\
	return (rval);							\
}
#else /* all other architectures */
#error Unknown Architecture
#endif

#ifdef __LP64__
#define	dtrace_loadptr	dtrace_load64
#else
#define	dtrace_loadptr	dtrace_load32
#endif

#define	DTRACE_DYNHASH_FREE	0
#define	DTRACE_DYNHASH_SINK	1
#define	DTRACE_DYNHASH_VALID	2

#define DTRACE_MATCH_FAIL       -1
#define	DTRACE_MATCH_NEXT	0
#define	DTRACE_MATCH_DONE	1
#define	DTRACE_ANCHORED(probe)	((probe)->dtpr_func[0] != '\0')
#define	DTRACE_STATE_ALIGN	64

#define	DTRACE_FLAGS2FLT(flags)						\
	(((flags) & CPU_DTRACE_BADADDR) ? DTRACEFLT_BADADDR :		\
	((flags) & CPU_DTRACE_ILLOP) ? DTRACEFLT_ILLOP :		\
	((flags) & CPU_DTRACE_DIVZERO) ? DTRACEFLT_DIVZERO :		\
	((flags) & CPU_DTRACE_KPRIV) ? DTRACEFLT_KPRIV :		\
	((flags) & CPU_DTRACE_UPRIV) ? DTRACEFLT_UPRIV :		\
	((flags) & CPU_DTRACE_TUPOFLOW) ?  DTRACEFLT_TUPOFLOW :		\
	((flags) & CPU_DTRACE_BADALIGN) ?  DTRACEFLT_BADALIGN :		\
	((flags) & CPU_DTRACE_NOSCRATCH) ?  DTRACEFLT_NOSCRATCH :	\
	((flags) & CPU_DTRACE_BADSTACK) ?  DTRACEFLT_BADSTACK :		\
	DTRACEFLT_UNKNOWN)

#define	DTRACEACT_ISSTRING(act)						\
	((act)->dta_kind == DTRACEACT_DIFEXPR &&			\
	(act)->dta_difo->dtdo_rtype.dtdt_kind == DIF_TYPE_STRING)


static size_t dtrace_strlen(const char *, size_t);
static dtrace_probe_t *dtrace_probe_lookup_id(dtrace_id_t id);
static void dtrace_enabling_provide(dtrace_provider_t *);
static int dtrace_enabling_match(dtrace_enabling_t *, int *, dtrace_match_cond_t *cond);
static void dtrace_enabling_matchall_with_cond(dtrace_match_cond_t *cond);
static void dtrace_enabling_matchall(void);
static dtrace_state_t *dtrace_anon_grab(void);
static uint64_t dtrace_helper(int, dtrace_mstate_t *,
    dtrace_state_t *, uint64_t, uint64_t);
static dtrace_helpers_t *dtrace_helpers_create(proc_t *);
static void dtrace_buffer_drop(dtrace_buffer_t *);
static intptr_t dtrace_buffer_reserve(dtrace_buffer_t *, size_t, size_t,
    dtrace_state_t *, dtrace_mstate_t *);
static int dtrace_state_option(dtrace_state_t *, dtrace_optid_t,
    dtrace_optval_t);
static int dtrace_ecb_create_enable(dtrace_probe_t *, void *);
static void dtrace_helper_provider_destroy(dtrace_helper_provider_t *);
static int dtrace_canload_remains(uint64_t, size_t, size_t *,
	dtrace_mstate_t *, dtrace_vstate_t *);
static int dtrace_canstore_remains(uint64_t, size_t, size_t *,
	dtrace_mstate_t *, dtrace_vstate_t *);


/*
 * DTrace sysctl handlers
 *
 * These declarations and functions are used for a deeper DTrace configuration.
 * Most of them are not per-consumer basis and may impact the other DTrace
 * consumers.  Correctness may not be supported for all the variables, so you
 * should be careful about what values you are using.
 */

SYSCTL_DECL(_kern_dtrace);
SYSCTL_NODE(_kern, OID_AUTO, dtrace, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "dtrace"); 

static int
sysctl_dtrace_err_verbose SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	int changed, error;
	int value = *(int *) arg1;

	error = sysctl_io_number(req, value, sizeof(value), &value, &changed);
	if (error || !changed)
		return (error);

	if (value != 0 && value != 1)
		return (ERANGE);

	lck_mtx_lock(&dtrace_lock);
		dtrace_err_verbose = value;
	lck_mtx_unlock(&dtrace_lock);

	return (0);
}

/*
 * kern.dtrace.err_verbose
 *
 * Set DTrace verbosity when an error occured (0 = disabled, 1 = enabld).
 * Errors are reported when a DIFO or a DOF has been rejected by the kernel.
 */
SYSCTL_PROC(_kern_dtrace, OID_AUTO, err_verbose,
	CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
	&dtrace_err_verbose, 0,
	sysctl_dtrace_err_verbose, "I", "dtrace error verbose");

static int
sysctl_dtrace_buffer_memory_maxsize SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2, req)
	int changed, error;
	uint64_t value = *(uint64_t *) arg1;

	error = sysctl_io_number(req, value, sizeof(value), &value, &changed);
	if (error || !changed)
		return (error);

	if (value <= dtrace_buffer_memory_inuse)
		return (ERANGE);

	lck_mtx_lock(&dtrace_lock);
		dtrace_buffer_memory_maxsize = value;	
	lck_mtx_unlock(&dtrace_lock);

	return (0);
}

/*
 * kern.dtrace.buffer_memory_maxsize
 *
 * Set DTrace maximal size in bytes used by all the consumers' state buffers.  By default
 * the limit is PHYS_MEM / 3 for *all* consumers.  Attempting to set a null, a negative value
 * or a value <= to dtrace_buffer_memory_inuse will result in a failure.
 */
SYSCTL_PROC(_kern_dtrace, OID_AUTO, buffer_memory_maxsize,
	CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
	&dtrace_buffer_memory_maxsize, 0,
	sysctl_dtrace_buffer_memory_maxsize, "Q", "dtrace state buffer memory maxsize");

/*
 * kern.dtrace.buffer_memory_inuse
 *
 * Current state buffer memory used, in bytes, by all the DTrace consumers.
 * This value is read-only.
 */
SYSCTL_QUAD(_kern_dtrace, OID_AUTO, buffer_memory_inuse, CTLFLAG_RD | CTLFLAG_LOCKED,
	&dtrace_buffer_memory_inuse, "dtrace state buffer memory in-use");

static int
sysctl_dtrace_difo_maxsize SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2, req)
	int changed, error;
	size_t value = *(size_t*) arg1;

	error = sysctl_io_number(req, value, sizeof(value), &value, &changed);
	if (error || !changed)
		return (error);

	if (value <= 0)
		return (ERANGE);

	lck_mtx_lock(&dtrace_lock);
		dtrace_difo_maxsize = value;
	lck_mtx_unlock(&dtrace_lock);

	return (0);
}

/*
 * kern.dtrace.difo_maxsize
 *
 * Set the DIFO max size in bytes, check the definition of dtrace_difo_maxsize
 * to get the default value.  Attempting to set a null or negative size will
 * result in a failure.
 */
SYSCTL_PROC(_kern_dtrace, OID_AUTO, difo_maxsize,
	CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
	&dtrace_difo_maxsize, 0,
	sysctl_dtrace_difo_maxsize, "Q", "dtrace difo maxsize");

static int
sysctl_dtrace_dof_maxsize SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2, req)
	int changed, error;
	dtrace_optval_t value = *(dtrace_optval_t *) arg1;

	error = sysctl_io_number(req, value, sizeof(value), &value, &changed);
	if (error || !changed)
		return (error);

	if (value <= 0)
		return (ERANGE);

	lck_mtx_lock(&dtrace_lock);
		dtrace_dof_maxsize = value;
	lck_mtx_unlock(&dtrace_lock);

	return (0);
}

/*
 * kern.dtrace.dof_maxsize
 *
 * Set the DOF max size in bytes, check the definition of dtrace_dof_maxsize to
 * get the default value.  Attempting to set a null or negative size will result
 * in a failure.
 */
SYSCTL_PROC(_kern_dtrace, OID_AUTO, dof_maxsize,
	CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
	&dtrace_dof_maxsize, 0,
	sysctl_dtrace_dof_maxsize, "Q", "dtrace dof maxsize");

static int
sysctl_dtrace_statvar_maxsize SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2, req)
	int changed, error;
	dtrace_optval_t value = *(dtrace_optval_t*) arg1;

	error = sysctl_io_number(req, value, sizeof(value), &value, &changed);
	if (error || !changed)
		return (error);

	if (value <= 0)
		return (ERANGE);
	if (value > dtrace_statvar_maxsize_max)
		return (ERANGE);

	lck_mtx_lock(&dtrace_lock);
		dtrace_statvar_maxsize = value;
	lck_mtx_unlock(&dtrace_lock);

	return (0);
}

/*
 * kern.dtrace.global_maxsize
 *
 * Set the variable max size in bytes, check the definition of
 * dtrace_statvar_maxsize to get the default value.  Attempting to set a null,
 * too high or negative size will result in a failure.
 */
SYSCTL_PROC(_kern_dtrace, OID_AUTO, global_maxsize,
	CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
	&dtrace_statvar_maxsize, 0,
	sysctl_dtrace_statvar_maxsize, "Q", "dtrace statvar maxsize");

static int
sysctl_dtrace_provide_private_probes SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	int error;
	int value = *(int *) arg1;

	error = sysctl_io_number(req, value, sizeof(value), &value, NULL);
	if (error)
		return (error);

	if (value != 0 && value != 1)
		return (ERANGE);

	lck_mtx_lock(&dtrace_lock);
		dtrace_provide_private_probes = value;
	lck_mtx_unlock(&dtrace_lock);

	return (0);
}

/*
 * kern.dtrace.provide_private_probes
 *
 * Set whether the providers must provide the private probes.  This is
 * mainly used by the FBT provider to request probes for the private/static
 * symbols.
 */
SYSCTL_PROC(_kern_dtrace, OID_AUTO, provide_private_probes,
	CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
	&dtrace_provide_private_probes, 0,
	sysctl_dtrace_provide_private_probes, "I", "provider must provide the private probes");

/*
 * DTrace Probe Context Functions
 *
 * These functions are called from probe context.  Because probe context is
 * any context in which C may be called, arbitrarily locks may be held,
 * interrupts may be disabled, we may be in arbitrary dispatched state, etc.
 * As a result, functions called from probe context may only call other DTrace
 * support functions -- they may not interact at all with the system at large.
 * (Note that the ASSERT macro is made probe-context safe by redefining it in
 * terms of dtrace_assfail(), a probe-context safe function.) If arbitrary
 * loads are to be performed from probe context, they _must_ be in terms of
 * the safe dtrace_load*() variants.
 *
 * Some functions in this block are not actually called from probe context;
 * for these functions, there will be a comment above the function reading
 * "Note:  not called from probe context."
 */

int
dtrace_assfail(const char *a, const char *f, int l)
{
	panic("dtrace: assertion failed: %s, file: %s, line: %d", a, f, l);

	/*
	 * We just need something here that even the most clever compiler
	 * cannot optimize away.
	 */
	return (a[(uintptr_t)f]);
}

/*
 * Atomically increment a specified error counter from probe context.
 */
static void
dtrace_error(uint32_t *counter)
{
	/*
	 * Most counters stored to in probe context are per-CPU counters.
	 * However, there are some error conditions that are sufficiently
	 * arcane that they don't merit per-CPU storage.  If these counters
	 * are incremented concurrently on different CPUs, scalability will be
	 * adversely affected -- but we don't expect them to be white-hot in a
	 * correctly constructed enabling...
	 */
	uint32_t oval, nval;

	do {
		oval = *counter;

		if ((nval = oval + 1) == 0) {
			/*
			 * If the counter would wrap, set it to 1 -- assuring
			 * that the counter is never zero when we have seen
			 * errors.  (The counter must be 32-bits because we
			 * aren't guaranteed a 64-bit compare&swap operation.)
			 * To save this code both the infamy of being fingered
			 * by a priggish news story and the indignity of being
			 * the target of a neo-puritan witch trial, we're
			 * carefully avoiding any colorful description of the
			 * likelihood of this condition -- but suffice it to
			 * say that it is only slightly more likely than the
			 * overflow of predicate cache IDs, as discussed in
			 * dtrace_predicate_create().
			 */
			nval = 1;
		}
	} while (dtrace_cas32(counter, oval, nval) != oval);
}

/*
 * Use the DTRACE_LOADFUNC macro to define functions for each of loading a
 * uint8_t, a uint16_t, a uint32_t and a uint64_t.
 */
DTRACE_LOADFUNC(8)
DTRACE_LOADFUNC(16)
DTRACE_LOADFUNC(32)
DTRACE_LOADFUNC(64)

static int
dtrace_inscratch(uintptr_t dest, size_t size, dtrace_mstate_t *mstate)
{
	if (dest < mstate->dtms_scratch_base)
		return (0);

	if (dest + size < dest)
		return (0);

	if (dest + size > mstate->dtms_scratch_ptr)
		return (0);

	return (1);
}

static int
dtrace_canstore_statvar(uint64_t addr, size_t sz, size_t *remain,
    dtrace_statvar_t **svars, int nsvars)
{
	int i;

	size_t maxglobalsize, maxlocalsize;

	maxglobalsize = dtrace_statvar_maxsize + sizeof (uint64_t);
	maxlocalsize = (maxglobalsize) * NCPU;

	if (nsvars == 0)
		return (0);

	for (i = 0; i < nsvars; i++) {
		dtrace_statvar_t *svar = svars[i];
		uint8_t scope;
		size_t size;

		if (svar == NULL || (size = svar->dtsv_size) == 0)
			continue;

		scope = svar->dtsv_var.dtdv_scope;

		/**
		 * We verify that our size is valid in the spirit of providing
		 * defense in depth:  we want to prevent attackers from using
		 * DTrace to escalate an orthogonal kernel heap corruption bug
		 * into the ability to store to arbitrary locations in memory.
		 */
		VERIFY((scope == DIFV_SCOPE_GLOBAL && size <= maxglobalsize) ||
			(scope == DIFV_SCOPE_LOCAL && size <= maxlocalsize));

		if (DTRACE_INRANGE(addr, sz, svar->dtsv_data, svar->dtsv_size)) {
			DTRACE_RANGE_REMAIN(remain, addr, svar->dtsv_data,
				svar->dtsv_size);
			return (1);
		}
	}

	return (0);
}

/*
 * Check to see if the address is within a memory region to which a store may
 * be issued.  This includes the DTrace scratch areas, and any DTrace variable
 * region.  The caller of dtrace_canstore() is responsible for performing any
 * alignment checks that are needed before stores are actually executed.
 */
static int
dtrace_canstore(uint64_t addr, size_t sz, dtrace_mstate_t *mstate,
    dtrace_vstate_t *vstate)
{
	return (dtrace_canstore_remains(addr, sz, NULL, mstate, vstate));
}
/*
 * Implementation of dtrace_canstore which communicates the upper bound of the
 * allowed memory region.
 */
static int
dtrace_canstore_remains(uint64_t addr, size_t sz, size_t *remain,
	dtrace_mstate_t *mstate, dtrace_vstate_t *vstate)
{
	/*
	 * First, check to see if the address is in scratch space...
	 */
	if (DTRACE_INRANGE(addr, sz, mstate->dtms_scratch_base,
	    mstate->dtms_scratch_size)) {
		DTRACE_RANGE_REMAIN(remain, addr, mstate->dtms_scratch_base,
			mstate->dtms_scratch_size);
		return (1);
	}
	/*
	 * Now check to see if it's a dynamic variable.  This check will pick
	 * up both thread-local variables and any global dynamically-allocated
	 * variables.
	 */
	if (DTRACE_INRANGE(addr, sz, (uintptr_t)vstate->dtvs_dynvars.dtds_base,
	    vstate->dtvs_dynvars.dtds_size)) {
		dtrace_dstate_t *dstate = &vstate->dtvs_dynvars;
		uintptr_t base = (uintptr_t)dstate->dtds_base +
		    (dstate->dtds_hashsize * sizeof (dtrace_dynhash_t));
		uintptr_t chunkoffs;
		dtrace_dynvar_t *dvar;

		/*
		 * Before we assume that we can store here, we need to make
		 * sure that it isn't in our metadata -- storing to our
		 * dynamic variable metadata would corrupt our state.  For
		 * the range to not include any dynamic variable metadata,
		 * it must:
		 *
		 *	(1) Start above the hash table that is at the base of
		 *	the dynamic variable space
		 *
		 *	(2) Have a starting chunk offset that is beyond the
		 *	dtrace_dynvar_t that is at the base of every chunk
		 *
		 *	(3) Not span a chunk boundary
		 *
		 *	(4) Not be in the tuple space of a dynamic variable
		 *
		 */
		if (addr < base)
			return (0);

		chunkoffs = (addr - base) % dstate->dtds_chunksize;

		if (chunkoffs < sizeof (dtrace_dynvar_t))
			return (0);

		if (chunkoffs + sz > dstate->dtds_chunksize)
			return (0);

		dvar = (dtrace_dynvar_t *)((uintptr_t)addr - chunkoffs);

		if (dvar->dtdv_hashval == DTRACE_DYNHASH_FREE)
			return (0);

		if (chunkoffs < sizeof (dtrace_dynvar_t) +
			((dvar->dtdv_tuple.dtt_nkeys - 1) * sizeof (dtrace_key_t)))
			return (0);

		return (1);
	}

	/*
	 * Finally, check the static local and global variables.  These checks
	 * take the longest, so we perform them last.
	 */
	if (dtrace_canstore_statvar(addr, sz, remain,
	    vstate->dtvs_locals, vstate->dtvs_nlocals))
		return (1);

	if (dtrace_canstore_statvar(addr, sz, remain,
	    vstate->dtvs_globals, vstate->dtvs_nglobals))
		return (1);

	return (0);
}


/*
 * Convenience routine to check to see if the address is within a memory
 * region in which a load may be issued given the user's privilege level;
 * if not, it sets the appropriate error flags and loads 'addr' into the
 * illegal value slot.
 *
 * DTrace subroutines (DIF_SUBR_*) should use this helper to implement
 * appropriate memory access protection.
 */
static int
dtrace_canload(uint64_t addr, size_t sz, dtrace_mstate_t *mstate,
    dtrace_vstate_t *vstate)
{
	return (dtrace_canload_remains(addr, sz, NULL, mstate, vstate));
}

/*
 * Implementation of dtrace_canload which communicates the upper bound of the
 * allowed memory region.
 */
static int
dtrace_canload_remains(uint64_t addr, size_t sz, size_t *remain,
	dtrace_mstate_t *mstate, dtrace_vstate_t *vstate)
{
	volatile uint64_t *illval = &cpu_core[CPU->cpu_id].cpuc_dtrace_illval;

	/*
	 * If we hold the privilege to read from kernel memory, then
	 * everything is readable.
	 */
	if ((mstate->dtms_access & DTRACE_ACCESS_KERNEL) != 0) {
		DTRACE_RANGE_REMAIN(remain, addr, addr, sz);
		return (1);
	}

	/*
	 * You can obviously read that which you can store.
	 */
	if (dtrace_canstore_remains(addr, sz, remain, mstate, vstate))
		return (1);

	/*
	 * We're allowed to read from our own string table.
	 */
	if (DTRACE_INRANGE(addr, sz, (uintptr_t)mstate->dtms_difo->dtdo_strtab,
	    mstate->dtms_difo->dtdo_strlen)) {
		DTRACE_RANGE_REMAIN(remain, addr,
			mstate->dtms_difo->dtdo_strtab,
			mstate->dtms_difo->dtdo_strlen);
		return (1);
	}

	DTRACE_CPUFLAG_SET(CPU_DTRACE_KPRIV);
	*illval = addr;
	return (0);
}

/*
 * Convenience routine to check to see if a given string is within a memory
 * region in which a load may be issued given the user's privilege level;
 * this exists so that we don't need to issue unnecessary dtrace_strlen()
 * calls in the event that the user has all privileges.
 */
static int
dtrace_strcanload(uint64_t addr, size_t sz, size_t *remain,
	dtrace_mstate_t *mstate, dtrace_vstate_t *vstate)
{
	size_t rsize;

	/*
	 * If we hold the privilege to read from kernel memory, then
	 * everything is readable.
	 */
	if ((mstate->dtms_access & DTRACE_ACCESS_KERNEL) != 0) {
		DTRACE_RANGE_REMAIN(remain, addr, addr, sz);
		return (1);
	}

	/*
	 * Even if the caller is uninterested in querying the remaining valid
	 * range, it is required to ensure that the access is allowed.
	 */
	if (remain == NULL) {
		remain = &rsize;
	}
	if (dtrace_canload_remains(addr, 0, remain, mstate, vstate)) {
		size_t strsz;
		/*
		 * Perform the strlen after determining the length of the
		 * memory region which is accessible.  This prevents timing
		 * information from being used to find NULs in memory which is
		 * not accessible to the caller.
		 */
		strsz = 1 + dtrace_strlen((char *)(uintptr_t)addr,
			MIN(sz, *remain));
		if (strsz <= *remain) {
			return (1);
		}
	}

	return (0);
}

/*
 * Convenience routine to check to see if a given variable is within a memory
 * region in which a load may be issued given the user's privilege level.
 */
static int
dtrace_vcanload(void *src, dtrace_diftype_t *type, size_t *remain,
	dtrace_mstate_t *mstate, dtrace_vstate_t *vstate)
{
	size_t sz;
	ASSERT(type->dtdt_flags & DIF_TF_BYREF);

	/*
	 * Calculate the max size before performing any checks since even
	 * DTRACE_ACCESS_KERNEL-credentialed callers expect that this function
	 * return the max length via 'remain'.
	 */
	if (type->dtdt_kind == DIF_TYPE_STRING) {
		dtrace_state_t *state = vstate->dtvs_state;

		if (state != NULL) {
			sz = state->dts_options[DTRACEOPT_STRSIZE];
		} else {
			/*
			 * In helper context, we have a NULL state; fall back
			 * to using the system-wide default for the string size
			 * in this case.
			 */
			sz = dtrace_strsize_default;
		}
	} else {
		sz = type->dtdt_size;
	}

	/*
	 * If we hold the privilege to read from kernel memory, then
	 * everything is readable.
	 */
	if ((mstate->dtms_access & DTRACE_ACCESS_KERNEL) != 0) {
		DTRACE_RANGE_REMAIN(remain, (uintptr_t)src, src, sz);
		return (1);
	}

	if (type->dtdt_kind == DIF_TYPE_STRING) {
		return (dtrace_strcanload((uintptr_t)src, sz, remain, mstate,
			vstate));
	}
	return (dtrace_canload_remains((uintptr_t)src, sz, remain, mstate,
		vstate));
}

/*
 * Compare two strings using safe loads.
 */
static int
dtrace_strncmp(char *s1, char *s2, size_t limit)
{
	uint8_t c1, c2;
	volatile uint16_t *flags;

	if (s1 == s2 || limit == 0)
		return (0);

	flags = (volatile uint16_t *)&cpu_core[CPU->cpu_id].cpuc_dtrace_flags;

	do {
		if (s1 == NULL) {
			c1 = '\0';
		} else {
			c1 = dtrace_load8((uintptr_t)s1++);
		}

		if (s2 == NULL) {
			c2 = '\0';
		} else {
			c2 = dtrace_load8((uintptr_t)s2++);
		}

		if (c1 != c2)
			return (c1 - c2);
	} while (--limit && c1 != '\0' && !(*flags & CPU_DTRACE_FAULT));

	return (0);
}

/*
 * Compute strlen(s) for a string using safe memory accesses.  The additional
 * len parameter is used to specify a maximum length to ensure completion.
 */
static size_t
dtrace_strlen(const char *s, size_t lim)
{
	uint_t len;

	for (len = 0; len != lim; len++) {
		if (dtrace_load8((uintptr_t)s++) == '\0')
			break;
	}

	return (len);
}

/*
 * Check if an address falls within a toxic region.
 */
static int
dtrace_istoxic(uintptr_t kaddr, size_t size)
{
	uintptr_t taddr, tsize;
	int i;

	for (i = 0; i < dtrace_toxranges; i++) {
		taddr = dtrace_toxrange[i].dtt_base;
		tsize = dtrace_toxrange[i].dtt_limit - taddr;

		if (kaddr - taddr < tsize) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpu_core[CPU->cpu_id].cpuc_dtrace_illval = kaddr;
			return (1);
		}

		if (taddr - kaddr < size) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpu_core[CPU->cpu_id].cpuc_dtrace_illval = taddr;
			return (1);
		}
	}

	return (0);
}

/*
 * Copy src to dst using safe memory accesses.  The src is assumed to be unsafe
 * memory specified by the DIF program.  The dst is assumed to be safe memory
 * that we can store to directly because it is managed by DTrace.  As with
 * standard bcopy, overlapping copies are handled properly.
 */
static void
dtrace_bcopy(const void *src, void *dst, size_t len)
{
	if (len != 0) {
		uint8_t *s1 = dst;
		const uint8_t *s2 = src;

		if (s1 <= s2) {
			do {
				*s1++ = dtrace_load8((uintptr_t)s2++);
			} while (--len != 0);
		} else {
			s2 += len;
			s1 += len;

			do {
				*--s1 = dtrace_load8((uintptr_t)--s2);
			} while (--len != 0);
		}
	}
}

/*
 * Copy src to dst using safe memory accesses, up to either the specified
 * length, or the point that a nul byte is encountered.  The src is assumed to
 * be unsafe memory specified by the DIF program.  The dst is assumed to be
 * safe memory that we can store to directly because it is managed by DTrace.
 * Unlike dtrace_bcopy(), overlapping regions are not handled.
 */
static void
dtrace_strcpy(const void *src, void *dst, size_t len)
{
	if (len != 0) {
		uint8_t *s1 = dst, c;
		const uint8_t *s2 = src;

		do {
			*s1++ = c = dtrace_load8((uintptr_t)s2++);
		} while (--len != 0 && c != '\0');
	}
}

/*
 * Copy src to dst, deriving the size and type from the specified (BYREF)
 * variable type.  The src is assumed to be unsafe memory specified by the DIF
 * program.  The dst is assumed to be DTrace variable memory that is of the
 * specified type; we assume that we can store to directly.
 */
static void
dtrace_vcopy(void *src, void *dst, dtrace_diftype_t *type, size_t limit)
{
	ASSERT(type->dtdt_flags & DIF_TF_BYREF);

	if (type->dtdt_kind == DIF_TYPE_STRING) {
		dtrace_strcpy(src, dst, MIN(type->dtdt_size, limit));
	} else {
		dtrace_bcopy(src, dst, MIN(type->dtdt_size, limit));
	}
}

/*
 * Compare s1 to s2 using safe memory accesses.  The s1 data is assumed to be
 * unsafe memory specified by the DIF program.  The s2 data is assumed to be
 * safe memory that we can access directly because it is managed by DTrace.
 */
static int
dtrace_bcmp(const void *s1, const void *s2, size_t len)
{
	volatile uint16_t *flags;

	flags = (volatile uint16_t *)&cpu_core[CPU->cpu_id].cpuc_dtrace_flags;

	if (s1 == s2)
		return (0);

	if (s1 == NULL || s2 == NULL)
		return (1);

	if (s1 != s2 && len != 0) {
		const uint8_t *ps1 = s1;
		const uint8_t *ps2 = s2;

		do {
			if (dtrace_load8((uintptr_t)ps1++) != *ps2++)
				return (1);
		} while (--len != 0 && !(*flags & CPU_DTRACE_FAULT));
	}
	return (0);
}

/*
 * Zero the specified region using a simple byte-by-byte loop.  Note that this
 * is for safe DTrace-managed memory only.
 */
static void
dtrace_bzero(void *dst, size_t len)
{
	uchar_t *cp;

	for (cp = dst; len != 0; len--)
		*cp++ = 0;
}

static void
dtrace_add_128(uint64_t *addend1, uint64_t *addend2, uint64_t *sum)
{
	uint64_t result[2];

	result[0] = addend1[0] + addend2[0];
	result[1] = addend1[1] + addend2[1] +
	    (result[0] < addend1[0] || result[0] < addend2[0] ? 1 : 0);

	sum[0] = result[0];
	sum[1] = result[1];
}

/*
 * Shift the 128-bit value in a by b. If b is positive, shift left.
 * If b is negative, shift right.
 */
static void
dtrace_shift_128(uint64_t *a, int b)
{
	uint64_t mask;

	if (b == 0)
		return;

	if (b < 0) {
		b = -b;
		if (b >= 64) {
			a[0] = a[1] >> (b - 64);
			a[1] = 0;
		} else {
			a[0] >>= b;
			mask = 1LL << (64 - b);
			mask -= 1;
			a[0] |= ((a[1] & mask) << (64 - b));
			a[1] >>= b;
		}
	} else {
		if (b >= 64) {
			a[1] = a[0] << (b - 64);
			a[0] = 0;
		} else {
			a[1] <<= b;
			mask = a[0] >> (64 - b);
			a[1] |= mask;
			a[0] <<= b;
		}
	}
}

/*
 * The basic idea is to break the 2 64-bit values into 4 32-bit values,
 * use native multiplication on those, and then re-combine into the
 * resulting 128-bit value.
 *
 * (hi1 << 32 + lo1) * (hi2 << 32 + lo2) =
 *     hi1 * hi2 << 64 +
 *     hi1 * lo2 << 32 +
 *     hi2 * lo1 << 32 +
 *     lo1 * lo2
 */
static void
dtrace_multiply_128(uint64_t factor1, uint64_t factor2, uint64_t *product)
{
	uint64_t hi1, hi2, lo1, lo2;
	uint64_t tmp[2];

	hi1 = factor1 >> 32;
	hi2 = factor2 >> 32;

	lo1 = factor1 & DT_MASK_LO;
	lo2 = factor2 & DT_MASK_LO;

	product[0] = lo1 * lo2;
	product[1] = hi1 * hi2;

	tmp[0] = hi1 * lo2;
	tmp[1] = 0;
	dtrace_shift_128(tmp, 32);
	dtrace_add_128(product, tmp, product);

	tmp[0] = hi2 * lo1;
	tmp[1] = 0;
	dtrace_shift_128(tmp, 32);
	dtrace_add_128(product, tmp, product);
}

/*
 * This privilege check should be used by actions and subroutines to
 * verify that the user credentials of the process that enabled the
 * invoking ECB match the target credentials
 */
static int
dtrace_priv_proc_common_user(dtrace_state_t *state)
{
	cred_t *cr, *s_cr = state->dts_cred.dcr_cred;

	/*
	 * We should always have a non-NULL state cred here, since if cred
	 * is null (anonymous tracing), we fast-path bypass this routine.
	 */
	ASSERT(s_cr != NULL);

	if ((cr = dtrace_CRED()) != NULL &&
	    posix_cred_get(s_cr)->cr_uid == posix_cred_get(cr)->cr_uid &&
	    posix_cred_get(s_cr)->cr_uid == posix_cred_get(cr)->cr_ruid &&
	    posix_cred_get(s_cr)->cr_uid == posix_cred_get(cr)->cr_suid &&
	    posix_cred_get(s_cr)->cr_gid == posix_cred_get(cr)->cr_gid &&
	    posix_cred_get(s_cr)->cr_gid == posix_cred_get(cr)->cr_rgid &&
	    posix_cred_get(s_cr)->cr_gid == posix_cred_get(cr)->cr_sgid)
		return (1);

	return (0);
}

/*
 * This privilege check should be used by actions and subroutines to
 * verify that the zone of the process that enabled the invoking ECB
 * matches the target credentials
 */
static int
dtrace_priv_proc_common_zone(dtrace_state_t *state)
{
	cred_t *cr, *s_cr = state->dts_cred.dcr_cred;
#pragma unused(cr, s_cr, state) /* __APPLE__ */

	/*
	 * We should always have a non-NULL state cred here, since if cred
	 * is null (anonymous tracing), we fast-path bypass this routine.
	 */
	ASSERT(s_cr != NULL);

	return 1; /* APPLE NOTE: Darwin doesn't do zones. */
}

/*
 * This privilege check should be used by actions and subroutines to
 * verify that the process has not setuid or changed credentials.
 */
static int
dtrace_priv_proc_common_nocd(void)
{
	return 1; /* Darwin omits "No Core Dump" flag. */
}

static int
dtrace_priv_proc_destructive(dtrace_state_t *state)
{
	int action = state->dts_cred.dcr_action;

	if (ISSET(current_proc()->p_lflag, P_LNOATTACH))
		goto bad;

	if (dtrace_is_restricted() && !dtrace_can_attach_to_proc(current_proc()))
		goto bad;

	if (((action & DTRACE_CRA_PROC_DESTRUCTIVE_ALLZONE) == 0) &&
	    dtrace_priv_proc_common_zone(state) == 0)
		goto bad;

	if (((action & DTRACE_CRA_PROC_DESTRUCTIVE_ALLUSER) == 0) &&
	    dtrace_priv_proc_common_user(state) == 0)
		goto bad;

	if (((action & DTRACE_CRA_PROC_DESTRUCTIVE_CREDCHG) == 0) &&
	    dtrace_priv_proc_common_nocd() == 0)
		goto bad;

	return (1);

bad:
	cpu_core[CPU->cpu_id].cpuc_dtrace_flags |= CPU_DTRACE_UPRIV;

	return (0);
}

static int
dtrace_priv_proc_control(dtrace_state_t *state)
{
	if (ISSET(current_proc()->p_lflag, P_LNOATTACH))
		goto bad;

	if (dtrace_is_restricted() && !dtrace_can_attach_to_proc(current_proc()))
		goto bad;

	if (state->dts_cred.dcr_action & DTRACE_CRA_PROC_CONTROL)
		return (1);

	if (dtrace_priv_proc_common_zone(state) &&
	    dtrace_priv_proc_common_user(state) &&
	    dtrace_priv_proc_common_nocd())
		return (1);

bad:
	cpu_core[CPU->cpu_id].cpuc_dtrace_flags |= CPU_DTRACE_UPRIV;

	return (0);
}

static int
dtrace_priv_proc(dtrace_state_t *state)
{
	if (ISSET(current_proc()->p_lflag, P_LNOATTACH))
		goto bad;

	if (dtrace_is_restricted() && !dtrace_are_restrictions_relaxed() && !dtrace_can_attach_to_proc(current_proc()))
		goto bad;

	if (state->dts_cred.dcr_action & DTRACE_CRA_PROC)
		return (1);

bad:
	cpu_core[CPU->cpu_id].cpuc_dtrace_flags |= CPU_DTRACE_UPRIV;

	return (0);
}

/*
 * The P_LNOATTACH check is an Apple specific check.
 * We need a version of dtrace_priv_proc() that omits
 * that check for PID and EXECNAME accesses
 */
static int
dtrace_priv_proc_relaxed(dtrace_state_t *state)
{

	if (state->dts_cred.dcr_action & DTRACE_CRA_PROC)
		return (1);

	cpu_core[CPU->cpu_id].cpuc_dtrace_flags |= CPU_DTRACE_UPRIV;

	return (0);
}

static int
dtrace_priv_kernel(dtrace_state_t *state)
{
	if (dtrace_is_restricted() && !dtrace_are_restrictions_relaxed())
		goto bad;

	if (state->dts_cred.dcr_action & DTRACE_CRA_KERNEL)
		return (1);

bad:
	cpu_core[CPU->cpu_id].cpuc_dtrace_flags |= CPU_DTRACE_KPRIV;

	return (0);
}

static int
dtrace_priv_kernel_destructive(dtrace_state_t *state)
{
	if (dtrace_is_restricted())
		goto bad;

	if (state->dts_cred.dcr_action & DTRACE_CRA_KERNEL_DESTRUCTIVE)
		return (1);

bad:
	cpu_core[CPU->cpu_id].cpuc_dtrace_flags |= CPU_DTRACE_KPRIV;

	return (0);
}

/*
 * Note:  not called from probe context.  This function is called
 * asynchronously (and at a regular interval) from outside of probe context to
 * clean the dirty dynamic variable lists on all CPUs.  Dynamic variable
 * cleaning is explained in detail in <sys/dtrace_impl.h>.
 */
static void
dtrace_dynvar_clean(dtrace_dstate_t *dstate)
{
	dtrace_dynvar_t *dirty;
	dtrace_dstate_percpu_t *dcpu;
	int i, work = 0;

	for (i = 0; i < (int)NCPU; i++) {
		dcpu = &dstate->dtds_percpu[i];

		ASSERT(dcpu->dtdsc_rinsing == NULL);

		/*
		 * If the dirty list is NULL, there is no dirty work to do.
		 */
		if (dcpu->dtdsc_dirty == NULL)
			continue;

		/*
		 * If the clean list is non-NULL, then we're not going to do
		 * any work for this CPU -- it means that there has not been
		 * a dtrace_dynvar() allocation on this CPU (or from this CPU)
		 * since the last time we cleaned house.
		 */
		if (dcpu->dtdsc_clean != NULL)
			continue;

		work = 1;

		/*
		 * Atomically move the dirty list aside.
		 */
		do {
			dirty = dcpu->dtdsc_dirty;

			/*
			 * Before we zap the dirty list, set the rinsing list.
			 * (This allows for a potential assertion in
			 * dtrace_dynvar():  if a free dynamic variable appears
			 * on a hash chain, either the dirty list or the
			 * rinsing list for some CPU must be non-NULL.)
			 */
			dcpu->dtdsc_rinsing = dirty;
			dtrace_membar_producer();
		} while (dtrace_casptr(&dcpu->dtdsc_dirty,
		    dirty, NULL) != dirty);
	}

	if (!work) {
		/*
		 * We have no work to do; we can simply return.
		 */
		return;
	}

	dtrace_sync();

	for (i = 0; i < (int)NCPU; i++) {
		dcpu = &dstate->dtds_percpu[i];

		if (dcpu->dtdsc_rinsing == NULL)
			continue;

		/*
		 * We are now guaranteed that no hash chain contains a pointer
		 * into this dirty list; we can make it clean.
		 */
		ASSERT(dcpu->dtdsc_clean == NULL);
		dcpu->dtdsc_clean = dcpu->dtdsc_rinsing;
		dcpu->dtdsc_rinsing = NULL;
	}

	/*
	 * Before we actually set the state to be DTRACE_DSTATE_CLEAN, make
	 * sure that all CPUs have seen all of the dtdsc_clean pointers.
	 * This prevents a race whereby a CPU incorrectly decides that
	 * the state should be something other than DTRACE_DSTATE_CLEAN
	 * after dtrace_dynvar_clean() has completed.
	 */
	dtrace_sync();

	dstate->dtds_state = DTRACE_DSTATE_CLEAN;
}

/*
 * Depending on the value of the op parameter, this function looks-up,
 * allocates or deallocates an arbitrarily-keyed dynamic variable.  If an
 * allocation is requested, this function will return a pointer to a
 * dtrace_dynvar_t corresponding to the allocated variable -- or NULL if no
 * variable can be allocated.  If NULL is returned, the appropriate counter
 * will be incremented.
 */
static dtrace_dynvar_t *
dtrace_dynvar(dtrace_dstate_t *dstate, uint_t nkeys,
    dtrace_key_t *key, size_t dsize, dtrace_dynvar_op_t op,
    dtrace_mstate_t *mstate, dtrace_vstate_t *vstate)
{
	uint64_t hashval = DTRACE_DYNHASH_VALID;
	dtrace_dynhash_t *hash = dstate->dtds_hash;
	dtrace_dynvar_t *free, *new_free, *next, *dvar, *start, *prev = NULL;
	processorid_t me = CPU->cpu_id, cpu = me;
	dtrace_dstate_percpu_t *dcpu = &dstate->dtds_percpu[me];
	size_t bucket, ksize;
	size_t chunksize = dstate->dtds_chunksize;
	uintptr_t kdata, lock, nstate;
	uint_t i;

	ASSERT(nkeys != 0);

	/*
	 * Hash the key.  As with aggregations, we use Jenkins' "One-at-a-time"
	 * algorithm.  For the by-value portions, we perform the algorithm in
	 * 16-bit chunks (as opposed to 8-bit chunks).  This speeds things up a
	 * bit, and seems to have only a minute effect on distribution.  For
	 * the by-reference data, we perform "One-at-a-time" iterating (safely)
	 * over each referenced byte.  It's painful to do this, but it's much
	 * better than pathological hash distribution.  The efficacy of the
	 * hashing algorithm (and a comparison with other algorithms) may be
	 * found by running the ::dtrace_dynstat MDB dcmd.
	 */
	for (i = 0; i < nkeys; i++) {
		if (key[i].dttk_size == 0) {
			uint64_t val = key[i].dttk_value;

			hashval += (val >> 48) & 0xffff;
			hashval += (hashval << 10);
			hashval ^= (hashval >> 6);

			hashval += (val >> 32) & 0xffff;
			hashval += (hashval << 10);
			hashval ^= (hashval >> 6);

			hashval += (val >> 16) & 0xffff;
			hashval += (hashval << 10);
			hashval ^= (hashval >> 6);

			hashval += val & 0xffff;
			hashval += (hashval << 10);
			hashval ^= (hashval >> 6);
		} else {
			/*
			 * This is incredibly painful, but it beats the hell
			 * out of the alternative.
			 */
			uint64_t j, size = key[i].dttk_size;
			uintptr_t base = (uintptr_t)key[i].dttk_value;

			if (!dtrace_canload(base, size, mstate, vstate))
				break;

			for (j = 0; j < size; j++) {
				hashval += dtrace_load8(base + j);
				hashval += (hashval << 10);
				hashval ^= (hashval >> 6);
			}
		}
	}

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_FAULT))
		return (NULL);

	hashval += (hashval << 3);
	hashval ^= (hashval >> 11);
	hashval += (hashval << 15);

	/*
	 * There is a remote chance (ideally, 1 in 2^31) that our hashval
	 * comes out to be one of our two sentinel hash values.  If this
	 * actually happens, we set the hashval to be a value known to be a
	 * non-sentinel value.
	 */
	if (hashval == DTRACE_DYNHASH_FREE || hashval == DTRACE_DYNHASH_SINK)
		hashval = DTRACE_DYNHASH_VALID;

	/*
	 * Yes, it's painful to do a divide here.  If the cycle count becomes
	 * important here, tricks can be pulled to reduce it.  (However, it's
	 * critical that hash collisions be kept to an absolute minimum;
	 * they're much more painful than a divide.)  It's better to have a
	 * solution that generates few collisions and still keeps things
	 * relatively simple.
	 */
	bucket = hashval % dstate->dtds_hashsize;

	if (op == DTRACE_DYNVAR_DEALLOC) {
		volatile uintptr_t *lockp = &hash[bucket].dtdh_lock;

		for (;;) {
			while ((lock = *lockp) & 1)
				continue;

			if (dtrace_casptr((void *)(uintptr_t)lockp,
			    (void *)lock, (void *)(lock + 1)) == (void *)lock)
				break;
		}

		dtrace_membar_producer();
	}

top:
	prev = NULL;
	lock = hash[bucket].dtdh_lock;

	dtrace_membar_consumer();

	start = hash[bucket].dtdh_chain;
	ASSERT(start != NULL && (start->dtdv_hashval == DTRACE_DYNHASH_SINK ||
	    start->dtdv_hashval != DTRACE_DYNHASH_FREE ||
	    op != DTRACE_DYNVAR_DEALLOC));

	for (dvar = start; dvar != NULL; dvar = dvar->dtdv_next) {
		dtrace_tuple_t *dtuple = &dvar->dtdv_tuple;
		dtrace_key_t *dkey = &dtuple->dtt_key[0];

		if (dvar->dtdv_hashval != hashval) {
			if (dvar->dtdv_hashval == DTRACE_DYNHASH_SINK) {
				/*
				 * We've reached the sink, and therefore the
				 * end of the hash chain; we can kick out of
				 * the loop knowing that we have seen a valid
				 * snapshot of state.
				 */
				ASSERT(dvar->dtdv_next == NULL);
				ASSERT(dvar == &dtrace_dynhash_sink);
				break;
			}

			if (dvar->dtdv_hashval == DTRACE_DYNHASH_FREE) {
				/*
				 * We've gone off the rails:  somewhere along
				 * the line, one of the members of this hash
				 * chain was deleted.  Note that we could also
				 * detect this by simply letting this loop run
				 * to completion, as we would eventually hit
				 * the end of the dirty list.  However, we
				 * want to avoid running the length of the
				 * dirty list unnecessarily (it might be quite
				 * long), so we catch this as early as
				 * possible by detecting the hash marker.  In
				 * this case, we simply set dvar to NULL and
				 * break; the conditional after the loop will
				 * send us back to top.
				 */
				dvar = NULL;
				break;
			}

			goto next;
		}

		if (dtuple->dtt_nkeys != nkeys)
			goto next;

		for (i = 0; i < nkeys; i++, dkey++) {
			if (dkey->dttk_size != key[i].dttk_size)
				goto next; /* size or type mismatch */

			if (dkey->dttk_size != 0) {
				if (dtrace_bcmp(
				    (void *)(uintptr_t)key[i].dttk_value,
				    (void *)(uintptr_t)dkey->dttk_value,
				    dkey->dttk_size))
					goto next;
			} else {
				if (dkey->dttk_value != key[i].dttk_value)
					goto next;
			}
		}

		if (op != DTRACE_DYNVAR_DEALLOC)
			return (dvar);

		ASSERT(dvar->dtdv_next == NULL ||
		    dvar->dtdv_next->dtdv_hashval != DTRACE_DYNHASH_FREE);

		if (prev != NULL) {
			ASSERT(hash[bucket].dtdh_chain != dvar);
			ASSERT(start != dvar);
			ASSERT(prev->dtdv_next == dvar);
			prev->dtdv_next = dvar->dtdv_next;
		} else {
			if (dtrace_casptr(&hash[bucket].dtdh_chain,
			    start, dvar->dtdv_next) != start) {
				/*
				 * We have failed to atomically swing the
				 * hash table head pointer, presumably because
				 * of a conflicting allocation on another CPU.
				 * We need to reread the hash chain and try
				 * again.
				 */
				goto top;
			}
		}

		dtrace_membar_producer();

		/*
		 * Now set the hash value to indicate that it's free.
		 */
		ASSERT(hash[bucket].dtdh_chain != dvar);
		dvar->dtdv_hashval = DTRACE_DYNHASH_FREE;

		dtrace_membar_producer();

		/*
		 * Set the next pointer to point at the dirty list, and
		 * atomically swing the dirty pointer to the newly freed dvar.
		 */
		do {
			next = dcpu->dtdsc_dirty;
			dvar->dtdv_next = next;
		} while (dtrace_casptr(&dcpu->dtdsc_dirty, next, dvar) != next);

		/*
		 * Finally, unlock this hash bucket.
		 */
		ASSERT(hash[bucket].dtdh_lock == lock);
		ASSERT(lock & 1);
		hash[bucket].dtdh_lock++;

		return (NULL);
next:
		prev = dvar;
		continue;
	}

	if (dvar == NULL) {
		/*
		 * If dvar is NULL, it is because we went off the rails:
		 * one of the elements that we traversed in the hash chain
		 * was deleted while we were traversing it.  In this case,
		 * we assert that we aren't doing a dealloc (deallocs lock
		 * the hash bucket to prevent themselves from racing with
		 * one another), and retry the hash chain traversal.
		 */
		ASSERT(op != DTRACE_DYNVAR_DEALLOC);
		goto top;
	}

	if (op != DTRACE_DYNVAR_ALLOC) {
		/*
		 * If we are not to allocate a new variable, we want to
		 * return NULL now.  Before we return, check that the value
		 * of the lock word hasn't changed.  If it has, we may have
		 * seen an inconsistent snapshot.
		 */
		if (op == DTRACE_DYNVAR_NOALLOC) {
			if (hash[bucket].dtdh_lock != lock)
				goto top;
		} else {
			ASSERT(op == DTRACE_DYNVAR_DEALLOC);
			ASSERT(hash[bucket].dtdh_lock == lock);
			ASSERT(lock & 1);
			hash[bucket].dtdh_lock++;
		}

		return (NULL);
	}

	/*
	 * We need to allocate a new dynamic variable.  The size we need is the
	 * size of dtrace_dynvar plus the size of nkeys dtrace_key_t's plus the
	 * size of any auxiliary key data (rounded up to 8-byte alignment) plus
	 * the size of any referred-to data (dsize).  We then round the final
	 * size up to the chunksize for allocation.
	 */
	for (ksize = 0, i = 0; i < nkeys; i++)
		ksize += P2ROUNDUP(key[i].dttk_size, sizeof (uint64_t));

	/*
	 * This should be pretty much impossible, but could happen if, say,
	 * strange DIF specified the tuple.  Ideally, this should be an
	 * assertion and not an error condition -- but that requires that the
	 * chunksize calculation in dtrace_difo_chunksize() be absolutely
	 * bullet-proof.  (That is, it must not be able to be fooled by
	 * malicious DIF.)  Given the lack of backwards branches in DIF,
	 * solving this would presumably not amount to solving the Halting
	 * Problem -- but it still seems awfully hard.
	 */
	if (sizeof (dtrace_dynvar_t) + sizeof (dtrace_key_t) * (nkeys - 1) +
	    ksize + dsize > chunksize) {
		dcpu->dtdsc_drops++;
		return (NULL);
	}

	nstate = DTRACE_DSTATE_EMPTY;

	do {
retry:
		free = dcpu->dtdsc_free;

		if (free == NULL) {
			dtrace_dynvar_t *clean = dcpu->dtdsc_clean;
			void *rval;

			if (clean == NULL) {
				/*
				 * We're out of dynamic variable space on
				 * this CPU.  Unless we have tried all CPUs,
				 * we'll try to allocate from a different
				 * CPU.
				 */
				switch (dstate->dtds_state) {
				case DTRACE_DSTATE_CLEAN: {
					void *sp = &dstate->dtds_state;

					if (++cpu >= (int)NCPU)
						cpu = 0;

					if (dcpu->dtdsc_dirty != NULL &&
					    nstate == DTRACE_DSTATE_EMPTY)
						nstate = DTRACE_DSTATE_DIRTY;

					if (dcpu->dtdsc_rinsing != NULL)
						nstate = DTRACE_DSTATE_RINSING;

					dcpu = &dstate->dtds_percpu[cpu];

					if (cpu != me)
						goto retry;

					(void) dtrace_cas32(sp,
					    DTRACE_DSTATE_CLEAN, nstate);

					/*
					 * To increment the correct bean
					 * counter, take another lap.
					 */
					goto retry;
				}

				case DTRACE_DSTATE_DIRTY:
					dcpu->dtdsc_dirty_drops++;
					break;

				case DTRACE_DSTATE_RINSING:
					dcpu->dtdsc_rinsing_drops++;
					break;

				case DTRACE_DSTATE_EMPTY:
					dcpu->dtdsc_drops++;
					break;
				}

				DTRACE_CPUFLAG_SET(CPU_DTRACE_DROP);
				return (NULL);
			}

			/*
			 * The clean list appears to be non-empty.  We want to
			 * move the clean list to the free list; we start by
			 * moving the clean pointer aside.
			 */
			if (dtrace_casptr(&dcpu->dtdsc_clean,
			    clean, NULL) != clean) {
				/*
				 * We are in one of two situations:
				 *
				 *  (a)	The clean list was switched to the
				 *	free list by another CPU.
				 *
				 *  (b)	The clean list was added to by the
				 *	cleansing cyclic.
				 *
				 * In either of these situations, we can
				 * just reattempt the free list allocation.
				 */
				goto retry;
			}

			ASSERT(clean->dtdv_hashval == DTRACE_DYNHASH_FREE);

			/*
			 * Now we'll move the clean list to the free list.
			 * It's impossible for this to fail:  the only way
			 * the free list can be updated is through this
			 * code path, and only one CPU can own the clean list.
			 * Thus, it would only be possible for this to fail if
			 * this code were racing with dtrace_dynvar_clean().
			 * (That is, if dtrace_dynvar_clean() updated the clean
			 * list, and we ended up racing to update the free
			 * list.)  This race is prevented by the dtrace_sync()
			 * in dtrace_dynvar_clean() -- which flushes the
			 * owners of the clean lists out before resetting
			 * the clean lists.
			 */
			rval = dtrace_casptr(&dcpu->dtdsc_free, NULL, clean);
			ASSERT(rval == NULL);
			goto retry;
		}

		dvar = free;
		new_free = dvar->dtdv_next;
	} while (dtrace_casptr(&dcpu->dtdsc_free, free, new_free) != free);

	/*
	 * We have now allocated a new chunk.  We copy the tuple keys into the
	 * tuple array and copy any referenced key data into the data space
	 * following the tuple array.  As we do this, we relocate dttk_value
	 * in the final tuple to point to the key data address in the chunk.
	 */
	kdata = (uintptr_t)&dvar->dtdv_tuple.dtt_key[nkeys];
	dvar->dtdv_data = (void *)(kdata + ksize);
	dvar->dtdv_tuple.dtt_nkeys = nkeys;

	for (i = 0; i < nkeys; i++) {
		dtrace_key_t *dkey = &dvar->dtdv_tuple.dtt_key[i];
		size_t kesize = key[i].dttk_size;

		if (kesize != 0) {
			dtrace_bcopy(
			    (const void *)(uintptr_t)key[i].dttk_value,
			    (void *)kdata, kesize);
			dkey->dttk_value = kdata;
			kdata += P2ROUNDUP(kesize, sizeof (uint64_t));
		} else {
			dkey->dttk_value = key[i].dttk_value;
		}

		dkey->dttk_size = kesize;
	}

	ASSERT(dvar->dtdv_hashval == DTRACE_DYNHASH_FREE);
	dvar->dtdv_hashval = hashval;
	dvar->dtdv_next = start;

	if (dtrace_casptr(&hash[bucket].dtdh_chain, start, dvar) == start)
		return (dvar);

	/*
	 * The cas has failed.  Either another CPU is adding an element to
	 * this hash chain, or another CPU is deleting an element from this
	 * hash chain.  The simplest way to deal with both of these cases
	 * (though not necessarily the most efficient) is to free our
	 * allocated block and tail-call ourselves.  Note that the free is
	 * to the dirty list and _not_ to the free list.  This is to prevent
	 * races with allocators, above.
	 */
	dvar->dtdv_hashval = DTRACE_DYNHASH_FREE;

	dtrace_membar_producer();

	do {
		free = dcpu->dtdsc_dirty;
		dvar->dtdv_next = free;
	} while (dtrace_casptr(&dcpu->dtdsc_dirty, free, dvar) != free);

	return (dtrace_dynvar(dstate, nkeys, key, dsize, op, mstate, vstate));
}

/*ARGSUSED*/
static void
dtrace_aggregate_min(uint64_t *oval, uint64_t nval, uint64_t arg)
{
#pragma unused(arg) /* __APPLE__ */
	if ((int64_t)nval < (int64_t)*oval)
		*oval = nval;
}

/*ARGSUSED*/
static void
dtrace_aggregate_max(uint64_t *oval, uint64_t nval, uint64_t arg)
{
#pragma unused(arg) /* __APPLE__ */
	if ((int64_t)nval > (int64_t)*oval)
		*oval = nval;
}

static void
dtrace_aggregate_quantize(uint64_t *quanta, uint64_t nval, uint64_t incr)
{
	int i, zero = DTRACE_QUANTIZE_ZEROBUCKET;
	int64_t val = (int64_t)nval;

	if (val < 0) {
		for (i = 0; i < zero; i++) {
			if (val <= DTRACE_QUANTIZE_BUCKETVAL(i)) {
				quanta[i] += incr;
				return;
			}
		}
	} else {
		for (i = zero + 1; i < DTRACE_QUANTIZE_NBUCKETS; i++) {
			if (val < DTRACE_QUANTIZE_BUCKETVAL(i)) {
				quanta[i - 1] += incr;
				return;
			}
		}

		quanta[DTRACE_QUANTIZE_NBUCKETS - 1] += incr;
		return;
	}

	ASSERT(0);
}

static void
dtrace_aggregate_lquantize(uint64_t *lquanta, uint64_t nval, uint64_t incr)
{
	uint64_t arg = *lquanta++;
	int32_t base = DTRACE_LQUANTIZE_BASE(arg);
	uint16_t step = DTRACE_LQUANTIZE_STEP(arg);
	uint16_t levels = DTRACE_LQUANTIZE_LEVELS(arg);
	int32_t val = (int32_t)nval, level;

	ASSERT(step != 0);
	ASSERT(levels != 0);

	if (val < base) {
		/*
		 * This is an underflow.
		 */
		lquanta[0] += incr;
		return;
	}

	level = (val - base) / step;

	if (level < levels) {
		lquanta[level + 1] += incr;
		return;
	}

	/*
	 * This is an overflow.
	 */
	lquanta[levels + 1] += incr;
}

static int
dtrace_aggregate_llquantize_bucket(int16_t factor, int16_t low, int16_t high,
                                   int16_t nsteps, int64_t value)
{
	int64_t this = 1, last, next;
	int base = 1, order;

	for (order = 0; order < low; ++order)
		this *= factor;

	/*
	 * If our value is less than our factor taken to the power of the
	 * low order of magnitude, it goes into the zeroth bucket.
	 */
	if (value < this)
		return 0;
	else
		last = this;

	for (this *= factor; order <= high; ++order) {
		int nbuckets = this > nsteps ? nsteps : this;

		/*
		 * We should not generally get log/linear quantizations
		 * with a high magnitude that allows 64-bits to
		 * overflow, but we nonetheless protect against this
		 * by explicitly checking for overflow, and clamping
		 * our value accordingly.
		 */
		next = this * factor;
		if (next < this) {
			value = this - 1;
		}

		/*
		 * If our value lies within this order of magnitude,
		 * determine its position by taking the offset within
		 * the order of magnitude, dividing by the bucket
		 * width, and adding to our (accumulated) base.
		 */
		if (value < this) {
			return (base + (value - last) / (this / nbuckets));
		}

		base += nbuckets - (nbuckets / factor);
		last = this;
		this = next;
	}

	/*
	 * Our value is greater than or equal to our factor taken to the
	 * power of one plus the high magnitude -- return the top bucket.
	 */
	return base;
}

static void
dtrace_aggregate_llquantize(uint64_t *llquanta, uint64_t nval, uint64_t incr)
{
	uint64_t arg    = *llquanta++;
	uint16_t factor = DTRACE_LLQUANTIZE_FACTOR(arg);
	uint16_t low    = DTRACE_LLQUANTIZE_LOW(arg);
	uint16_t high   = DTRACE_LLQUANTIZE_HIGH(arg);
	uint16_t nsteps = DTRACE_LLQUANTIZE_NSTEP(arg);

	llquanta[dtrace_aggregate_llquantize_bucket(factor, low, high, nsteps, nval)] += incr;
}

/*ARGSUSED*/
static void
dtrace_aggregate_avg(uint64_t *data, uint64_t nval, uint64_t arg)
{
#pragma unused(arg) /* __APPLE__ */
	data[0]++;
	data[1] += nval;
}

/*ARGSUSED*/
static void
dtrace_aggregate_stddev(uint64_t *data, uint64_t nval, uint64_t arg)
{
#pragma unused(arg) /* __APPLE__ */
	int64_t snval = (int64_t)nval;
	uint64_t tmp[2];

	data[0]++;
	data[1] += nval;

	/*
	 * What we want to say here is:
	 *
	 * data[2] += nval * nval;
	 *
	 * But given that nval is 64-bit, we could easily overflow, so
	 * we do this as 128-bit arithmetic.
	 */
	if (snval < 0)
		snval = -snval;

	dtrace_multiply_128((uint64_t)snval, (uint64_t)snval, tmp);
	dtrace_add_128(data + 2, tmp, data + 2);
}

/*ARGSUSED*/
static void
dtrace_aggregate_count(uint64_t *oval, uint64_t nval, uint64_t arg)
{
#pragma unused(nval, arg) /* __APPLE__ */
	*oval = *oval + 1;
}

/*ARGSUSED*/
static void
dtrace_aggregate_sum(uint64_t *oval, uint64_t nval, uint64_t arg)
{
#pragma unused(arg) /* __APPLE__ */
	*oval += nval;
}

/*
 * Aggregate given the tuple in the principal data buffer, and the aggregating
 * action denoted by the specified dtrace_aggregation_t.  The aggregation
 * buffer is specified as the buf parameter.  This routine does not return
 * failure; if there is no space in the aggregation buffer, the data will be
 * dropped, and a corresponding counter incremented.
 */
static void
dtrace_aggregate(dtrace_aggregation_t *agg, dtrace_buffer_t *dbuf,
    intptr_t offset, dtrace_buffer_t *buf, uint64_t expr, uint64_t arg)
{
#pragma unused(arg)
	dtrace_recdesc_t *rec = &agg->dtag_action.dta_rec;
	uint32_t i, ndx, size, fsize;
	uint32_t align = sizeof (uint64_t) - 1;
	dtrace_aggbuffer_t *agb;
	dtrace_aggkey_t *key;
	uint32_t hashval = 0, limit, isstr;
	caddr_t tomax, data, kdata;
	dtrace_actkind_t action;
	dtrace_action_t *act;
	uintptr_t offs;

	if (buf == NULL)
		return;

	if (!agg->dtag_hasarg) {
		/*
		 * Currently, only quantize() and lquantize() take additional
		 * arguments, and they have the same semantics:  an increment
		 * value that defaults to 1 when not present.  If additional
		 * aggregating actions take arguments, the setting of the
		 * default argument value will presumably have to become more
		 * sophisticated...
		 */
		arg = 1;
	}

	action = agg->dtag_action.dta_kind - DTRACEACT_AGGREGATION;
	size = rec->dtrd_offset - agg->dtag_base;
	fsize = size + rec->dtrd_size;

	ASSERT(dbuf->dtb_tomax != NULL);
	data = dbuf->dtb_tomax + offset + agg->dtag_base;

	if ((tomax = buf->dtb_tomax) == NULL) {
		dtrace_buffer_drop(buf);
		return;
	}

	/*
	 * The metastructure is always at the bottom of the buffer.
	 */
	agb = (dtrace_aggbuffer_t *)(tomax + buf->dtb_size -
	    sizeof (dtrace_aggbuffer_t));

	if (buf->dtb_offset == 0) {
		/*
		 * We just kludge up approximately 1/8th of the size to be
		 * buckets.  If this guess ends up being routinely
		 * off-the-mark, we may need to dynamically readjust this
		 * based on past performance.
		 */
		uintptr_t hashsize = (buf->dtb_size >> 3) / sizeof (uintptr_t);

		if ((uintptr_t)agb - hashsize * sizeof (dtrace_aggkey_t *) <
		    (uintptr_t)tomax || hashsize == 0) {
			/*
			 * We've been given a ludicrously small buffer;
			 * increment our drop count and leave.
			 */
			dtrace_buffer_drop(buf);
			return;
		}

		/*
		 * And now, a pathetic attempt to try to get a an odd (or
		 * perchance, a prime) hash size for better hash distribution.
		 */
		if (hashsize > (DTRACE_AGGHASHSIZE_SLEW << 3))
			hashsize -= DTRACE_AGGHASHSIZE_SLEW;

		agb->dtagb_hashsize = hashsize;
		agb->dtagb_hash = (dtrace_aggkey_t **)((uintptr_t)agb -
		    agb->dtagb_hashsize * sizeof (dtrace_aggkey_t *));
		agb->dtagb_free = (uintptr_t)agb->dtagb_hash;

		for (i = 0; i < agb->dtagb_hashsize; i++)
			agb->dtagb_hash[i] = NULL;
	}

	ASSERT(agg->dtag_first != NULL);
	ASSERT(agg->dtag_first->dta_intuple);

	/*
	 * Calculate the hash value based on the key.  Note that we _don't_
	 * include the aggid in the hashing (but we will store it as part of
	 * the key).  The hashing algorithm is Bob Jenkins' "One-at-a-time"
	 * algorithm: a simple, quick algorithm that has no known funnels, and
	 * gets good distribution in practice.  The efficacy of the hashing
	 * algorithm (and a comparison with other algorithms) may be found by
	 * running the ::dtrace_aggstat MDB dcmd.
	 */
	for (act = agg->dtag_first; act->dta_intuple; act = act->dta_next) {
		i = act->dta_rec.dtrd_offset - agg->dtag_base;
		limit = i + act->dta_rec.dtrd_size;
		ASSERT(limit <= size);
		isstr = DTRACEACT_ISSTRING(act);

		for (; i < limit; i++) {
			hashval += data[i];
			hashval += (hashval << 10);
			hashval ^= (hashval >> 6);

			if (isstr && data[i] == '\0')
				break;
		}
	}

	hashval += (hashval << 3);
	hashval ^= (hashval >> 11);
	hashval += (hashval << 15);

	/*
	 * Yes, the divide here is expensive -- but it's generally the least
	 * of the performance issues given the amount of data that we iterate
	 * over to compute hash values, compare data, etc.
	 */
	ndx = hashval % agb->dtagb_hashsize;

	for (key = agb->dtagb_hash[ndx]; key != NULL; key = key->dtak_next) {
		ASSERT((caddr_t)key >= tomax);
		ASSERT((caddr_t)key < tomax + buf->dtb_size);

		if (hashval != key->dtak_hashval || key->dtak_size != size)
			continue;

		kdata = key->dtak_data;
		ASSERT(kdata >= tomax && kdata < tomax + buf->dtb_size);

		for (act = agg->dtag_first; act->dta_intuple;
		    act = act->dta_next) {
			i = act->dta_rec.dtrd_offset - agg->dtag_base;
			limit = i + act->dta_rec.dtrd_size;
			ASSERT(limit <= size);
			isstr = DTRACEACT_ISSTRING(act);

			for (; i < limit; i++) {
				if (kdata[i] != data[i])
					goto next;

				if (isstr && data[i] == '\0')
					break;
			}
		}

		if (action != key->dtak_action) {
			/*
			 * We are aggregating on the same value in the same
			 * aggregation with two different aggregating actions.
			 * (This should have been picked up in the compiler,
			 * so we may be dealing with errant or devious DIF.)
			 * This is an error condition; we indicate as much,
			 * and return.
			 */
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			return;
		}

		/*
		 * This is a hit:  we need to apply the aggregator to
		 * the value at this key.
		 */
		agg->dtag_aggregate((uint64_t *)(kdata + size), expr, arg);
		return;
next:
		continue;
	}

	/*
	 * We didn't find it.  We need to allocate some zero-filled space,
	 * link it into the hash table appropriately, and apply the aggregator
	 * to the (zero-filled) value.
	 */
	offs = buf->dtb_offset;
	while (offs & (align - 1))
		offs += sizeof (uint32_t);

	/*
	 * If we don't have enough room to both allocate a new key _and_
	 * its associated data, increment the drop count and return.
	 */
	if ((uintptr_t)tomax + offs + fsize >
	    agb->dtagb_free - sizeof (dtrace_aggkey_t)) {
		dtrace_buffer_drop(buf);
		return;
	}

	/*CONSTCOND*/
	ASSERT(!(sizeof (dtrace_aggkey_t) & (sizeof (uintptr_t) - 1)));
	key = (dtrace_aggkey_t *)(agb->dtagb_free - sizeof (dtrace_aggkey_t));
	agb->dtagb_free -= sizeof (dtrace_aggkey_t);

	key->dtak_data = kdata = tomax + offs;
	buf->dtb_offset = offs + fsize;

	/*
	 * Now copy the data across.
	 */
	*((dtrace_aggid_t *)kdata) = agg->dtag_id;

	for (i = sizeof (dtrace_aggid_t); i < size; i++)
		kdata[i] = data[i];

	/*
	 * Because strings are not zeroed out by default, we need to iterate
	 * looking for actions that store strings, and we need to explicitly
	 * pad these strings out with zeroes.
	 */
	for (act = agg->dtag_first; act->dta_intuple; act = act->dta_next) {
		int nul;

		if (!DTRACEACT_ISSTRING(act))
			continue;

		i = act->dta_rec.dtrd_offset - agg->dtag_base;
		limit = i + act->dta_rec.dtrd_size;
		ASSERT(limit <= size);

		for (nul = 0; i < limit; i++) {
			if (nul) {
				kdata[i] = '\0';
				continue;
			}

			if (data[i] != '\0')
				continue;

			nul = 1;
		}
	}

	for (i = size; i < fsize; i++)
		kdata[i] = 0;

	key->dtak_hashval = hashval;
	key->dtak_size = size;
	key->dtak_action = action;
	key->dtak_next = agb->dtagb_hash[ndx];
	agb->dtagb_hash[ndx] = key;

	/*
	 * Finally, apply the aggregator.
	 */
	*((uint64_t *)(key->dtak_data + size)) = agg->dtag_initial;
	agg->dtag_aggregate((uint64_t *)(key->dtak_data + size), expr, arg);
}

/*
 * Given consumer state, this routine finds a speculation in the INACTIVE
 * state and transitions it into the ACTIVE state.  If there is no speculation
 * in the INACTIVE state, 0 is returned.  In this case, no error counter is
 * incremented -- it is up to the caller to take appropriate action.
 */
static int
dtrace_speculation(dtrace_state_t *state)
{
	int i = 0;
	dtrace_speculation_state_t current;
	uint32_t *stat = &state->dts_speculations_unavail, count;

	while (i < state->dts_nspeculations) {
		dtrace_speculation_t *spec = &state->dts_speculations[i];

		current = spec->dtsp_state;

		if (current != DTRACESPEC_INACTIVE) {
			if (current == DTRACESPEC_COMMITTINGMANY ||
			    current == DTRACESPEC_COMMITTING ||
			    current == DTRACESPEC_DISCARDING)
				stat = &state->dts_speculations_busy;
			i++;
			continue;
		}

		if (dtrace_cas32((uint32_t *)&spec->dtsp_state,
		    current, DTRACESPEC_ACTIVE) == current)
			return (i + 1);
	}

	/*
	 * We couldn't find a speculation.  If we found as much as a single
	 * busy speculation buffer, we'll attribute this failure as "busy"
	 * instead of "unavail".
	 */
	do {
		count = *stat;
	} while (dtrace_cas32(stat, count, count + 1) != count);

	return (0);
}

/*
 * This routine commits an active speculation.  If the specified speculation
 * is not in a valid state to perform a commit(), this routine will silently do
 * nothing.  The state of the specified speculation is transitioned according
 * to the state transition diagram outlined in <sys/dtrace_impl.h>
 */
static void
dtrace_speculation_commit(dtrace_state_t *state, processorid_t cpu,
    dtrace_specid_t which)
{
	dtrace_speculation_t *spec;
	dtrace_buffer_t *src, *dest;
	uintptr_t daddr, saddr, dlimit, slimit;
	dtrace_speculation_state_t current,  new = DTRACESPEC_INACTIVE;
	intptr_t offs;
	uint64_t timestamp;

	if (which == 0)
		return;

	if (which > (dtrace_specid_t)state->dts_nspeculations) {
		cpu_core[cpu].cpuc_dtrace_flags |= CPU_DTRACE_ILLOP;
		return;
	}
	
	spec = &state->dts_speculations[which - 1];
	src = &spec->dtsp_buffer[cpu];
	dest = &state->dts_buffer[cpu];

	do {
		current = spec->dtsp_state;

		if (current == DTRACESPEC_COMMITTINGMANY)
			break;

		switch (current) {
		case DTRACESPEC_INACTIVE:
		case DTRACESPEC_DISCARDING:
			return;

		case DTRACESPEC_COMMITTING:
			/*
			 * This is only possible if we are (a) commit()'ing
			 * without having done a prior speculate() on this CPU
			 * and (b) racing with another commit() on a different
			 * CPU.  There's nothing to do -- we just assert that
			 * our offset is 0.
			 */
			ASSERT(src->dtb_offset == 0);
			return;

		case DTRACESPEC_ACTIVE:
			new = DTRACESPEC_COMMITTING;
			break;

		case DTRACESPEC_ACTIVEONE:
			/*
			 * This speculation is active on one CPU.  If our
			 * buffer offset is non-zero, we know that the one CPU
			 * must be us.  Otherwise, we are committing on a
			 * different CPU from the speculate(), and we must
			 * rely on being asynchronously cleaned.
			 */
			if (src->dtb_offset != 0) {
				new = DTRACESPEC_COMMITTING;
				break;
			}
			/*FALLTHROUGH*/

		case DTRACESPEC_ACTIVEMANY:
			new = DTRACESPEC_COMMITTINGMANY;
			break;

		default:
			ASSERT(0);
		}
	} while (dtrace_cas32((uint32_t *)&spec->dtsp_state,
	    current, new) != current);

	/*
	 * We have set the state to indicate that we are committing this
	 * speculation.  Now reserve the necessary space in the destination
	 * buffer.
	 */
	if ((offs = dtrace_buffer_reserve(dest, src->dtb_offset,
	    sizeof (uint64_t), state, NULL)) < 0) {
		dtrace_buffer_drop(dest);
		goto out;
	}

	/*
	 * We have sufficient space to copy the speculative buffer into the
	 * primary buffer.  First, modify the speculative buffer, filling
	 * in the timestamp of all entries with the current time.  The data
	 * must have the commit() time rather than the time it was traced,
	 * so that all entries in the primary buffer are in timestamp order.
	 */
	timestamp = dtrace_gethrtime();
	saddr = (uintptr_t)src->dtb_tomax;
	slimit = saddr + src->dtb_offset;
	while (saddr < slimit) {
		size_t size;
		dtrace_rechdr_t *dtrh = (dtrace_rechdr_t *)saddr;

		if (dtrh->dtrh_epid == DTRACE_EPIDNONE) {
			saddr += sizeof (dtrace_epid_t);
			continue;
		}

		ASSERT(dtrh->dtrh_epid <= ((dtrace_epid_t) state->dts_necbs));
		size = state->dts_ecbs[dtrh->dtrh_epid - 1]->dte_size;

		ASSERT(saddr + size <= slimit);
		ASSERT(size >= sizeof(dtrace_rechdr_t));
		ASSERT(DTRACE_RECORD_LOAD_TIMESTAMP(dtrh) == UINT64_MAX);

		DTRACE_RECORD_STORE_TIMESTAMP(dtrh, timestamp);

		saddr += size;
	}

	/*
	 * Copy the buffer across.  (Note that this is a
	 * highly subobtimal bcopy(); in the unlikely event that this becomes
	 * a serious performance issue, a high-performance DTrace-specific
	 * bcopy() should obviously be invented.)
	 */
	daddr = (uintptr_t)dest->dtb_tomax + offs;
	dlimit = daddr + src->dtb_offset;
	saddr = (uintptr_t)src->dtb_tomax;

	/*
	 * First, the aligned portion.
	 */
	while (dlimit - daddr >= sizeof (uint64_t)) {
		*((uint64_t *)daddr) = *((uint64_t *)saddr);

		daddr += sizeof (uint64_t);
		saddr += sizeof (uint64_t);
	}

	/*
	 * Now any left-over bit...
	 */
	while (dlimit - daddr)
		*((uint8_t *)daddr++) = *((uint8_t *)saddr++);

	/*
	 * Finally, commit the reserved space in the destination buffer.
	 */
	dest->dtb_offset = offs + src->dtb_offset;

out:
	/*
	 * If we're lucky enough to be the only active CPU on this speculation
	 * buffer, we can just set the state back to DTRACESPEC_INACTIVE.
	 */
	if (current == DTRACESPEC_ACTIVE ||
	    (current == DTRACESPEC_ACTIVEONE && new == DTRACESPEC_COMMITTING)) {
		uint32_t rval = dtrace_cas32((uint32_t *)&spec->dtsp_state,
		    DTRACESPEC_COMMITTING, DTRACESPEC_INACTIVE);
#pragma unused(rval) /* __APPLE__ */

		ASSERT(rval == DTRACESPEC_COMMITTING);
	}

	src->dtb_offset = 0;
	src->dtb_xamot_drops += src->dtb_drops;
	src->dtb_drops = 0;
}

/*
 * This routine discards an active speculation.  If the specified speculation
 * is not in a valid state to perform a discard(), this routine will silently
 * do nothing.  The state of the specified speculation is transitioned
 * according to the state transition diagram outlined in <sys/dtrace_impl.h>
 */
static void
dtrace_speculation_discard(dtrace_state_t *state, processorid_t cpu,
    dtrace_specid_t which)
{
	dtrace_speculation_t *spec;
	dtrace_speculation_state_t current, new = DTRACESPEC_INACTIVE;
	dtrace_buffer_t *buf;

	if (which == 0)
		return;

	if (which > (dtrace_specid_t)state->dts_nspeculations) {
		cpu_core[cpu].cpuc_dtrace_flags |= CPU_DTRACE_ILLOP;
		return;
	}

	spec = &state->dts_speculations[which - 1];
	buf = &spec->dtsp_buffer[cpu];

	do {
		current = spec->dtsp_state;

		switch (current) {
		case DTRACESPEC_INACTIVE:
		case DTRACESPEC_COMMITTINGMANY:
		case DTRACESPEC_COMMITTING:
		case DTRACESPEC_DISCARDING:
			return;

		case DTRACESPEC_ACTIVE:
		case DTRACESPEC_ACTIVEMANY:
			new = DTRACESPEC_DISCARDING;
			break;

		case DTRACESPEC_ACTIVEONE:
			if (buf->dtb_offset != 0) {
				new = DTRACESPEC_INACTIVE;
			} else {
				new = DTRACESPEC_DISCARDING;
			}
			break;

		default:
			ASSERT(0);
		}
	} while (dtrace_cas32((uint32_t *)&spec->dtsp_state,
	    current, new) != current);

	buf->dtb_offset = 0;
	buf->dtb_drops = 0;
}

/*
 * Note:  not called from probe context.  This function is called
 * asynchronously from cross call context to clean any speculations that are
 * in the COMMITTINGMANY or DISCARDING states.  These speculations may not be
 * transitioned back to the INACTIVE state until all CPUs have cleaned the
 * speculation.
 */
static void
dtrace_speculation_clean_here(dtrace_state_t *state)
{
	dtrace_icookie_t cookie;
	processorid_t cpu = CPU->cpu_id;
	dtrace_buffer_t *dest = &state->dts_buffer[cpu];
	dtrace_specid_t i;

	cookie = dtrace_interrupt_disable();

	if (dest->dtb_tomax == NULL) {
		dtrace_interrupt_enable(cookie);
		return;
	}

	for (i = 0; i < (dtrace_specid_t)state->dts_nspeculations; i++) {
		dtrace_speculation_t *spec = &state->dts_speculations[i];
		dtrace_buffer_t *src = &spec->dtsp_buffer[cpu];

		if (src->dtb_tomax == NULL)
			continue;

		if (spec->dtsp_state == DTRACESPEC_DISCARDING) {
			src->dtb_offset = 0;
			continue;
		}

		if (spec->dtsp_state != DTRACESPEC_COMMITTINGMANY)
			continue;

		if (src->dtb_offset == 0)
			continue;

		dtrace_speculation_commit(state, cpu, i + 1);
	}

	dtrace_interrupt_enable(cookie);
}

/*
 * Note:  not called from probe context.  This function is called
 * asynchronously (and at a regular interval) to clean any speculations that
 * are in the COMMITTINGMANY or DISCARDING states.  If it discovers that there
 * is work to be done, it cross calls all CPUs to perform that work;
 * COMMITMANY and DISCARDING speculations may not be transitioned back to the
 * INACTIVE state until they have been cleaned by all CPUs.
 */
static void
dtrace_speculation_clean(dtrace_state_t *state)
{
	int work = 0;
	uint32_t rv;
	dtrace_specid_t i;

	for (i = 0; i < (dtrace_specid_t)state->dts_nspeculations; i++) {
		dtrace_speculation_t *spec = &state->dts_speculations[i];

		ASSERT(!spec->dtsp_cleaning);

		if (spec->dtsp_state != DTRACESPEC_DISCARDING &&
		    spec->dtsp_state != DTRACESPEC_COMMITTINGMANY)
			continue;

		work++;
		spec->dtsp_cleaning = 1;
	}

	if (!work)
		return;

	dtrace_xcall(DTRACE_CPUALL,
	    (dtrace_xcall_t)dtrace_speculation_clean_here, state);

	/*
	 * We now know that all CPUs have committed or discarded their
	 * speculation buffers, as appropriate.  We can now set the state
	 * to inactive.
	 */
	for (i = 0; i < (dtrace_specid_t)state->dts_nspeculations; i++) {
		dtrace_speculation_t *spec = &state->dts_speculations[i];
		dtrace_speculation_state_t current, new;

		if (!spec->dtsp_cleaning)
			continue;

		current = spec->dtsp_state;
		ASSERT(current == DTRACESPEC_DISCARDING ||
		    current == DTRACESPEC_COMMITTINGMANY);

		new = DTRACESPEC_INACTIVE;

		rv = dtrace_cas32((uint32_t *)&spec->dtsp_state, current, new);
		ASSERT(rv == current);
		spec->dtsp_cleaning = 0;
	}
}

/*
 * Called as part of a speculate() to get the speculative buffer associated
 * with a given speculation.  Returns NULL if the specified speculation is not
 * in an ACTIVE state.  If the speculation is in the ACTIVEONE state -- and
 * the active CPU is not the specified CPU -- the speculation will be
 * atomically transitioned into the ACTIVEMANY state.
 */
static dtrace_buffer_t *
dtrace_speculation_buffer(dtrace_state_t *state, processorid_t cpuid,
    dtrace_specid_t which)
{
	dtrace_speculation_t *spec;
	dtrace_speculation_state_t current, new = DTRACESPEC_INACTIVE;
	dtrace_buffer_t *buf;

	if (which == 0)
		return (NULL);

	if (which > (dtrace_specid_t)state->dts_nspeculations) {
		cpu_core[cpuid].cpuc_dtrace_flags |= CPU_DTRACE_ILLOP;
		return (NULL);
	}

	spec = &state->dts_speculations[which - 1];
	buf = &spec->dtsp_buffer[cpuid];

	do {
		current = spec->dtsp_state;

		switch (current) {
		case DTRACESPEC_INACTIVE:
		case DTRACESPEC_COMMITTINGMANY:
		case DTRACESPEC_DISCARDING:
			return (NULL);

		case DTRACESPEC_COMMITTING:
			ASSERT(buf->dtb_offset == 0);
			return (NULL);

		case DTRACESPEC_ACTIVEONE:
			/*
			 * This speculation is currently active on one CPU.
			 * Check the offset in the buffer; if it's non-zero,
			 * that CPU must be us (and we leave the state alone).
			 * If it's zero, assume that we're starting on a new
			 * CPU -- and change the state to indicate that the
			 * speculation is active on more than one CPU.
			 */
			if (buf->dtb_offset != 0)
				return (buf);

			new = DTRACESPEC_ACTIVEMANY;
			break;

		case DTRACESPEC_ACTIVEMANY:
			return (buf);

		case DTRACESPEC_ACTIVE:
			new = DTRACESPEC_ACTIVEONE;
			break;

		default:
			ASSERT(0);
		}
	} while (dtrace_cas32((uint32_t *)&spec->dtsp_state,
	    current, new) != current);

	ASSERT(new == DTRACESPEC_ACTIVEONE || new == DTRACESPEC_ACTIVEMANY);
	return (buf);
}

/*
 * Return a string.  In the event that the user lacks the privilege to access
 * arbitrary kernel memory, we copy the string out to scratch memory so that we
 * don't fail access checking.
 *
 * dtrace_dif_variable() uses this routine as a helper for various
 * builtin values such as 'execname' and 'probefunc.'
 */
static
uintptr_t
dtrace_dif_varstr(uintptr_t addr, dtrace_state_t *state,
    dtrace_mstate_t *mstate)
{
	uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
	uintptr_t ret;
	size_t strsz;

	/*
	 * The easy case: this probe is allowed to read all of memory, so
	 * we can just return this as a vanilla pointer.
	 */
	if ((mstate->dtms_access & DTRACE_ACCESS_KERNEL) != 0)
		return (addr);

	/*
	 * This is the tougher case: we copy the string in question from
	 * kernel memory into scratch memory and return it that way: this
	 * ensures that we won't trip up when access checking tests the
	 * BYREF return value.
	 */
	strsz = dtrace_strlen((char *)addr, size) + 1;

	if (mstate->dtms_scratch_ptr + strsz >
	    mstate->dtms_scratch_base + mstate->dtms_scratch_size) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
		return (0);
	}

	dtrace_strcpy((const void *)addr, (void *)mstate->dtms_scratch_ptr,
	    strsz);
	ret = mstate->dtms_scratch_ptr;
	mstate->dtms_scratch_ptr += strsz;
	return (ret);
}

/*
 * This function implements the DIF emulator's variable lookups.  The emulator
 * passes a reserved variable identifier and optional built-in array index.
 */
static uint64_t
dtrace_dif_variable(dtrace_mstate_t *mstate, dtrace_state_t *state, uint64_t v,
    uint64_t ndx)
{
	/*
	 * If we're accessing one of the uncached arguments, we'll turn this
	 * into a reference in the args array.
	 */
	if (v >= DIF_VAR_ARG0 && v <= DIF_VAR_ARG9) {
		ndx = v - DIF_VAR_ARG0;
		v = DIF_VAR_ARGS;
	}

	switch (v) {
	case DIF_VAR_ARGS:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_ARGS);
		if (ndx >= sizeof (mstate->dtms_arg) /
		    sizeof (mstate->dtms_arg[0])) {
			/*
			 * APPLE NOTE: Account for introduction of __dtrace_probe()
			 */
			int aframes = mstate->dtms_probe->dtpr_aframes + 3;
			dtrace_provider_t *pv;
			uint64_t val;

			pv = mstate->dtms_probe->dtpr_provider;
			if (pv->dtpv_pops.dtps_getargval != NULL)
				val = pv->dtpv_pops.dtps_getargval(pv->dtpv_arg,
				    mstate->dtms_probe->dtpr_id,
				    mstate->dtms_probe->dtpr_arg, ndx, aframes);
			/* Special case access of arg5 as passed to dtrace_probe_error() (which see.) */
			else if (mstate->dtms_probe->dtpr_id == dtrace_probeid_error && ndx == 5) {
			        return ((dtrace_state_t *)(uintptr_t)(mstate->dtms_arg[0]))->dts_arg_error_illval;
			}

			else
				val = dtrace_getarg(ndx, aframes);

			/*
			 * This is regrettably required to keep the compiler
			 * from tail-optimizing the call to dtrace_getarg().
			 * The condition always evaluates to true, but the
			 * compiler has no way of figuring that out a priori.
			 * (None of this would be necessary if the compiler
			 * could be relied upon to _always_ tail-optimize
			 * the call to dtrace_getarg() -- but it can't.)
			 */
			if (mstate->dtms_probe != NULL)
				return (val);

			ASSERT(0);
		}

		return (mstate->dtms_arg[ndx]);

	case DIF_VAR_UREGS: {
		thread_t thread;

		if (!dtrace_priv_proc(state))
			return (0);

		if ((thread = current_thread()) == NULL) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpu_core[CPU->cpu_id].cpuc_dtrace_illval = 0;
			return (0);
		}

		return (dtrace_getreg(find_user_regs(thread), ndx));
	}


	case DIF_VAR_CURTHREAD:
		if (!dtrace_priv_kernel(state))
			return (0);

		return ((uint64_t)(uintptr_t)current_thread());

	case DIF_VAR_TIMESTAMP:
		if (!(mstate->dtms_present & DTRACE_MSTATE_TIMESTAMP)) {
			mstate->dtms_timestamp = dtrace_gethrtime();
			mstate->dtms_present |= DTRACE_MSTATE_TIMESTAMP;
		}
		return (mstate->dtms_timestamp);

	case DIF_VAR_VTIMESTAMP:
		ASSERT(dtrace_vtime_references != 0);
		return (dtrace_get_thread_vtime(current_thread()));

	case DIF_VAR_WALLTIMESTAMP:
		if (!(mstate->dtms_present & DTRACE_MSTATE_WALLTIMESTAMP)) {
			mstate->dtms_walltimestamp = dtrace_gethrestime();
			mstate->dtms_present |= DTRACE_MSTATE_WALLTIMESTAMP;
		}
		return (mstate->dtms_walltimestamp);

	case DIF_VAR_MACHTIMESTAMP:
		if (!(mstate->dtms_present & DTRACE_MSTATE_MACHTIMESTAMP)) {
			mstate->dtms_machtimestamp = mach_absolute_time();
			mstate->dtms_present |= DTRACE_MSTATE_MACHTIMESTAMP;
		}
		return (mstate->dtms_machtimestamp);

	case DIF_VAR_CPU:
		return ((uint64_t) dtrace_get_thread_last_cpu_id(current_thread()));

	case DIF_VAR_IPL:
		if (!dtrace_priv_kernel(state))
			return (0);
		if (!(mstate->dtms_present & DTRACE_MSTATE_IPL)) {
			mstate->dtms_ipl = dtrace_getipl();
			mstate->dtms_present |= DTRACE_MSTATE_IPL;
		}
		return (mstate->dtms_ipl);

	case DIF_VAR_EPID:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_EPID);
		return (mstate->dtms_epid);

	case DIF_VAR_ID:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_PROBE);
		return (mstate->dtms_probe->dtpr_id);

	case DIF_VAR_STACKDEPTH:
		if (!dtrace_priv_kernel(state))
			return (0);
		if (!(mstate->dtms_present & DTRACE_MSTATE_STACKDEPTH)) {
			/*
			 * APPLE NOTE: Account for introduction of __dtrace_probe()
			 */
			int aframes = mstate->dtms_probe->dtpr_aframes + 3;

			mstate->dtms_stackdepth = dtrace_getstackdepth(aframes);
			mstate->dtms_present |= DTRACE_MSTATE_STACKDEPTH;
		}
		return (mstate->dtms_stackdepth);

	case DIF_VAR_USTACKDEPTH:
		if (!dtrace_priv_proc(state))
			return (0);
		if (!(mstate->dtms_present & DTRACE_MSTATE_USTACKDEPTH)) {
			/*
			 * See comment in DIF_VAR_PID.
			 */
			if (DTRACE_ANCHORED(mstate->dtms_probe) &&
			    CPU_ON_INTR(CPU)) {
				mstate->dtms_ustackdepth = 0;
			} else {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
				mstate->dtms_ustackdepth =
				    dtrace_getustackdepth();
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
			}
			mstate->dtms_present |= DTRACE_MSTATE_USTACKDEPTH;
		}
		return (mstate->dtms_ustackdepth);

	case DIF_VAR_CALLER:
		if (!dtrace_priv_kernel(state))
			return (0);
		if (!(mstate->dtms_present & DTRACE_MSTATE_CALLER)) {
			/*
			 * APPLE NOTE: Account for introduction of __dtrace_probe()
			 */
			int aframes = mstate->dtms_probe->dtpr_aframes + 3;

			if (!DTRACE_ANCHORED(mstate->dtms_probe)) {
				/*
				 * If this is an unanchored probe, we are
				 * required to go through the slow path:
				 * dtrace_caller() only guarantees correct
				 * results for anchored probes.
				 */
				pc_t caller[2];

				dtrace_getpcstack(caller, 2, aframes,
				    (uint32_t *)(uintptr_t)mstate->dtms_arg[0]);
				mstate->dtms_caller = caller[1];
			} else if ((mstate->dtms_caller =
				dtrace_caller(aframes)) == (uintptr_t)-1) {
				/*
				 * We have failed to do this the quick way;
				 * we must resort to the slower approach of
				 * calling dtrace_getpcstack().
				 */
				pc_t caller;

				dtrace_getpcstack(&caller, 1, aframes, NULL);
				mstate->dtms_caller = caller;
			}

			mstate->dtms_present |= DTRACE_MSTATE_CALLER;
		}
		return (mstate->dtms_caller);

	case DIF_VAR_UCALLER:
		if (!dtrace_priv_proc(state))
			return (0);

		if (!(mstate->dtms_present & DTRACE_MSTATE_UCALLER)) {
			uint64_t ustack[3];

			/*
			 * dtrace_getupcstack() fills in the first uint64_t
			 * with the current PID.  The second uint64_t will
			 * be the program counter at user-level.  The third
			 * uint64_t will contain the caller, which is what
			 * we're after.
			 */
			ustack[2] = 0;
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			dtrace_getupcstack(ustack, 3);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
			mstate->dtms_ucaller = ustack[2];
			mstate->dtms_present |= DTRACE_MSTATE_UCALLER;
		}

		return (mstate->dtms_ucaller);

	case DIF_VAR_PROBEPROV:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_PROBE);
		return (dtrace_dif_varstr(
		    (uintptr_t)mstate->dtms_probe->dtpr_provider->dtpv_name,
		    state, mstate));

	case DIF_VAR_PROBEMOD:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_PROBE);
		return (dtrace_dif_varstr(
		    (uintptr_t)mstate->dtms_probe->dtpr_mod,
		    state, mstate));

	case DIF_VAR_PROBEFUNC:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_PROBE);
		return (dtrace_dif_varstr(
		    (uintptr_t)mstate->dtms_probe->dtpr_func,
		    state, mstate));

	case DIF_VAR_PROBENAME:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_PROBE);
		return (dtrace_dif_varstr(
		    (uintptr_t)mstate->dtms_probe->dtpr_name,
		    state, mstate));

	case DIF_VAR_PID:
		if (!dtrace_priv_proc_relaxed(state))
			return (0);

		/*
		 * Note that we are assuming that an unanchored probe is
		 * always due to a high-level interrupt.  (And we're assuming
		 * that there is only a single high level interrupt.)
		 */
		if (DTRACE_ANCHORED(mstate->dtms_probe) && CPU_ON_INTR(CPU))
			/* Anchored probe that fires while on an interrupt accrues to process 0 */
			return 0; 

		return ((uint64_t)dtrace_proc_selfpid());

	case DIF_VAR_PPID:
		if (!dtrace_priv_proc_relaxed(state))
			return (0);

		/*
		 * See comment in DIF_VAR_PID.
		 */
		if (DTRACE_ANCHORED(mstate->dtms_probe) && CPU_ON_INTR(CPU))
			return (0);

		return ((uint64_t)dtrace_proc_selfppid());

	case DIF_VAR_TID:
		/* We do not need to check for null current_thread() */
		return thread_tid(current_thread()); /* globally unique */

	case DIF_VAR_PTHREAD_SELF:
		if (!dtrace_priv_proc(state))
			return (0);

		/* Not currently supported, but we should be able to delta the dispatchqaddr and dispatchqoffset to get pthread_self */
		return 0;

	case DIF_VAR_DISPATCHQADDR:
		if (!dtrace_priv_proc(state))
			return (0);

		/* We do not need to check for null current_thread() */
		return thread_dispatchqaddr(current_thread());

	case DIF_VAR_EXECNAME:
	{
		char *xname = (char *)mstate->dtms_scratch_ptr;
		size_t scratch_size = MAXCOMLEN+1;
		
		/* The scratch allocation's lifetime is that of the clause. */
		if (!DTRACE_INSCRATCH(mstate, scratch_size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			return 0;
		}
			
		if (!dtrace_priv_proc_relaxed(state))
			return (0);

		mstate->dtms_scratch_ptr += scratch_size;
		proc_selfname( xname, scratch_size );

		return ((uint64_t)(uintptr_t)xname);
	}


	case DIF_VAR_ZONENAME:
        {
                /* scratch_size is equal to length('global') + 1 for the null-terminator. */
                char *zname = (char *)mstate->dtms_scratch_ptr;
                size_t scratch_size = 6 + 1;

		if (!dtrace_priv_proc(state))
			return (0);

                /* The scratch allocation's lifetime is that of the clause. */
                if (!DTRACE_INSCRATCH(mstate, scratch_size)) {
                        DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
                        return 0;
                }

                mstate->dtms_scratch_ptr += scratch_size;

                /* The kernel does not provide zonename, it will always return 'global'. */
                strlcpy(zname, "global", scratch_size);

                return ((uint64_t)(uintptr_t)zname);
        }

	case DIF_VAR_UID:
		if (!dtrace_priv_proc_relaxed(state))
			return (0);

		/*
		 * See comment in DIF_VAR_PID.
		 */
		if (DTRACE_ANCHORED(mstate->dtms_probe) && CPU_ON_INTR(CPU))
			return (0);

		return ((uint64_t) dtrace_proc_selfruid());

	case DIF_VAR_GID:
		if (!dtrace_priv_proc(state))
			return (0);

		/*
		 * See comment in DIF_VAR_PID.
		 */
		if (DTRACE_ANCHORED(mstate->dtms_probe) && CPU_ON_INTR(CPU))
			return (0);

		if (dtrace_CRED() != NULL)
			/* Credential does not require lazy initialization. */
			return ((uint64_t)kauth_getgid());
		else {
			/* proc_lock would be taken under kauth_cred_proc_ref() in kauth_cred_get(). */
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			return -1ULL;
		}

	case DIF_VAR_ERRNO: {
		uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());
		if (!dtrace_priv_proc(state))
			return (0);

		/*
		 * See comment in DIF_VAR_PID.
		 */
		if (DTRACE_ANCHORED(mstate->dtms_probe) && CPU_ON_INTR(CPU))
			return (0);

		if (uthread)
			return (uint64_t)uthread->t_dtrace_errno;
		else {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			return -1ULL;
		}
	}

	default:
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return (0);
	}
}

/*
 * Emulate the execution of DTrace ID subroutines invoked by the call opcode.
 * Notice that we don't bother validating the proper number of arguments or
 * their types in the tuple stack.  This isn't needed because all argument
 * interpretation is safe because of our load safety -- the worst that can
 * happen is that a bogus program can obtain bogus results.
 */
static void
dtrace_dif_subr(uint_t subr, uint_t rd, uint64_t *regs,
    dtrace_key_t *tupregs, int nargs,
    dtrace_mstate_t *mstate, dtrace_state_t *state)
{
	volatile uint16_t *flags = &cpu_core[CPU->cpu_id].cpuc_dtrace_flags;
	volatile uint64_t *illval = &cpu_core[CPU->cpu_id].cpuc_dtrace_illval;
	dtrace_vstate_t *vstate = &state->dts_vstate;

#if !defined(__APPLE__)
	union {
		mutex_impl_t mi;
		uint64_t mx;
	} m;

	union {
		krwlock_t ri;
		uintptr_t rw;
	} r;
#else
/* FIXME: awaits lock/mutex work */
#endif /* __APPLE__ */

	switch (subr) {
	case DIF_SUBR_RAND:
		regs[rd] = (dtrace_gethrtime() * 2416 + 374441) % 1771875;
		break;

#if !defined(__APPLE__)
	case DIF_SUBR_MUTEX_OWNED:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (kmutex_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		m.mx = dtrace_load64(tupregs[0].dttk_value);
		if (MUTEX_TYPE_ADAPTIVE(&m.mi))
			regs[rd] = MUTEX_OWNER(&m.mi) != MUTEX_NO_OWNER;
		else
			regs[rd] = LOCK_HELD(&m.mi.m_spin.m_spinlock);
		break;

	case DIF_SUBR_MUTEX_OWNER:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (kmutex_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		m.mx = dtrace_load64(tupregs[0].dttk_value);
		if (MUTEX_TYPE_ADAPTIVE(&m.mi) &&
		    MUTEX_OWNER(&m.mi) != MUTEX_NO_OWNER)
			regs[rd] = (uintptr_t)MUTEX_OWNER(&m.mi);
		else
			regs[rd] = 0;
		break;

	case DIF_SUBR_MUTEX_TYPE_ADAPTIVE:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (kmutex_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		m.mx = dtrace_load64(tupregs[0].dttk_value);
		regs[rd] = MUTEX_TYPE_ADAPTIVE(&m.mi);
		break;

	case DIF_SUBR_MUTEX_TYPE_SPIN:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (kmutex_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		m.mx = dtrace_load64(tupregs[0].dttk_value);
		regs[rd] = MUTEX_TYPE_SPIN(&m.mi);
		break;

	case DIF_SUBR_RW_READ_HELD: {
		uintptr_t tmp;

		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (uintptr_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		r.rw = dtrace_loadptr(tupregs[0].dttk_value);
		regs[rd] = _RW_READ_HELD(&r.ri, tmp);
		break;
	}

	case DIF_SUBR_RW_WRITE_HELD:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (krwlock_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		r.rw = dtrace_loadptr(tupregs[0].dttk_value);
		regs[rd] = _RW_WRITE_HELD(&r.ri);
		break;

	case DIF_SUBR_RW_ISWRITER:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (krwlock_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		r.rw = dtrace_loadptr(tupregs[0].dttk_value);
		regs[rd] = _RW_ISWRITER(&r.ri);
		break;
#else
/* FIXME: awaits lock/mutex work */
#endif /* __APPLE__ */

	case DIF_SUBR_BCOPY: {
		/*
		 * We need to be sure that the destination is in the scratch
		 * region -- no other region is allowed.
		 */
		uintptr_t src = tupregs[0].dttk_value;
		uintptr_t dest = tupregs[1].dttk_value;
		size_t size = tupregs[2].dttk_value;

		if (!dtrace_inscratch(dest, size, mstate)) {
			*flags |= CPU_DTRACE_BADADDR;
			*illval = regs[rd];
			break;
		}

		if (!dtrace_canload(src, size, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		dtrace_bcopy((void *)src, (void *)dest, size);
		break;
	}

	case DIF_SUBR_ALLOCA:
	case DIF_SUBR_COPYIN: {
		uintptr_t dest = P2ROUNDUP(mstate->dtms_scratch_ptr, 8);
		uint64_t size =
		    tupregs[subr == DIF_SUBR_ALLOCA ? 0 : 1].dttk_value;
		size_t scratch_size = (dest - mstate->dtms_scratch_ptr) + size;

		/*
		 * Check whether the user can access kernel memory
		 */
		if (dtrace_priv_kernel(state) == 0) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_KPRIV);
			regs[rd] = 0;
			break;
		}
		/*
		 * This action doesn't require any credential checks since
		 * probes will not activate in user contexts to which the
		 * enabling user does not have permissions.
		 */

		/*
		 * Rounding up the user allocation size could have overflowed
		 * a large, bogus allocation (like -1ULL) to 0.
		 */
		if (scratch_size < size ||
		    !DTRACE_INSCRATCH(mstate, scratch_size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		if (subr == DIF_SUBR_COPYIN) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			if (dtrace_priv_proc(state))
				dtrace_copyin(tupregs[0].dttk_value, dest, size, flags);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		}

		mstate->dtms_scratch_ptr += scratch_size;
		regs[rd] = dest;
		break;
	}

	case DIF_SUBR_COPYINTO: {
		uint64_t size = tupregs[1].dttk_value;
		uintptr_t dest = tupregs[2].dttk_value;

		/*
		 * This action doesn't require any credential checks since
		 * probes will not activate in user contexts to which the
		 * enabling user does not have permissions.
		 */
		if (!dtrace_inscratch(dest, size, mstate)) {
			*flags |= CPU_DTRACE_BADADDR;
			*illval = regs[rd];
			break;
		}

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		if (dtrace_priv_proc(state))
			dtrace_copyin(tupregs[0].dttk_value, dest, size, flags);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		break;
	}

	case DIF_SUBR_COPYINSTR: {
		uintptr_t dest = mstate->dtms_scratch_ptr;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];

		if (nargs > 1 && tupregs[1].dttk_value < size)
			size = tupregs[1].dttk_value + 1;

		/*
		 * This action doesn't require any credential checks since
		 * probes will not activate in user contexts to which the
		 * enabling user does not have permissions.
		 */
		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		if (dtrace_priv_proc(state))
			dtrace_copyinstr(tupregs[0].dttk_value, dest, size, flags);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

		((char *)dest)[size - 1] = '\0';
		mstate->dtms_scratch_ptr += size;
		regs[rd] = dest;
		break;
	}

	case DIF_SUBR_MSGSIZE:
	case DIF_SUBR_MSGDSIZE: {
		/* Darwin does not implement SysV streams messages */
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		regs[rd] = 0;
		break;
	}

	case DIF_SUBR_PROGENYOF: {
		pid_t pid = tupregs[0].dttk_value;
		struct proc *p = current_proc();
		int rval = 0, lim = nprocs;

		while(p && (lim-- > 0)) {
			pid_t ppid;

			ppid = (pid_t)dtrace_load32((uintptr_t)&(p->p_pid));
			if (*flags & CPU_DTRACE_FAULT)
				break;

			if (ppid == pid) {
				rval = 1;
				break;
			}

			if (ppid == 0)
				break; /* Can't climb process tree any further. */

			p = (struct proc *)dtrace_loadptr((uintptr_t)&(p->p_pptr));
			if (*flags & CPU_DTRACE_FAULT)
				break;
		}

		regs[rd] = rval;
		break;
	}

	case DIF_SUBR_SPECULATION:
		regs[rd] = dtrace_speculation(state);
		break;


	case DIF_SUBR_COPYOUT: {
		uintptr_t kaddr = tupregs[0].dttk_value;
		user_addr_t uaddr = tupregs[1].dttk_value;
		uint64_t size = tupregs[2].dttk_value;

		if (!dtrace_destructive_disallow &&
		    dtrace_priv_proc_control(state) &&
		    !dtrace_istoxic(kaddr, size) &&
		    dtrace_canload(kaddr, size, mstate, vstate)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			dtrace_copyout(kaddr, uaddr, size, flags);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		}
		break;
	}

	case DIF_SUBR_COPYOUTSTR: {
		uintptr_t kaddr = tupregs[0].dttk_value;
		user_addr_t uaddr = tupregs[1].dttk_value;
		uint64_t size = tupregs[2].dttk_value;
		size_t lim;

		if (!dtrace_destructive_disallow &&
		    dtrace_priv_proc_control(state) &&
		    !dtrace_istoxic(kaddr, size) &&
		    dtrace_strcanload(kaddr, size, &lim, mstate, vstate)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			dtrace_copyoutstr(kaddr, uaddr, lim, flags);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		}
		break;
	}

	case DIF_SUBR_STRLEN: {
		size_t size = state->dts_options[DTRACEOPT_STRSIZE];
		uintptr_t addr = (uintptr_t)tupregs[0].dttk_value;
		size_t lim;

		if (!dtrace_strcanload(addr, size, &lim, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		regs[rd] = dtrace_strlen((char *)addr, lim);

		break;
	}

	case DIF_SUBR_STRCHR:
	case DIF_SUBR_STRRCHR: {
		/*
		 * We're going to iterate over the string looking for the
		 * specified character.  We will iterate until we have reached
		 * the string length or we have found the character.  If this
		 * is DIF_SUBR_STRRCHR, we will look for the last occurrence
		 * of the specified character instead of the first.
		 */
		uintptr_t addr = tupregs[0].dttk_value;
		uintptr_t addr_limit;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		size_t lim;
		char c, target = (char)tupregs[1].dttk_value;

		if (!dtrace_strcanload(addr, size, &lim, mstate, vstate)) {
			regs[rd] = NULL;
			break;
		}
		addr_limit = addr + lim;

		for (regs[rd] = 0; addr < addr_limit; addr++) {
			if ((c = dtrace_load8(addr)) == target) {
				regs[rd] = addr;

				if (subr == DIF_SUBR_STRCHR)
					break;
			}

			if (c == '\0')
				break;
		}

		break;
	}

	case DIF_SUBR_STRSTR:
	case DIF_SUBR_INDEX:
	case DIF_SUBR_RINDEX: {
		/*
		 * We're going to iterate over the string looking for the
		 * specified string.  We will iterate until we have reached
		 * the string length or we have found the string.  (Yes, this
		 * is done in the most naive way possible -- but considering
		 * that the string we're searching for is likely to be
		 * relatively short, the complexity of Rabin-Karp or similar
		 * hardly seems merited.)
		 */
		char *addr = (char *)(uintptr_t)tupregs[0].dttk_value;
		char *substr = (char *)(uintptr_t)tupregs[1].dttk_value;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		size_t len = dtrace_strlen(addr, size);
		size_t sublen = dtrace_strlen(substr, size);
		char *limit = addr + len, *orig = addr;
		int notfound = subr == DIF_SUBR_STRSTR ? 0 : -1;
		int inc = 1;

		regs[rd] = notfound;

		if (!dtrace_canload((uintptr_t)addr, len + 1, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!dtrace_canload((uintptr_t)substr, sublen + 1, mstate,
		    vstate)) {
			regs[rd] = 0;
			break;
		}

		/*
		 * strstr() and index()/rindex() have similar semantics if
		 * both strings are the empty string: strstr() returns a
		 * pointer to the (empty) string, and index() and rindex()
		 * both return index 0 (regardless of any position argument).
		 */
		if (sublen == 0 && len == 0) {
			if (subr == DIF_SUBR_STRSTR)
				regs[rd] = (uintptr_t)addr;
			else
				regs[rd] = 0;
			break;
		}

		if (subr != DIF_SUBR_STRSTR) {
			if (subr == DIF_SUBR_RINDEX) {
				limit = orig - 1;
				addr += len;
				inc = -1;
			}

			/*
			 * Both index() and rindex() take an optional position
			 * argument that denotes the starting position.
			 */
			if (nargs == 3) {
				int64_t pos = (int64_t)tupregs[2].dttk_value;

				/*
				 * If the position argument to index() is
				 * negative, Perl implicitly clamps it at
				 * zero.  This semantic is a little surprising
				 * given the special meaning of negative
				 * positions to similar Perl functions like
				 * substr(), but it appears to reflect a
				 * notion that index() can start from a
				 * negative index and increment its way up to
				 * the string.  Given this notion, Perl's
				 * rindex() is at least self-consistent in
				 * that it implicitly clamps positions greater
				 * than the string length to be the string
				 * length.  Where Perl completely loses
				 * coherence, however, is when the specified
				 * substring is the empty string ("").  In
				 * this case, even if the position is
				 * negative, rindex() returns 0 -- and even if
				 * the position is greater than the length,
				 * index() returns the string length.  These
				 * semantics violate the notion that index()
				 * should never return a value less than the
				 * specified position and that rindex() should
				 * never return a value greater than the
				 * specified position.  (One assumes that
				 * these semantics are artifacts of Perl's
				 * implementation and not the results of
				 * deliberate design -- it beggars belief that
				 * even Larry Wall could desire such oddness.)
				 * While in the abstract one would wish for
				 * consistent position semantics across
				 * substr(), index() and rindex() -- or at the
				 * very least self-consistent position
				 * semantics for index() and rindex() -- we
				 * instead opt to keep with the extant Perl
				 * semantics, in all their broken glory.  (Do
				 * we have more desire to maintain Perl's
				 * semantics than Perl does?  Probably.)
				 */
				if (subr == DIF_SUBR_RINDEX) {
					if (pos < 0) {
						if (sublen == 0)
							regs[rd] = 0;
						break;
					}

					if ((size_t)pos > len)
						pos = len;
				} else {
					if (pos < 0)
						pos = 0;

					if ((size_t)pos >= len) {
						if (sublen == 0)
							regs[rd] = len;
						break;
					}
				}

				addr = orig + pos;
			}
		}

		for (regs[rd] = notfound; addr != limit; addr += inc) {
			if (dtrace_strncmp(addr, substr, sublen) == 0) {
				if (subr != DIF_SUBR_STRSTR) {
					/*
					 * As D index() and rindex() are
					 * modeled on Perl (and not on awk),
					 * we return a zero-based (and not a
					 * one-based) index.  (For you Perl
					 * weenies: no, we're not going to add
					 * $[ -- and shouldn't you be at a con
					 * or something?)
					 */
					regs[rd] = (uintptr_t)(addr - orig);
					break;
				}

				ASSERT(subr == DIF_SUBR_STRSTR);
				regs[rd] = (uintptr_t)addr;
				break;
			}
		}

		break;
	}

	case DIF_SUBR_STRTOK: {
		uintptr_t addr = tupregs[0].dttk_value;
		uintptr_t tokaddr = tupregs[1].dttk_value;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		uintptr_t limit, toklimit;
		size_t clim;
		char *dest = (char *)mstate->dtms_scratch_ptr;
		uint8_t c='\0', tokmap[32];	 /* 256 / 8 */
		uint64_t i = 0;

		/*
		 * Check both the token buffer and (later) the input buffer,
		 * since both could be non-scratch addresses.
		 */
		if (!dtrace_strcanload(tokaddr, size, &clim, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}
		toklimit = tokaddr + clim;

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		if (addr == 0) {
			/*
			 * If the address specified is NULL, we use our saved
			 * strtok pointer from the mstate.  Note that this
			 * means that the saved strtok pointer is _only_
			 * valid within multiple enablings of the same probe --
			 * it behaves like an implicit clause-local variable.
			 */
			addr = mstate->dtms_strtok;
			limit = mstate->dtms_strtok_limit;
		} else {
			/*
			 * If the user-specified address is non-NULL we must
			 * access check it.  This is the only time we have
			 * a chance to do so, since this address may reside
			 * in the string table of this clause-- future calls
			 * (when we fetch addr from mstate->dtms_strtok)
			 * would fail this access check.
			 */
			if (!dtrace_strcanload(addr, size, &clim, mstate,
				vstate)) {
				regs[rd] = 0;
				break;
			}
			limit = addr + clim;
		}

		/*
		 * First, zero the token map, and then process the token
		 * string -- setting a bit in the map for every character
		 * found in the token string.
		 */
		for (i = 0; i < (int)sizeof (tokmap); i++)
			tokmap[i] = 0;

		for (; tokaddr < toklimit; tokaddr++) {
			if ((c = dtrace_load8(tokaddr)) == '\0')
				break;

			ASSERT((c >> 3) < sizeof (tokmap));
			tokmap[c >> 3] |= (1 << (c & 0x7));
		}

		for (; addr < limit; addr++) {
			/*
			 * We're looking for a character that is _not_
			 * contained in the token string.
			 */
			if ((c = dtrace_load8(addr)) == '\0')
				break;

			if (!(tokmap[c >> 3] & (1 << (c & 0x7))))
				break;
		}

		if (c == '\0') {
			/*
			 * We reached the end of the string without finding
			 * any character that was not in the token string.
			 * We return NULL in this case, and we set the saved
			 * address to NULL as well.
			 */
			regs[rd] = 0;
			mstate->dtms_strtok = 0;
			mstate->dtms_strtok_limit = NULL;
			break;
		}

		/*
		 * From here on, we're copying into the destination string.
		 */
		for (i = 0; addr < limit && i < size - 1; addr++) {
			if ((c = dtrace_load8(addr)) == '\0')
				break;

			if (tokmap[c >> 3] & (1 << (c & 0x7)))
				break;

			ASSERT(i < size);
			dest[i++] = c;
		}

		ASSERT(i < size);
		dest[i] = '\0';
		regs[rd] = (uintptr_t)dest;
		mstate->dtms_scratch_ptr += size;
		mstate->dtms_strtok = addr;
		mstate->dtms_strtok_limit = limit;
		break;
	}

	case DIF_SUBR_SUBSTR: {
		uintptr_t s = tupregs[0].dttk_value;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		char *d = (char *)mstate->dtms_scratch_ptr;
		int64_t index = (int64_t)tupregs[1].dttk_value;
		int64_t remaining = (int64_t)tupregs[2].dttk_value;
		size_t len = dtrace_strlen((char *)s, size);
		int64_t i = 0;

		if (!dtrace_canload(s, len + 1, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		if (nargs <= 2)
			remaining = (int64_t)size;

		if (index < 0) {
			index += len;

			if (index < 0 && index + remaining > 0) {
				remaining += index;
				index = 0;
			}
		}

		if ((size_t)index >= len || index < 0) {
			remaining = 0;
		} else if (remaining < 0) {
			remaining += len - index;
		} else if ((uint64_t)index + (uint64_t)remaining > size) {
			remaining = size - index;
		}

		for (i = 0; i < remaining; i++) {
			if ((d[i] = dtrace_load8(s + index + i)) == '\0')
				break;
			}

		d[i] = '\0';

		mstate->dtms_scratch_ptr += size;
		regs[rd] = (uintptr_t)d;
		break;
	}

	case DIF_SUBR_GETMAJOR:
		regs[rd] = (uintptr_t)major( (dev_t)tupregs[0].dttk_value );
		break;

	case DIF_SUBR_GETMINOR:
		regs[rd] = (uintptr_t)minor( (dev_t)tupregs[0].dttk_value );
		break;

	case DIF_SUBR_DDI_PATHNAME: {
		/* APPLE NOTE: currently unsupported on Darwin */
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		regs[rd] = 0;
		break;
	}

	case DIF_SUBR_STRJOIN: {
		char *d = (char *)mstate->dtms_scratch_ptr;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		uintptr_t s1 = tupregs[0].dttk_value;
		uintptr_t s2 = tupregs[1].dttk_value;
		uint64_t i = 0, j = 0;
		size_t lim1, lim2;
		char c;

		if (!dtrace_strcanload(s1, size, &lim1, mstate, vstate) ||
		    !dtrace_strcanload(s2, size, &lim2, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		for (;;) {
			if (i >= size) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
				regs[rd] = 0;
				break;
			}
			c = (i >= lim1) ? '\0' : dtrace_load8(s1++);
			if ((d[i++] = c) == '\0') {
				i--;
				break;
			}
		}

		for (;;) {
			if (i >= size) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
				regs[rd] = 0;
				break;
			}
			c = (j++ >= lim2) ? '\0' : dtrace_load8(s2++);
			if ((d[i++] = c) == '\0')
				break;
		}

		if (i < size) {
			mstate->dtms_scratch_ptr += i;
			regs[rd] = (uintptr_t)d;
		}

		break;
	}

	case DIF_SUBR_LLTOSTR: {
		int64_t i = (int64_t)tupregs[0].dttk_value;
		int64_t val = i < 0 ? i * -1 : i;
		uint64_t size = 22;	/* enough room for 2^64 in decimal */
		char *end = (char *)mstate->dtms_scratch_ptr + size - 1;

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		for (*end-- = '\0'; val; val /= 10)
			*end-- = '0' + (val % 10);

		if (i == 0)
			*end-- = '0';

		if (i < 0)
			*end-- = '-';

		regs[rd] = (uintptr_t)end + 1;
		mstate->dtms_scratch_ptr += size;
		break;
	}

	case DIF_SUBR_HTONS:
	case DIF_SUBR_NTOHS:
#ifdef _BIG_ENDIAN
		regs[rd] = (uint16_t)tupregs[0].dttk_value;
#else
		regs[rd] = DT_BSWAP_16((uint16_t)tupregs[0].dttk_value);
#endif
		break;


	case DIF_SUBR_HTONL:
	case DIF_SUBR_NTOHL:
#ifdef _BIG_ENDIAN
		regs[rd] = (uint32_t)tupregs[0].dttk_value;
#else
		regs[rd] = DT_BSWAP_32((uint32_t)tupregs[0].dttk_value);
#endif
		break;


	case DIF_SUBR_HTONLL:
	case DIF_SUBR_NTOHLL:
#ifdef _BIG_ENDIAN
		regs[rd] = (uint64_t)tupregs[0].dttk_value;
#else
		regs[rd] = DT_BSWAP_64((uint64_t)tupregs[0].dttk_value);
#endif
		break;


	case DIF_SUBR_DIRNAME:
	case DIF_SUBR_BASENAME: {
		char *dest = (char *)mstate->dtms_scratch_ptr;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		uintptr_t src = tupregs[0].dttk_value;
		int i, j, len = dtrace_strlen((char *)src, size);
		int lastbase = -1, firstbase = -1, lastdir = -1;
		int start, end;

		if (!dtrace_canload(src, len + 1, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		/*
		 * The basename and dirname for a zero-length string is
		 * defined to be "."
		 */
		if (len == 0) {
			len = 1;
			src = (uintptr_t)".";
		}

		/*
		 * Start from the back of the string, moving back toward the
		 * front until we see a character that isn't a slash.  That
		 * character is the last character in the basename.
		 */
		for (i = len - 1; i >= 0; i--) {
			if (dtrace_load8(src + i) != '/')
				break;
		}

		if (i >= 0)
			lastbase = i;

		/*
		 * Starting from the last character in the basename, move
		 * towards the front until we find a slash.  The character
		 * that we processed immediately before that is the first
		 * character in the basename.
		 */
		for (; i >= 0; i--) {
			if (dtrace_load8(src + i) == '/')
				break;
		}

		if (i >= 0)
			firstbase = i + 1;

		/*
		 * Now keep going until we find a non-slash character.  That
		 * character is the last character in the dirname.
		 */
		for (; i >= 0; i--) {
			if (dtrace_load8(src + i) != '/')
				break;
		}

		if (i >= 0)
			lastdir = i;

		ASSERT(!(lastbase == -1 && firstbase != -1));
		ASSERT(!(firstbase == -1 && lastdir != -1));

		if (lastbase == -1) {
			/*
			 * We didn't find a non-slash character.  We know that
			 * the length is non-zero, so the whole string must be
			 * slashes.  In either the dirname or the basename
			 * case, we return '/'.
			 */
			ASSERT(firstbase == -1);
			firstbase = lastbase = lastdir = 0;
		}

		if (firstbase == -1) {
			/*
			 * The entire string consists only of a basename
			 * component.  If we're looking for dirname, we need
			 * to change our string to be just "."; if we're
			 * looking for a basename, we'll just set the first
			 * character of the basename to be 0.
			 */
			if (subr == DIF_SUBR_DIRNAME) {
				ASSERT(lastdir == -1);
				src = (uintptr_t)".";
				lastdir = 0;
			} else {
				firstbase = 0;
			}
		}

		if (subr == DIF_SUBR_DIRNAME) {
			if (lastdir == -1) {
				/*
				 * We know that we have a slash in the name --
				 * or lastdir would be set to 0, above.  And
				 * because lastdir is -1, we know that this
				 * slash must be the first character.  (That
				 * is, the full string must be of the form
				 * "/basename".)  In this case, the last
				 * character of the directory name is 0.
				 */
				lastdir = 0;
			}

			start = 0;
			end = lastdir;
		} else {
			ASSERT(subr == DIF_SUBR_BASENAME);
			ASSERT(firstbase != -1 && lastbase != -1);
			start = firstbase;
			end = lastbase;
		}

		for (i = start, j = 0; i <= end && (uint64_t)j < size - 1; i++, j++)
			dest[j] = dtrace_load8(src + i);

		dest[j] = '\0';
		regs[rd] = (uintptr_t)dest;
		mstate->dtms_scratch_ptr += size;
		break;
	}

	case DIF_SUBR_CLEANPATH: {
		char *dest = (char *)mstate->dtms_scratch_ptr, c;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		uintptr_t src = tupregs[0].dttk_value;
		size_t lim;
		size_t i = 0, j = 0;

		if (!dtrace_strcanload(src, size, &lim, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		/*
		 * Move forward, loading each character.
		 */
		do {
			c = (i >= lim) ? '\0' : dtrace_load8(src + i++);
next:
			if ((uint64_t)(j + 5) >= size)	/* 5 = strlen("/..c\0") */
				break;

			if (c != '/') {
				dest[j++] = c;
				continue;
			}

			c = (i >= lim) ? '\0' : dtrace_load8(src + i++);

			if (c == '/') {
				/*
				 * We have two slashes -- we can just advance
				 * to the next character.
				 */
				goto next;
			}

			if (c != '.') {
				/*
				 * This is not "." and it's not ".." -- we can
				 * just store the "/" and this character and
				 * drive on.
				 */
				dest[j++] = '/';
				dest[j++] = c;
				continue;
			}

			c = (i >= lim) ? '\0' : dtrace_load8(src + i++);

			if (c == '/') {
				/*
				 * This is a "/./" component.  We're not going
				 * to store anything in the destination buffer;
				 * we're just going to go to the next component.
				 */
				goto next;
			}

			if (c != '.') {
				/*
				 * This is not ".." -- we can just store the
				 * "/." and this character and continue
				 * processing.
				 */
				dest[j++] = '/';
				dest[j++] = '.';
				dest[j++] = c;
				continue;
			}

			c = (i >= lim) ? '\0' : dtrace_load8(src + i++);

			if (c != '/' && c != '\0') {
				/*
				 * This is not ".." -- it's "..[mumble]".
				 * We'll store the "/.." and this character
				 * and continue processing.
				 */
				dest[j++] = '/';
				dest[j++] = '.';
				dest[j++] = '.';
				dest[j++] = c;
				continue;
			}

			/*
			 * This is "/../" or "/..\0".  We need to back up
			 * our destination pointer until we find a "/".
			 */
			i--;
			while (j != 0 && dest[--j] != '/')
				continue;

			if (c == '\0')
				dest[++j] = '/';
		} while (c != '\0');

		dest[j] = '\0';
		regs[rd] = (uintptr_t)dest;
		mstate->dtms_scratch_ptr += size;
		break;
	}

	case DIF_SUBR_INET_NTOA:
	case DIF_SUBR_INET_NTOA6:
	case DIF_SUBR_INET_NTOP: {
		size_t size;
		int af, argi, i;
		char *base, *end;

		if (subr == DIF_SUBR_INET_NTOP) {
			af = (int)tupregs[0].dttk_value;
			argi = 1;
		} else {
			af = subr == DIF_SUBR_INET_NTOA ? AF_INET: AF_INET6;
			argi = 0;
		}

		if (af == AF_INET) {
#if !defined(__APPLE__)
			ipaddr_t ip4;
#else
			uint32_t ip4;
#endif /* __APPLE__ */
			uint8_t *ptr8, val;

			/*
			 * Safely load the IPv4 address.
			 */
#if !defined(__APPLE__)			
			ip4 = dtrace_load32(tupregs[argi].dttk_value);
#else
			if (!dtrace_canload(tupregs[argi].dttk_value, sizeof(ip4),
				mstate, vstate)) {
				regs[rd] = 0;
				break;
			}

			dtrace_bcopy(
			    (void *)(uintptr_t)tupregs[argi].dttk_value,
			    (void *)(uintptr_t)&ip4, sizeof (ip4));
#endif /* __APPLE__ */			
			/*
			 * Check an IPv4 string will fit in scratch.
			 */
#if !defined(__APPLE__)
			size = INET_ADDRSTRLEN;
#else
			size = MAX_IPv4_STR_LEN;
#endif /* __APPLE__ */
			if (!DTRACE_INSCRATCH(mstate, size)) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
				regs[rd] = 0;
				break;
			}
			base = (char *)mstate->dtms_scratch_ptr;
			end = (char *)mstate->dtms_scratch_ptr + size - 1;

			/*
			 * Stringify as a dotted decimal quad.
			 */
			*end-- = '\0';
			ptr8 = (uint8_t *)&ip4;
			for (i = 3; i >= 0; i--) {
				val = ptr8[i];

				if (val == 0) {
					*end-- = '0';
				} else {
					for (; val; val /= 10) {
						*end-- = '0' + (val % 10);
					}
				}

				if (i > 0)
					*end-- = '.';
			}
			ASSERT(end + 1 >= base);

		} else if (af == AF_INET6) {
#if defined(__APPLE__)
#define _S6_un __u6_addr
#define _S6_u8 __u6_addr8
#endif /* __APPLE__ */
			struct in6_addr ip6;
			int firstzero, tryzero, numzero, v6end;
			uint16_t val;
			const char digits[] = "0123456789abcdef";

			/*
			 * Stringify using RFC 1884 convention 2 - 16 bit
			 * hexadecimal values with a zero-run compression.
			 * Lower case hexadecimal digits are used.
			 * 	eg, fe80::214:4fff:fe0b:76c8.
			 * The IPv4 embedded form is returned for inet_ntop,
			 * just the IPv4 string is returned for inet_ntoa6.
			 */

			if (!dtrace_canload(tupregs[argi].dttk_value,
				sizeof(struct in6_addr), mstate, vstate)) {
				regs[rd] = 0;
				break;
			}

			/*
			 * Safely load the IPv6 address.
			 */
			dtrace_bcopy(
			    (void *)(uintptr_t)tupregs[argi].dttk_value,
			    (void *)(uintptr_t)&ip6, sizeof (struct in6_addr));

			/*
			 * Check an IPv6 string will fit in scratch.
			 */
			size = INET6_ADDRSTRLEN;
			if (!DTRACE_INSCRATCH(mstate, size)) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
				regs[rd] = 0;
				break;
			}
			base = (char *)mstate->dtms_scratch_ptr;
			end = (char *)mstate->dtms_scratch_ptr + size - 1;
			*end-- = '\0';

			/*
			 * Find the longest run of 16 bit zero values
			 * for the single allowed zero compression - "::".
			 */
			firstzero = -1;
			tryzero = -1;
			numzero = 1;
			for (i = 0; i < (int)sizeof (struct in6_addr); i++) {
				if (ip6._S6_un._S6_u8[i] == 0 &&
				    tryzero == -1 && i % 2 == 0) {
					tryzero = i;
					continue;
				}

				if (tryzero != -1 &&
				    (ip6._S6_un._S6_u8[i] != 0 ||
				    i == sizeof (struct in6_addr) - 1)) {

					if (i - tryzero <= numzero) {
						tryzero = -1;
						continue;
					}

					firstzero = tryzero;
					numzero = i - i % 2 - tryzero;
					tryzero = -1;

					if (ip6._S6_un._S6_u8[i] == 0 &&
					    i == sizeof (struct in6_addr) - 1)
						numzero += 2;
				}
			}
			ASSERT(firstzero + numzero <= (int)sizeof (struct in6_addr));

			/*
			 * Check for an IPv4 embedded address.
			 */
			v6end = sizeof (struct in6_addr) - 2;
			if (IN6_IS_ADDR_V4MAPPED(&ip6) ||
			    IN6_IS_ADDR_V4COMPAT(&ip6)) {
				for (i = sizeof (struct in6_addr) - 1;
				     i >= (int)DTRACE_V4MAPPED_OFFSET; i--) {
					ASSERT(end >= base);

					val = ip6._S6_un._S6_u8[i];

					if (val == 0) {
						*end-- = '0';
					} else {
						for (; val; val /= 10) {
							*end-- = '0' + val % 10;
						}
					}

					if (i > (int)DTRACE_V4MAPPED_OFFSET)
						*end-- = '.';
				}

				if (subr == DIF_SUBR_INET_NTOA6)
					goto inetout;

				/*
				 * Set v6end to skip the IPv4 address that
				 * we have already stringified.
				 */
				v6end = 10;
			}

			/*
			 * Build the IPv6 string by working through the
			 * address in reverse.
			 */
			for (i = v6end; i >= 0; i -= 2) {
				ASSERT(end >= base);

				if (i == firstzero + numzero - 2) {
					*end-- = ':';
					*end-- = ':';
					i -= numzero - 2;
					continue;
				}

				if (i < 14 && i != firstzero - 2)
					*end-- = ':';

				val = (ip6._S6_un._S6_u8[i] << 8) +
				    ip6._S6_un._S6_u8[i + 1];

				if (val == 0) {
					*end-- = '0';
				} else {
					for (; val; val /= 16) {
						*end-- = digits[val % 16];
					}
				}
			}
			ASSERT(end + 1 >= base);

#if defined(__APPLE__)
#undef _S6_un
#undef _S6_u8
#endif /* __APPLE__ */
		} else {
			/*
			 * The user didn't use AH_INET or AH_INET6.
			 */
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			regs[rd] = 0;
			break;
		}

inetout:	regs[rd] = (uintptr_t)end + 1;
		mstate->dtms_scratch_ptr += size;
		break;
	}

	case DIF_SUBR_TOUPPER:
	case DIF_SUBR_TOLOWER: {
		uintptr_t src = tupregs[0].dttk_value;
		char *dest = (char *)mstate->dtms_scratch_ptr;
		char lower, upper, base, c;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		size_t len = dtrace_strlen((char*) src, size);
		size_t i = 0;

		lower = (subr == DIF_SUBR_TOUPPER) ? 'a' : 'A';
		upper = (subr == DIF_SUBR_TOUPPER) ? 'z' : 'Z';
		base  = (subr == DIF_SUBR_TOUPPER) ? 'A' : 'a';

		if (!dtrace_canload(src, len + 1, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		for (i = 0; i < size - 1; ++i) {
			if ((c = dtrace_load8(src + i)) == '\0')
				break;
			if (c >= lower && c <= upper)
				c = base + (c - lower);
			dest[i] = c;
		}

		ASSERT(i < size);

		dest[i] = '\0';
		regs[rd] = (uintptr_t) dest;
		mstate->dtms_scratch_ptr += size;

		break;
	}

#if defined(__APPLE__)
	case DIF_SUBR_VM_KERNEL_ADDRPERM: {
		if (!dtrace_priv_kernel(state)) {
			regs[rd] = 0;
		} else {
			regs[rd] = VM_KERNEL_ADDRPERM((vm_offset_t) tupregs[0].dttk_value);
		}

		break;
	}

	case DIF_SUBR_KDEBUG_TRACE: {
		uint32_t debugid;
		uintptr_t args[4] = {0};
		int i;

		if (nargs < 2 || nargs > 5) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			break;
		}

		if (dtrace_destructive_disallow)
			return;

		debugid = tupregs[0].dttk_value;
		for (i = 0; i < nargs - 1; i++)
			args[i] = tupregs[i + 1].dttk_value;

		kernel_debug(debugid, args[0], args[1], args[2], args[3], 0);

		break;
	}

	case DIF_SUBR_KDEBUG_TRACE_STRING: {
		if (nargs != 3) {
			break;
		}

		if (dtrace_destructive_disallow)
			return;

		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		uint32_t debugid = tupregs[0].dttk_value;
		uint64_t str_id = tupregs[1].dttk_value;
		uintptr_t src = tupregs[2].dttk_value;
		size_t lim;
		char buf[size];
		char* str = NULL;

		if (src != (uintptr_t)0) {
			str = buf;
			if (!dtrace_strcanload(src, size, &lim, mstate, vstate)) {
				break;
			}
			dtrace_strcpy((void*)src, buf, size);
		}

		(void)kernel_debug_string(debugid, &str_id, str);
		regs[rd] = str_id;

		break;
	}
#endif

	}
}

/*
 * Emulate the execution of DTrace IR instructions specified by the given
 * DIF object.  This function is deliberately void of assertions as all of
 * the necessary checks are handled by a call to dtrace_difo_validate().
 */
static uint64_t
dtrace_dif_emulate(dtrace_difo_t *difo, dtrace_mstate_t *mstate,
    dtrace_vstate_t *vstate, dtrace_state_t *state)
{
	const dif_instr_t *text = difo->dtdo_buf;
	const uint_t textlen = difo->dtdo_len;
	const char *strtab = difo->dtdo_strtab;
	const uint64_t *inttab = difo->dtdo_inttab;

	uint64_t rval = 0;
	dtrace_statvar_t *svar;
	dtrace_dstate_t *dstate = &vstate->dtvs_dynvars;
	dtrace_difv_t *v;
	volatile uint16_t *flags = &cpu_core[CPU->cpu_id].cpuc_dtrace_flags;
	volatile uint64_t *illval = &cpu_core[CPU->cpu_id].cpuc_dtrace_illval;

	dtrace_key_t tupregs[DIF_DTR_NREGS + 2]; /* +2 for thread and id */
	uint64_t regs[DIF_DIR_NREGS];
	uint64_t *tmp;

	uint8_t cc_n = 0, cc_z = 0, cc_v = 0, cc_c = 0;
	int64_t cc_r;
	uint_t pc = 0, id, opc = 0;
	uint8_t ttop = 0;
	dif_instr_t instr;
	uint_t r1, r2, rd;

	/*
	 * We stash the current DIF object into the machine state: we need it
	 * for subsequent access checking.
	 */
	mstate->dtms_difo = difo;

	regs[DIF_REG_R0] = 0; 		/* %r0 is fixed at zero */

	while (pc < textlen && !(*flags & CPU_DTRACE_FAULT)) {
		opc = pc;

		instr = text[pc++];
		r1 = DIF_INSTR_R1(instr);
		r2 = DIF_INSTR_R2(instr);
		rd = DIF_INSTR_RD(instr);

		switch (DIF_INSTR_OP(instr)) {
		case DIF_OP_OR:
			regs[rd] = regs[r1] | regs[r2];
			break;
		case DIF_OP_XOR:
			regs[rd] = regs[r1] ^ regs[r2];
			break;
		case DIF_OP_AND:
			regs[rd] = regs[r1] & regs[r2];
			break;
		case DIF_OP_SLL:
			regs[rd] = regs[r1] << regs[r2];
			break;
		case DIF_OP_SRL:
			regs[rd] = regs[r1] >> regs[r2];
			break;
		case DIF_OP_SUB:
			regs[rd] = regs[r1] - regs[r2];
			break;
		case DIF_OP_ADD:
			regs[rd] = regs[r1] + regs[r2];
			break;
		case DIF_OP_MUL:
			regs[rd] = regs[r1] * regs[r2];
			break;
		case DIF_OP_SDIV:
			if (regs[r2] == 0) {
				regs[rd] = 0;
				*flags |= CPU_DTRACE_DIVZERO;
			} else {
				regs[rd] = (int64_t)regs[r1] /
				    (int64_t)regs[r2];
			}
			break;

		case DIF_OP_UDIV:
			if (regs[r2] == 0) {
				regs[rd] = 0;
				*flags |= CPU_DTRACE_DIVZERO;
			} else {
				regs[rd] = regs[r1] / regs[r2];
			}
			break;

		case DIF_OP_SREM:
			if (regs[r2] == 0) {
				regs[rd] = 0;
				*flags |= CPU_DTRACE_DIVZERO;
			} else {
				regs[rd] = (int64_t)regs[r1] %
				    (int64_t)regs[r2];
			}
			break;

		case DIF_OP_UREM:
			if (regs[r2] == 0) {
				regs[rd] = 0;
				*flags |= CPU_DTRACE_DIVZERO;
			} else {
				regs[rd] = regs[r1] % regs[r2];
			}
			break;

		case DIF_OP_NOT:
			regs[rd] = ~regs[r1];
			break;
		case DIF_OP_MOV:
			regs[rd] = regs[r1];
			break;
		case DIF_OP_CMP:
			cc_r = regs[r1] - regs[r2];
			cc_n = cc_r < 0;
			cc_z = cc_r == 0;
			cc_v = 0;
			cc_c = regs[r1] < regs[r2];
			break;
		case DIF_OP_TST:
			cc_n = cc_v = cc_c = 0;
			cc_z = regs[r1] == 0;
			break;
		case DIF_OP_BA:
			pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BE:
			if (cc_z)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BNE:
			if (cc_z == 0)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BG:
			if ((cc_z | (cc_n ^ cc_v)) == 0)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BGU:
			if ((cc_c | cc_z) == 0)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BGE:
			if ((cc_n ^ cc_v) == 0)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BGEU:
			if (cc_c == 0)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BL:
			if (cc_n ^ cc_v)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BLU:
			if (cc_c)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BLE:
			if (cc_z | (cc_n ^ cc_v))
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BLEU:
			if (cc_c | cc_z)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_RLDSB:
			if (!dtrace_canstore(regs[r1], 1, mstate, vstate)) {
				*flags |= CPU_DTRACE_KPRIV;
				*illval = regs[r1];
				break;
			}
			/*FALLTHROUGH*/
		case DIF_OP_LDSB:
			regs[rd] = (int8_t)dtrace_load8(regs[r1]);
			break;
		case DIF_OP_RLDSH:
			if (!dtrace_canstore(regs[r1], 2, mstate, vstate)) {
				*flags |= CPU_DTRACE_KPRIV;
				*illval = regs[r1];
				break;
			}
			/*FALLTHROUGH*/
		case DIF_OP_LDSH:
			regs[rd] = (int16_t)dtrace_load16(regs[r1]);
			break;
		case DIF_OP_RLDSW:
			if (!dtrace_canstore(regs[r1], 4, mstate, vstate)) {
				*flags |= CPU_DTRACE_KPRIV;
				*illval = regs[r1];
				break;
			}
			/*FALLTHROUGH*/
		case DIF_OP_LDSW:
			regs[rd] = (int32_t)dtrace_load32(regs[r1]);
			break;
		case DIF_OP_RLDUB:
			if (!dtrace_canstore(regs[r1], 1, mstate, vstate)) {
				*flags |= CPU_DTRACE_KPRIV;
				*illval = regs[r1];
				break;
			}
			/*FALLTHROUGH*/
		case DIF_OP_LDUB:
			regs[rd] = dtrace_load8(regs[r1]);
			break;
		case DIF_OP_RLDUH:
			if (!dtrace_canstore(regs[r1], 2, mstate, vstate)) {
				*flags |= CPU_DTRACE_KPRIV;
				*illval = regs[r1];
				break;
			}
			/*FALLTHROUGH*/
		case DIF_OP_LDUH:
			regs[rd] = dtrace_load16(regs[r1]);
			break;
		case DIF_OP_RLDUW:
			if (!dtrace_canstore(regs[r1], 4, mstate, vstate)) {
				*flags |= CPU_DTRACE_KPRIV;
				*illval = regs[r1];
				break;
			}
			/*FALLTHROUGH*/
		case DIF_OP_LDUW:
			regs[rd] = dtrace_load32(regs[r1]);
			break;
		case DIF_OP_RLDX:
			if (!dtrace_canstore(regs[r1], 8, mstate, vstate)) {
				*flags |= CPU_DTRACE_KPRIV;
				*illval = regs[r1];
				break;
			}
			/*FALLTHROUGH*/
		case DIF_OP_LDX:
			regs[rd] = dtrace_load64(regs[r1]);
			break;
/*
 * Darwin 32-bit kernel may fetch from 64-bit user.
 * Do not cast regs to uintptr_t
 * DIF_OP_ULDSB,DIF_OP_ULDSH, DIF_OP_ULDSW, DIF_OP_ULDUB
 * DIF_OP_ULDUH, DIF_OP_ULDUW, DIF_OP_ULDX
 */
		case DIF_OP_ULDSB:
			regs[rd] = (int8_t)
			    dtrace_fuword8(regs[r1]);
			break;
		case DIF_OP_ULDSH:
			regs[rd] = (int16_t)
			    dtrace_fuword16(regs[r1]);
			break;
		case DIF_OP_ULDSW:
			regs[rd] = (int32_t)
			    dtrace_fuword32(regs[r1]);
			break;
		case DIF_OP_ULDUB:
			regs[rd] =
			    dtrace_fuword8(regs[r1]);
			break;
		case DIF_OP_ULDUH:
			regs[rd] =
			    dtrace_fuword16(regs[r1]);
			break;
		case DIF_OP_ULDUW:
			regs[rd] =
			    dtrace_fuword32(regs[r1]);
			break;
		case DIF_OP_ULDX:
			regs[rd] =
			    dtrace_fuword64(regs[r1]);
			break;
		case DIF_OP_RET:
			rval = regs[rd];
			pc = textlen;
			break;
		case DIF_OP_NOP:
			break;
		case DIF_OP_SETX:
			regs[rd] = inttab[DIF_INSTR_INTEGER(instr)];
			break;
		case DIF_OP_SETS:
			regs[rd] = (uint64_t)(uintptr_t)
			    (strtab + DIF_INSTR_STRING(instr));
			break;
		case DIF_OP_SCMP: {
			size_t sz = state->dts_options[DTRACEOPT_STRSIZE];
			uintptr_t s1 = regs[r1];
			uintptr_t s2 = regs[r2];
			size_t lim1 = sz, lim2 = sz;

			if (s1 != 0 &&
			    !dtrace_strcanload(s1, sz, &lim1, mstate, vstate))
				break;
			if (s2 != 0 &&
			    !dtrace_strcanload(s2, sz, &lim2, mstate, vstate))
				break;

			cc_r = dtrace_strncmp((char *)s1, (char *)s2,
				MIN(lim1, lim2));

			cc_n = cc_r < 0;
			cc_z = cc_r == 0;
			cc_v = cc_c = 0;
			break;
		}
		case DIF_OP_LDGA:
			regs[rd] = dtrace_dif_variable(mstate, state,
			    r1, regs[r2]);
			break;
		case DIF_OP_LDGS:
			id = DIF_INSTR_VAR(instr);

			if (id >= DIF_VAR_OTHER_UBASE) {
				uintptr_t a;

				id -= DIF_VAR_OTHER_UBASE;
				svar = vstate->dtvs_globals[id];
				ASSERT(svar != NULL);
				v = &svar->dtsv_var;

				if (!(v->dtdv_type.dtdt_flags & DIF_TF_BYREF)) {
					regs[rd] = svar->dtsv_data;
					break;
				}

				a = (uintptr_t)svar->dtsv_data;

				if (*(uint8_t *)a == UINT8_MAX) {
					/*
					 * If the 0th byte is set to UINT8_MAX
					 * then this is to be treated as a
					 * reference to a NULL variable.
					 */
					regs[rd] = 0;
				} else {
					regs[rd] = a + sizeof (uint64_t);
				}

				break;
			}

			regs[rd] = dtrace_dif_variable(mstate, state, id, 0);
			break;

		case DIF_OP_STGS:
			id = DIF_INSTR_VAR(instr);

			ASSERT(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;

			VERIFY(id < (uint_t)vstate->dtvs_nglobals);
			svar = vstate->dtvs_globals[id];
			ASSERT(svar != NULL);
			v = &svar->dtsv_var;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				uintptr_t a = (uintptr_t)svar->dtsv_data;
				size_t lim;

				ASSERT(a != 0);
				ASSERT(svar->dtsv_size != 0);

				if (regs[rd] == 0) {
					*(uint8_t *)a = UINT8_MAX;
					break;
				} else {
					*(uint8_t *)a = 0;
					a += sizeof (uint64_t);
				}
				if (!dtrace_vcanload(
				    (void *)(uintptr_t)regs[rd], &v->dtdv_type,
					&lim, mstate, vstate))
					break;

				dtrace_vcopy((void *)(uintptr_t)regs[rd],
				    (void *)a, &v->dtdv_type, lim);
				break;
			}

			svar->dtsv_data = regs[rd];
			break;

		case DIF_OP_LDTA:
			/*
			 * There are no DTrace built-in thread-local arrays at
			 * present.  This opcode is saved for future work.
			 */
			*flags |= CPU_DTRACE_ILLOP;
			regs[rd] = 0;
			break;

		case DIF_OP_LDLS:
			id = DIF_INSTR_VAR(instr);

			if (id < DIF_VAR_OTHER_UBASE) {
				/*
				 * For now, this has no meaning.
				 */
				regs[rd] = 0;
				break;
			}

			id -= DIF_VAR_OTHER_UBASE;

			ASSERT(id < (uint_t)vstate->dtvs_nlocals);
			ASSERT(vstate->dtvs_locals != NULL);
			svar = vstate->dtvs_locals[id];
			ASSERT(svar != NULL);
			v = &svar->dtsv_var;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				uintptr_t a = (uintptr_t)svar->dtsv_data;
				size_t sz = v->dtdv_type.dtdt_size;

				sz += sizeof (uint64_t);
				ASSERT(svar->dtsv_size == (int)NCPU * sz);
				a += CPU->cpu_id * sz;

				if (*(uint8_t *)a == UINT8_MAX) {
					/*
					 * If the 0th byte is set to UINT8_MAX
					 * then this is to be treated as a
					 * reference to a NULL variable.
					 */
					regs[rd] = 0;
				} else {
					regs[rd] = a + sizeof (uint64_t);
				}

				break;
			}

			ASSERT(svar->dtsv_size == (int)NCPU * sizeof (uint64_t));
			tmp = (uint64_t *)(uintptr_t)svar->dtsv_data;
			regs[rd] = tmp[CPU->cpu_id];
			break;

		case DIF_OP_STLS:
			id = DIF_INSTR_VAR(instr);

			ASSERT(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;
			VERIFY(id < (uint_t)vstate->dtvs_nlocals);
			ASSERT(vstate->dtvs_locals != NULL);
			svar = vstate->dtvs_locals[id];
			ASSERT(svar != NULL);
			v = &svar->dtsv_var;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				uintptr_t a = (uintptr_t)svar->dtsv_data;
				size_t sz = v->dtdv_type.dtdt_size;
				size_t lim;

				sz += sizeof (uint64_t);
				ASSERT(svar->dtsv_size == (int)NCPU * sz);
				a += CPU->cpu_id * sz;

				if (regs[rd] == 0) {
					*(uint8_t *)a = UINT8_MAX;
					break;
				} else {
					*(uint8_t *)a = 0;
					a += sizeof (uint64_t);
				}

				if (!dtrace_vcanload(
				    (void *)(uintptr_t)regs[rd], &v->dtdv_type,
				    &lim, mstate, vstate))
					break;

				dtrace_vcopy((void *)(uintptr_t)regs[rd],
				    (void *)a, &v->dtdv_type, lim);
				break;
			}

			ASSERT(svar->dtsv_size == (int)NCPU * sizeof (uint64_t));
			tmp = (uint64_t *)(uintptr_t)svar->dtsv_data;
			tmp[CPU->cpu_id] = regs[rd];
			break;

		case DIF_OP_LDTS: {
			dtrace_dynvar_t *dvar;
			dtrace_key_t *key;

			id = DIF_INSTR_VAR(instr);
			ASSERT(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;
			v = &vstate->dtvs_tlocals[id];

			key = &tupregs[DIF_DTR_NREGS];
			key[0].dttk_value = (uint64_t)id;
			key[0].dttk_size = 0;
			DTRACE_TLS_THRKEY(key[1].dttk_value);
			key[1].dttk_size = 0;

			dvar = dtrace_dynvar(dstate, 2, key,
			    sizeof (uint64_t), DTRACE_DYNVAR_NOALLOC,
			    mstate, vstate);

			if (dvar == NULL) {
				regs[rd] = 0;
				break;
			}

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				regs[rd] = (uint64_t)(uintptr_t)dvar->dtdv_data;
			} else {
				regs[rd] = *((uint64_t *)dvar->dtdv_data);
			}

			break;
		}

		case DIF_OP_STTS: {
			dtrace_dynvar_t *dvar;
			dtrace_key_t *key;

			id = DIF_INSTR_VAR(instr);
			ASSERT(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;
			VERIFY(id < (uint_t)vstate->dtvs_ntlocals);

			key = &tupregs[DIF_DTR_NREGS];
			key[0].dttk_value = (uint64_t)id;
			key[0].dttk_size = 0;
			DTRACE_TLS_THRKEY(key[1].dttk_value);
			key[1].dttk_size = 0;
			v = &vstate->dtvs_tlocals[id];

			dvar = dtrace_dynvar(dstate, 2, key,
			    v->dtdv_type.dtdt_size > sizeof (uint64_t) ?
			    v->dtdv_type.dtdt_size : sizeof (uint64_t),
			    regs[rd] ? DTRACE_DYNVAR_ALLOC :
			    DTRACE_DYNVAR_DEALLOC, mstate, vstate);

			/*
			 * Given that we're storing to thread-local data,
			 * we need to flush our predicate cache.
			 */
			dtrace_set_thread_predcache(current_thread(), 0);

			if (dvar == NULL)
				break;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				size_t lim;

				if (!dtrace_vcanload(
				    (void *)(uintptr_t)regs[rd],
				    &v->dtdv_type, &lim, mstate, vstate))
					break;

				dtrace_vcopy((void *)(uintptr_t)regs[rd],
				    dvar->dtdv_data, &v->dtdv_type, lim);
			} else {
				*((uint64_t *)dvar->dtdv_data) = regs[rd];
			}

			break;
		}

		case DIF_OP_SRA:
			regs[rd] = (int64_t)regs[r1] >> regs[r2];
			break;

		case DIF_OP_CALL:
			dtrace_dif_subr(DIF_INSTR_SUBR(instr), rd,
			    regs, tupregs, ttop, mstate, state);
			break;

		case DIF_OP_PUSHTR:
			if (ttop == DIF_DTR_NREGS) {
				*flags |= CPU_DTRACE_TUPOFLOW;
				break;
			}

			if (r1 == DIF_TYPE_STRING) {
				/*
				 * If this is a string type and the size is 0,
				 * we'll use the system-wide default string
				 * size.  Note that we are _not_ looking at
				 * the value of the DTRACEOPT_STRSIZE option;
				 * had this been set, we would expect to have
				 * a non-zero size value in the "pushtr".
				 */
				tupregs[ttop].dttk_size =
				    dtrace_strlen((char *)(uintptr_t)regs[rd],
				    regs[r2] ? regs[r2] :
				    dtrace_strsize_default) + 1;
			} else {
				if (regs[r2] > LONG_MAX) {
					*flags |= CPU_DTRACE_ILLOP;
					break;
				}
				tupregs[ttop].dttk_size = regs[r2];
			}

			tupregs[ttop++].dttk_value = regs[rd];
			break;

		case DIF_OP_PUSHTV:
			if (ttop == DIF_DTR_NREGS) {
				*flags |= CPU_DTRACE_TUPOFLOW;
				break;
			}

			tupregs[ttop].dttk_value = regs[rd];
			tupregs[ttop++].dttk_size = 0;
			break;

		case DIF_OP_POPTS:
			if (ttop != 0)
				ttop--;
			break;

		case DIF_OP_FLUSHTS:
			ttop = 0;
			break;

		case DIF_OP_LDGAA:
		case DIF_OP_LDTAA: {
			dtrace_dynvar_t *dvar;
			dtrace_key_t *key = tupregs;
			uint_t nkeys = ttop;

			id = DIF_INSTR_VAR(instr);
			ASSERT(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;

			key[nkeys].dttk_value = (uint64_t)id;
			key[nkeys++].dttk_size = 0;

			if (DIF_INSTR_OP(instr) == DIF_OP_LDTAA) {
				DTRACE_TLS_THRKEY(key[nkeys].dttk_value);
				key[nkeys++].dttk_size = 0;
				VERIFY(id < (uint_t)vstate->dtvs_ntlocals);
				v = &vstate->dtvs_tlocals[id];
			} else {
				VERIFY(id < (uint_t)vstate->dtvs_nglobals);
				v = &vstate->dtvs_globals[id]->dtsv_var;
			}

			dvar = dtrace_dynvar(dstate, nkeys, key,
			    v->dtdv_type.dtdt_size > sizeof (uint64_t) ?
			    v->dtdv_type.dtdt_size : sizeof (uint64_t),
			    DTRACE_DYNVAR_NOALLOC, mstate, vstate);

			if (dvar == NULL) {
				regs[rd] = 0;
				break;
			}

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				regs[rd] = (uint64_t)(uintptr_t)dvar->dtdv_data;
			} else {
				regs[rd] = *((uint64_t *)dvar->dtdv_data);
			}

			break;
		}

		case DIF_OP_STGAA:
		case DIF_OP_STTAA: {
			dtrace_dynvar_t *dvar;
			dtrace_key_t *key = tupregs;
			uint_t nkeys = ttop;

			id = DIF_INSTR_VAR(instr);
			ASSERT(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;

			key[nkeys].dttk_value = (uint64_t)id;
			key[nkeys++].dttk_size = 0;

			if (DIF_INSTR_OP(instr) == DIF_OP_STTAA) {
				DTRACE_TLS_THRKEY(key[nkeys].dttk_value);
				key[nkeys++].dttk_size = 0;
				VERIFY(id < (uint_t)vstate->dtvs_ntlocals);
				v = &vstate->dtvs_tlocals[id];
			} else {
				VERIFY(id < (uint_t)vstate->dtvs_nglobals);
				v = &vstate->dtvs_globals[id]->dtsv_var;
			}

			dvar = dtrace_dynvar(dstate, nkeys, key,
			    v->dtdv_type.dtdt_size > sizeof (uint64_t) ?
			    v->dtdv_type.dtdt_size : sizeof (uint64_t),
			    regs[rd] ? DTRACE_DYNVAR_ALLOC :
			    DTRACE_DYNVAR_DEALLOC, mstate, vstate);

			if (dvar == NULL)
				break;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				size_t lim;

				if (!dtrace_vcanload(
				    (void *)(uintptr_t)regs[rd], &v->dtdv_type,
				    &lim, mstate, vstate))
					break;

				dtrace_vcopy((void *)(uintptr_t)regs[rd],
				    dvar->dtdv_data, &v->dtdv_type, lim);
			} else {
				*((uint64_t *)dvar->dtdv_data) = regs[rd];
			}

			break;
		}

		case DIF_OP_ALLOCS: {
			uintptr_t ptr = P2ROUNDUP(mstate->dtms_scratch_ptr, 8);
			size_t size = ptr - mstate->dtms_scratch_ptr + regs[r1];

			/*
			 * Rounding up the user allocation size could have
			 * overflowed large, bogus allocations (like -1ULL) to
			 * 0.
			 */
			if (size < regs[r1] ||
			    !DTRACE_INSCRATCH(mstate, size)) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
				regs[rd] = 0;
				break;
			}

			dtrace_bzero((void *) mstate->dtms_scratch_ptr, size);
				mstate->dtms_scratch_ptr += size;
				regs[rd] = ptr;
			break;
		}

		case DIF_OP_COPYS:
			if (!dtrace_canstore(regs[rd], regs[r2],
			    mstate, vstate)) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = regs[rd];
				break;
			}

			if (!dtrace_canload(regs[r1], regs[r2], mstate, vstate))
				break;

			dtrace_bcopy((void *)(uintptr_t)regs[r1],
			    (void *)(uintptr_t)regs[rd], (size_t)regs[r2]);
			break;

		case DIF_OP_STB:
			if (!dtrace_canstore(regs[rd], 1, mstate, vstate)) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = regs[rd];
				break;
			}
			*((uint8_t *)(uintptr_t)regs[rd]) = (uint8_t)regs[r1];
			break;

		case DIF_OP_STH:
			if (!dtrace_canstore(regs[rd], 2, mstate, vstate)) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = regs[rd];
				break;
			}
			if (regs[rd] & 1) {
				*flags |= CPU_DTRACE_BADALIGN;
				*illval = regs[rd];
				break;
			}
			*((uint16_t *)(uintptr_t)regs[rd]) = (uint16_t)regs[r1];
			break;

		case DIF_OP_STW:
			if (!dtrace_canstore(regs[rd], 4, mstate, vstate)) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = regs[rd];
				break;
			}
			if (regs[rd] & 3) {
				*flags |= CPU_DTRACE_BADALIGN;
				*illval = regs[rd];
				break;
			}
			*((uint32_t *)(uintptr_t)regs[rd]) = (uint32_t)regs[r1];
			break;

		case DIF_OP_STX:
			if (!dtrace_canstore(regs[rd], 8, mstate, vstate)) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = regs[rd];
				break;
			}

			/*
			* Darwin kmem_zalloc() called from
			* dtrace_difo_init() is 4-byte aligned.
			*/
			if (regs[rd] & 3) {
				*flags |= CPU_DTRACE_BADALIGN;
				*illval = regs[rd];
				break;
			}
			*((uint64_t *)(uintptr_t)regs[rd]) = regs[r1];
			break;
		}
	}

	if (!(*flags & CPU_DTRACE_FAULT))
		return (rval);

	mstate->dtms_fltoffs = opc * sizeof (dif_instr_t);
	mstate->dtms_present |= DTRACE_MSTATE_FLTOFFS;

	return (0);
}

static void
dtrace_action_breakpoint(dtrace_ecb_t *ecb)
{
	dtrace_probe_t *probe = ecb->dte_probe;
	dtrace_provider_t *prov = probe->dtpr_provider;
	char c[DTRACE_FULLNAMELEN + 80], *str;
	const char *msg = "dtrace: breakpoint action at probe ";
	const char *ecbmsg = " (ecb ";
	uintptr_t mask = (0xf << (sizeof (uintptr_t) * NBBY / 4));
	uintptr_t val = (uintptr_t)ecb;
	int shift = (sizeof (uintptr_t) * NBBY) - 4, i = 0;

	if (dtrace_destructive_disallow)
		return;

	/*
	 * It's impossible to be taking action on the NULL probe.
	 */
	ASSERT(probe != NULL);

	/*
	 * This is a poor man's (destitute man's?) sprintf():  we want to
	 * print the provider name, module name, function name and name of
	 * the probe, along with the hex address of the ECB with the breakpoint
	 * action -- all of which we must place in the character buffer by
	 * hand.
	 */
	while (*msg != '\0')
		c[i++] = *msg++;

	for (str = prov->dtpv_name; *str != '\0'; str++)
		c[i++] = *str;
	c[i++] = ':';

	for (str = probe->dtpr_mod; *str != '\0'; str++)
		c[i++] = *str;
	c[i++] = ':';

	for (str = probe->dtpr_func; *str != '\0'; str++)
		c[i++] = *str;
	c[i++] = ':';

	for (str = probe->dtpr_name; *str != '\0'; str++)
		c[i++] = *str;

	while (*ecbmsg != '\0')
		c[i++] = *ecbmsg++;

	while (shift >= 0) {
		mask = (uintptr_t)0xf << shift;

		if (val >= ((uintptr_t)1 << shift))
			c[i++] = "0123456789abcdef"[(val & mask) >> shift];
		shift -= 4;
	}

	c[i++] = ')';
	c[i] = '\0';

	debug_enter(c);
}

static void
dtrace_action_panic(dtrace_ecb_t *ecb)
{
	dtrace_probe_t *probe = ecb->dte_probe;

	/*
	 * It's impossible to be taking action on the NULL probe.
	 */
	ASSERT(probe != NULL);

	if (dtrace_destructive_disallow)
		return;

	if (dtrace_panicked != NULL)
		return;

	if (dtrace_casptr(&dtrace_panicked, NULL, current_thread()) != NULL)
		return;

	/*
	 * We won the right to panic.  (We want to be sure that only one
	 * thread calls panic() from dtrace_probe(), and that panic() is
	 * called exactly once.)
	 */
	panic("dtrace: panic action at probe %s:%s:%s:%s (ecb %p)",
	    probe->dtpr_provider->dtpv_name, probe->dtpr_mod,
	    probe->dtpr_func, probe->dtpr_name, (void *)ecb);

	/*
	 * APPLE NOTE: this was for an old Mac OS X debug feature
	 * allowing a return from panic().  Revisit someday.
	 */
	dtrace_panicked = NULL;
}

static void
dtrace_action_raise(uint64_t sig)
{
	if (dtrace_destructive_disallow)
		return;

	if (sig >= NSIG) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return;
	}

	/*
	 * raise() has a queue depth of 1 -- we ignore all subsequent
	 * invocations of the raise() action.
	 */

	uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());

	if (uthread && uthread->t_dtrace_sig == 0) {
		uthread->t_dtrace_sig = sig;
		act_set_astbsd(current_thread());
	}
}

static void
dtrace_action_stop(void)
{
	if (dtrace_destructive_disallow)
		return;

        uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());
	if (uthread) {
		/*
		 * The currently running process will be set to task_suspend
		 * when it next leaves the kernel.
		*/
		uthread->t_dtrace_stop = 1;
		act_set_astbsd(current_thread());
	}
}


/*
 * APPLE NOTE: pidresume works in conjunction with the dtrace stop action.
 * Both activate only when the currently running process next leaves the
 * kernel.
 */
static void
dtrace_action_pidresume(uint64_t pid)
{
	if (dtrace_destructive_disallow)
		return;

	if (kauth_cred_issuser(kauth_cred_get()) == 0) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);		
		return;
	}
        uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());

	/*
	 * When the currently running process leaves the kernel, it attempts to
	 * task_resume the process (denoted by pid), if that pid appears to have
	 * been stopped by dtrace_action_stop().
	 * The currently running process has a pidresume() queue depth of 1 --
	 * subsequent invocations of the pidresume() action are ignored.
	 */	

	if (pid != 0 && uthread && uthread->t_dtrace_resumepid == 0) {
		uthread->t_dtrace_resumepid = pid;
		act_set_astbsd(current_thread());
	}
}

static void
dtrace_action_chill(dtrace_mstate_t *mstate, hrtime_t val)
{
	hrtime_t now;
	volatile uint16_t *flags;
	dtrace_cpu_t *cpu = CPU;

	if (dtrace_destructive_disallow)
		return;

	flags = (volatile uint16_t *)&cpu_core[cpu->cpu_id].cpuc_dtrace_flags;

	now = dtrace_gethrtime();

	if (now - cpu->cpu_dtrace_chillmark > dtrace_chill_interval) {
		/*
		 * We need to advance the mark to the current time.
		 */
		cpu->cpu_dtrace_chillmark = now;
		cpu->cpu_dtrace_chilled = 0;
	}

	/*
	 * Now check to see if the requested chill time would take us over
	 * the maximum amount of time allowed in the chill interval.  (Or
	 * worse, if the calculation itself induces overflow.)
	 */
	if (cpu->cpu_dtrace_chilled + val > dtrace_chill_max ||
	    cpu->cpu_dtrace_chilled + val < cpu->cpu_dtrace_chilled) {
		*flags |= CPU_DTRACE_ILLOP;
		return;
	}

	while (dtrace_gethrtime() - now < val)
		continue;

	/*
	 * Normally, we assure that the value of the variable "timestamp" does
	 * not change within an ECB.  The presence of chill() represents an
	 * exception to this rule, however.
	 */
	mstate->dtms_present &= ~DTRACE_MSTATE_TIMESTAMP;
	cpu->cpu_dtrace_chilled += val;
}

static void
dtrace_action_ustack(dtrace_mstate_t *mstate, dtrace_state_t *state,
    uint64_t *buf, uint64_t arg)
{
	int nframes = DTRACE_USTACK_NFRAMES(arg);
	int strsize = DTRACE_USTACK_STRSIZE(arg);
	uint64_t *pcs = &buf[1], *fps;
	char *str = (char *)&pcs[nframes];
	int size, offs = 0, i, j;
	uintptr_t old = mstate->dtms_scratch_ptr, saved;
	uint16_t *flags = &cpu_core[CPU->cpu_id].cpuc_dtrace_flags;
	char *sym;

	/*
	 * Should be taking a faster path if string space has not been
	 * allocated.
	 */
	ASSERT(strsize != 0);

	/*
	 * We will first allocate some temporary space for the frame pointers.
	 */
	fps = (uint64_t *)P2ROUNDUP(mstate->dtms_scratch_ptr, 8);
	size = (uintptr_t)fps - mstate->dtms_scratch_ptr +
	    (nframes * sizeof (uint64_t));

	if (!DTRACE_INSCRATCH(mstate, (uintptr_t)size)) {
		/*
		 * Not enough room for our frame pointers -- need to indicate
		 * that we ran out of scratch space.
		 */
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
		return;
	}

	mstate->dtms_scratch_ptr += size;
	saved = mstate->dtms_scratch_ptr;

	/*
	 * Now get a stack with both program counters and frame pointers.
	 */
	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	dtrace_getufpstack(buf, fps, nframes + 1);
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	/*
	 * If that faulted, we're cooked.
	 */
	if (*flags & CPU_DTRACE_FAULT)
		goto out;

	/*
	 * Now we want to walk up the stack, calling the USTACK helper.  For
	 * each iteration, we restore the scratch pointer.
	 */
	for (i = 0; i < nframes; i++) {
		mstate->dtms_scratch_ptr = saved;

		if (offs >= strsize)
			break;

		sym = (char *)(uintptr_t)dtrace_helper(
		    DTRACE_HELPER_ACTION_USTACK,
		    mstate, state, pcs[i], fps[i]);

		/*
		 * If we faulted while running the helper, we're going to
		 * clear the fault and null out the corresponding string.
		 */
		if (*flags & CPU_DTRACE_FAULT) {
			*flags &= ~CPU_DTRACE_FAULT;
			str[offs++] = '\0';
			continue;
		}

		if (sym == NULL) {
			str[offs++] = '\0';
			continue;
		}

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);

		/*
		 * Now copy in the string that the helper returned to us.
		 */
		for (j = 0; offs + j < strsize; j++) {
			if ((str[offs + j] = sym[j]) == '\0')
				break;
		}

		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

		offs += j + 1;
	}

	if (offs >= strsize) {
		/*
		 * If we didn't have room for all of the strings, we don't
		 * abort processing -- this needn't be a fatal error -- but we
		 * still want to increment a counter (dts_stkstroverflows) to
		 * allow this condition to be warned about.  (If this is from
		 * a jstack() action, it is easily tuned via jstackstrsize.)
		 */
		dtrace_error(&state->dts_stkstroverflows);
	}

	while (offs < strsize)
		str[offs++] = '\0';

out:
	mstate->dtms_scratch_ptr = old;
}

static void
dtrace_store_by_ref(dtrace_difo_t *dp, caddr_t tomax, size_t size,
    size_t *valoffsp, uint64_t *valp, uint64_t end, int intuple, int dtkind)
{
	volatile uint16_t *flags;
	uint64_t val = *valp;
	size_t valoffs = *valoffsp;

	flags = (volatile uint16_t *)&cpu_core[CPU->cpu_id].cpuc_dtrace_flags;
	ASSERT(dtkind == DIF_TF_BYREF || dtkind == DIF_TF_BYUREF);

	/*
	 * If this is a string, we're going to only load until we find the zero
	 * byte -- after which we'll store zero bytes.
	 */
	if (dp->dtdo_rtype.dtdt_kind == DIF_TYPE_STRING) {
		char c = '\0' + 1;
		size_t s;

		for (s = 0; s < size; s++) {
			if (c != '\0' && dtkind == DIF_TF_BYREF) {
				c = dtrace_load8(val++);
			} else if (c != '\0' && dtkind == DIF_TF_BYUREF) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
				c = dtrace_fuword8((user_addr_t)(uintptr_t)val++);
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
				if (*flags & CPU_DTRACE_FAULT)
					break;
			}

			DTRACE_STORE(uint8_t, tomax, valoffs++, c);

			if (c == '\0' && intuple)
				break;
		}
	} else {
		uint8_t c;
		while (valoffs < end) {
			if (dtkind == DIF_TF_BYREF) {
				c = dtrace_load8(val++);
			} else if (dtkind == DIF_TF_BYUREF) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
				c = dtrace_fuword8((user_addr_t)(uintptr_t)val++);
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
				if (*flags & CPU_DTRACE_FAULT)
					break;
			}

			DTRACE_STORE(uint8_t, tomax,
			    valoffs++, c);
		}
	}

	*valp = val;
	*valoffsp = valoffs;
}

/*
 * If you're looking for the epicenter of DTrace, you just found it.  This
 * is the function called by the provider to fire a probe -- from which all
 * subsequent probe-context DTrace activity emanates.
 */
static void
__dtrace_probe(dtrace_id_t id, uint64_t arg0, uint64_t arg1,
    uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
	processorid_t cpuid;
	dtrace_icookie_t cookie;
	dtrace_probe_t *probe;
	dtrace_mstate_t mstate;
	dtrace_ecb_t *ecb;
	dtrace_action_t *act;
	intptr_t offs;
	size_t size;
	int vtime, onintr;
	volatile uint16_t *flags;
	hrtime_t now;

	cookie = dtrace_interrupt_disable();
	probe = dtrace_probes[id - 1];
	cpuid = CPU->cpu_id;
	onintr = CPU_ON_INTR(CPU);

	if (!onintr && probe->dtpr_predcache != DTRACE_CACHEIDNONE &&
	    probe->dtpr_predcache == dtrace_get_thread_predcache(current_thread())) {
		/*
		 * We have hit in the predicate cache; we know that
		 * this predicate would evaluate to be false.
		 */
		dtrace_interrupt_enable(cookie);
		return;
	}

	if (panic_quiesce) {
		/*
		 * We don't trace anything if we're panicking.
		 */
		dtrace_interrupt_enable(cookie);
		return;
	}

#if !defined(__APPLE__)
	now = dtrace_gethrtime();
	vtime = dtrace_vtime_references != 0;

	if (vtime && curthread->t_dtrace_start)
		curthread->t_dtrace_vtime += now - curthread->t_dtrace_start;
#else
	/*
	 * APPLE NOTE:  The time spent entering DTrace and arriving
	 * to this point, is attributed to the current thread.
	 * Instead it should accrue to DTrace.  FIXME
	 */
	vtime = dtrace_vtime_references != 0;

	if (vtime)
	{
		int64_t dtrace_accum_time, recent_vtime;
		thread_t thread = current_thread();

		dtrace_accum_time = dtrace_get_thread_tracing(thread); /* Time spent inside DTrace so far (nanoseconds) */

		if (dtrace_accum_time >= 0) {
			recent_vtime = dtrace_abs_to_nano(dtrace_calc_thread_recent_vtime(thread)); /* up to the moment thread vtime */

			recent_vtime = recent_vtime - dtrace_accum_time; /* Time without DTrace contribution */
		
			dtrace_set_thread_vtime(thread, recent_vtime);
		}
	}

	now = dtrace_gethrtime(); /* must not precede dtrace_calc_thread_recent_vtime() call! */
#endif /* __APPLE__ */

	/*
	 * APPLE NOTE: A provider may call dtrace_probe_error() in lieu of
	 * dtrace_probe() in some circumstances.   See, e.g. fasttrap_isa.c.
	 * However the provider has no access to ECB context, so passes
	 * 0 through "arg0" and the probe_id of the overridden probe as arg1.
	 * Detect that here and cons up a viable state (from the probe_id).
	 */
	if (dtrace_probeid_error == id && 0 == arg0) {
		dtrace_id_t ftp_id = (dtrace_id_t)arg1;
		dtrace_probe_t *ftp_probe = dtrace_probes[ftp_id - 1];
		dtrace_ecb_t *ftp_ecb = ftp_probe->dtpr_ecb;

		if (NULL != ftp_ecb) {
			dtrace_state_t *ftp_state = ftp_ecb->dte_state;

			arg0 = (uint64_t)(uintptr_t)ftp_state;
			arg1 = ftp_ecb->dte_epid;
			/*
			 * args[2-4] established by caller.
			 */
			ftp_state->dts_arg_error_illval = -1; /* arg5 */
		}
	}

	mstate.dtms_difo = NULL;
	mstate.dtms_probe = probe;
	mstate.dtms_strtok = 0;
	mstate.dtms_arg[0] = arg0;
	mstate.dtms_arg[1] = arg1;
	mstate.dtms_arg[2] = arg2;
	mstate.dtms_arg[3] = arg3;
	mstate.dtms_arg[4] = arg4;

	flags = (volatile uint16_t *)&cpu_core[cpuid].cpuc_dtrace_flags;

	for (ecb = probe->dtpr_ecb; ecb != NULL; ecb = ecb->dte_next) {
		dtrace_predicate_t *pred = ecb->dte_predicate;
		dtrace_state_t *state = ecb->dte_state;
		dtrace_buffer_t *buf = &state->dts_buffer[cpuid];
		dtrace_buffer_t *aggbuf = &state->dts_aggbuffer[cpuid];
		dtrace_vstate_t *vstate = &state->dts_vstate;
		dtrace_provider_t *prov = probe->dtpr_provider;
		uint64_t tracememsize = 0;
		int committed = 0;
		caddr_t tomax;

		/*
		 * A little subtlety with the following (seemingly innocuous)
		 * declaration of the automatic 'val':  by looking at the
		 * code, you might think that it could be declared in the
		 * action processing loop, below.  (That is, it's only used in
		 * the action processing loop.)  However, it must be declared
		 * out of that scope because in the case of DIF expression
		 * arguments to aggregating actions, one iteration of the
		 * action loop will use the last iteration's value.
		 */
#ifdef lint
		uint64_t val = 0;
#else
		uint64_t val = 0;
#endif

		mstate.dtms_present = DTRACE_MSTATE_ARGS | DTRACE_MSTATE_PROBE;
		*flags &= ~CPU_DTRACE_ERROR;

		if (prov == dtrace_provider) {
			/*
			 * If dtrace itself is the provider of this probe,
			 * we're only going to continue processing the ECB if
			 * arg0 (the dtrace_state_t) is equal to the ECB's
			 * creating state.  (This prevents disjoint consumers
			 * from seeing one another's metaprobes.)
			 */
			if (arg0 != (uint64_t)(uintptr_t)state)
				continue;
		}

		if (state->dts_activity != DTRACE_ACTIVITY_ACTIVE) {
			/*
			 * We're not currently active.  If our provider isn't
			 * the dtrace pseudo provider, we're not interested.
			 */
			if (prov != dtrace_provider)
				continue;

			/*
			 * Now we must further check if we are in the BEGIN
			 * probe.  If we are, we will only continue processing
			 * if we're still in WARMUP -- if one BEGIN enabling
			 * has invoked the exit() action, we don't want to
			 * evaluate subsequent BEGIN enablings.
			 */
			if (probe->dtpr_id == dtrace_probeid_begin &&
			    state->dts_activity != DTRACE_ACTIVITY_WARMUP) {
				ASSERT(state->dts_activity ==
				    DTRACE_ACTIVITY_DRAINING);
				continue;
			}
		}

		if (ecb->dte_cond) {
			/*
			 * If the dte_cond bits indicate that this
			 * consumer is only allowed to see user-mode firings
			 * of this probe, call the provider's dtps_usermode()
			 * entry point to check that the probe was fired
			 * while in a user context. Skip this ECB if that's
			 * not the case.
			 */
			if ((ecb->dte_cond & DTRACE_COND_USERMODE) &&
			    prov->dtpv_pops.dtps_usermode &&
			    prov->dtpv_pops.dtps_usermode(prov->dtpv_arg,
			    probe->dtpr_id, probe->dtpr_arg) == 0)
				continue;

			/*
			 * This is more subtle than it looks. We have to be
			 * absolutely certain that CRED() isn't going to
			 * change out from under us so it's only legit to
			 * examine that structure if we're in constrained
			 * situations. Currently, the only times we'll this
			 * check is if a non-super-user has enabled the
			 * profile or syscall providers -- providers that
			 * allow visibility of all processes. For the
			 * profile case, the check above will ensure that
			 * we're examining a user context.
			 */
			if (ecb->dte_cond & DTRACE_COND_OWNER) {
				cred_t *cr;
				cred_t *s_cr =
				    ecb->dte_state->dts_cred.dcr_cred;
				proc_t *proc;
#pragma unused(proc) /* __APPLE__ */

				ASSERT(s_cr != NULL);

			/*
			 * XXX this is hackish, but so is setting a variable
			 * XXX in a McCarthy OR...
			 */
				if ((cr = dtrace_CRED()) == NULL ||
				    posix_cred_get(s_cr)->cr_uid != posix_cred_get(cr)->cr_uid ||
				    posix_cred_get(s_cr)->cr_uid != posix_cred_get(cr)->cr_ruid ||
				    posix_cred_get(s_cr)->cr_uid != posix_cred_get(cr)->cr_suid ||
				    posix_cred_get(s_cr)->cr_gid != posix_cred_get(cr)->cr_gid ||
				    posix_cred_get(s_cr)->cr_gid != posix_cred_get(cr)->cr_rgid ||
				    posix_cred_get(s_cr)->cr_gid != posix_cred_get(cr)->cr_sgid ||
#if !defined(__APPLE__)
				    (proc = ttoproc(curthread)) == NULL ||
				    (proc->p_flag & SNOCD))
#else
					1) /* APPLE NOTE: Darwin omits "No Core Dump" flag */
#endif /* __APPLE__ */
					continue;
			}

			if (ecb->dte_cond & DTRACE_COND_ZONEOWNER) {
				cred_t *cr;
				cred_t *s_cr =
				    ecb->dte_state->dts_cred.dcr_cred;
#pragma unused(cr, s_cr) /* __APPLE__ */

				ASSERT(s_cr != NULL);

#if !defined(__APPLE__)
				if ((cr = CRED()) == NULL ||
				    s_cr->cr_zone->zone_id !=
				    cr->cr_zone->zone_id)
					continue;
#else
				/* APPLE NOTE: Darwin doesn't do zones. */
#endif /* __APPLE__ */
			}
		}

		if (now - state->dts_alive > dtrace_deadman_timeout) {
			/*
			 * We seem to be dead.  Unless we (a) have kernel
			 * destructive permissions (b) have expicitly enabled
			 * destructive actions and (c) destructive actions have
			 * not been disabled, we're going to transition into
			 * the KILLED state, from which no further processing
			 * on this state will be performed.
			 */
			if (!dtrace_priv_kernel_destructive(state) ||
			    !state->dts_cred.dcr_destructive ||
			    dtrace_destructive_disallow) {
				void *activity = &state->dts_activity;
				dtrace_activity_t current;

				do {
					current = state->dts_activity;
				} while (dtrace_cas32(activity, current,
				    DTRACE_ACTIVITY_KILLED) != current);

				continue;
			}
		}

		if ((offs = dtrace_buffer_reserve(buf, ecb->dte_needed,
		    ecb->dte_alignment, state, &mstate)) < 0)
			continue;

		tomax = buf->dtb_tomax;
		ASSERT(tomax != NULL);

		/*
		 * Build and store the record header corresponding to the ECB.
		 */
		if (ecb->dte_size != 0) {
			dtrace_rechdr_t dtrh;

			if (!(mstate.dtms_present & DTRACE_MSTATE_TIMESTAMP)) {
				mstate.dtms_timestamp = dtrace_gethrtime();
				mstate.dtms_present |= DTRACE_MSTATE_TIMESTAMP;
			}

			ASSERT(ecb->dte_size >= sizeof(dtrace_rechdr_t));

			dtrh.dtrh_epid = ecb->dte_epid;
			DTRACE_RECORD_STORE_TIMESTAMP(&dtrh, mstate.dtms_timestamp);
			DTRACE_STORE(dtrace_rechdr_t, tomax, offs, dtrh);
		}

		mstate.dtms_epid = ecb->dte_epid;
		mstate.dtms_present |= DTRACE_MSTATE_EPID;

		if (state->dts_cred.dcr_visible & DTRACE_CRV_KERNEL)
			mstate.dtms_access = DTRACE_ACCESS_KERNEL;
		else
			mstate.dtms_access = 0;

		if (pred != NULL) {
			dtrace_difo_t *dp = pred->dtp_difo;
			int rval;

			rval = dtrace_dif_emulate(dp, &mstate, vstate, state);

			if (!(*flags & CPU_DTRACE_ERROR) && !rval) {
				dtrace_cacheid_t cid = probe->dtpr_predcache;

				if (cid != DTRACE_CACHEIDNONE && !onintr) {
					/*
					 * Update the predicate cache...
					 */
					ASSERT(cid == pred->dtp_cacheid);

					dtrace_set_thread_predcache(current_thread(), cid);
				}

				continue;
			}
		}

		for (act = ecb->dte_action; !(*flags & CPU_DTRACE_ERROR) &&
		    act != NULL; act = act->dta_next) {
			size_t valoffs;
			dtrace_difo_t *dp;
			dtrace_recdesc_t *rec = &act->dta_rec;

			size = rec->dtrd_size;
			valoffs = offs + rec->dtrd_offset;

			if (DTRACEACT_ISAGG(act->dta_kind)) {
				uint64_t v = 0xbad;
				dtrace_aggregation_t *agg;

				agg = (dtrace_aggregation_t *)act;

				if ((dp = act->dta_difo) != NULL)
					v = dtrace_dif_emulate(dp,
					    &mstate, vstate, state);

				if (*flags & CPU_DTRACE_ERROR)
					continue;

				/*
				 * Note that we always pass the expression
				 * value from the previous iteration of the
				 * action loop.  This value will only be used
				 * if there is an expression argument to the
				 * aggregating action, denoted by the
				 * dtag_hasarg field.
				 */
				dtrace_aggregate(agg, buf,
				    offs, aggbuf, v, val);
				continue;
			}

			switch (act->dta_kind) {
			case DTRACEACT_STOP:
				if (dtrace_priv_proc_destructive(state))
					dtrace_action_stop();
				continue;

			case DTRACEACT_BREAKPOINT:
				if (dtrace_priv_kernel_destructive(state))
					dtrace_action_breakpoint(ecb);
				continue;

			case DTRACEACT_PANIC:
				if (dtrace_priv_kernel_destructive(state))
					dtrace_action_panic(ecb);
				continue;

			case DTRACEACT_STACK:
				if (!dtrace_priv_kernel(state))
					continue;

				dtrace_getpcstack((pc_t *)(tomax + valoffs),
				    size / sizeof (pc_t), probe->dtpr_aframes,
				    DTRACE_ANCHORED(probe) ? NULL :
				  (uint32_t *)(uintptr_t)arg0);
				continue;

			case DTRACEACT_JSTACK:
			case DTRACEACT_USTACK:
				if (!dtrace_priv_proc(state))
					continue;

				/*
				 * See comment in DIF_VAR_PID.
				 */
				if (DTRACE_ANCHORED(mstate.dtms_probe) &&
				    CPU_ON_INTR(CPU)) {
					int depth = DTRACE_USTACK_NFRAMES(
					    rec->dtrd_arg) + 1;

					dtrace_bzero((void *)(tomax + valoffs),
					    DTRACE_USTACK_STRSIZE(rec->dtrd_arg)
					    + depth * sizeof (uint64_t));

					continue;
				}

				if (DTRACE_USTACK_STRSIZE(rec->dtrd_arg) != 0 &&
				    curproc->p_dtrace_helpers != NULL) {
					/*
					 * This is the slow path -- we have
					 * allocated string space, and we're
					 * getting the stack of a process that
					 * has helpers.  Call into a separate
					 * routine to perform this processing.
					 */
					dtrace_action_ustack(&mstate, state,
					    (uint64_t *)(tomax + valoffs),
					    rec->dtrd_arg);
					continue;
				}

				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
				dtrace_getupcstack((uint64_t *)
				    (tomax + valoffs),
				    DTRACE_USTACK_NFRAMES(rec->dtrd_arg) + 1);
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
				continue;

			default:
				break;
			}

			dp = act->dta_difo;
			ASSERT(dp != NULL);

			val = dtrace_dif_emulate(dp, &mstate, vstate, state);

			if (*flags & CPU_DTRACE_ERROR)
				continue;

			switch (act->dta_kind) {
			case DTRACEACT_SPECULATE: {
				dtrace_rechdr_t *dtrh = NULL;

				ASSERT(buf == &state->dts_buffer[cpuid]);
				buf = dtrace_speculation_buffer(state,
				    cpuid, val);

				if (buf == NULL) {
					*flags |= CPU_DTRACE_DROP;
					continue;
				}

				offs = dtrace_buffer_reserve(buf,
				    ecb->dte_needed, ecb->dte_alignment,
				    state, NULL);

				if (offs < 0) {
					*flags |= CPU_DTRACE_DROP;
					continue;
				}

				tomax = buf->dtb_tomax;
				ASSERT(tomax != NULL);

				if (ecb->dte_size == 0)
					continue;

				ASSERT(ecb->dte_size >= sizeof(dtrace_rechdr_t));
				dtrh = ((void *)(tomax + offs));
				dtrh->dtrh_epid = ecb->dte_epid;

				/*
				 * When the speculation is committed, all of
				 * the records in the speculative buffer will
				 * have their timestamps set to the commit
				 * time.  Until then, it is set to a sentinel
				 * value, for debugability.
				 */
				DTRACE_RECORD_STORE_TIMESTAMP(dtrh, UINT64_MAX);

 				continue;
			}

			case DTRACEACT_CHILL:
				if (dtrace_priv_kernel_destructive(state))
					dtrace_action_chill(&mstate, val);
				continue;

			case DTRACEACT_RAISE:
				if (dtrace_priv_proc_destructive(state))
					dtrace_action_raise(val);
				continue;

			case DTRACEACT_PIDRESUME:   /* __APPLE__ */
				if (dtrace_priv_proc_destructive(state))
					dtrace_action_pidresume(val);
				continue;

			case DTRACEACT_COMMIT:
				ASSERT(!committed);

				/*
				 * We need to commit our buffer state.
				 */
				if (ecb->dte_size)
					buf->dtb_offset = offs + ecb->dte_size;
				buf = &state->dts_buffer[cpuid];
				dtrace_speculation_commit(state, cpuid, val);
				committed = 1;
				continue;

			case DTRACEACT_DISCARD:
				dtrace_speculation_discard(state, cpuid, val);
				continue;

			case DTRACEACT_DIFEXPR:
			case DTRACEACT_LIBACT:
			case DTRACEACT_PRINTF:
			case DTRACEACT_PRINTA:
			case DTRACEACT_SYSTEM:
			case DTRACEACT_FREOPEN:
			case DTRACEACT_APPLEBINARY:   /* __APPLE__ */
			case DTRACEACT_TRACEMEM:
				break;

			case DTRACEACT_TRACEMEM_DYNSIZE:
				tracememsize = val;
				break;

			case DTRACEACT_SYM:
			case DTRACEACT_MOD:
				if (!dtrace_priv_kernel(state))
					continue;
				break;

			case DTRACEACT_USYM:
			case DTRACEACT_UMOD:
			case DTRACEACT_UADDR: {
				if (!dtrace_priv_proc(state))
					continue;

				DTRACE_STORE(uint64_t, tomax,
				    valoffs, (uint64_t)dtrace_proc_selfpid());
				DTRACE_STORE(uint64_t, tomax,
				    valoffs + sizeof (uint64_t), val);

				continue;
			}

			case DTRACEACT_EXIT: {
				/*
				 * For the exit action, we are going to attempt
				 * to atomically set our activity to be
				 * draining.  If this fails (either because
				 * another CPU has beat us to the exit action,
				 * or because our current activity is something
				 * other than ACTIVE or WARMUP), we will
				 * continue.  This assures that the exit action
				 * can be successfully recorded at most once
				 * when we're in the ACTIVE state.  If we're
				 * encountering the exit() action while in
				 * COOLDOWN, however, we want to honor the new
				 * status code.  (We know that we're the only
				 * thread in COOLDOWN, so there is no race.)
				 */
				void *activity = &state->dts_activity;
				dtrace_activity_t current = state->dts_activity;

				if (current == DTRACE_ACTIVITY_COOLDOWN)
					break;

				if (current != DTRACE_ACTIVITY_WARMUP)
					current = DTRACE_ACTIVITY_ACTIVE;

				if (dtrace_cas32(activity, current,
				    DTRACE_ACTIVITY_DRAINING) != current) {
					*flags |= CPU_DTRACE_DROP;
					continue;
				}

				break;
			}

			default:
				ASSERT(0);
			}

			if (dp->dtdo_rtype.dtdt_flags & (DIF_TF_BYREF | DIF_TF_BYUREF)) {
				uintptr_t end = valoffs + size;

				if (tracememsize != 0 &&
                                    valoffs + tracememsize < end)
				{
                                        end = valoffs + tracememsize;
                                        tracememsize = 0;
                                }

				if (dp->dtdo_rtype.dtdt_flags & DIF_TF_BYREF &&
				    !dtrace_vcanload((void *)(uintptr_t)val,
				    &dp->dtdo_rtype, NULL, &mstate, vstate))
				{
					continue;
				}

				dtrace_store_by_ref(dp, tomax, size, &valoffs,
				    &val, end, act->dta_intuple,
				    dp->dtdo_rtype.dtdt_flags & DIF_TF_BYREF ?
				    DIF_TF_BYREF: DIF_TF_BYUREF);

				continue;
			}

			switch (size) {
			case 0:
				break;

			case sizeof (uint8_t):
				DTRACE_STORE(uint8_t, tomax, valoffs, val);
				break;
			case sizeof (uint16_t):
				DTRACE_STORE(uint16_t, tomax, valoffs, val);
				break;
			case sizeof (uint32_t):
				DTRACE_STORE(uint32_t, tomax, valoffs, val);
				break;
			case sizeof (uint64_t):
				DTRACE_STORE(uint64_t, tomax, valoffs, val);
				break;
			default:
				/*
				 * Any other size should have been returned by
				 * reference, not by value.
				 */
				ASSERT(0);
				break;
			}
		}

		if (*flags & CPU_DTRACE_DROP)
			continue;

		if (*flags & CPU_DTRACE_FAULT) {
			int ndx;
			dtrace_action_t *err;

			buf->dtb_errors++;

			if (probe->dtpr_id == dtrace_probeid_error) {
				/*
				 * There's nothing we can do -- we had an
				 * error on the error probe.  We bump an
				 * error counter to at least indicate that
				 * this condition happened.
				 */
				dtrace_error(&state->dts_dblerrors);
				continue;
			}

			if (vtime) {
				/*
				 * Before recursing on dtrace_probe(), we
				 * need to explicitly clear out our start
				 * time to prevent it from being accumulated
				 * into t_dtrace_vtime.
				 */

				/*				   
				 * Darwin sets the sign bit on t_dtrace_tracing
				 * to suspend accumulation to it.
				 */
				dtrace_set_thread_tracing(current_thread(), 
				    (1ULL<<63) | dtrace_get_thread_tracing(current_thread()));

			}

			/*
			 * Iterate over the actions to figure out which action
			 * we were processing when we experienced the error.
			 * Note that act points _past_ the faulting action; if
			 * act is ecb->dte_action, the fault was in the
			 * predicate, if it's ecb->dte_action->dta_next it's
			 * in action #1, and so on.
			 */
			for (err = ecb->dte_action, ndx = 0;
			    err != act; err = err->dta_next, ndx++)
				continue;

			dtrace_probe_error(state, ecb->dte_epid, ndx,
			    (mstate.dtms_present & DTRACE_MSTATE_FLTOFFS) ?
			    mstate.dtms_fltoffs : -1, DTRACE_FLAGS2FLT(*flags),
			    cpu_core[cpuid].cpuc_dtrace_illval);

			continue;
		}

		if (!committed)
			buf->dtb_offset = offs + ecb->dte_size;
	}

	/* FIXME: On Darwin the time spent leaving DTrace from this point to the rti is attributed
	   to the current thread. Instead it should accrue to DTrace. */
	if (vtime) {
		thread_t thread = current_thread();
		int64_t t = dtrace_get_thread_tracing(thread);
		
		if (t >= 0) { 
			/* Usual case, accumulate time spent here into t_dtrace_tracing */
			dtrace_set_thread_tracing(thread, t + (dtrace_gethrtime() - now));
		} else { 
			/* Return from error recursion. No accumulation, just clear the sign bit on t_dtrace_tracing. */
			dtrace_set_thread_tracing(thread, (~(1ULL<<63)) & t); 
		}
	}

	dtrace_interrupt_enable(cookie);
}

/*
 * APPLE NOTE:  Don't allow a thread to re-enter dtrace_probe().
 * This could occur if a probe is encountered on some function in the
 * transitive closure of the call to dtrace_probe().
 * Solaris has some strong guarantees that this won't happen.
 * The Darwin implementation is not so mature as to make those guarantees.
 * Hence, the introduction of __dtrace_probe() on xnu.
 */

void
dtrace_probe(dtrace_id_t id, uint64_t arg0, uint64_t arg1,
    uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
	thread_t thread = current_thread();
	disable_preemption();
	if (id == dtrace_probeid_error) {
		__dtrace_probe(id, arg0, arg1, arg2, arg3, arg4);
		dtrace_getipl(); /* Defeat tail-call optimization of __dtrace_probe() */
	} else if (!dtrace_get_thread_reentering(thread)) {
		dtrace_set_thread_reentering(thread, TRUE);
		__dtrace_probe(id, arg0, arg1, arg2, arg3, arg4);
		dtrace_set_thread_reentering(thread, FALSE);
	}
#if DEBUG
	else __dtrace_probe(dtrace_probeid_error, 0, id, 1, -1, DTRACEFLT_UNKNOWN);
#endif
	enable_preemption();
}

/*
 * DTrace Probe Hashing Functions
 *
 * The functions in this section (and indeed, the functions in remaining
 * sections) are not _called_ from probe context.  (Any exceptions to this are
 * marked with a "Note:".)  Rather, they are called from elsewhere in the
 * DTrace framework to look-up probes in, add probes to and remove probes from
 * the DTrace probe hashes.  (Each probe is hashed by each element of the
 * probe tuple -- allowing for fast lookups, regardless of what was
 * specified.)
 */
static uint_t
dtrace_hash_str(const char *p)
{
	unsigned int g;
	uint_t hval = 0;

	while (*p) {
		hval = (hval << 4) + *p++;
		if ((g = (hval & 0xf0000000)) != 0)
			hval ^= g >> 24;
		hval &= ~g;
	}
	return (hval);
}

static dtrace_hash_t *
dtrace_hash_create(uintptr_t stroffs, uintptr_t nextoffs, uintptr_t prevoffs)
{
	dtrace_hash_t *hash = kmem_zalloc(sizeof (dtrace_hash_t), KM_SLEEP);

	hash->dth_stroffs = stroffs;
	hash->dth_nextoffs = nextoffs;
	hash->dth_prevoffs = prevoffs;

	hash->dth_size = 1;
	hash->dth_mask = hash->dth_size - 1;

	hash->dth_tab = kmem_zalloc(hash->dth_size *
	    sizeof (dtrace_hashbucket_t *), KM_SLEEP);

	return (hash);
}

/*
 * APPLE NOTE: dtrace_hash_destroy is not used.
 * It is called by dtrace_detach which is not
 * currently implemented.  Revisit someday.
 */
#if !defined(__APPLE__)
static void
dtrace_hash_destroy(dtrace_hash_t *hash)
{
#if DEBUG
	int i;

	for (i = 0; i < hash->dth_size; i++)
		ASSERT(hash->dth_tab[i] == NULL);
#endif

	kmem_free(hash->dth_tab,
	    hash->dth_size * sizeof (dtrace_hashbucket_t *));
	kmem_free(hash, sizeof (dtrace_hash_t));
}
#endif /* __APPLE__ */

static void
dtrace_hash_resize(dtrace_hash_t *hash)
{
	int size = hash->dth_size, i, ndx;
	int new_size = hash->dth_size << 1;
	int new_mask = new_size - 1;
	dtrace_hashbucket_t **new_tab, *bucket, *next;

	ASSERT((new_size & new_mask) == 0);

	new_tab = kmem_zalloc(new_size * sizeof (void *), KM_SLEEP);

	for (i = 0; i < size; i++) {
		for (bucket = hash->dth_tab[i]; bucket != NULL; bucket = next) {
			dtrace_probe_t *probe = bucket->dthb_chain;

			ASSERT(probe != NULL);
			ndx = DTRACE_HASHSTR(hash, probe) & new_mask;

			next = bucket->dthb_next;
			bucket->dthb_next = new_tab[ndx];
			new_tab[ndx] = bucket;
		}
	}

	kmem_free(hash->dth_tab, hash->dth_size * sizeof (void *));
	hash->dth_tab = new_tab;
	hash->dth_size = new_size;
	hash->dth_mask = new_mask;
}

static void
dtrace_hash_add(dtrace_hash_t *hash, dtrace_probe_t *new)
{
	int hashval = DTRACE_HASHSTR(hash, new);
	int ndx = hashval & hash->dth_mask;
	dtrace_hashbucket_t *bucket = hash->dth_tab[ndx];
	dtrace_probe_t **nextp, **prevp;

	for (; bucket != NULL; bucket = bucket->dthb_next) {
		if (DTRACE_HASHEQ(hash, bucket->dthb_chain, new))
			goto add;
	}

	if ((hash->dth_nbuckets >> 1) > hash->dth_size) {
		dtrace_hash_resize(hash);
		dtrace_hash_add(hash, new);
		return;
	}

	bucket = kmem_zalloc(sizeof (dtrace_hashbucket_t), KM_SLEEP);
	bucket->dthb_next = hash->dth_tab[ndx];
	hash->dth_tab[ndx] = bucket;
	hash->dth_nbuckets++;

add:
	nextp = DTRACE_HASHNEXT(hash, new);
	ASSERT(*nextp == NULL && *(DTRACE_HASHPREV(hash, new)) == NULL);
	*nextp = bucket->dthb_chain;

	if (bucket->dthb_chain != NULL) {
		prevp = DTRACE_HASHPREV(hash, bucket->dthb_chain);
		ASSERT(*prevp == NULL);
		*prevp = new;
	}

	bucket->dthb_chain = new;
	bucket->dthb_len++;
}

static dtrace_probe_t *
dtrace_hash_lookup(dtrace_hash_t *hash, dtrace_probe_t *template)
{
	int hashval = DTRACE_HASHSTR(hash, template);
	int ndx = hashval & hash->dth_mask;
	dtrace_hashbucket_t *bucket = hash->dth_tab[ndx];

	for (; bucket != NULL; bucket = bucket->dthb_next) {
		if (DTRACE_HASHEQ(hash, bucket->dthb_chain, template))
			return (bucket->dthb_chain);
	}

	return (NULL);
}

static int
dtrace_hash_collisions(dtrace_hash_t *hash, dtrace_probe_t *template)
{
	int hashval = DTRACE_HASHSTR(hash, template);
	int ndx = hashval & hash->dth_mask;
	dtrace_hashbucket_t *bucket = hash->dth_tab[ndx];

	for (; bucket != NULL; bucket = bucket->dthb_next) {
		if (DTRACE_HASHEQ(hash, bucket->dthb_chain, template))
			return (bucket->dthb_len);
	}

	return (0);
}

static void
dtrace_hash_remove(dtrace_hash_t *hash, dtrace_probe_t *probe)
{
	int ndx = DTRACE_HASHSTR(hash, probe) & hash->dth_mask;
	dtrace_hashbucket_t *bucket = hash->dth_tab[ndx];

	dtrace_probe_t **prevp = DTRACE_HASHPREV(hash, probe);
	dtrace_probe_t **nextp = DTRACE_HASHNEXT(hash, probe);

	/*
	 * Find the bucket that we're removing this probe from.
	 */
	for (; bucket != NULL; bucket = bucket->dthb_next) {
		if (DTRACE_HASHEQ(hash, bucket->dthb_chain, probe))
			break;
	}

	ASSERT(bucket != NULL);

	if (*prevp == NULL) {
		if (*nextp == NULL) {
			/*
			 * The removed probe was the only probe on this
			 * bucket; we need to remove the bucket.
			 */
			dtrace_hashbucket_t *b = hash->dth_tab[ndx];

			ASSERT(bucket->dthb_chain == probe);
			ASSERT(b != NULL);

			if (b == bucket) {
				hash->dth_tab[ndx] = bucket->dthb_next;
			} else {
				while (b->dthb_next != bucket)
					b = b->dthb_next;
				b->dthb_next = bucket->dthb_next;
			}

			ASSERT(hash->dth_nbuckets > 0);
			hash->dth_nbuckets--;
			kmem_free(bucket, sizeof (dtrace_hashbucket_t));
			return;
		}

		bucket->dthb_chain = *nextp;
	} else {
		*(DTRACE_HASHNEXT(hash, *prevp)) = *nextp;
	}

	if (*nextp != NULL)
		*(DTRACE_HASHPREV(hash, *nextp)) = *prevp;
}

/*
 * DTrace Utility Functions
 *
 * These are random utility functions that are _not_ called from probe context.
 */
static int
dtrace_badattr(const dtrace_attribute_t *a)
{
	return (a->dtat_name > DTRACE_STABILITY_MAX ||
	    a->dtat_data > DTRACE_STABILITY_MAX ||
	    a->dtat_class > DTRACE_CLASS_MAX);
}

/*
 * Return a duplicate copy of a string.  If the specified string is NULL,
 * this function returns a zero-length string.
 * APPLE NOTE: Darwin employs size bounded string operation.
 */
static char *
dtrace_strdup(const char *str)
{
	size_t bufsize = (str != NULL ? strlen(str) : 0) + 1;
	char *new = kmem_zalloc(bufsize, KM_SLEEP);

	if (str != NULL)
		(void) strlcpy(new, str, bufsize);

	return (new);
}

#define	DTRACE_ISALPHA(c)	\
	(((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z'))

static int
dtrace_badname(const char *s)
{
	char c;

	if (s == NULL || (c = *s++) == '\0')
		return (0);

	if (!DTRACE_ISALPHA(c) && c != '-' && c != '_' && c != '.')
		return (1);

	while ((c = *s++) != '\0') {
		if (!DTRACE_ISALPHA(c) && (c < '0' || c > '9') &&
		    c != '-' && c != '_' && c != '.' && c != '`')
			return (1);
	}

	return (0);
}

static void
dtrace_cred2priv(cred_t *cr, uint32_t *privp, uid_t *uidp, zoneid_t *zoneidp)
{
	uint32_t priv;

	if (cr == NULL || PRIV_POLICY_ONLY(cr, PRIV_ALL, B_FALSE)) {
		if (dtrace_is_restricted() && !dtrace_are_restrictions_relaxed()) {
			priv = DTRACE_PRIV_USER | DTRACE_PRIV_PROC;
		}
		else {
			priv = DTRACE_PRIV_ALL;
		}
	} else {
		*uidp = crgetuid(cr);
		*zoneidp = crgetzoneid(cr);

		priv = 0;
		if (PRIV_POLICY_ONLY(cr, PRIV_DTRACE_KERNEL, B_FALSE))
			priv |= DTRACE_PRIV_KERNEL | DTRACE_PRIV_USER;
		else if (PRIV_POLICY_ONLY(cr, PRIV_DTRACE_USER, B_FALSE))
			priv |= DTRACE_PRIV_USER;
		if (PRIV_POLICY_ONLY(cr, PRIV_DTRACE_PROC, B_FALSE))
			priv |= DTRACE_PRIV_PROC;
		if (PRIV_POLICY_ONLY(cr, PRIV_PROC_OWNER, B_FALSE))
			priv |= DTRACE_PRIV_OWNER;
		if (PRIV_POLICY_ONLY(cr, PRIV_PROC_ZONE, B_FALSE))
			priv |= DTRACE_PRIV_ZONEOWNER;
	}

	*privp = priv;
}

#ifdef DTRACE_ERRDEBUG
static void
dtrace_errdebug(const char *str)
{
	int hval = dtrace_hash_str(str) % DTRACE_ERRHASHSZ;
	int occupied = 0;

	lck_mtx_lock(&dtrace_errlock);
	dtrace_errlast = str;
	dtrace_errthread = (kthread_t *)current_thread();

	while (occupied++ < DTRACE_ERRHASHSZ) {
		if (dtrace_errhash[hval].dter_msg == str) {
			dtrace_errhash[hval].dter_count++;
			goto out;
		}

		if (dtrace_errhash[hval].dter_msg != NULL) {
			hval = (hval + 1) % DTRACE_ERRHASHSZ;
			continue;
		}

		dtrace_errhash[hval].dter_msg = str;
		dtrace_errhash[hval].dter_count = 1;
		goto out;
	}

	panic("dtrace: undersized error hash");
out:
	lck_mtx_unlock(&dtrace_errlock);
}
#endif

/*
 * DTrace Matching Functions
 *
 * These functions are used to match groups of probes, given some elements of
 * a probe tuple, or some globbed expressions for elements of a probe tuple.
 */
static int
dtrace_match_priv(const dtrace_probe_t *prp, uint32_t priv, uid_t uid,
    zoneid_t zoneid)
{
	if (priv != DTRACE_PRIV_ALL) {
		uint32_t ppriv = prp->dtpr_provider->dtpv_priv.dtpp_flags;
		uint32_t match = priv & ppriv;

		/*
		 * No PRIV_DTRACE_* privileges...
		 */
		if ((priv & (DTRACE_PRIV_PROC | DTRACE_PRIV_USER |
		    DTRACE_PRIV_KERNEL)) == 0)
			return (0);

		/*
		 * No matching bits, but there were bits to match...
		 */
		if (match == 0 && ppriv != 0)
			return (0);

		/*
		 * Need to have permissions to the process, but don't...
		 */
		if (((ppriv & ~match) & DTRACE_PRIV_OWNER) != 0 &&
		    uid != prp->dtpr_provider->dtpv_priv.dtpp_uid) {
			return (0);
		}

		/*
		 * Need to be in the same zone unless we possess the
		 * privilege to examine all zones.
		 */
		if (((ppriv & ~match) & DTRACE_PRIV_ZONEOWNER) != 0 &&
		    zoneid != prp->dtpr_provider->dtpv_priv.dtpp_zoneid) {
			return (0);
		}
	}

	return (1);
}

/*
 * dtrace_match_probe compares a dtrace_probe_t to a pre-compiled key, which
 * consists of input pattern strings and an ops-vector to evaluate them.
 * This function returns >0 for match, 0 for no match, and <0 for error.
 */
static int
dtrace_match_probe(const dtrace_probe_t *prp, const dtrace_probekey_t *pkp,
    uint32_t priv, uid_t uid, zoneid_t zoneid)
{
	dtrace_provider_t *pvp = prp->dtpr_provider;
	int rv;

	if (pvp->dtpv_defunct)
		return (0);

	if ((rv = pkp->dtpk_pmatch(pvp->dtpv_name, pkp->dtpk_prov, 0)) <= 0)
		return (rv);

	if ((rv = pkp->dtpk_mmatch(prp->dtpr_mod, pkp->dtpk_mod, 0)) <= 0)
		return (rv);

	if ((rv = pkp->dtpk_fmatch(prp->dtpr_func, pkp->dtpk_func, 0)) <= 0)
		return (rv);

	if ((rv = pkp->dtpk_nmatch(prp->dtpr_name, pkp->dtpk_name, 0)) <= 0)
		return (rv);

	if (dtrace_match_priv(prp, priv, uid, zoneid) == 0)
		return (0);

	return (rv);
}

/*
 * dtrace_match_glob() is a safe kernel implementation of the gmatch(3GEN)
 * interface for matching a glob pattern 'p' to an input string 's'.  Unlike
 * libc's version, the kernel version only applies to 8-bit ASCII strings.
 * In addition, all of the recursion cases except for '*' matching have been
 * unwound.  For '*', we still implement recursive evaluation, but a depth
 * counter is maintained and matching is aborted if we recurse too deep.
 * The function returns 0 if no match, >0 if match, and <0 if recursion error.
 */
static int
dtrace_match_glob(const char *s, const char *p, int depth)
{
	const char *olds;
	char s1, c;
	int gs;

	if (depth > DTRACE_PROBEKEY_MAXDEPTH)
		return (-1);

	if (s == NULL)
		s = ""; /* treat NULL as empty string */

top:
	olds = s;
	s1 = *s++;

	if (p == NULL)
		return (0);

	if ((c = *p++) == '\0')
		return (s1 == '\0');

	switch (c) {
	case '[': {
		int ok = 0, notflag = 0;
		char lc = '\0';

		if (s1 == '\0')
			return (0);

		if (*p == '!') {
			notflag = 1;
			p++;
		}

		if ((c = *p++) == '\0')
			return (0);

		do {
			if (c == '-' && lc != '\0' && *p != ']') {
				if ((c = *p++) == '\0')
					return (0);
				if (c == '\\' && (c = *p++) == '\0')
					return (0);

				if (notflag) {
					if (s1 < lc || s1 > c)
						ok++;
					else
						return (0);
				} else if (lc <= s1 && s1 <= c)
					ok++;

			} else if (c == '\\' && (c = *p++) == '\0')
				return (0);

			lc = c; /* save left-hand 'c' for next iteration */

			if (notflag) {
				if (s1 != c)
					ok++;
				else
					return (0);
			} else if (s1 == c)
				ok++;

			if ((c = *p++) == '\0')
				return (0);

		} while (c != ']');

		if (ok)
			goto top;

		return (0);
	}

	case '\\':
		if ((c = *p++) == '\0')
			return (0);
		/*FALLTHRU*/

	default:
		if (c != s1)
			return (0);
		/*FALLTHRU*/

	case '?':
		if (s1 != '\0')
			goto top;
		return (0);

	case '*':
		while (*p == '*')
			p++; /* consecutive *'s are identical to a single one */

		if (*p == '\0')
			return (1);

		for (s = olds; *s != '\0'; s++) {
			if ((gs = dtrace_match_glob(s, p, depth + 1)) != 0)
				return (gs);
		}

		return (0);
	}
}

/*ARGSUSED*/
static int
dtrace_match_string(const char *s, const char *p, int depth)
{
#pragma unused(depth) /* __APPLE__ */

	/* APPLE NOTE: Darwin employs size bounded string operation. */
	return (s != NULL && strncmp(s, p, strlen(s) + 1) == 0);
}

/*ARGSUSED*/
static int
dtrace_match_nul(const char *s, const char *p, int depth)
{
#pragma unused(s, p, depth) /* __APPLE__ */
	return (1); /* always match the empty pattern */
}

/*ARGSUSED*/
static int
dtrace_match_nonzero(const char *s, const char *p, int depth)
{
#pragma unused(p, depth) /* __APPLE__ */
	return (s != NULL && s[0] != '\0');
}

static int
dtrace_match(const dtrace_probekey_t *pkp, uint32_t priv, uid_t uid,
    zoneid_t zoneid, int (*matched)(dtrace_probe_t *, void *), void *arg)
{
	dtrace_probe_t template, *probe;
	dtrace_hash_t *hash = NULL;
	int len, rc, best = INT_MAX, nmatched = 0;
	dtrace_id_t i;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	/*
	 * If the probe ID is specified in the key, just lookup by ID and
	 * invoke the match callback once if a matching probe is found.
	 */
	if (pkp->dtpk_id != DTRACE_IDNONE) {
		if ((probe = dtrace_probe_lookup_id(pkp->dtpk_id)) != NULL &&
		    dtrace_match_probe(probe, pkp, priv, uid, zoneid) > 0) {
		        if ((*matched)(probe, arg) == DTRACE_MATCH_FAIL)
                               return (DTRACE_MATCH_FAIL);
			nmatched++;
		}
		return (nmatched);
	}

	template.dtpr_mod =  (char *)(uintptr_t)pkp->dtpk_mod;
	template.dtpr_func = (char *)(uintptr_t)pkp->dtpk_func;
	template.dtpr_name = (char *)(uintptr_t)pkp->dtpk_name;

	/*
	 * We want to find the most distinct of the module name, function
	 * name, and name.  So for each one that is not a glob pattern or
	 * empty string, we perform a lookup in the corresponding hash and
	 * use the hash table with the fewest collisions to do our search.
	 */
	if (pkp->dtpk_mmatch == &dtrace_match_string &&
	    (len = dtrace_hash_collisions(dtrace_bymod, &template)) < best) {
		best = len;
		hash = dtrace_bymod;
	}

	if (pkp->dtpk_fmatch == &dtrace_match_string &&
	    (len = dtrace_hash_collisions(dtrace_byfunc, &template)) < best) {
		best = len;
		hash = dtrace_byfunc;
	}

	if (pkp->dtpk_nmatch == &dtrace_match_string &&
	    (len = dtrace_hash_collisions(dtrace_byname, &template)) < best) {
		best = len;
		hash = dtrace_byname;
	}

	/*
	 * If we did not select a hash table, iterate over every probe and
	 * invoke our callback for each one that matches our input probe key.
	 */
	if (hash == NULL) {
		for (i = 0; i < (dtrace_id_t)dtrace_nprobes; i++) {
			if ((probe = dtrace_probes[i]) == NULL ||
			    dtrace_match_probe(probe, pkp, priv, uid,
			    zoneid) <= 0)
				continue;

			nmatched++;

                       if ((rc = (*matched)(probe, arg)) != DTRACE_MATCH_NEXT) {
			       if (rc == DTRACE_MATCH_FAIL)
                                       return (DTRACE_MATCH_FAIL);
			       break;
                       }
		}

		return (nmatched);
	}

	/*
	 * If we selected a hash table, iterate over each probe of the same key
	 * name and invoke the callback for every probe that matches the other
	 * attributes of our input probe key.
	 */
	for (probe = dtrace_hash_lookup(hash, &template); probe != NULL;
	    probe = *(DTRACE_HASHNEXT(hash, probe))) {

		if (dtrace_match_probe(probe, pkp, priv, uid, zoneid) <= 0)
			continue;

		nmatched++;

		if ((rc = (*matched)(probe, arg)) != DTRACE_MATCH_NEXT) {
		    if (rc == DTRACE_MATCH_FAIL)
			return (DTRACE_MATCH_FAIL);
		    break;
		}
	}

	return (nmatched);
}

/*
 * Return the function pointer dtrace_probecmp() should use to compare the
 * specified pattern with a string.  For NULL or empty patterns, we select
 * dtrace_match_nul().  For glob pattern strings, we use dtrace_match_glob().
 * For non-empty non-glob strings, we use dtrace_match_string().
 */
static dtrace_probekey_f *
dtrace_probekey_func(const char *p)
{
	char c;

	if (p == NULL || *p == '\0')
		return (&dtrace_match_nul);

	while ((c = *p++) != '\0') {
		if (c == '[' || c == '?' || c == '*' || c == '\\')
			return (&dtrace_match_glob);
	}

	return (&dtrace_match_string);
}

/*
 * Build a probe comparison key for use with dtrace_match_probe() from the
 * given probe description.  By convention, a null key only matches anchored
 * probes: if each field is the empty string, reset dtpk_fmatch to
 * dtrace_match_nonzero().
 */
static void
dtrace_probekey(const dtrace_probedesc_t *pdp, dtrace_probekey_t *pkp)
{
	pkp->dtpk_prov = pdp->dtpd_provider;
	pkp->dtpk_pmatch = dtrace_probekey_func(pdp->dtpd_provider);

	pkp->dtpk_mod = pdp->dtpd_mod;
	pkp->dtpk_mmatch = dtrace_probekey_func(pdp->dtpd_mod);

	pkp->dtpk_func = pdp->dtpd_func;
	pkp->dtpk_fmatch = dtrace_probekey_func(pdp->dtpd_func);

	pkp->dtpk_name = pdp->dtpd_name;
	pkp->dtpk_nmatch = dtrace_probekey_func(pdp->dtpd_name);

	pkp->dtpk_id = pdp->dtpd_id;

	if (pkp->dtpk_id == DTRACE_IDNONE &&
	    pkp->dtpk_pmatch == &dtrace_match_nul &&
	    pkp->dtpk_mmatch == &dtrace_match_nul &&
	    pkp->dtpk_fmatch == &dtrace_match_nul &&
	    pkp->dtpk_nmatch == &dtrace_match_nul)
		pkp->dtpk_fmatch = &dtrace_match_nonzero;
}

static int
dtrace_cond_provider_match(dtrace_probedesc_t *desc, void *data)
{
	if (desc == NULL)
		return 1;

	dtrace_probekey_f *func = dtrace_probekey_func(desc->dtpd_provider);

	return func(desc->dtpd_provider, (char*)data, 0);
}

/*
 * DTrace Provider-to-Framework API Functions
 *
 * These functions implement much of the Provider-to-Framework API, as
 * described in <sys/dtrace.h>.  The parts of the API not in this section are
 * the functions in the API for probe management (found below), and
 * dtrace_probe() itself (found above).
 */

/*
 * Register the calling provider with the DTrace framework.  This should
 * generally be called by DTrace providers in their attach(9E) entry point.
 */
int
dtrace_register(const char *name, const dtrace_pattr_t *pap, uint32_t priv,
    cred_t *cr, const dtrace_pops_t *pops, void *arg, dtrace_provider_id_t *idp)
{
	dtrace_provider_t *provider;

	if (name == NULL || pap == NULL || pops == NULL || idp == NULL) {
		cmn_err(CE_WARN, "failed to register provider '%s': invalid "
		    "arguments", name ? name : "<NULL>");
		return (EINVAL);
	}

	if (name[0] == '\0' || dtrace_badname(name)) {
		cmn_err(CE_WARN, "failed to register provider '%s': invalid "
		    "provider name", name);
		return (EINVAL);
	}

	if ((pops->dtps_provide == NULL && pops->dtps_provide_module == NULL) ||
	    pops->dtps_enable == NULL || pops->dtps_disable == NULL ||
	    pops->dtps_destroy == NULL ||
	    ((pops->dtps_resume == NULL) != (pops->dtps_suspend == NULL))) {
		cmn_err(CE_WARN, "failed to register provider '%s': invalid "
		    "provider ops", name);
		return (EINVAL);
	}

	if (dtrace_badattr(&pap->dtpa_provider) ||
	    dtrace_badattr(&pap->dtpa_mod) ||
	    dtrace_badattr(&pap->dtpa_func) ||
	    dtrace_badattr(&pap->dtpa_name) ||
	    dtrace_badattr(&pap->dtpa_args)) {
		cmn_err(CE_WARN, "failed to register provider '%s': invalid "
		    "provider attributes", name);
		return (EINVAL);
	}

	if (priv & ~DTRACE_PRIV_ALL) {
		cmn_err(CE_WARN, "failed to register provider '%s': invalid "
		    "privilege attributes", name);
		return (EINVAL);
	}

	if ((priv & DTRACE_PRIV_KERNEL) &&
	    (priv & (DTRACE_PRIV_USER | DTRACE_PRIV_OWNER)) &&
	    pops->dtps_usermode == NULL) {
		cmn_err(CE_WARN, "failed to register provider '%s': need "
		    "dtps_usermode() op for given privilege attributes", name);
		return (EINVAL);
	}

	provider = kmem_zalloc(sizeof (dtrace_provider_t), KM_SLEEP);

	/* APPLE NOTE: Darwin employs size bounded string operation. */
	{
	size_t bufsize = strlen(name) + 1;
	provider->dtpv_name = kmem_alloc(bufsize, KM_SLEEP);
	(void) strlcpy(provider->dtpv_name, name, bufsize);
	}

	provider->dtpv_attr = *pap;
	provider->dtpv_priv.dtpp_flags = priv;
	if (cr != NULL) {
		provider->dtpv_priv.dtpp_uid = crgetuid(cr);
		provider->dtpv_priv.dtpp_zoneid = crgetzoneid(cr);
	}
	provider->dtpv_pops = *pops;

	if (pops->dtps_provide == NULL) {
		ASSERT(pops->dtps_provide_module != NULL);
		provider->dtpv_pops.dtps_provide =
		    (void (*)(void *, const dtrace_probedesc_t *))dtrace_nullop;
	}

	if (pops->dtps_provide_module == NULL) {
		ASSERT(pops->dtps_provide != NULL);
		provider->dtpv_pops.dtps_provide_module =
		    (void (*)(void *, struct modctl *))dtrace_nullop;
	}

	if (pops->dtps_suspend == NULL) {
		ASSERT(pops->dtps_resume == NULL);
		provider->dtpv_pops.dtps_suspend =
		    (void (*)(void *, dtrace_id_t, void *))dtrace_nullop;
		provider->dtpv_pops.dtps_resume =
		    (void (*)(void *, dtrace_id_t, void *))dtrace_nullop;
	}

	provider->dtpv_arg = arg;
	*idp = (dtrace_provider_id_t)provider;

	if (pops == &dtrace_provider_ops) {
		lck_mtx_assert(&dtrace_provider_lock, LCK_MTX_ASSERT_OWNED);
		lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
		ASSERT(dtrace_anon.dta_enabling == NULL);

		/*
		 * We make sure that the DTrace provider is at the head of
		 * the provider chain.
		 */
		provider->dtpv_next = dtrace_provider;
		dtrace_provider = provider;
		return (0);
	}

	lck_mtx_lock(&dtrace_provider_lock);
	lck_mtx_lock(&dtrace_lock);

	/*
	 * If there is at least one provider registered, we'll add this
	 * provider after the first provider.
	 */
	if (dtrace_provider != NULL) {
		provider->dtpv_next = dtrace_provider->dtpv_next;
		dtrace_provider->dtpv_next = provider;
	} else {
		dtrace_provider = provider;
	}

	if (dtrace_retained != NULL) {
		dtrace_enabling_provide(provider);

		/*
		 * Now we need to call dtrace_enabling_matchall_with_cond() --
		 * with a condition matching the provider name we just added,
		 * which will acquire cpu_lock and dtrace_lock.  We therefore need
		 * to drop all of our locks before calling into it...
		 */
		lck_mtx_unlock(&dtrace_lock);
		lck_mtx_unlock(&dtrace_provider_lock);

		dtrace_match_cond_t cond = {dtrace_cond_provider_match, provider->dtpv_name};
		dtrace_enabling_matchall_with_cond(&cond);

		return (0);
	}

	lck_mtx_unlock(&dtrace_lock);
	lck_mtx_unlock(&dtrace_provider_lock);

	return (0);
}

/*
 * Unregister the specified provider from the DTrace framework.  This should
 * generally be called by DTrace providers in their detach(9E) entry point.
 */
int
dtrace_unregister(dtrace_provider_id_t id)
{
	dtrace_provider_t *old = (dtrace_provider_t *)id;
	dtrace_provider_t *prev = NULL;
	int i, self = 0;
	dtrace_probe_t *probe, *first = NULL;

	if (old->dtpv_pops.dtps_enable ==
	    (int (*)(void *, dtrace_id_t, void *))dtrace_enable_nullop) {
		/*
		 * If DTrace itself is the provider, we're called with locks
		 * already held.
		 */
		ASSERT(old == dtrace_provider);
		ASSERT(dtrace_devi != NULL);
		lck_mtx_assert(&dtrace_provider_lock, LCK_MTX_ASSERT_OWNED);
		lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
		self = 1;

		if (dtrace_provider->dtpv_next != NULL) {
			/*
			 * There's another provider here; return failure.
			 */
			return (EBUSY);
		}
	} else {
		lck_mtx_lock(&dtrace_provider_lock);
		lck_mtx_lock(&mod_lock);
		lck_mtx_lock(&dtrace_lock);
	}

	/*
	 * If anyone has /dev/dtrace open, or if there are anonymous enabled
	 * probes, we refuse to let providers slither away, unless this
	 * provider has already been explicitly invalidated.
	 */
	if (!old->dtpv_defunct &&
	    (dtrace_opens || (dtrace_anon.dta_state != NULL &&
	    dtrace_anon.dta_state->dts_necbs > 0))) {
		if (!self) {
			lck_mtx_unlock(&dtrace_lock);
			lck_mtx_unlock(&mod_lock);
			lck_mtx_unlock(&dtrace_provider_lock);
		}
		return (EBUSY);
	}

	/*
	 * Attempt to destroy the probes associated with this provider.
	 */
	if (old->dtpv_ecb_count!=0) {
		/*
		 * We have at least one ECB; we can't remove this provider.
		 */
		if (!self) {
			lck_mtx_unlock(&dtrace_lock);
			lck_mtx_unlock(&mod_lock);
			lck_mtx_unlock(&dtrace_provider_lock);
		}
		return (EBUSY);
	}

	/*
	 * All of the probes for this provider are disabled; we can safely
	 * remove all of them from their hash chains and from the probe array.
	 */
	for (i = 0; i < dtrace_nprobes && old->dtpv_probe_count!=0; i++) {
		if ((probe = dtrace_probes[i]) == NULL)
			continue;

		if (probe->dtpr_provider != old)
			continue;

		dtrace_probes[i] = NULL;
		old->dtpv_probe_count--;

		dtrace_hash_remove(dtrace_bymod, probe);
		dtrace_hash_remove(dtrace_byfunc, probe);
		dtrace_hash_remove(dtrace_byname, probe);

		if (first == NULL) {
			first = probe;
			probe->dtpr_nextmod = NULL;
		} else {
			probe->dtpr_nextmod = first;
			first = probe;
		}
	}

	/*
	 * The provider's probes have been removed from the hash chains and
	 * from the probe array.  Now issue a dtrace_sync() to be sure that
	 * everyone has cleared out from any probe array processing.
	 */
	dtrace_sync();

	for (probe = first; probe != NULL; probe = first) {
		first = probe->dtpr_nextmod;

		old->dtpv_pops.dtps_destroy(old->dtpv_arg, probe->dtpr_id,
		    probe->dtpr_arg);
		kmem_free(probe->dtpr_mod, strlen(probe->dtpr_mod) + 1);
		kmem_free(probe->dtpr_func, strlen(probe->dtpr_func) + 1);
		kmem_free(probe->dtpr_name, strlen(probe->dtpr_name) + 1);
		vmem_free(dtrace_arena, (void *)(uintptr_t)(probe->dtpr_id), 1);
		zfree(dtrace_probe_t_zone, probe);
	}

	if ((prev = dtrace_provider) == old) {
		ASSERT(self || dtrace_devi == NULL);
		ASSERT(old->dtpv_next == NULL || dtrace_devi == NULL);
		dtrace_provider = old->dtpv_next;
	} else {
		while (prev != NULL && prev->dtpv_next != old)
			prev = prev->dtpv_next;

		if (prev == NULL) {
			panic("attempt to unregister non-existent "
			    "dtrace provider %p\n", (void *)id);
		}

		prev->dtpv_next = old->dtpv_next;
	}

	if (!self) {
		lck_mtx_unlock(&dtrace_lock);
		lck_mtx_unlock(&mod_lock);
		lck_mtx_unlock(&dtrace_provider_lock);
	}

	kmem_free(old->dtpv_name, strlen(old->dtpv_name) + 1);
	kmem_free(old, sizeof (dtrace_provider_t));

	return (0);
}

/*
 * Invalidate the specified provider.  All subsequent probe lookups for the
 * specified provider will fail, but its probes will not be removed.
 */
void
dtrace_invalidate(dtrace_provider_id_t id)
{
	dtrace_provider_t *pvp = (dtrace_provider_t *)id;

	ASSERT(pvp->dtpv_pops.dtps_enable !=
	    (int (*)(void *, dtrace_id_t, void *))dtrace_enable_nullop);

	lck_mtx_lock(&dtrace_provider_lock);
	lck_mtx_lock(&dtrace_lock);

	pvp->dtpv_defunct = 1;

	lck_mtx_unlock(&dtrace_lock);
	lck_mtx_unlock(&dtrace_provider_lock);
}

/*
 * Indicate whether or not DTrace has attached.
 */
int
dtrace_attached(void)
{
	/*
	 * dtrace_provider will be non-NULL iff the DTrace driver has
	 * attached.  (It's non-NULL because DTrace is always itself a
	 * provider.)
	 */
	return (dtrace_provider != NULL);
}

/*
 * Remove all the unenabled probes for the given provider.  This function is
 * not unlike dtrace_unregister(), except that it doesn't remove the provider
 * -- just as many of its associated probes as it can.
 */
int
dtrace_condense(dtrace_provider_id_t id)
{
	dtrace_provider_t *prov = (dtrace_provider_t *)id;
	int i;
	dtrace_probe_t *probe;

	/*
	 * Make sure this isn't the dtrace provider itself.
	 */
	ASSERT(prov->dtpv_pops.dtps_enable !=
	  (int (*)(void *, dtrace_id_t, void *))dtrace_enable_nullop);

	lck_mtx_lock(&dtrace_provider_lock);
	lck_mtx_lock(&dtrace_lock);

	/*
	 * Attempt to destroy the probes associated with this provider.
	 */
	for (i = 0; i < dtrace_nprobes; i++) {
		if ((probe = dtrace_probes[i]) == NULL)
			continue;

		if (probe->dtpr_provider != prov)
			continue;

		if (probe->dtpr_ecb != NULL)
			continue;

		dtrace_probes[i] = NULL;
		prov->dtpv_probe_count--;

		dtrace_hash_remove(dtrace_bymod, probe);
		dtrace_hash_remove(dtrace_byfunc, probe);
		dtrace_hash_remove(dtrace_byname, probe);

		prov->dtpv_pops.dtps_destroy(prov->dtpv_arg, i + 1,
		    probe->dtpr_arg);
		kmem_free(probe->dtpr_mod, strlen(probe->dtpr_mod) + 1);
		kmem_free(probe->dtpr_func, strlen(probe->dtpr_func) + 1);
		kmem_free(probe->dtpr_name, strlen(probe->dtpr_name) + 1);
		zfree(dtrace_probe_t_zone, probe);
		vmem_free(dtrace_arena, (void *)((uintptr_t)i + 1), 1);
	}

	lck_mtx_unlock(&dtrace_lock);
	lck_mtx_unlock(&dtrace_provider_lock);

	return (0);
}

/*
 * DTrace Probe Management Functions
 *
 * The functions in this section perform the DTrace probe management,
 * including functions to create probes, look-up probes, and call into the
 * providers to request that probes be provided.  Some of these functions are
 * in the Provider-to-Framework API; these functions can be identified by the
 * fact that they are not declared "static".
 */

/*
 * Create a probe with the specified module name, function name, and name.
 */
dtrace_id_t
dtrace_probe_create(dtrace_provider_id_t prov, const char *mod,
    const char *func, const char *name, int aframes, void *arg)
{
	dtrace_probe_t *probe, **probes;
	dtrace_provider_t *provider = (dtrace_provider_t *)prov;
	dtrace_id_t id;

	if (provider == dtrace_provider) {
		lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	} else {
		lck_mtx_lock(&dtrace_lock);
	}

	id = (dtrace_id_t)(uintptr_t)vmem_alloc(dtrace_arena, 1,
	    VM_BESTFIT | VM_SLEEP);

	probe = zalloc(dtrace_probe_t_zone);
	bzero(probe, sizeof (dtrace_probe_t));

	probe->dtpr_id = id;
	probe->dtpr_gen = dtrace_probegen++;
	probe->dtpr_mod = dtrace_strdup(mod);
	probe->dtpr_func = dtrace_strdup(func);
	probe->dtpr_name = dtrace_strdup(name);
	probe->dtpr_arg = arg;
	probe->dtpr_aframes = aframes;
	probe->dtpr_provider = provider;

	dtrace_hash_add(dtrace_bymod, probe);
	dtrace_hash_add(dtrace_byfunc, probe);
	dtrace_hash_add(dtrace_byname, probe);

	if (id - 1 >= (dtrace_id_t)dtrace_nprobes) {
		size_t osize = dtrace_nprobes * sizeof (dtrace_probe_t *);
		size_t nsize = osize << 1;

		if (nsize == 0) {
			ASSERT(osize == 0);
			ASSERT(dtrace_probes == NULL);
			nsize = sizeof (dtrace_probe_t *);
		}

		probes = kmem_zalloc(nsize, KM_SLEEP);

		if (dtrace_probes == NULL) {
			ASSERT(osize == 0);
			dtrace_probes = probes;
			dtrace_nprobes = 1;
		} else {
			dtrace_probe_t **oprobes = dtrace_probes;

			bcopy(oprobes, probes, osize);
			dtrace_membar_producer();
			dtrace_probes = probes;

			dtrace_sync();

			/*
			 * All CPUs are now seeing the new probes array; we can
			 * safely free the old array.
			 */
			kmem_free(oprobes, osize);
			dtrace_nprobes <<= 1;
		}

		ASSERT(id - 1 < (dtrace_id_t)dtrace_nprobes);
	}

	ASSERT(dtrace_probes[id - 1] == NULL);
	dtrace_probes[id - 1] = probe;
	provider->dtpv_probe_count++;	

	if (provider != dtrace_provider)
		lck_mtx_unlock(&dtrace_lock);

	return (id);
}

static dtrace_probe_t *
dtrace_probe_lookup_id(dtrace_id_t id)
{
	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	if (id == 0 || id > (dtrace_id_t)dtrace_nprobes)
		return (NULL);

	return (dtrace_probes[id - 1]);
}

static int
dtrace_probe_lookup_match(dtrace_probe_t *probe, void *arg)
{
	*((dtrace_id_t *)arg) = probe->dtpr_id;

	return (DTRACE_MATCH_DONE);
}

/*
 * Look up a probe based on provider and one or more of module name, function
 * name and probe name.
 */
dtrace_id_t
dtrace_probe_lookup(dtrace_provider_id_t prid, const char *mod,
    const char *func, const char *name)
{
	dtrace_probekey_t pkey;
	dtrace_id_t id;
	int match;

	pkey.dtpk_prov = ((dtrace_provider_t *)prid)->dtpv_name;
	pkey.dtpk_pmatch = &dtrace_match_string;
	pkey.dtpk_mod = mod;
	pkey.dtpk_mmatch = mod ? &dtrace_match_string : &dtrace_match_nul;
	pkey.dtpk_func = func;
	pkey.dtpk_fmatch = func ? &dtrace_match_string : &dtrace_match_nul;
	pkey.dtpk_name = name;
	pkey.dtpk_nmatch = name ? &dtrace_match_string : &dtrace_match_nul;
	pkey.dtpk_id = DTRACE_IDNONE;

	lck_mtx_lock(&dtrace_lock);
	match = dtrace_match(&pkey, DTRACE_PRIV_ALL, 0, 0,
	    dtrace_probe_lookup_match, &id);
	lck_mtx_unlock(&dtrace_lock);

	ASSERT(match == 1 || match == 0);
	return (match ? id : 0);
}

/*
 * Returns the probe argument associated with the specified probe.
 */
void *
dtrace_probe_arg(dtrace_provider_id_t id, dtrace_id_t pid)
{
	dtrace_probe_t *probe;
	void *rval = NULL;

	lck_mtx_lock(&dtrace_lock);

	if ((probe = dtrace_probe_lookup_id(pid)) != NULL &&
	    probe->dtpr_provider == (dtrace_provider_t *)id)
		rval = probe->dtpr_arg;

	lck_mtx_unlock(&dtrace_lock);

	return (rval);
}

/*
 * Copy a probe into a probe description.
 */
static void
dtrace_probe_description(const dtrace_probe_t *prp, dtrace_probedesc_t *pdp)
{
	bzero(pdp, sizeof (dtrace_probedesc_t));
	pdp->dtpd_id = prp->dtpr_id;

	/* APPLE NOTE: Darwin employs size bounded string operation. */
	(void) strlcpy(pdp->dtpd_provider,
	    prp->dtpr_provider->dtpv_name, DTRACE_PROVNAMELEN);

	(void) strlcpy(pdp->dtpd_mod, prp->dtpr_mod, DTRACE_MODNAMELEN);
	(void) strlcpy(pdp->dtpd_func, prp->dtpr_func, DTRACE_FUNCNAMELEN);
	(void) strlcpy(pdp->dtpd_name, prp->dtpr_name, DTRACE_NAMELEN);
}

/*
 * Called to indicate that a probe -- or probes -- should be provided by a
 * specfied provider.  If the specified description is NULL, the provider will
 * be told to provide all of its probes.  (This is done whenever a new
 * consumer comes along, or whenever a retained enabling is to be matched.) If
 * the specified description is non-NULL, the provider is given the
 * opportunity to dynamically provide the specified probe, allowing providers
 * to support the creation of probes on-the-fly.  (So-called _autocreated_
 * probes.)  If the provider is NULL, the operations will be applied to all
 * providers; if the provider is non-NULL the operations will only be applied
 * to the specified provider.  The dtrace_provider_lock must be held, and the
 * dtrace_lock must _not_ be held -- the provider's dtps_provide() operation
 * will need to grab the dtrace_lock when it reenters the framework through
 * dtrace_probe_lookup(), dtrace_probe_create(), etc.
 */
static void
dtrace_probe_provide(dtrace_probedesc_t *desc, dtrace_provider_t *prv)
{
	struct modctl *ctl;
	int all = 0;

	lck_mtx_assert(&dtrace_provider_lock, LCK_MTX_ASSERT_OWNED);

	if (prv == NULL) {
		all = 1;
		prv = dtrace_provider;
	}
		 
	do {
		/*
		 * First, call the blanket provide operation.
		 */
		prv->dtpv_pops.dtps_provide(prv->dtpv_arg, desc);
		
		/*
		 * Now call the per-module provide operation.  We will grab
		 * mod_lock to prevent the list from being modified.  Note
		 * that this also prevents the mod_busy bits from changing.
		 * (mod_busy can only be changed with mod_lock held.)
		 */
		lck_mtx_lock(&mod_lock);
		
		ctl = dtrace_modctl_list;
		while (ctl) {
			prv->dtpv_pops.dtps_provide_module(prv->dtpv_arg, ctl);
			ctl = ctl->mod_next;
		}
		
		lck_mtx_unlock(&mod_lock);
	} while (all && (prv = prv->dtpv_next) != NULL);
}

/*
 * Iterate over each probe, and call the Framework-to-Provider API function
 * denoted by offs.
 */
static void
dtrace_probe_foreach(uintptr_t offs)
{
	dtrace_provider_t *prov;
	void (*func)(void *, dtrace_id_t, void *);
	dtrace_probe_t *probe;
	dtrace_icookie_t cookie;
	int i;

	/*
	 * We disable interrupts to walk through the probe array.  This is
	 * safe -- the dtrace_sync() in dtrace_unregister() assures that we
	 * won't see stale data.
	 */
	cookie = dtrace_interrupt_disable();

	for (i = 0; i < dtrace_nprobes; i++) {
		if ((probe = dtrace_probes[i]) == NULL)
			continue;

		if (probe->dtpr_ecb == NULL) {
			/*
			 * This probe isn't enabled -- don't call the function.
			 */
			continue;
		}

		prov = probe->dtpr_provider;
		func = *((void(**)(void *, dtrace_id_t, void *))
		    ((uintptr_t)&prov->dtpv_pops + offs));

		func(prov->dtpv_arg, i + 1, probe->dtpr_arg);
	}

	dtrace_interrupt_enable(cookie);
}

static int
dtrace_probe_enable(const dtrace_probedesc_t *desc, dtrace_enabling_t *enab)
{
	dtrace_probekey_t pkey;
	uint32_t priv;
	uid_t uid;
	zoneid_t zoneid;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	dtrace_ecb_create_cache = NULL;

	if (desc == NULL) {
		/*
		 * If we're passed a NULL description, we're being asked to
		 * create an ECB with a NULL probe.
		 */
		(void) dtrace_ecb_create_enable(NULL, enab);
		return (0);
	}

	dtrace_probekey(desc, &pkey);
	dtrace_cred2priv(enab->dten_vstate->dtvs_state->dts_cred.dcr_cred,
	    &priv, &uid, &zoneid);

	return (dtrace_match(&pkey, priv, uid, zoneid, dtrace_ecb_create_enable,
	    enab));
}

/*
 * DTrace Helper Provider Functions
 */
static void
dtrace_dofattr2attr(dtrace_attribute_t *attr, const dof_attr_t dofattr)
{
	attr->dtat_name = DOF_ATTR_NAME(dofattr);
	attr->dtat_data = DOF_ATTR_DATA(dofattr);
	attr->dtat_class = DOF_ATTR_CLASS(dofattr);
}

static void
dtrace_dofprov2hprov(dtrace_helper_provdesc_t *hprov,
    const dof_provider_t *dofprov, char *strtab)
{
	hprov->dthpv_provname = strtab + dofprov->dofpv_name;
	dtrace_dofattr2attr(&hprov->dthpv_pattr.dtpa_provider,
	    dofprov->dofpv_provattr);
	dtrace_dofattr2attr(&hprov->dthpv_pattr.dtpa_mod,
	    dofprov->dofpv_modattr);
	dtrace_dofattr2attr(&hprov->dthpv_pattr.dtpa_func,
	    dofprov->dofpv_funcattr);
	dtrace_dofattr2attr(&hprov->dthpv_pattr.dtpa_name,
	    dofprov->dofpv_nameattr);
	dtrace_dofattr2attr(&hprov->dthpv_pattr.dtpa_args,
	    dofprov->dofpv_argsattr);
}

static void
dtrace_helper_provide_one(dof_helper_t *dhp, dof_sec_t *sec, pid_t pid)
{
	uintptr_t daddr = (uintptr_t)dhp->dofhp_dof;
	dof_hdr_t *dof = (dof_hdr_t *)daddr;
	dof_sec_t *str_sec, *prb_sec, *arg_sec, *off_sec, *enoff_sec;
	dof_provider_t *provider;
	dof_probe_t *probe;
	uint32_t *off, *enoff;
	uint8_t *arg;
	char *strtab;
	uint_t i, nprobes;
	dtrace_helper_provdesc_t dhpv;
	dtrace_helper_probedesc_t dhpb;
	dtrace_meta_t *meta = dtrace_meta_pid;
	dtrace_mops_t *mops = &meta->dtm_mops;
	void *parg;

	provider = (dof_provider_t *)(uintptr_t)(daddr + sec->dofs_offset);
	str_sec = (dof_sec_t *)(uintptr_t)(daddr + dof->dofh_secoff +
	    provider->dofpv_strtab * dof->dofh_secsize);
	prb_sec = (dof_sec_t *)(uintptr_t)(daddr + dof->dofh_secoff +
	    provider->dofpv_probes * dof->dofh_secsize);
	arg_sec = (dof_sec_t *)(uintptr_t)(daddr + dof->dofh_secoff +
	    provider->dofpv_prargs * dof->dofh_secsize);
	off_sec = (dof_sec_t *)(uintptr_t)(daddr + dof->dofh_secoff +
	    provider->dofpv_proffs * dof->dofh_secsize);

	strtab = (char *)(uintptr_t)(daddr + str_sec->dofs_offset);
	off = (uint32_t *)(uintptr_t)(daddr + off_sec->dofs_offset);
	arg = (uint8_t *)(uintptr_t)(daddr + arg_sec->dofs_offset);
	enoff = NULL;

	/*
	 * See dtrace_helper_provider_validate().
	 */
	if (dof->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_1 &&
	    provider->dofpv_prenoffs != DOF_SECT_NONE) {
		enoff_sec = (dof_sec_t *)(uintptr_t)(daddr + dof->dofh_secoff +
		    provider->dofpv_prenoffs * dof->dofh_secsize);
		enoff = (uint32_t *)(uintptr_t)(daddr + enoff_sec->dofs_offset);
	}

	nprobes = prb_sec->dofs_size / prb_sec->dofs_entsize;

	/*
	 * Create the provider.
	 */
	dtrace_dofprov2hprov(&dhpv, provider, strtab);

	if ((parg = mops->dtms_provide_pid(meta->dtm_arg, &dhpv, pid)) == NULL)
		return;

	meta->dtm_count++;

	/*
	 * Create the probes.
	 */
	for (i = 0; i < nprobes; i++) {
		probe = (dof_probe_t *)(uintptr_t)(daddr +
		    prb_sec->dofs_offset + i * prb_sec->dofs_entsize);

		dhpb.dthpb_mod = dhp->dofhp_mod;
		dhpb.dthpb_func = strtab + probe->dofpr_func;
		dhpb.dthpb_name = strtab + probe->dofpr_name;
#if !defined(__APPLE__)
		dhpb.dthpb_base = probe->dofpr_addr;
#else
		dhpb.dthpb_base = dhp->dofhp_addr; /* FIXME: James, why? */
#endif
		dhpb.dthpb_offs = (int32_t *)(off + probe->dofpr_offidx);
		dhpb.dthpb_noffs = probe->dofpr_noffs;
		if (enoff != NULL) {
			dhpb.dthpb_enoffs = (int32_t *)(enoff + probe->dofpr_enoffidx);
			dhpb.dthpb_nenoffs = probe->dofpr_nenoffs;
		} else {
			dhpb.dthpb_enoffs = NULL;
			dhpb.dthpb_nenoffs = 0;
		}
		dhpb.dthpb_args = arg + probe->dofpr_argidx;
		dhpb.dthpb_nargc = probe->dofpr_nargc;
		dhpb.dthpb_xargc = probe->dofpr_xargc;
		dhpb.dthpb_ntypes = strtab + probe->dofpr_nargv;
		dhpb.dthpb_xtypes = strtab + probe->dofpr_xargv;

		mops->dtms_create_probe(meta->dtm_arg, parg, &dhpb);
	}

	/*
	 * Since we just created probes, we need to match our enablings
	 * against those, with a precondition knowing that we have only
	 * added probes from this provider
	 */
	char *prov_name = mops->dtms_provider_name(parg);
	ASSERT(prov_name != NULL);
	dtrace_match_cond_t cond = {dtrace_cond_provider_match, (void*)prov_name};

	dtrace_enabling_matchall_with_cond(&cond);
}

static void
dtrace_helper_provide(dof_helper_t *dhp, pid_t pid)
{
	uintptr_t daddr = (uintptr_t)dhp->dofhp_dof;
	dof_hdr_t *dof = (dof_hdr_t *)daddr;
	uint32_t i;

	lck_mtx_assert(&dtrace_meta_lock, LCK_MTX_ASSERT_OWNED);

	for (i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = (dof_sec_t *)(uintptr_t)(daddr +
		    dof->dofh_secoff + i * dof->dofh_secsize);

		if (sec->dofs_type != DOF_SECT_PROVIDER)
			continue;

		dtrace_helper_provide_one(dhp, sec, pid);
	}
}

static void
dtrace_helper_provider_remove_one(dof_helper_t *dhp, dof_sec_t *sec, pid_t pid)
{
	uintptr_t daddr = (uintptr_t)dhp->dofhp_dof;
	dof_hdr_t *dof = (dof_hdr_t *)daddr;
	dof_sec_t *str_sec;
	dof_provider_t *provider;
	char *strtab;
	dtrace_helper_provdesc_t dhpv;
	dtrace_meta_t *meta = dtrace_meta_pid;
	dtrace_mops_t *mops = &meta->dtm_mops;

	provider = (dof_provider_t *)(uintptr_t)(daddr + sec->dofs_offset);
	str_sec = (dof_sec_t *)(uintptr_t)(daddr + dof->dofh_secoff +
	    provider->dofpv_strtab * dof->dofh_secsize);

	strtab = (char *)(uintptr_t)(daddr + str_sec->dofs_offset);

	/*
	 * Create the provider.
	 */
	dtrace_dofprov2hprov(&dhpv, provider, strtab);

	mops->dtms_remove_pid(meta->dtm_arg, &dhpv, pid);

	meta->dtm_count--;
}

static void
dtrace_helper_provider_remove(dof_helper_t *dhp, pid_t pid)
{
	uintptr_t daddr = (uintptr_t)dhp->dofhp_dof;
	dof_hdr_t *dof = (dof_hdr_t *)daddr;
	uint32_t i;

	lck_mtx_assert(&dtrace_meta_lock, LCK_MTX_ASSERT_OWNED);

	for (i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = (dof_sec_t *)(uintptr_t)(daddr +
		    dof->dofh_secoff + i * dof->dofh_secsize);

		if (sec->dofs_type != DOF_SECT_PROVIDER)
			continue;

		dtrace_helper_provider_remove_one(dhp, sec, pid);
	}
}

/*
 * DTrace Meta Provider-to-Framework API Functions
 *
 * These functions implement the Meta Provider-to-Framework API, as described
 * in <sys/dtrace.h>.
 */
int
dtrace_meta_register(const char *name, const dtrace_mops_t *mops, void *arg,
    dtrace_meta_provider_id_t *idp)
{
	dtrace_meta_t *meta;
	dtrace_helpers_t *help, *next;
	uint_t i;

	*idp = DTRACE_METAPROVNONE;

	/*
	 * We strictly don't need the name, but we hold onto it for
	 * debuggability. All hail error queues!
	 */
	if (name == NULL) {
		cmn_err(CE_WARN, "failed to register meta-provider: "
		    "invalid name");
		return (EINVAL);
	}

	if (mops == NULL ||
	    mops->dtms_create_probe == NULL ||
	    mops->dtms_provide_pid == NULL ||
	    mops->dtms_remove_pid == NULL) {
		cmn_err(CE_WARN, "failed to register meta-register %s: "
		    "invalid ops", name);
		return (EINVAL);
	}

	meta = kmem_zalloc(sizeof (dtrace_meta_t), KM_SLEEP);
	meta->dtm_mops = *mops;

	/* APPLE NOTE: Darwin employs size bounded string operation. */
	{
	size_t bufsize = strlen(name) + 1;
	meta->dtm_name = kmem_alloc(bufsize, KM_SLEEP);
	(void) strlcpy(meta->dtm_name, name, bufsize);
	}

	meta->dtm_arg = arg;

	lck_mtx_lock(&dtrace_meta_lock);
	lck_mtx_lock(&dtrace_lock);

	if (dtrace_meta_pid != NULL) {
		lck_mtx_unlock(&dtrace_lock);
		lck_mtx_unlock(&dtrace_meta_lock);
		cmn_err(CE_WARN, "failed to register meta-register %s: "
		    "user-land meta-provider exists", name);
		kmem_free(meta->dtm_name, strlen(meta->dtm_name) + 1);
		kmem_free(meta, sizeof (dtrace_meta_t));
		return (EINVAL);
	}

	dtrace_meta_pid = meta;
	*idp = (dtrace_meta_provider_id_t)meta;

	/*
	 * If there are providers and probes ready to go, pass them
	 * off to the new meta provider now.
	 */

	help = dtrace_deferred_pid;
	dtrace_deferred_pid = NULL;

	lck_mtx_unlock(&dtrace_lock);

	while (help != NULL) {
		for (i = 0; i < help->dthps_nprovs; i++) {
			dtrace_helper_provide(&help->dthps_provs[i]->dthp_prov,
			    help->dthps_pid);
		}

		next = help->dthps_next;
		help->dthps_next = NULL;
		help->dthps_prev = NULL;
		help->dthps_deferred = 0;
		help = next;
	}

	lck_mtx_unlock(&dtrace_meta_lock);

	return (0);
}

int
dtrace_meta_unregister(dtrace_meta_provider_id_t id)
{
	dtrace_meta_t **pp, *old = (dtrace_meta_t *)id;

	lck_mtx_lock(&dtrace_meta_lock);
	lck_mtx_lock(&dtrace_lock);

	if (old == dtrace_meta_pid) {
		pp = &dtrace_meta_pid;
	} else {
		panic("attempt to unregister non-existent "
		    "dtrace meta-provider %p\n", (void *)old);
	}

	if (old->dtm_count != 0) {
		lck_mtx_unlock(&dtrace_lock);
		lck_mtx_unlock(&dtrace_meta_lock);
		return (EBUSY);
	}

	*pp = NULL;

	lck_mtx_unlock(&dtrace_lock);
	lck_mtx_unlock(&dtrace_meta_lock);

	kmem_free(old->dtm_name, strlen(old->dtm_name) + 1);
	kmem_free(old, sizeof (dtrace_meta_t));

	return (0);
}


/*
 * DTrace DIF Object Functions
 */
static int
dtrace_difo_err(uint_t pc, const char *format, ...)
{
	if (dtrace_err_verbose) {
		va_list alist;

		(void) uprintf("dtrace DIF object error: [%u]: ", pc);
		va_start(alist, format);
		(void) vuprintf(format, alist);
		va_end(alist);
	}

#ifdef DTRACE_ERRDEBUG
	dtrace_errdebug(format);
#endif
	return (1);
}

/*
 * Validate a DTrace DIF object by checking the IR instructions.  The following
 * rules are currently enforced by dtrace_difo_validate():
 *
 * 1. Each instruction must have a valid opcode
 * 2. Each register, string, variable, or subroutine reference must be valid
 * 3. No instruction can modify register %r0 (must be zero)
 * 4. All instruction reserved bits must be set to zero
 * 5. The last instruction must be a "ret" instruction
 * 6. All branch targets must reference a valid instruction _after_ the branch
 */
static int
dtrace_difo_validate(dtrace_difo_t *dp, dtrace_vstate_t *vstate, uint_t nregs,
    cred_t *cr)
{
	int err = 0;
	uint_t i;

	int (*efunc)(uint_t pc, const char *, ...) = dtrace_difo_err;
	int kcheckload;
	uint_t pc;
	int maxglobal = -1, maxlocal = -1, maxtlocal = -1;

	kcheckload = cr == NULL ||
	    (vstate->dtvs_state->dts_cred.dcr_visible & DTRACE_CRV_KERNEL) == 0;

	dp->dtdo_destructive = 0;

	for (pc = 0; pc < dp->dtdo_len && err == 0; pc++) {
		dif_instr_t instr = dp->dtdo_buf[pc];

		uint_t r1 = DIF_INSTR_R1(instr);
		uint_t r2 = DIF_INSTR_R2(instr);
		uint_t rd = DIF_INSTR_RD(instr);
		uint_t rs = DIF_INSTR_RS(instr);
		uint_t label = DIF_INSTR_LABEL(instr);
		uint_t v = DIF_INSTR_VAR(instr);
		uint_t subr = DIF_INSTR_SUBR(instr);
		uint_t type = DIF_INSTR_TYPE(instr);
		uint_t op = DIF_INSTR_OP(instr);

		switch (op) {
		case DIF_OP_OR:
		case DIF_OP_XOR:
		case DIF_OP_AND:
		case DIF_OP_SLL:
		case DIF_OP_SRL:
		case DIF_OP_SRA:
		case DIF_OP_SUB:
		case DIF_OP_ADD:
		case DIF_OP_MUL:
		case DIF_OP_SDIV:
		case DIF_OP_UDIV:
		case DIF_OP_SREM:
		case DIF_OP_UREM:
		case DIF_OP_COPYS:
			if (r1 >= nregs)
				err += efunc(pc, "invalid register %u\n", r1);
			if (r2 >= nregs)
				err += efunc(pc, "invalid register %u\n", r2);
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			break;
		case DIF_OP_NOT:
		case DIF_OP_MOV:
		case DIF_OP_ALLOCS:
			if (r1 >= nregs)
				err += efunc(pc, "invalid register %u\n", r1);
			if (r2 != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			break;
		case DIF_OP_LDSB:
		case DIF_OP_LDSH:
		case DIF_OP_LDSW:
		case DIF_OP_LDUB:
		case DIF_OP_LDUH:
		case DIF_OP_LDUW:
		case DIF_OP_LDX:
			if (r1 >= nregs)
				err += efunc(pc, "invalid register %u\n", r1);
			if (r2 != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			if (kcheckload)
				dp->dtdo_buf[pc] = DIF_INSTR_LOAD(op +
				    DIF_OP_RLDSB - DIF_OP_LDSB, r1, rd);
			break;
		case DIF_OP_RLDSB:
		case DIF_OP_RLDSH:
		case DIF_OP_RLDSW:
		case DIF_OP_RLDUB:
		case DIF_OP_RLDUH:
		case DIF_OP_RLDUW:
		case DIF_OP_RLDX:
			if (r1 >= nregs)
				err += efunc(pc, "invalid register %u\n", r1);
			if (r2 != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			break;
		case DIF_OP_ULDSB:
		case DIF_OP_ULDSH:
		case DIF_OP_ULDSW:
		case DIF_OP_ULDUB:
		case DIF_OP_ULDUH:
		case DIF_OP_ULDUW:
		case DIF_OP_ULDX:
			if (r1 >= nregs)
				err += efunc(pc, "invalid register %u\n", r1);
			if (r2 != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			break;
		case DIF_OP_STB:
		case DIF_OP_STH:
		case DIF_OP_STW:
		case DIF_OP_STX:
			if (r1 >= nregs)
				err += efunc(pc, "invalid register %u\n", r1);
			if (r2 != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to 0 address\n");
			break;
		case DIF_OP_CMP:
		case DIF_OP_SCMP:
			if (r1 >= nregs)
				err += efunc(pc, "invalid register %u\n", r1);
			if (r2 >= nregs)
				err += efunc(pc, "invalid register %u\n", r2);
			if (rd != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			break;
		case DIF_OP_TST:
			if (r1 >= nregs)
				err += efunc(pc, "invalid register %u\n", r1);
			if (r2 != 0 || rd != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			break;
		case DIF_OP_BA:
		case DIF_OP_BE:
		case DIF_OP_BNE:
		case DIF_OP_BG:
		case DIF_OP_BGU:
		case DIF_OP_BGE:
		case DIF_OP_BGEU:
		case DIF_OP_BL:
		case DIF_OP_BLU:
		case DIF_OP_BLE:
		case DIF_OP_BLEU:
			if (label >= dp->dtdo_len) {
				err += efunc(pc, "invalid branch target %u\n",
				    label);
			}
			if (label <= pc) {
				err += efunc(pc, "backward branch to %u\n",
				    label);
			}
			break;
		case DIF_OP_RET:
			if (r1 != 0 || r2 != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			break;
		case DIF_OP_NOP:
		case DIF_OP_POPTS:
		case DIF_OP_FLUSHTS:
			if (r1 != 0 || r2 != 0 || rd != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			break;
		case DIF_OP_SETX:
			if (DIF_INSTR_INTEGER(instr) >= dp->dtdo_intlen) {
				err += efunc(pc, "invalid integer ref %u\n",
				    DIF_INSTR_INTEGER(instr));
			}
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			break;
		case DIF_OP_SETS:
			if (DIF_INSTR_STRING(instr) >= dp->dtdo_strlen) {
				err += efunc(pc, "invalid string ref %u\n",
				    DIF_INSTR_STRING(instr));
			}
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			break;
		case DIF_OP_LDGA:
		case DIF_OP_LDTA:
			if (r1 > DIF_VAR_ARRAY_MAX)
				err += efunc(pc, "invalid array %u\n", r1);
			if (r2 >= nregs)
				err += efunc(pc, "invalid register %u\n", r2);
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			break;
		case DIF_OP_LDGS:
		case DIF_OP_LDTS:
		case DIF_OP_LDLS:
		case DIF_OP_LDGAA:
		case DIF_OP_LDTAA:
			if (v < DIF_VAR_OTHER_MIN || v > DIF_VAR_OTHER_MAX)
				err += efunc(pc, "invalid variable %u\n", v);
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			break;
		case DIF_OP_STGS:
		case DIF_OP_STTS:
		case DIF_OP_STLS:
		case DIF_OP_STGAA:
		case DIF_OP_STTAA:
			if (v < DIF_VAR_OTHER_UBASE || v > DIF_VAR_OTHER_MAX)
				err += efunc(pc, "invalid variable %u\n", v);
			if (rs >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			break;
		case DIF_OP_CALL:
			if (subr > DIF_SUBR_MAX &&
			   !(subr >= DIF_SUBR_APPLE_MIN && subr <= DIF_SUBR_APPLE_MAX))
				err += efunc(pc, "invalid subr %u\n", subr);
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");

			if (subr == DIF_SUBR_COPYOUT ||
			    subr == DIF_SUBR_COPYOUTSTR ||
			    subr == DIF_SUBR_KDEBUG_TRACE ||
			    subr == DIF_SUBR_KDEBUG_TRACE_STRING) {
				dp->dtdo_destructive = 1;
			}
			break;
		case DIF_OP_PUSHTR:
			if (type != DIF_TYPE_STRING && type != DIF_TYPE_CTF)
				err += efunc(pc, "invalid ref type %u\n", type);
			if (r2 >= nregs)
				err += efunc(pc, "invalid register %u\n", r2);
			if (rs >= nregs)
				err += efunc(pc, "invalid register %u\n", rs);
			break;
		case DIF_OP_PUSHTV:
			if (type != DIF_TYPE_CTF)
				err += efunc(pc, "invalid val type %u\n", type);
			if (r2 >= nregs)
				err += efunc(pc, "invalid register %u\n", r2);
			if (rs >= nregs)
				err += efunc(pc, "invalid register %u\n", rs);
			break;
		default:
			err += efunc(pc, "invalid opcode %u\n",
			    DIF_INSTR_OP(instr));
		}
	}

	if (dp->dtdo_len != 0 &&
	    DIF_INSTR_OP(dp->dtdo_buf[dp->dtdo_len - 1]) != DIF_OP_RET) {
		err += efunc(dp->dtdo_len - 1,
		    "expected 'ret' as last DIF instruction\n");
	}

	if (!(dp->dtdo_rtype.dtdt_flags & (DIF_TF_BYREF | DIF_TF_BYUREF))) {
		/*
		 * If we're not returning by reference, the size must be either
		 * 0 or the size of one of the base types.
		 */
		switch (dp->dtdo_rtype.dtdt_size) {
		case 0:
		case sizeof (uint8_t):
		case sizeof (uint16_t):
		case sizeof (uint32_t):
		case sizeof (uint64_t):
			break;

		default:
			err += efunc(dp->dtdo_len - 1, "bad return size\n");
		}
	}

	for (i = 0; i < dp->dtdo_varlen && err == 0; i++) {
		dtrace_difv_t *v = &dp->dtdo_vartab[i], *existing = NULL;
		dtrace_diftype_t *vt, *et;
		uint_t id;
		int ndx;

		if (v->dtdv_scope != DIFV_SCOPE_GLOBAL &&
		    v->dtdv_scope != DIFV_SCOPE_THREAD &&
		    v->dtdv_scope != DIFV_SCOPE_LOCAL) {
			err += efunc(i, "unrecognized variable scope %d\n",
			    v->dtdv_scope);
			break;
		}

		if (v->dtdv_kind != DIFV_KIND_ARRAY &&
		    v->dtdv_kind != DIFV_KIND_SCALAR) {
			err += efunc(i, "unrecognized variable type %d\n",
			    v->dtdv_kind);
			break;
		}

		if ((id = v->dtdv_id) > DIF_VARIABLE_MAX) {
			err += efunc(i, "%d exceeds variable id limit\n", id);
			break;
		}

		if (id < DIF_VAR_OTHER_UBASE)
			continue;

		/*
		 * For user-defined variables, we need to check that this
		 * definition is identical to any previous definition that we
		 * encountered.
		 */
		ndx = id - DIF_VAR_OTHER_UBASE;

		switch (v->dtdv_scope) {
		case DIFV_SCOPE_GLOBAL:
			if (maxglobal == -1 || ndx > maxglobal)
				maxglobal = ndx;

			if (ndx < vstate->dtvs_nglobals) {
				dtrace_statvar_t *svar;

				if ((svar = vstate->dtvs_globals[ndx]) != NULL)
					existing = &svar->dtsv_var;
			}

			break;

		case DIFV_SCOPE_THREAD:
			if (maxtlocal == -1 || ndx > maxtlocal)
				maxtlocal = ndx;

			if (ndx < vstate->dtvs_ntlocals)
				existing = &vstate->dtvs_tlocals[ndx];
			break;

		case DIFV_SCOPE_LOCAL:
			if (maxlocal == -1 || ndx > maxlocal)
				maxlocal = ndx;
			if (ndx < vstate->dtvs_nlocals) {
				dtrace_statvar_t *svar;

				if ((svar = vstate->dtvs_locals[ndx]) != NULL)
					existing = &svar->dtsv_var;
			}

			break;
		}

		vt = &v->dtdv_type;

		if (vt->dtdt_flags & DIF_TF_BYREF) {
			if (vt->dtdt_size == 0) {
				err += efunc(i, "zero-sized variable\n");
				break;
			}

			if ((v->dtdv_scope == DIFV_SCOPE_GLOBAL ||
			    v->dtdv_scope == DIFV_SCOPE_LOCAL) &&
			    vt->dtdt_size > dtrace_statvar_maxsize) {
				err += efunc(i, "oversized by-ref static\n");
				break;
			}
		}

		if (existing == NULL || existing->dtdv_id == 0)
			continue;

		ASSERT(existing->dtdv_id == v->dtdv_id);
		ASSERT(existing->dtdv_scope == v->dtdv_scope);

		if (existing->dtdv_kind != v->dtdv_kind)
			err += efunc(i, "%d changed variable kind\n", id);

		et = &existing->dtdv_type;

		if (vt->dtdt_flags != et->dtdt_flags) {
			err += efunc(i, "%d changed variable type flags\n", id);
			break;
		}

		if (vt->dtdt_size != 0 && vt->dtdt_size != et->dtdt_size) {
			err += efunc(i, "%d changed variable type size\n", id);
			break;
		}
	}

	for (pc = 0; pc < dp->dtdo_len && err == 0; pc++) {
		dif_instr_t instr = dp->dtdo_buf[pc];

		uint_t v = DIF_INSTR_VAR(instr);
		uint_t op = DIF_INSTR_OP(instr);

		switch (op) {
		case DIF_OP_LDGS:
		case DIF_OP_LDGAA:
		case DIF_OP_STGS:
		case DIF_OP_STGAA:
			if (v > (uint_t)(DIF_VAR_OTHER_UBASE + maxglobal))
				err += efunc(pc, "invalid variable %u\n", v);
			break;
		case DIF_OP_LDTS:
		case DIF_OP_LDTAA:
		case DIF_OP_STTS:
		case DIF_OP_STTAA:
			if (v > (uint_t)(DIF_VAR_OTHER_UBASE + maxtlocal))
				err += efunc(pc, "invalid variable %u\n", v);
			break;
		case DIF_OP_LDLS:
		case DIF_OP_STLS:
			if (v > (uint_t)(DIF_VAR_OTHER_UBASE + maxlocal))
				err += efunc(pc, "invalid variable %u\n", v);
			break;
		default:
			break;
		}
	}

	return (err);
}

/*
 * Validate a DTrace DIF object that it is to be used as a helper.  Helpers
 * are much more constrained than normal DIFOs.  Specifically, they may
 * not:
 *
 * 1. Make calls to subroutines other than copyin(), copyinstr() or
 *    miscellaneous string routines
 * 2. Access DTrace variables other than the args[] array, and the
 *    curthread, pid, ppid, tid, execname, zonename, uid and gid variables.
 * 3. Have thread-local variables.
 * 4. Have dynamic variables.
 */
static int
dtrace_difo_validate_helper(dtrace_difo_t *dp)
{
	int (*efunc)(uint_t pc, const char *, ...) = dtrace_difo_err;
	int err = 0;
	uint_t pc;

	for (pc = 0; pc < dp->dtdo_len; pc++) {
		dif_instr_t instr = dp->dtdo_buf[pc];

		uint_t v = DIF_INSTR_VAR(instr);
		uint_t subr = DIF_INSTR_SUBR(instr);
		uint_t op = DIF_INSTR_OP(instr);

		switch (op) {
		case DIF_OP_OR:
		case DIF_OP_XOR:
		case DIF_OP_AND:
		case DIF_OP_SLL:
		case DIF_OP_SRL:
		case DIF_OP_SRA:
		case DIF_OP_SUB:
		case DIF_OP_ADD:
		case DIF_OP_MUL:
		case DIF_OP_SDIV:
		case DIF_OP_UDIV:
		case DIF_OP_SREM:
		case DIF_OP_UREM:
		case DIF_OP_COPYS:
		case DIF_OP_NOT:
		case DIF_OP_MOV:
		case DIF_OP_RLDSB:
		case DIF_OP_RLDSH:
		case DIF_OP_RLDSW:
		case DIF_OP_RLDUB:
		case DIF_OP_RLDUH:
		case DIF_OP_RLDUW:
		case DIF_OP_RLDX:
		case DIF_OP_ULDSB:
		case DIF_OP_ULDSH:
		case DIF_OP_ULDSW:
		case DIF_OP_ULDUB:
		case DIF_OP_ULDUH:
		case DIF_OP_ULDUW:
		case DIF_OP_ULDX:
		case DIF_OP_STB:
		case DIF_OP_STH:
		case DIF_OP_STW:
		case DIF_OP_STX:
		case DIF_OP_ALLOCS:
		case DIF_OP_CMP:
		case DIF_OP_SCMP:
		case DIF_OP_TST:
		case DIF_OP_BA:
		case DIF_OP_BE:
		case DIF_OP_BNE:
		case DIF_OP_BG:
		case DIF_OP_BGU:
		case DIF_OP_BGE:
		case DIF_OP_BGEU:
		case DIF_OP_BL:
		case DIF_OP_BLU:
		case DIF_OP_BLE:
		case DIF_OP_BLEU:
		case DIF_OP_RET:
		case DIF_OP_NOP:
		case DIF_OP_POPTS:
		case DIF_OP_FLUSHTS:
		case DIF_OP_SETX:
		case DIF_OP_SETS:
		case DIF_OP_LDGA:
		case DIF_OP_LDLS:
		case DIF_OP_STGS:
		case DIF_OP_STLS:
		case DIF_OP_PUSHTR:
		case DIF_OP_PUSHTV:
			break;

		case DIF_OP_LDGS:
			if (v >= DIF_VAR_OTHER_UBASE)
				break;

			if (v >= DIF_VAR_ARG0 && v <= DIF_VAR_ARG9)
				break;

			if (v == DIF_VAR_CURTHREAD || v == DIF_VAR_PID ||
			    v == DIF_VAR_PPID || v == DIF_VAR_TID ||
			    v == DIF_VAR_EXECNAME || v == DIF_VAR_ZONENAME ||
			    v == DIF_VAR_UID || v == DIF_VAR_GID)
				break;

			err += efunc(pc, "illegal variable %u\n", v);
			break;

		case DIF_OP_LDTA:
		case DIF_OP_LDTS:
		case DIF_OP_LDGAA:
		case DIF_OP_LDTAA:
			err += efunc(pc, "illegal dynamic variable load\n");
			break;

		case DIF_OP_STTS:
		case DIF_OP_STGAA:
		case DIF_OP_STTAA:
			err += efunc(pc, "illegal dynamic variable store\n");
			break;

		case DIF_OP_CALL:
			if (subr == DIF_SUBR_ALLOCA ||
			    subr == DIF_SUBR_BCOPY ||
			    subr == DIF_SUBR_COPYIN ||
			    subr == DIF_SUBR_COPYINTO ||
			    subr == DIF_SUBR_COPYINSTR ||
			    subr == DIF_SUBR_INDEX ||
			    subr == DIF_SUBR_INET_NTOA ||
			    subr == DIF_SUBR_INET_NTOA6 ||
			    subr == DIF_SUBR_INET_NTOP ||
			    subr == DIF_SUBR_LLTOSTR ||
			    subr == DIF_SUBR_RINDEX ||
			    subr == DIF_SUBR_STRCHR ||
			    subr == DIF_SUBR_STRJOIN ||
			    subr == DIF_SUBR_STRRCHR ||
			    subr == DIF_SUBR_STRSTR ||
			    subr == DIF_SUBR_KDEBUG_TRACE ||
			    subr == DIF_SUBR_KDEBUG_TRACE_STRING ||
			    subr == DIF_SUBR_HTONS ||
			    subr == DIF_SUBR_HTONL ||
			    subr == DIF_SUBR_HTONLL ||
			    subr == DIF_SUBR_NTOHS ||
			    subr == DIF_SUBR_NTOHL ||
			    subr == DIF_SUBR_NTOHLL)
				break;

			err += efunc(pc, "invalid subr %u\n", subr);
			break;

		default:
			err += efunc(pc, "invalid opcode %u\n",
			    DIF_INSTR_OP(instr));
		}
	}

	return (err);
}

/*
 * Returns 1 if the expression in the DIF object can be cached on a per-thread
 * basis; 0 if not.
 */
static int
dtrace_difo_cacheable(dtrace_difo_t *dp)
{
	uint_t i;

	if (dp == NULL)
		return (0);

	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t *v = &dp->dtdo_vartab[i];

		if (v->dtdv_scope != DIFV_SCOPE_GLOBAL)
			continue;

		switch (v->dtdv_id) {
		case DIF_VAR_CURTHREAD:
		case DIF_VAR_PID:
		case DIF_VAR_TID:
		case DIF_VAR_EXECNAME:
		case DIF_VAR_ZONENAME:
			break;

		default:
			return (0);
		}
	}

	/*
	 * This DIF object may be cacheable.  Now we need to look for any
	 * array loading instructions, any memory loading instructions, or
	 * any stores to thread-local variables.
	 */
	for (i = 0; i < dp->dtdo_len; i++) {
		uint_t op = DIF_INSTR_OP(dp->dtdo_buf[i]);

		if ((op >= DIF_OP_LDSB && op <= DIF_OP_LDX) ||
		    (op >= DIF_OP_ULDSB && op <= DIF_OP_ULDX) ||
		    (op >= DIF_OP_RLDSB && op <= DIF_OP_RLDX) ||
		    op == DIF_OP_LDGA || op == DIF_OP_STTS)
			return (0);
	}

	return (1);
}

static void
dtrace_difo_hold(dtrace_difo_t *dp)
{
	uint_t i;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	dp->dtdo_refcnt++;
	ASSERT(dp->dtdo_refcnt != 0);

	/*
	 * We need to check this DIF object for references to the variable
	 * DIF_VAR_VTIMESTAMP.
	 */
	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t *v = &dp->dtdo_vartab[i];

		if (v->dtdv_id != DIF_VAR_VTIMESTAMP)
			continue;

		if (dtrace_vtime_references++ == 0)
			dtrace_vtime_enable();
	}
}

/*
 * This routine calculates the dynamic variable chunksize for a given DIF
 * object.  The calculation is not fool-proof, and can probably be tricked by
 * malicious DIF -- but it works for all compiler-generated DIF.  Because this
 * calculation is likely imperfect, dtrace_dynvar() is able to gracefully fail
 * if a dynamic variable size exceeds the chunksize.
 */
static void
dtrace_difo_chunksize(dtrace_difo_t *dp, dtrace_vstate_t *vstate)
{
	uint64_t sval = 0;
	dtrace_key_t tupregs[DIF_DTR_NREGS + 2]; /* +2 for thread and id */
	const dif_instr_t *text = dp->dtdo_buf;
	uint_t pc, srd = 0;
	uint_t ttop = 0;
	size_t size, ksize;
	uint_t id, i;

	for (pc = 0; pc < dp->dtdo_len; pc++) {
		dif_instr_t instr = text[pc];
		uint_t op = DIF_INSTR_OP(instr);
		uint_t rd = DIF_INSTR_RD(instr);
		uint_t r1 = DIF_INSTR_R1(instr);
		uint_t nkeys = 0;
		uchar_t scope;

		dtrace_key_t *key = tupregs;

		switch (op) {
		case DIF_OP_SETX:
			sval = dp->dtdo_inttab[DIF_INSTR_INTEGER(instr)];
			srd = rd;
			continue;

		case DIF_OP_STTS:
			key = &tupregs[DIF_DTR_NREGS];
			key[0].dttk_size = 0;
			key[1].dttk_size = 0;
			nkeys = 2;
			scope = DIFV_SCOPE_THREAD;
			break;

		case DIF_OP_STGAA:
		case DIF_OP_STTAA:
			nkeys = ttop;

			if (DIF_INSTR_OP(instr) == DIF_OP_STTAA)
				key[nkeys++].dttk_size = 0;

			key[nkeys++].dttk_size = 0;

			if (op == DIF_OP_STTAA) {
				scope = DIFV_SCOPE_THREAD;
			} else {
				scope = DIFV_SCOPE_GLOBAL;
			}

			break;

		case DIF_OP_PUSHTR:
			if (ttop == DIF_DTR_NREGS)
				return;

			if ((srd == 0 || sval == 0) && r1 == DIF_TYPE_STRING) {
				/*
				 * If the register for the size of the "pushtr"
				 * is %r0 (or the value is 0) and the type is
				 * a string, we'll use the system-wide default
				 * string size.
				 */
				tupregs[ttop++].dttk_size =
				    dtrace_strsize_default;
			} else {
				if (srd == 0)
					return;

				if (sval > LONG_MAX)
					return;

				tupregs[ttop++].dttk_size = sval;
			}

			break;

		case DIF_OP_PUSHTV:
			if (ttop == DIF_DTR_NREGS)
				return;

			tupregs[ttop++].dttk_size = 0;
			break;

		case DIF_OP_FLUSHTS:
			ttop = 0;
			break;

		case DIF_OP_POPTS:
			if (ttop != 0)
				ttop--;
			break;
		}

		sval = 0;
		srd = 0;

		if (nkeys == 0)
			continue;

		/*
		 * We have a dynamic variable allocation; calculate its size.
		 */
		for (ksize = 0, i = 0; i < nkeys; i++)
			ksize += P2ROUNDUP(key[i].dttk_size, sizeof (uint64_t));

		size = sizeof (dtrace_dynvar_t);
		size += sizeof (dtrace_key_t) * (nkeys - 1);
		size += ksize;

		/*
		 * Now we need to determine the size of the stored data.
		 */
		id = DIF_INSTR_VAR(instr);

		for (i = 0; i < dp->dtdo_varlen; i++) {
			dtrace_difv_t *v = &dp->dtdo_vartab[i];

			if (v->dtdv_id == id && v->dtdv_scope == scope) {
				size += v->dtdv_type.dtdt_size;
				break;
			}
		}

		if (i == dp->dtdo_varlen)
			return;

		/*
		 * We have the size.  If this is larger than the chunk size
		 * for our dynamic variable state, reset the chunk size.
		 */
		size = P2ROUNDUP(size, sizeof (uint64_t));

		/*
		 * Before setting the chunk size, check that we're not going
		 * to set it to a negative value...
		 */
		if (size > LONG_MAX)
			return;

		/*
		 * ...and make certain that we didn't badly overflow.
		 */
		if (size < ksize || size < sizeof (dtrace_dynvar_t))
			return;

		if (size > vstate->dtvs_dynvars.dtds_chunksize)
			vstate->dtvs_dynvars.dtds_chunksize = size;
	}
}

static void
dtrace_difo_init(dtrace_difo_t *dp, dtrace_vstate_t *vstate)
{
	int oldsvars, osz, nsz, otlocals, ntlocals;
	uint_t i, id;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(dp->dtdo_buf != NULL && dp->dtdo_len != 0);

	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t *v = &dp->dtdo_vartab[i];
		dtrace_statvar_t *svar;
		dtrace_statvar_t ***svarp = NULL;
		size_t dsize = 0;
		uint8_t scope = v->dtdv_scope;
		int *np = (int *)NULL;

		if ((id = v->dtdv_id) < DIF_VAR_OTHER_UBASE)
			continue;

		id -= DIF_VAR_OTHER_UBASE;

		switch (scope) {
		case DIFV_SCOPE_THREAD:
			while (id >= (uint_t)(otlocals = vstate->dtvs_ntlocals)) {
				dtrace_difv_t *tlocals;

				if ((ntlocals = (otlocals << 1)) == 0)
					ntlocals = 1;

				osz = otlocals * sizeof (dtrace_difv_t);
				nsz = ntlocals * sizeof (dtrace_difv_t);

				tlocals = kmem_zalloc(nsz, KM_SLEEP);

				if (osz != 0) {
					bcopy(vstate->dtvs_tlocals,
					    tlocals, osz);
					kmem_free(vstate->dtvs_tlocals, osz);
				}

				vstate->dtvs_tlocals = tlocals;
				vstate->dtvs_ntlocals = ntlocals;
			}

			vstate->dtvs_tlocals[id] = *v;
			continue;

		case DIFV_SCOPE_LOCAL:
			np = &vstate->dtvs_nlocals;
			svarp = &vstate->dtvs_locals;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF)
				dsize = (int)NCPU * (v->dtdv_type.dtdt_size +
				    sizeof (uint64_t));
			else
				dsize = (int)NCPU * sizeof (uint64_t);

			break;

		case DIFV_SCOPE_GLOBAL:
			np = &vstate->dtvs_nglobals;
			svarp = &vstate->dtvs_globals;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF)
				dsize = v->dtdv_type.dtdt_size +
				    sizeof (uint64_t);

			break;

		default:
			ASSERT(0);
		}

		while (id >= (uint_t)(oldsvars = *np)) {
			dtrace_statvar_t **statics;
			int newsvars, oldsize, newsize;

			if ((newsvars = (oldsvars << 1)) == 0)
				newsvars = 1;

			oldsize = oldsvars * sizeof (dtrace_statvar_t *);
			newsize = newsvars * sizeof (dtrace_statvar_t *);

			statics = kmem_zalloc(newsize, KM_SLEEP);

			if (oldsize != 0) {
				bcopy(*svarp, statics, oldsize);
				kmem_free(*svarp, oldsize);
			}

			*svarp = statics;
			*np = newsvars;
		}

		if ((svar = (*svarp)[id]) == NULL) {
			svar = kmem_zalloc(sizeof (dtrace_statvar_t), KM_SLEEP);
			svar->dtsv_var = *v;

			if ((svar->dtsv_size = dsize) != 0) {
				svar->dtsv_data = (uint64_t)(uintptr_t)
				    kmem_zalloc(dsize, KM_SLEEP);
			}

			(*svarp)[id] = svar;
		}

		svar->dtsv_refcnt++;
	}

	dtrace_difo_chunksize(dp, vstate);
	dtrace_difo_hold(dp);
}

static dtrace_difo_t *
dtrace_difo_duplicate(dtrace_difo_t *dp, dtrace_vstate_t *vstate)
{
	dtrace_difo_t *new;
	size_t sz;

	ASSERT(dp->dtdo_buf != NULL);
	ASSERT(dp->dtdo_refcnt != 0);

	new = kmem_zalloc(sizeof (dtrace_difo_t), KM_SLEEP);

	ASSERT(dp->dtdo_buf != NULL);
	sz = dp->dtdo_len * sizeof (dif_instr_t);
	new->dtdo_buf = kmem_alloc(sz, KM_SLEEP);
	bcopy(dp->dtdo_buf, new->dtdo_buf, sz);
	new->dtdo_len = dp->dtdo_len;

	if (dp->dtdo_strtab != NULL) {
		ASSERT(dp->dtdo_strlen != 0);
		new->dtdo_strtab = kmem_alloc(dp->dtdo_strlen, KM_SLEEP);
		bcopy(dp->dtdo_strtab, new->dtdo_strtab, dp->dtdo_strlen);
		new->dtdo_strlen = dp->dtdo_strlen;
	}

	if (dp->dtdo_inttab != NULL) {
		ASSERT(dp->dtdo_intlen != 0);
		sz = dp->dtdo_intlen * sizeof (uint64_t);
		new->dtdo_inttab = kmem_alloc(sz, KM_SLEEP);
		bcopy(dp->dtdo_inttab, new->dtdo_inttab, sz);
		new->dtdo_intlen = dp->dtdo_intlen;
	}

	if (dp->dtdo_vartab != NULL) {
		ASSERT(dp->dtdo_varlen != 0);
		sz = dp->dtdo_varlen * sizeof (dtrace_difv_t);
		new->dtdo_vartab = kmem_alloc(sz, KM_SLEEP);
		bcopy(dp->dtdo_vartab, new->dtdo_vartab, sz);
		new->dtdo_varlen = dp->dtdo_varlen;
	}

	dtrace_difo_init(new, vstate);
	return (new);
}

static void
dtrace_difo_destroy(dtrace_difo_t *dp, dtrace_vstate_t *vstate)
{
	uint_t i;

	ASSERT(dp->dtdo_refcnt == 0);

	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t *v = &dp->dtdo_vartab[i];
		dtrace_statvar_t *svar;
		dtrace_statvar_t **svarp = NULL;
		uint_t id;
		uint8_t scope = v->dtdv_scope;
		int *np = NULL;

		switch (scope) {
		case DIFV_SCOPE_THREAD:
			continue;

		case DIFV_SCOPE_LOCAL:
			np = &vstate->dtvs_nlocals;
			svarp = vstate->dtvs_locals;
			break;

		case DIFV_SCOPE_GLOBAL:
			np = &vstate->dtvs_nglobals;
			svarp = vstate->dtvs_globals;
			break;

		default:
			ASSERT(0);
		}

		if ((id = v->dtdv_id) < DIF_VAR_OTHER_UBASE)
			continue;

		id -= DIF_VAR_OTHER_UBASE;
		
		ASSERT(id < (uint_t)*np);

		svar = svarp[id];
		ASSERT(svar != NULL);
		ASSERT(svar->dtsv_refcnt > 0);

		if (--svar->dtsv_refcnt > 0)
			continue;

		if (svar->dtsv_size != 0) {
			ASSERT(svar->dtsv_data != 0);
			kmem_free((void *)(uintptr_t)svar->dtsv_data,
			    svar->dtsv_size);
		}

		kmem_free(svar, sizeof (dtrace_statvar_t));
		svarp[id] = NULL;
	}

	kmem_free(dp->dtdo_buf, dp->dtdo_len * sizeof (dif_instr_t));
	kmem_free(dp->dtdo_inttab, dp->dtdo_intlen * sizeof (uint64_t));
	kmem_free(dp->dtdo_strtab, dp->dtdo_strlen);
	kmem_free(dp->dtdo_vartab, dp->dtdo_varlen * sizeof (dtrace_difv_t));

	kmem_free(dp, sizeof (dtrace_difo_t));
}

static void
dtrace_difo_release(dtrace_difo_t *dp, dtrace_vstate_t *vstate)
{
	uint_t i;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(dp->dtdo_refcnt != 0);

	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t *v = &dp->dtdo_vartab[i];

		if (v->dtdv_id != DIF_VAR_VTIMESTAMP)
			continue;

		ASSERT(dtrace_vtime_references > 0);
		if (--dtrace_vtime_references == 0)
			dtrace_vtime_disable();
	}

	if (--dp->dtdo_refcnt == 0)
		dtrace_difo_destroy(dp, vstate);
}

/*
 * DTrace Format Functions
 */
static uint16_t
dtrace_format_add(dtrace_state_t *state, char *str)
{
	char *fmt, **new;
	uint16_t ndx, len = strlen(str) + 1;

	fmt = kmem_zalloc(len, KM_SLEEP);
	bcopy(str, fmt, len);

	for (ndx = 0; ndx < state->dts_nformats; ndx++) {
		if (state->dts_formats[ndx] == NULL) {
			state->dts_formats[ndx] = fmt;
			return (ndx + 1);
		}
	}

	if (state->dts_nformats == USHRT_MAX) {
		/*
		 * This is only likely if a denial-of-service attack is being
		 * attempted.  As such, it's okay to fail silently here.
		 */
		kmem_free(fmt, len);
		return (0);
	}

	/*
	 * For simplicity, we always resize the formats array to be exactly the
	 * number of formats.
	 */
	ndx = state->dts_nformats++;
	new = kmem_alloc((ndx + 1) * sizeof (char *), KM_SLEEP);

	if (state->dts_formats != NULL) {
		ASSERT(ndx != 0);
		bcopy(state->dts_formats, new, ndx * sizeof (char *));
		kmem_free(state->dts_formats, ndx * sizeof (char *));
	}

	state->dts_formats = new;
	state->dts_formats[ndx] = fmt;

	return (ndx + 1);
}

static void
dtrace_format_remove(dtrace_state_t *state, uint16_t format)
{
	char *fmt;

	ASSERT(state->dts_formats != NULL);
	ASSERT(format <= state->dts_nformats);
	ASSERT(state->dts_formats[format - 1] != NULL);

	fmt = state->dts_formats[format - 1];
	kmem_free(fmt, strlen(fmt) + 1);
	state->dts_formats[format - 1] = NULL;
}

static void
dtrace_format_destroy(dtrace_state_t *state)
{
	int i;

	if (state->dts_nformats == 0) {
		ASSERT(state->dts_formats == NULL);
		return;
	}

	ASSERT(state->dts_formats != NULL);

	for (i = 0; i < state->dts_nformats; i++) {
		char *fmt = state->dts_formats[i];

		if (fmt == NULL)
			continue;

		kmem_free(fmt, strlen(fmt) + 1);
	}

	kmem_free(state->dts_formats, state->dts_nformats * sizeof (char *));
	state->dts_nformats = 0;
	state->dts_formats = NULL;
}

/*
 * DTrace Predicate Functions
 */
static dtrace_predicate_t *
dtrace_predicate_create(dtrace_difo_t *dp)
{
	dtrace_predicate_t *pred;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(dp->dtdo_refcnt != 0);

	pred = kmem_zalloc(sizeof (dtrace_predicate_t), KM_SLEEP);
	pred->dtp_difo = dp;
	pred->dtp_refcnt = 1;

	if (!dtrace_difo_cacheable(dp))
		return (pred);

	if (dtrace_predcache_id == DTRACE_CACHEIDNONE) {
		/*
		 * This is only theoretically possible -- we have had 2^32
		 * cacheable predicates on this machine.  We cannot allow any
		 * more predicates to become cacheable:  as unlikely as it is,
		 * there may be a thread caching a (now stale) predicate cache
		 * ID. (N.B.: the temptation is being successfully resisted to
		 * have this cmn_err() "Holy shit -- we executed this code!")
		 */
		return (pred);
	}

	pred->dtp_cacheid = dtrace_predcache_id++;

	return (pred);
}

static void
dtrace_predicate_hold(dtrace_predicate_t *pred)
{
	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(pred->dtp_difo != NULL && pred->dtp_difo->dtdo_refcnt != 0);
	ASSERT(pred->dtp_refcnt > 0);

	pred->dtp_refcnt++;
}

static void
dtrace_predicate_release(dtrace_predicate_t *pred, dtrace_vstate_t *vstate)
{
	dtrace_difo_t *dp = pred->dtp_difo;
#pragma unused(dp) /* __APPLE__ */

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(dp != NULL && dp->dtdo_refcnt != 0);
	ASSERT(pred->dtp_refcnt > 0);

	if (--pred->dtp_refcnt == 0) {
		dtrace_difo_release(pred->dtp_difo, vstate);
		kmem_free(pred, sizeof (dtrace_predicate_t));
	}
}

/*
 * DTrace Action Description Functions
 */
static dtrace_actdesc_t *
dtrace_actdesc_create(dtrace_actkind_t kind, uint32_t ntuple,
    uint64_t uarg, uint64_t arg)
{
	dtrace_actdesc_t *act;

	ASSERT(!DTRACEACT_ISPRINTFLIKE(kind) || (arg != 0 &&
	    arg >= KERNELBASE) || (arg == 0 && kind == DTRACEACT_PRINTA));

	act = kmem_zalloc(sizeof (dtrace_actdesc_t), KM_SLEEP);
	act->dtad_kind = kind;
	act->dtad_ntuple = ntuple;
	act->dtad_uarg = uarg;
	act->dtad_arg = arg;
	act->dtad_refcnt = 1;

	return (act);
}

static void
dtrace_actdesc_hold(dtrace_actdesc_t *act)
{
	ASSERT(act->dtad_refcnt >= 1);
	act->dtad_refcnt++;
}

static void
dtrace_actdesc_release(dtrace_actdesc_t *act, dtrace_vstate_t *vstate)
{
	dtrace_actkind_t kind = act->dtad_kind;
	dtrace_difo_t *dp;

	ASSERT(act->dtad_refcnt >= 1);

	if (--act->dtad_refcnt != 0)
		return;

	if ((dp = act->dtad_difo) != NULL)
		dtrace_difo_release(dp, vstate);

	if (DTRACEACT_ISPRINTFLIKE(kind)) {
		char *str = (char *)(uintptr_t)act->dtad_arg;

		ASSERT((str != NULL && (uintptr_t)str >= KERNELBASE) ||
		    (str == NULL && act->dtad_kind == DTRACEACT_PRINTA));

		if (str != NULL)
			kmem_free(str, strlen(str) + 1);
	}

	kmem_free(act, sizeof (dtrace_actdesc_t));
}

/*
 * DTrace ECB Functions
 */
static dtrace_ecb_t *
dtrace_ecb_add(dtrace_state_t *state, dtrace_probe_t *probe)
{
	dtrace_ecb_t *ecb;
	dtrace_epid_t epid;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	ecb = kmem_zalloc(sizeof (dtrace_ecb_t), KM_SLEEP);
	ecb->dte_predicate = NULL;
	ecb->dte_probe = probe;

	/*
	 * The default size is the size of the default action: recording
	 * the header.
	 */
	ecb->dte_size = ecb->dte_needed = sizeof (dtrace_rechdr_t);
	ecb->dte_alignment = sizeof (dtrace_epid_t);

	epid = state->dts_epid++;

	if (epid - 1 >= (dtrace_epid_t)state->dts_necbs) {
		dtrace_ecb_t **oecbs = state->dts_ecbs, **ecbs;
		int necbs = state->dts_necbs << 1;

		ASSERT(epid == (dtrace_epid_t)state->dts_necbs + 1);

		if (necbs == 0) {
			ASSERT(oecbs == NULL);
			necbs = 1;
		}

		ecbs = kmem_zalloc(necbs * sizeof (*ecbs), KM_SLEEP);

		if (oecbs != NULL)
			bcopy(oecbs, ecbs, state->dts_necbs * sizeof (*ecbs));

		dtrace_membar_producer();
		state->dts_ecbs = ecbs;

		if (oecbs != NULL) {
			/*
			 * If this state is active, we must dtrace_sync()
			 * before we can free the old dts_ecbs array:  we're
			 * coming in hot, and there may be active ring
			 * buffer processing (which indexes into the dts_ecbs
			 * array) on another CPU.
			 */
			if (state->dts_activity != DTRACE_ACTIVITY_INACTIVE)
				dtrace_sync();

			kmem_free(oecbs, state->dts_necbs * sizeof (*ecbs));
		}

		dtrace_membar_producer();
		state->dts_necbs = necbs;
	}

	ecb->dte_state = state;

	ASSERT(state->dts_ecbs[epid - 1] == NULL);
	dtrace_membar_producer();
	state->dts_ecbs[(ecb->dte_epid = epid) - 1] = ecb;

	return (ecb);
}

static int
dtrace_ecb_enable(dtrace_ecb_t *ecb)
{
	dtrace_probe_t *probe = ecb->dte_probe;

	lck_mtx_assert(&cpu_lock, LCK_MTX_ASSERT_OWNED);
	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(ecb->dte_next == NULL);

	if (probe == NULL) {
		/*
		 * This is the NULL probe -- there's nothing to do.
		 */
	    return(0);
	}

	probe->dtpr_provider->dtpv_ecb_count++;
	if (probe->dtpr_ecb == NULL) {
		dtrace_provider_t *prov = probe->dtpr_provider;

		/*
		 * We're the first ECB on this probe.
		 */
		probe->dtpr_ecb = probe->dtpr_ecb_last = ecb;

		if (ecb->dte_predicate != NULL)
			probe->dtpr_predcache = ecb->dte_predicate->dtp_cacheid;

		return (prov->dtpv_pops.dtps_enable(prov->dtpv_arg,
                    probe->dtpr_id, probe->dtpr_arg));
	} else {
		/*
		 * This probe is already active.  Swing the last pointer to
		 * point to the new ECB, and issue a dtrace_sync() to assure
		 * that all CPUs have seen the change.
		 */
		ASSERT(probe->dtpr_ecb_last != NULL);
		probe->dtpr_ecb_last->dte_next = ecb;
		probe->dtpr_ecb_last = ecb;
		probe->dtpr_predcache = 0;

		dtrace_sync();
		return(0);
	}
}

static int
dtrace_ecb_resize(dtrace_ecb_t *ecb)
{
	dtrace_action_t *act;
	uint32_t curneeded = UINT32_MAX;
	uint32_t aggbase = UINT32_MAX;

	/*
	 * If we record anything, we always record the dtrace_rechdr_t.  (And
	 * we always record it first.)
	 */
	ecb->dte_size = sizeof (dtrace_rechdr_t);
	ecb->dte_alignment = sizeof (dtrace_epid_t);

	for (act = ecb->dte_action; act != NULL; act = act->dta_next) {
		dtrace_recdesc_t *rec = &act->dta_rec;
		ASSERT(rec->dtrd_size > 0 || rec->dtrd_alignment == 1);

		ecb->dte_alignment = MAX(ecb->dte_alignment, rec->dtrd_alignment);

		if (DTRACEACT_ISAGG(act->dta_kind)) {
			dtrace_aggregation_t *agg = (dtrace_aggregation_t *)act;

			ASSERT(rec->dtrd_size != 0);
			ASSERT(agg->dtag_first != NULL);
			ASSERT(act->dta_prev->dta_intuple);
			ASSERT(aggbase != UINT32_MAX);
			ASSERT(curneeded != UINT32_MAX);

			agg->dtag_base = aggbase;
			curneeded = P2ROUNDUP(curneeded, rec->dtrd_alignment);
			rec->dtrd_offset = curneeded;
			if (curneeded + rec->dtrd_size < curneeded)
				return (EINVAL);
			curneeded += rec->dtrd_size;
			ecb->dte_needed = MAX(ecb->dte_needed, curneeded);

			aggbase = UINT32_MAX;
			curneeded = UINT32_MAX;
		} else if (act->dta_intuple) {
			if (curneeded == UINT32_MAX) {
				/*
				 * This is the first record in a tuple.  Align
				 * curneeded to be at offset 4 in an 8-byte
				 * aligned block.
				 */
				ASSERT(act->dta_prev == NULL || !act->dta_prev->dta_intuple);
				ASSERT(aggbase == UINT32_MAX);

				curneeded = P2PHASEUP(ecb->dte_size,
				    sizeof (uint64_t), sizeof (dtrace_aggid_t));

				aggbase = curneeded - sizeof (dtrace_aggid_t);
				ASSERT(IS_P2ALIGNED(aggbase,
				    sizeof (uint64_t)));
			}

			curneeded = P2ROUNDUP(curneeded, rec->dtrd_alignment);
			rec->dtrd_offset = curneeded;
			curneeded += rec->dtrd_size;
			if (curneeded + rec->dtrd_size < curneeded)
				return (EINVAL);
		} else {
			/* tuples must be followed by an aggregation */
			ASSERT(act->dta_prev == NULL || !act->dta_prev->dta_intuple);
			ecb->dte_size = P2ROUNDUP(ecb->dte_size, rec->dtrd_alignment);
			rec->dtrd_offset = ecb->dte_size;
			if (ecb->dte_size + rec->dtrd_size < ecb->dte_size)
				return (EINVAL);
			ecb->dte_size += rec->dtrd_size;
			ecb->dte_needed = MAX(ecb->dte_needed, ecb->dte_size);
		}
	}

	if ((act = ecb->dte_action) != NULL &&
	    !(act->dta_kind == DTRACEACT_SPECULATE && act->dta_next == NULL) &&
	    ecb->dte_size == sizeof (dtrace_rechdr_t)) {
		/*
		 * If the size is still sizeof (dtrace_rechdr_t), then all
		 * actions store no data; set the size to 0.
		 */
		ecb->dte_size = 0;
	}

	ecb->dte_size = P2ROUNDUP(ecb->dte_size, sizeof (dtrace_epid_t));
	ecb->dte_needed = P2ROUNDUP(ecb->dte_needed, (sizeof (dtrace_epid_t)));
	ecb->dte_state->dts_needed = MAX(ecb->dte_state->dts_needed, ecb->dte_needed);
	return (0);
}

static dtrace_action_t *
dtrace_ecb_aggregation_create(dtrace_ecb_t *ecb, dtrace_actdesc_t *desc)
{
	dtrace_aggregation_t *agg;
	size_t size = sizeof (uint64_t);
	int ntuple = desc->dtad_ntuple;
	dtrace_action_t *act;
	dtrace_recdesc_t *frec;
	dtrace_aggid_t aggid;
	dtrace_state_t *state = ecb->dte_state;

	agg = kmem_zalloc(sizeof (dtrace_aggregation_t), KM_SLEEP);
	agg->dtag_ecb = ecb;

	ASSERT(DTRACEACT_ISAGG(desc->dtad_kind));

	switch (desc->dtad_kind) {
	case DTRACEAGG_MIN:
		agg->dtag_initial = INT64_MAX;
		agg->dtag_aggregate = dtrace_aggregate_min;
		break;

	case DTRACEAGG_MAX:
		agg->dtag_initial = INT64_MIN;
		agg->dtag_aggregate = dtrace_aggregate_max;
		break;

	case DTRACEAGG_COUNT:
		agg->dtag_aggregate = dtrace_aggregate_count;
		break;

	case DTRACEAGG_QUANTIZE:
		agg->dtag_aggregate = dtrace_aggregate_quantize;
		size = (((sizeof (uint64_t) * NBBY) - 1) * 2 + 1) *
		    sizeof (uint64_t);
		break;

	case DTRACEAGG_LQUANTIZE: {
		uint16_t step = DTRACE_LQUANTIZE_STEP(desc->dtad_arg);
		uint16_t levels = DTRACE_LQUANTIZE_LEVELS(desc->dtad_arg);

		agg->dtag_initial = desc->dtad_arg;
		agg->dtag_aggregate = dtrace_aggregate_lquantize;

		if (step == 0 || levels == 0)
			goto err;

		size = levels * sizeof (uint64_t) + 3 * sizeof (uint64_t);
		break;
	}

	case DTRACEAGG_LLQUANTIZE: {
		uint16_t factor = DTRACE_LLQUANTIZE_FACTOR(desc->dtad_arg);
		uint16_t low    = DTRACE_LLQUANTIZE_LOW(desc->dtad_arg);
		uint16_t high   = DTRACE_LLQUANTIZE_HIGH(desc->dtad_arg);
		uint16_t nsteps = DTRACE_LLQUANTIZE_NSTEP(desc->dtad_arg);
		int64_t v;

		agg->dtag_initial = desc->dtad_arg;
		agg->dtag_aggregate = dtrace_aggregate_llquantize;

		if (factor < 2 || low >= high || nsteps < factor)
			goto err;

		/*
		 * Now check that the number of steps evenly divides a power
		 * of the factor.  (This assures both integer bucket size and
		 * linearity within each magnitude.)
		 */
		for (v = factor; v < nsteps; v *= factor)
			continue;

		if ((v % nsteps) || (nsteps % factor))
			goto err;

 		size = (dtrace_aggregate_llquantize_bucket(factor, low, high, nsteps, INT64_MAX) + 2) * sizeof (uint64_t);
		break;
  }

	case DTRACEAGG_AVG:
		agg->dtag_aggregate = dtrace_aggregate_avg;
		size = sizeof (uint64_t) * 2;
		break;

	case DTRACEAGG_STDDEV:
		agg->dtag_aggregate = dtrace_aggregate_stddev;
		size = sizeof (uint64_t) * 4;
		break;

	case DTRACEAGG_SUM:
		agg->dtag_aggregate = dtrace_aggregate_sum;
		break;

	default:
		goto err;
	}

	agg->dtag_action.dta_rec.dtrd_size = size;

	if (ntuple == 0)
		goto err;

	/*
	 * We must make sure that we have enough actions for the n-tuple.
	 */
	for (act = ecb->dte_action_last; act != NULL; act = act->dta_prev) {
		if (DTRACEACT_ISAGG(act->dta_kind))
			break;

		if (--ntuple == 0) {
			/*
			 * This is the action with which our n-tuple begins.
			 */
			agg->dtag_first = act;
			goto success;
		}
	}

	/*
	 * This n-tuple is short by ntuple elements.  Return failure.
	 */
	ASSERT(ntuple != 0);
err:
	kmem_free(agg, sizeof (dtrace_aggregation_t));
	return (NULL);

success:
	/*
	 * If the last action in the tuple has a size of zero, it's actually
	 * an expression argument for the aggregating action.
	 */
	ASSERT(ecb->dte_action_last != NULL);
	act = ecb->dte_action_last;

	if (act->dta_kind == DTRACEACT_DIFEXPR) {
		ASSERT(act->dta_difo != NULL);

		if (act->dta_difo->dtdo_rtype.dtdt_size == 0)
			agg->dtag_hasarg = 1;
	}

	/*
	 * We need to allocate an id for this aggregation.
	 */
	aggid = (dtrace_aggid_t)(uintptr_t)vmem_alloc(state->dts_aggid_arena, 1,
	    VM_BESTFIT | VM_SLEEP);

	if (aggid - 1 >= (dtrace_aggid_t)state->dts_naggregations) {
		dtrace_aggregation_t **oaggs = state->dts_aggregations;
		dtrace_aggregation_t **aggs;
		int naggs = state->dts_naggregations << 1;
		int onaggs = state->dts_naggregations;

		ASSERT(aggid == (dtrace_aggid_t)state->dts_naggregations + 1);

		if (naggs == 0) {
			ASSERT(oaggs == NULL);
			naggs = 1;
		}

		aggs = kmem_zalloc(naggs * sizeof (*aggs), KM_SLEEP);

		if (oaggs != NULL) {
			bcopy(oaggs, aggs, onaggs * sizeof (*aggs));
			kmem_free(oaggs, onaggs * sizeof (*aggs));
		}

		state->dts_aggregations = aggs;
		state->dts_naggregations = naggs;
	}

	ASSERT(state->dts_aggregations[aggid - 1] == NULL);
	state->dts_aggregations[(agg->dtag_id = aggid) - 1] = agg;

	frec = &agg->dtag_first->dta_rec;
	if (frec->dtrd_alignment < sizeof (dtrace_aggid_t))
		frec->dtrd_alignment = sizeof (dtrace_aggid_t);

	for (act = agg->dtag_first; act != NULL; act = act->dta_next) {
		ASSERT(!act->dta_intuple);
		act->dta_intuple = 1;
	}

	return (&agg->dtag_action);
}

static void
dtrace_ecb_aggregation_destroy(dtrace_ecb_t *ecb, dtrace_action_t *act)
{
	dtrace_aggregation_t *agg = (dtrace_aggregation_t *)act;
	dtrace_state_t *state = ecb->dte_state;
	dtrace_aggid_t aggid = agg->dtag_id;

	ASSERT(DTRACEACT_ISAGG(act->dta_kind));
	vmem_free(state->dts_aggid_arena, (void *)(uintptr_t)aggid, 1);

	ASSERT(state->dts_aggregations[aggid - 1] == agg);
	state->dts_aggregations[aggid - 1] = NULL;

	kmem_free(agg, sizeof (dtrace_aggregation_t));
}

static int
dtrace_ecb_action_add(dtrace_ecb_t *ecb, dtrace_actdesc_t *desc)
{
	dtrace_action_t *action, *last;
	dtrace_difo_t *dp = desc->dtad_difo;
	uint32_t size = 0, align = sizeof (uint8_t), mask;
	uint16_t format = 0;
	dtrace_recdesc_t *rec;
	dtrace_state_t *state = ecb->dte_state;
	dtrace_optval_t *opt = state->dts_options;
	dtrace_optval_t nframes=0, strsize;
	uint64_t arg = desc->dtad_arg;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(ecb->dte_action == NULL || ecb->dte_action->dta_refcnt == 1);

	if (DTRACEACT_ISAGG(desc->dtad_kind)) {
		/*
		 * If this is an aggregating action, there must be neither
		 * a speculate nor a commit on the action chain.
		 */
		dtrace_action_t *act;

		for (act = ecb->dte_action; act != NULL; act = act->dta_next) {
			if (act->dta_kind == DTRACEACT_COMMIT)
				return (EINVAL);

			if (act->dta_kind == DTRACEACT_SPECULATE)
				return (EINVAL);
		}

		action = dtrace_ecb_aggregation_create(ecb, desc);

		if (action == NULL)
			return (EINVAL);
	} else {
		if (DTRACEACT_ISDESTRUCTIVE(desc->dtad_kind) ||
		    (desc->dtad_kind == DTRACEACT_DIFEXPR &&
		    dp != NULL && dp->dtdo_destructive)) {
			state->dts_destructive = 1;
		}

		switch (desc->dtad_kind) {
		case DTRACEACT_PRINTF:
		case DTRACEACT_PRINTA:
		case DTRACEACT_SYSTEM:
		case DTRACEACT_FREOPEN:
		case DTRACEACT_DIFEXPR:
			/*
			 * We know that our arg is a string -- turn it into a
			 * format.
			 */
			if (arg == 0) {
				ASSERT(desc->dtad_kind == DTRACEACT_PRINTA ||
				       desc->dtad_kind == DTRACEACT_DIFEXPR);
				format = 0;
			} else {
				ASSERT(arg != 0);
				ASSERT(arg > KERNELBASE);
				format = dtrace_format_add(state,
				    (char *)(uintptr_t)arg);
			}

			/*FALLTHROUGH*/
		case DTRACEACT_LIBACT:
		case DTRACEACT_TRACEMEM:
		case DTRACEACT_TRACEMEM_DYNSIZE:
		case DTRACEACT_APPLEBINARY:	/* __APPLE__ */
			if (dp == NULL)
				return (EINVAL);

			if ((size = dp->dtdo_rtype.dtdt_size) != 0)
				break;

			if (dp->dtdo_rtype.dtdt_kind == DIF_TYPE_STRING) {
				if (!(dp->dtdo_rtype.dtdt_flags & DIF_TF_BYREF))
					return (EINVAL);

				size = opt[DTRACEOPT_STRSIZE];
			}

			break;

		case DTRACEACT_STACK:
			if ((nframes = arg) == 0) {
				nframes = opt[DTRACEOPT_STACKFRAMES];
				ASSERT(nframes > 0);
				arg = nframes;
			}

			size = nframes * sizeof (pc_t);
			break;

		case DTRACEACT_JSTACK:
			if ((strsize = DTRACE_USTACK_STRSIZE(arg)) == 0)
				strsize = opt[DTRACEOPT_JSTACKSTRSIZE];

			if ((nframes = DTRACE_USTACK_NFRAMES(arg)) == 0)
				nframes = opt[DTRACEOPT_JSTACKFRAMES];

			arg = DTRACE_USTACK_ARG(nframes, strsize);

			/*FALLTHROUGH*/
		case DTRACEACT_USTACK:
			if (desc->dtad_kind != DTRACEACT_JSTACK &&
			    (nframes = DTRACE_USTACK_NFRAMES(arg)) == 0) {
				strsize = DTRACE_USTACK_STRSIZE(arg);
				nframes = opt[DTRACEOPT_USTACKFRAMES];
				ASSERT(nframes > 0);
				arg = DTRACE_USTACK_ARG(nframes, strsize);
			}

			/*
			 * Save a slot for the pid.
			 */
			size = (nframes + 1) * sizeof (uint64_t);
			size += DTRACE_USTACK_STRSIZE(arg);
			size = P2ROUNDUP(size, (uint32_t)(sizeof (uintptr_t)));

			break;

		case DTRACEACT_SYM:
		case DTRACEACT_MOD:
			if (dp == NULL || ((size = dp->dtdo_rtype.dtdt_size) !=
			    sizeof (uint64_t)) ||
			    (dp->dtdo_rtype.dtdt_flags & DIF_TF_BYREF))
				return (EINVAL);
			break;

		case DTRACEACT_USYM:
		case DTRACEACT_UMOD:
		case DTRACEACT_UADDR:
			if (dp == NULL ||
			    (dp->dtdo_rtype.dtdt_size != sizeof (uint64_t)) ||
			    (dp->dtdo_rtype.dtdt_flags & DIF_TF_BYREF))
				return (EINVAL);

			/*
			 * We have a slot for the pid, plus a slot for the
			 * argument.  To keep things simple (aligned with
			 * bitness-neutral sizing), we store each as a 64-bit
			 * quantity.
			 */
			size = 2 * sizeof (uint64_t);
			break;

		case DTRACEACT_STOP:
		case DTRACEACT_BREAKPOINT:
		case DTRACEACT_PANIC:
			break;

		case DTRACEACT_CHILL:
		case DTRACEACT_DISCARD:
		case DTRACEACT_RAISE:
		case DTRACEACT_PIDRESUME:	/* __APPLE__ */
			if (dp == NULL)
				return (EINVAL);
			break;

		case DTRACEACT_EXIT:
			if (dp == NULL ||
			    (size = dp->dtdo_rtype.dtdt_size) != sizeof (int) ||
			    (dp->dtdo_rtype.dtdt_flags & DIF_TF_BYREF))
				return (EINVAL);
			break;

		case DTRACEACT_SPECULATE:
			if (ecb->dte_size > sizeof (dtrace_rechdr_t))
				return (EINVAL);

			if (dp == NULL)
				return (EINVAL);

			state->dts_speculates = 1;
			break;

		case DTRACEACT_COMMIT: {
			dtrace_action_t *act = ecb->dte_action;

			for (; act != NULL; act = act->dta_next) {
				if (act->dta_kind == DTRACEACT_COMMIT)
					return (EINVAL);
			}

			if (dp == NULL)
				return (EINVAL);
			break;
		}

		default:
			return (EINVAL);
		}

		if (size != 0 || desc->dtad_kind == DTRACEACT_SPECULATE) {
			/*
			 * If this is a data-storing action or a speculate,
			 * we must be sure that there isn't a commit on the
			 * action chain.
			 */
			dtrace_action_t *act = ecb->dte_action;

			for (; act != NULL; act = act->dta_next) {
				if (act->dta_kind == DTRACEACT_COMMIT)
					return (EINVAL);
			}
		}

		action = kmem_zalloc(sizeof (dtrace_action_t), KM_SLEEP);
		action->dta_rec.dtrd_size = size;
	}

	action->dta_refcnt = 1;
	rec = &action->dta_rec;
	size = rec->dtrd_size;

	for (mask = sizeof (uint64_t) - 1; size != 0 && mask > 0; mask >>= 1) {
		if (!(size & mask)) {
			align = mask + 1;
			break;
		}
	}

	action->dta_kind = desc->dtad_kind;

	if ((action->dta_difo = dp) != NULL)
		dtrace_difo_hold(dp);

	rec->dtrd_action = action->dta_kind;
	rec->dtrd_arg = arg;
	rec->dtrd_uarg = desc->dtad_uarg;
	rec->dtrd_alignment = (uint16_t)align;
	rec->dtrd_format = format;

	if ((last = ecb->dte_action_last) != NULL) {
		ASSERT(ecb->dte_action != NULL);
		action->dta_prev = last;
		last->dta_next = action;
	} else {
		ASSERT(ecb->dte_action == NULL);
		ecb->dte_action = action;
	}

	ecb->dte_action_last = action;

	return (0);
}

static void
dtrace_ecb_action_remove(dtrace_ecb_t *ecb)
{
	dtrace_action_t *act = ecb->dte_action, *next;
	dtrace_vstate_t *vstate = &ecb->dte_state->dts_vstate;
	dtrace_difo_t *dp;
	uint16_t format;

	if (act != NULL && act->dta_refcnt > 1) {
		ASSERT(act->dta_next == NULL || act->dta_next->dta_refcnt == 1);
		act->dta_refcnt--;
	} else {
		for (; act != NULL; act = next) {
			next = act->dta_next;
			ASSERT(next != NULL || act == ecb->dte_action_last);
			ASSERT(act->dta_refcnt == 1);

			if ((format = act->dta_rec.dtrd_format) != 0)
				dtrace_format_remove(ecb->dte_state, format);

			if ((dp = act->dta_difo) != NULL)
				dtrace_difo_release(dp, vstate);

			if (DTRACEACT_ISAGG(act->dta_kind)) {
				dtrace_ecb_aggregation_destroy(ecb, act);
			} else {
				kmem_free(act, sizeof (dtrace_action_t));
			}
		}
	}

	ecb->dte_action = NULL;
	ecb->dte_action_last = NULL;
	ecb->dte_size = 0;
}

static void
dtrace_ecb_disable(dtrace_ecb_t *ecb)
{
	/*
	 * We disable the ECB by removing it from its probe.
	 */
	dtrace_ecb_t *pecb, *prev = NULL;
	dtrace_probe_t *probe = ecb->dte_probe;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	if (probe == NULL) {
		/*
		 * This is the NULL probe; there is nothing to disable.
		 */
		return;
	}

	for (pecb = probe->dtpr_ecb; pecb != NULL; pecb = pecb->dte_next) {
		if (pecb == ecb)
			break;
		prev = pecb;
	}

	ASSERT(pecb != NULL);

	if (prev == NULL) {
		probe->dtpr_ecb = ecb->dte_next;
	} else {
		prev->dte_next = ecb->dte_next;
	}

	if (ecb == probe->dtpr_ecb_last) {
		ASSERT(ecb->dte_next == NULL);
		probe->dtpr_ecb_last = prev;
	}

	probe->dtpr_provider->dtpv_ecb_count--;
	/*
	 * The ECB has been disconnected from the probe; now sync to assure
	 * that all CPUs have seen the change before returning.
	 */
	dtrace_sync();

	if (probe->dtpr_ecb == NULL) {
		/*
		 * That was the last ECB on the probe; clear the predicate
		 * cache ID for the probe, disable it and sync one more time
		 * to assure that we'll never hit it again.
		 */
		dtrace_provider_t *prov = probe->dtpr_provider;

		ASSERT(ecb->dte_next == NULL);
		ASSERT(probe->dtpr_ecb_last == NULL);
		probe->dtpr_predcache = DTRACE_CACHEIDNONE;
		prov->dtpv_pops.dtps_disable(prov->dtpv_arg,
		    probe->dtpr_id, probe->dtpr_arg);
		dtrace_sync();
	} else {
		/*
		 * There is at least one ECB remaining on the probe.  If there
		 * is _exactly_ one, set the probe's predicate cache ID to be
		 * the predicate cache ID of the remaining ECB.
		 */
		ASSERT(probe->dtpr_ecb_last != NULL);
		ASSERT(probe->dtpr_predcache == DTRACE_CACHEIDNONE);

		if (probe->dtpr_ecb == probe->dtpr_ecb_last) {
			dtrace_predicate_t *p = probe->dtpr_ecb->dte_predicate;

			ASSERT(probe->dtpr_ecb->dte_next == NULL);

			if (p != NULL)
				probe->dtpr_predcache = p->dtp_cacheid;
		}

		ecb->dte_next = NULL;
	}
}

static void
dtrace_ecb_destroy(dtrace_ecb_t *ecb)
{
	dtrace_state_t *state = ecb->dte_state;
	dtrace_vstate_t *vstate = &state->dts_vstate;
	dtrace_predicate_t *pred;
	dtrace_epid_t epid = ecb->dte_epid;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(ecb->dte_next == NULL);
	ASSERT(ecb->dte_probe == NULL || ecb->dte_probe->dtpr_ecb != ecb);

	if ((pred = ecb->dte_predicate) != NULL)
		dtrace_predicate_release(pred, vstate);

	dtrace_ecb_action_remove(ecb);

	ASSERT(state->dts_ecbs[epid - 1] == ecb);
	state->dts_ecbs[epid - 1] = NULL;

	kmem_free(ecb, sizeof (dtrace_ecb_t));
}

static dtrace_ecb_t *
dtrace_ecb_create(dtrace_state_t *state, dtrace_probe_t *probe,
    dtrace_enabling_t *enab)
{
	dtrace_ecb_t *ecb;
	dtrace_predicate_t *pred;
	dtrace_actdesc_t *act;
	dtrace_provider_t *prov;
	dtrace_ecbdesc_t *desc = enab->dten_current;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(state != NULL);

	ecb = dtrace_ecb_add(state, probe);
	ecb->dte_uarg = desc->dted_uarg;

	if ((pred = desc->dted_pred.dtpdd_predicate) != NULL) {
		dtrace_predicate_hold(pred);
		ecb->dte_predicate = pred;
	}

	if (probe != NULL) {
		/*
		 * If the provider shows more leg than the consumer is old
		 * enough to see, we need to enable the appropriate implicit
		 * predicate bits to prevent the ecb from activating at
		 * revealing times.
		 *
		 * Providers specifying DTRACE_PRIV_USER at register time
		 * are stating that they need the /proc-style privilege
		 * model to be enforced, and this is what DTRACE_COND_OWNER
		 * and DTRACE_COND_ZONEOWNER will then do at probe time.
		 */
		prov = probe->dtpr_provider;
		if (!(state->dts_cred.dcr_visible & DTRACE_CRV_ALLPROC) &&
		    (prov->dtpv_priv.dtpp_flags & DTRACE_PRIV_USER))
			ecb->dte_cond |= DTRACE_COND_OWNER;

		if (!(state->dts_cred.dcr_visible & DTRACE_CRV_ALLZONE) &&
		    (prov->dtpv_priv.dtpp_flags & DTRACE_PRIV_USER))
			ecb->dte_cond |= DTRACE_COND_ZONEOWNER;

		/*
		 * If the provider shows us kernel innards and the user
		 * is lacking sufficient privilege, enable the
		 * DTRACE_COND_USERMODE implicit predicate.
		 */
		if (!(state->dts_cred.dcr_visible & DTRACE_CRV_KERNEL) &&
		    (prov->dtpv_priv.dtpp_flags & DTRACE_PRIV_KERNEL))
			ecb->dte_cond |= DTRACE_COND_USERMODE;
	}

	if (dtrace_ecb_create_cache != NULL) {
		/*
		 * If we have a cached ecb, we'll use its action list instead
		 * of creating our own (saving both time and space).
		 */
		dtrace_ecb_t *cached = dtrace_ecb_create_cache;
		dtrace_action_t *act_if = cached->dte_action;

		if (act_if != NULL) {
			ASSERT(act_if->dta_refcnt > 0);
			act_if->dta_refcnt++;
			ecb->dte_action = act_if;
			ecb->dte_action_last = cached->dte_action_last;
			ecb->dte_needed = cached->dte_needed;
			ecb->dte_size = cached->dte_size;
			ecb->dte_alignment = cached->dte_alignment;
		}

		return (ecb);
	}

	for (act = desc->dted_action; act != NULL; act = act->dtad_next) {
		if ((enab->dten_error = dtrace_ecb_action_add(ecb, act)) != 0) {
			dtrace_ecb_destroy(ecb);
			return (NULL);
		}
	}

	if ((enab->dten_error = dtrace_ecb_resize(ecb)) != 0) {
		dtrace_ecb_destroy(ecb);
		return (NULL);
	}

	return (dtrace_ecb_create_cache = ecb);
}

static int
dtrace_ecb_create_enable(dtrace_probe_t *probe, void *arg)
{
	dtrace_ecb_t *ecb;
	dtrace_enabling_t *enab = arg;
	dtrace_state_t *state = enab->dten_vstate->dtvs_state;

	ASSERT(state != NULL);

	if (probe != NULL && probe->dtpr_gen < enab->dten_probegen) {
		/*
		 * This probe was created in a generation for which this
		 * enabling has previously created ECBs; we don't want to
		 * enable it again, so just kick out.
		 */
		return (DTRACE_MATCH_NEXT);
	}

	if ((ecb = dtrace_ecb_create(state, probe, enab)) == NULL)
		return (DTRACE_MATCH_DONE);

	if (dtrace_ecb_enable(ecb) < 0)
               return (DTRACE_MATCH_FAIL);
	
	return (DTRACE_MATCH_NEXT);
}

static dtrace_ecb_t *
dtrace_epid2ecb(dtrace_state_t *state, dtrace_epid_t id)
{
	dtrace_ecb_t *ecb;
#pragma unused(ecb) /* __APPLE__ */

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	if (id == 0 || id > (dtrace_epid_t)state->dts_necbs)
		return (NULL);

	ASSERT(state->dts_necbs > 0 && state->dts_ecbs != NULL);
	ASSERT((ecb = state->dts_ecbs[id - 1]) == NULL || ecb->dte_epid == id);

	return (state->dts_ecbs[id - 1]);
}

static dtrace_aggregation_t *
dtrace_aggid2agg(dtrace_state_t *state, dtrace_aggid_t id)
{
	dtrace_aggregation_t *agg;
#pragma unused(agg) /* __APPLE__ */

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	if (id == 0 || id > (dtrace_aggid_t)state->dts_naggregations)
		return (NULL);

	ASSERT(state->dts_naggregations > 0 && state->dts_aggregations != NULL);
	ASSERT((agg = state->dts_aggregations[id - 1]) == NULL ||
	    agg->dtag_id == id);

	return (state->dts_aggregations[id - 1]);
}

/*
 * DTrace Buffer Functions
 *
 * The following functions manipulate DTrace buffers.  Most of these functions
 * are called in the context of establishing or processing consumer state;
 * exceptions are explicitly noted.
 */

/*
 * Note:  called from cross call context.  This function switches the two
 * buffers on a given CPU.  The atomicity of this operation is assured by
 * disabling interrupts while the actual switch takes place; the disabling of
 * interrupts serializes the execution with any execution of dtrace_probe() on
 * the same CPU.
 */
static void
dtrace_buffer_switch(dtrace_buffer_t *buf)
{
	caddr_t tomax = buf->dtb_tomax;
	caddr_t xamot = buf->dtb_xamot;
	dtrace_icookie_t cookie;
	hrtime_t now;

	ASSERT(!(buf->dtb_flags & DTRACEBUF_NOSWITCH));
	ASSERT(!(buf->dtb_flags & DTRACEBUF_RING));

	cookie = dtrace_interrupt_disable();
	now = dtrace_gethrtime();
	buf->dtb_tomax = xamot;
	buf->dtb_xamot = tomax;
	buf->dtb_xamot_drops = buf->dtb_drops;
	buf->dtb_xamot_offset = buf->dtb_offset;
	buf->dtb_xamot_errors = buf->dtb_errors;
	buf->dtb_xamot_flags = buf->dtb_flags;
	buf->dtb_offset = 0;
	buf->dtb_drops = 0;
	buf->dtb_errors = 0;
	buf->dtb_flags &= ~(DTRACEBUF_ERROR | DTRACEBUF_DROPPED);
	buf->dtb_interval = now - buf->dtb_switched;
	buf->dtb_switched = now;
	buf->dtb_cur_limit = buf->dtb_limit;

	dtrace_interrupt_enable(cookie);
}

/*
 * Note:  called from cross call context.  This function activates a buffer
 * on a CPU.  As with dtrace_buffer_switch(), the atomicity of the operation
 * is guaranteed by the disabling of interrupts.
 */
static void
dtrace_buffer_activate(dtrace_state_t *state)
{
	dtrace_buffer_t *buf;
	dtrace_icookie_t cookie = dtrace_interrupt_disable();

	buf = &state->dts_buffer[CPU->cpu_id];

	if (buf->dtb_tomax != NULL) {
		/*
		 * We might like to assert that the buffer is marked inactive,
		 * but this isn't necessarily true:  the buffer for the CPU
		 * that processes the BEGIN probe has its buffer activated
		 * manually.  In this case, we take the (harmless) action
		 * re-clearing the bit INACTIVE bit.
		 */
		buf->dtb_flags &= ~DTRACEBUF_INACTIVE;
	}

	dtrace_interrupt_enable(cookie);
}

static int
dtrace_buffer_canalloc(size_t size)
{
	if (size > (UINT64_MAX - dtrace_buffer_memory_inuse))
		return (B_FALSE);
	if ((size + dtrace_buffer_memory_inuse) > dtrace_buffer_memory_maxsize)
		return (B_FALSE);

	return (B_TRUE);
}

static int
dtrace_buffer_alloc(dtrace_buffer_t *bufs, size_t limit, size_t size, int flags,
    processorid_t cpu)
{
	dtrace_cpu_t *cp;
	dtrace_buffer_t *buf;
	size_t size_before_alloc = dtrace_buffer_memory_inuse;

	lck_mtx_assert(&cpu_lock, LCK_MTX_ASSERT_OWNED);
	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	if (size > (size_t)dtrace_nonroot_maxsize &&
	    !PRIV_POLICY_CHOICE(CRED(), PRIV_ALL, B_FALSE))
		return (EFBIG);

	cp = cpu_list;

	do {
		if (cpu != DTRACE_CPUALL && cpu != cp->cpu_id)
			continue;

		buf = &bufs[cp->cpu_id];

		/*
		 * If there is already a buffer allocated for this CPU, it
		 * is only possible that this is a DR event.  In this case,
		 * the buffer size must match our specified size.
		 */
		if (buf->dtb_tomax != NULL) {
			ASSERT(buf->dtb_size == size);
			continue;
		}

		ASSERT(buf->dtb_xamot == NULL);


		/* DTrace, please do not eat all the memory. */
		if (dtrace_buffer_canalloc(size) == B_FALSE)
			goto err;
		if ((buf->dtb_tomax = kmem_zalloc(size, KM_NOSLEEP)) == NULL)
			goto err;
		dtrace_buffer_memory_inuse += size;

		/* Unsure that limit is always lower than size */
		limit = limit == size ? limit - 1 : limit;
		buf->dtb_cur_limit = limit;
		buf->dtb_limit = limit;
		buf->dtb_size = size;
		buf->dtb_flags = flags;
		buf->dtb_offset = 0;
		buf->dtb_drops = 0;

		if (flags & DTRACEBUF_NOSWITCH)
			continue;

		/* DTrace, please do not eat all the memory. */
		if (dtrace_buffer_canalloc(size) == B_FALSE)
			goto err;
		if ((buf->dtb_xamot = kmem_zalloc(size, KM_NOSLEEP)) == NULL)
			goto err;
		dtrace_buffer_memory_inuse += size;
	} while ((cp = cp->cpu_next) != cpu_list);

	ASSERT(dtrace_buffer_memory_inuse <= dtrace_buffer_memory_maxsize);

	return (0);

err:
	cp = cpu_list;

	do {
		if (cpu != DTRACE_CPUALL && cpu != cp->cpu_id)
			continue;

		buf = &bufs[cp->cpu_id];

		if (buf->dtb_xamot != NULL) {
			ASSERT(buf->dtb_tomax != NULL);
			ASSERT(buf->dtb_size == size);
			kmem_free(buf->dtb_xamot, size);
		}

		if (buf->dtb_tomax != NULL) {
			ASSERT(buf->dtb_size == size);
			kmem_free(buf->dtb_tomax, size);
		}

		buf->dtb_tomax = NULL;
		buf->dtb_xamot = NULL;
		buf->dtb_size = 0;
	} while ((cp = cp->cpu_next) != cpu_list);

	/* Restore the size saved before allocating memory */
	dtrace_buffer_memory_inuse = size_before_alloc;

	return (ENOMEM);
}

/*
 * Note:  called from probe context.  This function just increments the drop
 * count on a buffer.  It has been made a function to allow for the
 * possibility of understanding the source of mysterious drop counts.  (A
 * problem for which one may be particularly disappointed that DTrace cannot
 * be used to understand DTrace.)
 */
static void
dtrace_buffer_drop(dtrace_buffer_t *buf)
{
	buf->dtb_drops++;
}

/*
 * Note:  called from probe context.  This function is called to reserve space
 * in a buffer.  If mstate is non-NULL, sets the scratch base and size in the
 * mstate.  Returns the new offset in the buffer, or a negative value if an
 * error has occurred.
 */
static intptr_t
dtrace_buffer_reserve(dtrace_buffer_t *buf, size_t needed, size_t align,
    dtrace_state_t *state, dtrace_mstate_t *mstate)
{
	intptr_t offs = buf->dtb_offset, soffs;
	intptr_t woffs;
	caddr_t tomax;
	size_t total_off;

	if (buf->dtb_flags & DTRACEBUF_INACTIVE)
		return (-1);

	if ((tomax = buf->dtb_tomax) == NULL) {
		dtrace_buffer_drop(buf);
		return (-1);
	}

	if (!(buf->dtb_flags & (DTRACEBUF_RING | DTRACEBUF_FILL))) {
		while (offs & (align - 1)) {
			/*
			 * Assert that our alignment is off by a number which
			 * is itself sizeof (uint32_t) aligned.
			 */
			ASSERT(!((align - (offs & (align - 1))) &
			    (sizeof (uint32_t) - 1)));
			DTRACE_STORE(uint32_t, tomax, offs, DTRACE_EPIDNONE);
			offs += sizeof (uint32_t);
		}

		if ((uint64_t)(soffs = offs + needed) > buf->dtb_cur_limit) {
			if (buf->dtb_cur_limit == buf->dtb_limit) {
				buf->dtb_cur_limit = buf->dtb_size;

				atomic_add_32(&state->dts_buf_over_limit, 1);
				/**
				 * Set an AST on the current processor
				 * so that we can wake up the process
				 * outside of probe context, when we know
				 * it is safe to do so
				 */
				minor_t minor = getminor(state->dts_dev);
				ASSERT(minor < 32);

				atomic_or_32(&dtrace_wake_clients, 1 << minor);
				ast_dtrace_on();
			}
			if ((uint64_t)soffs > buf->dtb_size) {
				dtrace_buffer_drop(buf);
				return (-1);
			}
		}

		if (mstate == NULL)
			return (offs);

		mstate->dtms_scratch_base = (uintptr_t)tomax + soffs;
		mstate->dtms_scratch_size = buf->dtb_size - soffs;
		mstate->dtms_scratch_ptr = mstate->dtms_scratch_base;

		return (offs);
	}

	if (buf->dtb_flags & DTRACEBUF_FILL) {
		if (state->dts_activity != DTRACE_ACTIVITY_COOLDOWN &&
		    (buf->dtb_flags & DTRACEBUF_FULL))
			return (-1);
		goto out;
	}

	total_off = needed + (offs & (align - 1));

	/*
	 * For a ring buffer, life is quite a bit more complicated.  Before
	 * we can store any padding, we need to adjust our wrapping offset.
	 * (If we've never before wrapped or we're not about to, no adjustment
	 * is required.)
	 */
	if ((buf->dtb_flags & DTRACEBUF_WRAPPED) ||
	    offs + total_off > buf->dtb_size) {
		woffs = buf->dtb_xamot_offset;

		if (offs + total_off > buf->dtb_size) {
			/*
			 * We can't fit in the end of the buffer.  First, a
			 * sanity check that we can fit in the buffer at all.
			 */
			if (total_off > buf->dtb_size) {
				dtrace_buffer_drop(buf);
				return (-1);
			}

			/*
			 * We're going to be storing at the top of the buffer,
			 * so now we need to deal with the wrapped offset.  We
			 * only reset our wrapped offset to 0 if it is
			 * currently greater than the current offset.  If it
			 * is less than the current offset, it is because a
			 * previous allocation induced a wrap -- but the
			 * allocation didn't subsequently take the space due
			 * to an error or false predicate evaluation.  In this
			 * case, we'll just leave the wrapped offset alone: if
			 * the wrapped offset hasn't been advanced far enough
			 * for this allocation, it will be adjusted in the
			 * lower loop.
			 */
			if (buf->dtb_flags & DTRACEBUF_WRAPPED) {
				if (woffs >= offs)
					woffs = 0;
			} else {
				woffs = 0;
			}

			/*
			 * Now we know that we're going to be storing to the
			 * top of the buffer and that there is room for us
			 * there.  We need to clear the buffer from the current
			 * offset to the end (there may be old gunk there).
			 */
			while ((uint64_t)offs < buf->dtb_size)
				tomax[offs++] = 0;

			/*
			 * We need to set our offset to zero.  And because we
			 * are wrapping, we need to set the bit indicating as
			 * much.  We can also adjust our needed space back
			 * down to the space required by the ECB -- we know
			 * that the top of the buffer is aligned.
			 */
			offs = 0;
			total_off = needed;
			buf->dtb_flags |= DTRACEBUF_WRAPPED;
		} else {
			/*
			 * There is room for us in the buffer, so we simply
			 * need to check the wrapped offset.
			 */
			if (woffs < offs) {
				/*
				 * The wrapped offset is less than the offset.
				 * This can happen if we allocated buffer space
				 * that induced a wrap, but then we didn't
				 * subsequently take the space due to an error
				 * or false predicate evaluation.  This is
				 * okay; we know that _this_ allocation isn't
				 * going to induce a wrap.  We still can't
				 * reset the wrapped offset to be zero,
				 * however: the space may have been trashed in
				 * the previous failed probe attempt.  But at
				 * least the wrapped offset doesn't need to
				 * be adjusted at all...
				 */
				goto out;
			}
		}

		while (offs + total_off > (size_t)woffs) {
			dtrace_epid_t epid = *(uint32_t *)(tomax + woffs);
			size_t size;

			if (epid == DTRACE_EPIDNONE) {
				size = sizeof (uint32_t);
			} else {
				ASSERT(epid <= (dtrace_epid_t)state->dts_necbs);
				ASSERT(state->dts_ecbs[epid - 1] != NULL);

				size = state->dts_ecbs[epid - 1]->dte_size;
			}

			ASSERT(woffs + size <= buf->dtb_size);
			ASSERT(size != 0);

			if (woffs + size == buf->dtb_size) {
				/*
				 * We've reached the end of the buffer; we want
				 * to set the wrapped offset to 0 and break
				 * out.  However, if the offs is 0, then we're
				 * in a strange edge-condition:  the amount of
				 * space that we want to reserve plus the size
				 * of the record that we're overwriting is
				 * greater than the size of the buffer.  This
				 * is problematic because if we reserve the
				 * space but subsequently don't consume it (due
				 * to a failed predicate or error) the wrapped
				 * offset will be 0 -- yet the EPID at offset 0
				 * will not be committed.  This situation is
				 * relatively easy to deal with:  if we're in
				 * this case, the buffer is indistinguishable
				 * from one that hasn't wrapped; we need only
				 * finish the job by clearing the wrapped bit,
				 * explicitly setting the offset to be 0, and
				 * zero'ing out the old data in the buffer.
				 */
				if (offs == 0) {
					buf->dtb_flags &= ~DTRACEBUF_WRAPPED;
					buf->dtb_offset = 0;
					woffs = total_off;

					while ((uint64_t)woffs < buf->dtb_size)
						tomax[woffs++] = 0;
				}

				woffs = 0;
				break;
			}

			woffs += size;
		}

		/*
		 * We have a wrapped offset.  It may be that the wrapped offset
		 * has become zero -- that's okay.
		 */
		buf->dtb_xamot_offset = woffs;
	}

out:
	/*
	 * Now we can plow the buffer with any necessary padding.
	 */
	while (offs & (align - 1)) {
		/*
		 * Assert that our alignment is off by a number which
		 * is itself sizeof (uint32_t) aligned.
		 */
		ASSERT(!((align - (offs & (align - 1))) &
		    (sizeof (uint32_t) - 1)));
		DTRACE_STORE(uint32_t, tomax, offs, DTRACE_EPIDNONE);
		offs += sizeof (uint32_t);
	}

	if (buf->dtb_flags & DTRACEBUF_FILL) {
		if (offs + needed > buf->dtb_size - state->dts_reserve) {
			buf->dtb_flags |= DTRACEBUF_FULL;
			return (-1);
		}
	}

	if (mstate == NULL)
		return (offs);

	/*
	 * For ring buffers and fill buffers, the scratch space is always
	 * the inactive buffer.
	 */
	mstate->dtms_scratch_base = (uintptr_t)buf->dtb_xamot;
	mstate->dtms_scratch_size = buf->dtb_size;
	mstate->dtms_scratch_ptr = mstate->dtms_scratch_base;

	return (offs);
}

static void
dtrace_buffer_polish(dtrace_buffer_t *buf)
{
	ASSERT(buf->dtb_flags & DTRACEBUF_RING);
	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	if (!(buf->dtb_flags & DTRACEBUF_WRAPPED))
		return;

	/*
	 * We need to polish the ring buffer.  There are three cases:
	 *
	 * - The first (and presumably most common) is that there is no gap
	 *   between the buffer offset and the wrapped offset.  In this case,
	 *   there is nothing in the buffer that isn't valid data; we can
	 *   mark the buffer as polished and return.
	 *
	 * - The second (less common than the first but still more common
	 *   than the third) is that there is a gap between the buffer offset
	 *   and the wrapped offset, and the wrapped offset is larger than the
	 *   buffer offset.  This can happen because of an alignment issue, or
	 *   can happen because of a call to dtrace_buffer_reserve() that
	 *   didn't subsequently consume the buffer space.  In this case,
	 *   we need to zero the data from the buffer offset to the wrapped
	 *   offset.
	 *
	 * - The third (and least common) is that there is a gap between the
	 *   buffer offset and the wrapped offset, but the wrapped offset is
	 *   _less_ than the buffer offset.  This can only happen because a
	 *   call to dtrace_buffer_reserve() induced a wrap, but the space
	 *   was not subsequently consumed.  In this case, we need to zero the
	 *   space from the offset to the end of the buffer _and_ from the
	 *   top of the buffer to the wrapped offset.
	 */
	if (buf->dtb_offset < buf->dtb_xamot_offset) {
		bzero(buf->dtb_tomax + buf->dtb_offset,
		    buf->dtb_xamot_offset - buf->dtb_offset);
	}

	if (buf->dtb_offset > buf->dtb_xamot_offset) {
		bzero(buf->dtb_tomax + buf->dtb_offset,
		    buf->dtb_size - buf->dtb_offset);
		bzero(buf->dtb_tomax, buf->dtb_xamot_offset);
	}
}

static void
dtrace_buffer_free(dtrace_buffer_t *bufs)
{
	int i;

	for (i = 0; i < (int)NCPU; i++) {
		dtrace_buffer_t *buf = &bufs[i];

		if (buf->dtb_tomax == NULL) {
			ASSERT(buf->dtb_xamot == NULL);
			ASSERT(buf->dtb_size == 0);
			continue;
		}

		if (buf->dtb_xamot != NULL) {
			ASSERT(!(buf->dtb_flags & DTRACEBUF_NOSWITCH));
			kmem_free(buf->dtb_xamot, buf->dtb_size);

			ASSERT(dtrace_buffer_memory_inuse >= buf->dtb_size);
			dtrace_buffer_memory_inuse -= buf->dtb_size;
		}

		kmem_free(buf->dtb_tomax, buf->dtb_size);
		ASSERT(dtrace_buffer_memory_inuse >= buf->dtb_size);
		dtrace_buffer_memory_inuse -= buf->dtb_size;

		buf->dtb_size = 0;
		buf->dtb_tomax = NULL;
		buf->dtb_xamot = NULL;
	}
}

/*
 * DTrace Enabling Functions
 */
static dtrace_enabling_t *
dtrace_enabling_create(dtrace_vstate_t *vstate)
{
	dtrace_enabling_t *enab;

	enab = kmem_zalloc(sizeof (dtrace_enabling_t), KM_SLEEP);
	enab->dten_vstate = vstate;

	return (enab);
}

static void
dtrace_enabling_add(dtrace_enabling_t *enab, dtrace_ecbdesc_t *ecb)
{
	dtrace_ecbdesc_t **ndesc;
	size_t osize, nsize;

	/*
	 * We can't add to enablings after we've enabled them, or after we've
	 * retained them.
	 */
	ASSERT(enab->dten_probegen == 0);
	ASSERT(enab->dten_next == NULL && enab->dten_prev == NULL);

	/* APPLE NOTE: this protects against gcc 4.0 botch on x86 */
	if (ecb == NULL) return;

	if (enab->dten_ndesc < enab->dten_maxdesc) {
		enab->dten_desc[enab->dten_ndesc++] = ecb;
		return;
	}

	osize = enab->dten_maxdesc * sizeof (dtrace_enabling_t *);

	if (enab->dten_maxdesc == 0) {
		enab->dten_maxdesc = 1;
	} else {
		enab->dten_maxdesc <<= 1;
	}

	ASSERT(enab->dten_ndesc < enab->dten_maxdesc);

	nsize = enab->dten_maxdesc * sizeof (dtrace_enabling_t *);
	ndesc = kmem_zalloc(nsize, KM_SLEEP);
	bcopy(enab->dten_desc, ndesc, osize);
	kmem_free(enab->dten_desc, osize);

	enab->dten_desc = ndesc;
	enab->dten_desc[enab->dten_ndesc++] = ecb;
}

static void
dtrace_enabling_addlike(dtrace_enabling_t *enab, dtrace_ecbdesc_t *ecb,
    dtrace_probedesc_t *pd)
{
	dtrace_ecbdesc_t *new;
	dtrace_predicate_t *pred;
	dtrace_actdesc_t *act;

	/*
	 * We're going to create a new ECB description that matches the
	 * specified ECB in every way, but has the specified probe description.
	 */
	new = kmem_zalloc(sizeof (dtrace_ecbdesc_t), KM_SLEEP);

	if ((pred = ecb->dted_pred.dtpdd_predicate) != NULL)
		dtrace_predicate_hold(pred);

	for (act = ecb->dted_action; act != NULL; act = act->dtad_next)
		dtrace_actdesc_hold(act);

	new->dted_action = ecb->dted_action;
	new->dted_pred = ecb->dted_pred;
	new->dted_probe = *pd;
	new->dted_uarg = ecb->dted_uarg;

	dtrace_enabling_add(enab, new);
}

static void
dtrace_enabling_dump(dtrace_enabling_t *enab)
{
	int i;

	for (i = 0; i < enab->dten_ndesc; i++) {
		dtrace_probedesc_t *desc = &enab->dten_desc[i]->dted_probe;

		cmn_err(CE_NOTE, "enabling probe %d (%s:%s:%s:%s)", i,
		    desc->dtpd_provider, desc->dtpd_mod,
		    desc->dtpd_func, desc->dtpd_name);
	}
}

static void
dtrace_enabling_destroy(dtrace_enabling_t *enab)
{
	int i;
	dtrace_ecbdesc_t *ep;
	dtrace_vstate_t *vstate = enab->dten_vstate;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	for (i = 0; i < enab->dten_ndesc; i++) {
		dtrace_actdesc_t *act, *next;
		dtrace_predicate_t *pred;

		ep = enab->dten_desc[i];

		if ((pred = ep->dted_pred.dtpdd_predicate) != NULL)
			dtrace_predicate_release(pred, vstate);

		for (act = ep->dted_action; act != NULL; act = next) {
			next = act->dtad_next;
			dtrace_actdesc_release(act, vstate);
		}

		kmem_free(ep, sizeof (dtrace_ecbdesc_t));
	}

	kmem_free(enab->dten_desc,
	    enab->dten_maxdesc * sizeof (dtrace_enabling_t *));

	/*
	 * If this was a retained enabling, decrement the dts_nretained count
	 * and take it off of the dtrace_retained list.
	 */
	if (enab->dten_prev != NULL || enab->dten_next != NULL ||
	    dtrace_retained == enab) {
		ASSERT(enab->dten_vstate->dtvs_state != NULL);
		ASSERT(enab->dten_vstate->dtvs_state->dts_nretained > 0);
		enab->dten_vstate->dtvs_state->dts_nretained--;
                dtrace_retained_gen++;
	}

	if (enab->dten_prev == NULL) {
		if (dtrace_retained == enab) {
			dtrace_retained = enab->dten_next;

			if (dtrace_retained != NULL)
				dtrace_retained->dten_prev = NULL;
		}
	} else {
		ASSERT(enab != dtrace_retained);
		ASSERT(dtrace_retained != NULL);
		enab->dten_prev->dten_next = enab->dten_next;
	}

	if (enab->dten_next != NULL) {
		ASSERT(dtrace_retained != NULL);
		enab->dten_next->dten_prev = enab->dten_prev;
	}

	kmem_free(enab, sizeof (dtrace_enabling_t));
}

static int
dtrace_enabling_retain(dtrace_enabling_t *enab)
{
	dtrace_state_t *state;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(enab->dten_next == NULL && enab->dten_prev == NULL);
	ASSERT(enab->dten_vstate != NULL);

	state = enab->dten_vstate->dtvs_state;
	ASSERT(state != NULL);

	/*
	 * We only allow each state to retain dtrace_retain_max enablings.
	 */
	if (state->dts_nretained >= dtrace_retain_max)
		return (ENOSPC);

	state->dts_nretained++;
        dtrace_retained_gen++;

	if (dtrace_retained == NULL) {
		dtrace_retained = enab;
		return (0);
	}

	enab->dten_next = dtrace_retained;
	dtrace_retained->dten_prev = enab;
	dtrace_retained = enab;

	return (0);
}

static int
dtrace_enabling_replicate(dtrace_state_t *state, dtrace_probedesc_t *match,
    dtrace_probedesc_t *create)
{
	dtrace_enabling_t *new, *enab;
	int found = 0, err = ENOENT;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(strlen(match->dtpd_provider) < DTRACE_PROVNAMELEN);
	ASSERT(strlen(match->dtpd_mod) < DTRACE_MODNAMELEN);
	ASSERT(strlen(match->dtpd_func) < DTRACE_FUNCNAMELEN);
	ASSERT(strlen(match->dtpd_name) < DTRACE_NAMELEN);

	new = dtrace_enabling_create(&state->dts_vstate);

	/*
	 * Iterate over all retained enablings, looking for enablings that
	 * match the specified state.
	 */
	for (enab = dtrace_retained; enab != NULL; enab = enab->dten_next) {
		int i;

		/*
		 * dtvs_state can only be NULL for helper enablings -- and
		 * helper enablings can't be retained.
		 */
		ASSERT(enab->dten_vstate->dtvs_state != NULL);

		if (enab->dten_vstate->dtvs_state != state)
			continue;

		/*
		 * Now iterate over each probe description; we're looking for
		 * an exact match to the specified probe description.
		 */
		for (i = 0; i < enab->dten_ndesc; i++) {
			dtrace_ecbdesc_t *ep = enab->dten_desc[i];
			dtrace_probedesc_t *pd = &ep->dted_probe;

			/* APPLE NOTE: Darwin employs size bounded string operation. */
			if (strncmp(pd->dtpd_provider, match->dtpd_provider, DTRACE_PROVNAMELEN))
				continue;

			if (strncmp(pd->dtpd_mod, match->dtpd_mod, DTRACE_MODNAMELEN))
				continue;

			if (strncmp(pd->dtpd_func, match->dtpd_func, DTRACE_FUNCNAMELEN))
				continue;

			if (strncmp(pd->dtpd_name, match->dtpd_name, DTRACE_NAMELEN))
				continue;

			/*
			 * We have a winning probe!  Add it to our growing
			 * enabling.
			 */
			found = 1;
			dtrace_enabling_addlike(new, ep, create);
		}
	}

	if (!found || (err = dtrace_enabling_retain(new)) != 0) {
		dtrace_enabling_destroy(new);
		return (err);
	}

	return (0);
}

static void
dtrace_enabling_retract(dtrace_state_t *state)
{
	dtrace_enabling_t *enab, *next;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	/*
	 * Iterate over all retained enablings, destroy the enablings retained
	 * for the specified state.
	 */
	for (enab = dtrace_retained; enab != NULL; enab = next) {
		next = enab->dten_next;

		/*
		 * dtvs_state can only be NULL for helper enablings -- and
		 * helper enablings can't be retained.
		 */
		ASSERT(enab->dten_vstate->dtvs_state != NULL);

		if (enab->dten_vstate->dtvs_state == state) {
			ASSERT(state->dts_nretained > 0);
			dtrace_enabling_destroy(enab);
		}
	}

	ASSERT(state->dts_nretained == 0);
}

static int
dtrace_enabling_match(dtrace_enabling_t *enab, int *nmatched, dtrace_match_cond_t *cond)
{
	int i = 0;
	int total_matched = 0, matched = 0;

	lck_mtx_assert(&cpu_lock, LCK_MTX_ASSERT_OWNED);
	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	for (i = 0; i < enab->dten_ndesc; i++) {
		dtrace_ecbdesc_t *ep = enab->dten_desc[i];

		enab->dten_current = ep;
		enab->dten_error = 0;

		/**
		 * Before doing a dtrace_probe_enable, which is really
		 * expensive, check that this enabling matches the matching precondition
		 * if we have one
		 */
		if (cond && (cond->dmc_func(&ep->dted_probe, cond->dmc_data) == 0)) {
			continue;
		}
		/*
		 * If a provider failed to enable a probe then get out and
		 * let the consumer know we failed.
		 */
		if ((matched = dtrace_probe_enable(&ep->dted_probe, enab)) < 0)
			return (EBUSY);

		total_matched += matched;

		if (enab->dten_error != 0) {
			/*
			 * If we get an error half-way through enabling the
			 * probes, we kick out -- perhaps with some number of
			 * them enabled.  Leaving enabled probes enabled may
			 * be slightly confusing for user-level, but we expect
			 * that no one will attempt to actually drive on in
			 * the face of such errors.  If this is an anonymous
			 * enabling (indicated with a NULL nmatched pointer),
			 * we cmn_err() a message.  We aren't expecting to
			 * get such an error -- such as it can exist at all,
			 * it would be a result of corrupted DOF in the driver
			 * properties.
			 */
			if (nmatched == NULL) {
				cmn_err(CE_WARN, "dtrace_enabling_match() "
				    "error on %p: %d", (void *)ep,
				    enab->dten_error);
			}

			return (enab->dten_error);
		}
	}

	enab->dten_probegen = dtrace_probegen;
	if (nmatched != NULL)
		*nmatched = total_matched;

	return (0);
}

static void
dtrace_enabling_matchall_with_cond(dtrace_match_cond_t *cond)
{
	dtrace_enabling_t *enab;

	lck_mtx_lock(&cpu_lock);
	lck_mtx_lock(&dtrace_lock);

	/*
	 * Iterate over all retained enablings to see if any probes match
	 * against them.  We only perform this operation on enablings for which
	 * we have sufficient permissions by virtue of being in the global zone
	 * or in the same zone as the DTrace client.  Because we can be called
	 * after dtrace_detach() has been called, we cannot assert that there
	 * are retained enablings.  We can safely load from dtrace_retained,
	 * however:  the taskq_destroy() at the end of dtrace_detach() will
	 * block pending our completion.
	 */

	/*
	 * Darwin doesn't do zones.
	 * Behave as if always in "global" zone."
	 */
	for (enab = dtrace_retained; enab != NULL; enab = enab->dten_next) {
		(void) dtrace_enabling_match(enab, NULL, cond);
	}

	lck_mtx_unlock(&dtrace_lock);
	lck_mtx_unlock(&cpu_lock);

}

static void
dtrace_enabling_matchall(void)
{
	dtrace_enabling_matchall_with_cond(NULL);
}



/*
 * If an enabling is to be enabled without having matched probes (that is, if
 * dtrace_state_go() is to be called on the underlying dtrace_state_t), the
 * enabling must be _primed_ by creating an ECB for every ECB description.
 * This must be done to assure that we know the number of speculations, the
 * number of aggregations, the minimum buffer size needed, etc. before we
 * transition out of DTRACE_ACTIVITY_INACTIVE.  To do this without actually
 * enabling any probes, we create ECBs for every ECB decription, but with a
 * NULL probe -- which is exactly what this function does.
 */
static void
dtrace_enabling_prime(dtrace_state_t *state)
{
	dtrace_enabling_t *enab;
	int i;

	for (enab = dtrace_retained; enab != NULL; enab = enab->dten_next) {
		ASSERT(enab->dten_vstate->dtvs_state != NULL);

		if (enab->dten_vstate->dtvs_state != state)
			continue;

		/*
		 * We don't want to prime an enabling more than once, lest
		 * we allow a malicious user to induce resource exhaustion.
		 * (The ECBs that result from priming an enabling aren't
		 * leaked -- but they also aren't deallocated until the
		 * consumer state is destroyed.)
		 */
		if (enab->dten_primed)
			continue;

		for (i = 0; i < enab->dten_ndesc; i++) {
			enab->dten_current = enab->dten_desc[i];
			(void) dtrace_probe_enable(NULL, enab);
		}

		enab->dten_primed = 1;
	}
}

/*
 * Called to indicate that probes should be provided due to retained
 * enablings.  This is implemented in terms of dtrace_probe_provide(), but it
 * must take an initial lap through the enabling calling the dtps_provide()
 * entry point explicitly to allow for autocreated probes.
 */
static void
dtrace_enabling_provide(dtrace_provider_t *prv)
{
	int i, all = 0;
	dtrace_probedesc_t desc;
        dtrace_genid_t gen;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	lck_mtx_assert(&dtrace_provider_lock, LCK_MTX_ASSERT_OWNED);

	if (prv == NULL) {
		all = 1;
		prv = dtrace_provider;
	}

	do {
		dtrace_enabling_t *enab;
		void *parg = prv->dtpv_arg;

retry:
		gen = dtrace_retained_gen;
		for (enab = dtrace_retained; enab != NULL;
		    enab = enab->dten_next) {
			for (i = 0; i < enab->dten_ndesc; i++) {
				desc = enab->dten_desc[i]->dted_probe;
				lck_mtx_unlock(&dtrace_lock);
				prv->dtpv_pops.dtps_provide(parg, &desc);
				lck_mtx_lock(&dtrace_lock);
				/*
				 * Process the retained enablings again if
				 * they have changed while we weren't holding
				 * dtrace_lock.
				 */
				if (gen != dtrace_retained_gen)
					goto retry;
			}
		}
	} while (all && (prv = prv->dtpv_next) != NULL);

	lck_mtx_unlock(&dtrace_lock);
	dtrace_probe_provide(NULL, all ? NULL : prv);
	lck_mtx_lock(&dtrace_lock);
}

/*
 * DTrace DOF Functions
 */
/*ARGSUSED*/
static void
dtrace_dof_error(dof_hdr_t *dof, const char *str)
{
#pragma unused(dof) /* __APPLE__ */
	if (dtrace_err_verbose)
		cmn_err(CE_WARN, "failed to process DOF: %s", str);

#ifdef DTRACE_ERRDEBUG
	dtrace_errdebug(str);
#endif
}

/*
 * Create DOF out of a currently enabled state.  Right now, we only create
 * DOF containing the run-time options -- but this could be expanded to create
 * complete DOF representing the enabled state.
 */
static dof_hdr_t *
dtrace_dof_create(dtrace_state_t *state)
{
	dof_hdr_t *dof;
	dof_sec_t *sec;
	dof_optdesc_t *opt;
	int i, len = sizeof (dof_hdr_t) +
	    roundup(sizeof (dof_sec_t), sizeof (uint64_t)) +
	    sizeof (dof_optdesc_t) * DTRACEOPT_MAX;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	dof = dt_kmem_zalloc_aligned(len, 8, KM_SLEEP);
	dof->dofh_ident[DOF_ID_MAG0] = DOF_MAG_MAG0;
	dof->dofh_ident[DOF_ID_MAG1] = DOF_MAG_MAG1;
	dof->dofh_ident[DOF_ID_MAG2] = DOF_MAG_MAG2;
	dof->dofh_ident[DOF_ID_MAG3] = DOF_MAG_MAG3;

	dof->dofh_ident[DOF_ID_MODEL] = DOF_MODEL_NATIVE;
	dof->dofh_ident[DOF_ID_ENCODING] = DOF_ENCODE_NATIVE;
	dof->dofh_ident[DOF_ID_VERSION] = DOF_VERSION;
	dof->dofh_ident[DOF_ID_DIFVERS] = DIF_VERSION;
	dof->dofh_ident[DOF_ID_DIFIREG] = DIF_DIR_NREGS;
	dof->dofh_ident[DOF_ID_DIFTREG] = DIF_DTR_NREGS;

	dof->dofh_flags = 0;
	dof->dofh_hdrsize = sizeof (dof_hdr_t);
	dof->dofh_secsize = sizeof (dof_sec_t);
	dof->dofh_secnum = 1;	/* only DOF_SECT_OPTDESC */
	dof->dofh_secoff = sizeof (dof_hdr_t);
	dof->dofh_loadsz = len;
	dof->dofh_filesz = len;
	dof->dofh_pad = 0;

	/*
	 * Fill in the option section header...
	 */
	sec = (dof_sec_t *)((uintptr_t)dof + sizeof (dof_hdr_t));
	sec->dofs_type = DOF_SECT_OPTDESC;
	sec->dofs_align = sizeof (uint64_t);
	sec->dofs_flags = DOF_SECF_LOAD;
	sec->dofs_entsize = sizeof (dof_optdesc_t);

	opt = (dof_optdesc_t *)((uintptr_t)sec +
	    roundup(sizeof (dof_sec_t), sizeof (uint64_t)));

	sec->dofs_offset = (uintptr_t)opt - (uintptr_t)dof;
	sec->dofs_size = sizeof (dof_optdesc_t) * DTRACEOPT_MAX;

	for (i = 0; i < DTRACEOPT_MAX; i++) {
		opt[i].dofo_option = i;
		opt[i].dofo_strtab = DOF_SECIDX_NONE;
		opt[i].dofo_value = state->dts_options[i];
	}

	return (dof);
}

static dof_hdr_t *
dtrace_dof_copyin(user_addr_t uarg, int *errp)
{
	dof_hdr_t hdr, *dof;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_NOTOWNED);

	/*
	 * First, we're going to copyin() the sizeof (dof_hdr_t).
	 */
	if (copyin(uarg, &hdr, sizeof (hdr)) != 0) {
		dtrace_dof_error(NULL, "failed to copyin DOF header");
		*errp = EFAULT;
		return (NULL);
	}

	/*
	 * Now we'll allocate the entire DOF and copy it in -- provided
	 * that the length isn't outrageous.
	 */
	if (hdr.dofh_loadsz >= (uint64_t)dtrace_dof_maxsize) {
		dtrace_dof_error(&hdr, "load size exceeds maximum");
		*errp = E2BIG;
		return (NULL);
	}

	if (hdr.dofh_loadsz < sizeof (hdr)) {
		dtrace_dof_error(&hdr, "invalid load size");
		*errp = EINVAL;
		return (NULL);
	}

	dof = dt_kmem_alloc_aligned(hdr.dofh_loadsz, 8, KM_SLEEP);

        if (copyin(uarg, dof, hdr.dofh_loadsz) != 0  ||
	  dof->dofh_loadsz != hdr.dofh_loadsz) {
	    dt_kmem_free_aligned(dof, hdr.dofh_loadsz);
	    *errp = EFAULT;
	    return (NULL);
	}	    

	return (dof);
}

static dof_hdr_t *
dtrace_dof_copyin_from_proc(proc_t* p, user_addr_t uarg, int *errp)
{
	dof_hdr_t hdr, *dof;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_NOTOWNED);

	/*
	 * First, we're going to copyin() the sizeof (dof_hdr_t).
	 */
	if (uread(p, &hdr, sizeof(hdr), uarg) != KERN_SUCCESS) {
		dtrace_dof_error(NULL, "failed to copyin DOF header");
		*errp = EFAULT;
		return (NULL);
	}

	/*
	 * Now we'll allocate the entire DOF and copy it in -- provided
	 * that the length isn't outrageous.
	 */
	if (hdr.dofh_loadsz >= (uint64_t)dtrace_dof_maxsize) {
		dtrace_dof_error(&hdr, "load size exceeds maximum");
		*errp = E2BIG;
		return (NULL);
	}

	if (hdr.dofh_loadsz < sizeof (hdr)) {
		dtrace_dof_error(&hdr, "invalid load size");
		*errp = EINVAL;
		return (NULL);
	}

	dof = dt_kmem_alloc_aligned(hdr.dofh_loadsz, 8, KM_SLEEP);

	if (uread(p, dof, hdr.dofh_loadsz, uarg) != KERN_SUCCESS) {
		dt_kmem_free_aligned(dof, hdr.dofh_loadsz);
		*errp = EFAULT;
		return (NULL);
	}

	return (dof);
}

static dof_hdr_t *
dtrace_dof_property(const char *name)
{
	uchar_t *buf;
	uint64_t loadsz;
	unsigned int len, i;
	dof_hdr_t *dof;

	/*
	 * Unfortunately, array of values in .conf files are always (and
	 * only) interpreted to be integer arrays.  We must read our DOF
	 * as an integer array, and then squeeze it into a byte array.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dtrace_devi, 0,
	    name, (int **)&buf, &len) != DDI_PROP_SUCCESS)
		return (NULL);

	for (i = 0; i < len; i++)
		buf[i] = (uchar_t)(((int *)buf)[i]);

	if (len < sizeof (dof_hdr_t)) {
		ddi_prop_free(buf);
		dtrace_dof_error(NULL, "truncated header");
		return (NULL);
	}

	if (len < (loadsz = ((dof_hdr_t *)buf)->dofh_loadsz)) {
		ddi_prop_free(buf);
		dtrace_dof_error(NULL, "truncated DOF");
		return (NULL);
	}

	if (loadsz >= (uint64_t)dtrace_dof_maxsize) {
		ddi_prop_free(buf);
		dtrace_dof_error(NULL, "oversized DOF");
		return (NULL);
	}

	dof = dt_kmem_alloc_aligned(loadsz, 8, KM_SLEEP);
	bcopy(buf, dof, loadsz);
	ddi_prop_free(buf);

	return (dof);
}

static void
dtrace_dof_destroy(dof_hdr_t *dof)
{
	dt_kmem_free_aligned(dof, dof->dofh_loadsz);
}

/*
 * Return the dof_sec_t pointer corresponding to a given section index.  If the
 * index is not valid, dtrace_dof_error() is called and NULL is returned.  If
 * a type other than DOF_SECT_NONE is specified, the header is checked against
 * this type and NULL is returned if the types do not match.
 */
static dof_sec_t *
dtrace_dof_sect(dof_hdr_t *dof, uint32_t type, dof_secidx_t i)
{
	dof_sec_t *sec = (dof_sec_t *)(uintptr_t)
	    ((uintptr_t)dof + dof->dofh_secoff + i * dof->dofh_secsize);

	if (i >= dof->dofh_secnum) {
		dtrace_dof_error(dof, "referenced section index is invalid");
		return (NULL);
	}

	if (!(sec->dofs_flags & DOF_SECF_LOAD)) {
		dtrace_dof_error(dof, "referenced section is not loadable");
		return (NULL);
	}

	if (type != DOF_SECT_NONE && type != sec->dofs_type) {
		dtrace_dof_error(dof, "referenced section is the wrong type");
		return (NULL);
	}

	return (sec);
}

static dtrace_probedesc_t *
dtrace_dof_probedesc(dof_hdr_t *dof, dof_sec_t *sec, dtrace_probedesc_t *desc)
{
	dof_probedesc_t *probe;
	dof_sec_t *strtab;
	uintptr_t daddr = (uintptr_t)dof;
	uintptr_t str;
	size_t size;

	if (sec->dofs_type != DOF_SECT_PROBEDESC) {
		dtrace_dof_error(dof, "invalid probe section");
		return (NULL);
	}

	if (sec->dofs_align != sizeof (dof_secidx_t)) {
		dtrace_dof_error(dof, "bad alignment in probe description");
		return (NULL);
	}

	if (sec->dofs_offset + sizeof (dof_probedesc_t) > dof->dofh_loadsz) {
		dtrace_dof_error(dof, "truncated probe description");
		return (NULL);
	}

	probe = (dof_probedesc_t *)(uintptr_t)(daddr + sec->dofs_offset);
	strtab = dtrace_dof_sect(dof, DOF_SECT_STRTAB, probe->dofp_strtab);

	if (strtab == NULL)
		return (NULL);

	str = daddr + strtab->dofs_offset;
	size = strtab->dofs_size;

	if (probe->dofp_provider >= strtab->dofs_size) {
		dtrace_dof_error(dof, "corrupt probe provider");
		return (NULL);
	}

	(void) strncpy(desc->dtpd_provider,
	    (char *)(str + probe->dofp_provider),
	    MIN(DTRACE_PROVNAMELEN - 1, size - probe->dofp_provider));

	/* APPLE NOTE: Darwin employs size bounded string operation. */
	desc->dtpd_provider[DTRACE_PROVNAMELEN - 1] = '\0';

	if (probe->dofp_mod >= strtab->dofs_size) {
		dtrace_dof_error(dof, "corrupt probe module");
		return (NULL);
	}

	(void) strncpy(desc->dtpd_mod, (char *)(str + probe->dofp_mod),
	    MIN(DTRACE_MODNAMELEN - 1, size - probe->dofp_mod));

	/* APPLE NOTE: Darwin employs size bounded string operation. */
	desc->dtpd_mod[DTRACE_MODNAMELEN - 1] = '\0';

	if (probe->dofp_func >= strtab->dofs_size) {
		dtrace_dof_error(dof, "corrupt probe function");
		return (NULL);
	}

	(void) strncpy(desc->dtpd_func, (char *)(str + probe->dofp_func),
	    MIN(DTRACE_FUNCNAMELEN - 1, size - probe->dofp_func));

	/* APPLE NOTE: Darwin employs size bounded string operation. */	
	desc->dtpd_func[DTRACE_FUNCNAMELEN - 1] = '\0';

	if (probe->dofp_name >= strtab->dofs_size) {
		dtrace_dof_error(dof, "corrupt probe name");
		return (NULL);
	}

	(void) strncpy(desc->dtpd_name, (char *)(str + probe->dofp_name),
	    MIN(DTRACE_NAMELEN - 1, size - probe->dofp_name));

	/* APPLE NOTE: Darwin employs size bounded string operation. */	
	desc->dtpd_name[DTRACE_NAMELEN - 1] = '\0';

	return (desc);
}

static dtrace_difo_t *
dtrace_dof_difo(dof_hdr_t *dof, dof_sec_t *sec, dtrace_vstate_t *vstate,
    cred_t *cr)
{
	dtrace_difo_t *dp;
	size_t ttl = 0;
	dof_difohdr_t *dofd;
	uintptr_t daddr = (uintptr_t)dof;
	size_t max_size = dtrace_difo_maxsize;
	uint_t i;
	int l, n;
		

	static const struct {
		int section;
		int bufoffs;
		int lenoffs;
		int entsize;
		int align;
		const char *msg;
	} difo[] = {
		{ DOF_SECT_DIF, offsetof(dtrace_difo_t, dtdo_buf),
		offsetof(dtrace_difo_t, dtdo_len), sizeof (dif_instr_t),
		sizeof (dif_instr_t), "multiple DIF sections" },

		{ DOF_SECT_INTTAB, offsetof(dtrace_difo_t, dtdo_inttab),
		offsetof(dtrace_difo_t, dtdo_intlen), sizeof (uint64_t),
		sizeof (uint64_t), "multiple integer tables" },

		{ DOF_SECT_STRTAB, offsetof(dtrace_difo_t, dtdo_strtab),
		offsetof(dtrace_difo_t, dtdo_strlen), 0,
		sizeof (char), "multiple string tables" },

		{ DOF_SECT_VARTAB, offsetof(dtrace_difo_t, dtdo_vartab),
		offsetof(dtrace_difo_t, dtdo_varlen), sizeof (dtrace_difv_t),
		sizeof (uint_t), "multiple variable tables" },

		{ DOF_SECT_NONE, 0, 0, 0, 0, NULL }
	};

	if (sec->dofs_type != DOF_SECT_DIFOHDR) {
		dtrace_dof_error(dof, "invalid DIFO header section");
		return (NULL);
	}

	if (sec->dofs_align != sizeof (dof_secidx_t)) {
		dtrace_dof_error(dof, "bad alignment in DIFO header");
		return (NULL);
	}

	if (sec->dofs_size < sizeof (dof_difohdr_t) ||
	    sec->dofs_size % sizeof (dof_secidx_t)) {
		dtrace_dof_error(dof, "bad size in DIFO header");
		return (NULL);
	}

	dofd = (dof_difohdr_t *)(uintptr_t)(daddr + sec->dofs_offset);
	n = (sec->dofs_size - sizeof (*dofd)) / sizeof (dof_secidx_t) + 1;

	dp = kmem_zalloc(sizeof (dtrace_difo_t), KM_SLEEP);
	dp->dtdo_rtype = dofd->dofd_rtype;

	for (l = 0; l < n; l++) {
		dof_sec_t *subsec;
		void **bufp;
		uint32_t *lenp;

		if ((subsec = dtrace_dof_sect(dof, DOF_SECT_NONE,
		    dofd->dofd_links[l])) == NULL)
			goto err; /* invalid section link */

		if (ttl + subsec->dofs_size > max_size) {
			dtrace_dof_error(dof, "exceeds maximum size");
			goto err;
		}

		ttl += subsec->dofs_size;

		for (i = 0; difo[i].section != DOF_SECT_NONE; i++) {

			if (subsec->dofs_type != (uint32_t)difo[i].section)
				continue;

			if (!(subsec->dofs_flags & DOF_SECF_LOAD)) {
				dtrace_dof_error(dof, "section not loaded");
				goto err;
			}

			if (subsec->dofs_align != (uint32_t)difo[i].align) {
				dtrace_dof_error(dof, "bad alignment");
				goto err;
			}

			bufp = (void **)((uintptr_t)dp + difo[i].bufoffs);
			lenp = (uint32_t *)((uintptr_t)dp + difo[i].lenoffs);

			if (*bufp != NULL) {
				dtrace_dof_error(dof, difo[i].msg);
				goto err;
			}

			if ((uint32_t)difo[i].entsize != subsec->dofs_entsize) {
				dtrace_dof_error(dof, "entry size mismatch");
				goto err;
			}

			if (subsec->dofs_entsize != 0 &&
			    (subsec->dofs_size % subsec->dofs_entsize) != 0) {
				dtrace_dof_error(dof, "corrupt entry size");
				goto err;
			}

			*lenp = subsec->dofs_size;
			*bufp = kmem_alloc(subsec->dofs_size, KM_SLEEP);
			bcopy((char *)(uintptr_t)(daddr + subsec->dofs_offset),
			    *bufp, subsec->dofs_size);

			if (subsec->dofs_entsize != 0)
				*lenp /= subsec->dofs_entsize;

			break;
		}

		/*
		 * If we encounter a loadable DIFO sub-section that is not
		 * known to us, assume this is a broken program and fail.
		 */
		if (difo[i].section == DOF_SECT_NONE &&
		    (subsec->dofs_flags & DOF_SECF_LOAD)) {
			dtrace_dof_error(dof, "unrecognized DIFO subsection");
			goto err;
		}
	}
	
	if (dp->dtdo_buf == NULL) {
		/*
		 * We can't have a DIF object without DIF text.
		 */
		dtrace_dof_error(dof, "missing DIF text");
		goto err;
	}

	/*
	 * Before we validate the DIF object, run through the variable table
	 * looking for the strings -- if any of their size are under, we'll set
	 * their size to be the system-wide default string size.  Note that
	 * this should _not_ happen if the "strsize" option has been set --
	 * in this case, the compiler should have set the size to reflect the
	 * setting of the option.
	 */
	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t *v = &dp->dtdo_vartab[i];
		dtrace_diftype_t *t = &v->dtdv_type;

		if (v->dtdv_id < DIF_VAR_OTHER_UBASE)
			continue;

		if (t->dtdt_kind == DIF_TYPE_STRING && t->dtdt_size == 0)
			t->dtdt_size = dtrace_strsize_default;
	}

	if (dtrace_difo_validate(dp, vstate, DIF_DIR_NREGS, cr) != 0)
		goto err;

	dtrace_difo_init(dp, vstate);
	return (dp);

err:
	kmem_free(dp->dtdo_buf, dp->dtdo_len * sizeof (dif_instr_t));
	kmem_free(dp->dtdo_inttab, dp->dtdo_intlen * sizeof (uint64_t));
	kmem_free(dp->dtdo_strtab, dp->dtdo_strlen);
	kmem_free(dp->dtdo_vartab, dp->dtdo_varlen * sizeof (dtrace_difv_t));

	kmem_free(dp, sizeof (dtrace_difo_t));
	return (NULL);
}

static dtrace_predicate_t *
dtrace_dof_predicate(dof_hdr_t *dof, dof_sec_t *sec, dtrace_vstate_t *vstate,
    cred_t *cr)
{
	dtrace_difo_t *dp;

	if ((dp = dtrace_dof_difo(dof, sec, vstate, cr)) == NULL)
		return (NULL);

	return (dtrace_predicate_create(dp));
}

static dtrace_actdesc_t *
dtrace_dof_actdesc(dof_hdr_t *dof, dof_sec_t *sec, dtrace_vstate_t *vstate,
    cred_t *cr)
{
	dtrace_actdesc_t *act, *first = NULL, *last = NULL, *next;
	dof_actdesc_t *desc;
	dof_sec_t *difosec;
	size_t offs;
	uintptr_t daddr = (uintptr_t)dof;
	uint64_t arg;
	dtrace_actkind_t kind;

	if (sec->dofs_type != DOF_SECT_ACTDESC) {
		dtrace_dof_error(dof, "invalid action section");
		return (NULL);
	}

	if (sec->dofs_offset + sizeof (dof_actdesc_t) > dof->dofh_loadsz) {
		dtrace_dof_error(dof, "truncated action description");
		return (NULL);
	}

	if (sec->dofs_align != sizeof (uint64_t)) {
		dtrace_dof_error(dof, "bad alignment in action description");
		return (NULL);
	}

	if (sec->dofs_size < sec->dofs_entsize) {
		dtrace_dof_error(dof, "section entry size exceeds total size");
		return (NULL);
	}

	if (sec->dofs_entsize != sizeof (dof_actdesc_t)) {
		dtrace_dof_error(dof, "bad entry size in action description");
		return (NULL);
	}

	if (sec->dofs_size / sec->dofs_entsize > dtrace_actions_max) {
		dtrace_dof_error(dof, "actions exceed dtrace_actions_max");
		return (NULL);
	}

	for (offs = 0; offs < sec->dofs_size; offs += sec->dofs_entsize) {
		desc = (dof_actdesc_t *)(daddr +
		    (uintptr_t)sec->dofs_offset + offs);
		kind = (dtrace_actkind_t)desc->dofa_kind;

		if ((DTRACEACT_ISPRINTFLIKE(kind) &&
		    (kind != DTRACEACT_PRINTA || desc->dofa_strtab != DOF_SECIDX_NONE)) ||
		    (kind == DTRACEACT_DIFEXPR && desc->dofa_strtab != DOF_SECIDX_NONE))
		{
			dof_sec_t *strtab;
			char *str, *fmt;
			uint64_t i;

			/*
			 * The argument to these actions is an index into the
			 * DOF string table.  For printf()-like actions, this
			 * is the format string.  For print(), this is the
			 * CTF type of the expression result.
			 */
			if ((strtab = dtrace_dof_sect(dof,
			    DOF_SECT_STRTAB, desc->dofa_strtab)) == NULL)
				goto err;

			str = (char *)((uintptr_t)dof +
			    (uintptr_t)strtab->dofs_offset);

			for (i = desc->dofa_arg; i < strtab->dofs_size; i++) {
				if (str[i] == '\0')
					break;
			}

			if (i >= strtab->dofs_size) {
				dtrace_dof_error(dof, "bogus format string");
				goto err;
			}

			if (i == desc->dofa_arg) {
				dtrace_dof_error(dof, "empty format string");
				goto err;
			}

			i -= desc->dofa_arg;
			fmt = kmem_alloc(i + 1, KM_SLEEP);
			bcopy(&str[desc->dofa_arg], fmt, i + 1);
			arg = (uint64_t)(uintptr_t)fmt;
		} else {
			if (kind == DTRACEACT_PRINTA) {
				ASSERT(desc->dofa_strtab == DOF_SECIDX_NONE);
				arg = 0;
			} else {
				arg = desc->dofa_arg;
			}
		}

		act = dtrace_actdesc_create(kind, desc->dofa_ntuple,
		    desc->dofa_uarg, arg);

		if (last != NULL) {
			last->dtad_next = act;
		} else {
			first = act;
		}

		last = act;

		if (desc->dofa_difo == DOF_SECIDX_NONE)
			continue;

		if ((difosec = dtrace_dof_sect(dof,
		    DOF_SECT_DIFOHDR, desc->dofa_difo)) == NULL)
			goto err;

		act->dtad_difo = dtrace_dof_difo(dof, difosec, vstate, cr);

		if (act->dtad_difo == NULL)
			goto err;
	}

	ASSERT(first != NULL);
	return (first);

err:
	for (act = first; act != NULL; act = next) {
		next = act->dtad_next;
		dtrace_actdesc_release(act, vstate);
	}

	return (NULL);
}

static dtrace_ecbdesc_t *
dtrace_dof_ecbdesc(dof_hdr_t *dof, dof_sec_t *sec, dtrace_vstate_t *vstate,
    cred_t *cr)
{
	dtrace_ecbdesc_t *ep;
	dof_ecbdesc_t *ecb;
	dtrace_probedesc_t *desc;
	dtrace_predicate_t *pred = NULL;

	if (sec->dofs_size < sizeof (dof_ecbdesc_t)) {
		dtrace_dof_error(dof, "truncated ECB description");
		return (NULL);
	}

	if (sec->dofs_align != sizeof (uint64_t)) {
		dtrace_dof_error(dof, "bad alignment in ECB description");
		return (NULL);
	}

	ecb = (dof_ecbdesc_t *)((uintptr_t)dof + (uintptr_t)sec->dofs_offset);
	sec = dtrace_dof_sect(dof, DOF_SECT_PROBEDESC, ecb->dofe_probes);

	if (sec == NULL)
		return (NULL);

	ep = kmem_zalloc(sizeof (dtrace_ecbdesc_t), KM_SLEEP);
	ep->dted_uarg = ecb->dofe_uarg;
	desc = &ep->dted_probe;

	if (dtrace_dof_probedesc(dof, sec, desc) == NULL)
		goto err;

	if (ecb->dofe_pred != DOF_SECIDX_NONE) {
		if ((sec = dtrace_dof_sect(dof,
		    DOF_SECT_DIFOHDR, ecb->dofe_pred)) == NULL)
			goto err;

		if ((pred = dtrace_dof_predicate(dof, sec, vstate, cr)) == NULL)
			goto err;

		ep->dted_pred.dtpdd_predicate = pred;
	}

	if (ecb->dofe_actions != DOF_SECIDX_NONE) {
		if ((sec = dtrace_dof_sect(dof,
		    DOF_SECT_ACTDESC, ecb->dofe_actions)) == NULL)
			goto err;

		ep->dted_action = dtrace_dof_actdesc(dof, sec, vstate, cr);

		if (ep->dted_action == NULL)
			goto err;
	}

	return (ep);

err:
	if (pred != NULL)
		dtrace_predicate_release(pred, vstate);
	kmem_free(ep, sizeof (dtrace_ecbdesc_t));
	return (NULL);
}

/*
 * APPLE NOTE: dyld handles dof relocation.
 * Darwin does not need dtrace_dof_relocate()
 */

/*
 * The dof_hdr_t passed to dtrace_dof_slurp() should be a partially validated
 * header:  it should be at the front of a memory region that is at least
 * sizeof (dof_hdr_t) in size -- and then at least dof_hdr.dofh_loadsz in
 * size.  It need not be validated in any other way.
 */
static int
dtrace_dof_slurp(dof_hdr_t *dof, dtrace_vstate_t *vstate, cred_t *cr,
    dtrace_enabling_t **enabp, uint64_t ubase, int noprobes)
{
#pragma unused(ubase) /* __APPLE__ */
	uint64_t len = dof->dofh_loadsz, seclen;
	uintptr_t daddr = (uintptr_t)dof;
	dtrace_ecbdesc_t *ep;
	dtrace_enabling_t *enab;
	uint_t i;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(dof->dofh_loadsz >= sizeof (dof_hdr_t));

	/*
	 * Check the DOF header identification bytes.  In addition to checking
	 * valid settings, we also verify that unused bits/bytes are zeroed so
	 * we can use them later without fear of regressing existing binaries.
	 */
	if (bcmp(&dof->dofh_ident[DOF_ID_MAG0],
	    DOF_MAG_STRING, DOF_MAG_STRLEN) != 0) {
		dtrace_dof_error(dof, "DOF magic string mismatch");
		return (-1);
	}

	if (dof->dofh_ident[DOF_ID_MODEL] != DOF_MODEL_ILP32 &&
	    dof->dofh_ident[DOF_ID_MODEL] != DOF_MODEL_LP64) {
		dtrace_dof_error(dof, "DOF has invalid data model");
		return (-1);
	}

	if (dof->dofh_ident[DOF_ID_ENCODING] != DOF_ENCODE_NATIVE) {
		dtrace_dof_error(dof, "DOF encoding mismatch");
		return (-1);
	}

	/*
	 * APPLE NOTE: Darwin only supports DOF_VERSION_3 for now.
	 */
	if (dof->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_3) {
		dtrace_dof_error(dof, "DOF version mismatch");
		return (-1);
	}

	if (dof->dofh_ident[DOF_ID_DIFVERS] != DIF_VERSION_2) {
		dtrace_dof_error(dof, "DOF uses unsupported instruction set");
		return (-1);
	}

	if (dof->dofh_ident[DOF_ID_DIFIREG] > DIF_DIR_NREGS) {
		dtrace_dof_error(dof, "DOF uses too many integer registers");
		return (-1);
	}

	if (dof->dofh_ident[DOF_ID_DIFTREG] > DIF_DTR_NREGS) {
		dtrace_dof_error(dof, "DOF uses too many tuple registers");
		return (-1);
	}

	for (i = DOF_ID_PAD; i < DOF_ID_SIZE; i++) {
		if (dof->dofh_ident[i] != 0) {
			dtrace_dof_error(dof, "DOF has invalid ident byte set");
			return (-1);
		}
	}

	if (dof->dofh_flags & ~DOF_FL_VALID) {
		dtrace_dof_error(dof, "DOF has invalid flag bits set");
		return (-1);
	}

	if (dof->dofh_secsize == 0) {
		dtrace_dof_error(dof, "zero section header size");
		return (-1);
	}

	/*
	 * Check that the section headers don't exceed the amount of DOF
	 * data.  Note that we cast the section size and number of sections
	 * to uint64_t's to prevent possible overflow in the multiplication.
	 */
	seclen = (uint64_t)dof->dofh_secnum * (uint64_t)dof->dofh_secsize;

	if (dof->dofh_secoff > len || seclen > len ||
	    dof->dofh_secoff + seclen > len) {
		dtrace_dof_error(dof, "truncated section headers");
		return (-1);
	}

	if (!IS_P2ALIGNED(dof->dofh_secoff, sizeof (uint64_t))) {
		dtrace_dof_error(dof, "misaligned section headers");
		return (-1);
	}

	if (!IS_P2ALIGNED(dof->dofh_secsize, sizeof (uint64_t))) {
		dtrace_dof_error(dof, "misaligned section size");
		return (-1);
	}

	/*
	 * Take an initial pass through the section headers to be sure that
	 * the headers don't have stray offsets.  If the 'noprobes' flag is
	 * set, do not permit sections relating to providers, probes, or args.
	 */
	for (i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = (dof_sec_t *)(daddr +
		    (uintptr_t)dof->dofh_secoff + i * dof->dofh_secsize);

		if (noprobes) {
			switch (sec->dofs_type) {
			case DOF_SECT_PROVIDER:
			case DOF_SECT_PROBES:
			case DOF_SECT_PRARGS:
			case DOF_SECT_PROFFS:
				dtrace_dof_error(dof, "illegal sections "
				    "for enabling");
				return (-1);
			}
		}

		if (!(sec->dofs_flags & DOF_SECF_LOAD))
			continue; /* just ignore non-loadable sections */

		if (sec->dofs_align & (sec->dofs_align - 1)) {
			dtrace_dof_error(dof, "bad section alignment");
			return (-1);
		}

		if (sec->dofs_offset & (sec->dofs_align - 1)) {
			dtrace_dof_error(dof, "misaligned section");
			return (-1);
		}

		if (sec->dofs_offset > len || sec->dofs_size > len ||
		    sec->dofs_offset + sec->dofs_size > len) {
			dtrace_dof_error(dof, "corrupt section header");
			return (-1);
		}

		if (sec->dofs_type == DOF_SECT_STRTAB && *((char *)daddr +
		    sec->dofs_offset + sec->dofs_size - 1) != '\0') {
			dtrace_dof_error(dof, "non-terminating string table");
			return (-1);
		}
	}

	/*
	 * APPLE NOTE: We have no further relocation to perform.
	 * All dof values are relative offsets.
	 */

	if ((enab = *enabp) == NULL)
		enab = *enabp = dtrace_enabling_create(vstate);

	for (i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = (dof_sec_t *)(daddr +
		    (uintptr_t)dof->dofh_secoff + i * dof->dofh_secsize);

		if (sec->dofs_type != DOF_SECT_ECBDESC)
			continue;

		/*
		 * APPLE NOTE: Defend against gcc 4.0 botch on x86.
		 * not all paths out of inlined dtrace_dof_ecbdesc
		 * are checked for the NULL return value.
		 * Check for NULL explicitly here.
		*/
		ep = dtrace_dof_ecbdesc(dof, sec, vstate, cr);
		if (ep == NULL) {
			dtrace_enabling_destroy(enab);
			*enabp = NULL;
			return (-1);
		}
		
		dtrace_enabling_add(enab, ep);
	}

	return (0);
}

/*
 * Process DOF for any options.  This routine assumes that the DOF has been
 * at least processed by dtrace_dof_slurp().
 */
static int
dtrace_dof_options(dof_hdr_t *dof, dtrace_state_t *state)
{
	uint_t i;
	int rval;
	uint32_t entsize;
	size_t offs;
	dof_optdesc_t *desc;

	for (i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = (dof_sec_t *)((uintptr_t)dof +
		    (uintptr_t)dof->dofh_secoff + i * dof->dofh_secsize);

		if (sec->dofs_type != DOF_SECT_OPTDESC)
			continue;

		if (sec->dofs_align != sizeof (uint64_t)) {
			dtrace_dof_error(dof, "bad alignment in "
			    "option description");
			return (EINVAL);
		}

		if ((entsize = sec->dofs_entsize) == 0) {
			dtrace_dof_error(dof, "zeroed option entry size");
			return (EINVAL);
		}

		if (entsize < sizeof (dof_optdesc_t)) {
			dtrace_dof_error(dof, "bad option entry size");
			return (EINVAL);
		}

		for (offs = 0; offs < sec->dofs_size; offs += entsize) {
			desc = (dof_optdesc_t *)((uintptr_t)dof +
			    (uintptr_t)sec->dofs_offset + offs);

			if (desc->dofo_strtab != DOF_SECIDX_NONE) {
				dtrace_dof_error(dof, "non-zero option string");
				return (EINVAL);
			}

			if (desc->dofo_value == (uint64_t)DTRACEOPT_UNSET) {
				dtrace_dof_error(dof, "unset option");
				return (EINVAL);
			}

			if ((rval = dtrace_state_option(state,
			    desc->dofo_option, desc->dofo_value)) != 0) {
				dtrace_dof_error(dof, "rejected option");
				return (rval);
			}
		}
	}

	return (0);
}

/*
 * DTrace Consumer State Functions
 */
static int
dtrace_dstate_init(dtrace_dstate_t *dstate, size_t size)
{
	size_t hashsize, maxper, min_size, chunksize = dstate->dtds_chunksize;
	void *base;
	uintptr_t limit;
	dtrace_dynvar_t *dvar, *next, *start;
	size_t i;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(dstate->dtds_base == NULL && dstate->dtds_percpu == NULL);

	bzero(dstate, sizeof (dtrace_dstate_t));

	if ((dstate->dtds_chunksize = chunksize) == 0)
		dstate->dtds_chunksize = DTRACE_DYNVAR_CHUNKSIZE;

	VERIFY(dstate->dtds_chunksize < (LONG_MAX - sizeof (dtrace_dynhash_t)));

	if (size < (min_size = dstate->dtds_chunksize + sizeof (dtrace_dynhash_t)))
		size = min_size;

	if ((base = kmem_zalloc(size, KM_NOSLEEP)) == NULL)
		return (ENOMEM);

	dstate->dtds_size = size;
	dstate->dtds_base = base;
	dstate->dtds_percpu = kmem_cache_alloc(dtrace_state_cache, KM_SLEEP);
	bzero(dstate->dtds_percpu, (int)NCPU * sizeof (dtrace_dstate_percpu_t));

	hashsize = size / (dstate->dtds_chunksize + sizeof (dtrace_dynhash_t));

	if (hashsize != 1 && (hashsize & 1))
		hashsize--;

	dstate->dtds_hashsize = hashsize;
	dstate->dtds_hash = dstate->dtds_base;

	/*
	 * Set all of our hash buckets to point to the single sink, and (if
	 * it hasn't already been set), set the sink's hash value to be the
	 * sink sentinel value.  The sink is needed for dynamic variable
	 * lookups to know that they have iterated over an entire, valid hash
	 * chain.
	 */
	for (i = 0; i < hashsize; i++)
		dstate->dtds_hash[i].dtdh_chain = &dtrace_dynhash_sink;

	if (dtrace_dynhash_sink.dtdv_hashval != DTRACE_DYNHASH_SINK)
		dtrace_dynhash_sink.dtdv_hashval = DTRACE_DYNHASH_SINK;

	/*
	 * Determine number of active CPUs.  Divide free list evenly among
	 * active CPUs.
	 */
	start = (dtrace_dynvar_t *)
	    ((uintptr_t)base + hashsize * sizeof (dtrace_dynhash_t));
	limit = (uintptr_t)base + size;

	VERIFY((uintptr_t)start < limit);
	VERIFY((uintptr_t)start >= (uintptr_t)base);

	maxper = (limit - (uintptr_t)start) / (int)NCPU;
	maxper = (maxper / dstate->dtds_chunksize) * dstate->dtds_chunksize;

	for (i = 0; i < NCPU; i++) {
		dstate->dtds_percpu[i].dtdsc_free = dvar = start;

		/*
		 * If we don't even have enough chunks to make it once through
		 * NCPUs, we're just going to allocate everything to the first
		 * CPU.  And if we're on the last CPU, we're going to allocate
		 * whatever is left over.  In either case, we set the limit to
		 * be the limit of the dynamic variable space.
		 */
		if (maxper == 0 || i == NCPU - 1) {
			limit = (uintptr_t)base + size;
			start = NULL;
		} else {
			limit = (uintptr_t)start + maxper;
			start = (dtrace_dynvar_t *)limit;
		}

		VERIFY(limit <= (uintptr_t)base + size);

		for (;;) {
			next = (dtrace_dynvar_t *)((uintptr_t)dvar +
			    dstate->dtds_chunksize);

			if ((uintptr_t)next + dstate->dtds_chunksize >= limit)
				break;

			VERIFY((uintptr_t)dvar >= (uintptr_t)base &&
			    (uintptr_t)dvar <= (uintptr_t)base + size);
			dvar->dtdv_next = next;
			dvar = next;
		}

		if (maxper == 0)
			break;
	}

	return (0);
}

static void
dtrace_dstate_fini(dtrace_dstate_t *dstate)
{
	lck_mtx_assert(&cpu_lock, LCK_MTX_ASSERT_OWNED);

	if (dstate->dtds_base == NULL)
		return;

	kmem_free(dstate->dtds_base, dstate->dtds_size);
	kmem_cache_free(dtrace_state_cache, dstate->dtds_percpu);
}

static void
dtrace_vstate_fini(dtrace_vstate_t *vstate)
{
	/*
	 * Logical XOR, where are you?
	 */
	ASSERT((vstate->dtvs_nglobals == 0) ^ (vstate->dtvs_globals != NULL));

	if (vstate->dtvs_nglobals > 0) {
		kmem_free(vstate->dtvs_globals, vstate->dtvs_nglobals *
		    sizeof (dtrace_statvar_t *));
	}

	if (vstate->dtvs_ntlocals > 0) {
		kmem_free(vstate->dtvs_tlocals, vstate->dtvs_ntlocals *
		    sizeof (dtrace_difv_t));
	}

	ASSERT((vstate->dtvs_nlocals == 0) ^ (vstate->dtvs_locals != NULL));

	if (vstate->dtvs_nlocals > 0) {
		kmem_free(vstate->dtvs_locals, vstate->dtvs_nlocals *
		    sizeof (dtrace_statvar_t *));
	}
}

static void
dtrace_state_clean(dtrace_state_t *state)
{
	if (state->dts_activity == DTRACE_ACTIVITY_INACTIVE)
		return;

	dtrace_dynvar_clean(&state->dts_vstate.dtvs_dynvars);
	dtrace_speculation_clean(state);
}

static void
dtrace_state_deadman(dtrace_state_t *state)
{
	hrtime_t now;

	dtrace_sync();

	now = dtrace_gethrtime();

	if (state != dtrace_anon.dta_state &&
	    now - state->dts_laststatus >= dtrace_deadman_user)
		return;

	/*
	 * We must be sure that dts_alive never appears to be less than the
	 * value upon entry to dtrace_state_deadman(), and because we lack a
	 * dtrace_cas64(), we cannot store to it atomically.  We thus instead
	 * store INT64_MAX to it, followed by a memory barrier, followed by
	 * the new value.  This assures that dts_alive never appears to be
	 * less than its true value, regardless of the order in which the
	 * stores to the underlying storage are issued.
	 */
	state->dts_alive = INT64_MAX;
	dtrace_membar_producer();
	state->dts_alive = now;
}

static int
dtrace_state_create(dev_t *devp, cred_t *cr, dtrace_state_t **new_state)
{
	minor_t minor;
	major_t major;
	char c[30];
	dtrace_state_t *state;
	dtrace_optval_t *opt;
	int bufsize = (int)NCPU * sizeof (dtrace_buffer_t), i;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	lck_mtx_assert(&cpu_lock, LCK_MTX_ASSERT_OWNED);

	/* Cause restart */
	*new_state = NULL;
	
	minor = getminor(*devp);

	state = dtrace_state_allocate(minor);
	if (NULL == state) {
		printf("dtrace_open: couldn't acquire minor number %d. This usually means that too many DTrace clients are in use at the moment", minor);
		return (ERESTART);	/* can't reacquire */
	}

	state->dts_epid = DTRACE_EPIDNONE + 1;

	(void) snprintf(c, sizeof (c), "dtrace_aggid_%d", minor);
	state->dts_aggid_arena = vmem_create(c, (void *)1, UINT32_MAX, 1,
	    NULL, NULL, NULL, 0, VM_SLEEP | VMC_IDENTIFIER);

	if (devp != NULL) {
		major = getemajor(*devp);
	} else {
		major = ddi_driver_major(dtrace_devi);
	}

	state->dts_dev = makedevice(major, minor);

	if (devp != NULL)
		*devp = state->dts_dev;

	/*
	 * We allocate NCPU buffers.  On the one hand, this can be quite
	 * a bit of memory per instance (nearly 36K on a Starcat).  On the
	 * other hand, it saves an additional memory reference in the probe
	 * path.
	 */
	state->dts_buffer = kmem_zalloc(bufsize, KM_SLEEP);
	state->dts_aggbuffer = kmem_zalloc(bufsize, KM_SLEEP);
	state->dts_buf_over_limit = 0;
	state->dts_cleaner = CYCLIC_NONE;
	state->dts_deadman = CYCLIC_NONE;
	state->dts_vstate.dtvs_state = state;

	for (i = 0; i < DTRACEOPT_MAX; i++)
		state->dts_options[i] = DTRACEOPT_UNSET;

	/*
	 * Set the default options.
	 */
	opt = state->dts_options;
	opt[DTRACEOPT_BUFPOLICY] = DTRACEOPT_BUFPOLICY_SWITCH;
	opt[DTRACEOPT_BUFRESIZE] = DTRACEOPT_BUFRESIZE_AUTO;
	opt[DTRACEOPT_NSPEC] = dtrace_nspec_default;
	opt[DTRACEOPT_SPECSIZE] = dtrace_specsize_default;
	opt[DTRACEOPT_CPU] = (dtrace_optval_t)DTRACE_CPUALL;
	opt[DTRACEOPT_STRSIZE] = dtrace_strsize_default;
	opt[DTRACEOPT_STACKFRAMES] = dtrace_stackframes_default;
	opt[DTRACEOPT_USTACKFRAMES] = dtrace_ustackframes_default;
	opt[DTRACEOPT_CLEANRATE] = dtrace_cleanrate_default;
	opt[DTRACEOPT_AGGRATE] = dtrace_aggrate_default;
	opt[DTRACEOPT_SWITCHRATE] = dtrace_switchrate_default;
	opt[DTRACEOPT_STATUSRATE] = dtrace_statusrate_default;
	opt[DTRACEOPT_JSTACKFRAMES] = dtrace_jstackframes_default;
	opt[DTRACEOPT_JSTACKSTRSIZE] = dtrace_jstackstrsize_default;
	opt[DTRACEOPT_BUFLIMIT] = dtrace_buflimit_default;

	/*
	 * Depending on the user credentials, we set flag bits which alter probe
	 * visibility or the amount of destructiveness allowed.  In the case of
	 * actual anonymous tracing, or the possession of all privileges, all of
	 * the normal checks are bypassed.
	 */
#if defined(__APPLE__)
	if (cr == NULL || PRIV_POLICY_ONLY(cr, PRIV_ALL, B_FALSE)) {
		if (dtrace_is_restricted() && !dtrace_are_restrictions_relaxed()) {
			/*
			 * Allow only proc credentials when DTrace is
			 * restricted by the current security policy
			 */
			state->dts_cred.dcr_visible = DTRACE_CRV_ALLPROC;
			state->dts_cred.dcr_action = DTRACE_CRA_PROC | DTRACE_CRA_PROC_CONTROL | DTRACE_CRA_PROC_DESTRUCTIVE_ALLUSER;
		}
		else {
			state->dts_cred.dcr_visible = DTRACE_CRV_ALL;
			state->dts_cred.dcr_action = DTRACE_CRA_ALL;
		}
	}

#else
	if (cr == NULL || PRIV_POLICY_ONLY(cr, PRIV_ALL, B_FALSE)) {
		state->dts_cred.dcr_visible = DTRACE_CRV_ALL;
		state->dts_cred.dcr_action = DTRACE_CRA_ALL;
	}
	else {
		/*
		 * Set up the credentials for this instantiation.  We take a
		 * hold on the credential to prevent it from disappearing on
		 * us; this in turn prevents the zone_t referenced by this
		 * credential from disappearing.  This means that we can
		 * examine the credential and the zone from probe context.
		 */
		crhold(cr);
		state->dts_cred.dcr_cred = cr;

		/*
		 * CRA_PROC means "we have *some* privilege for dtrace" and
		 * unlocks the use of variables like pid, zonename, etc.
		 */
		if (PRIV_POLICY_ONLY(cr, PRIV_DTRACE_USER, B_FALSE) ||
		    PRIV_POLICY_ONLY(cr, PRIV_DTRACE_PROC, B_FALSE)) {
			state->dts_cred.dcr_action |= DTRACE_CRA_PROC;
		}

		/*
		 * dtrace_user allows use of syscall and profile providers.
		 * If the user also has proc_owner and/or proc_zone, we
		 * extend the scope to include additional visibility and
		 * destructive power.
		 */
		if (PRIV_POLICY_ONLY(cr, PRIV_DTRACE_USER, B_FALSE)) {
			if (PRIV_POLICY_ONLY(cr, PRIV_PROC_OWNER, B_FALSE)) {
				state->dts_cred.dcr_visible |=
				    DTRACE_CRV_ALLPROC;

				state->dts_cred.dcr_action |=
				    DTRACE_CRA_PROC_DESTRUCTIVE_ALLUSER;
			}

			if (PRIV_POLICY_ONLY(cr, PRIV_PROC_ZONE, B_FALSE)) {
				state->dts_cred.dcr_visible |=
				    DTRACE_CRV_ALLZONE;

				state->dts_cred.dcr_action |=
				    DTRACE_CRA_PROC_DESTRUCTIVE_ALLZONE;
			}

			/*
			 * If we have all privs in whatever zone this is,
			 * we can do destructive things to processes which
			 * have altered credentials.
			 *
			 * APPLE NOTE: Darwin doesn't do zones.
			 * Behave as if zone always has destructive privs.
			 */

			state->dts_cred.dcr_action |=
				DTRACE_CRA_PROC_DESTRUCTIVE_CREDCHG;
		}

		/*
		 * Holding the dtrace_kernel privilege also implies that
		 * the user has the dtrace_user privilege from a visibility
		 * perspective.  But without further privileges, some
		 * destructive actions are not available.
		 */
		if (PRIV_POLICY_ONLY(cr, PRIV_DTRACE_KERNEL, B_FALSE)) {
			/*
			 * Make all probes in all zones visible.  However,
			 * this doesn't mean that all actions become available
			 * to all zones.
			 */
			state->dts_cred.dcr_visible |= DTRACE_CRV_KERNEL |
			    DTRACE_CRV_ALLPROC | DTRACE_CRV_ALLZONE;

			state->dts_cred.dcr_action |= DTRACE_CRA_KERNEL |
			    DTRACE_CRA_PROC;
			/*
			 * Holding proc_owner means that destructive actions
			 * for *this* zone are allowed.
			 */
			if (PRIV_POLICY_ONLY(cr, PRIV_PROC_OWNER, B_FALSE))
				state->dts_cred.dcr_action |=
				    DTRACE_CRA_PROC_DESTRUCTIVE_ALLUSER;

			/*
			 * Holding proc_zone means that destructive actions
			 * for this user/group ID in all zones is allowed.
			 */
			if (PRIV_POLICY_ONLY(cr, PRIV_PROC_ZONE, B_FALSE))
				state->dts_cred.dcr_action |=
				    DTRACE_CRA_PROC_DESTRUCTIVE_ALLZONE;

			/*
			 * If we have all privs in whatever zone this is,
			 * we can do destructive things to processes which
			 * have altered credentials.
			 *
			 * APPLE NOTE: Darwin doesn't do zones.			 
			 * Behave as if zone always has destructive privs.
			 */			
			state->dts_cred.dcr_action |=
				DTRACE_CRA_PROC_DESTRUCTIVE_CREDCHG;
		}

		/*
		 * Holding the dtrace_proc privilege gives control over fasttrap
		 * and pid providers.  We need to grant wider destructive
		 * privileges in the event that the user has proc_owner and/or
		 * proc_zone.
		 */
		if (PRIV_POLICY_ONLY(cr, PRIV_DTRACE_PROC, B_FALSE)) {
			if (PRIV_POLICY_ONLY(cr, PRIV_PROC_OWNER, B_FALSE))
				state->dts_cred.dcr_action |=
				    DTRACE_CRA_PROC_DESTRUCTIVE_ALLUSER;

			if (PRIV_POLICY_ONLY(cr, PRIV_PROC_ZONE, B_FALSE))
				state->dts_cred.dcr_action |=
				    DTRACE_CRA_PROC_DESTRUCTIVE_ALLZONE;
		}
	}
#endif

	*new_state = state;
	return(0);  /* Success */
}

static int
dtrace_state_buffer(dtrace_state_t *state, dtrace_buffer_t *buf, int which)
{
	dtrace_optval_t *opt = state->dts_options, size;
	processorid_t cpu = 0;
	size_t limit = buf->dtb_size;
	int flags = 0, rval;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	lck_mtx_assert(&cpu_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(which < DTRACEOPT_MAX);
	ASSERT(state->dts_activity == DTRACE_ACTIVITY_INACTIVE ||
	    (state == dtrace_anon.dta_state &&
	    state->dts_activity == DTRACE_ACTIVITY_ACTIVE));

	if (opt[which] == DTRACEOPT_UNSET || opt[which] == 0)
		return (0);

	if (opt[DTRACEOPT_CPU] != DTRACEOPT_UNSET)
		cpu = opt[DTRACEOPT_CPU];

	if (which == DTRACEOPT_SPECSIZE)
		flags |= DTRACEBUF_NOSWITCH;

	if (which == DTRACEOPT_BUFSIZE) {
		if (opt[DTRACEOPT_BUFPOLICY] == DTRACEOPT_BUFPOLICY_RING)
			flags |= DTRACEBUF_RING;

		if (opt[DTRACEOPT_BUFPOLICY] == DTRACEOPT_BUFPOLICY_FILL)
			flags |= DTRACEBUF_FILL;

		if (state != dtrace_anon.dta_state ||
		    state->dts_activity != DTRACE_ACTIVITY_ACTIVE)
			flags |= DTRACEBUF_INACTIVE;
	}

	for (size = opt[which]; (size_t)size >= sizeof (uint64_t); size >>= 1) {
		/*
		 * The size must be 8-byte aligned.  If the size is not 8-byte
		 * aligned, drop it down by the difference.
		 */
		if (size & (sizeof (uint64_t) - 1))
			size -= size & (sizeof (uint64_t) - 1);

		if (size < state->dts_reserve) {
			/*
			 * Buffers always must be large enough to accommodate
			 * their prereserved space.  We return E2BIG instead
			 * of ENOMEM in this case to allow for user-level
			 * software to differentiate the cases.
			 */
			return (E2BIG);
		}
		limit = opt[DTRACEOPT_BUFLIMIT] * size / 100;
		rval = dtrace_buffer_alloc(buf, limit, size, flags, cpu);

		if (rval != ENOMEM) {
			opt[which] = size;
			return (rval);
		}

		if (opt[DTRACEOPT_BUFRESIZE] == DTRACEOPT_BUFRESIZE_MANUAL)
			return (rval);
	}

	return (ENOMEM);
}

static int
dtrace_state_buffers(dtrace_state_t *state)
{
	dtrace_speculation_t *spec = state->dts_speculations;
	int rval, i;

	if ((rval = dtrace_state_buffer(state, state->dts_buffer,
	    DTRACEOPT_BUFSIZE)) != 0)
		return (rval);

	if ((rval = dtrace_state_buffer(state, state->dts_aggbuffer,
	    DTRACEOPT_AGGSIZE)) != 0)
		return (rval);

	for (i = 0; i < state->dts_nspeculations; i++) {
		if ((rval = dtrace_state_buffer(state,
		    spec[i].dtsp_buffer, DTRACEOPT_SPECSIZE)) != 0)
			return (rval);
	}

	return (0);
}

static void
dtrace_state_prereserve(dtrace_state_t *state)
{
	dtrace_ecb_t *ecb;
	dtrace_probe_t *probe;

	state->dts_reserve = 0;

	if (state->dts_options[DTRACEOPT_BUFPOLICY] != DTRACEOPT_BUFPOLICY_FILL)
		return;

	/*
	 * If our buffer policy is a "fill" buffer policy, we need to set the
	 * prereserved space to be the space required by the END probes.
	 */
	probe = dtrace_probes[dtrace_probeid_end - 1];
	ASSERT(probe != NULL);

	for (ecb = probe->dtpr_ecb; ecb != NULL; ecb = ecb->dte_next) {
		if (ecb->dte_state != state)
			continue;

		state->dts_reserve += ecb->dte_needed + ecb->dte_alignment;
	}
}

static int
dtrace_state_go(dtrace_state_t *state, processorid_t *cpu)
{
	dtrace_optval_t *opt = state->dts_options, sz, nspec;
	dtrace_speculation_t *spec;
	dtrace_buffer_t *buf;
	cyc_handler_t hdlr;
	cyc_time_t when;
	int rval = 0, i, bufsize = (int)NCPU * sizeof (dtrace_buffer_t);
	dtrace_icookie_t cookie;

	lck_mtx_lock(&cpu_lock);
	lck_mtx_lock(&dtrace_lock);

	if (state->dts_activity != DTRACE_ACTIVITY_INACTIVE) {
		rval = EBUSY;
		goto out;
	}

	/*
	 * Before we can perform any checks, we must prime all of the
	 * retained enablings that correspond to this state.
	 */
	dtrace_enabling_prime(state);

	if (state->dts_destructive && !state->dts_cred.dcr_destructive) {
		rval = EACCES;
		goto out;
	}

	dtrace_state_prereserve(state);

	/*
	 * Now we want to do is try to allocate our speculations.
	 * We do not automatically resize the number of speculations; if
	 * this fails, we will fail the operation.
	 */
	nspec = opt[DTRACEOPT_NSPEC];
	ASSERT(nspec != DTRACEOPT_UNSET);

	if (nspec > INT_MAX) {
		rval = ENOMEM;
		goto out;
	}

	spec = kmem_zalloc(nspec * sizeof (dtrace_speculation_t), KM_NOSLEEP);

	if (spec == NULL) {
		rval = ENOMEM;
		goto out;
	}

	state->dts_speculations = spec;
	state->dts_nspeculations = (int)nspec;

	for (i = 0; i < nspec; i++) {
		if ((buf = kmem_zalloc(bufsize, KM_NOSLEEP)) == NULL) {
			rval = ENOMEM;
			goto err;
		}

		spec[i].dtsp_buffer = buf;
	}

	if (opt[DTRACEOPT_GRABANON] != DTRACEOPT_UNSET) {
		if (dtrace_anon.dta_state == NULL) {
			rval = ENOENT;
			goto out;
		}

		if (state->dts_necbs != 0) {
			rval = EALREADY;
			goto out;
		}

		state->dts_anon = dtrace_anon_grab();
		ASSERT(state->dts_anon != NULL);
		state = state->dts_anon;

		/*
		 * We want "grabanon" to be set in the grabbed state, so we'll
		 * copy that option value from the grabbing state into the
		 * grabbed state.
		 */
		state->dts_options[DTRACEOPT_GRABANON] =
		    opt[DTRACEOPT_GRABANON];

		*cpu = dtrace_anon.dta_beganon;

		/*
		 * If the anonymous state is active (as it almost certainly
		 * is if the anonymous enabling ultimately matched anything),
		 * we don't allow any further option processing -- but we
		 * don't return failure.
		 */
		if (state->dts_activity != DTRACE_ACTIVITY_INACTIVE)
			goto out;
	}

	if (opt[DTRACEOPT_AGGSIZE] != DTRACEOPT_UNSET &&
	    opt[DTRACEOPT_AGGSIZE] != 0) {
		if (state->dts_aggregations == NULL) {
			/*
			 * We're not going to create an aggregation buffer
			 * because we don't have any ECBs that contain
			 * aggregations -- set this option to 0.
			 */
			opt[DTRACEOPT_AGGSIZE] = 0;
		} else {
			/*
			 * If we have an aggregation buffer, we must also have
			 * a buffer to use as scratch.
			 */
			if (opt[DTRACEOPT_BUFSIZE] == DTRACEOPT_UNSET ||
			  (size_t)opt[DTRACEOPT_BUFSIZE] < state->dts_needed) {
				opt[DTRACEOPT_BUFSIZE] = state->dts_needed;
			}
		}
	}

	if (opt[DTRACEOPT_SPECSIZE] != DTRACEOPT_UNSET &&
	    opt[DTRACEOPT_SPECSIZE] != 0) {
		if (!state->dts_speculates) {
			/*
			 * We're not going to create speculation buffers
			 * because we don't have any ECBs that actually
			 * speculate -- set the speculation size to 0.
			 */
			opt[DTRACEOPT_SPECSIZE] = 0;
		}
	}

	/*
	 * The bare minimum size for any buffer that we're actually going to
	 * do anything to is sizeof (uint64_t).
	 */
	sz = sizeof (uint64_t);

	if ((state->dts_needed != 0 && opt[DTRACEOPT_BUFSIZE] < sz) ||
	    (state->dts_speculates && opt[DTRACEOPT_SPECSIZE] < sz) ||
	    (state->dts_aggregations != NULL && opt[DTRACEOPT_AGGSIZE] < sz)) {
		/*
		 * A buffer size has been explicitly set to 0 (or to a size
		 * that will be adjusted to 0) and we need the space -- we
		 * need to return failure.  We return ENOSPC to differentiate
		 * it from failing to allocate a buffer due to failure to meet
		 * the reserve (for which we return E2BIG).
		 */
		rval = ENOSPC;
		goto out;
	}

	if ((rval = dtrace_state_buffers(state)) != 0)
		goto err;

	if ((sz = opt[DTRACEOPT_DYNVARSIZE]) == DTRACEOPT_UNSET)
		sz = dtrace_dstate_defsize;

	do {
		rval = dtrace_dstate_init(&state->dts_vstate.dtvs_dynvars, sz);

		if (rval == 0)
			break;

		if (opt[DTRACEOPT_BUFRESIZE] == DTRACEOPT_BUFRESIZE_MANUAL)
			goto err;
	} while (sz >>= 1);

	opt[DTRACEOPT_DYNVARSIZE] = sz;

	if (rval != 0)
		goto err;

	if (opt[DTRACEOPT_STATUSRATE] > dtrace_statusrate_max)
		opt[DTRACEOPT_STATUSRATE] = dtrace_statusrate_max;

	if (opt[DTRACEOPT_CLEANRATE] == 0)
		opt[DTRACEOPT_CLEANRATE] = dtrace_cleanrate_max;

	if (opt[DTRACEOPT_CLEANRATE] < dtrace_cleanrate_min)
		opt[DTRACEOPT_CLEANRATE] = dtrace_cleanrate_min;

	if (opt[DTRACEOPT_CLEANRATE] > dtrace_cleanrate_max)
		opt[DTRACEOPT_CLEANRATE] = dtrace_cleanrate_max;

	if (opt[DTRACEOPT_STRSIZE] > dtrace_strsize_max)
		opt[DTRACEOPT_STRSIZE] = dtrace_strsize_max;

	if (opt[DTRACEOPT_STRSIZE] < dtrace_strsize_min)
		opt[DTRACEOPT_STRSIZE] = dtrace_strsize_min;

	if (opt[DTRACEOPT_BUFLIMIT] > dtrace_buflimit_max)
		opt[DTRACEOPT_BUFLIMIT] = dtrace_buflimit_max;

	if (opt[DTRACEOPT_BUFLIMIT] < dtrace_buflimit_min)
		opt[DTRACEOPT_BUFLIMIT] = dtrace_buflimit_min;

	hdlr.cyh_func = (cyc_func_t)dtrace_state_clean;
	hdlr.cyh_arg = state;
	hdlr.cyh_level = CY_LOW_LEVEL;

	when.cyt_when = 0;
	when.cyt_interval = opt[DTRACEOPT_CLEANRATE];

	state->dts_cleaner = cyclic_add(&hdlr, &when);

	hdlr.cyh_func = (cyc_func_t)dtrace_state_deadman;
	hdlr.cyh_arg = state;
	hdlr.cyh_level = CY_LOW_LEVEL;

	when.cyt_when = 0;
	when.cyt_interval = dtrace_deadman_interval;

	state->dts_alive = state->dts_laststatus = dtrace_gethrtime();
	state->dts_deadman = cyclic_add(&hdlr, &when);

	state->dts_activity = DTRACE_ACTIVITY_WARMUP;

	/*
	 * Now it's time to actually fire the BEGIN probe.  We need to disable
	 * interrupts here both to record the CPU on which we fired the BEGIN
	 * probe (the data from this CPU will be processed first at user
	 * level) and to manually activate the buffer for this CPU.
	 */
	cookie = dtrace_interrupt_disable();
	*cpu = CPU->cpu_id;
	ASSERT(state->dts_buffer[*cpu].dtb_flags & DTRACEBUF_INACTIVE);
	state->dts_buffer[*cpu].dtb_flags &= ~DTRACEBUF_INACTIVE;

	dtrace_probe(dtrace_probeid_begin,
	    (uint64_t)(uintptr_t)state, 0, 0, 0, 0);
	dtrace_interrupt_enable(cookie);
	/*
	 * We may have had an exit action from a BEGIN probe; only change our
	 * state to ACTIVE if we're still in WARMUP.
	 */
	ASSERT(state->dts_activity == DTRACE_ACTIVITY_WARMUP ||
	    state->dts_activity == DTRACE_ACTIVITY_DRAINING);

	if (state->dts_activity == DTRACE_ACTIVITY_WARMUP)
		state->dts_activity = DTRACE_ACTIVITY_ACTIVE;

	/*
	 * Regardless of whether or not now we're in ACTIVE or DRAINING, we
	 * want each CPU to transition its principal buffer out of the
	 * INACTIVE state.  Doing this assures that no CPU will suddenly begin
	 * processing an ECB halfway down a probe's ECB chain; all CPUs will
	 * atomically transition from processing none of a state's ECBs to
	 * processing all of them.
	 */
	dtrace_xcall(DTRACE_CPUALL,
	    (dtrace_xcall_t)dtrace_buffer_activate, state);
	goto out;

err:
	dtrace_buffer_free(state->dts_buffer);
	dtrace_buffer_free(state->dts_aggbuffer);

	if ((nspec = state->dts_nspeculations) == 0) {
		ASSERT(state->dts_speculations == NULL);
		goto out;
	}

	spec = state->dts_speculations;
	ASSERT(spec != NULL);

	for (i = 0; i < state->dts_nspeculations; i++) {
		if ((buf = spec[i].dtsp_buffer) == NULL)
			break;

		dtrace_buffer_free(buf);
		kmem_free(buf, bufsize);
	}

	kmem_free(spec, nspec * sizeof (dtrace_speculation_t));
	state->dts_nspeculations = 0;
	state->dts_speculations = NULL;

out:
	lck_mtx_unlock(&dtrace_lock);
	lck_mtx_unlock(&cpu_lock);

	return (rval);
}

static int
dtrace_state_stop(dtrace_state_t *state, processorid_t *cpu)
{
	dtrace_icookie_t cookie;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	if (state->dts_activity != DTRACE_ACTIVITY_ACTIVE &&
	    state->dts_activity != DTRACE_ACTIVITY_DRAINING)
		return (EINVAL);

	/*
	 * We'll set the activity to DTRACE_ACTIVITY_DRAINING, and issue a sync
	 * to be sure that every CPU has seen it.  See below for the details
	 * on why this is done.
	 */
	state->dts_activity = DTRACE_ACTIVITY_DRAINING;
	dtrace_sync();

	/*
	 * By this point, it is impossible for any CPU to be still processing
	 * with DTRACE_ACTIVITY_ACTIVE.  We can thus set our activity to
	 * DTRACE_ACTIVITY_COOLDOWN and know that we're not racing with any
	 * other CPU in dtrace_buffer_reserve().  This allows dtrace_probe()
	 * and callees to know that the activity is DTRACE_ACTIVITY_COOLDOWN
	 * iff we're in the END probe.
	 */
	state->dts_activity = DTRACE_ACTIVITY_COOLDOWN;
	dtrace_sync();
	ASSERT(state->dts_activity == DTRACE_ACTIVITY_COOLDOWN);

	/*
	 * Finally, we can release the reserve and call the END probe.  We
	 * disable interrupts across calling the END probe to allow us to
	 * return the CPU on which we actually called the END probe.  This
	 * allows user-land to be sure that this CPU's principal buffer is
	 * processed last.
	 */
	state->dts_reserve = 0;

	cookie = dtrace_interrupt_disable();
	*cpu = CPU->cpu_id;
	dtrace_probe(dtrace_probeid_end,
	    (uint64_t)(uintptr_t)state, 0, 0, 0, 0);
	dtrace_interrupt_enable(cookie);

	state->dts_activity = DTRACE_ACTIVITY_STOPPED;
	dtrace_sync();

	return (0);
}

static int
dtrace_state_option(dtrace_state_t *state, dtrace_optid_t option,
    dtrace_optval_t val)
{
	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	if (state->dts_activity != DTRACE_ACTIVITY_INACTIVE)
		return (EBUSY);

	if (option >= DTRACEOPT_MAX)
		return (EINVAL);

	if (option != DTRACEOPT_CPU && val < 0)
		return (EINVAL);

	switch (option) {
	case DTRACEOPT_DESTRUCTIVE:
		/*
		 * Prevent consumers from enabling destructive actions if DTrace
		 * is running in a restricted environment, or if actions are
		 * disallowed.
		 */
		if (dtrace_is_restricted() || dtrace_destructive_disallow)
			return (EACCES);

		state->dts_cred.dcr_destructive = 1;
		break;

	case DTRACEOPT_BUFSIZE:
	case DTRACEOPT_DYNVARSIZE:
	case DTRACEOPT_AGGSIZE:
	case DTRACEOPT_SPECSIZE:
	case DTRACEOPT_STRSIZE:
		if (val < 0)
			return (EINVAL);

		if (val >= LONG_MAX) {
			/*
			 * If this is an otherwise negative value, set it to
			 * the highest multiple of 128m less than LONG_MAX.
			 * Technically, we're adjusting the size without
			 * regard to the buffer resizing policy, but in fact,
			 * this has no effect -- if we set the buffer size to
			 * ~LONG_MAX and the buffer policy is ultimately set to
			 * be "manual", the buffer allocation is guaranteed to
			 * fail, if only because the allocation requires two
			 * buffers.  (We set the the size to the highest
			 * multiple of 128m because it ensures that the size
			 * will remain a multiple of a megabyte when
			 * repeatedly halved -- all the way down to 15m.)
			 */
			val = LONG_MAX - (1 << 27) + 1;
		}
	}

	state->dts_options[option] = val;

	return (0);
}

static void
dtrace_state_destroy(dtrace_state_t *state)
{
	dtrace_ecb_t *ecb;
	dtrace_vstate_t *vstate = &state->dts_vstate;
	minor_t minor = getminor(state->dts_dev);
	int i, bufsize = (int)NCPU * sizeof (dtrace_buffer_t);
	dtrace_speculation_t *spec = state->dts_speculations;
	int nspec = state->dts_nspeculations;
	uint32_t match;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	lck_mtx_assert(&cpu_lock, LCK_MTX_ASSERT_OWNED);

	/*
	 * First, retract any retained enablings for this state.
	 */
	dtrace_enabling_retract(state);
	ASSERT(state->dts_nretained == 0);

	if (state->dts_activity == DTRACE_ACTIVITY_ACTIVE ||
	    state->dts_activity == DTRACE_ACTIVITY_DRAINING) {
		/*
		 * We have managed to come into dtrace_state_destroy() on a
		 * hot enabling -- almost certainly because of a disorderly
		 * shutdown of a consumer.  (That is, a consumer that is
		 * exiting without having called dtrace_stop().) In this case,
		 * we're going to set our activity to be KILLED, and then
		 * issue a sync to be sure that everyone is out of probe
		 * context before we start blowing away ECBs.
		 */
		state->dts_activity = DTRACE_ACTIVITY_KILLED;
		dtrace_sync();
	}

	/*
	 * Release the credential hold we took in dtrace_state_create().
	 */
	if (state->dts_cred.dcr_cred != NULL)
		crfree(state->dts_cred.dcr_cred);

	/*
	 * Now we can safely disable and destroy any enabled probes.  Because
	 * any DTRACE_PRIV_KERNEL probes may actually be slowing our progress
	 * (especially if they're all enabled), we take two passes through the
	 * ECBs:  in the first, we disable just DTRACE_PRIV_KERNEL probes, and
	 * in the second we disable whatever is left over.
	 */
	for (match = DTRACE_PRIV_KERNEL; ; match = 0) {
		for (i = 0; i < state->dts_necbs; i++) {
			if ((ecb = state->dts_ecbs[i]) == NULL)
				continue;

			if (match && ecb->dte_probe != NULL) {
				dtrace_probe_t *probe = ecb->dte_probe;
				dtrace_provider_t *prov = probe->dtpr_provider;

				if (!(prov->dtpv_priv.dtpp_flags & match))
					continue;
			}

			dtrace_ecb_disable(ecb);
			dtrace_ecb_destroy(ecb);
		}

		if (!match)
			break;
	}

	/*
	 * Before we free the buffers, perform one more sync to assure that
	 * every CPU is out of probe context.
	 */
	dtrace_sync();

	dtrace_buffer_free(state->dts_buffer);
	dtrace_buffer_free(state->dts_aggbuffer);

	for (i = 0; i < nspec; i++)
		dtrace_buffer_free(spec[i].dtsp_buffer);

	if (state->dts_cleaner != CYCLIC_NONE)
		cyclic_remove(state->dts_cleaner);

	if (state->dts_deadman != CYCLIC_NONE)
		cyclic_remove(state->dts_deadman);

	dtrace_dstate_fini(&vstate->dtvs_dynvars);
	dtrace_vstate_fini(vstate);
	kmem_free(state->dts_ecbs, state->dts_necbs * sizeof (dtrace_ecb_t *));

	if (state->dts_aggregations != NULL) {
#if DEBUG
		for (i = 0; i < state->dts_naggregations; i++)
			ASSERT(state->dts_aggregations[i] == NULL);
#endif
		ASSERT(state->dts_naggregations > 0);
		kmem_free(state->dts_aggregations,
		    state->dts_naggregations * sizeof (dtrace_aggregation_t *));
	}

	kmem_free(state->dts_buffer, bufsize);
	kmem_free(state->dts_aggbuffer, bufsize);

	for (i = 0; i < nspec; i++)
		kmem_free(spec[i].dtsp_buffer, bufsize);

	kmem_free(spec, nspec * sizeof (dtrace_speculation_t));

	dtrace_format_destroy(state);

	vmem_destroy(state->dts_aggid_arena);
	dtrace_state_free(minor);
}

/*
 * DTrace Anonymous Enabling Functions
 */
static dtrace_state_t *
dtrace_anon_grab(void)
{
	dtrace_state_t *state;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	if ((state = dtrace_anon.dta_state) == NULL) {
		ASSERT(dtrace_anon.dta_enabling == NULL);
		return (NULL);
	}

	ASSERT(dtrace_anon.dta_enabling != NULL);
	ASSERT(dtrace_retained != NULL);

	dtrace_enabling_destroy(dtrace_anon.dta_enabling);
	dtrace_anon.dta_enabling = NULL;
	dtrace_anon.dta_state = NULL;

	return (state);
}

static void
dtrace_anon_property(void)
{
	int i, rv;
	dtrace_state_t *state;
	dof_hdr_t *dof;
	char c[32];		/* enough for "dof-data-" + digits */

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	lck_mtx_assert(&cpu_lock, LCK_MTX_ASSERT_OWNED);

	for (i = 0; ; i++) {
		(void) snprintf(c, sizeof (c), "dof-data-%d", i);

		dtrace_err_verbose = 1;

		if ((dof = dtrace_dof_property(c)) == NULL) {
			dtrace_err_verbose = 0;
			break;
		}

		/*
		 * We want to create anonymous state, so we need to transition
		 * the kernel debugger to indicate that DTrace is active.  If
		 * this fails (e.g. because the debugger has modified text in
		 * some way), we won't continue with the processing.
		 */
		if (kdi_dtrace_set(KDI_DTSET_DTRACE_ACTIVATE) != 0) {
			cmn_err(CE_NOTE, "kernel debugger active; anonymous "
			    "enabling ignored.");
			dtrace_dof_destroy(dof);
			break;
		}

		/*
		 * If we haven't allocated an anonymous state, we'll do so now.
		 */
		if ((state = dtrace_anon.dta_state) == NULL) {
			rv = dtrace_state_create(NULL, NULL, &state);
			dtrace_anon.dta_state = state;
			if (rv != 0 || state == NULL) {
				/*
				 * This basically shouldn't happen:  the only
				 * failure mode from dtrace_state_create() is a
				 * failure of ddi_soft_state_zalloc() that
				 * itself should never happen.  Still, the
				 * interface allows for a failure mode, and
				 * we want to fail as gracefully as possible:
				 * we'll emit an error message and cease
				 * processing anonymous state in this case.
				 */
				cmn_err(CE_WARN, "failed to create "
				    "anonymous state");
				dtrace_dof_destroy(dof);
				break;
			}
		}

		rv = dtrace_dof_slurp(dof, &state->dts_vstate, CRED(),
		    &dtrace_anon.dta_enabling, 0, B_TRUE);

		if (rv == 0)
			rv = dtrace_dof_options(dof, state);

		dtrace_err_verbose = 0;
		dtrace_dof_destroy(dof);

		if (rv != 0) {
			/*
			 * This is malformed DOF; chuck any anonymous state
			 * that we created.
			 */
			ASSERT(dtrace_anon.dta_enabling == NULL);
			dtrace_state_destroy(state);
			dtrace_anon.dta_state = NULL;
			break;
		}

		ASSERT(dtrace_anon.dta_enabling != NULL);
	}

	if (dtrace_anon.dta_enabling != NULL) {
		int rval;

		/*
		 * dtrace_enabling_retain() can only fail because we are
		 * trying to retain more enablings than are allowed -- but
		 * we only have one anonymous enabling, and we are guaranteed
		 * to be allowed at least one retained enabling; we assert
		 * that dtrace_enabling_retain() returns success.
		 */
		rval = dtrace_enabling_retain(dtrace_anon.dta_enabling);
		ASSERT(rval == 0);

		dtrace_enabling_dump(dtrace_anon.dta_enabling);
	}
}

/*
 * DTrace Helper Functions
 */
static void
dtrace_helper_trace(dtrace_helper_action_t *helper,
    dtrace_mstate_t *mstate, dtrace_vstate_t *vstate, int where)
{
	uint32_t size, next, nnext;
	int i;
	dtrace_helptrace_t *ent;
	uint16_t flags = cpu_core[CPU->cpu_id].cpuc_dtrace_flags;

	if (!dtrace_helptrace_enabled)
		return;

	ASSERT((uint32_t)vstate->dtvs_nlocals <= dtrace_helptrace_nlocals);

	/*
	 * What would a tracing framework be without its own tracing
	 * framework?  (Well, a hell of a lot simpler, for starters...)
	 */
	size = sizeof (dtrace_helptrace_t) + dtrace_helptrace_nlocals *
	    sizeof (uint64_t) - sizeof (uint64_t);

	/*
	 * Iterate until we can allocate a slot in the trace buffer.
	 */
	do {
		next = dtrace_helptrace_next;

		if (next + size < dtrace_helptrace_bufsize) {
			nnext = next + size;
		} else {
			nnext = size;
		}
	} while (dtrace_cas32(&dtrace_helptrace_next, next, nnext) != next);

	/*
	 * We have our slot; fill it in.
	 */
	if (nnext == size)
		next = 0;

	ent = (dtrace_helptrace_t *)&dtrace_helptrace_buffer[next];
	ent->dtht_helper = helper;
	ent->dtht_where = where;
	ent->dtht_nlocals = vstate->dtvs_nlocals;

	ent->dtht_fltoffs = (mstate->dtms_present & DTRACE_MSTATE_FLTOFFS) ?
	    mstate->dtms_fltoffs : -1;
	ent->dtht_fault = DTRACE_FLAGS2FLT(flags);
	ent->dtht_illval = cpu_core[CPU->cpu_id].cpuc_dtrace_illval;

	for (i = 0; i < vstate->dtvs_nlocals; i++) {
		dtrace_statvar_t *svar;

		if ((svar = vstate->dtvs_locals[i]) == NULL)
			continue;

		ASSERT(svar->dtsv_size >= (int)NCPU * sizeof (uint64_t));
		ent->dtht_locals[i] =
		    ((uint64_t *)(uintptr_t)svar->dtsv_data)[CPU->cpu_id];
	}
}

static uint64_t
dtrace_helper(int which, dtrace_mstate_t *mstate,
    dtrace_state_t *state, uint64_t arg0, uint64_t arg1)
{
	uint16_t *flags = &cpu_core[CPU->cpu_id].cpuc_dtrace_flags;
	uint64_t sarg0 = mstate->dtms_arg[0];
	uint64_t sarg1 = mstate->dtms_arg[1];
	uint64_t rval = 0;
	dtrace_helpers_t *helpers = curproc->p_dtrace_helpers;
	dtrace_helper_action_t *helper;
	dtrace_vstate_t *vstate;
	dtrace_difo_t *pred;
	int i, trace = dtrace_helptrace_enabled;

	ASSERT(which >= 0 && which < DTRACE_NHELPER_ACTIONS);

	if (helpers == NULL)
		return (0);

	if ((helper = helpers->dthps_actions[which]) == NULL)
		return (0);

	vstate = &helpers->dthps_vstate;
	mstate->dtms_arg[0] = arg0;
	mstate->dtms_arg[1] = arg1;

	/*
	 * Now iterate over each helper.  If its predicate evaluates to 'true',
	 * we'll call the corresponding actions.  Note that the below calls
	 * to dtrace_dif_emulate() may set faults in machine state.  This is
	 * okay:  our caller (the outer dtrace_dif_emulate()) will simply plow
	 * the stored DIF offset with its own (which is the desired behavior).
	 * Also, note the calls to dtrace_dif_emulate() may allocate scratch
	 * from machine state; this is okay, too.
	 */
	for (; helper != NULL; helper = helper->dtha_next) {
		if ((pred = helper->dtha_predicate) != NULL) {
			if (trace)
				dtrace_helper_trace(helper, mstate, vstate, 0);

			if (!dtrace_dif_emulate(pred, mstate, vstate, state))
				goto next;

			if (*flags & CPU_DTRACE_FAULT)
				goto err;
		}

		for (i = 0; i < helper->dtha_nactions; i++) {
			if (trace)
				dtrace_helper_trace(helper,
				    mstate, vstate, i + 1);

			rval = dtrace_dif_emulate(helper->dtha_actions[i],
			    mstate, vstate, state);

			if (*flags & CPU_DTRACE_FAULT)
				goto err;
		}

next:
		if (trace)
			dtrace_helper_trace(helper, mstate, vstate,
			    DTRACE_HELPTRACE_NEXT);
	}

	if (trace)
		dtrace_helper_trace(helper, mstate, vstate,
		    DTRACE_HELPTRACE_DONE);

	/*
	 * Restore the arg0 that we saved upon entry.
	 */
	mstate->dtms_arg[0] = sarg0;
	mstate->dtms_arg[1] = sarg1;

	return (rval);

err:
	if (trace)
		dtrace_helper_trace(helper, mstate, vstate,
		    DTRACE_HELPTRACE_ERR);

	/*
	 * Restore the arg0 that we saved upon entry.
	 */
	mstate->dtms_arg[0] = sarg0;
	mstate->dtms_arg[1] = sarg1;

	return (0);
}

static void
dtrace_helper_action_destroy(dtrace_helper_action_t *helper,
    dtrace_vstate_t *vstate)
{
	int i;

	if (helper->dtha_predicate != NULL)
		dtrace_difo_release(helper->dtha_predicate, vstate);

	for (i = 0; i < helper->dtha_nactions; i++) {
		ASSERT(helper->dtha_actions[i] != NULL);
		dtrace_difo_release(helper->dtha_actions[i], vstate);
	}

	kmem_free(helper->dtha_actions,
	    helper->dtha_nactions * sizeof (dtrace_difo_t *));
	kmem_free(helper, sizeof (dtrace_helper_action_t));
}

static int
dtrace_helper_destroygen(proc_t* p, int gen)
{
	dtrace_helpers_t *help = p->p_dtrace_helpers;
	dtrace_vstate_t *vstate;
	uint_t i;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	if (help == NULL || gen > help->dthps_generation)
		return (EINVAL);

	vstate = &help->dthps_vstate;

	for (i = 0; i < DTRACE_NHELPER_ACTIONS; i++) {
		dtrace_helper_action_t *last = NULL, *h, *next;

		for (h = help->dthps_actions[i]; h != NULL; h = next) {
			next = h->dtha_next;

			if (h->dtha_generation == gen) {
				if (last != NULL) {
					last->dtha_next = next;
				} else {
					help->dthps_actions[i] = next;
				}

				dtrace_helper_action_destroy(h, vstate);
			} else {
				last = h;
			}
		}
	}

	/*
	 * Interate until we've cleared out all helper providers with the
	 * given generation number.
	 */
	for (;;) {
		dtrace_helper_provider_t *prov = NULL;

		/*
		 * Look for a helper provider with the right generation. We
		 * have to start back at the beginning of the list each time
		 * because we drop dtrace_lock. It's unlikely that we'll make
		 * more than two passes.
		 */
		for (i = 0; i < help->dthps_nprovs; i++) {
			prov = help->dthps_provs[i];

			if (prov->dthp_generation == gen)
				break;
		}

		/*
		 * If there were no matches, we're done.
		 */
		if (i == help->dthps_nprovs)
			break;

		/*
		 * Move the last helper provider into this slot.
		 */
		help->dthps_nprovs--;
		help->dthps_provs[i] = help->dthps_provs[help->dthps_nprovs];
		help->dthps_provs[help->dthps_nprovs] = NULL;

		lck_mtx_unlock(&dtrace_lock);

		/*
		 * If we have a meta provider, remove this helper provider.
		 */
		lck_mtx_lock(&dtrace_meta_lock);
		if (dtrace_meta_pid != NULL) {
			ASSERT(dtrace_deferred_pid == NULL);
			dtrace_helper_provider_remove(&prov->dthp_prov,
			    p->p_pid);
		}
		lck_mtx_unlock(&dtrace_meta_lock);

		dtrace_helper_provider_destroy(prov);

		lck_mtx_lock(&dtrace_lock);
	}

	return (0);
}

static int
dtrace_helper_validate(dtrace_helper_action_t *helper)
{
	int err = 0, i;
	dtrace_difo_t *dp;

	if ((dp = helper->dtha_predicate) != NULL)
		err += dtrace_difo_validate_helper(dp);

	for (i = 0; i < helper->dtha_nactions; i++)
		err += dtrace_difo_validate_helper(helper->dtha_actions[i]);

	return (err == 0);
}

static int
dtrace_helper_action_add(proc_t* p, int which, dtrace_ecbdesc_t *ep)
{
	dtrace_helpers_t *help;
	dtrace_helper_action_t *helper, *last;
	dtrace_actdesc_t *act;
	dtrace_vstate_t *vstate;
	dtrace_predicate_t *pred;
	int count = 0, nactions = 0, i;

	if (which < 0 || which >= DTRACE_NHELPER_ACTIONS)
		return (EINVAL);

	help = p->p_dtrace_helpers;
	last = help->dthps_actions[which];
	vstate = &help->dthps_vstate;

	for (count = 0; last != NULL; last = last->dtha_next) {
		count++;
		if (last->dtha_next == NULL)
			break;
	}

	/*
	 * If we already have dtrace_helper_actions_max helper actions for this
	 * helper action type, we'll refuse to add a new one.
	 */
	if (count >= dtrace_helper_actions_max)
		return (ENOSPC);

	helper = kmem_zalloc(sizeof (dtrace_helper_action_t), KM_SLEEP);
	helper->dtha_generation = help->dthps_generation;

	if ((pred = ep->dted_pred.dtpdd_predicate) != NULL) {
		ASSERT(pred->dtp_difo != NULL);
		dtrace_difo_hold(pred->dtp_difo);
		helper->dtha_predicate = pred->dtp_difo;
	}

	for (act = ep->dted_action; act != NULL; act = act->dtad_next) {
		if (act->dtad_kind != DTRACEACT_DIFEXPR)
			goto err;

		if (act->dtad_difo == NULL)
			goto err;

		nactions++;
	}

	helper->dtha_actions = kmem_zalloc(sizeof (dtrace_difo_t *) *
	    (helper->dtha_nactions = nactions), KM_SLEEP);

	for (act = ep->dted_action, i = 0; act != NULL; act = act->dtad_next) {
		dtrace_difo_hold(act->dtad_difo);
		helper->dtha_actions[i++] = act->dtad_difo;
	}

	if (!dtrace_helper_validate(helper))
		goto err;

	if (last == NULL) {
		help->dthps_actions[which] = helper;
	} else {
		last->dtha_next = helper;
	}

	if ((uint32_t)vstate->dtvs_nlocals > dtrace_helptrace_nlocals) {
		dtrace_helptrace_nlocals = vstate->dtvs_nlocals;
		dtrace_helptrace_next = 0;
	}

	return (0);
err:
	dtrace_helper_action_destroy(helper, vstate);
	return (EINVAL);
}

static void
dtrace_helper_provider_register(proc_t *p, dtrace_helpers_t *help,
    dof_helper_t *dofhp)
{
	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_NOTOWNED);

	lck_mtx_lock(&dtrace_meta_lock);
	lck_mtx_lock(&dtrace_lock);

	if (!dtrace_attached() || dtrace_meta_pid == NULL) {
		/*
		 * If the dtrace module is loaded but not attached, or if
		 * there aren't isn't a meta provider registered to deal with
		 * these provider descriptions, we need to postpone creating
		 * the actual providers until later.
		 */

		if (help->dthps_next == NULL && help->dthps_prev == NULL &&
		    dtrace_deferred_pid != help) {
			help->dthps_deferred = 1;
			help->dthps_pid = p->p_pid;
			help->dthps_next = dtrace_deferred_pid;
			help->dthps_prev = NULL;
			if (dtrace_deferred_pid != NULL)
				dtrace_deferred_pid->dthps_prev = help;
			dtrace_deferred_pid = help;
		}

		lck_mtx_unlock(&dtrace_lock);

	} else if (dofhp != NULL) {
		/*
		 * If the dtrace module is loaded and we have a particular
		 * helper provider description, pass that off to the
		 * meta provider.
		 */

		lck_mtx_unlock(&dtrace_lock);

		dtrace_helper_provide(dofhp, p->p_pid);

	} else {
		/*
		 * Otherwise, just pass all the helper provider descriptions
		 * off to the meta provider.
		 */

		uint_t i;
		lck_mtx_unlock(&dtrace_lock);

		for (i = 0; i < help->dthps_nprovs; i++) {
			dtrace_helper_provide(&help->dthps_provs[i]->dthp_prov,
			    p->p_pid);
		}
	}

	lck_mtx_unlock(&dtrace_meta_lock);
}

static int
dtrace_helper_provider_add(proc_t* p, dof_helper_t *dofhp, int gen)
{
	dtrace_helpers_t *help;
	dtrace_helper_provider_t *hprov, **tmp_provs;
	uint_t tmp_maxprovs, i;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	help = p->p_dtrace_helpers;
	ASSERT(help != NULL);

	/*
	 * If we already have dtrace_helper_providers_max helper providers,
	 * we're refuse to add a new one.
	 */
	if (help->dthps_nprovs >= dtrace_helper_providers_max)
		return (ENOSPC);

	/*
	 * Check to make sure this isn't a duplicate.
	 */
	for (i = 0; i < help->dthps_nprovs; i++) {
		if (dofhp->dofhp_addr ==
		    help->dthps_provs[i]->dthp_prov.dofhp_addr)
			return (EALREADY);
	}

	hprov = kmem_zalloc(sizeof (dtrace_helper_provider_t), KM_SLEEP);
	hprov->dthp_prov = *dofhp;
	hprov->dthp_ref = 1;
	hprov->dthp_generation = gen;

	/*
	 * Allocate a bigger table for helper providers if it's already full.
	 */
	if (help->dthps_maxprovs == help->dthps_nprovs) {
		tmp_maxprovs = help->dthps_maxprovs;
		tmp_provs = help->dthps_provs;

		if (help->dthps_maxprovs == 0)
			help->dthps_maxprovs = 2;
		else
			help->dthps_maxprovs *= 2;
		if (help->dthps_maxprovs > dtrace_helper_providers_max)
			help->dthps_maxprovs = dtrace_helper_providers_max;

		ASSERT(tmp_maxprovs < help->dthps_maxprovs);

		help->dthps_provs = kmem_zalloc(help->dthps_maxprovs *
		    sizeof (dtrace_helper_provider_t *), KM_SLEEP);

		if (tmp_provs != NULL) {
			bcopy(tmp_provs, help->dthps_provs, tmp_maxprovs *
			    sizeof (dtrace_helper_provider_t *));
			kmem_free(tmp_provs, tmp_maxprovs *
			    sizeof (dtrace_helper_provider_t *));
		}
	}

	help->dthps_provs[help->dthps_nprovs] = hprov;
	help->dthps_nprovs++;

	return (0);
}

static void
dtrace_helper_provider_destroy(dtrace_helper_provider_t *hprov)
{
	lck_mtx_lock(&dtrace_lock);

	if (--hprov->dthp_ref == 0) {
		dof_hdr_t *dof;
		lck_mtx_unlock(&dtrace_lock);
		dof = (dof_hdr_t *)(uintptr_t)hprov->dthp_prov.dofhp_dof;
		dtrace_dof_destroy(dof);
		kmem_free(hprov, sizeof (dtrace_helper_provider_t));
	} else {
		lck_mtx_unlock(&dtrace_lock);
	}
}

static int
dtrace_helper_provider_validate(dof_hdr_t *dof, dof_sec_t *sec)
{
	uintptr_t daddr = (uintptr_t)dof;
	dof_sec_t *str_sec, *prb_sec, *arg_sec, *off_sec, *enoff_sec;
	dof_provider_t *provider;
	dof_probe_t *probe;
	uint8_t *arg;
	char *strtab, *typestr;
	dof_stridx_t typeidx;
	size_t typesz;
	uint_t nprobes, j, k;

	ASSERT(sec->dofs_type == DOF_SECT_PROVIDER);

	if (sec->dofs_offset & (sizeof (uint_t) - 1)) {
		dtrace_dof_error(dof, "misaligned section offset");
		return (-1);
	}

	/*
	 * The section needs to be large enough to contain the DOF provider
	 * structure appropriate for the given version.
	 */
	if (sec->dofs_size <
	    ((dof->dofh_ident[DOF_ID_VERSION] == DOF_VERSION_1) ?
	    offsetof(dof_provider_t, dofpv_prenoffs) :
	    sizeof (dof_provider_t))) {
		dtrace_dof_error(dof, "provider section too small");
		return (-1);
	}

	provider = (dof_provider_t *)(uintptr_t)(daddr + sec->dofs_offset);
	str_sec = dtrace_dof_sect(dof, DOF_SECT_STRTAB, provider->dofpv_strtab);
	prb_sec = dtrace_dof_sect(dof, DOF_SECT_PROBES, provider->dofpv_probes);
	arg_sec = dtrace_dof_sect(dof, DOF_SECT_PRARGS, provider->dofpv_prargs);
	off_sec = dtrace_dof_sect(dof, DOF_SECT_PROFFS, provider->dofpv_proffs);

	if (str_sec == NULL || prb_sec == NULL ||
	    arg_sec == NULL || off_sec == NULL)
		return (-1);

	enoff_sec = NULL;

	if (dof->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_1 &&
	    provider->dofpv_prenoffs != DOF_SECT_NONE &&
	    (enoff_sec = dtrace_dof_sect(dof, DOF_SECT_PRENOFFS,
	    provider->dofpv_prenoffs)) == NULL)
		return (-1);

	strtab = (char *)(uintptr_t)(daddr + str_sec->dofs_offset);

	if (provider->dofpv_name >= str_sec->dofs_size ||
	    strlen(strtab + provider->dofpv_name) >= DTRACE_PROVNAMELEN) {
		dtrace_dof_error(dof, "invalid provider name");
		return (-1);
	}

	if (prb_sec->dofs_entsize == 0 ||
	    prb_sec->dofs_entsize > prb_sec->dofs_size) {
		dtrace_dof_error(dof, "invalid entry size");
		return (-1);
	}

	if (prb_sec->dofs_entsize & (sizeof (uintptr_t) - 1)) {
		dtrace_dof_error(dof, "misaligned entry size");
		return (-1);
	}

	if (off_sec->dofs_entsize != sizeof (uint32_t)) {
		dtrace_dof_error(dof, "invalid entry size");
		return (-1);
	}

	if (off_sec->dofs_offset & (sizeof (uint32_t) - 1)) {
		dtrace_dof_error(dof, "misaligned section offset");
		return (-1);
	}

	if (arg_sec->dofs_entsize != sizeof (uint8_t)) {
		dtrace_dof_error(dof, "invalid entry size");
		return (-1);
	}

	arg = (uint8_t *)(uintptr_t)(daddr + arg_sec->dofs_offset);

	nprobes = prb_sec->dofs_size / prb_sec->dofs_entsize;

	/*
	 * Take a pass through the probes to check for errors.
	 */
	for (j = 0; j < nprobes; j++) {
		probe = (dof_probe_t *)(uintptr_t)(daddr +
		    prb_sec->dofs_offset + j * prb_sec->dofs_entsize);

		if (probe->dofpr_func >= str_sec->dofs_size) {
			dtrace_dof_error(dof, "invalid function name");
			return (-1);
		}

		if (strlen(strtab + probe->dofpr_func) >= DTRACE_FUNCNAMELEN) {
			dtrace_dof_error(dof, "function name too long");
			return (-1);
		}

		if (probe->dofpr_name >= str_sec->dofs_size ||
		    strlen(strtab + probe->dofpr_name) >= DTRACE_NAMELEN) {
			dtrace_dof_error(dof, "invalid probe name");
			return (-1);
		}

		/*
		 * The offset count must not wrap the index, and the offsets
		 * must also not overflow the section's data.
		 */
		if (probe->dofpr_offidx + probe->dofpr_noffs <
		    probe->dofpr_offidx ||
		    (probe->dofpr_offidx + probe->dofpr_noffs) *
		    off_sec->dofs_entsize > off_sec->dofs_size) {
			dtrace_dof_error(dof, "invalid probe offset");
			return (-1);
		}

		if (dof->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_1) {
			/*
			 * If there's no is-enabled offset section, make sure
			 * there aren't any is-enabled offsets. Otherwise
			 * perform the same checks as for probe offsets
			 * (immediately above).
			 */
			if (enoff_sec == NULL) {
				if (probe->dofpr_enoffidx != 0 ||
				    probe->dofpr_nenoffs != 0) {
					dtrace_dof_error(dof, "is-enabled "
					    "offsets with null section");
					return (-1);
				}
			} else if (probe->dofpr_enoffidx +
			    probe->dofpr_nenoffs < probe->dofpr_enoffidx ||
			    (probe->dofpr_enoffidx + probe->dofpr_nenoffs) *
			    enoff_sec->dofs_entsize > enoff_sec->dofs_size) {
				dtrace_dof_error(dof, "invalid is-enabled "
				    "offset");
				return (-1);
			}

			if (probe->dofpr_noffs + probe->dofpr_nenoffs == 0) {
				dtrace_dof_error(dof, "zero probe and "
				    "is-enabled offsets");
				return (-1);
			}
		} else if (probe->dofpr_noffs == 0) {
			dtrace_dof_error(dof, "zero probe offsets");
			return (-1);
		}

		if (probe->dofpr_argidx + probe->dofpr_xargc <
		    probe->dofpr_argidx ||
		    (probe->dofpr_argidx + probe->dofpr_xargc) *
		    arg_sec->dofs_entsize > arg_sec->dofs_size) {
			dtrace_dof_error(dof, "invalid args");
			return (-1);
		}

		typeidx = probe->dofpr_nargv;
		typestr = strtab + probe->dofpr_nargv;
		for (k = 0; k < probe->dofpr_nargc; k++) {
			if (typeidx >= str_sec->dofs_size) {
				dtrace_dof_error(dof, "bad "
				    "native argument type");
				return (-1);
			}

			typesz = strlen(typestr) + 1;
			if (typesz > DTRACE_ARGTYPELEN) {
				dtrace_dof_error(dof, "native "
				    "argument type too long");
				return (-1);
			}
			typeidx += typesz;
			typestr += typesz;
		}

		typeidx = probe->dofpr_xargv;
		typestr = strtab + probe->dofpr_xargv;
		for (k = 0; k < probe->dofpr_xargc; k++) {
			if (arg[probe->dofpr_argidx + k] > probe->dofpr_nargc) {
				dtrace_dof_error(dof, "bad "
				    "native argument index");
				return (-1);
			}

			if (typeidx >= str_sec->dofs_size) {
				dtrace_dof_error(dof, "bad "
				    "translated argument type");
				return (-1);
			}

			typesz = strlen(typestr) + 1;
			if (typesz > DTRACE_ARGTYPELEN) {
				dtrace_dof_error(dof, "translated argument "
				    "type too long");
				return (-1);
			}

			typeidx += typesz;
			typestr += typesz;
		}
	}

	return (0);
}

static int
dtrace_helper_slurp(proc_t* p, dof_hdr_t *dof, dof_helper_t *dhp)
{
	dtrace_helpers_t *help;
	dtrace_vstate_t *vstate;
	dtrace_enabling_t *enab = NULL;
	int i, gen, rv, nhelpers = 0, nprovs = 0, destroy = 1;
	uintptr_t daddr = (uintptr_t)dof;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);

	if ((help = p->p_dtrace_helpers) == NULL)
		help = dtrace_helpers_create(p);

	vstate = &help->dthps_vstate;

	if ((rv = dtrace_dof_slurp(dof, vstate, NULL, &enab,
	    dhp != NULL ? dhp->dofhp_addr : 0, B_FALSE)) != 0) {
		dtrace_dof_destroy(dof);
		return (rv);
	}

	/*
	 * Look for helper providers and validate their descriptions.
	 */
	if (dhp != NULL) {
		for (i = 0; (uint32_t)i < dof->dofh_secnum; i++) {
			dof_sec_t *sec = (dof_sec_t *)(uintptr_t)(daddr +
			    dof->dofh_secoff + i * dof->dofh_secsize);

			if (sec->dofs_type != DOF_SECT_PROVIDER)
				continue;

			if (dtrace_helper_provider_validate(dof, sec) != 0) {
				dtrace_enabling_destroy(enab);
				dtrace_dof_destroy(dof);
				return (-1);
			}

			nprovs++;
		}
	}

	/*
	 * Now we need to walk through the ECB descriptions in the enabling.
	 */
	for (i = 0; i < enab->dten_ndesc; i++) {
		dtrace_ecbdesc_t *ep = enab->dten_desc[i];
		dtrace_probedesc_t *desc = &ep->dted_probe;

		/* APPLE NOTE: Darwin employs size bounded string operation. */
		if (!LIT_STRNEQL(desc->dtpd_provider, "dtrace"))
			continue;

		if (!LIT_STRNEQL(desc->dtpd_mod, "helper"))
			continue;

		if (!LIT_STRNEQL(desc->dtpd_func, "ustack"))
			continue;

		if ((rv = dtrace_helper_action_add(p, DTRACE_HELPER_ACTION_USTACK,
		    ep)) != 0) {
			/*
			 * Adding this helper action failed -- we are now going
			 * to rip out the entire generation and return failure.
			 */
			(void) dtrace_helper_destroygen(p, help->dthps_generation);
			dtrace_enabling_destroy(enab);
			dtrace_dof_destroy(dof);
			return (-1);
		}

		nhelpers++;
	}

	if (nhelpers < enab->dten_ndesc)
		dtrace_dof_error(dof, "unmatched helpers");

	gen = help->dthps_generation++;
	dtrace_enabling_destroy(enab);

	if (dhp != NULL && nprovs > 0) {
		dhp->dofhp_dof = (uint64_t)(uintptr_t)dof;
		if (dtrace_helper_provider_add(p, dhp, gen) == 0) {
			lck_mtx_unlock(&dtrace_lock);
			dtrace_helper_provider_register(p, help, dhp);
			lck_mtx_lock(&dtrace_lock);

			destroy = 0;
		}
	}

	if (destroy)
		dtrace_dof_destroy(dof);

	return (gen);
}

/*
 * APPLE NOTE:  DTrace lazy dof implementation
 *
 * DTrace user static probes (USDT probes) and helper actions are loaded
 * in a process by proccessing dof sections. The dof sections are passed
 * into the kernel by dyld, in a dof_ioctl_data_t block. It is rather
 * expensive to process dof for a process that will never use it. There
 * is a memory cost (allocating the providers/probes), and a cpu cost
 * (creating the providers/probes).
 *
 * To reduce this cost, we use "lazy dof". The normal proceedure for
 * dof processing is to copyin the dof(s) pointed to by the dof_ioctl_data_t
 * block, and invoke dof_slurp_helper() on them. When "lazy dof" is
 * used, each process retains the dof_ioctl_data_t block, instead of
 * copying in the data it points to.
 *
 * The dof_ioctl_data_t blocks are managed as if they were the actual
 * processed dof; on fork the block is copied to the child, on exec and
 * exit the block is freed.
 *
 * If the process loads library(s) containing additional dof, the
 * new dof_ioctl_data_t is merged with the existing block.
 *
 * There are a few catches that make this slightly more difficult.
 * When dyld registers dof_ioctl_data_t blocks, it expects a unique
 * identifier value for each dof in the block. In non-lazy dof terms,
 * this is the generation that dof was loaded in. If we hand back
 * a UID for a lazy dof, that same UID must be able to unload the
 * dof once it has become non-lazy. To meet this requirement, the
 * code that loads lazy dof requires that the UID's for dof(s) in
 * the lazy dof be sorted, and in ascending order. It is okay to skip
 * UID's, I.E., 1 -> 5 -> 6 is legal.
 *
 * Once a process has become non-lazy, it will stay non-lazy. All
 * future dof operations for that process will be non-lazy, even
 * if the dof mode transitions back to lazy.
 *
 * Always do lazy dof checks before non-lazy (I.E. In fork, exit, exec.).
 * That way if the lazy check fails due to transitioning to non-lazy, the
 * right thing is done with the newly faulted in dof.
 */

/*
 * This method is a bit squicky. It must handle:
 *
 * dof should not be lazy.
 * dof should have been handled lazily, but there was an error
 * dof was handled lazily, and needs to be freed.
 * dof was handled lazily, and must not be freed.
 *
 * 
 * Returns EACCESS if dof should be handled non-lazily.
 * 
 * KERN_SUCCESS and all other return codes indicate lazy handling of dof.
 * 
 * If the dofs data is claimed by this method, dofs_claimed will be set.
 * Callers should not free claimed dofs.
 */
static int
dtrace_lazy_dofs_add(proc_t *p, dof_ioctl_data_t* incoming_dofs, int *dofs_claimed)
{
	ASSERT(p);
	ASSERT(incoming_dofs && incoming_dofs->dofiod_count > 0);

	int rval = 0;
	*dofs_claimed = 0;

	lck_rw_lock_shared(&dtrace_dof_mode_lock);

	ASSERT(p->p_dtrace_lazy_dofs == NULL || p->p_dtrace_helpers == NULL);
	ASSERT(dtrace_dof_mode != DTRACE_DOF_MODE_NEVER);

	/*
	 * Any existing helpers force non-lazy behavior.
	 */
	if (dtrace_dof_mode == DTRACE_DOF_MODE_LAZY_ON && (p->p_dtrace_helpers == NULL)) {
		lck_mtx_lock(&p->p_dtrace_sprlock);

		dof_ioctl_data_t* existing_dofs = p->p_dtrace_lazy_dofs;
		unsigned int existing_dofs_count = (existing_dofs) ? existing_dofs->dofiod_count : 0;
		unsigned int i, merged_dofs_count = incoming_dofs->dofiod_count + existing_dofs_count;

		/*
		 * Range check...
		 */
		if (merged_dofs_count == 0 || merged_dofs_count > 1024) {
			dtrace_dof_error(NULL, "lazy_dofs_add merged_dofs_count out of range");
			rval = EINVAL;
			goto unlock;
		}
		
		/*
		 * Each dof being added must be assigned a unique generation.
		 */
		uint64_t generation = (existing_dofs) ? existing_dofs->dofiod_helpers[existing_dofs_count - 1].dofhp_dof + 1 : 1;
		for (i=0; i<incoming_dofs->dofiod_count; i++) {
			/*
			 * We rely on these being the same so we can overwrite dofhp_dof and not lose info.
			 */
			ASSERT(incoming_dofs->dofiod_helpers[i].dofhp_dof == incoming_dofs->dofiod_helpers[i].dofhp_addr);
			incoming_dofs->dofiod_helpers[i].dofhp_dof = generation++;
		}

		
		if (existing_dofs) {
			/*
			 * Merge the existing and incoming dofs
			 */
			size_t merged_dofs_size = DOF_IOCTL_DATA_T_SIZE(merged_dofs_count);
			dof_ioctl_data_t* merged_dofs = kmem_alloc(merged_dofs_size, KM_SLEEP);

			bcopy(&existing_dofs->dofiod_helpers[0],
			      &merged_dofs->dofiod_helpers[0],
			      sizeof(dof_helper_t) * existing_dofs_count);
			bcopy(&incoming_dofs->dofiod_helpers[0],
			      &merged_dofs->dofiod_helpers[existing_dofs_count],
			      sizeof(dof_helper_t) * incoming_dofs->dofiod_count);

			merged_dofs->dofiod_count = merged_dofs_count;

			kmem_free(existing_dofs, DOF_IOCTL_DATA_T_SIZE(existing_dofs_count));

			p->p_dtrace_lazy_dofs = merged_dofs;
		} else {
			/*
			 * Claim the incoming dofs
			 */
			*dofs_claimed = 1;
			p->p_dtrace_lazy_dofs = incoming_dofs;
		}

#if DEBUG
		dof_ioctl_data_t* all_dofs = p->p_dtrace_lazy_dofs;
		for (i=0; i<all_dofs->dofiod_count-1; i++) {
			ASSERT(all_dofs->dofiod_helpers[i].dofhp_dof < all_dofs->dofiod_helpers[i+1].dofhp_dof);
		}
#endif /* DEBUG */

unlock:
		lck_mtx_unlock(&p->p_dtrace_sprlock);
	} else {
		rval = EACCES;
	}

 	lck_rw_unlock_shared(&dtrace_dof_mode_lock);

	return rval;
}

/*
 * Returns:
 *
 * EINVAL: lazy dof is enabled, but the requested generation was not found.
 * EACCES: This removal needs to be handled non-lazily. 
 */
static int
dtrace_lazy_dofs_remove(proc_t *p, int generation)
{
	int rval = EINVAL;

	lck_rw_lock_shared(&dtrace_dof_mode_lock);

	ASSERT(p->p_dtrace_lazy_dofs == NULL || p->p_dtrace_helpers == NULL);
	ASSERT(dtrace_dof_mode != DTRACE_DOF_MODE_NEVER);

	/*
	 * Any existing helpers force non-lazy behavior.
	 */
	if (dtrace_dof_mode == DTRACE_DOF_MODE_LAZY_ON && (p->p_dtrace_helpers == NULL)) {
		lck_mtx_lock(&p->p_dtrace_sprlock);

		dof_ioctl_data_t* existing_dofs = p->p_dtrace_lazy_dofs;
		
		if (existing_dofs) {		
			int index, existing_dofs_count = existing_dofs->dofiod_count;
			for (index=0; index<existing_dofs_count; index++) {
				if ((int)existing_dofs->dofiod_helpers[index].dofhp_dof == generation) {
					dof_ioctl_data_t* removed_dofs = NULL;
				
					/*
					 * If there is only 1 dof, we'll delete it and swap in NULL.
					 */
					if (existing_dofs_count > 1) {
						int removed_dofs_count = existing_dofs_count - 1;
						size_t removed_dofs_size = DOF_IOCTL_DATA_T_SIZE(removed_dofs_count);
					
						removed_dofs = kmem_alloc(removed_dofs_size, KM_SLEEP);
						removed_dofs->dofiod_count = removed_dofs_count;
					
						/*
						 * copy the remaining data.
						 */
						if (index > 0) {
							bcopy(&existing_dofs->dofiod_helpers[0],
							      &removed_dofs->dofiod_helpers[0],
							      index * sizeof(dof_helper_t));
						}
					
						if (index < existing_dofs_count-1) {
							bcopy(&existing_dofs->dofiod_helpers[index+1],
							      &removed_dofs->dofiod_helpers[index],
							      (existing_dofs_count - index - 1) * sizeof(dof_helper_t));
						}
					}
				
					kmem_free(existing_dofs, DOF_IOCTL_DATA_T_SIZE(existing_dofs_count));
				
					p->p_dtrace_lazy_dofs = removed_dofs;

					rval = KERN_SUCCESS;

					break;
				}
			}

#if DEBUG
			dof_ioctl_data_t* all_dofs = p->p_dtrace_lazy_dofs;
			if (all_dofs) {
				unsigned int i;
				for (i=0; i<all_dofs->dofiod_count-1; i++) {
					ASSERT(all_dofs->dofiod_helpers[i].dofhp_dof < all_dofs->dofiod_helpers[i+1].dofhp_dof);
				}
			}
#endif

		}

		lck_mtx_unlock(&p->p_dtrace_sprlock);
	} else {		
		rval = EACCES;
	}
	
	lck_rw_unlock_shared(&dtrace_dof_mode_lock);

	return rval;
}

void
dtrace_lazy_dofs_destroy(proc_t *p)
{
	lck_rw_lock_shared(&dtrace_dof_mode_lock);
	lck_mtx_lock(&p->p_dtrace_sprlock);
	
	ASSERT(p->p_dtrace_lazy_dofs == NULL || p->p_dtrace_helpers == NULL);

	dof_ioctl_data_t* lazy_dofs = p->p_dtrace_lazy_dofs;
	p->p_dtrace_lazy_dofs = NULL;

	lck_mtx_unlock(&p->p_dtrace_sprlock);
	lck_rw_unlock_shared(&dtrace_dof_mode_lock);

	if (lazy_dofs) {
		kmem_free(lazy_dofs, DOF_IOCTL_DATA_T_SIZE(lazy_dofs->dofiod_count));
	}
}

static int
dtrace_lazy_dofs_proc_iterate_filter(proc_t *p, void* ignored)
{
#pragma unused(ignored)
	/*
	 * Okay to NULL test without taking the sprlock.
	 */
	return p->p_dtrace_lazy_dofs != NULL;
}

static void
dtrace_lazy_dofs_process(proc_t *p) {
	/*
	 * It is possible this process may exit during our attempt to
	 * fault in the dof. We could fix this by holding locks longer,
	 * but the errors are benign.
	 */
	lck_mtx_lock(&p->p_dtrace_sprlock);


	ASSERT(p->p_dtrace_lazy_dofs == NULL || p->p_dtrace_helpers == NULL);
	ASSERT(dtrace_dof_mode == DTRACE_DOF_MODE_LAZY_OFF);

	dof_ioctl_data_t* lazy_dofs = p->p_dtrace_lazy_dofs;
	p->p_dtrace_lazy_dofs = NULL;

	lck_mtx_unlock(&p->p_dtrace_sprlock);

	/*
	 * Process each dof_helper_t
	 */
	if (lazy_dofs != NULL) {
		unsigned int i;
		int rval;

		for (i=0; i<lazy_dofs->dofiod_count; i++) {
			/*
			 * When loading lazy dof, we depend on the generations being sorted in ascending order.
			 */
			ASSERT(i >= (lazy_dofs->dofiod_count - 1) || lazy_dofs->dofiod_helpers[i].dofhp_dof < lazy_dofs->dofiod_helpers[i+1].dofhp_dof);

			dof_helper_t *dhp = &lazy_dofs->dofiod_helpers[i];

			/*
			 * We stored the generation in dofhp_dof. Save it, and restore the original value.
			 */
			int generation = dhp->dofhp_dof;
			dhp->dofhp_dof = dhp->dofhp_addr;

			dof_hdr_t *dof = dtrace_dof_copyin_from_proc(p, dhp->dofhp_dof, &rval);

			if (dof != NULL) {
				dtrace_helpers_t *help;
								
				lck_mtx_lock(&dtrace_lock);
				
				/*
				 * This must be done with the dtrace_lock held
				 */
				if ((help = p->p_dtrace_helpers) == NULL)
					help = dtrace_helpers_create(p);
				
				/*
				 * If the generation value has been bumped, someone snuck in
				 * when we released the dtrace lock. We have to dump this generation,
				 * there is no safe way to load it.
				 */
				if (help->dthps_generation <= generation) {
					help->dthps_generation = generation;
					
					/*
					 * dtrace_helper_slurp() takes responsibility for the dof --
					 * it may free it now or it may save it and free it later.
					 */
					if ((rval = dtrace_helper_slurp(p, dof, dhp)) != generation) {
						dtrace_dof_error(NULL, "returned value did not match expected generation");
					}
				}
				
				lck_mtx_unlock(&dtrace_lock);
			}
		}

		kmem_free(lazy_dofs, DOF_IOCTL_DATA_T_SIZE(lazy_dofs->dofiod_count));
	}
}

static int
dtrace_lazy_dofs_proc_iterate_doit(proc_t *p, void* ignored)
{
#pragma unused(ignored)

	dtrace_lazy_dofs_process(p);

	return PROC_RETURNED;
}

#define DTRACE_LAZY_DOFS_DUPLICATED 1

static int
dtrace_lazy_dofs_duplicate(proc_t *parent, proc_t *child)
{
	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_assert(&parent->p_dtrace_sprlock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_assert(&child->p_dtrace_sprlock, LCK_MTX_ASSERT_NOTOWNED);

	lck_rw_lock_shared(&dtrace_dof_mode_lock);
	lck_mtx_lock(&parent->p_dtrace_sprlock);

	/*
	 * We need to make sure that the transition to lazy dofs -> helpers
	 * was atomic for our parent
	 */
	ASSERT(parent->p_dtrace_lazy_dofs == NULL || parent->p_dtrace_helpers == NULL);
	/*
	 * In theory we should hold the child sprlock, but this is safe...
	 */
	ASSERT(child->p_dtrace_lazy_dofs == NULL && child->p_dtrace_helpers == NULL);

	dof_ioctl_data_t* parent_dofs = parent->p_dtrace_lazy_dofs;
	dof_ioctl_data_t* child_dofs = NULL;
	if (parent_dofs) {
		size_t parent_dofs_size = DOF_IOCTL_DATA_T_SIZE(parent_dofs->dofiod_count);
		child_dofs = kmem_alloc(parent_dofs_size, KM_SLEEP);
		bcopy(parent_dofs, child_dofs, parent_dofs_size);
	}

	lck_mtx_unlock(&parent->p_dtrace_sprlock);

	if (child_dofs) {
		lck_mtx_lock(&child->p_dtrace_sprlock);
		child->p_dtrace_lazy_dofs = child_dofs;
		lck_mtx_unlock(&child->p_dtrace_sprlock);
		/**
		 * We process the DOF at this point if the mode is set to
		 * LAZY_OFF. This can happen if DTrace is still processing the
		 * DOF of other process (which can happen because the
		 * protected pager can have a huge latency)
		 * but has not processed our parent yet
		 */
		if (dtrace_dof_mode == DTRACE_DOF_MODE_LAZY_OFF) {
			dtrace_lazy_dofs_process(child);
		}
		lck_rw_unlock_shared(&dtrace_dof_mode_lock);

		return DTRACE_LAZY_DOFS_DUPLICATED;
	}
	lck_rw_unlock_shared(&dtrace_dof_mode_lock);

	return 0;
}

static dtrace_helpers_t *
dtrace_helpers_create(proc_t *p)
{
	dtrace_helpers_t *help;

	lck_mtx_assert(&dtrace_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(p->p_dtrace_helpers == NULL);

	help = kmem_zalloc(sizeof (dtrace_helpers_t), KM_SLEEP);
	help->dthps_actions = kmem_zalloc(sizeof (dtrace_helper_action_t *) *
	    DTRACE_NHELPER_ACTIONS, KM_SLEEP);

	p->p_dtrace_helpers = help;
	dtrace_helpers++;

	return (help);
}

static void
dtrace_helpers_destroy(proc_t* p)
{
	dtrace_helpers_t *help;
	dtrace_vstate_t *vstate;
	uint_t i;

	lck_mtx_lock(&dtrace_lock);

	ASSERT(p->p_dtrace_helpers != NULL);
	ASSERT(dtrace_helpers > 0);

	help = p->p_dtrace_helpers;
	vstate = &help->dthps_vstate;

	/*
	 * We're now going to lose the help from this process.
	 */
	p->p_dtrace_helpers = NULL;
	dtrace_sync();

	/*
	 * Destory the helper actions.
	 */
	for (i = 0; i < DTRACE_NHELPER_ACTIONS; i++) {
		dtrace_helper_action_t *h, *next;

		for (h = help->dthps_actions[i]; h != NULL; h = next) {
			next = h->dtha_next;
			dtrace_helper_action_destroy(h, vstate);
			h = next;
		}
	}

	lck_mtx_unlock(&dtrace_lock);

	/*
	 * Destroy the helper providers.
	 */
	if (help->dthps_maxprovs > 0) {
		lck_mtx_lock(&dtrace_meta_lock);
		if (dtrace_meta_pid != NULL) {
			ASSERT(dtrace_deferred_pid == NULL);

			for (i = 0; i < help->dthps_nprovs; i++) {
				dtrace_helper_provider_remove(
				    &help->dthps_provs[i]->dthp_prov, p->p_pid);
			}
		} else {
			lck_mtx_lock(&dtrace_lock);
			ASSERT(help->dthps_deferred == 0 ||
			    help->dthps_next != NULL ||
			    help->dthps_prev != NULL ||
			    help == dtrace_deferred_pid);

			/*
			 * Remove the helper from the deferred list.
			 */
			if (help->dthps_next != NULL)
				help->dthps_next->dthps_prev = help->dthps_prev;
			if (help->dthps_prev != NULL)
				help->dthps_prev->dthps_next = help->dthps_next;
			if (dtrace_deferred_pid == help) {
				dtrace_deferred_pid = help->dthps_next;
				ASSERT(help->dthps_prev == NULL);
			}

			lck_mtx_unlock(&dtrace_lock);
		}

		lck_mtx_unlock(&dtrace_meta_lock);

		for (i = 0; i < help->dthps_nprovs; i++) {
			dtrace_helper_provider_destroy(help->dthps_provs[i]);
		}

		kmem_free(help->dthps_provs, help->dthps_maxprovs *
		    sizeof (dtrace_helper_provider_t *));
	}

	lck_mtx_lock(&dtrace_lock);

	dtrace_vstate_fini(&help->dthps_vstate);
	kmem_free(help->dthps_actions,
	    sizeof (dtrace_helper_action_t *) * DTRACE_NHELPER_ACTIONS);
	kmem_free(help, sizeof (dtrace_helpers_t));

	--dtrace_helpers;
	lck_mtx_unlock(&dtrace_lock);
}

static void
dtrace_helpers_duplicate(proc_t *from, proc_t *to)
{
	dtrace_helpers_t *help, *newhelp;
	dtrace_helper_action_t *helper, *new, *last;
	dtrace_difo_t *dp;
	dtrace_vstate_t *vstate;
	uint_t i;
	int j, sz, hasprovs = 0;

	lck_mtx_lock(&dtrace_lock);
	ASSERT(from->p_dtrace_helpers != NULL);
	ASSERT(dtrace_helpers > 0);

	help = from->p_dtrace_helpers;
	newhelp = dtrace_helpers_create(to);
	ASSERT(to->p_dtrace_helpers != NULL);

	newhelp->dthps_generation = help->dthps_generation;
	vstate = &newhelp->dthps_vstate;

	/*
	 * Duplicate the helper actions.
	 */
	for (i = 0; i < DTRACE_NHELPER_ACTIONS; i++) {
		if ((helper = help->dthps_actions[i]) == NULL)
			continue;

		for (last = NULL; helper != NULL; helper = helper->dtha_next) {
			new = kmem_zalloc(sizeof (dtrace_helper_action_t),
			    KM_SLEEP);
			new->dtha_generation = helper->dtha_generation;

			if ((dp = helper->dtha_predicate) != NULL) {
				dp = dtrace_difo_duplicate(dp, vstate);
				new->dtha_predicate = dp;
			}

			new->dtha_nactions = helper->dtha_nactions;
			sz = sizeof (dtrace_difo_t *) * new->dtha_nactions;
			new->dtha_actions = kmem_alloc(sz, KM_SLEEP);

			for (j = 0; j < new->dtha_nactions; j++) {
				dtrace_difo_t *dpj = helper->dtha_actions[j];

				ASSERT(dpj != NULL);
				dpj = dtrace_difo_duplicate(dpj, vstate);
				new->dtha_actions[j] = dpj;
			}

			if (last != NULL) {
				last->dtha_next = new;
			} else {
				newhelp->dthps_actions[i] = new;
			}

			last = new;
		}
	}

	/*
	 * Duplicate the helper providers and register them with the
	 * DTrace framework.
	 */
	if (help->dthps_nprovs > 0) {
		newhelp->dthps_nprovs = help->dthps_nprovs;
		newhelp->dthps_maxprovs = help->dthps_nprovs;
		newhelp->dthps_provs = kmem_alloc(newhelp->dthps_nprovs *
		    sizeof (dtrace_helper_provider_t *), KM_SLEEP);
		for (i = 0; i < newhelp->dthps_nprovs; i++) {
			newhelp->dthps_provs[i] = help->dthps_provs[i];
			newhelp->dthps_provs[i]->dthp_ref++;
		}

		hasprovs = 1;
	}

	lck_mtx_unlock(&dtrace_lock);

	if (hasprovs)
		dtrace_helper_provider_register(to, newhelp, NULL);
}

/**
 * DTrace Process functions
 */

void
dtrace_proc_fork(proc_t *parent_proc, proc_t *child_proc, int spawn)
{
	/*
	 * This code applies to new processes who are copying the task
	 * and thread state and address spaces of their parent process.
	 */
	if (!spawn) {
		/*
		 * APPLE NOTE: Solaris does a sprlock() and drops the
		 * proc_lock here. We're cheating a bit and only taking
		 * the p_dtrace_sprlock lock. A full sprlock would
		 * task_suspend the parent.
		 */
		lck_mtx_lock(&parent_proc->p_dtrace_sprlock);

		/*
		 * Remove all DTrace tracepoints from the child process. We
		 * need to do this _before_ duplicating USDT providers since
		 * any associated probes may be immediately enabled.
		 */
		if (parent_proc->p_dtrace_count > 0) {
			dtrace_fasttrap_fork(parent_proc, child_proc);
		}

		lck_mtx_unlock(&parent_proc->p_dtrace_sprlock);

		/*
		 * Duplicate any lazy dof(s). This must be done while NOT
		 * holding the parent sprlock! Lock ordering is
		 * dtrace_dof_mode_lock, then sprlock.  It is imperative we
		 * always call dtrace_lazy_dofs_duplicate, rather than null
		 * check and call if !NULL. If we NULL test, during lazy dof
		 * faulting we can race with the faulting code and proceed
		 * from here to beyond the helpers copy. The lazy dof
		 * faulting will then fail to copy the helpers to the child
		 * process. We return if we duplicated lazy dofs as a process
		 * can only have one at the same time to avoid a race between
		 * a dtrace client and dtrace_proc_fork where a process would
		 * end up with both lazy dofs and helpers.
		 */
		if (dtrace_lazy_dofs_duplicate(parent_proc, child_proc) == DTRACE_LAZY_DOFS_DUPLICATED) {
			return;
		}

		/*
		 * Duplicate any helper actions and providers if they haven't
		 * already.
		 */
#if !defined(__APPLE__)
		 /*
		 * The SFORKING
		 * we set above informs the code to enable USDT probes that
		 * sprlock() may fail because the child is being forked.
		 */
#endif
		/*
		 * APPLE NOTE: As best I can tell, Apple's sprlock() equivalent
		 * never fails to find the child. We do not set SFORKING.
		 */
		if (parent_proc->p_dtrace_helpers != NULL && dtrace_helpers_fork) {
			(*dtrace_helpers_fork)(parent_proc, child_proc);
		}
	}
}

void
dtrace_proc_exec(proc_t *p)
{
	/*
	 * Invalidate any predicate evaluation already cached for this thread by DTrace.
	 * That's because we've just stored to p_comm and DTrace refers to that when it
	 * evaluates the "execname" special variable. uid and gid may have changed as well.
	 */
	dtrace_set_thread_predcache(current_thread(), 0);

	/*
	 * Free any outstanding lazy dof entries. It is imperative we
	 * always call dtrace_lazy_dofs_destroy, rather than null check
	 * and call if !NULL. If we NULL test, during lazy dof faulting
	 * we can race with the faulting code and proceed from here to
	 * beyond the helpers cleanup. The lazy dof faulting will then
	 * install new helpers which no longer belong to this process!
	 */
	dtrace_lazy_dofs_destroy(p);


	/*
	 * Clean up any DTrace helpers for the process.
	 */
	if (p->p_dtrace_helpers != NULL && dtrace_helpers_cleanup) {
		(*dtrace_helpers_cleanup)(p);
	}

	/*
	 * Cleanup the DTrace provider associated with this process.
	 */
	proc_lock(p);
	if (p->p_dtrace_probes && dtrace_fasttrap_exec_ptr) {
		(*dtrace_fasttrap_exec_ptr)(p);
	}
	proc_unlock(p);
}

void
dtrace_proc_exit(proc_t *p)
{
	/*
	 * Free any outstanding lazy dof entries. It is imperative we
	 * always call dtrace_lazy_dofs_destroy, rather than null check
	 * and call if !NULL. If we NULL test, during lazy dof faulting
	 * we can race with the faulting code and proceed from here to
	 * beyond the helpers cleanup. The lazy dof faulting will then
	 * install new helpers which will never be cleaned up, and leak.
	 */
	dtrace_lazy_dofs_destroy(p);

	/*
	 * Clean up any DTrace helper actions or probes for the process.
	 */
	if (p->p_dtrace_helpers != NULL) {
		(*dtrace_helpers_cleanup)(p);
	}

	/*
	 * Clean up any DTrace probes associated with this process.
	 */
	/*
	 * APPLE NOTE: We release ptss pages/entries in dtrace_fasttrap_exit_ptr(),
	 * call this after dtrace_helpers_cleanup()
	 */
	proc_lock(p);
	if (p->p_dtrace_probes && dtrace_fasttrap_exit_ptr) {
		(*dtrace_fasttrap_exit_ptr)(p);
	}
	proc_unlock(p);
}

/*
 * DTrace Hook Functions
 */

/*
 * APPLE NOTE:  dtrace_modctl_* routines for kext support.
 * Used to manipulate the modctl list within dtrace xnu.
 */

modctl_t *dtrace_modctl_list;

static void
dtrace_modctl_add(struct modctl * newctl)
{
	struct modctl *nextp, *prevp;

	ASSERT(newctl != NULL);
	lck_mtx_assert(&mod_lock, LCK_MTX_ASSERT_OWNED);

	// Insert new module at the front of the list,
	
	newctl->mod_next = dtrace_modctl_list;
	dtrace_modctl_list = newctl;

	/*
	 * If a module exists with the same name, then that module
	 * must have been unloaded with enabled probes. We will move
	 * the unloaded module to the new module's stale chain and
	 * then stop traversing the list.
	 */

	prevp = newctl;
	nextp = newctl->mod_next;
    
	while (nextp != NULL) {
		if (nextp->mod_loaded) {
			/* This is a loaded module. Keep traversing. */
			prevp = nextp;
			nextp = nextp->mod_next;
			continue;
		}
		else {
			/* Found an unloaded module */
			if (strncmp (newctl->mod_modname, nextp->mod_modname, KMOD_MAX_NAME)) {
				/* Names don't match. Keep traversing. */
				prevp = nextp;
				nextp = nextp->mod_next;
				continue;
			}
			else {
				/* We found a stale entry, move it. We're done. */
				prevp->mod_next = nextp->mod_next;
				newctl->mod_stale = nextp;
				nextp->mod_next = NULL;
				break;
			}
		}
	}
}

static modctl_t *
dtrace_modctl_lookup(struct kmod_info * kmod)
{
    lck_mtx_assert(&mod_lock, LCK_MTX_ASSERT_OWNED);

    struct modctl * ctl;

    for (ctl = dtrace_modctl_list; ctl; ctl=ctl->mod_next) {
	if (ctl->mod_id == kmod->id)
	    return(ctl);
    }
    return (NULL);
}

/*
 * This routine is called from dtrace_module_unloaded().
 * It removes a modctl structure and its stale chain
 * from the kext shadow list.
 */
static void
dtrace_modctl_remove(struct modctl * ctl)
{
	ASSERT(ctl != NULL);
	lck_mtx_assert(&mod_lock, LCK_MTX_ASSERT_OWNED);
	modctl_t *prevp, *nextp, *curp;

	// Remove stale chain first
	for (curp=ctl->mod_stale; curp != NULL; curp=nextp) {
		nextp = curp->mod_stale;
		/* There should NEVER be user symbols allocated at this point */
		ASSERT(curp->mod_user_symbols == NULL);	
		kmem_free(curp, sizeof(modctl_t));
	}

	prevp = NULL;
	curp = dtrace_modctl_list;
	
	while (curp != ctl) {
		prevp = curp;
		curp = curp->mod_next;
	}

	if (prevp != NULL) {
		prevp->mod_next = ctl->mod_next;
	}
	else {
		dtrace_modctl_list = ctl->mod_next;
	}

	/* There should NEVER be user symbols allocated at this point */
	ASSERT(ctl->mod_user_symbols == NULL);

	kmem_free (ctl, sizeof(modctl_t));
}
	
/*
 * APPLE NOTE: The kext loader will call dtrace_module_loaded
 * when the kext is loaded in memory, but before calling the
 * kext's start routine.
 *
 * Return 0 on success
 * Return -1 on failure
 */
	
static int
dtrace_module_loaded(struct kmod_info *kmod, uint32_t flag)
{
	dtrace_provider_t *prv;

	/*
	 * If kernel symbols have been disabled, return immediately
	 * DTRACE_KERNEL_SYMBOLS_NEVER is a permanent mode, it is safe to test without holding locks
	 */
	if (dtrace_kernel_symbol_mode == DTRACE_KERNEL_SYMBOLS_NEVER)
		return 0;
	
	struct modctl *ctl = NULL;
	if (!kmod || kmod->address == 0 || kmod->size == 0)
		return(-1);
		
	lck_mtx_lock(&dtrace_provider_lock);
	lck_mtx_lock(&mod_lock);	
	
	/*
	 * Have we seen this kext before?
	 */

	ctl = dtrace_modctl_lookup(kmod);

	if (ctl != NULL) {
		/* bail... we already have this kext in the modctl list */
		lck_mtx_unlock(&mod_lock);
		lck_mtx_unlock(&dtrace_provider_lock);
		if (dtrace_err_verbose)
			cmn_err(CE_WARN, "dtrace load module already exists '%s %u' is failing against '%s %u'", kmod->name, (uint_t)kmod->id, ctl->mod_modname, ctl->mod_id);
		return(-1);
	}
	else {
		ctl = kmem_alloc(sizeof(struct modctl), KM_SLEEP);
		if (ctl == NULL) {
			if (dtrace_err_verbose)
				cmn_err(CE_WARN, "dtrace module load '%s %u' is failing ", kmod->name, (uint_t)kmod->id);
			lck_mtx_unlock(&mod_lock);
			lck_mtx_unlock(&dtrace_provider_lock);
			return (-1);
		}
		ctl->mod_next = NULL;
		ctl->mod_stale = NULL;
		strlcpy (ctl->mod_modname, kmod->name, sizeof(ctl->mod_modname));
		ctl->mod_loadcnt = kmod->id;
		ctl->mod_nenabled = 0;
		ctl->mod_address  = kmod->address;
		ctl->mod_size = kmod->size;
		ctl->mod_id = kmod->id;
		ctl->mod_loaded = 1;
		ctl->mod_flags = 0;
		ctl->mod_user_symbols = NULL;
		
		/*
		 * Find the UUID for this module, if it has one
		 */
		kernel_mach_header_t* header = (kernel_mach_header_t *)ctl->mod_address;
		struct load_command* load_cmd = (struct load_command *)&header[1];
		uint32_t i;
		for (i = 0; i < header->ncmds; i++) {
			if (load_cmd->cmd == LC_UUID) {
				struct uuid_command* uuid_cmd = (struct uuid_command *)load_cmd;
				memcpy(ctl->mod_uuid, uuid_cmd->uuid, sizeof(uuid_cmd->uuid));
				ctl->mod_flags |= MODCTL_HAS_UUID;
				break;
			}
			load_cmd = (struct load_command *)((caddr_t)load_cmd + load_cmd->cmdsize);
		}
		
		if (ctl->mod_address == g_kernel_kmod_info.address) {
			ctl->mod_flags |= MODCTL_IS_MACH_KERNEL;
		}
	}
	dtrace_modctl_add(ctl);
	
	/*
	 * We must hold the dtrace_lock to safely test non permanent dtrace_fbt_symbol_mode(s)
	 */
	lck_mtx_lock(&dtrace_lock);
	
	/*
	 * DTrace must decide if it will instrument modules lazily via
	 * userspace symbols (default mode), or instrument immediately via 
	 * kernel symbols (non-default mode)
	 *
	 * When in default/lazy mode, DTrace will only support modules
	 * built with a valid UUID.
	 *
	 * Overriding the default can be done explicitly in one of
	 * the following two ways.
	 *
	 * A module can force symbols from kernel space using the plist key,
	 * OSBundleForceDTraceInit (see kmod.h).  If this per kext state is set,
	 * we fall through and instrument this module now.
	 *
	 * Or, the boot-arg, dtrace_kernel_symbol_mode, can be set to force symbols
	 * from kernel space (see dtrace_impl.h).  If this system state is set
	 * to a non-userspace mode, we fall through and instrument the module now.
	 */

	if ((dtrace_kernel_symbol_mode == DTRACE_KERNEL_SYMBOLS_FROM_USERSPACE) &&
	    (!(flag & KMOD_DTRACE_FORCE_INIT)))
	{
		/* We will instrument the module lazily -- this is the default */
		lck_mtx_unlock(&dtrace_lock);
		lck_mtx_unlock(&mod_lock);
		lck_mtx_unlock(&dtrace_provider_lock);
		return 0;
	}
	
	/* We will instrument the module immediately using kernel symbols */
	ctl->mod_flags |= MODCTL_HAS_KERNEL_SYMBOLS;
	
	lck_mtx_unlock(&dtrace_lock);
	
	/*
	 * We're going to call each providers per-module provide operation
	 * specifying only this module.
	 */
	for (prv = dtrace_provider; prv != NULL; prv = prv->dtpv_next)
		prv->dtpv_pops.dtps_provide_module(prv->dtpv_arg, ctl);	
	
	/*
	 * APPLE NOTE: The contract with the kext loader is that once this function
	 * has completed, it may delete kernel symbols at will.
	 * We must set this while still holding the mod_lock.
	 */
	ctl->mod_flags &= ~MODCTL_HAS_KERNEL_SYMBOLS;
	
	lck_mtx_unlock(&mod_lock);
	lck_mtx_unlock(&dtrace_provider_lock);
	
	/*
	 * If we have any retained enablings, we need to match against them.
	 * Enabling probes requires that cpu_lock be held, and we cannot hold
	 * cpu_lock here -- it is legal for cpu_lock to be held when loading a
	 * module.  (In particular, this happens when loading scheduling
	 * classes.)  So if we have any retained enablings, we need to dispatch
	 * our task queue to do the match for us.
	 */
	lck_mtx_lock(&dtrace_lock);
	
	if (dtrace_retained == NULL) {
		lck_mtx_unlock(&dtrace_lock);
		return 0;
	}
	
	/* APPLE NOTE!
	 *
	 * The cpu_lock mentioned above is only held by dtrace code, Apple's xnu never actually
	 * holds it for any reason. Thus the comment above is invalid, we can directly invoke
	 * dtrace_enabling_matchall without jumping through all the hoops, and we can avoid
	 * the delay call as well.
	 */
	lck_mtx_unlock(&dtrace_lock);
	
	dtrace_enabling_matchall();
	
	return 0;
}

/*
 * Return 0 on success
 * Return -1 on failure
 */
static int
dtrace_module_unloaded(struct kmod_info *kmod)
{
	dtrace_probe_t template, *probe, *first, *next;
	dtrace_provider_t *prov;
        struct modctl *ctl = NULL;
	struct modctl *syncctl = NULL;
	struct modctl *nextsyncctl = NULL;
	int syncmode = 0;
	
        lck_mtx_lock(&dtrace_provider_lock);
	lck_mtx_lock(&mod_lock);
	lck_mtx_lock(&dtrace_lock);

	if (kmod == NULL) {
	    syncmode = 1;
	}
	else {
	    ctl = dtrace_modctl_lookup(kmod);
	    if (ctl == NULL)
	    {
		lck_mtx_unlock(&dtrace_lock);
		lck_mtx_unlock(&mod_lock);
		lck_mtx_unlock(&dtrace_provider_lock);
		return (-1);
	    }
	    ctl->mod_loaded = 0;
	    ctl->mod_address = 0;
	    ctl->mod_size = 0;
	}
	
	if (dtrace_bymod == NULL) {
		/*
		 * The DTrace module is loaded (obviously) but not attached;
		 * we don't have any work to do.
		 */
	         if (ctl != NULL)
			 (void)dtrace_modctl_remove(ctl);
		 lck_mtx_unlock(&dtrace_lock);
		 lck_mtx_unlock(&mod_lock);
		 lck_mtx_unlock(&dtrace_provider_lock);
		 return(0);
	}

	/* Syncmode set means we target and traverse entire modctl list. */
        if (syncmode)
	    nextsyncctl = dtrace_modctl_list;

syncloop:
	if (syncmode)
	{
	    /* find a stale modctl struct */
	    for (syncctl = nextsyncctl; syncctl != NULL; syncctl=syncctl->mod_next) {
		if (syncctl->mod_address == 0)
		    break;
	    }
	    if (syncctl==NULL)
	    {
		/* We have no more work to do */
		lck_mtx_unlock(&dtrace_lock);
		lck_mtx_unlock(&mod_lock);
		lck_mtx_unlock(&dtrace_provider_lock);
		return(0);
	    }
	    else {
		/* keep track of next syncctl in case this one is removed */
		nextsyncctl = syncctl->mod_next;
		ctl = syncctl;
	    }
	}

	template.dtpr_mod = ctl->mod_modname;
	
	for (probe = first = dtrace_hash_lookup(dtrace_bymod, &template);
	    probe != NULL; probe = probe->dtpr_nextmod) {
	        if (probe->dtpr_ecb != NULL) {
			/*
			 * This shouldn't _actually_ be possible -- we're
			 * unloading a module that has an enabled probe in it.
			 * (It's normally up to the provider to make sure that
			 * this can't happen.)  However, because dtps_enable()
			 * doesn't have a failure mode, there can be an
			 * enable/unload race.  Upshot:  we don't want to
			 * assert, but we're not going to disable the
			 * probe, either.
			 */


		        if (syncmode) {
			    /* We're syncing, let's look at next in list */
			    goto syncloop;
			}

			lck_mtx_unlock(&dtrace_lock);
			lck_mtx_unlock(&mod_lock);
			lck_mtx_unlock(&dtrace_provider_lock);
		    
			if (dtrace_err_verbose) {
				cmn_err(CE_WARN, "unloaded module '%s' had "
				    "enabled probes", ctl->mod_modname);
			}
			return(-1);
		}
	}

	probe = first;

	for (first = NULL; probe != NULL; probe = next) {
		ASSERT(dtrace_probes[probe->dtpr_id - 1] == probe);

		dtrace_probes[probe->dtpr_id - 1] = NULL;
		probe->dtpr_provider->dtpv_probe_count--;					

		next = probe->dtpr_nextmod;
		dtrace_hash_remove(dtrace_bymod, probe);
		dtrace_hash_remove(dtrace_byfunc, probe);
		dtrace_hash_remove(dtrace_byname, probe);

		if (first == NULL) {
			first = probe;
			probe->dtpr_nextmod = NULL;
		} else {
			probe->dtpr_nextmod = first;
			first = probe;
		}
	}

	/*
	 * We've removed all of the module's probes from the hash chains and
	 * from the probe array.  Now issue a dtrace_sync() to be sure that
	 * everyone has cleared out from any probe array processing.
	 */
	dtrace_sync();

	for (probe = first; probe != NULL; probe = first) {
		first = probe->dtpr_nextmod;
		prov = probe->dtpr_provider;
		prov->dtpv_pops.dtps_destroy(prov->dtpv_arg, probe->dtpr_id,
		    probe->dtpr_arg);
		kmem_free(probe->dtpr_mod, strlen(probe->dtpr_mod) + 1);
		kmem_free(probe->dtpr_func, strlen(probe->dtpr_func) + 1);
		kmem_free(probe->dtpr_name, strlen(probe->dtpr_name) + 1);
		vmem_free(dtrace_arena, (void *)(uintptr_t)probe->dtpr_id, 1);

		zfree(dtrace_probe_t_zone, probe);
	}

	dtrace_modctl_remove(ctl);
	
	if (syncmode)
	    goto syncloop;

	lck_mtx_unlock(&dtrace_lock);
	lck_mtx_unlock(&mod_lock);
	lck_mtx_unlock(&dtrace_provider_lock);

	return(0);
}

void
dtrace_suspend(void)
{
	dtrace_probe_foreach(offsetof(dtrace_pops_t, dtps_suspend));
}

void
dtrace_resume(void)
{
	dtrace_probe_foreach(offsetof(dtrace_pops_t, dtps_resume));
}

static int
dtrace_cpu_setup(cpu_setup_t what, processorid_t cpu)
{
	lck_mtx_assert(&cpu_lock, LCK_MTX_ASSERT_OWNED);
	lck_mtx_lock(&dtrace_lock);

	switch (what) {
	case CPU_CONFIG: {
		dtrace_state_t *state;
		dtrace_optval_t *opt, rs, c;

		/*
		 * For now, we only allocate a new buffer for anonymous state.
		 */
		if ((state = dtrace_anon.dta_state) == NULL)
			break;

		if (state->dts_activity != DTRACE_ACTIVITY_ACTIVE)
			break;

		opt = state->dts_options;
		c = opt[DTRACEOPT_CPU];

		if (c != DTRACE_CPUALL && c != DTRACEOPT_UNSET && c != cpu)
			break;

		/*
		 * Regardless of what the actual policy is, we're going to
		 * temporarily set our resize policy to be manual.  We're
		 * also going to temporarily set our CPU option to denote
		 * the newly configured CPU.
		 */
		rs = opt[DTRACEOPT_BUFRESIZE];
		opt[DTRACEOPT_BUFRESIZE] = DTRACEOPT_BUFRESIZE_MANUAL;
		opt[DTRACEOPT_CPU] = (dtrace_optval_t)cpu;

		(void) dtrace_state_buffers(state);

		opt[DTRACEOPT_BUFRESIZE] = rs;
		opt[DTRACEOPT_CPU] = c;

		break;
	}

	case CPU_UNCONFIG:
		/*
		 * We don't free the buffer in the CPU_UNCONFIG case.  (The
		 * buffer will be freed when the consumer exits.)
		 */
		break;

	default:
		break;
	}

	lck_mtx_unlock(&dtrace_lock);
	return (0);
}

static void
dtrace_cpu_setup_initial(processorid_t cpu)
{
	(void) dtrace_cpu_setup(CPU_CONFIG, cpu);
}

static void
dtrace_toxrange_add(uintptr_t base, uintptr_t limit)
{
	if (dtrace_toxranges >= dtrace_toxranges_max) {
		int osize, nsize;
		dtrace_toxrange_t *range;

		osize = dtrace_toxranges_max * sizeof (dtrace_toxrange_t);

		if (osize == 0) {
			ASSERT(dtrace_toxrange == NULL);
			ASSERT(dtrace_toxranges_max == 0);
			dtrace_toxranges_max = 1;
		} else {
			dtrace_toxranges_max <<= 1;
		}

		nsize = dtrace_toxranges_max * sizeof (dtrace_toxrange_t);
		range = kmem_zalloc(nsize, KM_SLEEP);

		if (dtrace_toxrange != NULL) {
			ASSERT(osize != 0);
			bcopy(dtrace_toxrange, range, osize);
			kmem_free(dtrace_toxrange, osize);
		}

		dtrace_toxrange = range;
	}

	ASSERT(dtrace_toxrange[dtrace_toxranges].dtt_base == 0);
	ASSERT(dtrace_toxrange[dtrace_toxranges].dtt_limit == 0);

	dtrace_toxrange[dtrace_toxranges].dtt_base = base;
	dtrace_toxrange[dtrace_toxranges].dtt_limit = limit;
	dtrace_toxranges++;
}

/*
 * DTrace Driver Cookbook Functions
 */
/*ARGSUSED*/
static int
dtrace_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
#pragma unused(cmd) /* __APPLE__ */
	dtrace_provider_id_t id;
	dtrace_state_t *state = NULL;
	dtrace_enabling_t *enab;

	lck_mtx_lock(&cpu_lock);
	lck_mtx_lock(&dtrace_provider_lock);
	lck_mtx_lock(&dtrace_lock);

	/* Darwin uses BSD cloning device driver to automagically obtain minor device number. */

	ddi_report_dev(devi);
	dtrace_devi = devi;

	dtrace_modload = dtrace_module_loaded;
	dtrace_modunload = dtrace_module_unloaded;
	dtrace_cpu_init = dtrace_cpu_setup_initial;
	dtrace_helpers_cleanup = dtrace_helpers_destroy;
	dtrace_helpers_fork = dtrace_helpers_duplicate;
	dtrace_cpustart_init = dtrace_suspend;
	dtrace_cpustart_fini = dtrace_resume;
	dtrace_debugger_init = dtrace_suspend;
	dtrace_debugger_fini = dtrace_resume;

	register_cpu_setup_func((cpu_setup_func_t *)dtrace_cpu_setup, NULL);

	lck_mtx_assert(&cpu_lock, LCK_MTX_ASSERT_OWNED);

	dtrace_arena = vmem_create("dtrace", (void *)1, UINT32_MAX, 1,
	    NULL, NULL, NULL, 0, VM_SLEEP | VMC_IDENTIFIER);
	dtrace_taskq = taskq_create("dtrace_taskq", 1, maxclsyspri,
	    1, INT_MAX, 0);

	dtrace_state_cache = kmem_cache_create("dtrace_state_cache",
	    sizeof (dtrace_dstate_percpu_t) * (int)NCPU, DTRACE_STATE_ALIGN,
	    NULL, NULL, NULL, NULL, NULL, 0);

	lck_mtx_assert(&cpu_lock, LCK_MTX_ASSERT_OWNED);

	dtrace_bymod = dtrace_hash_create(offsetof(dtrace_probe_t, dtpr_mod),
	    offsetof(dtrace_probe_t, dtpr_nextmod),
	    offsetof(dtrace_probe_t, dtpr_prevmod));

	dtrace_byfunc = dtrace_hash_create(offsetof(dtrace_probe_t, dtpr_func),
	    offsetof(dtrace_probe_t, dtpr_nextfunc),
	    offsetof(dtrace_probe_t, dtpr_prevfunc));

	dtrace_byname = dtrace_hash_create(offsetof(dtrace_probe_t, dtpr_name),
	    offsetof(dtrace_probe_t, dtpr_nextname),
	    offsetof(dtrace_probe_t, dtpr_prevname));

	if (dtrace_retain_max < 1) {
		cmn_err(CE_WARN, "illegal value (%lu) for dtrace_retain_max; "
		    "setting to 1", dtrace_retain_max);
		dtrace_retain_max = 1;
	}

	/*
	 * Now discover our toxic ranges.
	 */
	dtrace_toxic_ranges(dtrace_toxrange_add);

	/*
	 * Before we register ourselves as a provider to our own framework,
	 * we would like to assert that dtrace_provider is NULL -- but that's
	 * not true if we were loaded as a dependency of a DTrace provider.
	 * Once we've registered, we can assert that dtrace_provider is our
	 * pseudo provider.
	 */
	(void) dtrace_register("dtrace", &dtrace_provider_attr,
	    DTRACE_PRIV_NONE, 0, &dtrace_provider_ops, NULL, &id);

	ASSERT(dtrace_provider != NULL);
	ASSERT((dtrace_provider_id_t)dtrace_provider == id);

#if defined (__x86_64__)
	dtrace_probeid_begin = dtrace_probe_create((dtrace_provider_id_t)
	    dtrace_provider, NULL, NULL, "BEGIN", 1, NULL);
	dtrace_probeid_end = dtrace_probe_create((dtrace_provider_id_t)
	    dtrace_provider, NULL, NULL, "END", 0, NULL);
	dtrace_probeid_error = dtrace_probe_create((dtrace_provider_id_t)
	    dtrace_provider, NULL, NULL, "ERROR", 3, NULL);
#else
#error Unknown Architecture
#endif

	dtrace_anon_property();
	lck_mtx_unlock(&cpu_lock);

	/*
	 * If DTrace helper tracing is enabled, we need to allocate the
	 * trace buffer and initialize the values.
	 */
	if (dtrace_helptrace_enabled) {
		ASSERT(dtrace_helptrace_buffer == NULL);
		dtrace_helptrace_buffer =
		    kmem_zalloc(dtrace_helptrace_bufsize, KM_SLEEP);
		dtrace_helptrace_next = 0;
	}

	/*
	 * If there are already providers, we must ask them to provide their
	 * probes, and then match any anonymous enabling against them.  Note
	 * that there should be no other retained enablings at this time:
	 * the only retained enablings at this time should be the anonymous
	 * enabling.
	 */
	if (dtrace_anon.dta_enabling != NULL) {
		ASSERT(dtrace_retained == dtrace_anon.dta_enabling);

		/*
		 * APPLE NOTE: if handling anonymous dof, switch symbol modes.
		 */
		if (dtrace_kernel_symbol_mode == DTRACE_KERNEL_SYMBOLS_FROM_USERSPACE) {
			dtrace_kernel_symbol_mode = DTRACE_KERNEL_SYMBOLS_FROM_KERNEL;
		}
		
		dtrace_enabling_provide(NULL);
		state = dtrace_anon.dta_state;

		/*
		 * We couldn't hold cpu_lock across the above call to
		 * dtrace_enabling_provide(), but we must hold it to actually
		 * enable the probes.  We have to drop all of our locks, pick
		 * up cpu_lock, and regain our locks before matching the
		 * retained anonymous enabling.
		 */
		lck_mtx_unlock(&dtrace_lock);
		lck_mtx_unlock(&dtrace_provider_lock);

		lck_mtx_lock(&cpu_lock);
		lck_mtx_lock(&dtrace_provider_lock);
		lck_mtx_lock(&dtrace_lock);

		if ((enab = dtrace_anon.dta_enabling) != NULL)
			(void) dtrace_enabling_match(enab, NULL, NULL);

		lck_mtx_unlock(&cpu_lock);
	}

	lck_mtx_unlock(&dtrace_lock);
	lck_mtx_unlock(&dtrace_provider_lock);

	if (state != NULL) {
		/*
		 * If we created any anonymous state, set it going now.
		 */
		(void) dtrace_state_go(state, &dtrace_anon.dta_beganon);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
dtrace_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
#pragma unused(flag, otyp)
	dtrace_state_t *state;
	uint32_t priv;
	uid_t uid;
	zoneid_t zoneid;
	int rv;

	/* APPLE: Darwin puts Helper on its own major device. */

	/*
	 * If no DTRACE_PRIV_* bits are set in the credential, then the
	 * caller lacks sufficient permission to do anything with DTrace.
	 */
	dtrace_cred2priv(cred_p, &priv, &uid, &zoneid);
	if (priv == DTRACE_PRIV_NONE)
		return (EACCES);

	/*
	 * APPLE NOTE: We delay the initialization of fasttrap as late as possible.
	 * It certainly can't be later than now!
	 */
	fasttrap_init();

	/*
	 * Ask all providers to provide all their probes.
	 */
	lck_mtx_lock(&dtrace_provider_lock);
	dtrace_probe_provide(NULL, NULL);
	lck_mtx_unlock(&dtrace_provider_lock);

	lck_mtx_lock(&cpu_lock);
	lck_mtx_lock(&dtrace_lock);
	dtrace_opens++;
	dtrace_membar_producer();

	/*
	 * If the kernel debugger is active (that is, if the kernel debugger
	 * modified text in some way), we won't allow the open.
	 */
	if (kdi_dtrace_set(KDI_DTSET_DTRACE_ACTIVATE) != 0) {
		dtrace_opens--;
		lck_mtx_unlock(&dtrace_lock);
		lck_mtx_unlock(&cpu_lock);
		return (EBUSY);
	}

	rv = dtrace_state_create(devp, cred_p, &state);
	lck_mtx_unlock(&cpu_lock);

	if (rv != 0 || state == NULL) {
		if (--dtrace_opens == 0 && dtrace_anon.dta_enabling == NULL)
			(void) kdi_dtrace_set(KDI_DTSET_DTRACE_DEACTIVATE);
		lck_mtx_unlock(&dtrace_lock);
		/* propagate EAGAIN or ERESTART */
		return (rv);
	}
	
	lck_mtx_unlock(&dtrace_lock);

	lck_rw_lock_exclusive(&dtrace_dof_mode_lock);

	/*
	 * If we are currently lazy, transition states.
	 *
	 * Unlike dtrace_close, we do not need to check the
	 * value of dtrace_opens, as any positive value (and
	 * we count as 1) means we transition states.
	 */
	if (dtrace_dof_mode == DTRACE_DOF_MODE_LAZY_ON) {
		dtrace_dof_mode = DTRACE_DOF_MODE_LAZY_OFF;
		/*
		 * We do not need to hold the exclusive lock while processing
		 * DOF on processes. We do need to make sure the mode does not get
		 * changed to DTRACE_DOF_MODE_LAZY_ON during that stage though
		 * (which should not happen anyway since it only happens in
		 * dtrace_close). There is no way imcomplete USDT probes can be
		 * activate by any DTrace clients here since they all have to
		 * call dtrace_open and be blocked on dtrace_dof_mode_lock
		 */
		lck_rw_lock_exclusive_to_shared(&dtrace_dof_mode_lock);
		/*
		 * Iterate all existing processes and load lazy dofs.
		 */
		proc_iterate(PROC_ALLPROCLIST | PROC_NOWAITTRANS,
			     dtrace_lazy_dofs_proc_iterate_doit,
			     NULL,
			     dtrace_lazy_dofs_proc_iterate_filter,
			     NULL);

		lck_rw_unlock_shared(&dtrace_dof_mode_lock);
	}
	else {
		lck_rw_unlock_exclusive(&dtrace_dof_mode_lock);
	}


	/*
	 * Update kernel symbol state.
	 *
	 * We must own the provider and dtrace locks. 
	 *
	 * NOTE! It may appear there is a race by setting this value so late
	 * after dtrace_probe_provide. However, any kext loaded after the
	 * call to probe provide and before we set LAZY_OFF will be marked as
	 * eligible for symbols from userspace. The same dtrace that is currently
	 * calling dtrace_open() (this call!) will get a list of kexts needing
	 * symbols and fill them in, thus closing the race window.
	 *
	 * We want to set this value only after it certain it will succeed, as
	 * this significantly reduces the complexity of error exits.
	 */
	lck_mtx_lock(&dtrace_lock);
	if (dtrace_kernel_symbol_mode == DTRACE_KERNEL_SYMBOLS_FROM_USERSPACE) {
		dtrace_kernel_symbol_mode = DTRACE_KERNEL_SYMBOLS_FROM_KERNEL;
	}
	lck_mtx_unlock(&dtrace_lock);

	return (0);
}

/*ARGSUSED*/
static int
dtrace_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
#pragma unused(flag, otyp, cred_p) /* __APPLE__ */
	minor_t minor = getminor(dev);
	dtrace_state_t *state;

	/* APPLE NOTE: Darwin puts Helper on its own major device. */
	state = dtrace_state_get(minor);

	lck_mtx_lock(&cpu_lock);
	lck_mtx_lock(&dtrace_lock);

	if (state->dts_anon) {
		/*
		 * There is anonymous state. Destroy that first.
		 */
		ASSERT(dtrace_anon.dta_state == NULL);
		dtrace_state_destroy(state->dts_anon);
	}

	dtrace_state_destroy(state);
	ASSERT(dtrace_opens > 0);

	/*
	 * Only relinquish control of the kernel debugger interface when there
	 * are no consumers and no anonymous enablings.
	 */
	if (--dtrace_opens == 0 && dtrace_anon.dta_enabling == NULL)
		(void) kdi_dtrace_set(KDI_DTSET_DTRACE_DEACTIVATE);
	
	lck_mtx_unlock(&dtrace_lock);
	lck_mtx_unlock(&cpu_lock);

	/*
	 * Lock ordering requires the dof mode lock be taken before
	 * the dtrace_lock.
	 */
	lck_rw_lock_exclusive(&dtrace_dof_mode_lock);
	lck_mtx_lock(&dtrace_lock);
	
	if (dtrace_opens == 0) {
		/*
		 * If we are currently lazy-off, and this is the last close, transition to
		 * lazy state.
		 */
		if (dtrace_dof_mode == DTRACE_DOF_MODE_LAZY_OFF) {
			dtrace_dof_mode = DTRACE_DOF_MODE_LAZY_ON;
		}

		/*
		 * If we are the last dtrace client, switch back to lazy (from userspace) symbols
		 */
		if (dtrace_kernel_symbol_mode == DTRACE_KERNEL_SYMBOLS_FROM_KERNEL) {
			dtrace_kernel_symbol_mode = DTRACE_KERNEL_SYMBOLS_FROM_USERSPACE;
		}
	}
	
	lck_mtx_unlock(&dtrace_lock);
	lck_rw_unlock_exclusive(&dtrace_dof_mode_lock);
	
	/*
	 * Kext probes may be retained past the end of the kext's lifespan. The
	 * probes are kept until the last reference to them has been removed.
	 * Since closing an active dtrace context is likely to drop that last reference,
	 * lets take a shot at cleaning out the orphaned probes now.
	 */
	dtrace_module_unloaded(NULL);

	return (0);
}

/*ARGSUSED*/
static int
dtrace_ioctl_helper(u_long cmd, caddr_t arg, int *rv)
{
#pragma unused(rv)
	/*
	 * Safe to check this outside the dof mode lock
	 */
	if (dtrace_dof_mode == DTRACE_DOF_MODE_NEVER)
		return KERN_SUCCESS;

	switch (cmd) {
	case DTRACEHIOC_ADDDOF:
	                {
			dof_helper_t *dhp = NULL;
			size_t dof_ioctl_data_size;
			dof_ioctl_data_t* multi_dof;
			unsigned int i;
			int rval = 0;
			user_addr_t user_address = *(user_addr_t*)arg;
			uint64_t dof_count;
			int multi_dof_claimed = 0;
			proc_t* p = current_proc();

			/*
			 * Read the number of DOF sections being passed in.
			 */
			if (copyin(user_address + offsetof(dof_ioctl_data_t, dofiod_count),
				   &dof_count,
				   sizeof(dof_count))) {
				dtrace_dof_error(NULL, "failed to copyin dofiod_count");
				return (EFAULT);
			}
				   			
			/*
			 * Range check the count.
			 */
			if (dof_count == 0 || dof_count > 1024) {
				dtrace_dof_error(NULL, "dofiod_count is not valid");
				return (EINVAL);
			}
			
			/*
			 * Allocate a correctly sized structure and copyin the data.
			 */
			dof_ioctl_data_size = DOF_IOCTL_DATA_T_SIZE(dof_count);
			if ((multi_dof = kmem_alloc(dof_ioctl_data_size, KM_SLEEP)) == NULL) 
				return (ENOMEM);
			
			/* NOTE! We can no longer exit this method via return */
			if (copyin(user_address, multi_dof, dof_ioctl_data_size) != 0) {
				dtrace_dof_error(NULL, "failed copyin of dof_ioctl_data_t");
				rval = EFAULT;
				goto cleanup;
			}
			
			/*
			 * Check that the count didn't change between the first copyin and the second.
			 */
			if (multi_dof->dofiod_count != dof_count) {
				rval = EINVAL;
				goto cleanup;
			}

			/*
			 * Try to process lazily first.
			 */
			rval = dtrace_lazy_dofs_add(p, multi_dof, &multi_dof_claimed);

			/*
			 * If rval is EACCES, we must be non-lazy.
			 */
			if (rval == EACCES) {
				rval = 0;
				/*
				 * Process each dof_helper_t
				 */
				i = 0;
				do {
					dhp = &multi_dof->dofiod_helpers[i];
					
					dof_hdr_t *dof = dtrace_dof_copyin(dhp->dofhp_dof, &rval);
					
					if (dof != NULL) {					
						lck_mtx_lock(&dtrace_lock);
						
						/*
						 * dtrace_helper_slurp() takes responsibility for the dof --
						 * it may free it now or it may save it and free it later.
						 */
						if ((dhp->dofhp_dof = (uint64_t)dtrace_helper_slurp(p, dof, dhp)) == -1ULL) {
							rval = EINVAL;
						}
						
						lck_mtx_unlock(&dtrace_lock);
					}
				} while (++i < multi_dof->dofiod_count && rval == 0);
			}

			/*
			 * We need to copyout the multi_dof struct, because it contains
			 * the generation (unique id) values needed to call DTRACEHIOC_REMOVE
			 *
			 * This could certainly be better optimized.
			 */
			if (copyout(multi_dof, user_address, dof_ioctl_data_size) != 0) {
				dtrace_dof_error(NULL, "failed copyout of dof_ioctl_data_t");
				/* Don't overwrite pre-existing error code */
				if (rval == 0) rval = EFAULT;
			}
			
		cleanup:
			/*
			 * If we had to allocate struct memory, free it.
			 */
			if (multi_dof != NULL && !multi_dof_claimed) {
				kmem_free(multi_dof, dof_ioctl_data_size);
			}
			
			return rval;
		}

		case DTRACEHIOC_REMOVE: {
			int generation = *(int*)arg;
			proc_t* p = current_proc();

			/*
			 * Try lazy first.
			 */
			int rval = dtrace_lazy_dofs_remove(p, generation);
			
			/*
			 * EACCES means non-lazy
			 */
			if (rval == EACCES) {
				lck_mtx_lock(&dtrace_lock);
				rval = dtrace_helper_destroygen(p, generation);
				lck_mtx_unlock(&dtrace_lock);
			}

			return (rval);
		}

		default:
			break;
	}

	return ENOTTY;
}

/*ARGSUSED*/
static int
dtrace_ioctl(dev_t dev, u_long cmd, user_addr_t arg, int md, cred_t *cr, int *rv)
{
#pragma unused(md)
	minor_t minor = getminor(dev);
	dtrace_state_t *state;
	int rval;

	/* Darwin puts Helper on its own major device. */

	state = dtrace_state_get(minor);

	if (state->dts_anon) {
	   ASSERT(dtrace_anon.dta_state == NULL);
	   state = state->dts_anon;
	}

	switch (cmd) {
	case DTRACEIOC_PROVIDER: {
		dtrace_providerdesc_t pvd;
		dtrace_provider_t *pvp;

		if (copyin(arg, &pvd, sizeof (pvd)) != 0)
			return (EFAULT);

		pvd.dtvd_name[DTRACE_PROVNAMELEN - 1] = '\0';
		lck_mtx_lock(&dtrace_provider_lock);

		for (pvp = dtrace_provider; pvp != NULL; pvp = pvp->dtpv_next) {
			if (strncmp(pvp->dtpv_name, pvd.dtvd_name, DTRACE_PROVNAMELEN) == 0)
				break;
		}

		lck_mtx_unlock(&dtrace_provider_lock);

		if (pvp == NULL)
			return (ESRCH);

		bcopy(&pvp->dtpv_priv, &pvd.dtvd_priv, sizeof (dtrace_ppriv_t));
		bcopy(&pvp->dtpv_attr, &pvd.dtvd_attr, sizeof (dtrace_pattr_t));
		if (copyout(&pvd, arg, sizeof (pvd)) != 0)
			return (EFAULT);

		return (0);
	}

	case DTRACEIOC_EPROBE: {
		dtrace_eprobedesc_t epdesc;
		dtrace_ecb_t *ecb;
		dtrace_action_t *act;
		void *buf;
		size_t size;
		uintptr_t dest;
		int nrecs;

		if (copyin(arg, &epdesc, sizeof (epdesc)) != 0)
			return (EFAULT);

		lck_mtx_lock(&dtrace_lock);

		if ((ecb = dtrace_epid2ecb(state, epdesc.dtepd_epid)) == NULL) {
			lck_mtx_unlock(&dtrace_lock);
			return (EINVAL);
		}

		if (ecb->dte_probe == NULL) {
			lck_mtx_unlock(&dtrace_lock);
			return (EINVAL);
		}

		epdesc.dtepd_probeid = ecb->dte_probe->dtpr_id;
		epdesc.dtepd_uarg = ecb->dte_uarg;
		epdesc.dtepd_size = ecb->dte_size;

		nrecs = epdesc.dtepd_nrecs;
		epdesc.dtepd_nrecs = 0;
		for (act = ecb->dte_action; act != NULL; act = act->dta_next) {
			if (DTRACEACT_ISAGG(act->dta_kind) || act->dta_intuple)
				continue;

			epdesc.dtepd_nrecs++;
		}

		/*
		 * Now that we have the size, we need to allocate a temporary
		 * buffer in which to store the complete description.  We need
		 * the temporary buffer to be able to drop dtrace_lock()
		 * across the copyout(), below.
		 */
		size = sizeof (dtrace_eprobedesc_t) +
			(epdesc.dtepd_nrecs * sizeof (dtrace_recdesc_t));

		buf = kmem_alloc(size, KM_SLEEP);
		dest = (uintptr_t)buf;

		bcopy(&epdesc, (void *)dest, sizeof (epdesc));
		dest += offsetof(dtrace_eprobedesc_t, dtepd_rec[0]);

		for (act = ecb->dte_action; act != NULL; act = act->dta_next) {
			if (DTRACEACT_ISAGG(act->dta_kind) || act->dta_intuple)
				continue;

			if (nrecs-- == 0)
				break;

			bcopy(&act->dta_rec, (void *)dest,
			sizeof (dtrace_recdesc_t));
			dest += sizeof (dtrace_recdesc_t);
		}

		lck_mtx_unlock(&dtrace_lock);

		if (copyout(buf, arg, dest - (uintptr_t)buf) != 0) {
			kmem_free(buf, size);
			return (EFAULT);
		}

		kmem_free(buf, size);
		return (0);
	}

	case DTRACEIOC_AGGDESC: {
		dtrace_aggdesc_t aggdesc;
		dtrace_action_t *act;
		dtrace_aggregation_t *agg;
		int nrecs;
		uint32_t offs;
		dtrace_recdesc_t *lrec;
		void *buf;
		size_t size;
		uintptr_t dest;

		if (copyin(arg, &aggdesc, sizeof (aggdesc)) != 0)
			return (EFAULT);

		lck_mtx_lock(&dtrace_lock);

		if ((agg = dtrace_aggid2agg(state, aggdesc.dtagd_id)) == NULL) {
			lck_mtx_unlock(&dtrace_lock);
			return (EINVAL);
		}

		aggdesc.dtagd_epid = agg->dtag_ecb->dte_epid;

		nrecs = aggdesc.dtagd_nrecs;
		aggdesc.dtagd_nrecs = 0;

		offs = agg->dtag_base;
		lrec = &agg->dtag_action.dta_rec;
		aggdesc.dtagd_size = lrec->dtrd_offset + lrec->dtrd_size - offs;

		for (act = agg->dtag_first; ; act = act->dta_next) {
			ASSERT(act->dta_intuple ||
			DTRACEACT_ISAGG(act->dta_kind));

			/*
			 * If this action has a record size of zero, it
			 * denotes an argument to the aggregating action.
			 * Because the presence of this record doesn't (or
			 * shouldn't) affect the way the data is interpreted,
			 * we don't copy it out to save user-level the
			 * confusion of dealing with a zero-length record.
			 */
			if (act->dta_rec.dtrd_size == 0) {
				ASSERT(agg->dtag_hasarg);
				continue;
			}

			aggdesc.dtagd_nrecs++;

			if (act == &agg->dtag_action)
				break;
		}

		/*
		 * Now that we have the size, we need to allocate a temporary
		 * buffer in which to store the complete description.  We need
		 * the temporary buffer to be able to drop dtrace_lock()
		 * across the copyout(), below.
		 */
		size = sizeof (dtrace_aggdesc_t) +
			(aggdesc.dtagd_nrecs * sizeof (dtrace_recdesc_t));

		buf = kmem_alloc(size, KM_SLEEP);
		dest = (uintptr_t)buf;

		bcopy(&aggdesc, (void *)dest, sizeof (aggdesc));
		dest += offsetof(dtrace_aggdesc_t, dtagd_rec[0]);

		for (act = agg->dtag_first; ; act = act->dta_next) {
			dtrace_recdesc_t rec = act->dta_rec;

			/*
			 * See the comment in the above loop for why we pass
			 * over zero-length records.
			 */
			if (rec.dtrd_size == 0) {
				ASSERT(agg->dtag_hasarg);
				continue;
			}

			if (nrecs-- == 0)
				break;

			rec.dtrd_offset -= offs;
			bcopy(&rec, (void *)dest, sizeof (rec));
			dest += sizeof (dtrace_recdesc_t);

			if (act == &agg->dtag_action)
				break;
		}

		lck_mtx_unlock(&dtrace_lock);

		if (copyout(buf, arg, dest - (uintptr_t)buf) != 0) {
			kmem_free(buf, size);
			return (EFAULT);
		}

		kmem_free(buf, size);
		return (0);
	}

	case DTRACEIOC_ENABLE: {
		dof_hdr_t *dof;
		dtrace_enabling_t *enab = NULL;
		dtrace_vstate_t *vstate;
		int err = 0;

		*rv = 0;

		/*
		 * If a NULL argument has been passed, we take this as our
		 * cue to reevaluate our enablings.
		 */
		if (arg == 0) {
			dtrace_enabling_matchall();

			return (0);
		}

		if ((dof = dtrace_dof_copyin(arg, &rval)) == NULL)
			return (rval);

		lck_mtx_lock(&cpu_lock);
		lck_mtx_lock(&dtrace_lock);
		vstate = &state->dts_vstate;

		if (state->dts_activity != DTRACE_ACTIVITY_INACTIVE) {
			lck_mtx_unlock(&dtrace_lock);
			lck_mtx_unlock(&cpu_lock);
			dtrace_dof_destroy(dof);
			return (EBUSY);
		}

		if (dtrace_dof_slurp(dof, vstate, cr, &enab, 0, B_TRUE) != 0) {
			lck_mtx_unlock(&dtrace_lock);
			lck_mtx_unlock(&cpu_lock);
			dtrace_dof_destroy(dof);
			return (EINVAL);
		}

		if ((rval = dtrace_dof_options(dof, state)) != 0) {
			dtrace_enabling_destroy(enab);
			lck_mtx_unlock(&dtrace_lock);
			lck_mtx_unlock(&cpu_lock);
			dtrace_dof_destroy(dof);
			return (rval);
		}

		if ((err = dtrace_enabling_match(enab, rv, NULL)) == 0) {
			err = dtrace_enabling_retain(enab);
		} else {
			dtrace_enabling_destroy(enab);
		}

		lck_mtx_unlock(&dtrace_lock);
		lck_mtx_unlock(&cpu_lock);
		dtrace_dof_destroy(dof);

		return (err);
	}

	case DTRACEIOC_REPLICATE: {
		dtrace_repldesc_t desc;
		dtrace_probedesc_t *match = &desc.dtrpd_match;
		dtrace_probedesc_t *create = &desc.dtrpd_create;
		int err;

		if (copyin(arg, &desc, sizeof (desc)) != 0)
			return (EFAULT);

		match->dtpd_provider[DTRACE_PROVNAMELEN - 1] = '\0';
		match->dtpd_mod[DTRACE_MODNAMELEN - 1] = '\0';
		match->dtpd_func[DTRACE_FUNCNAMELEN - 1] = '\0';
		match->dtpd_name[DTRACE_NAMELEN - 1] = '\0';

		create->dtpd_provider[DTRACE_PROVNAMELEN - 1] = '\0';
		create->dtpd_mod[DTRACE_MODNAMELEN - 1] = '\0';
		create->dtpd_func[DTRACE_FUNCNAMELEN - 1] = '\0';
		create->dtpd_name[DTRACE_NAMELEN - 1] = '\0';

		lck_mtx_lock(&dtrace_lock);
		err = dtrace_enabling_replicate(state, match, create);
		lck_mtx_unlock(&dtrace_lock);

		return (err);
	}

	case DTRACEIOC_PROBEMATCH:
	case DTRACEIOC_PROBES: {
		dtrace_probe_t *probe = NULL;
		dtrace_probedesc_t desc;
		dtrace_probekey_t pkey;
		dtrace_id_t i;
		int m = 0;
		uint32_t priv;
		uid_t uid;
		zoneid_t zoneid;

		if (copyin(arg, &desc, sizeof (desc)) != 0)
			return (EFAULT);

		desc.dtpd_provider[DTRACE_PROVNAMELEN - 1] = '\0';
		desc.dtpd_mod[DTRACE_MODNAMELEN - 1] = '\0';
		desc.dtpd_func[DTRACE_FUNCNAMELEN - 1] = '\0';
		desc.dtpd_name[DTRACE_NAMELEN - 1] = '\0';

		/*
		 * Before we attempt to match this probe, we want to give
		 * all providers the opportunity to provide it.
		 */
		if (desc.dtpd_id == DTRACE_IDNONE) {
			lck_mtx_lock(&dtrace_provider_lock);
			dtrace_probe_provide(&desc, NULL);
			lck_mtx_unlock(&dtrace_provider_lock);
			desc.dtpd_id++;
		}

		if (cmd == DTRACEIOC_PROBEMATCH)  {
			dtrace_probekey(&desc, &pkey);
			pkey.dtpk_id = DTRACE_IDNONE;
		}

		dtrace_cred2priv(cr, &priv, &uid, &zoneid);

		lck_mtx_lock(&dtrace_lock);

		if (cmd == DTRACEIOC_PROBEMATCH) {
                        /* Quiet compiler warning */
			for (i = desc.dtpd_id; i <= (dtrace_id_t)dtrace_nprobes; i++) {
				if ((probe = dtrace_probes[i - 1]) != NULL &&
					(m = dtrace_match_probe(probe, &pkey,
					priv, uid, zoneid)) != 0)
					break;
			}

			if (m < 0) {
				lck_mtx_unlock(&dtrace_lock);
				return (EINVAL);
			}

		} else {
                        /* Quiet compiler warning */
			for (i = desc.dtpd_id; i <= (dtrace_id_t)dtrace_nprobes; i++) {
				if ((probe = dtrace_probes[i - 1]) != NULL &&
					dtrace_match_priv(probe, priv, uid, zoneid))
					break;
			}
		}

		if (probe == NULL) {
			lck_mtx_unlock(&dtrace_lock);
			return (ESRCH);
		}

		dtrace_probe_description(probe, &desc);
		lck_mtx_unlock(&dtrace_lock);

		if (copyout(&desc, arg, sizeof (desc)) != 0)
			return (EFAULT);

		return (0);
	}

	case DTRACEIOC_PROBEARG: {
		dtrace_argdesc_t desc;
		dtrace_probe_t *probe;
		dtrace_provider_t *prov;

		if (copyin(arg, &desc, sizeof (desc)) != 0)
			return (EFAULT);

		if (desc.dtargd_id == DTRACE_IDNONE)
			return (EINVAL);

		if (desc.dtargd_ndx == DTRACE_ARGNONE)
			return (EINVAL);

		lck_mtx_lock(&dtrace_provider_lock);
		lck_mtx_lock(&mod_lock);
		lck_mtx_lock(&dtrace_lock);

                /* Quiet compiler warning */
		if (desc.dtargd_id > (dtrace_id_t)dtrace_nprobes) {
			lck_mtx_unlock(&dtrace_lock);
			lck_mtx_unlock(&mod_lock);
			lck_mtx_unlock(&dtrace_provider_lock);
			return (EINVAL);
		}

		if ((probe = dtrace_probes[desc.dtargd_id - 1]) == NULL) {
			lck_mtx_unlock(&dtrace_lock);
			lck_mtx_unlock(&mod_lock);
			lck_mtx_unlock(&dtrace_provider_lock);
			return (EINVAL);
		}

		lck_mtx_unlock(&dtrace_lock);

		prov = probe->dtpr_provider;

		if (prov->dtpv_pops.dtps_getargdesc == NULL) {
		/*
		 * There isn't any typed information for this probe.
		 * Set the argument number to DTRACE_ARGNONE.
		 */
			desc.dtargd_ndx = DTRACE_ARGNONE;
		} else {
			desc.dtargd_native[0] = '\0';
			desc.dtargd_xlate[0] = '\0';
			desc.dtargd_mapping = desc.dtargd_ndx;

			prov->dtpv_pops.dtps_getargdesc(prov->dtpv_arg,
			probe->dtpr_id, probe->dtpr_arg, &desc);
		}

		lck_mtx_unlock(&mod_lock);
		lck_mtx_unlock(&dtrace_provider_lock);

		if (copyout(&desc, arg, sizeof (desc)) != 0)
			return (EFAULT);

		return (0);
	}

	case DTRACEIOC_GO: {
		processorid_t cpuid;
		rval = dtrace_state_go(state, &cpuid);

		if (rval != 0)
			return (rval);

		if (copyout(&cpuid, arg, sizeof (cpuid)) != 0)
			return (EFAULT);

		return (0);
	}

	case DTRACEIOC_STOP: {
		processorid_t cpuid;

		lck_mtx_lock(&dtrace_lock);
		rval = dtrace_state_stop(state, &cpuid);
		lck_mtx_unlock(&dtrace_lock);

		if (rval != 0)
			return (rval);

		if (copyout(&cpuid, arg, sizeof (cpuid)) != 0)
			return (EFAULT);

		return (0);
	}

	case DTRACEIOC_DOFGET: {
		dof_hdr_t hdr, *dof;
		uint64_t len;

		if (copyin(arg, &hdr, sizeof (hdr)) != 0)
			return (EFAULT);

		lck_mtx_lock(&dtrace_lock);
		dof = dtrace_dof_create(state);
		lck_mtx_unlock(&dtrace_lock);

		len = MIN(hdr.dofh_loadsz, dof->dofh_loadsz);
		rval = copyout(dof, arg, len);
		dtrace_dof_destroy(dof);

		return (rval == 0 ? 0 : EFAULT);
	}

	case DTRACEIOC_SLEEP: {
		int64_t time;
		uint64_t abstime;
		uint64_t rvalue = DTRACE_WAKE_TIMEOUT;

		if (copyin(arg, &time, sizeof(time)) != 0)
			return (EFAULT);

		nanoseconds_to_absolutetime((uint64_t)time, &abstime);
		clock_absolutetime_interval_to_deadline(abstime, &abstime);

		if (assert_wait_deadline(state, THREAD_ABORTSAFE, abstime) == THREAD_WAITING) {
			if (state->dts_buf_over_limit > 0) {
				clear_wait(current_thread(), THREAD_INTERRUPTED);
				rvalue = DTRACE_WAKE_BUF_LIMIT;
			} else {
				thread_block(THREAD_CONTINUE_NULL);
				if (state->dts_buf_over_limit > 0) {
					rvalue = DTRACE_WAKE_BUF_LIMIT;
				}
			}
		}

		if (copyout(&rvalue, arg, sizeof(rvalue)) != 0)
			return (EFAULT);

		return (0);
	}

	case DTRACEIOC_SIGNAL: {
		wakeup(state);
		return (0);
	}

	case DTRACEIOC_AGGSNAP:
	case DTRACEIOC_BUFSNAP: {
		dtrace_bufdesc_t desc;
		caddr_t cached;
		boolean_t over_limit;
		dtrace_buffer_t *buf;

		if (copyin(arg, &desc, sizeof (desc)) != 0)
			return (EFAULT);

		if ((int)desc.dtbd_cpu < 0 || desc.dtbd_cpu >= NCPU)
			return (EINVAL);

		lck_mtx_lock(&dtrace_lock);

		if (cmd == DTRACEIOC_BUFSNAP) {
			buf = &state->dts_buffer[desc.dtbd_cpu];
		} else {
			buf = &state->dts_aggbuffer[desc.dtbd_cpu];
		}

		if (buf->dtb_flags & (DTRACEBUF_RING | DTRACEBUF_FILL)) {
			size_t sz = buf->dtb_offset;

			if (state->dts_activity != DTRACE_ACTIVITY_STOPPED) {
				lck_mtx_unlock(&dtrace_lock);
				return (EBUSY);
			}

			/*
			 * If this buffer has already been consumed, we're
			 * going to indicate that there's nothing left here
			 * to consume.
			 */
			if (buf->dtb_flags & DTRACEBUF_CONSUMED) {
				lck_mtx_unlock(&dtrace_lock);

				desc.dtbd_size = 0;
				desc.dtbd_drops = 0;
				desc.dtbd_errors = 0;
				desc.dtbd_oldest = 0;
				sz = sizeof (desc);

				if (copyout(&desc, arg, sz) != 0)
					return (EFAULT);

				return (0);
			}

			/*
			 * If this is a ring buffer that has wrapped, we want
			 * to copy the whole thing out.
			 */
			if (buf->dtb_flags & DTRACEBUF_WRAPPED) {
				dtrace_buffer_polish(buf);
				sz = buf->dtb_size;
			}

			if (copyout(buf->dtb_tomax, (user_addr_t)desc.dtbd_data, sz) != 0) {
				lck_mtx_unlock(&dtrace_lock);
				return (EFAULT);
			}

			desc.dtbd_size = sz;
			desc.dtbd_drops = buf->dtb_drops;
			desc.dtbd_errors = buf->dtb_errors;
			desc.dtbd_oldest = buf->dtb_xamot_offset;
			desc.dtbd_timestamp = dtrace_gethrtime();

			lck_mtx_unlock(&dtrace_lock);

			if (copyout(&desc, arg, sizeof (desc)) != 0)
				return (EFAULT);

			buf->dtb_flags |= DTRACEBUF_CONSUMED;

			return (0);
		}

		if (buf->dtb_tomax == NULL) {
			ASSERT(buf->dtb_xamot == NULL);
			lck_mtx_unlock(&dtrace_lock);
			return (ENOENT);
		}

		cached = buf->dtb_tomax;
		over_limit = buf->dtb_cur_limit == buf->dtb_size;

		ASSERT(!(buf->dtb_flags & DTRACEBUF_NOSWITCH));

		dtrace_xcall(desc.dtbd_cpu,
			(dtrace_xcall_t)dtrace_buffer_switch, buf);

		state->dts_errors += buf->dtb_xamot_errors;

		/*
		* If the buffers did not actually switch, then the cross call
		* did not take place -- presumably because the given CPU is
		* not in the ready set.  If this is the case, we'll return
		* ENOENT.
		*/
		if (buf->dtb_tomax == cached) {
			ASSERT(buf->dtb_xamot != cached);
			lck_mtx_unlock(&dtrace_lock);
			return (ENOENT);
		}

		ASSERT(cached == buf->dtb_xamot);
		/*
		 * At this point we know the buffer have switched, so we
		 * can decrement the over limit count if the buffer was over
		 * its limit. The new buffer might already be over its limit
		 * yet, but we don't care since we're guaranteed not to be
		 * checking the buffer over limit count  at this point.
		 */
		if (over_limit) {
			uint32_t old = atomic_add_32(&state->dts_buf_over_limit, -1);
			#pragma unused(old)

			/*
			 * Verify that we didn't underflow the value
			 */
			ASSERT(old != 0);
		}

		/*
		* We have our snapshot; now copy it out.
		*/
		if (copyout(buf->dtb_xamot, (user_addr_t)desc.dtbd_data,
					buf->dtb_xamot_offset) != 0) {
			lck_mtx_unlock(&dtrace_lock);
			return (EFAULT);
		}

		desc.dtbd_size = buf->dtb_xamot_offset;
		desc.dtbd_drops = buf->dtb_xamot_drops;
		desc.dtbd_errors = buf->dtb_xamot_errors;
		desc.dtbd_oldest = 0;
		desc.dtbd_timestamp = buf->dtb_switched;

		lck_mtx_unlock(&dtrace_lock);

		/*
		 * Finally, copy out the buffer description.
		 */
		if (copyout(&desc, arg, sizeof (desc)) != 0)
			return (EFAULT);

		return (0);
	}

	case DTRACEIOC_CONF: {
		dtrace_conf_t conf;

		bzero(&conf, sizeof (conf));
		conf.dtc_difversion = DIF_VERSION;
		conf.dtc_difintregs = DIF_DIR_NREGS;
		conf.dtc_diftupregs = DIF_DTR_NREGS;
		conf.dtc_ctfmodel = CTF_MODEL_NATIVE;

		if (copyout(&conf, arg, sizeof (conf)) != 0)
			return (EFAULT);

		return (0);
	}

	case DTRACEIOC_STATUS: {
		dtrace_status_t stat;
		dtrace_dstate_t *dstate;
		int i, j;
		uint64_t nerrs;

		/*
		* See the comment in dtrace_state_deadman() for the reason
		* for setting dts_laststatus to INT64_MAX before setting
		* it to the correct value.
		*/
		state->dts_laststatus = INT64_MAX;
		dtrace_membar_producer();
		state->dts_laststatus = dtrace_gethrtime();

		bzero(&stat, sizeof (stat));

		lck_mtx_lock(&dtrace_lock);

		if (state->dts_activity == DTRACE_ACTIVITY_INACTIVE) {
			lck_mtx_unlock(&dtrace_lock);
			return (ENOENT);
		}

		if (state->dts_activity == DTRACE_ACTIVITY_DRAINING)
			stat.dtst_exiting = 1;

		nerrs = state->dts_errors;
		dstate = &state->dts_vstate.dtvs_dynvars;

		for (i = 0; i < (int)NCPU; i++) {
			dtrace_dstate_percpu_t *dcpu = &dstate->dtds_percpu[i];

			stat.dtst_dyndrops += dcpu->dtdsc_drops;
			stat.dtst_dyndrops_dirty += dcpu->dtdsc_dirty_drops;
			stat.dtst_dyndrops_rinsing += dcpu->dtdsc_rinsing_drops;

			if (state->dts_buffer[i].dtb_flags & DTRACEBUF_FULL)
				stat.dtst_filled++;

			nerrs += state->dts_buffer[i].dtb_errors;

			for (j = 0; j < state->dts_nspeculations; j++) {
				dtrace_speculation_t *spec;
				dtrace_buffer_t *buf;

				spec = &state->dts_speculations[j];
				buf = &spec->dtsp_buffer[i];
				stat.dtst_specdrops += buf->dtb_xamot_drops;
			}
		}

		stat.dtst_specdrops_busy = state->dts_speculations_busy;
		stat.dtst_specdrops_unavail = state->dts_speculations_unavail;
		stat.dtst_stkstroverflows = state->dts_stkstroverflows;
		stat.dtst_dblerrors = state->dts_dblerrors;
		stat.dtst_killed =
			(state->dts_activity == DTRACE_ACTIVITY_KILLED);
		stat.dtst_errors = nerrs;

		lck_mtx_unlock(&dtrace_lock);

		if (copyout(&stat, arg, sizeof (stat)) != 0)
			return (EFAULT);

		return (0);
	}

	case DTRACEIOC_FORMAT: {
		dtrace_fmtdesc_t fmt;
		char *str;
		int len;

		if (copyin(arg, &fmt, sizeof (fmt)) != 0)
			return (EFAULT);

		lck_mtx_lock(&dtrace_lock);

		if (fmt.dtfd_format == 0 ||
			fmt.dtfd_format > state->dts_nformats) {
			lck_mtx_unlock(&dtrace_lock);
			return (EINVAL);
		}

		/*
		 * Format strings are allocated contiguously and they are
		 * never freed; if a format index is less than the number
		 * of formats, we can assert that the format map is non-NULL
		 * and that the format for the specified index is non-NULL.
		 */
		ASSERT(state->dts_formats != NULL);
		str = state->dts_formats[fmt.dtfd_format - 1];
		ASSERT(str != NULL);

		len = strlen(str) + 1;

		if (len > fmt.dtfd_length) {
			fmt.dtfd_length = len;

			if (copyout(&fmt, arg, sizeof (fmt)) != 0) {
				lck_mtx_unlock(&dtrace_lock);
				return (EINVAL);
			}
		} else {
			if (copyout(str, (user_addr_t)fmt.dtfd_string, len) != 0) {
				lck_mtx_unlock(&dtrace_lock);
				return (EINVAL);
			}
		}

		lck_mtx_unlock(&dtrace_lock);
		return (0);
	}

	case DTRACEIOC_MODUUIDSLIST: {
		size_t module_uuids_list_size;
		dtrace_module_uuids_list_t* uuids_list;
		uint64_t dtmul_count;

		/*
		 * Security restrictions make this operation illegal, if this is enabled DTrace
		 * must refuse to provide any fbt probes.
		 */
		if (dtrace_fbt_probes_restricted()) {
			cmn_err(CE_WARN, "security restrictions disallow DTRACEIOC_MODUUIDSLIST");	
			return (EPERM);
		}

		/*
		 * Fail if the kernel symbol mode makes this operation illegal.
		 * Both NEVER & ALWAYS_FROM_KERNEL are permanent states, it is legal to check
		 * for them without holding the dtrace_lock.
		 */		
		if (dtrace_kernel_symbol_mode == DTRACE_KERNEL_SYMBOLS_NEVER ||
		    dtrace_kernel_symbol_mode == DTRACE_KERNEL_SYMBOLS_ALWAYS_FROM_KERNEL) {
			cmn_err(CE_WARN, "dtrace_kernel_symbol_mode of %u disallows DTRACEIOC_MODUUIDSLIST", dtrace_kernel_symbol_mode);
			return (EPERM);
		}
			
		/*
		 * Read the number of symbolsdesc structs being passed in.
		 */
		if (copyin(arg + offsetof(dtrace_module_uuids_list_t, dtmul_count),
			   &dtmul_count,
			   sizeof(dtmul_count))) {
			cmn_err(CE_WARN, "failed to copyin dtmul_count");
			return (EFAULT);
		}
		
		/*
		 * Range check the count. More than 2k kexts is probably an error.
		 */
		if (dtmul_count > 2048) {
			cmn_err(CE_WARN, "dtmul_count is not valid");
			return (EINVAL);
		}

		/*
		 * For all queries, we return EINVAL when the user specified
		 * count does not match the actual number of modules we find
		 * available.
		 *
		 * If the user specified count is zero, then this serves as a
		 * simple query to count the available modules in need of symbols.
		 */
		
		rval = 0;

		if (dtmul_count == 0)
		{
			lck_mtx_lock(&mod_lock);
			struct modctl* ctl = dtrace_modctl_list;
			while (ctl) {
				/* Update the private probes bit */
				if (dtrace_provide_private_probes)
					ctl->mod_flags |= MODCTL_FBT_PROVIDE_PRIVATE_PROBES;

				ASSERT(!MOD_HAS_USERSPACE_SYMBOLS(ctl));
				if (!MOD_SYMBOLS_DONE(ctl)) {
					dtmul_count++;
					rval = EINVAL;
				}
				ctl = ctl->mod_next;
			}
			lck_mtx_unlock(&mod_lock);
			
			if (copyout(&dtmul_count, arg, sizeof (dtmul_count)) != 0)
				return (EFAULT);
			else
				return (rval);
		}
		
		/*
		 * If we reach this point, then we have a request for full list data.
		 * Allocate a correctly sized structure and copyin the data.
		 */
		module_uuids_list_size = DTRACE_MODULE_UUIDS_LIST_SIZE(dtmul_count);
		if ((uuids_list = kmem_alloc(module_uuids_list_size, KM_SLEEP)) == NULL) 
			return (ENOMEM);
		
		/* NOTE! We can no longer exit this method via return */
		if (copyin(arg, uuids_list, module_uuids_list_size) != 0) {
			cmn_err(CE_WARN, "failed copyin of dtrace_module_uuids_list_t");
			rval = EFAULT;
			goto moduuidslist_cleanup;
		}
		
		/*
		 * Check that the count didn't change between the first copyin and the second.
		 */
		if (uuids_list->dtmul_count != dtmul_count) {
			rval = EINVAL;
			goto moduuidslist_cleanup;
		}
		
		/*
		 * Build the list of UUID's that need symbols
		 */
		lck_mtx_lock(&mod_lock);
		
		dtmul_count = 0;
		
		struct modctl* ctl = dtrace_modctl_list;
		while (ctl) {
			/* Update the private probes bit */
			if (dtrace_provide_private_probes)
				ctl->mod_flags |= MODCTL_FBT_PROVIDE_PRIVATE_PROBES;

			/*
			 * We assume that userspace symbols will be "better" than kernel level symbols,
			 * as userspace can search for dSYM(s) and symbol'd binaries. Even if kernel syms
			 * are available, add user syms if the module might use them.
			 */
			ASSERT(!MOD_HAS_USERSPACE_SYMBOLS(ctl));
			if (!MOD_SYMBOLS_DONE(ctl)) {
				UUID* uuid = &uuids_list->dtmul_uuid[dtmul_count];
				if (dtmul_count++ < uuids_list->dtmul_count) {
					memcpy(uuid, ctl->mod_uuid, sizeof(UUID));
				}
			}
			ctl = ctl->mod_next;
		}
		
		lck_mtx_unlock(&mod_lock);
		
		if (uuids_list->dtmul_count < dtmul_count)
			rval = EINVAL;
		
		uuids_list->dtmul_count = dtmul_count;
		
		/*
		 * Copyout the symbols list (or at least the count!)
		 */
		if (copyout(uuids_list, arg, module_uuids_list_size) != 0) {
			cmn_err(CE_WARN, "failed copyout of dtrace_symbolsdesc_list_t");
			rval = EFAULT;
		}
		
	moduuidslist_cleanup:
		/*
		 * If we had to allocate struct memory, free it.
		 */
		if (uuids_list != NULL) {
			kmem_free(uuids_list, module_uuids_list_size);
		}
		
		return rval;
	}

	case DTRACEIOC_PROVMODSYMS: {
		size_t module_symbols_size;
		dtrace_module_symbols_t* module_symbols;
		uint64_t dtmodsyms_count;

		/*
		 * Security restrictions make this operation illegal, if this is enabled DTrace
		 * must refuse to provide any fbt probes.
		 */
		if (dtrace_fbt_probes_restricted()) {
			cmn_err(CE_WARN, "security restrictions disallow DTRACEIOC_MODUUIDSLIST");	
			return (EPERM);
		}

		/*
		 * Fail if the kernel symbol mode makes this operation illegal.
		 * Both NEVER & ALWAYS_FROM_KERNEL are permanent states, it is legal to check
		 * for them without holding the dtrace_lock.
		 */
		if (dtrace_kernel_symbol_mode == DTRACE_KERNEL_SYMBOLS_NEVER ||
		    dtrace_kernel_symbol_mode == DTRACE_KERNEL_SYMBOLS_ALWAYS_FROM_KERNEL) {
			cmn_err(CE_WARN, "dtrace_kernel_symbol_mode of %u disallows DTRACEIOC_PROVMODSYMS", dtrace_kernel_symbol_mode);
			return (EPERM);
		}
		
		/*
		 * Read the number of module symbols structs being passed in.
		 */
		if (copyin(arg + offsetof(dtrace_module_symbols_t, dtmodsyms_count),
			   &dtmodsyms_count,
			   sizeof(dtmodsyms_count))) {
			cmn_err(CE_WARN, "failed to copyin dtmodsyms_count");
			return (EFAULT);
		}
		
		/*
		 * Range check the count. How much data can we pass around?
		 * FIX ME!
		 */
		if (dtmodsyms_count == 0 || (dtmodsyms_count > 100 * 1024)) {
			cmn_err(CE_WARN, "dtmodsyms_count is not valid");
			return (EINVAL);
		}
			
		/*
		 * Allocate a correctly sized structure and copyin the data.
		 */
		module_symbols_size = DTRACE_MODULE_SYMBOLS_SIZE(dtmodsyms_count);
		if ((module_symbols = kmem_alloc(module_symbols_size, KM_SLEEP)) == NULL) 
			return (ENOMEM);
			
		rval = 0;

		/* NOTE! We can no longer exit this method via return */
		if (copyin(arg, module_symbols, module_symbols_size) != 0) {
			cmn_err(CE_WARN, "failed copyin of dtrace_module_symbols_t");
			rval = EFAULT;
			goto module_symbols_cleanup;
		}
			
		/*
		 * Check that the count didn't change between the first copyin and the second.
		 */
		if (module_symbols->dtmodsyms_count != dtmodsyms_count) {
			rval = EINVAL;
			goto module_symbols_cleanup;
		}
			
		/*
		 * Find the modctl to add symbols to.
		 */
		lck_mtx_lock(&dtrace_provider_lock);
		lck_mtx_lock(&mod_lock);
		
		struct modctl* ctl = dtrace_modctl_list;
		while (ctl) {
			/* Update the private probes bit */
			if (dtrace_provide_private_probes)
				ctl->mod_flags |= MODCTL_FBT_PROVIDE_PRIVATE_PROBES;

			ASSERT(!MOD_HAS_USERSPACE_SYMBOLS(ctl));
			if (MOD_HAS_UUID(ctl) && !MOD_SYMBOLS_DONE(ctl)) {
				if (memcmp(module_symbols->dtmodsyms_uuid, ctl->mod_uuid, sizeof(UUID)) == 0) {
					/* BINGO! */
					ctl->mod_user_symbols = module_symbols;
					break;
				}
			}
			ctl = ctl->mod_next;
		}

		if (ctl) {
			dtrace_provider_t *prv;

			/*
			 * We're going to call each providers per-module provide operation
			 * specifying only this module.
			 */
			for (prv = dtrace_provider; prv != NULL; prv = prv->dtpv_next)
				prv->dtpv_pops.dtps_provide_module(prv->dtpv_arg, ctl);	
						
			/*
			 * We gave every provider a chance to provide with the user syms, go ahead and clear them
			 */
			ctl->mod_user_symbols = NULL; /* MUST reset this to clear HAS_USERSPACE_SYMBOLS */
		}
		
		lck_mtx_unlock(&mod_lock);
		lck_mtx_unlock(&dtrace_provider_lock);

	module_symbols_cleanup:
		/*
		 * If we had to allocate struct memory, free it.
		 */
		if (module_symbols != NULL) {
			kmem_free(module_symbols, module_symbols_size);
		}
		
		return rval;
	}

	case DTRACEIOC_PROCWAITFOR: {
		dtrace_procdesc_t pdesc = {
			.p_name = {0},
			.p_pid  = -1
		};

		if ((rval = copyin(arg, &pdesc, sizeof(pdesc))) != 0)
			goto proc_waitfor_error;

		if ((rval = dtrace_proc_waitfor(&pdesc)) != 0)
			goto proc_waitfor_error;

		if ((rval = copyout(&pdesc, arg, sizeof(pdesc))) != 0)
			goto proc_waitfor_error;

		return 0;

	proc_waitfor_error:
		/* The process was suspended, revert this since the client will not do it. */
		if (pdesc.p_pid != -1) {
			proc_t *proc = proc_find(pdesc.p_pid);
			if (proc != PROC_NULL) {
				task_pidresume(proc->task);
				proc_rele(proc);
			}
		}

		return rval;
	}

	default:
		break;
	}

	return (ENOTTY);
}

/*
 * APPLE NOTE:  dtrace_detach not implemented
 */
#if !defined(__APPLE__)
/*ARGSUSED*/
static int
dtrace_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	dtrace_state_t *state;

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	lck_mtx_lock(&cpu_lock);
	lck_mtx_lock(&dtrace_provider_lock);
	lck_mtx_lock(&dtrace_lock);

	ASSERT(dtrace_opens == 0);

	if (dtrace_helpers > 0) {
		lck_mtx_unlock(&dtrace_lock);
		lck_mtx_unlock(&dtrace_provider_lock);
		lck_mtx_unlock(&cpu_lock);
		return (DDI_FAILURE);
	}

	if (dtrace_unregister((dtrace_provider_id_t)dtrace_provider) != 0) {
		lck_mtx_unlock(&dtrace_lock);
		lck_mtx_unlock(&dtrace_provider_lock);
		lck_mtx_unlock(&cpu_lock);
		return (DDI_FAILURE);
	}

	dtrace_provider = NULL;

	if ((state = dtrace_anon_grab()) != NULL) {
		/*
		 * If there were ECBs on this state, the provider should
		 * have not been allowed to detach; assert that there is
		 * none.
		 */
		ASSERT(state->dts_necbs == 0);
		dtrace_state_destroy(state);

		/*
		 * If we're being detached with anonymous state, we need to
		 * indicate to the kernel debugger that DTrace is now inactive.
		 */
		(void) kdi_dtrace_set(KDI_DTSET_DTRACE_DEACTIVATE);
	}

	bzero(&dtrace_anon, sizeof (dtrace_anon_t));
	unregister_cpu_setup_func((cpu_setup_func_t *)dtrace_cpu_setup, NULL);
	dtrace_cpu_init = NULL;
	dtrace_helpers_cleanup = NULL;
	dtrace_helpers_fork = NULL;
	dtrace_cpustart_init = NULL;
	dtrace_cpustart_fini = NULL;
	dtrace_debugger_init = NULL;
	dtrace_debugger_fini = NULL;
	dtrace_kreloc_init = NULL;
	dtrace_kreloc_fini = NULL;
	dtrace_modload = NULL;
	dtrace_modunload = NULL;

	lck_mtx_unlock(&cpu_lock);

	if (dtrace_helptrace_enabled) {
		kmem_free(dtrace_helptrace_buffer, dtrace_helptrace_bufsize);
		dtrace_helptrace_buffer = NULL;
	}

	kmem_free(dtrace_probes, dtrace_nprobes * sizeof (dtrace_probe_t *));
	dtrace_probes = NULL;
	dtrace_nprobes = 0;

	dtrace_hash_destroy(dtrace_bymod);
	dtrace_hash_destroy(dtrace_byfunc);
	dtrace_hash_destroy(dtrace_byname);
	dtrace_bymod = NULL;
	dtrace_byfunc = NULL;
	dtrace_byname = NULL;

	kmem_cache_destroy(dtrace_state_cache);
	vmem_destroy(dtrace_arena);

	if (dtrace_toxrange != NULL) {
		kmem_free(dtrace_toxrange,
		    dtrace_toxranges_max * sizeof (dtrace_toxrange_t));
		dtrace_toxrange = NULL;
		dtrace_toxranges = 0;
		dtrace_toxranges_max = 0;
	}

	ddi_remove_minor_node(dtrace_devi, NULL);
	dtrace_devi = NULL;

	ddi_soft_state_fini(&dtrace_softstate);

	ASSERT(dtrace_vtime_references == 0);
	ASSERT(dtrace_opens == 0);
	ASSERT(dtrace_retained == NULL);

	lck_mtx_unlock(&dtrace_lock);
	lck_mtx_unlock(&dtrace_provider_lock);

	/*
	 * We don't destroy the task queue until after we have dropped our
	 * locks (taskq_destroy() may block on running tasks).  To prevent
	 * attempting to do work after we have effectively detached but before
	 * the task queue has been destroyed, all tasks dispatched via the
	 * task queue must check that DTrace is still attached before
	 * performing any operation.
	 */
	taskq_destroy(dtrace_taskq);
	dtrace_taskq = NULL;

	return (DDI_SUCCESS);
}
#endif  /* __APPLE__ */

d_open_t _dtrace_open, helper_open;
d_close_t _dtrace_close, helper_close;
d_ioctl_t _dtrace_ioctl, helper_ioctl;

int 
_dtrace_open(dev_t dev, int flags, int devtype, struct proc *p)
{
#pragma unused(p)
	dev_t locdev = dev;

	return  dtrace_open( &locdev, flags, devtype, CRED());
}

int
helper_open(dev_t dev, int flags, int devtype, struct proc *p)
{	
#pragma unused(dev,flags,devtype,p)
	return 0;
}

int
_dtrace_close(dev_t dev, int flags, int devtype, struct proc *p)
{
#pragma unused(p)
	return dtrace_close( dev, flags, devtype, CRED());
}

int
helper_close(dev_t dev, int flags, int devtype, struct proc *p)
{
#pragma unused(dev,flags,devtype,p)
	return 0;
}

int
_dtrace_ioctl(dev_t dev, u_long cmd, caddr_t data, int fflag, struct proc *p)
{
#pragma unused(p)
	int err, rv = 0;
    user_addr_t uaddrp;

    if (proc_is64bit(p))
		uaddrp = *(user_addr_t *)data;
	else
		uaddrp = (user_addr_t) *(uint32_t *)data;

	err = dtrace_ioctl(dev, cmd, uaddrp, fflag, CRED(), &rv);
	
	/* Darwin's BSD ioctls only return -1 or zero. Overload errno to mimic Solaris. 20 bits suffice. */
	if (err != 0) {
		ASSERT( (err & 0xfffff000) == 0 );
		return (err & 0xfff); /* ioctl will return -1 and will set errno to an error code < 4096 */
	} else if (rv != 0) {
		ASSERT( (rv & 0xfff00000) == 0 );
		return (((rv & 0xfffff) << 12)); /* ioctl will return -1 and will set errno to a value >= 4096 */
	} else 
		return 0;
}

int
helper_ioctl(dev_t dev, u_long cmd, caddr_t data, int fflag, struct proc *p)
{
#pragma unused(dev,fflag,p)
	int err, rv = 0;
	
	err = dtrace_ioctl_helper(cmd, data, &rv);
	/* Darwin's BSD ioctls only return -1 or zero. Overload errno to mimic Solaris. 20 bits suffice. */
	if (err != 0) {
		ASSERT( (err & 0xfffff000) == 0 );
		return (err & 0xfff); /* ioctl will return -1 and will set errno to an error code < 4096 */
	} else if (rv != 0) {
		ASSERT( (rv & 0xfff00000) == 0 );
		return (((rv & 0xfffff) << 12)); /* ioctl will return -1 and will set errno to a value >= 4096 */
	} else 
		return 0;
}

#define HELPER_MAJOR  -24 /* let the kernel pick the device number */

/*
 * A struct describing which functions will get invoked for certain
 * actions.
 */
static struct cdevsw helper_cdevsw =
{
	helper_open,		/* open */
	helper_close,		/* close */
	eno_rdwrt,			/* read */
	eno_rdwrt,			/* write */
	helper_ioctl,		/* ioctl */
	(stop_fcn_t *)nulldev, /* stop */
	(reset_fcn_t *)nulldev, /* reset */
	NULL,				/* tty's */
	eno_select,			/* select */
	eno_mmap,			/* mmap */
	eno_strat,			/* strategy */
	eno_getc,			/* getc */
	eno_putc,			/* putc */
	0					/* type */
};

static int helper_majdevno = 0;

static int gDTraceInited = 0;

void
helper_init( void )
{
	/*
	 * Once the "helper" is initialized, it can take ioctl calls that use locks
	 * and zones initialized in dtrace_init. Make certain dtrace_init was called
	 * before us.
	 */

	if (!gDTraceInited) {
		panic("helper_init before dtrace_init\n");
	}

	if (0 >= helper_majdevno)
	{
		helper_majdevno = cdevsw_add(HELPER_MAJOR, &helper_cdevsw);
		
		if (helper_majdevno < 0) {
			printf("helper_init: failed to allocate a major number!\n");
			return;
		}
		
		if (NULL == devfs_make_node( makedev(helper_majdevno, 0), DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0666, 
					DTRACEMNR_HELPER, 0 )) {
			printf("dtrace_init: failed to devfs_make_node for helper!\n");
			return;
		}
	} else
		panic("helper_init: called twice!\n");
}

#undef HELPER_MAJOR

static int
dtrace_clone_func(dev_t dev, int action)
{
#pragma unused(dev)

	if (action == DEVFS_CLONE_ALLOC) {
		return dtrace_state_reserve();
	}
	else if (action == DEVFS_CLONE_FREE) {
		return 0;
	}
	else return -1;
}

void dtrace_ast(void);

void
dtrace_ast(void)
{
	int i;
	uint32_t clients = atomic_and_32(&dtrace_wake_clients, 0);
	if (clients == 0)
		return;
	/**
	 * We disable preemption here to be sure that we won't get
	 * interrupted by a wakeup to a thread that is higher
	 * priority than us, so that we do issue all wakeups
	 */
	disable_preemption();
	for (i = 0; i < DTRACE_NCLIENTS; i++) {
		if (clients & (1 << i)) {
			dtrace_state_t *state = dtrace_state_get(i);
			if (state) {
				wakeup(state);
			}

		}
	}
	enable_preemption();
}


#define DTRACE_MAJOR  -24 /* let the kernel pick the device number */

static struct cdevsw dtrace_cdevsw =
{
	_dtrace_open,		/* open */
	_dtrace_close,		/* close */
	eno_rdwrt,			/* read */
	eno_rdwrt,			/* write */
	_dtrace_ioctl,		/* ioctl */
	(stop_fcn_t *)nulldev, /* stop */
	(reset_fcn_t *)nulldev, /* reset */
	NULL,				/* tty's */
	eno_select,			/* select */
	eno_mmap,			/* mmap */
	eno_strat,			/* strategy */
	eno_getc,			/* getc */
	eno_putc,			/* putc */
	0					/* type */
};

lck_attr_t* dtrace_lck_attr;
lck_grp_attr_t* dtrace_lck_grp_attr;
lck_grp_t* dtrace_lck_grp;

static int gMajDevNo;

void
dtrace_init( void )
{
	if (0 == gDTraceInited) {
		int i, ncpu;
		size_t size = sizeof(dtrace_buffer_memory_maxsize);

		/*
		 * DTrace allocates buffers based on the maximum number
		 * of enabled cpus. This call avoids any race when finding
		 * that count.
		 */
		ASSERT(dtrace_max_cpus == 0);
		ncpu = dtrace_max_cpus = ml_get_max_cpus();

		/*
		 * Retrieve the size of the physical memory in order to define
		 * the state buffer memory maximal size.  If we cannot retrieve
		 * this value, we'll consider that we have 1Gb of memory per CPU, that's
		 * still better than raising a kernel panic.
		 */
		if (0 != kernel_sysctlbyname("hw.memsize", &dtrace_buffer_memory_maxsize,
		                             &size, NULL, 0))
		{
			dtrace_buffer_memory_maxsize = ncpu * 1024 * 1024 * 1024;
			printf("dtrace_init: failed to retrieve the hw.memsize, defaulted to %lld bytes\n",
			       dtrace_buffer_memory_maxsize);
		}

		/*
		 * Finally, divide by three to prevent DTrace from eating too
		 * much memory.
		 */
		dtrace_buffer_memory_maxsize /= 3;
		ASSERT(dtrace_buffer_memory_maxsize > 0);

		gMajDevNo = cdevsw_add(DTRACE_MAJOR, &dtrace_cdevsw);

		if (gMajDevNo < 0) {
			printf("dtrace_init: failed to allocate a major number!\n");
			gDTraceInited = 0;
			return;
		}

		if (NULL == devfs_make_node_clone( makedev(gMajDevNo, 0), DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0666, 
					dtrace_clone_func, DTRACEMNR_DTRACE, 0 )) {
			printf("dtrace_init: failed to devfs_make_node_clone for dtrace!\n");
			gDTraceInited = 0;
			return;
		}

#if defined(DTRACE_MEMORY_ZONES)
		/*
		 * Initialize the dtrace kalloc-emulation zones.
		 */
		dtrace_alloc_init();
#endif /* DTRACE_MEMORY_ZONES */

		/*
		 * Allocate the dtrace_probe_t zone
		 */
		dtrace_probe_t_zone = zinit(sizeof(dtrace_probe_t),
					    1024 * sizeof(dtrace_probe_t),
					    sizeof(dtrace_probe_t),
					    "dtrace.dtrace_probe_t");

		/*
		 * Create the dtrace lock group and attrs.
		 */
		dtrace_lck_attr = lck_attr_alloc_init();
		dtrace_lck_grp_attr= lck_grp_attr_alloc_init();		
		dtrace_lck_grp = lck_grp_alloc_init("dtrace",  dtrace_lck_grp_attr);

		/*
		 * We have to initialize all locks explicitly
		 */
		lck_mtx_init(&dtrace_lock, dtrace_lck_grp, dtrace_lck_attr);
		lck_mtx_init(&dtrace_provider_lock, dtrace_lck_grp, dtrace_lck_attr);
		lck_mtx_init(&dtrace_meta_lock, dtrace_lck_grp, dtrace_lck_attr);
		lck_mtx_init(&dtrace_procwaitfor_lock, dtrace_lck_grp, dtrace_lck_attr);
#if DEBUG
		lck_mtx_init(&dtrace_errlock, dtrace_lck_grp, dtrace_lck_attr);
#endif
		lck_rw_init(&dtrace_dof_mode_lock, dtrace_lck_grp, dtrace_lck_attr);

		/*
		 * The cpu_core structure consists of per-CPU state available in any context.
		 * On some architectures, this may mean that the page(s) containing the
		 * NCPU-sized array of cpu_core structures must be locked in the TLB -- it
		 * is up to the platform to assure that this is performed properly.  Note that
		 * the structure is sized to avoid false sharing.
		 */
		lck_mtx_init(&cpu_lock, dtrace_lck_grp, dtrace_lck_attr);
		lck_mtx_init(&cyc_lock, dtrace_lck_grp, dtrace_lck_attr);
		lck_mtx_init(&mod_lock, dtrace_lck_grp, dtrace_lck_attr);

		/*
		 * Initialize the CPU offline/online hooks.
		 */
		dtrace_install_cpu_hooks();

		dtrace_modctl_list = NULL;

		cpu_core = (cpu_core_t *)kmem_zalloc( ncpu * sizeof(cpu_core_t), KM_SLEEP );
		for (i = 0; i < ncpu; ++i) {
			lck_mtx_init(&cpu_core[i].cpuc_pid_lock, dtrace_lck_grp, dtrace_lck_attr);
		}

		cpu_list = (dtrace_cpu_t *)kmem_zalloc( ncpu * sizeof(dtrace_cpu_t), KM_SLEEP );
		for (i = 0; i < ncpu; ++i) {
			cpu_list[i].cpu_id = (processorid_t)i;
			cpu_list[i].cpu_next = &(cpu_list[(i+1) % ncpu]);
			LIST_INIT(&cpu_list[i].cpu_cyc_list);
			lck_rw_init(&cpu_list[i].cpu_ft_lock, dtrace_lck_grp, dtrace_lck_attr);
		}

		lck_mtx_lock(&cpu_lock);
		for (i = 0; i < ncpu; ++i) 
			/* FIXME: track CPU configuration */
			dtrace_cpu_setup_initial( (processorid_t)i ); /* In lieu of register_cpu_setup_func() callback */
		lck_mtx_unlock(&cpu_lock);

		(void)dtrace_abs_to_nano(0LL); /* Force once only call to clock_timebase_info (which can take a lock) */

		dtrace_isa_init();
		/*
		 * See dtrace_impl.h for a description of dof modes.
		 * The default is lazy dof.
		 *
		 * FIXME: Warn if state is LAZY_OFF? It won't break anything, but
		 * makes no sense...
		 */
		if (!PE_parse_boot_argn("dtrace_dof_mode", &dtrace_dof_mode, sizeof (dtrace_dof_mode))) {
			dtrace_dof_mode = DTRACE_DOF_MODE_LAZY_ON;
		}

		/*
		 * Sanity check of dof mode value.
		 */
		switch (dtrace_dof_mode) {
			case DTRACE_DOF_MODE_NEVER:
			case DTRACE_DOF_MODE_LAZY_ON:
				/* valid modes, but nothing else we need to do */
				break;

			case DTRACE_DOF_MODE_LAZY_OFF:
			case DTRACE_DOF_MODE_NON_LAZY:
				/* Cannot wait for a dtrace_open to init fasttrap */
				fasttrap_init();
				break;

			default:
				/* Invalid, clamp to non lazy */
				dtrace_dof_mode = DTRACE_DOF_MODE_NON_LAZY;
				fasttrap_init();
				break;
		}

		/*
		 * See dtrace_impl.h for a description of kernel symbol modes.
		 * The default is to wait for symbols from userspace (lazy symbols).
		 */
		if (!PE_parse_boot_argn("dtrace_kernel_symbol_mode", &dtrace_kernel_symbol_mode, sizeof (dtrace_kernel_symbol_mode))) {
			dtrace_kernel_symbol_mode = DTRACE_KERNEL_SYMBOLS_FROM_USERSPACE;
		}

		dtrace_restriction_policy_load();

		gDTraceInited = 1;

	} else
		panic("dtrace_init: called twice!\n");
}

void
dtrace_postinit(void)
{
	/*
	 * Called from bsd_init after all provider's *_init() routines have been
	 * run. That way, anonymous DOF enabled under dtrace_attach() is safe
	 * to go.
	 */
	dtrace_attach( (dev_info_t *)(uintptr_t)makedev(gMajDevNo, 0), 0 ); /* Punning a dev_t to a dev_info_t* */
	
	/*
	 * Add the mach_kernel to the module list for lazy processing
	 */
	struct kmod_info fake_kernel_kmod;
	memset(&fake_kernel_kmod, 0, sizeof(fake_kernel_kmod));
	
	strlcpy(fake_kernel_kmod.name, "mach_kernel", sizeof(fake_kernel_kmod.name));
	fake_kernel_kmod.id = 1;
	fake_kernel_kmod.address = g_kernel_kmod_info.address;
	fake_kernel_kmod.size = g_kernel_kmod_info.size;

	if (dtrace_module_loaded(&fake_kernel_kmod, 0) != 0) {
		printf("dtrace_postinit: Could not register mach_kernel modctl\n");
	}
	
	(void)OSKextRegisterKextsWithDTrace();
}
#undef DTRACE_MAJOR

/*
 * Routines used to register interest in cpu's being added to or removed
 * from the system.
 */
void
register_cpu_setup_func(cpu_setup_func_t *ignore1, void *ignore2)
{
#pragma unused(ignore1,ignore2)
}

void
unregister_cpu_setup_func(cpu_setup_func_t *ignore1, void *ignore2)
{
#pragma unused(ignore1,ignore2)
}
