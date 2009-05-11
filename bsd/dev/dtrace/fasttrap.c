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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * #pragma ident	"@(#)fasttrap.c	1.21	06/06/12 SMI"
 */

#include <sys/types.h>
#include <sys/time.h>

#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/kauth.h>

#include <sys/fasttrap.h>
#include <sys/fasttrap_impl.h>
#include <sys/fasttrap_isa.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <sys/proc.h>

#include <miscfs/devfs/devfs.h>
#include <sys/proc_internal.h>
#include <sys/dtrace_glue.h>
#include <sys/dtrace_ptss.h>

#include <kern/zalloc.h>

#define proc_t struct proc

/*
 * User-Land Trap-Based Tracing
 * ----------------------------
 *
 * The fasttrap provider allows DTrace consumers to instrument any user-level
 * instruction to gather data; this includes probes with semantic
 * signifigance like entry and return as well as simple offsets into the
 * function. While the specific techniques used are very ISA specific, the
 * methodology is generalizable to any architecture.
 *
 *
 * The General Methodology
 * -----------------------
 *
 * With the primary goal of tracing every user-land instruction and the
 * limitation that we can't trust user space so don't want to rely on much
 * information there, we begin by replacing the instructions we want to trace
 * with trap instructions. Each instruction we overwrite is saved into a hash
 * table keyed by process ID and pc address. When we enter the kernel due to
 * this trap instruction, we need the effects of the replaced instruction to
 * appear to have occurred before we proceed with the user thread's
 * execution.
 *
 * Each user level thread is represented by a ulwp_t structure which is
 * always easily accessible through a register. The most basic way to produce
 * the effects of the instruction we replaced is to copy that instruction out
 * to a bit of scratch space reserved in the user thread's ulwp_t structure
 * (a sort of kernel-private thread local storage), set the PC to that
 * scratch space and single step. When we reenter the kernel after single
 * stepping the instruction we must then adjust the PC to point to what would
 * normally be the next instruction. Of course, special care must be taken
 * for branches and jumps, but these represent such a small fraction of any
 * instruction set that writing the code to emulate these in the kernel is
 * not too difficult.
 *
 * Return probes may require several tracepoints to trace every return site,
 * and, conversely, each tracepoint may activate several probes (the entry
 * and offset 0 probes, for example). To solve this muliplexing problem,
 * tracepoints contain lists of probes to activate and probes contain lists
 * of tracepoints to enable. If a probe is activated, it adds its ID to
 * existing tracepoints or creates new ones as necessary.
 *
 * Most probes are activated _before_ the instruction is executed, but return
 * probes are activated _after_ the effects of the last instruction of the
 * function are visible. Return probes must be fired _after_ we have
 * single-stepped the instruction whereas all other probes are fired
 * beforehand.
 *
 *
 * Lock Ordering
 * -------------
 *
 * The lock ordering below -- both internally and with respect to the DTrace
 * framework -- is a little tricky and bears some explanation. Each provider
 * has a lock (ftp_mtx) that protects its members including reference counts
 * for enabled probes (ftp_rcount), consumers actively creating probes
 * (ftp_ccount) and USDT consumers (ftp_mcount); all three prevent a provider
 * from being freed. A provider is looked up by taking the bucket lock for the
 * provider hash table, and is returned with its lock held. The provider lock
 * may be taken in functions invoked by the DTrace framework, but may not be
 * held while calling functions in the DTrace framework.
 *
 * To ensure consistency over multiple calls to the DTrace framework, the
 * creation lock (ftp_cmtx) should be held. Naturally, the creation lock may
 * not be taken when holding the provider lock as that would create a cyclic
 * lock ordering. In situations where one would naturally take the provider
 * lock and then the creation lock, we instead up a reference count to prevent
 * the provider from disappearing, drop the provider lock, and acquire the
 * creation lock.
 *
 * Briefly:
 * 	bucket lock before provider lock
 *	DTrace before provider lock
 *	creation lock before DTrace
 *	never hold the provider lock and creation lock simultaneously
 */

static dev_info_t *fasttrap_devi;
static dtrace_meta_provider_id_t fasttrap_meta_id;

static thread_call_t fasttrap_timeout;
static lck_mtx_t fasttrap_cleanup_mtx;
static uint_t fasttrap_cleanup_work;

/*
 * Generation count on modifications to the global tracepoint lookup table.
 */
static volatile uint64_t fasttrap_mod_gen;

#if !defined(__APPLE__)
/*
 * When the fasttrap provider is loaded, fasttrap_max is set to either
 * FASTTRAP_MAX_DEFAULT or the value for fasttrap-max-probes in the
 * fasttrap.conf file. Each time a probe is created, fasttrap_total is
 * incremented by the number of tracepoints that may be associated with that
 * probe; fasttrap_total is capped at fasttrap_max.
 */
#define	FASTTRAP_MAX_DEFAULT		2500000
#endif

static uint32_t fasttrap_max;
static uint32_t fasttrap_total;


#define	FASTTRAP_TPOINTS_DEFAULT_SIZE	0x4000
#define	FASTTRAP_PROVIDERS_DEFAULT_SIZE	0x100
#define	FASTTRAP_PROCS_DEFAULT_SIZE	0x100

fasttrap_hash_t			fasttrap_tpoints;
static fasttrap_hash_t		fasttrap_provs;
static fasttrap_hash_t		fasttrap_procs;

static uint64_t			fasttrap_pid_count;	/* pid ref count */
static lck_mtx_t       		fasttrap_count_mtx;	/* lock on ref count */

#define	FASTTRAP_ENABLE_FAIL	1
#define	FASTTRAP_ENABLE_PARTIAL	2

static int fasttrap_tracepoint_enable(proc_t *, fasttrap_probe_t *, uint_t);
static void fasttrap_tracepoint_disable(proc_t *, fasttrap_probe_t *, uint_t);

#if defined(__APPLE__)
static fasttrap_provider_t *fasttrap_provider_lookup(pid_t, fasttrap_provider_type_t, const char *,
    const dtrace_pattr_t *);
#endif
static void fasttrap_provider_retire(pid_t, const char *, int);
static void fasttrap_provider_free(fasttrap_provider_t *);

static fasttrap_proc_t *fasttrap_proc_lookup(pid_t);
static void fasttrap_proc_release(fasttrap_proc_t *);

#define	FASTTRAP_PROVS_INDEX(pid, name) \
	((fasttrap_hash_str(name) + (pid)) & fasttrap_provs.fth_mask)

#define	FASTTRAP_PROCS_INDEX(pid) ((pid) & fasttrap_procs.fth_mask)

#if defined(__APPLE__)

/*
 * To save memory, some common memory allocations are given a
 * unique zone. In example, dtrace_probe_t is 72 bytes in size,
 * which means it would fall into the kalloc.128 bucket. With
 * 20k elements allocated, the space saved is substantial.
 */

struct zone *fasttrap_tracepoint_t_zone;

/*
 * fasttrap_probe_t's are variable in size. Some quick profiling has shown
 * that the sweet spot for reducing memory footprint is covering the first
 * three sizes. Everything larger goes into the common pool.
 */
#define FASTTRAP_PROBE_T_ZONE_MAX_TRACEPOINTS 4

struct zone *fasttrap_probe_t_zones[FASTTRAP_PROBE_T_ZONE_MAX_TRACEPOINTS];

static const char *fasttrap_probe_t_zone_names[FASTTRAP_PROBE_T_ZONE_MAX_TRACEPOINTS] = {
	"",
	"dtrace.fasttrap_probe_t[1]",
	"dtrace.fasttrap_probe_t[2]",
	"dtrace.fasttrap_probe_t[3]"
};

/*
 * We have to manage locks explicitly
 */
lck_grp_t*			fasttrap_lck_grp;
lck_grp_attr_t*			fasttrap_lck_grp_attr;
lck_attr_t*			fasttrap_lck_attr;
#endif

static int
fasttrap_highbit(ulong_t i)
{
	int h = 1;

	if (i == 0)
		return (0);
#ifdef _LP64
	if (i & 0xffffffff00000000ul) {
		h += 32; i >>= 32;
	}
#endif
	if (i & 0xffff0000) {
		h += 16; i >>= 16;
	}
	if (i & 0xff00) {
		h += 8; i >>= 8;
	}
	if (i & 0xf0) {
		h += 4; i >>= 4;
	}
	if (i & 0xc) {
		h += 2; i >>= 2;
	}
	if (i & 0x2) {
		h += 1;
	}
	return (h);
}

static uint_t
fasttrap_hash_str(const char *p)
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

/*
 * FIXME - needs implementation
 */
void
fasttrap_sigtrap(proc_t *p, uthread_t t, user_addr_t pc)
{
#pragma unused(p, t, pc)

#if 0
	sigqueue_t *sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);

	sqp->sq_info.si_signo = SIGTRAP;
	sqp->sq_info.si_code = TRAP_DTRACE;
	sqp->sq_info.si_addr = (caddr_t)pc;

	mutex_enter(&p->p_lock);
	sigaddqa(p, t, sqp);
	mutex_exit(&p->p_lock);

	if (t != NULL)
		aston(t);
#endif

	printf("fasttrap_sigtrap called with no implementation.\n");
}

/*
 * This function ensures that no threads are actively using the memory
 * associated with probes that were formerly live.
 */
static void
fasttrap_mod_barrier(uint64_t gen)
{
	unsigned int i;

	if (gen < fasttrap_mod_gen)
		return;

	fasttrap_mod_gen++;

	for (i = 0; i < NCPU; i++) {
		lck_mtx_lock(&cpu_core[i].cpuc_pid_lock);
		lck_mtx_unlock(&cpu_core[i].cpuc_pid_lock);
	}
}

/*
 * This is the timeout's callback for cleaning up the providers and their
 * probes.
 */
/*ARGSUSED*/
static void
fasttrap_pid_cleanup_cb(void *ignored, void* ignored2)
{
#pragma unused(ignored, ignored2)
	fasttrap_provider_t **fpp, *fp;
	fasttrap_bucket_t *bucket;
	dtrace_provider_id_t provid;
	unsigned int i, later = 0;

	static volatile int in = 0;
	ASSERT(in == 0);
	in = 1;

	lck_mtx_lock(&fasttrap_cleanup_mtx);
	while (fasttrap_cleanup_work) {
		fasttrap_cleanup_work = 0;
		lck_mtx_unlock(&fasttrap_cleanup_mtx);

		later = 0;

		/*
		 * Iterate over all the providers trying to remove the marked
		 * ones. If a provider is marked but not retired, we just
		 * have to take a crack at removing it -- it's no big deal if
		 * we can't.
		 */
		for (i = 0; i < fasttrap_provs.fth_nent; i++) {
			bucket = &fasttrap_provs.fth_table[i];
			lck_mtx_lock(&bucket->ftb_mtx);
			fpp = (fasttrap_provider_t **)&bucket->ftb_data;

			while ((fp = *fpp) != NULL) {
				if (!fp->ftp_marked) {
					fpp = &fp->ftp_next;
					continue;
				}

				lck_mtx_lock(&fp->ftp_mtx);

				/*
				 * If this provider has consumers actively
				 * creating probes (ftp_ccount) or is a USDT
				 * provider (ftp_mcount), we can't unregister
				 * or even condense.
				 */
				if (fp->ftp_ccount != 0 ||
				    fp->ftp_mcount != 0) {
					fp->ftp_marked = 0;
					lck_mtx_unlock(&fp->ftp_mtx);
					continue;
				}

				if (!fp->ftp_retired || fp->ftp_rcount != 0)
					fp->ftp_marked = 0;

				lck_mtx_unlock(&fp->ftp_mtx);

				/*
				 * If we successfully unregister this
				 * provider we can remove it from the hash
				 * chain and free the memory. If our attempt
				 * to unregister fails and this is a retired
				 * provider, increment our flag to try again
				 * pretty soon. If we've consumed more than
				 * half of our total permitted number of
				 * probes call dtrace_condense() to try to
				 * clean out the unenabled probes.
				 */
				provid = fp->ftp_provid;
				if (dtrace_unregister(provid) != 0) {
					if (fasttrap_total > fasttrap_max / 2)
						(void) dtrace_condense(provid);
					later += fp->ftp_marked;
					fpp = &fp->ftp_next;
				} else {
					*fpp = fp->ftp_next;
					fasttrap_provider_free(fp);
				}
			}
			lck_mtx_unlock(&bucket->ftb_mtx);
		}

		lck_mtx_lock(&fasttrap_cleanup_mtx);
	}

	ASSERT(fasttrap_timeout != 0);

	/*
	 * APPLE NOTE: You must hold the fasttrap_cleanup_mtx to do this!
	 */
	if (fasttrap_timeout != (thread_call_t)1)
		thread_call_free(fasttrap_timeout);

	/*
	 * If we were unable to remove a retired provider, try again after
	 * a second. This situation can occur in certain circumstances where
	 * providers cannot be unregistered even though they have no probes
	 * enabled because of an execution of dtrace -l or something similar.
	 * If the timeout has been disabled (set to 1 because we're trying
	 * to detach), we set fasttrap_cleanup_work to ensure that we'll
	 * get a chance to do that work if and when the timeout is reenabled
	 * (if detach fails).
	 */
	if (later > 0 && fasttrap_timeout != (thread_call_t)1)
		/* The time value passed to dtrace_timeout is in nanos */
		fasttrap_timeout = dtrace_timeout(&fasttrap_pid_cleanup_cb, NULL, NANOSEC / SEC);
	else if (later > 0)
		fasttrap_cleanup_work = 1;
	else
		fasttrap_timeout = 0;

	lck_mtx_unlock(&fasttrap_cleanup_mtx);
	in = 0;
}

/*
 * Activates the asynchronous cleanup mechanism.
 */
static void
fasttrap_pid_cleanup(void)
{
	lck_mtx_lock(&fasttrap_cleanup_mtx);
	fasttrap_cleanup_work = 1;
	if (fasttrap_timeout == 0)
		fasttrap_timeout = dtrace_timeout(&fasttrap_pid_cleanup_cb, NULL, NANOSEC / MILLISEC);
	lck_mtx_unlock(&fasttrap_cleanup_mtx);
}

/*
 * This is called from cfork() via dtrace_fasttrap_fork(). The child
 * process's address space is a (roughly) a copy of the parent process's so
 * we have to remove all the instrumentation we had previously enabled in the
 * parent.
 */
static void
fasttrap_fork(proc_t *p, proc_t *cp)
{
	pid_t ppid = p->p_pid;
	unsigned int i;

	ASSERT(current_proc() == p);
	lck_mtx_assert(&p->p_dtrace_sprlock, LCK_MTX_ASSERT_OWNED);
	ASSERT(p->p_dtrace_count > 0);
	ASSERT(cp->p_dtrace_count == 0);

	/*
	 * This would be simpler and faster if we maintained per-process
	 * hash tables of enabled tracepoints. It could, however, potentially
	 * slow down execution of a tracepoint since we'd need to go
	 * through two levels of indirection. In the future, we should
	 * consider either maintaining per-process ancillary lists of
	 * enabled tracepoints or hanging a pointer to a per-process hash
	 * table of enabled tracepoints off the proc structure.
	 */

	/*
	 * We don't have to worry about the child process disappearing
	 * because we're in fork().
	 */
	if (cp != sprlock(cp->p_pid)) {
		printf("fasttrap_fork: sprlock(%d) returned a differt proc\n", cp->p_pid);
		return;
	}
	proc_unlock(cp);

	/*
	 * Iterate over every tracepoint looking for ones that belong to the
	 * parent process, and remove each from the child process.
	 */
	for (i = 0; i < fasttrap_tpoints.fth_nent; i++) {
		fasttrap_tracepoint_t *tp;
		fasttrap_bucket_t *bucket = &fasttrap_tpoints.fth_table[i];

		lck_mtx_lock(&bucket->ftb_mtx);
		for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
			if (tp->ftt_pid == ppid &&
			    !tp->ftt_proc->ftpc_defunct) {
				fasttrap_tracepoint_remove(cp, tp);
			}
		}
		lck_mtx_unlock(&bucket->ftb_mtx);
	}

	/*
	 * Free any ptss pages/entries in the child.
	 */
	dtrace_ptss_fork(p, cp);

	proc_lock(cp);
	sprunlock(cp);
}

/*
 * This is called from proc_exit() or from exec_common() if p_dtrace_probes
 * is set on the proc structure to indicate that there is a pid provider
 * associated with this process.
 */
static void
fasttrap_exec_exit(proc_t *p)
{
	ASSERT(p == current_proc());
	lck_mtx_assert(&p->p_mlock, LCK_MTX_ASSERT_OWNED);
	lck_mtx_assert(&p->p_dtrace_sprlock, LCK_MTX_ASSERT_NOTOWNED);


	/* APPLE NOTE: Okay, the locking here is really odd and needs some
	 * explaining. This method is always called with the proc_lock held.
	 * We must drop the proc_lock before calling fasttrap_provider_retire
	 * to avoid a deadlock when it takes the bucket lock.
	 * 
	 * Next, the dtrace_ptss_exec_exit function requires the sprlock
	 * be held, but not the proc_lock. 
	 *
	 * Finally, we must re-acquire the proc_lock
	 */
	proc_unlock(p);

	/*
	 * We clean up the pid provider for this process here; user-land
	 * static probes are handled by the meta-provider remove entry point.
	 */
	fasttrap_provider_retire(p->p_pid, FASTTRAP_PID_NAME, 0);
#if defined(__APPLE__)
	/*
	 * We also need to remove any aliased providers.
	 * XXX optimization: track which provider types are instantiated
	 * and only retire as needed.
	 */
	fasttrap_provider_retire(p->p_pid, FASTTRAP_OBJC_NAME, 0);
	fasttrap_provider_retire(p->p_pid, FASTTRAP_ONESHOT_NAME, 0);
#endif /* __APPLE__ */

	/*
	 * This should be called after it is no longer possible for a user
	 * thread to execute (potentially dtrace instrumented) instructions.
	 */
	lck_mtx_lock(&p->p_dtrace_sprlock);
	dtrace_ptss_exec_exit(p);
	lck_mtx_unlock(&p->p_dtrace_sprlock);

	proc_lock(p);
}


/*ARGSUSED*/
static void
fasttrap_pid_provide(void *arg, const dtrace_probedesc_t *desc)
{
#pragma unused(arg, desc)
	/*
	 * There are no "default" pid probes.
	 */
}

static int
fasttrap_tracepoint_enable(proc_t *p, fasttrap_probe_t *probe, uint_t index)
{
	fasttrap_tracepoint_t *tp, *new_tp = NULL;
	fasttrap_bucket_t *bucket;
	fasttrap_id_t *id;
	pid_t pid;
	user_addr_t pc;

	ASSERT(index < probe->ftp_ntps);

	pid = probe->ftp_pid;
	pc = probe->ftp_tps[index].fit_tp->ftt_pc;
	id = &probe->ftp_tps[index].fit_id;

	ASSERT(probe->ftp_tps[index].fit_tp->ftt_pid == pid);

	//ASSERT(!(p->p_flag & SVFORK));

	/*
	 * Before we make any modifications, make sure we've imposed a barrier
	 * on the generation in which this probe was last modified.
	 */
	fasttrap_mod_barrier(probe->ftp_gen);

	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];

	/*
	 * If the tracepoint has already been enabled, just add our id to the
	 * list of interested probes. This may be our second time through
	 * this path in which case we'll have constructed the tracepoint we'd
	 * like to install. If we can't find a match, and have an allocated
	 * tracepoint ready to go, enable that one now.
	 *
	 * A tracepoint whose process is defunct is also considered defunct.
	 */
again:
	lck_mtx_lock(&bucket->ftb_mtx);
	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (tp->ftt_pid != pid || tp->ftt_pc != pc ||
		    tp->ftt_proc->ftpc_defunct)
			continue;

		/*
		 * Now that we've found a matching tracepoint, it would be
		 * a decent idea to confirm that the tracepoint is still
		 * enabled and the trap instruction hasn't been overwritten.
		 * Since this is a little hairy, we'll punt for now.
		 */

		/*
		 * This can't be the first interested probe. We don't have
		 * to worry about another thread being in the midst of
		 * deleting this tracepoint (which would be the only valid
		 * reason for a tracepoint to have no interested probes)
		 * since we're holding P_PR_LOCK for this process.
		 */
		ASSERT(tp->ftt_ids != NULL || tp->ftt_retids != NULL);

		switch (id->fti_ptype) {
		case DTFTP_ENTRY:
		case DTFTP_OFFSETS:
		case DTFTP_IS_ENABLED:
			id->fti_next = tp->ftt_ids;
			dtrace_membar_producer();
			tp->ftt_ids = id;
			dtrace_membar_producer();
			break;

		case DTFTP_RETURN:
		case DTFTP_POST_OFFSETS:
			id->fti_next = tp->ftt_retids;
			dtrace_membar_producer();
			tp->ftt_retids = id;
			dtrace_membar_producer();
			break;

		default:
			ASSERT(0);
		}

		lck_mtx_unlock(&bucket->ftb_mtx);

		if (new_tp != NULL) {
			new_tp->ftt_ids = NULL;
			new_tp->ftt_retids = NULL;
		}

		return (0);
	}

	/*
	 * If we have a good tracepoint ready to go, install it now while
	 * we have the lock held and no one can screw with us.
	 */
	if (new_tp != NULL) {
		int rc = 0;

		new_tp->ftt_next = bucket->ftb_data;
		dtrace_membar_producer();
		bucket->ftb_data = new_tp;
		dtrace_membar_producer();
		lck_mtx_unlock(&bucket->ftb_mtx);

		/*
		 * Activate the tracepoint in the ISA-specific manner.
		 * If this fails, we need to report the failure, but
		 * indicate that this tracepoint must still be disabled
		 * by calling fasttrap_tracepoint_disable().
		 */
		if (fasttrap_tracepoint_install(p, new_tp) != 0)
			rc = FASTTRAP_ENABLE_PARTIAL;

		/*
		 * Increment the count of the number of tracepoints active in
		 * the victim process.
		 */
		//ASSERT(p->p_proc_flag & P_PR_LOCK);
		p->p_dtrace_count++;

		return (rc);
	}

	lck_mtx_unlock(&bucket->ftb_mtx);

	/*
	 * Initialize the tracepoint that's been preallocated with the probe.
	 */
	new_tp = probe->ftp_tps[index].fit_tp;

	ASSERT(new_tp->ftt_pid == pid);
	ASSERT(new_tp->ftt_pc == pc);
	ASSERT(new_tp->ftt_proc == probe->ftp_prov->ftp_proc);
	ASSERT(new_tp->ftt_ids == NULL);
	ASSERT(new_tp->ftt_retids == NULL);

	switch (id->fti_ptype) {
	case DTFTP_ENTRY:
	case DTFTP_OFFSETS:
	case DTFTP_IS_ENABLED:
		id->fti_next = NULL;
		new_tp->ftt_ids = id;
		break;

	case DTFTP_RETURN:
	case DTFTP_POST_OFFSETS:
		id->fti_next = NULL;
		new_tp->ftt_retids = id;
		break;

	default:
		ASSERT(0);
	}

	/*
	 * If the ISA-dependent initialization goes to plan, go back to the
	 * beginning and try to install this freshly made tracepoint.
	 */
	if (fasttrap_tracepoint_init(p, new_tp, pc, id->fti_ptype) == 0)
		goto again;

	new_tp->ftt_ids = NULL;
	new_tp->ftt_retids = NULL;

	return (FASTTRAP_ENABLE_FAIL);
}

static void
fasttrap_tracepoint_disable(proc_t *p, fasttrap_probe_t *probe, uint_t index)
{
	fasttrap_bucket_t *bucket;
	fasttrap_provider_t *provider = probe->ftp_prov;
	fasttrap_tracepoint_t **pp, *tp;
	fasttrap_id_t *id, **idp;
	pid_t pid;
	user_addr_t pc;

	ASSERT(index < probe->ftp_ntps);

	pid = probe->ftp_pid;
	pc = probe->ftp_tps[index].fit_tp->ftt_pc;
	id = &probe->ftp_tps[index].fit_id;

	ASSERT(probe->ftp_tps[index].fit_tp->ftt_pid == pid);

	/*
	 * Find the tracepoint and make sure that our id is one of the
	 * ones registered with it.
	 */
	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];
	lck_mtx_lock(&bucket->ftb_mtx);
	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (tp->ftt_pid == pid && tp->ftt_pc == pc &&
		    tp->ftt_proc == provider->ftp_proc)
			break;
	}

	/*
	 * If we somehow lost this tracepoint, we're in a world of hurt.
	 */
	ASSERT(tp != NULL);

	switch (id->fti_ptype) {
		case DTFTP_ENTRY:
		case DTFTP_OFFSETS:
		case DTFTP_IS_ENABLED:
			ASSERT(tp->ftt_ids != NULL);
			idp = &tp->ftt_ids;
			break;
			
		case DTFTP_RETURN:
		case DTFTP_POST_OFFSETS:
			ASSERT(tp->ftt_retids != NULL);
			idp = &tp->ftt_retids;
			break;
			
		default:
			/* Fix compiler warning... */
			idp = NULL;
			ASSERT(0);
	}

	while ((*idp)->fti_probe != probe) {
		idp = &(*idp)->fti_next;
		ASSERT(*idp != NULL);
	}

	id = *idp;
	*idp = id->fti_next;
	dtrace_membar_producer();

	ASSERT(id->fti_probe == probe);

	/*
	 * If there are other registered enablings of this tracepoint, we're
	 * all done, but if this was the last probe assocated with this
	 * this tracepoint, we need to remove and free it.
	 */
	if (tp->ftt_ids != NULL || tp->ftt_retids != NULL) {

		/*
		 * If the current probe's tracepoint is in use, swap it
		 * for an unused tracepoint.
		 */
		if (tp == probe->ftp_tps[index].fit_tp) {
			fasttrap_probe_t *tmp_probe;
			fasttrap_tracepoint_t **tmp_tp;
			uint_t tmp_index;

			if (tp->ftt_ids != NULL) {
				tmp_probe = tp->ftt_ids->fti_probe;
				tmp_index = FASTTRAP_ID_INDEX(tp->ftt_ids);
				tmp_tp = &tmp_probe->ftp_tps[tmp_index].fit_tp;
			} else {
				tmp_probe = tp->ftt_retids->fti_probe;
				tmp_index = FASTTRAP_ID_INDEX(tp->ftt_retids);
				tmp_tp = &tmp_probe->ftp_tps[tmp_index].fit_tp;
			}

			ASSERT(*tmp_tp != NULL);
			ASSERT(*tmp_tp != probe->ftp_tps[index].fit_tp);
			ASSERT((*tmp_tp)->ftt_ids == NULL);
			ASSERT((*tmp_tp)->ftt_retids == NULL);

			probe->ftp_tps[index].fit_tp = *tmp_tp;
			*tmp_tp = tp;

		}

		lck_mtx_unlock(&bucket->ftb_mtx);

		/*
		 * Tag the modified probe with the generation in which it was
		 * changed.
		 */
		probe->ftp_gen = fasttrap_mod_gen;
		return;
	}

	lck_mtx_unlock(&bucket->ftb_mtx);

	/*
	 * We can't safely remove the tracepoint from the set of active
	 * tracepoints until we've actually removed the fasttrap instruction
	 * from the process's text. We can, however, operate on this
	 * tracepoint secure in the knowledge that no other thread is going to
	 * be looking at it since we hold P_PR_LOCK on the process if it's
	 * live or we hold the provider lock on the process if it's dead and
	 * gone.
	 */

	/*
	 * We only need to remove the actual instruction if we're looking
	 * at an existing process
	 */
	if (p != NULL) {
		/*
		 * If we fail to restore the instruction we need to kill
		 * this process since it's in a completely unrecoverable
		 * state.
		 */
		if (fasttrap_tracepoint_remove(p, tp) != 0)
			fasttrap_sigtrap(p, NULL, pc);

		/*
		 * Decrement the count of the number of tracepoints active
		 * in the victim process.
		 */
		//ASSERT(p->p_proc_flag & P_PR_LOCK);
		p->p_dtrace_count--;
	}

	/*
	 * Remove the probe from the hash table of active tracepoints.
	 */
	lck_mtx_lock(&bucket->ftb_mtx);
	pp = (fasttrap_tracepoint_t **)&bucket->ftb_data;
	ASSERT(*pp != NULL);
	while (*pp != tp) {
		pp = &(*pp)->ftt_next;
		ASSERT(*pp != NULL);
	}

	*pp = tp->ftt_next;
	dtrace_membar_producer();

	lck_mtx_unlock(&bucket->ftb_mtx);

	/*
	 * Tag the modified probe with the generation in which it was changed.
	 */
	probe->ftp_gen = fasttrap_mod_gen;
}

static void
fasttrap_enable_callbacks(void)
{
	/*
	 * We don't have to play the rw lock game here because we're
	 * providing something rather than taking something away --
	 * we can be sure that no threads have tried to follow this
	 * function pointer yet.
	 */
	lck_mtx_lock(&fasttrap_count_mtx);
	if (fasttrap_pid_count == 0) {
		ASSERT(dtrace_pid_probe_ptr == NULL);
		ASSERT(dtrace_return_probe_ptr == NULL);
		dtrace_pid_probe_ptr = &fasttrap_pid_probe;
		dtrace_return_probe_ptr = &fasttrap_return_probe;
	}
	ASSERT(dtrace_pid_probe_ptr == &fasttrap_pid_probe);
	ASSERT(dtrace_return_probe_ptr == &fasttrap_return_probe);
	fasttrap_pid_count++;
	lck_mtx_unlock(&fasttrap_count_mtx);
}

static void
fasttrap_disable_callbacks(void)
{
	//ASSERT(MUTEX_HELD(&cpu_lock));

	lck_mtx_lock(&fasttrap_count_mtx);
	ASSERT(fasttrap_pid_count > 0);
	fasttrap_pid_count--;
	if (fasttrap_pid_count == 0) {
		cpu_t *cur, *cpu = CPU;

		/*
		 * APPLE NOTE: This loop seems broken, it touches every CPU
		 * but the one we're actually running on. Need to ask Sun folks
		 * if that is safe. Scenario is this: We're running on CPU A,
		 * and lock all but A. Then we get preempted, and start running
		 * on CPU B. A probe fires on A, and is allowed to enter. BOOM!
		 */
		for (cur = cpu->cpu_next; cur != cpu; cur = cur->cpu_next) {
			lck_rw_lock_exclusive(&cur->cpu_ft_lock);
			// rw_enter(&cur->cpu_ft_lock, RW_WRITER);
		}

		dtrace_pid_probe_ptr = NULL;
		dtrace_return_probe_ptr = NULL;

		for (cur = cpu->cpu_next; cur != cpu; cur = cur->cpu_next) {
			lck_rw_unlock_exclusive(&cur->cpu_ft_lock);
			// rw_exit(&cur->cpu_ft_lock);
		}
	}
	lck_mtx_unlock(&fasttrap_count_mtx);
}

/*ARGSUSED*/
static void
fasttrap_pid_enable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg, id)
	fasttrap_probe_t *probe = parg;
	proc_t *p;
	int i, rc;

	ASSERT(probe != NULL);
	ASSERT(!probe->ftp_enabled);
	ASSERT(id == probe->ftp_id);
	// ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Increment the count of enabled probes on this probe's provider;
	 * the provider can't go away while the probe still exists. We
	 * must increment this even if we aren't able to properly enable
	 * this probe.
	 */
	lck_mtx_lock(&probe->ftp_prov->ftp_mtx);
	probe->ftp_prov->ftp_rcount++;
	lck_mtx_unlock(&probe->ftp_prov->ftp_mtx);

	/*
	 * If this probe's provider is retired (meaning it was valid in a
	 * previously exec'ed incarnation of this address space), bail out. The
	 * provider can't go away while we're in this code path.
	 */
	if (probe->ftp_prov->ftp_retired)
		return;

	/*
	 * If we can't find the process, it may be that we're in the context of
	 * a fork in which the traced process is being born and we're copying
	 * USDT probes. Otherwise, the process is gone so bail.
	 */
	if ((p = sprlock(probe->ftp_pid)) == PROC_NULL) {
#if defined(__APPLE__)
		/*
		 * APPLE NOTE: We should never end up here. The Solaris sprlock()
		 * does not return process's with SIDL set, but we always return
		 * the child process.
		 */
		return;
#else

		if ((curproc->p_flag & SFORKING) == 0)
			return;

		lck_mtx_lock(&pidlock);
		p = prfind(probe->ftp_pid);

		/*
		 * Confirm that curproc is indeed forking the process in which
		 * we're trying to enable probes.
		 */
		ASSERT(p != NULL);
		//ASSERT(p->p_parent == curproc);
		ASSERT(p->p_stat == SIDL);

		lck_mtx_lock(&p->p_lock);
		lck_mtx_unlock(&pidlock);

		sprlock_proc(p);
#endif
	}

	/*
	 * APPLE NOTE: We do not have an equivalent thread structure to Solaris.
	 * Solaris uses its ulwp_t struct for scratch space to support the pid provider.
	 * To mimic this, we allocate on demand scratch space. If this is the first
	 * time a probe has been enabled in this process, we need to allocate scratch
	 * space for each already existing thread. Now is a good time to do this, as
	 * the target process is suspended and the proc_lock is held.
	 */
	if (p->p_dtrace_ptss_pages == NULL) {
		dtrace_ptss_enable(p);
	}

	// ASSERT(!(p->p_flag & SVFORK));
	proc_unlock(p);

	/*
	 * We have to enable the trap entry point before any user threads have
	 * the chance to execute the trap instruction we're about to place
	 * in their process's text.
	 */
	fasttrap_enable_callbacks();

	/*
	 * Enable all the tracepoints and add this probe's id to each
	 * tracepoint's list of active probes.
	 */
	for (i = 0; i < (int)probe->ftp_ntps; i++) {
		if ((rc = fasttrap_tracepoint_enable(p, probe, i)) != 0) {
			/*
			 * If enabling the tracepoint failed completely,
			 * we don't have to disable it; if the failure
			 * was only partial we must disable it.
			 */
			if (rc == FASTTRAP_ENABLE_FAIL)
				i--;
			else
				ASSERT(rc == FASTTRAP_ENABLE_PARTIAL);

			/*
			 * Back up and pull out all the tracepoints we've
			 * created so far for this probe.
			 */
			while (i >= 0) {
				fasttrap_tracepoint_disable(p, probe, i);
				i--;
			}

			proc_lock(p);
			sprunlock(p);

			/*
			 * Since we're not actually enabling this probe,
			 * drop our reference on the trap table entry.
			 */
			fasttrap_disable_callbacks();
			return;
		}
	}

	proc_lock(p);
	sprunlock(p);

	probe->ftp_enabled = 1;
}

/*ARGSUSED*/
static void
fasttrap_pid_disable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg, id)
	fasttrap_probe_t *probe = parg;
	fasttrap_provider_t *provider = probe->ftp_prov;
	proc_t *p;
	int i, whack = 0;

	ASSERT(id == probe->ftp_id);

	/*
	 * We won't be able to acquire a /proc-esque lock on the process
	 * iff the process is dead and gone. In this case, we rely on the
	 * provider lock as a point of mutual exclusion to prevent other
	 * DTrace consumers from disabling this probe.
	 */
	if ((p = sprlock(probe->ftp_pid)) != PROC_NULL) {
		// ASSERT(!(p->p_flag & SVFORK));
		proc_unlock(p);
	}

	lck_mtx_lock(&provider->ftp_mtx);

	/*
	 * Disable all the associated tracepoints (for fully enabled probes).
	 */
	if (probe->ftp_enabled) {
		for (i = 0; i < (int)probe->ftp_ntps; i++) {
			fasttrap_tracepoint_disable(p, probe, i);
		}
	}

	ASSERT(provider->ftp_rcount > 0);
	provider->ftp_rcount--;

	if (p != NULL) {
		/*
		 * Even though we may not be able to remove it entirely, we
		 * mark this retired provider to get a chance to remove some
		 * of the associated probes.
		 */
		if (provider->ftp_retired && !provider->ftp_marked)
			whack = provider->ftp_marked = 1;
		lck_mtx_unlock(&provider->ftp_mtx);

		proc_lock(p);
		sprunlock(p);
	} else {
		/*
		 * If the process is dead, we're just waiting for the
		 * last probe to be disabled to be able to free it.
		 */
		if (provider->ftp_rcount == 0 && !provider->ftp_marked)
			whack = provider->ftp_marked = 1;
		lck_mtx_unlock(&provider->ftp_mtx);
	}

	if (whack)
		fasttrap_pid_cleanup();

	if (!probe->ftp_enabled)
		return;

	probe->ftp_enabled = 0;

	// ASSERT(MUTEX_HELD(&cpu_lock));
	fasttrap_disable_callbacks();
}

/*ARGSUSED*/
static void
fasttrap_pid_getargdesc(void *arg, dtrace_id_t id, void *parg,
    dtrace_argdesc_t *desc)
{
#pragma unused(arg, id)
	fasttrap_probe_t *probe = parg;
	char *str;
	int i;

	desc->dtargd_native[0] = '\0';
	desc->dtargd_xlate[0] = '\0';

	if (probe->ftp_prov->ftp_retired != 0 ||
	    desc->dtargd_ndx >= probe->ftp_nargs) {
		desc->dtargd_ndx = DTRACE_ARGNONE;
		return;
	}

	/*
	 * We only need to set this member if the argument is remapped.
	 */
	if (probe->ftp_argmap != NULL)
		desc->dtargd_mapping = probe->ftp_argmap[desc->dtargd_ndx];

	str = probe->ftp_ntypes;
	for (i = 0; i < desc->dtargd_mapping; i++) {
		str += strlen(str) + 1;
	}

	(void) strlcpy(desc->dtargd_native, str, sizeof(desc->dtargd_native));

	if (probe->ftp_xtypes == NULL)
		return;

	str = probe->ftp_xtypes;
	for (i = 0; i < desc->dtargd_ndx; i++) {
		str += strlen(str) + 1;
	}

	(void) strlcpy(desc->dtargd_xlate, str, sizeof(desc->dtargd_xlate));
}

/*ARGSUSED*/
static void
fasttrap_pid_destroy(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg, id)
	fasttrap_probe_t *probe = parg;
	unsigned int i;

	ASSERT(probe != NULL);
	ASSERT(!probe->ftp_enabled);
	ASSERT(fasttrap_total >= probe->ftp_ntps);

	atomic_add_32(&fasttrap_total, -probe->ftp_ntps);
#if !defined(__APPLE__)
	size_t size = offsetof(fasttrap_probe_t, ftp_tps[probe->ftp_ntps]);
#endif

	if (probe->ftp_gen + 1 >= fasttrap_mod_gen)
		fasttrap_mod_barrier(probe->ftp_gen);

	for (i = 0; i < probe->ftp_ntps; i++) {
#if !defined(__APPLE__)
		kmem_free(probe->ftp_tps[i].fit_tp, sizeof (fasttrap_tracepoint_t));
#else
		zfree(fasttrap_tracepoint_t_zone, probe->ftp_tps[i].fit_tp);
#endif
	}

#if !defined(__APPLE__)
	kmem_free(probe, size);
#else
	if (probe->ftp_ntps < FASTTRAP_PROBE_T_ZONE_MAX_TRACEPOINTS) {
		zfree(fasttrap_probe_t_zones[probe->ftp_ntps], probe);
	} else {
		size_t size = offsetof(fasttrap_probe_t, ftp_tps[probe->ftp_ntps]);
		kmem_free(probe, size);
	}
#endif
}


static const dtrace_pattr_t pid_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
};

static dtrace_pops_t pid_pops = {
	fasttrap_pid_provide,
	NULL,
	fasttrap_pid_enable,
	fasttrap_pid_disable,
	NULL,
	NULL,
	fasttrap_pid_getargdesc,
	fasttrap_pid_getarg,
	NULL,
	fasttrap_pid_destroy
};

static dtrace_pops_t usdt_pops = {
	fasttrap_pid_provide,
	NULL,
	fasttrap_pid_enable,
	fasttrap_pid_disable,
	NULL,
	NULL,
	fasttrap_pid_getargdesc,
	fasttrap_usdt_getarg,
	NULL,
	fasttrap_pid_destroy
};

static fasttrap_proc_t *
fasttrap_proc_lookup(pid_t pid)
{
	fasttrap_bucket_t *bucket;
	fasttrap_proc_t *fprc, *new_fprc;

	bucket = &fasttrap_procs.fth_table[FASTTRAP_PROCS_INDEX(pid)];
	lck_mtx_lock(&bucket->ftb_mtx);

	for (fprc = bucket->ftb_data; fprc != NULL; fprc = fprc->ftpc_next) {
		if (fprc->ftpc_pid == pid && !fprc->ftpc_defunct) {
			lck_mtx_lock(&fprc->ftpc_mtx);
			lck_mtx_unlock(&bucket->ftb_mtx);
			fprc->ftpc_count++;
			lck_mtx_unlock(&fprc->ftpc_mtx);

			return (fprc);
		}
	}

	/*
	 * Drop the bucket lock so we don't try to perform a sleeping
	 * allocation under it.
	 */
	lck_mtx_unlock(&bucket->ftb_mtx);

	new_fprc = kmem_zalloc(sizeof (fasttrap_proc_t), KM_SLEEP);
	ASSERT(new_fprc != NULL);
	new_fprc->ftpc_pid = pid;
	new_fprc->ftpc_count = 1;

	lck_mtx_lock(&bucket->ftb_mtx);

	/*
	 * Take another lap through the list to make sure a proc hasn't
	 * been created for this pid while we weren't under the bucket lock.
	 */
	for (fprc = bucket->ftb_data; fprc != NULL; fprc = fprc->ftpc_next) {
		if (fprc->ftpc_pid == pid && !fprc->ftpc_defunct) {
			lck_mtx_lock(&fprc->ftpc_mtx);
			lck_mtx_unlock(&bucket->ftb_mtx);
			fprc->ftpc_count++;
			lck_mtx_unlock(&fprc->ftpc_mtx);

			kmem_free(new_fprc, sizeof (fasttrap_proc_t));

			return (fprc);
		}
	}

#if defined(__APPLE__)
	/*
	 * We have to initialize all locks explicitly
	 */
	lck_mtx_init(&new_fprc->ftpc_mtx, fasttrap_lck_grp, fasttrap_lck_attr);
#endif

	new_fprc->ftpc_next = bucket->ftb_data;
	bucket->ftb_data = new_fprc;

	lck_mtx_unlock(&bucket->ftb_mtx);

	return (new_fprc);
}

static void
fasttrap_proc_release(fasttrap_proc_t *proc)
{
	fasttrap_bucket_t *bucket;
	fasttrap_proc_t *fprc, **fprcp;
	pid_t pid = proc->ftpc_pid;

	lck_mtx_lock(&proc->ftpc_mtx);

	ASSERT(proc->ftpc_count != 0);

	if (--proc->ftpc_count != 0) {
		lck_mtx_unlock(&proc->ftpc_mtx);
		return;
	}

	lck_mtx_unlock(&proc->ftpc_mtx);

	bucket = &fasttrap_procs.fth_table[FASTTRAP_PROCS_INDEX(pid)];
	lck_mtx_lock(&bucket->ftb_mtx);

	fprcp = (fasttrap_proc_t **)&bucket->ftb_data;
	while ((fprc = *fprcp) != NULL) {
		if (fprc == proc)
			break;

		fprcp = &fprc->ftpc_next;
	}

	/*
	 * Something strange has happened if we can't find the proc.
	 */
	ASSERT(fprc != NULL);

	*fprcp = fprc->ftpc_next;

	lck_mtx_unlock(&bucket->ftb_mtx);

#if defined(__APPLE__)
	/*
	 * Apple explicit lock management. Not 100% certain we need this, the
	 * memory is freed even without the destroy. Maybe accounting cleanup?
	 */
	lck_mtx_destroy(&fprc->ftpc_mtx, fasttrap_lck_grp);
#endif

	kmem_free(fprc, sizeof (fasttrap_proc_t));
}

/*
 * Lookup a fasttrap-managed provider based on its name and associated pid.
 * If the pattr argument is non-NULL, this function instantiates the provider
 * if it doesn't exist otherwise it returns NULL. The provider is returned
 * with its lock held.
 */
#if defined(__APPLE__)
static fasttrap_provider_t *
fasttrap_provider_lookup(pid_t pid, fasttrap_provider_type_t provider_type, const char *name,
    const dtrace_pattr_t *pattr)
#endif /* __APPLE__ */
{
	fasttrap_provider_t *fp, *new_fp = NULL;
	fasttrap_bucket_t *bucket;
	char provname[DTRACE_PROVNAMELEN];
	proc_t *p;
	cred_t *cred;

	ASSERT(strlen(name) < sizeof (fp->ftp_name));
	ASSERT(pattr != NULL);

	bucket = &fasttrap_provs.fth_table[FASTTRAP_PROVS_INDEX(pid, name)];
	lck_mtx_lock(&bucket->ftb_mtx);

	/*
	 * Take a lap through the list and return the match if we find it.
	 */
	for (fp = bucket->ftb_data; fp != NULL; fp = fp->ftp_next) {
		if (fp->ftp_pid == pid &&
#if defined(__APPLE__)
		    fp->ftp_provider_type == provider_type &&
#endif /* __APPLE__ */
		    strncmp(fp->ftp_name, name, sizeof(fp->ftp_name)) == 0 &&
		    !fp->ftp_retired) {
			lck_mtx_lock(&fp->ftp_mtx);
			lck_mtx_unlock(&bucket->ftb_mtx);
			return (fp);
		}
	}

	/*
	 * Drop the bucket lock so we don't try to perform a sleeping
	 * allocation under it.
	 */
	lck_mtx_unlock(&bucket->ftb_mtx);

	/*
	 * Make sure the process exists, isn't a child created as the result
	 * of a vfork(2), and isn't a zombie (but may be in fork).
	 */
	if ((p = proc_find(pid)) == NULL) {
		return NULL;
	}
	proc_lock(p);
	if (p->p_lflag & (P_LINVFORK | P_LEXIT)) {
		proc_unlock(p);
		proc_rele(p);
		return (NULL);
	}

	/*
	 * Increment p_dtrace_probes so that the process knows to inform us
	 * when it exits or execs. fasttrap_provider_free() decrements this
	 * when we're done with this provider.
	 */
	p->p_dtrace_probes++;

	/*
	 * Grab the credentials for this process so we have
	 * something to pass to dtrace_register().
	 */
#if !defined(__APPLE__)
	mutex_enter(&p->p_crlock);
	crhold(p->p_cred);
	cred = p->p_cred;
	mutex_exit(&p->p_crlock);
	mutex_exit(&p->p_lock);
#else
	// lck_mtx_lock(&p->p_crlock);
	// Seems like OS X has no equivalent to crhold, even though it has a cr_ref field in ucred
	crhold(p->p_ucred);
	cred = p->p_ucred;
	// lck_mtx_unlock(&p->p_crlock);
	proc_unlock(p);
	proc_rele(p);
#endif /* __APPLE__ */

	new_fp = kmem_zalloc(sizeof (fasttrap_provider_t), KM_SLEEP);
	ASSERT(new_fp != NULL);
	new_fp->ftp_pid = pid;
	new_fp->ftp_proc = fasttrap_proc_lookup(pid);
#if defined(__APPLE__)
	new_fp->ftp_provider_type = provider_type;

	/*
	 * Apple locks require explicit init.
	 */
	lck_mtx_init(&new_fp->ftp_mtx, fasttrap_lck_grp, fasttrap_lck_attr);
	lck_mtx_init(&new_fp->ftp_cmtx, fasttrap_lck_grp, fasttrap_lck_attr);
#endif /* __APPLE__ */

	ASSERT(new_fp->ftp_proc != NULL);

	lck_mtx_lock(&bucket->ftb_mtx);

	/*
	 * Take another lap through the list to make sure a provider hasn't
	 * been created for this pid while we weren't under the bucket lock.
	 */
	for (fp = bucket->ftb_data; fp != NULL; fp = fp->ftp_next) {
		if (fp->ftp_pid == pid && strncmp(fp->ftp_name, name, sizeof(fp->ftp_name)) == 0 &&
		    !fp->ftp_retired) {
			lck_mtx_lock(&fp->ftp_mtx);
			lck_mtx_unlock(&bucket->ftb_mtx);
			fasttrap_provider_free(new_fp);
			crfree(cred);
			return (fp);
		}
	}

	(void) strlcpy(new_fp->ftp_name, name, sizeof(new_fp->ftp_name));

	/*
	 * Fail and return NULL if either the provider name is too long
	 * or we fail to register this new provider with the DTrace
	 * framework. Note that this is the only place we ever construct
	 * the full provider name -- we keep it in pieces in the provider
	 * structure.
	 */
	if (snprintf(provname, sizeof (provname), "%s%u", name, (uint_t)pid) >=
	    (int)sizeof (provname) ||
	    dtrace_register(provname, pattr,
	    DTRACE_PRIV_PROC | DTRACE_PRIV_OWNER | DTRACE_PRIV_ZONEOWNER, cred,
	    pattr == &pid_attr ? &pid_pops : &usdt_pops, new_fp,
	    &new_fp->ftp_provid) != 0) {
		lck_mtx_unlock(&bucket->ftb_mtx);
		fasttrap_provider_free(new_fp);
		crfree(cred);
		return (NULL);
	}

	new_fp->ftp_next = bucket->ftb_data;
	bucket->ftb_data = new_fp;

	lck_mtx_lock(&new_fp->ftp_mtx);
	lck_mtx_unlock(&bucket->ftb_mtx);

	crfree(cred);
	return (new_fp);
}

static void
fasttrap_provider_free(fasttrap_provider_t *provider)
{
	pid_t pid = provider->ftp_pid;
	proc_t *p;

	/*
	 * There need to be no associated enabled probes, no consumers
	 * creating probes, and no meta providers referencing this provider.
	 */
	ASSERT(provider->ftp_rcount == 0);
	ASSERT(provider->ftp_ccount == 0);
	ASSERT(provider->ftp_mcount == 0);

	fasttrap_proc_release(provider->ftp_proc);

#if defined(__APPLE__)
	/*
	 * Apple explicit lock management. Not 100% certain we need this, the
	 * memory is freed even without the destroy. Maybe accounting cleanup?
	 */
	lck_mtx_destroy(&provider->ftp_mtx, fasttrap_lck_grp);
	lck_mtx_destroy(&provider->ftp_cmtx, fasttrap_lck_grp);
#endif

	kmem_free(provider, sizeof (fasttrap_provider_t));

	/*
	 * Decrement p_dtrace_probes on the process whose provider we're
	 * freeing. We don't have to worry about clobbering somone else's
	 * modifications to it because we have locked the bucket that
	 * corresponds to this process's hash chain in the provider hash
	 * table. Don't sweat it if we can't find the process.
	 */
	if ((p = proc_find(pid)) == NULL) {
		return;
	}

	proc_lock(p);
	p->p_dtrace_probes--;
	proc_unlock(p);
	
	proc_rele(p);
}

static void
fasttrap_provider_retire(pid_t pid, const char *name, int mprov)
{
	fasttrap_provider_t *fp;
	fasttrap_bucket_t *bucket;
	dtrace_provider_id_t provid;

	ASSERT(strlen(name) < sizeof (fp->ftp_name));

	bucket = &fasttrap_provs.fth_table[FASTTRAP_PROVS_INDEX(pid, name)];
	lck_mtx_lock(&bucket->ftb_mtx);

	for (fp = bucket->ftb_data; fp != NULL; fp = fp->ftp_next) {
		if (fp->ftp_pid == pid && strncmp(fp->ftp_name, name, sizeof(fp->ftp_name)) == 0 &&
		    !fp->ftp_retired)
			break;
	}

	if (fp == NULL) {
		lck_mtx_unlock(&bucket->ftb_mtx);
		return;
	}

	lck_mtx_lock(&fp->ftp_mtx);
	ASSERT(!mprov || fp->ftp_mcount > 0);
	if (mprov && --fp->ftp_mcount != 0)  {
		lck_mtx_unlock(&fp->ftp_mtx);
		lck_mtx_unlock(&bucket->ftb_mtx);
		return;
	}

	/*
	 * Mark the provider to be removed in our post-processing step,
	 * mark it retired, and mark its proc as defunct (though it may
	 * already be marked defunct by another provider that shares the
	 * same proc). Marking it indicates that we should try to remove it;
	 * setting the retired flag indicates that we're done with this
	 * provider; setting the proc to be defunct indicates that all
	 * tracepoints associated with the traced process should be ignored.
	 *
	 * We obviously need to take the bucket lock before the provider lock
	 * to perform the lookup, but we need to drop the provider lock
	 * before calling into the DTrace framework since we acquire the
	 * provider lock in callbacks invoked from the DTrace framework. The
	 * bucket lock therefore protects the integrity of the provider hash
	 * table.
	 */
	fp->ftp_proc->ftpc_defunct = 1;
	fp->ftp_retired = 1;
	fp->ftp_marked = 1;
	provid = fp->ftp_provid;
	lck_mtx_unlock(&fp->ftp_mtx);

	/*
	 * We don't have to worry about invalidating the same provider twice
	 * since fasttrap_provider_lookup() will ignore provider that have
	 * been marked as retired.
	 */
	dtrace_invalidate(provid);

	lck_mtx_unlock(&bucket->ftb_mtx);

	fasttrap_pid_cleanup();
}

static int
fasttrap_add_probe(fasttrap_probe_spec_t *pdata)
{
	fasttrap_provider_t *provider;
	fasttrap_probe_t *pp;
	fasttrap_tracepoint_t *tp;
	const char *name;
	unsigned int i, aframes, whack;

#if defined(__APPLE__)
	switch (pdata->ftps_probe_type) {
#endif
	case DTFTP_ENTRY:
		name = "entry";
		aframes = FASTTRAP_ENTRY_AFRAMES;
		break;
	case DTFTP_RETURN:
		name = "return";
		aframes = FASTTRAP_RETURN_AFRAMES;
		break;
	case DTFTP_OFFSETS:
		aframes = 0;
		name = NULL;
		break;
	default:
		return (EINVAL);
	}

#if defined(__APPLE__)
	const char* provider_name;
	switch (pdata->ftps_provider_type) {
		case DTFTP_PROVIDER_PID:
			provider_name = FASTTRAP_PID_NAME;
			break;
		case DTFTP_PROVIDER_OBJC:
			provider_name = FASTTRAP_OBJC_NAME;
			break;
		case DTFTP_PROVIDER_ONESHOT:
			provider_name = FASTTRAP_ONESHOT_NAME;
			break;
		default:
			return (EINVAL);
	}

	if ((provider = fasttrap_provider_lookup(pdata->ftps_pid, pdata->ftps_provider_type,
						 provider_name, &pid_attr)) == NULL)
		return (ESRCH);
#endif /* __APPLE__ */

	/*
	 * Increment this reference count to indicate that a consumer is
	 * actively adding a new probe associated with this provider. This
	 * prevents the provider from being deleted -- we'll need to check
	 * for pending deletions when we drop this reference count.
	 */
	provider->ftp_ccount++;
	lck_mtx_unlock(&provider->ftp_mtx);

	/*
	 * Grab the creation lock to ensure consistency between calls to
	 * dtrace_probe_lookup() and dtrace_probe_create() in the face of
	 * other threads creating probes. We must drop the provider lock
	 * before taking this lock to avoid a three-way deadlock with the
	 * DTrace framework.
	 */
	lck_mtx_lock(&provider->ftp_cmtx);

	if (name == NULL) {
		for (i = 0; i < pdata->ftps_noffs; i++) {
			char name_str[17];

			(void) snprintf(name_str, sizeof(name_str), "%llx",
			    (unsigned long long)pdata->ftps_offs[i]);

			if (dtrace_probe_lookup(provider->ftp_provid,
			    pdata->ftps_mod, pdata->ftps_func, name_str) != 0)
				continue;

			atomic_add_32(&fasttrap_total, 1);

			if (fasttrap_total > fasttrap_max) {
				atomic_add_32(&fasttrap_total, -1);
				goto no_mem;
			}

#if !defined(__APPLE__)
			pp = kmem_zalloc(sizeof (fasttrap_probe_t), KM_SLEEP);
			ASSERT(pp != NULL);
#else
			pp = zalloc(fasttrap_probe_t_zones[1]);
			bzero(pp, sizeof (fasttrap_probe_t));
#endif

			pp->ftp_prov = provider;
			pp->ftp_faddr = pdata->ftps_pc;
			pp->ftp_fsize = pdata->ftps_size;
			pp->ftp_pid = pdata->ftps_pid;
			pp->ftp_ntps = 1;

#if !defined(__APPLE__)
			tp = kmem_zalloc(sizeof (fasttrap_tracepoint_t), KM_SLEEP);
#else
			tp = zalloc(fasttrap_tracepoint_t_zone);			
			bzero(tp, sizeof (fasttrap_tracepoint_t));
#endif

			tp->ftt_proc = provider->ftp_proc;
			tp->ftt_pc = pdata->ftps_offs[i] + pdata->ftps_pc;
			tp->ftt_pid = pdata->ftps_pid;


			pp->ftp_tps[0].fit_tp = tp;
			pp->ftp_tps[0].fit_id.fti_probe = pp;
#if defined(__APPLE__)
			pp->ftp_tps[0].fit_id.fti_ptype = pdata->ftps_probe_type;
#endif
			pp->ftp_id = dtrace_probe_create(provider->ftp_provid,
			    pdata->ftps_mod, pdata->ftps_func, name_str,
			    FASTTRAP_OFFSET_AFRAMES, pp);
		}

	} else if (dtrace_probe_lookup(provider->ftp_provid, pdata->ftps_mod,
	    pdata->ftps_func, name) == 0) {
		atomic_add_32(&fasttrap_total, pdata->ftps_noffs);

		if (fasttrap_total > fasttrap_max) {
			atomic_add_32(&fasttrap_total, -pdata->ftps_noffs);
			goto no_mem;
		}

		ASSERT(pdata->ftps_noffs > 0);
#if !defined(__APPLE__)
		pp = kmem_zalloc(offsetof(fasttrap_probe_t,
					  ftp_tps[pdata->ftps_noffs]), KM_SLEEP);
		ASSERT(pp != NULL);
#else
		if (pdata->ftps_noffs < FASTTRAP_PROBE_T_ZONE_MAX_TRACEPOINTS) {
			pp = zalloc(fasttrap_probe_t_zones[pdata->ftps_noffs]);
			bzero(pp, offsetof(fasttrap_probe_t, ftp_tps[pdata->ftps_noffs]));
		} else {
			pp = kmem_zalloc(offsetof(fasttrap_probe_t, ftp_tps[pdata->ftps_noffs]), KM_SLEEP);
		}
#endif

		pp->ftp_prov = provider;
		pp->ftp_faddr = pdata->ftps_pc;
		pp->ftp_fsize = pdata->ftps_size;
		pp->ftp_pid = pdata->ftps_pid;
		pp->ftp_ntps = pdata->ftps_noffs;

		for (i = 0; i < pdata->ftps_noffs; i++) {
#if !defined(__APPLE__)
			tp = kmem_zalloc(sizeof (fasttrap_tracepoint_t), KM_SLEEP);
#else
			tp = zalloc(fasttrap_tracepoint_t_zone);
			bzero(tp, sizeof (fasttrap_tracepoint_t));
#endif

			tp->ftt_proc = provider->ftp_proc;
			tp->ftt_pc = pdata->ftps_offs[i] + pdata->ftps_pc;
			tp->ftt_pid = pdata->ftps_pid;

			pp->ftp_tps[i].fit_tp = tp;
			pp->ftp_tps[i].fit_id.fti_probe = pp;
#if defined(__APPLE__)
			pp->ftp_tps[i].fit_id.fti_ptype = pdata->ftps_probe_type;
#endif
		}

		pp->ftp_id = dtrace_probe_create(provider->ftp_provid,
		    pdata->ftps_mod, pdata->ftps_func, name, aframes, pp);
	}

	lck_mtx_unlock(&provider->ftp_cmtx);

	/*
	 * We know that the provider is still valid since we incremented the
	 * creation reference count. If someone tried to clean up this provider
	 * while we were using it (e.g. because the process called exec(2) or
	 * exit(2)), take note of that and try to clean it up now.
	 */
	lck_mtx_lock(&provider->ftp_mtx);
	provider->ftp_ccount--;
	whack = provider->ftp_retired;
	lck_mtx_unlock(&provider->ftp_mtx);

	if (whack)
		fasttrap_pid_cleanup();

	return (0);

no_mem:
	/*
	 * If we've exhausted the allowable resources, we'll try to remove
	 * this provider to free some up. This is to cover the case where
	 * the user has accidentally created many more probes than was
	 * intended (e.g. pid123:::).
	 */
	lck_mtx_unlock(&provider->ftp_cmtx);
	lck_mtx_lock(&provider->ftp_mtx);
	provider->ftp_ccount--;
	provider->ftp_marked = 1;
	lck_mtx_unlock(&provider->ftp_mtx);

	fasttrap_pid_cleanup();

	return (ENOMEM);
}

/*ARGSUSED*/
static void *
fasttrap_meta_provide(void *arg, dtrace_helper_provdesc_t *dhpv, pid_t pid)
{
#pragma unused(arg)
	fasttrap_provider_t *provider;

	/*
	 * A 32-bit unsigned integer (like a pid for example) can be
	 * expressed in 10 or fewer decimal digits. Make sure that we'll
	 * have enough space for the provider name.
	 */
	if (strlen(dhpv->dthpv_provname) + 10 >=
	    sizeof (provider->ftp_name)) {
		cmn_err(CE_WARN, "failed to instantiate provider %s: "
		    "name too long to accomodate pid", dhpv->dthpv_provname);
		return (NULL);
	}

	/*
	 * Don't let folks spoof the true pid provider.
	 */
	if (strncmp(dhpv->dthpv_provname, FASTTRAP_PID_NAME, sizeof(FASTTRAP_PID_NAME)) == 0) {
		cmn_err(CE_WARN, "failed to instantiate provider %s: "
		    "%s is an invalid name", dhpv->dthpv_provname,
		    FASTTRAP_PID_NAME);
		return (NULL);
	}
#if defined(__APPLE__)
	/*
	 * We also need to check the other pid provider types
	 */
	if (strncmp(dhpv->dthpv_provname, FASTTRAP_OBJC_NAME, sizeof(FASTTRAP_OBJC_NAME)) == 0) {
		cmn_err(CE_WARN, "failed to instantiate provider %s: "
		    "%s is an invalid name", dhpv->dthpv_provname,
		    FASTTRAP_OBJC_NAME);
		return (NULL);
	}
	if (strncmp(dhpv->dthpv_provname, FASTTRAP_ONESHOT_NAME, sizeof(FASTTRAP_ONESHOT_NAME)) == 0) {
		cmn_err(CE_WARN, "failed to instantiate provider %s: "
		    "%s is an invalid name", dhpv->dthpv_provname,
		    FASTTRAP_ONESHOT_NAME);
		return (NULL);
	}
#endif /* __APPLE__ */

	/*
	 * The highest stability class that fasttrap supports is ISA; cap
	 * the stability of the new provider accordingly.
	 */
	if (dhpv->dthpv_pattr.dtpa_provider.dtat_class >= DTRACE_CLASS_COMMON)
		dhpv->dthpv_pattr.dtpa_provider.dtat_class = DTRACE_CLASS_ISA;
	if (dhpv->dthpv_pattr.dtpa_mod.dtat_class >= DTRACE_CLASS_COMMON)
		dhpv->dthpv_pattr.dtpa_mod.dtat_class = DTRACE_CLASS_ISA;
	if (dhpv->dthpv_pattr.dtpa_func.dtat_class >= DTRACE_CLASS_COMMON)
		dhpv->dthpv_pattr.dtpa_func.dtat_class = DTRACE_CLASS_ISA;
	if (dhpv->dthpv_pattr.dtpa_name.dtat_class >= DTRACE_CLASS_COMMON)
		dhpv->dthpv_pattr.dtpa_name.dtat_class = DTRACE_CLASS_ISA;
	if (dhpv->dthpv_pattr.dtpa_args.dtat_class >= DTRACE_CLASS_COMMON)
		dhpv->dthpv_pattr.dtpa_args.dtat_class = DTRACE_CLASS_ISA;

#if defined(__APPLE__)
	if ((provider = fasttrap_provider_lookup(pid, DTFTP_PROVIDER_USDT, dhpv->dthpv_provname,
	    &dhpv->dthpv_pattr)) == NULL) {
		cmn_err(CE_WARN, "failed to instantiate provider %s for "
		    "process %u",  dhpv->dthpv_provname, (uint_t)pid);
		return (NULL);
	}

	/*
	 * APPLE NOTE!
	 *
	 * USDT probes (fasttrap meta probes) are very expensive to create.
	 * Profiling has shown that the largest single cost is verifying that
	 * dtrace hasn't already created a given meta_probe. The reason for
	 * this is dtrace_match() often has to strcmp ~100 hashed entries for
	 * each static probe being created. We want to get rid of that check.
	 * The simplest way of eliminating it is to deny the ability to add
	 * probes to an existing provider. If the provider already exists, BZZT!
	 * This still leaves the possibility of intentionally malformed DOF
	 * having duplicate probes. However, duplicate probes are not fatal,
	 * and there is no way to get that by accident, so we will not check
	 * for that case.
	 */

	if (provider->ftp_mcount != 0) {
		/* This is the duplicate provider case. */
		lck_mtx_unlock(&provider->ftp_mtx);
		return NULL;
	}
#endif /* __APPLE__ */

	/*
	 * Up the meta provider count so this provider isn't removed until
	 * the meta provider has been told to remove it.
	 */
	provider->ftp_mcount++;

	lck_mtx_unlock(&provider->ftp_mtx);

	return (provider);
}

/*ARGSUSED*/
static void
fasttrap_meta_create_probe(void *arg, void *parg,
    dtrace_helper_probedesc_t *dhpb)
{
#pragma unused(arg)
	fasttrap_provider_t *provider = parg;
	fasttrap_probe_t *pp;
	fasttrap_tracepoint_t *tp;
	unsigned int i, j;
	uint32_t ntps;

	/*
	 * Since the meta provider count is non-zero we don't have to worry
	 * about this provider disappearing.
	 */
	ASSERT(provider->ftp_mcount > 0);

	/*
	 * Grab the creation lock to ensure consistency between calls to
	 * dtrace_probe_lookup() and dtrace_probe_create() in the face of
	 * other threads creating probes.
	 */
	lck_mtx_lock(&provider->ftp_cmtx);

#if !defined(__APPLE__)
	/*
	 * APPLE NOTE: This is hideously expensive. See note in 
	 * fasttrap_meta_provide() for why we can get away without
	 * checking here.
	 */
	if (dtrace_probe_lookup(provider->ftp_provid, dhpb->dthpb_mod,
	    dhpb->dthpb_func, dhpb->dthpb_name) != 0) {
		lck_mtx_unlock(&provider->ftp_cmtx);
		return;
	}
#endif

	ntps = dhpb->dthpb_noffs + dhpb->dthpb_nenoffs;
	ASSERT(ntps > 0);

	atomic_add_32(&fasttrap_total, ntps);

	if (fasttrap_total > fasttrap_max) {
		atomic_add_32(&fasttrap_total, -ntps);
		lck_mtx_unlock(&provider->ftp_cmtx);
		return;
	}

#if !defined(__APPLE__)
	pp = kmem_zalloc(offsetof(fasttrap_probe_t, ftp_tps[ntps]), KM_SLEEP);
	ASSERT(pp != NULL);
#else
	if (ntps < FASTTRAP_PROBE_T_ZONE_MAX_TRACEPOINTS) {
		pp = zalloc(fasttrap_probe_t_zones[ntps]);
		bzero(pp, offsetof(fasttrap_probe_t, ftp_tps[ntps]));
	} else {
		pp = kmem_zalloc(offsetof(fasttrap_probe_t, ftp_tps[ntps]), KM_SLEEP);
	}
#endif

	pp->ftp_prov = provider;
	pp->ftp_pid = provider->ftp_pid;
	pp->ftp_ntps = ntps;
	pp->ftp_nargs = dhpb->dthpb_xargc;
	pp->ftp_xtypes = dhpb->dthpb_xtypes;
	pp->ftp_ntypes = dhpb->dthpb_ntypes;

	/*
	 * First create a tracepoint for each actual point of interest.
	 */
	for (i = 0; i < dhpb->dthpb_noffs; i++) {
#if !defined(__APPLE__)
		tp = kmem_zalloc(sizeof (fasttrap_tracepoint_t), KM_SLEEP);
#else
		tp = zalloc(fasttrap_tracepoint_t_zone);
		bzero(tp, sizeof (fasttrap_tracepoint_t));
#endif

		tp->ftt_proc = provider->ftp_proc;
#if defined(__APPLE__)
		/*
		 * APPLE NOTE: We have linker support when creating DOF to handle all relocations for us.
		 * Unfortunately, a side effect of this is that the relocations do not point at exactly
		 * the location we want. We need to fix up the addresses here. The fixups vary by arch and type.
		 */
#if defined(__i386__)
		/*
		 * Both 32 & 64 bit want to go back one byte, to point at the first NOP
		 */
		tp->ftt_pc = dhpb->dthpb_base + (int64_t)dhpb->dthpb_offs[i] - 1;
#elif defined(__ppc__)
		/* All PPC probes are zero offset. */
		tp->ftt_pc = dhpb->dthpb_base + (int64_t)dhpb->dthpb_offs[i];
#else
#error "Architecture not supported"
#endif

#else
		tp->ftt_pc = dhpb->dthpb_base + dhpb->dthpb_offs[i];
#endif
		tp->ftt_pid = provider->ftp_pid;

		pp->ftp_tps[i].fit_tp = tp;
		pp->ftp_tps[i].fit_id.fti_probe = pp;
#ifdef __sparc
		pp->ftp_tps[i].fit_id.fti_ptype = DTFTP_POST_OFFSETS;
#else
		pp->ftp_tps[i].fit_id.fti_ptype = DTFTP_OFFSETS;
#endif
	}

	/*
	 * Then create a tracepoint for each is-enabled point.
	 */
	for (j = 0; i < ntps; i++, j++) {
#if !defined(__APPLE__)
		tp = kmem_zalloc(sizeof (fasttrap_tracepoint_t), KM_SLEEP);
#else
		tp = zalloc(fasttrap_tracepoint_t_zone);
		bzero(tp, sizeof (fasttrap_tracepoint_t));
#endif

		tp->ftt_proc = provider->ftp_proc;
#if defined(__APPLE__)
		/*
		 * APPLE NOTE: We have linker support when creating DOF to handle all relocations for us.
		 * Unfortunately, a side effect of this is that the relocations do not point at exactly
		 * the location we want. We need to fix up the addresses here. The fixups vary by arch and type.
		 */
#if defined(__i386__)
		/*
		 * Both 32 & 64 bit want to go forward two bytes, to point at a single byte nop.
		 */
		tp->ftt_pc = dhpb->dthpb_base + (int64_t)dhpb->dthpb_enoffs[j] + 2;
#elif defined(__ppc__)
		/* All PPC is-enabled probes are zero offset. */
		tp->ftt_pc = dhpb->dthpb_base + (int64_t)dhpb->dthpb_enoffs[j];
#else
#error "Architecture not supported"
#endif

#else
		tp->ftt_pc = dhpb->dthpb_base + dhpb->dthpb_enoffs[j];
#endif
		tp->ftt_pid = provider->ftp_pid;

		pp->ftp_tps[i].fit_tp = tp;
		pp->ftp_tps[i].fit_id.fti_probe = pp;
		pp->ftp_tps[i].fit_id.fti_ptype = DTFTP_IS_ENABLED;
	}

	/*
	 * If the arguments are shuffled around we set the argument remapping
	 * table. Later, when the probe fires, we only remap the arguments
	 * if the table is non-NULL.
	 */
	for (i = 0; i < dhpb->dthpb_xargc; i++) {
		if (dhpb->dthpb_args[i] != i) {
			pp->ftp_argmap = dhpb->dthpb_args;
			break;
		}
	}

	/*
	 * The probe is fully constructed -- register it with DTrace.
	 */
	pp->ftp_id = dtrace_probe_create(provider->ftp_provid, dhpb->dthpb_mod,
	    dhpb->dthpb_func, dhpb->dthpb_name, FASTTRAP_OFFSET_AFRAMES, pp);

	lck_mtx_unlock(&provider->ftp_cmtx);
}

/*ARGSUSED*/
static void
fasttrap_meta_remove(void *arg, dtrace_helper_provdesc_t *dhpv, pid_t pid)
{
#pragma unused(arg)
	/*
	 * Clean up the USDT provider. There may be active consumers of the
	 * provider busy adding probes, no damage will actually befall the
	 * provider until that count has dropped to zero. This just puts
	 * the provider on death row.
	 */
	fasttrap_provider_retire(pid, dhpv->dthpv_provname, 1);
}

static dtrace_mops_t fasttrap_mops = {
	fasttrap_meta_create_probe,
	fasttrap_meta_provide,
	fasttrap_meta_remove
};

/*ARGSUSED*/
static int
fasttrap_ioctl(dev_t dev, int cmd, intptr_t arg, int md, cred_t *cr, int *rv)
{
#pragma unused(dev, md, rv)
	if (!dtrace_attached())
		return (EAGAIN);

	if (cmd == FASTTRAPIOC_MAKEPROBE) {
		// FIXME! What size is arg? If it is not 64 bit, how do we pass in a 64 bit value?
		fasttrap_probe_spec_t *uprobe = (void *)arg;
		fasttrap_probe_spec_t *probe;
		uint64_t noffs;
		size_t size, i;
		int ret;
		char *c;

		/*
		 * FIXME! How does this work? The kern is running in 32 bit mode. It has a 32 bit pointer,
		 * uprobe. We do address manipulations on it, and still have a 64 bit value? This seems
		 * broken. What is the right way to do this?
		 */
		if (copyin((user_addr_t)(unsigned long)&uprobe->ftps_noffs, &noffs,
		    sizeof (uprobe->ftps_noffs)))
			return (EFAULT);

		/*
		 * Probes must have at least one tracepoint.
		 */
		if (noffs == 0)
			return (EINVAL);

		/*
		 * We want to check the number of noffs before doing
		 * sizing math, to prevent potential buffer overflows.
		 */
		if (noffs > ((1024 * 1024) - sizeof(fasttrap_probe_spec_t)) / sizeof(probe->ftps_offs[0]))
			return (ENOMEM);

		size = sizeof (fasttrap_probe_spec_t) +
		    sizeof (probe->ftps_offs[0]) * (noffs - 1);

		probe = kmem_alloc(size, KM_SLEEP);

		if (copyin((user_addr_t)(unsigned long)uprobe, probe, size) != 0) {
			kmem_free(probe, size);
			return (EFAULT);
		}

		/*
		 * Verify that the function and module strings contain no
		 * funny characters.
		 */
		for (i = 0, c = &probe->ftps_func[0]; i < sizeof(probe->ftps_func) && *c != '\0'; i++, c++) {
			if (*c < 0x20 || 0x7f <= *c) {
				ret = EINVAL;
				goto err;
			}
		}
		if (*c != '\0') {
			ret = EINVAL;
			goto err;
		}

		for (i = 0, c = &probe->ftps_mod[0]; i < sizeof(probe->ftps_mod) && *c != '\0'; i++, c++) {
			if (*c < 0x20 || 0x7f <= *c) {
				ret = EINVAL;
				goto err;
			}
		}
		if (*c != '\0') {
			ret = EINVAL;
			goto err;
		}

		if (!PRIV_POLICY_CHOICE(cr, PRIV_ALL, B_FALSE)) {
			proc_t *p;
			pid_t pid = probe->ftps_pid;

			/*
			 * Report an error if the process doesn't exist
			 * or is actively being birthed.
			 */
			if ((p = proc_find(pid)) == PROC_NULL || p->p_stat == SIDL) {
				if (p != PROC_NULL)
					proc_rele(p);
				return (ESRCH);
			}
			// proc_lock(p);
			// FIXME! How is this done on OS X?
			// if ((ret = priv_proc_cred_perm(cr, p, NULL,
			//     VREAD | VWRITE)) != 0) {
			// 	mutex_exit(&p->p_lock);
			// 	return (ret);
			// }
			// proc_unlock(p);
			proc_rele(p);
		}

		ret = fasttrap_add_probe(probe);

err:
		kmem_free(probe, size);

		return (ret);

	} else if (cmd == FASTTRAPIOC_GETINSTR) {
		fasttrap_instr_query_t instr;
		fasttrap_tracepoint_t *tp;
		uint_t index;
		// int ret;

		if (copyin((user_addr_t)(unsigned long)arg, &instr, sizeof (instr)) != 0)
			return (EFAULT);

		if (!PRIV_POLICY_CHOICE(cr, PRIV_ALL, B_FALSE)) {
			proc_t *p;
			pid_t pid = instr.ftiq_pid;

			/*
			 * Report an error if the process doesn't exist
			 * or is actively being birthed.
			 */
			if ((p = proc_find(pid)) == NULL || p->p_stat == SIDL) {
				if (p != PROC_NULL)
					proc_rele(p);
				return (ESRCH);
			}
			//proc_lock(p);
			// FIXME! How is this done on OS X?
			// if ((ret = priv_proc_cred_perm(cr, p, NULL,
			//     VREAD)) != 0) {
			// 	mutex_exit(&p->p_lock);
			// 	return (ret);
			// }
			// proc_unlock(p);
			proc_rele(p);
		}

		index = FASTTRAP_TPOINTS_INDEX(instr.ftiq_pid, instr.ftiq_pc);

		lck_mtx_lock(&fasttrap_tpoints.fth_table[index].ftb_mtx);
		tp = fasttrap_tpoints.fth_table[index].ftb_data;
		while (tp != NULL) {
			if (instr.ftiq_pid == tp->ftt_pid &&
			    instr.ftiq_pc == tp->ftt_pc &&
			    !tp->ftt_proc->ftpc_defunct)
				break;

			tp = tp->ftt_next;
		}

		if (tp == NULL) {
			lck_mtx_unlock(&fasttrap_tpoints.fth_table[index].ftb_mtx);
			return (ENOENT);
		}

		bcopy(&tp->ftt_instr, &instr.ftiq_instr,
		    sizeof (instr.ftiq_instr));
		lck_mtx_unlock(&fasttrap_tpoints.fth_table[index].ftb_mtx);

		if (copyout(&instr, (user_addr_t)(unsigned long)arg, sizeof (instr)) != 0)
			return (EFAULT);

		return (0);
	}

	return (EINVAL);
}

static int
fasttrap_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	ulong_t nent;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	fasttrap_devi = devi;

	/*
	 * Install our hooks into fork(2), exec(2), and exit(2).
	 */
	dtrace_fasttrap_fork_ptr = &fasttrap_fork;
	dtrace_fasttrap_exit_ptr = &fasttrap_exec_exit;
	dtrace_fasttrap_exec_ptr = &fasttrap_exec_exit;

#if !defined(__APPLE__)
	fasttrap_max = ddi_getprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "fasttrap-max-probes", FASTTRAP_MAX_DEFAULT);
#else
	/*
	 * We're sizing based on system memory. 100k probes per 256M of system memory.
	 * Yes, this is a WAG.
	 */
	fasttrap_max = (sane_size >> 28) * 100000;
	if (fasttrap_max == 0)
		fasttrap_max = 50000;
#endif
	fasttrap_total = 0;

	/*
	 * Conjure up the tracepoints hashtable...
	 */
	nent = ddi_getprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "fasttrap-hash-size", FASTTRAP_TPOINTS_DEFAULT_SIZE);

	if (nent <= 0 || nent > 0x1000000)
		nent = FASTTRAP_TPOINTS_DEFAULT_SIZE;

	if ((nent & (nent - 1)) == 0)
		fasttrap_tpoints.fth_nent = nent;
	else
		fasttrap_tpoints.fth_nent = 1 << fasttrap_highbit(nent);
	ASSERT(fasttrap_tpoints.fth_nent > 0);
	fasttrap_tpoints.fth_mask = fasttrap_tpoints.fth_nent - 1;
	fasttrap_tpoints.fth_table = kmem_zalloc(fasttrap_tpoints.fth_nent *
	    sizeof (fasttrap_bucket_t), KM_SLEEP);
	ASSERT(fasttrap_tpoints.fth_table != NULL);
#if defined(__APPLE__)
	/*
	 * We have to explicitly initialize all locks...
	 */
	unsigned int i;
	for (i=0; i<fasttrap_tpoints.fth_nent; i++) {
		lck_mtx_init(&fasttrap_tpoints.fth_table[i].ftb_mtx, fasttrap_lck_grp, fasttrap_lck_attr);
	}
#endif

	/*
	 * ... and the providers hash table...
	 */
	nent = FASTTRAP_PROVIDERS_DEFAULT_SIZE;
	if ((nent & (nent - 1)) == 0)
		fasttrap_provs.fth_nent = nent;
	else
		fasttrap_provs.fth_nent = 1 << fasttrap_highbit(nent);
	ASSERT(fasttrap_provs.fth_nent > 0);
	fasttrap_provs.fth_mask = fasttrap_provs.fth_nent - 1;
	fasttrap_provs.fth_table = kmem_zalloc(fasttrap_provs.fth_nent *
	    sizeof (fasttrap_bucket_t), KM_SLEEP);
	ASSERT(fasttrap_provs.fth_table != NULL);
#if defined(__APPLE__)
	/*
	 * We have to explicitly initialize all locks...
	 */
	for (i=0; i<fasttrap_provs.fth_nent; i++) {
		lck_mtx_init(&fasttrap_provs.fth_table[i].ftb_mtx, fasttrap_lck_grp, fasttrap_lck_attr);
	}
#endif

	/*
	 * ... and the procs hash table.
	 */
	nent = FASTTRAP_PROCS_DEFAULT_SIZE;
	if ((nent & (nent - 1)) == 0)
		fasttrap_procs.fth_nent = nent;
	else
		fasttrap_procs.fth_nent = 1 << fasttrap_highbit(nent);
	ASSERT(fasttrap_procs.fth_nent > 0);
	fasttrap_procs.fth_mask = fasttrap_procs.fth_nent - 1;
	fasttrap_procs.fth_table = kmem_zalloc(fasttrap_procs.fth_nent *
	    sizeof (fasttrap_bucket_t), KM_SLEEP);
	ASSERT(fasttrap_procs.fth_table != NULL);
#if defined(__APPLE__)
	/*
	 * We have to explicitly initialize all locks...
	 */
	for (i=0; i<fasttrap_procs.fth_nent; i++) {
		lck_mtx_init(&fasttrap_procs.fth_table[i].ftb_mtx, fasttrap_lck_grp, fasttrap_lck_attr);
	}
#endif

	(void) dtrace_meta_register("fasttrap", &fasttrap_mops, NULL,
	    &fasttrap_meta_id);

	return (DDI_SUCCESS);
}

static int 
_fasttrap_open(dev_t dev, int flags, int devtype, struct proc *p)
{
#pragma unused(dev, flags, devtype, p)
	return  0;
}

static int
_fasttrap_ioctl(dev_t dev, u_long cmd, caddr_t data, int fflag, struct proc *p)
{
#pragma unused(p)
	int err, rv = 0;

	/*
	 * FIXME! 64 bit problem with the data var.
	 */
	err = fasttrap_ioctl(dev, (int)cmd, *(intptr_t *)data, fflag, CRED(), &rv);

	/* XXX Darwin's BSD ioctls only return -1 or zero. Overload errno to mimic Solaris. 20 bits suffice. */
	if (err != 0) {
		ASSERT( (err & 0xfffff000) == 0 );
		return (err & 0xfff); /* ioctl returns -1 and errno set to an error code < 4096 */
	} else if (rv != 0) {
		ASSERT( (rv & 0xfff00000) == 0 );
		return (((rv & 0xfffff) << 12)); /* ioctl returns -1 and errno set to a return value >= 4096 */
	} else 
		return 0;
}

static int gFasttrapInited = 0;

#define FASTTRAP_MAJOR  -24 /* let the kernel pick the device number */

/*
 * A struct describing which functions will get invoked for certain
 * actions.
 */

static struct cdevsw fasttrap_cdevsw =
{
	_fasttrap_open,         /* open */
	eno_opcl,               /* close */
	eno_rdwrt,              /* read */
	eno_rdwrt,              /* write */
	_fasttrap_ioctl,        /* ioctl */
	(stop_fcn_t *)nulldev,  /* stop */
	(reset_fcn_t *)nulldev, /* reset */
	NULL,                   /* tty's */
	eno_select,             /* select */
	eno_mmap,               /* mmap */
	eno_strat,              /* strategy */
	eno_getc,               /* getc */
	eno_putc,               /* putc */
	0                       /* type */
};

void fasttrap_init(void);

void
fasttrap_init( void )
{
	/*
	 * This method is now invoked from multiple places. Any open of /dev/dtrace,
	 * also dtrace_init if the dtrace_dof_mode is DTRACE_DOF_MODE_NON_LAZY.
	 *
	 * The reason is to delay allocating the (rather large) resources as late as possible.
	 */
	if (0 == gFasttrapInited) {
		int majdevno = cdevsw_add(FASTTRAP_MAJOR, &fasttrap_cdevsw);

		if (majdevno < 0) {
			// FIX ME! What kind of error reporting to do here?
			printf("fasttrap_init: failed to allocate a major number!\n");
			return;
		}

		dev_t device = makedev( (uint32_t)majdevno, 0 );
		if (NULL == devfs_make_node( device, DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0666, "fasttrap", 0 )) {
			return;
		}

		/*
		 * Allocate the fasttrap_tracepoint_t zone
		 */
		fasttrap_tracepoint_t_zone = zinit(sizeof(fasttrap_tracepoint_t),
						   1024 * sizeof(fasttrap_tracepoint_t),
						   sizeof(fasttrap_tracepoint_t),
						   "dtrace.fasttrap_tracepoint_t");

		/*
		 * fasttrap_probe_t's are variable in size. We use an array of zones to
		 * cover the most common sizes.
		 */
		int i;
		for (i=1; i<FASTTRAP_PROBE_T_ZONE_MAX_TRACEPOINTS; i++) {
			size_t zone_element_size = offsetof(fasttrap_probe_t, ftp_tps[i]);
			fasttrap_probe_t_zones[i] = zinit(zone_element_size,
							  1024 * zone_element_size,
							  zone_element_size,
							  fasttrap_probe_t_zone_names[i]);
		}

		
		/*
		 * Create the fasttrap lock group. Must be done before fasttrap_attach()!
		 */
		fasttrap_lck_attr = lck_attr_alloc_init();
		fasttrap_lck_grp_attr= lck_grp_attr_alloc_init();		
		fasttrap_lck_grp = lck_grp_alloc_init("fasttrap",  fasttrap_lck_grp_attr);

		/*
		 * Initialize global locks
		 */
		lck_mtx_init(&fasttrap_cleanup_mtx, fasttrap_lck_grp, fasttrap_lck_attr);
		lck_mtx_init(&fasttrap_count_mtx, fasttrap_lck_grp, fasttrap_lck_attr);

		if (DDI_FAILURE == fasttrap_attach((dev_info_t *)device, 0 )) {
			// FIX ME! Do we remove the devfs node here?
			// What kind of error reporting?
			printf("fasttrap_init: Call to fasttrap_attach failed.\n");
			return;
		}

		gFasttrapInited = 1;		
	}
}

#undef FASTTRAP_MAJOR
