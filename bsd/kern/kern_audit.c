/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
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
#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/namei.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include <sys/unistd.h>
#include <sys/file_internal.h>
#include <sys/vnode_internal.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/malloc.h>
#include <sys/un.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/vfs_context.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>

#include <bsm/audit.h>
#include <bsm/audit_kevents.h>
#include <bsm/audit_klib.h>
#include <bsm/audit_kernel.h>

#include <mach/host_priv.h>
#include <mach/host_special_ports.h>
#include <mach/audit_triggers_server.h>

#include <kern/host.h>
#include <kern/kalloc.h>
#include <kern/zalloc.h>
#include <kern/lock.h>
#include <kern/wait_queue.h>
#include <kern/sched_prim.h>

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>

#ifdef AUDIT

/*
 * The AUDIT_EXCESSIVELY_VERBOSE define enables a number of
 * gratuitously noisy printf's to the console.  Due to the
 * volume, it should be left off unless you want your system
 * to churn a lot whenever the audit record flow gets high.
 */
/* #define	AUDIT_EXCESSIVELY_VERBOSE */
#ifdef AUDIT_EXCESSIVELY_VERBOSE
#define	AUDIT_PRINTF_ONLY
#define	AUDIT_PRINTF(x)	printf x
#else
#define	AUDIT_PRINTF_ONLY __unused
#define	AUDIT_PRINTF(X)
#endif

#if DIAGNOSTIC
#if defined(assert)
#undef assert()
#endif
#define assert(cond)    \
    ((void) ((cond) ? 0 : panic("%s:%d (%s)", __FILE__, __LINE__, # cond)))
#else
#include <kern/assert.h>
#endif /* DIAGNOSTIC */

/* 
 * Define the audit control flags.
 */
int	audit_enabled;
int	audit_suspended;

/*
 * Mutex to protect global variables shared between various threads and
 * processes.
 */
static mutex_t				*audit_mtx;

/*
 * Queue of audit records ready for delivery to disk.  We insert new
 * records at the tail, and remove records from the head.  Also,
 * a count of the number of records used for checking queue depth.
 * In addition, a counter of records that we have allocated but are
 * not yet in the queue, which is needed to estimate the total
 * size of the combined set of records outstanding in the system.
 */
static TAILQ_HEAD(, kaudit_record)	 audit_q;
static size_t				audit_q_len;
static size_t				audit_pre_q_len;

static wait_queue_t			audit_wait_queue;
static zone_t				audit_zone;

/*
 * Condition variable to signal to the worker that it has work to do:
 * either new records are in the queue, or a log replacement is taking
 * place.
 */
static int audit_worker_event;
#define    AUDIT_WORKER_EVENT	((event_t)&audit_worker_event)

/*
 * The audit worker thread (which is lazy started when we first
 * rotate the audit log.
 */
static thread_t audit_worker_thread = THREAD_NULL;

/*
 * When an audit log is rotated, the actual rotation must be performed
 * by the audit worker thread, as it may have outstanding writes on the
 * current audit log.  audit_replacement_vp holds the vnode replacing
 * the current vnode.  We can't let more than one replacement occur
 * at a time, so if more than one thread requests a replacement, only
 * one can have the replacement "in progress" at any given moment.  If
 * a thread tries to replace the audit vnode and discovers a replacement
 * is already in progress (i.e., audit_replacement_flag != 0), then it
 * will sleep on audit_replacement_cv waiting its turn to perform a
 * replacement.  When a replacement is completed, this cv is signalled
 * by the worker thread so a waiting thread can start another replacement.
 * We also store a credential to perform audit log write operations with.
 */
static int audit_replacement_event;
#define    AUDIT_REPLACEMENT_EVENT ((event_t)&audit_replacement_event)

static int				 audit_replacement_flag;
static struct vnode			*audit_replacement_vp;
static kauth_cred_t		audit_replacement_cred;

/*
 * Wait queue for auditing threads that cannot commit the audit
 * record at the present time. Also, the queue control parameter
 * structure.
 */
static int audit_commit_event;
#define    AUDIT_COMMIT_EVENT ((event_t)&audit_commit_event)

static struct au_qctrl			audit_qctrl;

/*
 * Flags to use on audit files when opening and closing.
 */
static const int		 audit_open_flags = FWRITE | O_APPEND;
static const int		 audit_close_flags = FWRITE | O_APPEND;

/*
 * Global audit statistiscs. 
 */
static struct audit_fstat 	audit_fstat;

/*
 Preselection mask for non-attributable events.
 */
static struct au_mask	 	audit_nae_mask;

/* 
 * Flags related to Kernel->user-space communication.
 */
static int			 audit_file_rotate_wait;

/*
 * Flags controlling behavior in low storage situations.
 * Should we panic if a write fails?  Should we fail stop
 * if we're out of disk space?  Are we currently "failing
 * stop" due to out of disk space?
 */
static int			 audit_panic_on_write_fail;
static int			 audit_fail_stop;
static int			 audit_in_failure;

/*
 * When in a fail-stop mode, threads will drop into this wait queue
 * rather than perform auditable events.  They won't ever get woken
 * up.
 */
static int audit_failure_event;
#define    AUDIT_FAILURE_EVENT ((event_t)&audit_failure_event)

/*
 * XXX: Couldn't find the include file for this, so copied kern_exec.c's
 * behavior.
 */
extern task_t kernel_task;

static void
audit_free(struct kaudit_record *ar)
{
	if (ar->k_ar.ar_arg_upath1 != NULL) {
		kfree(ar->k_ar.ar_arg_upath1, MAXPATHLEN);
	}
	if (ar->k_ar.ar_arg_upath2 != NULL) {
		kfree(ar->k_ar.ar_arg_upath2, MAXPATHLEN);

	}
	if (ar->k_ar.ar_arg_kpath1 != NULL) {
		kfree(ar->k_ar.ar_arg_kpath1, MAXPATHLEN);

	}
	if (ar->k_ar.ar_arg_kpath2 != NULL) {
		kfree(ar->k_ar.ar_arg_kpath2, MAXPATHLEN);

	}
	if (ar->k_ar.ar_arg_text != NULL) {
		kfree(ar->k_ar.ar_arg_text, MAXPATHLEN);

	}
	if (ar->k_udata != NULL) {
		kfree(ar->k_udata, ar->k_ulen);

	}
	zfree(audit_zone, ar);
}

static int
audit_write(struct vnode *vp, struct kaudit_record *ar, kauth_cred_t cred,
    struct proc *p)
{
	struct vfsstatfs *mnt_stat = &vp->v_mount->mnt_vfsstat;
	int ret;
	struct au_record *bsm;
	/* KVV maybe we should take a context as a param to audit_write? */
	struct vfs_context context;
	off_t file_size;

	mach_port_t audit_port;

	/* 
	 * First, gather statistics on the audit log file and file system
	 * so that we know how we're doing on space.  In both cases,
	 * if we're unable to perform the operation, we drop the record
	 * and return.  However, this is arguably an assertion failure.
	 */
	context.vc_proc = p;
	context.vc_ucred = cred;
	ret = vfs_update_vfsstat(vp->v_mount, &context);
	if (ret)
		goto out;

	/* update the global stats struct */
	if ((ret = vnode_size(vp, &file_size, &context)) != 0)
		goto out;
	audit_fstat.af_currsz = file_size;
	
	/* 
	 * Send a message to the audit daemon when disk space is getting
	 * low.
	 * XXX Need to decide what to do if the trigger to the audit daemon
	 * fails.
	 */
	if(host_get_audit_control_port(host_priv_self(), &audit_port) 
		!= KERN_SUCCESS)
		printf("Cannot get audit control port\n");

	if (audit_port != MACH_PORT_NULL) {
		uint64_t temp;

		/* 
		 * If we fall below percent free blocks, then trigger the
		 * audit daemon to do something about it.
		 */
		if (audit_qctrl.aq_minfree != 0) {
			temp = mnt_stat->f_blocks / (100 / audit_qctrl.aq_minfree);
			if (mnt_stat->f_bfree < temp) {
				ret = audit_triggers(audit_port, 
					AUDIT_TRIGGER_LOW_SPACE); 
				if (ret != KERN_SUCCESS) {
					printf(
    "Failed audit_triggers(AUDIT_TRIGGER_LOW_SPACE): %d\n", ret);
				/*
				 * XXX: What to do here? Disable auditing?
				 * panic?
				 */
				}
			}
		}
		/* Check if the current log file is full; if so, call for
		 * a log rotate. This is not an exact comparison; we may
		 * write some records over the limit. If that's not
		 * acceptable, then add a fudge factor here.
		 */
		if ((audit_fstat.af_filesz != 0) &&
		    (audit_file_rotate_wait == 0) && 
		    (file_size >= audit_fstat.af_filesz)) {
			audit_file_rotate_wait = 1;
			ret = audit_triggers(audit_port, 
				AUDIT_TRIGGER_FILE_FULL); 
			if (ret != KERN_SUCCESS) {
				printf(
    "Failed audit_triggers(AUDIT_TRIGGER_FILE_FULL): %d\n", ret);
			/* XXX what to do here? */
			}
		}
	}

	/*
	 * If the estimated amount of audit data in the audit event queue
	 * (plus records allocated but not yet queued) has reached the
	 * amount of free space on the disk, then we need to go into an
	 * audit fail stop state, in which we do not permit the
	 * allocation/committing of any new audit records.  We continue to
	 * process packets but don't allow any activities that might
	 * generate new records.  In the future, we might want to detect
	 * when space is available again and allow operation to continue,
	 * but this behavior is sufficient to meet fail stop requirements
	 * in CAPP.
	 */
	if (audit_fail_stop &&
	    (unsigned long)
	    ((audit_q_len + audit_pre_q_len + 1) * MAX_AUDIT_RECORD_SIZE) /
	    mnt_stat->f_bsize >= (unsigned long)(mnt_stat->f_bfree)) {
		printf(
    "audit_worker: free space below size of audit queue, failing stop\n");
		audit_in_failure = 1;
	}

	/* 
	 * If there is a user audit record attached to the kernel record,
	 * then write the user record.
	 */
	/* XXX Need to decide a few things here: IF the user audit 
	 * record is written, but the write of the kernel record fails,
	 * what to do? Should the kernel record come before or after the
	 * user record? For now, we write the user record first, and
	 * we ignore errors.
	 */
	if (ar->k_ar_commit & AR_COMMIT_USER) {
	        if (vnode_getwithref(vp) == 0) {
		        ret = vn_rdwr(UIO_WRITE, vp, (void *)ar->k_udata, ar->k_ulen,
				(off_t)0, UIO_SYSSPACE32, IO_APPEND|IO_UNIT, cred, NULL, p);
			vnode_put(vp);
			if (ret)
				goto out;
		} else {
			goto out;
		}
	}

	/* 
	 * Convert the internal kernel record to BSM format and write it
	 * out if everything's OK.
	 */
	if (!(ar->k_ar_commit & AR_COMMIT_KERNEL)) {
		ret = 0;
		goto out;
	}

	ret = kaudit_to_bsm(ar, &bsm);
	if (ret == BSM_NOAUDIT) {
		ret = 0;
		goto out;
	}

	/*
	 * XXX: We drop the record on BSM conversion failure, but really
	 * this is an assertion failure.
	 */
	if (ret == BSM_FAILURE) {
		AUDIT_PRINTF(("BSM conversion failure\n"));
		ret = EINVAL;
		goto out;
	}
	
	/* XXX This function can be called with the kernel funnel held,
	 * which is not optimal. We should break the write functionality
	 * away from the BSM record generation and have the BSM generation
	 * done before this function is called. This function will then
	 * take the BSM record as a parameter.
	 */
	if ((ret = vnode_getwithref(vp)) == 0) {
	        ret = (vn_rdwr(UIO_WRITE, vp, (void *)bsm->data, bsm->len,
			       (off_t)0, UIO_SYSSPACE32, IO_APPEND|IO_UNIT, cred, NULL, p));
		vnode_put(vp);
	}
	kau_free(bsm);

out:
	/*
	 * When we're done processing the current record, we have to
	 * check to see if we're in a failure mode, and if so, whether
	 * this was the last record left to be drained.  If we're done
	 * draining, then we fsync the vnode and panic.
	 */
	if (audit_in_failure &&
	    audit_q_len == 0 && audit_pre_q_len == 0) {
		(void)VNOP_FSYNC(vp, MNT_WAIT, &context);
		panic("Audit store overflow; record queue drained.");
	}

	return (ret);
}

static void
audit_worker(void)
{
	int do_replacement_signal, error, release_funnel;
	TAILQ_HEAD(, kaudit_record) ar_worklist;
	struct kaudit_record *ar;
	struct vnode *audit_vp, *old_vp;
	kauth_cred_t audit_cred;
	kauth_cred_t old_cred;
	struct proc *audit_p;

	AUDIT_PRINTF(("audit_worker starting\n"));

	TAILQ_INIT(&ar_worklist);
	audit_cred = NULL;
	audit_p = current_proc();
	audit_vp = NULL;

	/*
	 * XXX: Presumably we can assume Mach threads are started without
	 * holding the BSD kernel funnel?
	 */
	thread_funnel_set(kernel_flock, FALSE);

	mutex_lock(audit_mtx);
	while (1) {
		/*
		 * First priority: replace the audit log target if requested.
		 * As we actually close the vnode in the worker thread, we
		 * need to grab the funnel, which means releasing audit_mtx.
		 * In case another replacement was scheduled while the mutex
		 * we released, we loop.
		 *
		 * XXX It could well be we should drain existing records
		 * first to ensure that the timestamps and ordering
		 * are right.
		 */
		do_replacement_signal = 0;
		while (audit_replacement_flag != 0) {
			old_cred = audit_cred;
			old_vp = audit_vp;
			audit_cred = audit_replacement_cred;
			audit_vp = audit_replacement_vp;
			audit_replacement_cred = NULL;
			audit_replacement_vp = NULL;
			audit_replacement_flag = 0;

			audit_enabled = (audit_vp != NULL);

			if (old_vp != NULL || audit_vp != NULL) {
				mutex_unlock(audit_mtx);
				thread_funnel_set(kernel_flock, TRUE);
				release_funnel = 1;
			} else
				release_funnel = 0;
			/*
			 * XXX: What to do about write failures here?
			 */
			if (old_vp != NULL) {
				AUDIT_PRINTF(("Closing old audit file\n"));
				vn_close(old_vp, audit_close_flags, old_cred,
				    audit_p);
				kauth_cred_rele(old_cred);
				old_cred = NOCRED;
				old_vp = NULL;
				AUDIT_PRINTF(("Audit file closed\n"));
			}
			if (audit_vp != NULL) {
				AUDIT_PRINTF(("Opening new audit file\n"));
			}
			if (release_funnel) {
				thread_funnel_set(kernel_flock, FALSE);
				mutex_lock(audit_mtx);
			}
			do_replacement_signal = 1;
		}
		/*
		 * Signal that replacement have occurred to wake up and
		 * start any other replacements started in parallel.  We can
		 * continue about our business in the mean time.  We
		 * broadcast so that both new replacements can be inserted,
		 * but also so that the source(s) of replacement can return
		 * successfully.
		 */
		if (do_replacement_signal)
			wait_queue_wakeup_all(audit_wait_queue,
			    AUDIT_REPLACEMENT_EVENT, THREAD_AWAKENED);

		/*
		 * Next, check to see if we have any records to drain into
		 * the vnode.  If not, go back to waiting for an event.
		 */
		if (TAILQ_EMPTY(&audit_q)) {
			int ret;

			AUDIT_PRINTF(("audit_worker waiting\n"));
			ret = wait_queue_assert_wait(audit_wait_queue,
						     AUDIT_WORKER_EVENT,
						     THREAD_UNINT,
						     0);
			mutex_unlock(audit_mtx);

			assert(ret == THREAD_WAITING);
			ret = thread_block(THREAD_CONTINUE_NULL);
			assert(ret == THREAD_AWAKENED);
			AUDIT_PRINTF(("audit_worker woken up\n"));
	AUDIT_PRINTF(("audit_worker: new vp = %p; value of flag %d\n",
	    audit_replacement_vp, audit_replacement_flag));

			mutex_lock(audit_mtx);
			continue;
		}

		/*
		 * If we have records, but there's no active vnode to
		 * write to, drain the record queue.  Generally, we
		 * prevent the unnecessary allocation of records
		 * elsewhere, but we need to allow for races between
		 * conditional allocation and queueing.  Go back to
		 * waiting when we're done.
		 *
		 * XXX: We go out of our way to avoid calling audit_free()
		 * with the audit_mtx held, to avoid a lock order reversal
		 * as free() may grab the funnel.  This will be fixed at
		 * some point.
		 */
		if (audit_vp == NULL) {
			while ((ar = TAILQ_FIRST(&audit_q))) {
				TAILQ_REMOVE(&audit_q, ar, k_q);
				audit_q_len--;
				if (audit_q_len <= audit_qctrl.aq_lowater)
					wait_queue_wakeup_one(
						audit_wait_queue,
						AUDIT_COMMIT_EVENT, 
						THREAD_AWAKENED);

				TAILQ_INSERT_TAIL(&ar_worklist, ar, k_q);
			}
			mutex_unlock(audit_mtx);
			while ((ar = TAILQ_FIRST(&ar_worklist))) {
				TAILQ_REMOVE(&ar_worklist, ar, k_q);
				audit_free(ar);
			}
			mutex_lock(audit_mtx);
			continue;
		}

		/*
		 * We have both records to write, and an active vnode
		 * to write to.  Dequeue a record, and start the write.
		 * Eventually, it might make sense to dequeue several
		 * records and perform our own clustering, if the lower
		 * layers aren't doing it automatically enough.
		 *
		 * XXX: We go out of our way to avoid calling audit_free()
		 * with the audit_mtx held, to avoid a lock order reversal
		 * as free() may grab the funnel.  This will be fixed at
		 * some point.
		 */
		while ((ar = TAILQ_FIRST(&audit_q))) {
			TAILQ_REMOVE(&audit_q, ar, k_q);
			audit_q_len--;
			if (audit_q_len <= audit_qctrl.aq_lowater) {
				wait_queue_wakeup_one(audit_wait_queue,
					 AUDIT_COMMIT_EVENT, THREAD_AWAKENED);
			}

			TAILQ_INSERT_TAIL(&ar_worklist, ar, k_q);
		}
		mutex_unlock(audit_mtx);
		release_funnel = 0;
		while ((ar = TAILQ_FIRST(&ar_worklist))) {
			TAILQ_REMOVE(&ar_worklist, ar, k_q);
			if (audit_vp != NULL) {
				/*
				 * XXX: What should happen if there's a write
				 * error here?
				 */
				if (!release_funnel) {
					thread_funnel_set(kernel_flock, TRUE);
					release_funnel = 1;
				}
				error = audit_write(audit_vp, ar, audit_cred,
				    audit_p);
				if (error && audit_panic_on_write_fail) {
					panic("audit_worker: write error %d\n",
					    error);
				} else if (error) {
					printf("audit_worker: write error %d\n",
					    error);
			}
			}
			audit_free(ar);
		}
		if (release_funnel)
			thread_funnel_set(kernel_flock, FALSE);
		mutex_lock(audit_mtx);
	}
}

void
audit_init(void)
{

	/* Verify that the syscall to audit event table is the same
	 * size as the system call table.
	 */
	if (nsys_au_event != nsysent) {
		printf("Security auditing service initialization failed, ");
		printf("audit event table doesn't match syscall table.\n");
		return;
	}

	printf("Security auditing service present\n");
	TAILQ_INIT(&audit_q);
	audit_q_len = 0;
	audit_enabled = 0;
	audit_suspended = 0;
	audit_replacement_cred = NULL;
	audit_replacement_flag = 0;
	audit_file_rotate_wait = 0;
	audit_replacement_vp = NULL;
	audit_fstat.af_filesz = 0;	/* '0' means unset, unbounded */
	audit_fstat.af_currsz = 0; 
	audit_qctrl.aq_hiwater = AQ_HIWATER;
	audit_qctrl.aq_lowater = AQ_LOWATER;
	audit_qctrl.aq_bufsz = AQ_BUFSZ;
	audit_qctrl.aq_minfree = AU_FS_MINFREE;

	audit_mtx = mutex_alloc(0);
	audit_wait_queue = wait_queue_alloc(SYNC_POLICY_FIFO);
	audit_zone = zinit(sizeof(struct kaudit_record), 
			   AQ_HIWATER*sizeof(struct kaudit_record),
			   8192,
			   "audit_zone");

	/* Initialize the BSM audit subsystem. */
	kau_init();
}

static void
audit_rotate_vnode(kauth_cred_t cred, struct vnode *vp)
{
	int ret;

	/*
	 * If other parallel log replacements have been requested, we wait
	 * until they've finished before continuing.
	 */
	mutex_lock(audit_mtx);
	while (audit_replacement_flag != 0) {

		AUDIT_PRINTF(("audit_rotate_vnode: sleeping to wait for "
		    "flag\n"));
		ret = wait_queue_assert_wait(audit_wait_queue,
					     AUDIT_REPLACEMENT_EVENT,
					     THREAD_UNINT,
					     0);
		mutex_unlock(audit_mtx);

		assert(ret == THREAD_WAITING);
		ret = thread_block(THREAD_CONTINUE_NULL);
		assert(ret == THREAD_AWAKENED);
		AUDIT_PRINTF(("audit_rotate_vnode: woken up (flag %d)\n",
		    audit_replacement_flag));

		mutex_lock(audit_mtx);
	}
	audit_replacement_cred = cred;
	audit_replacement_flag = 1;
	audit_replacement_vp = vp;

	/*
	 * Start or wake up the audit worker to perform the exchange.
	 * It will have to wait until we release the mutex.
	 */
	if (audit_worker_thread == THREAD_NULL)
		audit_worker_thread = kernel_thread(kernel_task,
						    audit_worker);
	else 
		wait_queue_wakeup_one(audit_wait_queue,
				      AUDIT_WORKER_EVENT,
				      THREAD_AWAKENED);

	/*
	 * Wait for the audit_worker to broadcast that a replacement has
	 * taken place; we know that once this has happened, our vnode
	 * has been replaced in, so we can return successfully.
	 */
	AUDIT_PRINTF(("audit_rotate_vnode: waiting for news of "
	    "replacement\n"));
	ret = wait_queue_assert_wait(audit_wait_queue, 
				     AUDIT_REPLACEMENT_EVENT,
				     THREAD_UNINT,
				     0);
	mutex_unlock(audit_mtx);

	assert(ret == THREAD_WAITING);
	ret = thread_block(THREAD_CONTINUE_NULL);
	assert(ret == THREAD_AWAKENED);
	AUDIT_PRINTF(("audit_rotate_vnode: change acknowledged by "
	    "audit_worker (flag " "now %d)\n", audit_replacement_flag));

	audit_file_rotate_wait = 0; /* We can now request another rotation */
}

/*
 * Drain the audit queue and close the log at shutdown.
 */
void
audit_shutdown(void)
{
	audit_rotate_vnode(NULL, NULL);
}

static __inline__ struct uthread *
curuthread(void)
{
	return (get_bsdthread_info(current_thread()));
}

static __inline__ struct kaudit_record *
currecord(void)
{
	return (curuthread()->uu_ar);
}

/**********************************
 * Begin system calls.            *
 **********************************/
/*
 * System call to allow a user space application to submit a BSM audit
 * record to the kernel for inclusion in the audit log. This function
 * does little verification on the audit record that is submitted.
 *
 * XXXAUDIT: Audit preselection for user records does not currently
 * work, since we pre-select only based on the AUE_audit event type,
 * not the event type submitted as part of the user audit data.
 */
/* ARGSUSED */
int
audit(struct proc *p, struct audit_args *uap, __unused register_t *retval)
{
	int error;
	void * rec;
	struct kaudit_record *ar;
	struct uthread *uthr;

	error = suser(kauth_cred_get(), &p->p_acflag);
	if (error)
		return (error);

	if ((uap->length <= 0) || (uap->length > (int)audit_qctrl.aq_bufsz))
		return (EINVAL);

	ar = currecord();

	/* If there's no current audit record (audit() itself not audited)
	 * commit the user audit record.
	 */
	if (ar == NULL) {
		uthr = curuthread();
		if (uthr == NULL)	/* can this happen? */
		return (ENOTSUP);

		/* This is not very efficient; we're required to allocate
		 * a complete kernel audit record just so the user record
		 * can tag along.
		 */
		uthr->uu_ar = audit_new(AUE_NULL, p, uthr);
		if (uthr->uu_ar == NULL) /* auditing not on, or memory error */
			return (ENOTSUP);
		ar = uthr->uu_ar;
	}

	if (uap->length > MAX_AUDIT_RECORD_SIZE) 
		return (EINVAL);

	rec = (void *)kalloc((vm_size_t)uap->length);

	error = copyin(uap->record, rec, uap->length);
	if (error)
		goto free_out;

	/* Verify the record */
	if (bsm_rec_verify(rec) == 0) {
		error = EINVAL;
		goto free_out;
	}

	/* Attach the user audit record to the kernel audit record. Because
	 * this system call is an auditable event, we will write the user
	 * record along with the record for this audit event.
	 */
	ar->k_udata = rec;
	ar->k_ar_commit |= AR_COMMIT_USER;
	ar->k_ulen  = uap->length;
	return (0);

free_out:
	/* audit_syscall_exit() will free the audit record on the thread
	 * even if we allocated it above.
	 */
	kfree(rec, uap->length);
	return (error);
}

/*
 *  System call to manipulate auditing.
 */
/* ARGSUSED */
int
auditon(struct proc *p, __unused struct auditon_args *uap, __unused register_t *retval)
{
	int ret;
	int len;
	union auditon_udata udata;
	struct proc *tp;

	AUDIT_ARG(cmd, uap->cmd);
	ret = suser(kauth_cred_get(), &p->p_acflag);
	if (ret)
		return (ret);

	len = uap->length;
	if ((len <= 0) || (len > (int)sizeof(union auditon_udata)))
		return (EINVAL);

	memset((void *)&udata, 0, sizeof(udata));

	switch (uap->cmd) {
	/* Some of the GET commands use the arguments too */
	case A_SETPOLICY:
	case A_SETKMASK:
	case A_SETQCTRL:
	case A_SETSTAT:
	case A_SETUMASK:
	case A_SETSMASK:
	case A_SETCOND:
	case A_SETCLASS:
	case A_SETPMASK:
	case A_SETFSIZE:
	case A_SETKAUDIT:
	case A_GETCLASS:
	case A_GETPINFO:
	case A_GETPINFO_ADDR:
		ret = copyin(uap->data, (void *)&udata, uap->length);
		if (ret)
			return (ret);
		AUDIT_ARG(auditon, &udata);
		break;
}

	/* XXX Need to implement these commands by accessing the global
	 * values associated with the commands.
	 */
	switch (uap->cmd) {
	case A_GETPOLICY:
		if (!audit_fail_stop)
			udata.au_policy |= AUDIT_CNT;
		if (audit_panic_on_write_fail)
			udata.au_policy |= AUDIT_AHLT;
		break;
	case A_SETPOLICY:
		if (udata.au_policy & ~(AUDIT_CNT|AUDIT_AHLT))
			return (EINVAL);
/*
		 * XXX - Need to wake up waiters if the policy relaxes?
 */
		audit_fail_stop = ((udata.au_policy & AUDIT_CNT) == 0);
		audit_panic_on_write_fail = (udata.au_policy & AUDIT_AHLT);
		break;
	case A_GETKMASK:
		udata.au_mask = audit_nae_mask;
		break;
	case A_SETKMASK:
		audit_nae_mask = udata.au_mask;
		break;
	case A_GETQCTRL:
		udata.au_qctrl = audit_qctrl;
		break;
	case A_SETQCTRL:
		if ((udata.au_qctrl.aq_hiwater > AQ_MAXHIGH) ||
		    (udata.au_qctrl.aq_lowater >= udata.au_qctrl.aq_hiwater) ||
		    (udata.au_qctrl.aq_bufsz > AQ_MAXBUFSZ) ||
		    (udata.au_qctrl.aq_minfree < 0) ||
		    (udata.au_qctrl.aq_minfree > 100))
			return (EINVAL);

		audit_qctrl = udata.au_qctrl;
		/* XXX The queue delay value isn't used with the kernel. */
		audit_qctrl.aq_delay = -1;
		break;
	case A_GETCWD:
		return (ENOSYS);
		break;
	case A_GETCAR:
		return (ENOSYS);
		break;
	case A_GETSTAT:
		return (ENOSYS);
		break;
	case A_SETSTAT:
		return (ENOSYS);
		break;
	case A_SETUMASK:
		return (ENOSYS);
		break;
	case A_SETSMASK:
		return (ENOSYS);
		break;
	case A_GETCOND:
		if (audit_enabled && !audit_suspended)
			udata.au_cond = AUC_AUDITING;
		else
			udata.au_cond = AUC_NOAUDIT;
		break;
	case A_SETCOND:
		if (udata.au_cond == AUC_NOAUDIT) 
			audit_suspended = 1;
		if (udata.au_cond == AUC_AUDITING) 
			audit_suspended = 0;
		if (udata.au_cond == AUC_DISABLED) {
			audit_suspended = 1;
			audit_shutdown();
		}
		break;
	case A_GETCLASS:
		udata.au_evclass.ec_class = 
			au_event_class(udata.au_evclass.ec_number);
		break;
	case A_SETCLASS:
		au_evclassmap_insert(udata.au_evclass.ec_number,
					udata.au_evclass.ec_class);
		break;
	case A_GETPINFO:
		if (udata.au_aupinfo.ap_pid < 1) 
			return (EINVAL);
		if ((tp = pfind(udata.au_aupinfo.ap_pid)) == NULL)
			return (EINVAL);

		udata.au_aupinfo.ap_auid = tp->p_ucred->cr_au.ai_auid;
		udata.au_aupinfo.ap_mask.am_success = 
			tp->p_ucred->cr_au.ai_mask.am_success;
		udata.au_aupinfo.ap_mask.am_failure = 
			tp->p_ucred->cr_au.ai_mask.am_failure;
		udata.au_aupinfo.ap_termid.machine = 
			tp->p_ucred->cr_au.ai_termid.machine;
		udata.au_aupinfo.ap_termid.port = 
			tp->p_ucred->cr_au.ai_termid.port;
		udata.au_aupinfo.ap_asid = tp->p_ucred->cr_au.ai_asid;
		break;
	case A_SETPMASK:
		if (udata.au_aupinfo.ap_pid < 1) 
			return (EINVAL);
		if ((tp = pfind(udata.au_aupinfo.ap_pid)) == NULL)
			return (EINVAL);

		/*
		 * we are modifying the audit info in a credential so we need a new
		 * credential (or take another reference on an existing credential that
		 * matches our new one).  We must do this because the audit info in the 
		 * credential is used as part of our hash key.  Get current credential 
		 * in the target process and take a reference while we muck with it.
		 */
		for (;;) {
			kauth_cred_t my_cred, my_new_cred;
			struct auditinfo temp_auditinfo;
			
			my_cred = kauth_cred_proc_ref(tp);
			/* 
			 * set the credential with new info.  If there is no change we get back 
			 * the same credential we passed in.
			 */
			temp_auditinfo = my_cred->cr_au;
			temp_auditinfo.ai_mask.am_success = 
					udata.au_aupinfo.ap_mask.am_success;
			temp_auditinfo.ai_mask.am_failure = 
					udata.au_aupinfo.ap_mask.am_failure;
			my_new_cred = kauth_cred_setauditinfo(my_cred, &temp_auditinfo);
		
			if (my_cred != my_new_cred) {
				proc_lock(tp);
				/* need to protect for a race where another thread also changed
				 * the credential after we took our reference.  If p_ucred has 
				 * changed then we should restart this again with the new cred.
				 */
				if (tp->p_ucred != my_cred) {
					proc_unlock(tp);
					kauth_cred_rele(my_cred);
					kauth_cred_rele(my_new_cred);
					/* try again */
					continue;
				}
				tp->p_ucred = my_new_cred;
				proc_unlock(tp);
			}
			/* drop our extra reference */
			kauth_cred_rele(my_cred);
			break;
		}
		break;
	case A_SETFSIZE:
		if ((udata.au_fstat.af_filesz != 0) &&
		   (udata.au_fstat.af_filesz < MIN_AUDIT_FILE_SIZE))
			return (EINVAL);
		audit_fstat.af_filesz = udata.au_fstat.af_filesz;
		break;
	case A_GETFSIZE:
		udata.au_fstat.af_filesz = audit_fstat.af_filesz;
		udata.au_fstat.af_currsz = audit_fstat.af_currsz;
		break;
	case A_GETPINFO_ADDR:
		return (ENOSYS);
		break;
	case A_GETKAUDIT:
		return (ENOSYS);
		break;
	case A_SETKAUDIT:
	return (ENOSYS);
		break;
}
	/* Copy data back to userspace for the GET comands */
	switch (uap->cmd) {
	case A_GETPOLICY:
	case A_GETKMASK:
	case A_GETQCTRL:
	case A_GETCWD:
	case A_GETCAR:
	case A_GETSTAT:
	case A_GETCOND:
	case A_GETCLASS:
	case A_GETPINFO:
	case A_GETFSIZE:
	case A_GETPINFO_ADDR:
	case A_GETKAUDIT:
		ret = copyout((void *)&udata, uap->data, uap->length);
		if (ret)
			return (ret);
		break;
	}

	return (0);
}

/* 
 * System calls to manage the user audit information.
 * XXXAUDIT May need to lock the proc structure.
 */
/* ARGSUSED */
int
getauid(struct proc *p, struct getauid_args *uap, __unused register_t *retval)
{
	int error;

	error = copyout((void *)&kauth_cred_get()->cr_au.ai_auid,
			uap->auid, sizeof(au_id_t));
	if (error)
		return (error);

	return (0);
}

/* ARGSUSED */
int
setauid(struct proc *p, struct setauid_args *uap, __unused register_t *retval)
{
	int error;
	au_id_t	temp_au_id;

	error = suser(kauth_cred_get(), &p->p_acflag);
	if (error)
		return (error);

	error = copyin(uap->auid,
			(void *)&temp_au_id, 
			sizeof(au_id_t));
	if (error)
		return (error);

	/*
	 * we are modifying the audit info in a credential so we need a new
	 * credential (or take another reference on an existing credential that
	 * matches our new one).  We must do this because the audit info in the 
	 * credential is used as part of our hash key.  Get current credential 
	 * in the target process and take a reference while we muck with it.
	 */
	for (;;) {
		kauth_cred_t my_cred, my_new_cred;
		struct auditinfo temp_auditinfo;
		
		my_cred = kauth_cred_proc_ref(p);
		/* 
		 * set the credential with new info.  If there is no change we get back 
		 * the same credential we passed in.
		 */
		temp_auditinfo = my_cred->cr_au;
		temp_auditinfo.ai_auid = temp_au_id;
		my_new_cred = kauth_cred_setauditinfo(my_cred, &temp_auditinfo);
	
		if (my_cred != my_new_cred) {
			proc_lock(p);
			/* need to protect for a race where another thread also changed
			 * the credential after we took our reference.  If p_ucred has 
			 * changed then we should restart this again with the new cred.
			 */
			if (p->p_ucred != my_cred) {
				proc_unlock(p);
				kauth_cred_rele(my_cred);
				kauth_cred_rele(my_new_cred);
				/* try again */
				continue;
			}
			p->p_ucred = my_new_cred;
			proc_unlock(p);
		}
		/* drop our extra reference */
		kauth_cred_rele(my_cred);
		break;
	}

	/* propagate the change from the process to Mach task */
	set_security_token(p);

	audit_arg_auid(kauth_cred_get()->cr_au.ai_auid);
	return (0);
}

/*
 *  System calls to get and set process audit information.
 *  If the caller is privileged, they get the whole set of
 *  audit information.  Otherwise, the real audit mask is
 *  filtered out - but the rest of the information is
 *  returned.
 */
/* ARGSUSED */
int
getaudit(struct proc *p, struct getaudit_args *uap, __unused register_t *retval)
{
	struct auditinfo ai;
	int error;

	ai = kauth_cred_get()->cr_au;

	/* only superuser gets to see the real mask */
	error = suser(kauth_cred_get(), &p->p_acflag);
	if (error) {
		ai.ai_mask.am_success = ~0;
		ai.ai_mask.am_failure = ~0;
	}

	error = copyout(&ai, uap->auditinfo, sizeof(ai));
	if (error)
		return (error);

	return (0);
}

/* ARGSUSED */
int
setaudit(struct proc *p, struct setaudit_args *uap, __unused register_t *retval)
{
	int error;
	struct auditinfo temp_auditinfo;

	error = suser(kauth_cred_get(), &p->p_acflag);
	if (error)
		return (error);
		
	error = copyin(uap->auditinfo,
		       (void *)&temp_auditinfo, 
		       sizeof(temp_auditinfo));
	if (error)
		return (error);

	/*
	 * we are modifying the audit info in a credential so we need a new
	 * credential (or take another reference on an existing credential that
	 * matches our new one).  We must do this because the audit info in the 
	 * credential is used as part of our hash key.  Get current credential 
	 * in the target process and take a reference while we muck with it.
	 */
	for (;;) {
		kauth_cred_t my_cred, my_new_cred;
		
		my_cred = kauth_cred_proc_ref(p);
		/* 
		 * set the credential with new info.  If there is no change we get back 
		 * the same credential we passed in.
		 */
		my_new_cred = kauth_cred_setauditinfo(my_cred, &temp_auditinfo);
	
		if (my_cred != my_new_cred) {
			proc_lock(p);
			/* need to protect for a race where another thread also changed
			 * the credential after we took our reference.  If p_ucred has 
			 * changed then we should restart this again with the new cred.
			 */
			if (p->p_ucred != my_cred) {
				proc_unlock(p);
				kauth_cred_rele(my_cred);
				kauth_cred_rele(my_new_cred);
				/* try again */
				continue;
			}
			p->p_ucred = my_new_cred;
			proc_unlock(p);
		}
		/* drop our extra reference */
		kauth_cred_rele(my_cred);
		break;
	}

	/* propagate the change from the process to Mach task */
	set_security_token(p);

	audit_arg_auditinfo(&p->p_ucred->cr_au);

	return (0);
}

/* ARGSUSED */
int
getaudit_addr(struct proc *p, __unused struct getaudit_addr_args *uap, __unused register_t *retval)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
setaudit_addr(struct proc *p, __unused struct setaudit_addr_args *uap, __unused register_t *retval)
{
	int error;

	error = suser(kauth_cred_get(), &p->p_acflag);
	if (error)
		return (error);
	return (ENOSYS);
}

/*
 * Syscall to manage audit files.
 *
 */
/* ARGSUSED */
int
auditctl(struct proc *p, struct auditctl_args *uap, __unused register_t *retval)
{
	struct nameidata nd;
	kauth_cred_t cred;
	struct vnode *vp;
	int error, flags;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	error = suser(kauth_cred_get(), &p->p_acflag);
	if (error)
		return (error);

	vp = NULL;
	cred = NULL;

	/*
	 * If a path is specified, open the replacement vnode, perform
	 * validity checks, and grab another reference to the current
	 * credential.
	 */
	if (uap->path != 0) {
		NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1, 
			(IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32),
			uap->path, &context);
		flags = audit_open_flags;
		error = vn_open(&nd, flags, 0);
		if (error)
			goto out;
		vp = nd.ni_vp;
		if (vp->v_type != VREG) {
			vn_close(vp, audit_close_flags, kauth_cred_get(), p);
			vnode_put(vp);
			error = EINVAL;
			goto out;
		}
		cred = kauth_cred_get_with_ref();
		audit_suspended = 0;
	}
	/*
	 * a vp and cred of NULL is valid at this point
	 * and indicates we're to turn off auditing...
	 */
	audit_rotate_vnode(cred, vp);
	if (vp)
		vnode_put(vp);
out:
	return (error);
}

/**********************************
 * End of system calls.           *
 **********************************/

/*
 * MPSAFE
 */
struct kaudit_record *
audit_new(int event, struct proc *p, __unused struct uthread *uthread)
{
	struct kaudit_record *ar;
	int no_record;

	/*
	 * Eventually, there may be certain classes of events that
	 * we will audit regardless of the audit state at the time
	 * the record is created.  These events will generally
	 * correspond to changes in the audit state.  The dummy
	 * code below is from our first prototype, but may also
	 * be used in the final version (with modified event numbers).
	 */
#if 0
	if (event != AUDIT_EVENT_FILESTOP && event != AUDIT_EVENT_FILESTART) {
#endif
		mutex_lock(audit_mtx);
		no_record = (audit_suspended || !audit_enabled);
		mutex_unlock(audit_mtx);
		if (no_record)
			return (NULL);
#if 0
	}
#endif

	/*
	 * Initialize the audit record header.
	 * XXX: We may want to fail-stop if allocation fails.
	 * XXX: The number of outstanding uncommitted audit records is
	 * limited by the number of concurrent threads servicing system
	 * calls in the kernel.  
	 */

	ar = (struct kaudit_record *)zalloc(audit_zone);
	if (ar == NULL)
		return NULL;

	mutex_lock(audit_mtx);
	audit_pre_q_len++;
	mutex_unlock(audit_mtx);

	bzero(ar, sizeof(*ar));
	ar->k_ar.ar_magic = AUDIT_RECORD_MAGIC;
	ar->k_ar.ar_event = event;
	nanotime(&ar->k_ar.ar_starttime);

	/* Export the subject credential. */
	cru2x(p->p_ucred, &ar->k_ar.ar_subj_cred);
	ar->k_ar.ar_subj_ruid = p->p_ucred->cr_ruid;
	ar->k_ar.ar_subj_rgid = p->p_ucred->cr_rgid;
	ar->k_ar.ar_subj_egid = p->p_ucred->cr_groups[0];
	ar->k_ar.ar_subj_auid = p->p_ucred->cr_au.ai_auid;
	ar->k_ar.ar_subj_asid = p->p_ucred->cr_au.ai_asid;
	ar->k_ar.ar_subj_pid = p->p_pid;
	ar->k_ar.ar_subj_amask = p->p_ucred->cr_au.ai_mask;
	ar->k_ar.ar_subj_term = p->p_ucred->cr_au.ai_termid;
	bcopy(p->p_comm, ar->k_ar.ar_subj_comm, MAXCOMLEN);

	return (ar);
}

/*
 * MPSAFE
 * XXXAUDIT: So far, this is unused, and should probably be GC'd.
 */
void
audit_abort(struct kaudit_record *ar)
{
	mutex_lock(audit_mtx);
	audit_pre_q_len--;
	mutex_unlock(audit_mtx);
	audit_free(ar);
}

/*
 * MPSAFE
 */
void
audit_commit(struct kaudit_record *ar, int error, int retval)
{
	int ret;
	int sorf;
	struct au_mask *aumask;

	if (ar == NULL)
		return;

	/*
	 * Decide whether to commit the audit record by checking the
	 * error value from the system call and using the appropriate
	 * audit mask. 
	 */
	if (ar->k_ar.ar_subj_auid == AU_DEFAUDITID)
		aumask = &audit_nae_mask;
	else
		aumask = &ar->k_ar.ar_subj_amask;
	
	if (error)
		sorf = AU_PRS_FAILURE;
	else
		sorf = AU_PRS_SUCCESS;

	switch(ar->k_ar.ar_event) {

	case AUE_OPEN_RWTC:
		/* The open syscall always writes a OPEN_RWTC event; limit the
		 * to the proper type of event based on the flags and the error
		 * value.
		 */
		ar->k_ar.ar_event = flags_and_error_to_openevent(ar->k_ar.ar_arg_fflags, error);
		break;

	case AUE_SYSCTL:
		ar->k_ar.ar_event = ctlname_to_sysctlevent(ar->k_ar.ar_arg_ctlname, ar->k_ar.ar_valid_arg);
		break;

	case AUE_AUDITON:
		/* Convert the auditon() command to an event */
		ar->k_ar.ar_event = auditon_command_event(ar->k_ar.ar_arg_cmd);
		break;
	}

	if (au_preselect(ar->k_ar.ar_event, aumask, sorf) != 0)
		ar->k_ar_commit |= AR_COMMIT_KERNEL;

	if ((ar->k_ar_commit & (AR_COMMIT_USER | AR_COMMIT_KERNEL)) == 0) {
		mutex_lock(audit_mtx);
		audit_pre_q_len--;
		mutex_unlock(audit_mtx);
		audit_free(ar);
		return;
	}

	ar->k_ar.ar_errno = error;
	ar->k_ar.ar_retval = retval;

	/*
	 * We might want to do some system-wide post-filtering
	 * here at some point.
	 */

	/*
	 * Timestamp system call end.
	 */
	nanotime(&ar->k_ar.ar_endtime);

	mutex_lock(audit_mtx);
	/*
	 * Note: it could be that some records initiated while audit was
	 * enabled should still be committed?
	 */
	if (audit_suspended || !audit_enabled) {
		audit_pre_q_len--;
		mutex_unlock(audit_mtx);
		audit_free(ar);
		return;
	}

	/*
	 * Constrain the number of committed audit records based on
	 * the configurable parameter.
	 */
	while (audit_q_len >= audit_qctrl.aq_hiwater) {

		ret = wait_queue_assert_wait(audit_wait_queue,
					     AUDIT_COMMIT_EVENT,
					     THREAD_UNINT,
					     0);
		mutex_unlock(audit_mtx);

		assert(ret == THREAD_WAITING);

		ret = thread_block(THREAD_CONTINUE_NULL);
		assert(ret == THREAD_AWAKENED);
		mutex_lock(audit_mtx);
	}

	TAILQ_INSERT_TAIL(&audit_q, ar, k_q);
	audit_q_len++;
	audit_pre_q_len--;
	wait_queue_wakeup_one(audit_wait_queue, AUDIT_WORKER_EVENT, THREAD_AWAKENED);
	mutex_unlock(audit_mtx);
}

/*
 * Calls to set up and tear down audit structures associated with
 * each system call.
 */
void
audit_syscall_enter(unsigned short code, struct proc *proc, 
			struct uthread *uthread)
{
	int audit_event;
	struct au_mask *aumask;

	audit_event = sys_au_event[code];
	if (audit_event == AUE_NULL)
		return;

	assert(uthread->uu_ar == NULL);

	/* Check which audit mask to use; either the kernel non-attributable
	 * event mask or the process audit mask.
	 */
	if (proc->p_ucred->cr_au.ai_auid == AU_DEFAUDITID)
		aumask = &audit_nae_mask;
	else
		aumask = &proc->p_ucred->cr_au.ai_mask;

	/*
	 * Allocate an audit record, if preselection allows it, and store 
	 * in the BSD thread for later use.
	 */
	if (au_preselect(audit_event, aumask,
				AU_PRS_FAILURE | AU_PRS_SUCCESS)) {
		/*
		 * If we're out of space and need to suspend unprivileged
		 * processes, do that here rather than trying to allocate
		 * another audit record.
		 */
		if (audit_in_failure &&
		    suser(kauth_cred_get(), &proc->p_acflag) != 0) {
			int ret;

			assert(audit_worker_thread != THREAD_NULL);
			ret = wait_queue_assert_wait(audit_wait_queue,
			    AUDIT_FAILURE_EVENT, THREAD_UNINT, 0);
			assert(ret == THREAD_WAITING);
			(void)thread_block(THREAD_CONTINUE_NULL);
			panic("audit_failing_stop: thread continued");
		}
			uthread->uu_ar = audit_new(audit_event, proc, uthread);
		} else {
			uthread->uu_ar = NULL;
		}
	}

void
audit_syscall_exit(int error, AUDIT_PRINTF_ONLY struct proc *proc, struct uthread *uthread)
{
	int retval;

	/*
	 * Commit the audit record as desired; once we pass the record
	 * into audit_commit(), the memory is owned by the audit
	 * subsystem.
	 * The return value from the system call is stored on the user
	 * thread. If there was an error, the return value is set to -1,
	 * imitating the behavior of the cerror routine.
	 */
	if (error)
		retval = -1;
	else
		retval = uthread->uu_rval[0];

	audit_commit(uthread->uu_ar, error, retval);
	if (uthread->uu_ar != NULL) {
		AUDIT_PRINTF(("audit record committed by pid %d\n", proc->p_pid));
	}
	uthread->uu_ar = NULL;

}

/*
 * Calls to set up and tear down audit structures used during Mach 
 * system calls.
 */
void
audit_mach_syscall_enter(unsigned short audit_event)
{
	struct uthread *uthread;
	struct proc *proc;
	struct au_mask *aumask;

	if (audit_event == AUE_NULL)
		return;

	uthread = curuthread();
	if (uthread == NULL)
		return;

	proc = current_proc();
	if (proc == NULL) 
		return;

	assert(uthread->uu_ar == NULL);

	/* Check which audit mask to use; either the kernel non-attributable
	 * event mask or the process audit mask.
	 */
	if (proc->p_ucred->cr_au.ai_auid == AU_DEFAUDITID)
		aumask = &audit_nae_mask;
	else
		aumask = &proc->p_ucred->cr_au.ai_mask;
	
	/*
	 * Allocate an audit record, if desired, and store in the BSD
	 * thread for later use.
	 */
	if (au_preselect(audit_event, aumask,
			AU_PRS_FAILURE | AU_PRS_SUCCESS)) {
		uthread->uu_ar = audit_new(audit_event, proc, uthread);
	} else {
		uthread->uu_ar = NULL;
	}
}

void
audit_mach_syscall_exit(int retval, struct uthread *uthread)
{
	/* The error code from Mach system calls is the same as the
	 * return value  
	 */
	/* XXX Is the above statement always true? */
	audit_commit(uthread->uu_ar, retval, retval);
	uthread->uu_ar = NULL;

}

/*
 * Calls to manipulate elements of the audit record structure from system
 * call code.  Macro wrappers will prevent this functions from being
 * entered if auditing is disabled, avoiding the function call cost.  We
 * check the thread audit record pointer anyway, as the audit condition
 * could change, and pre-selection may not have allocated an audit
 * record for this event.
 */
void
audit_arg_addr(user_addr_t addr)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_addr = CAST_DOWN(void *, addr);  /* XXX */
	ar->k_ar.ar_valid_arg |= ARG_ADDR;
}

void
audit_arg_len(user_size_t len)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_len = CAST_DOWN(int, len);  /* XXX */
	ar->k_ar.ar_valid_arg |= ARG_LEN;
}

void
audit_arg_fd(int fd)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_fd = fd;
	ar->k_ar.ar_valid_arg |= ARG_FD;
}

void
audit_arg_fflags(int fflags)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_fflags = fflags;
	ar->k_ar.ar_valid_arg |= ARG_FFLAGS;
}

void
audit_arg_gid(gid_t gid, gid_t egid, gid_t rgid, gid_t sgid)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_gid = gid;
	ar->k_ar.ar_arg_egid = egid;
	ar->k_ar.ar_arg_rgid = rgid;
	ar->k_ar.ar_arg_sgid = sgid;
	ar->k_ar.ar_valid_arg |= (ARG_GID | ARG_EGID | ARG_RGID | ARG_SGID);
}

void
audit_arg_uid(uid_t uid, uid_t euid, uid_t ruid, uid_t suid)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_uid = uid;
	ar->k_ar.ar_arg_euid = euid;
	ar->k_ar.ar_arg_ruid = ruid;
	ar->k_ar.ar_arg_suid = suid;
	ar->k_ar.ar_valid_arg |= (ARG_UID | ARG_EUID | ARG_RUID | ARG_SUID);
}

void
audit_arg_groupset(const gid_t *gidset, u_int gidset_size)
{
	uint i;
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	for (i = 0; i < gidset_size; i++)
		ar->k_ar.ar_arg_groups.gidset[i] = gidset[i];
	ar->k_ar.ar_arg_groups.gidset_size = gidset_size;
	ar->k_ar.ar_valid_arg |= ARG_GROUPSET;
}

void
audit_arg_login(const char *login)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

#if 0
	/*
	 * XXX: Add strlcpy() to Darwin for improved safety.
	 */
	strlcpy(ar->k_ar.ar_arg_login, login, MAXLOGNAME);
#else
	strcpy(ar->k_ar.ar_arg_login, login);
#endif

	ar->k_ar.ar_valid_arg |= ARG_LOGIN;
}

void
audit_arg_ctlname(const int *name, int namelen)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	bcopy(name, &ar->k_ar.ar_arg_ctlname, namelen * sizeof(int));
	ar->k_ar.ar_arg_len = namelen;
	ar->k_ar.ar_valid_arg |= (ARG_CTLNAME | ARG_LEN);
}

void
audit_arg_mask(int mask)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_mask = mask;
	ar->k_ar.ar_valid_arg |= ARG_MASK;
}

void
audit_arg_mode(mode_t mode)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_mode = mode;
	ar->k_ar.ar_valid_arg |= ARG_MODE;
}

void
audit_arg_dev(int dev)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_dev = dev;
	ar->k_ar.ar_valid_arg |= ARG_DEV;
}

void
audit_arg_value(long value)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_value = value;
	ar->k_ar.ar_valid_arg |= ARG_VALUE;
}

void
audit_arg_owner(uid_t uid, gid_t gid)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_uid = uid;
	ar->k_ar.ar_arg_gid = gid;
	ar->k_ar.ar_valid_arg |= (ARG_UID | ARG_GID);
}

void
audit_arg_pid(pid_t pid)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_pid = pid;
	ar->k_ar.ar_valid_arg |= ARG_PID;
}

void
audit_arg_process(struct proc *p)
{
	struct kaudit_record *ar;

	ar = currecord();
	if ((ar == NULL) || (p == NULL))
		return;

	ar->k_ar.ar_arg_auid = p->p_ucred->cr_au.ai_auid;
	ar->k_ar.ar_arg_euid = p->p_ucred->cr_uid;
	ar->k_ar.ar_arg_egid = p->p_ucred->cr_groups[0];
	ar->k_ar.ar_arg_ruid = p->p_ucred->cr_ruid;
	ar->k_ar.ar_arg_rgid = p->p_ucred->cr_rgid;
	ar->k_ar.ar_arg_asid = p->p_ucred->cr_au.ai_asid;
	ar->k_ar.ar_arg_termid = p->p_ucred->cr_au.ai_termid;

	ar->k_ar.ar_valid_arg |= ARG_AUID | ARG_EUID | ARG_EGID | ARG_RUID | 
		ARG_RGID | ARG_ASID | ARG_TERMID | ARG_PROCESS;
}

void
audit_arg_signum(u_int signum)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_signum = signum;
	ar->k_ar.ar_valid_arg |= ARG_SIGNUM;
}

void
audit_arg_socket(int sodomain, int sotype, int soprotocol)
{

	struct kaudit_record *ar;
 
	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_sockinfo.so_domain = sodomain;
	ar->k_ar.ar_arg_sockinfo.so_type = sotype;
	ar->k_ar.ar_arg_sockinfo.so_protocol = soprotocol;
	ar->k_ar.ar_valid_arg |= ARG_SOCKINFO;
}

void
audit_arg_sockaddr(struct proc *p, struct sockaddr *so)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL || p == NULL || so == NULL)
		return;

	bcopy(so, &ar->k_ar.ar_arg_sockaddr, sizeof(ar->k_ar.ar_arg_sockaddr));
	switch (so->sa_family) {
	case AF_INET:
		ar->k_ar.ar_valid_arg |= ARG_SADDRINET;
		break;
	case AF_INET6:
		ar->k_ar.ar_valid_arg |= ARG_SADDRINET6;
		break;
	case AF_UNIX:
		audit_arg_upath(p, ((struct sockaddr_un *)so)->sun_path, 
				ARG_UPATH1);
		ar->k_ar.ar_valid_arg |= ARG_SADDRUNIX;
		break;
	}
}

void
audit_arg_auid(uid_t auid)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_auid = auid;
	ar->k_ar.ar_valid_arg |= ARG_AUID;
}

void
audit_arg_auditinfo(const struct auditinfo *au_info)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_auid = au_info->ai_auid;
	ar->k_ar.ar_arg_asid = au_info->ai_asid;
	ar->k_ar.ar_arg_amask.am_success = au_info->ai_mask.am_success;
	ar->k_ar.ar_arg_amask.am_failure = au_info->ai_mask.am_failure;
	ar->k_ar.ar_arg_termid.port = au_info->ai_termid.port;
	ar->k_ar.ar_arg_termid.machine = au_info->ai_termid.machine;
	ar->k_ar.ar_valid_arg |= ARG_AUID | ARG_ASID | ARG_AMASK | ARG_TERMID;
}

void
audit_arg_text(const char *text)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	/* Invalidate the text string */
	ar->k_ar.ar_valid_arg &= (ARG_ALL ^ ARG_TEXT);
	if (text == NULL)
		return;	

	if (ar->k_ar.ar_arg_text == NULL) {
		ar->k_ar.ar_arg_text = (char *)kalloc(MAXPATHLEN);
		if (ar->k_ar.ar_arg_text == NULL)
			return;	
	}

	strncpy(ar->k_ar.ar_arg_text, text, MAXPATHLEN);
	ar->k_ar.ar_valid_arg |= ARG_TEXT;
}

void
audit_arg_cmd(int cmd)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_cmd = cmd;
	ar->k_ar.ar_valid_arg |= ARG_CMD;
}

void
audit_arg_svipc_cmd(int cmd)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_svipc_cmd = cmd;
	ar->k_ar.ar_valid_arg |= ARG_SVIPC_CMD;
}

void
audit_arg_svipc_perm(const struct ipc_perm *perm)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	bcopy(perm, &ar->k_ar.ar_arg_svipc_perm, 
		sizeof(ar->k_ar.ar_arg_svipc_perm));
	ar->k_ar.ar_valid_arg |= ARG_SVIPC_PERM;
}

void
audit_arg_svipc_id(int id)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_svipc_id = id;
	ar->k_ar.ar_valid_arg |= ARG_SVIPC_ID;
}

void
audit_arg_svipc_addr(void * addr)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_svipc_addr = addr;
	ar->k_ar.ar_valid_arg |= ARG_SVIPC_ADDR;
}

void
audit_arg_posix_ipc_perm(uid_t uid, gid_t gid, mode_t mode)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_pipc_perm.pipc_uid = uid;
	ar->k_ar.ar_arg_pipc_perm.pipc_gid = gid;
	ar->k_ar.ar_arg_pipc_perm.pipc_mode = mode;
	ar->k_ar.ar_valid_arg |= ARG_POSIX_IPC_PERM;
}

void
audit_arg_auditon(const union auditon_udata *udata)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	bcopy((const void *)udata, &ar->k_ar.ar_arg_auditon, 
		sizeof(ar->k_ar.ar_arg_auditon));
	ar->k_ar.ar_valid_arg |= ARG_AUDITON;
}

/* 
 * Audit information about a file, either the file's vnode info, or its
 * socket address info.
 */
void
audit_arg_file(__unused struct proc *p, const struct fileproc *fp)
{
	struct kaudit_record *ar;
	struct socket *so;
	struct inpcb *pcb;

	if (fp->f_fglob->fg_type == DTYPE_VNODE) {
		audit_arg_vnpath_withref((struct vnode *)fp->f_fglob->fg_data, ARG_VNODE1);
		return;
	}

	if (fp->f_fglob->fg_type == DTYPE_SOCKET) {
		ar = currecord();
		if (ar == NULL)
			return;
		so = (struct socket *)fp->f_fglob->fg_data;
		if (INP_CHECK_SOCKAF(so, PF_INET)) {
			if (so->so_pcb == NULL)
				return;
			ar->k_ar.ar_arg_sockinfo.so_type =
				so->so_type;
			ar->k_ar.ar_arg_sockinfo.so_domain =
				INP_SOCKAF(so);
			ar->k_ar.ar_arg_sockinfo.so_protocol =
				so->so_proto->pr_protocol;
			pcb = (struct inpcb *)so->so_pcb;
			ar->k_ar.ar_arg_sockinfo.so_raddr =
				pcb->inp_faddr.s_addr;
			ar->k_ar.ar_arg_sockinfo.so_laddr =
				pcb->inp_laddr.s_addr;
			ar->k_ar.ar_arg_sockinfo.so_rport =
				pcb->inp_fport;
			ar->k_ar.ar_arg_sockinfo.so_lport =
				pcb->inp_lport;
			ar->k_ar.ar_valid_arg |= ARG_SOCKINFO;
		}
	}

}


/* 
 * Store a path as given by the user process for auditing into the audit 
 * record stored on the user thread. This function will allocate the memory to 
 * store the path info if not already available. This memory will be 
 * freed when the audit record is freed.
 */
void
audit_arg_upath(struct proc *p, char *upath, u_int64_t flags)
{
	struct kaudit_record *ar;
	char **pathp;

	if (p == NULL || upath == NULL) 
		return;		/* nothing to do! */

	if ((flags & (ARG_UPATH1 | ARG_UPATH2)) == 0)
		return;

	ar = currecord();
	if (ar == NULL)	/* This will be the case for unaudited system calls */
		return;

	if (flags & ARG_UPATH1) {
		ar->k_ar.ar_valid_arg &= (ARG_ALL ^ ARG_UPATH1);
		pathp = &ar->k_ar.ar_arg_upath1;
	}
	else {
		ar->k_ar.ar_valid_arg &= (ARG_ALL ^ ARG_UPATH2);
		pathp = &ar->k_ar.ar_arg_upath2;
	}

	if (*pathp == NULL) {
		*pathp = (char *)kalloc(MAXPATHLEN);
		if (*pathp == NULL)
			return;
	}

	if (canon_path(p, upath, *pathp) == 0) {
		if (flags & ARG_UPATH1)
			ar->k_ar.ar_valid_arg |= ARG_UPATH1;
		else
			ar->k_ar.ar_valid_arg |= ARG_UPATH2;
		} else {
			kfree(*pathp, MAXPATHLEN);
			*pathp = NULL;
	}
}

/*
 * Function to save the path and vnode attr information into the audit 
 * record. 
 *
 * It is assumed that the caller will hold any vnode locks necessary to
 * perform a VNOP_GETATTR() on the passed vnode.
 *
 * XXX: The attr code is very similar to vfs_vnops.c:vn_stat(), but
 * always provides access to the generation number as we need that
 * to construct the BSM file ID.
 * XXX: We should accept the process argument from the caller, since
 * it's very likely they already have a reference.
 * XXX: Error handling in this function is poor.
 */
void
audit_arg_vnpath(struct vnode *vp, u_int64_t flags)
{
	struct kaudit_record *ar;
	struct vnode_attr va;
	int error;
	int len;
	char **pathp;
	struct vnode_au_info *vnp;
	struct proc *p;
	struct vfs_context context;

	if (vp == NULL)
		return;

	ar = currecord();
	if (ar == NULL)	/* This will be the case for unaudited system calls */
		return;

	if ((flags & (ARG_VNODE1 | ARG_VNODE2)) == 0)
		return;

	p = current_proc();

	if (flags & ARG_VNODE1) {
		ar->k_ar.ar_valid_arg &= (ARG_ALL ^ ARG_KPATH1);
		ar->k_ar.ar_valid_arg &= (ARG_ALL ^ ARG_VNODE1);
		pathp = &ar->k_ar.ar_arg_kpath1;
		vnp = &ar->k_ar.ar_arg_vnode1;
	}
	else {
		ar->k_ar.ar_valid_arg &= (ARG_ALL ^ ARG_KPATH2);
		ar->k_ar.ar_valid_arg &= (ARG_ALL ^ ARG_VNODE2);
		pathp = &ar->k_ar.ar_arg_kpath2;
		vnp = &ar->k_ar.ar_arg_vnode2;
	}

	if (*pathp == NULL) {
		*pathp = (char *)kalloc(MAXPATHLEN);
		if (*pathp == NULL)
			return;
	}

	/*
	 * If vn_getpath() succeeds, place it in a string buffer
	 * attached to the audit record, and set a flag indicating
	 * it is present.
	 */
	len = MAXPATHLEN;
	if (vn_getpath(vp, *pathp, &len) == 0) {
	if (flags & ARG_VNODE1)
		ar->k_ar.ar_valid_arg |= ARG_KPATH1;
	else
		ar->k_ar.ar_valid_arg |= ARG_KPATH2;
	} else {
		kfree(*pathp, MAXPATHLEN);
		*pathp = NULL;
	}

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_mode);
	VATTR_WANTED(&va, va_uid);
	VATTR_WANTED(&va, va_gid);
	VATTR_WANTED(&va, va_rdev);
	VATTR_WANTED(&va, va_fsid);
	VATTR_WANTED(&va, va_fileid);
	VATTR_WANTED(&va, va_gen);
	error = vnode_getattr(vp, &va, &context);
	if (error) {
		/* XXX: How to handle this case? */
		return;
	}

	/* XXX do we want to fall back here when these aren't supported? */
	vnp->vn_mode = va.va_mode;
	vnp->vn_uid = va.va_uid;
	vnp->vn_gid = va.va_gid;
	vnp->vn_dev = va.va_rdev;
	vnp->vn_fsid = va.va_fsid;
	vnp->vn_fileid = (u_long)va.va_fileid;
	vnp->vn_gen = va.va_gen;
	if (flags & ARG_VNODE1)
		ar->k_ar.ar_valid_arg |= ARG_VNODE1;
	else
		ar->k_ar.ar_valid_arg |= ARG_VNODE2;

}

void
audit_arg_vnpath_withref(struct vnode *vp, u_int64_t flags)
{
	if (vp == NULL || vnode_getwithref(vp))
		return;
	audit_arg_vnpath(vp, flags);
	(void)vnode_put(vp);
}

void
audit_arg_mach_port1(mach_port_name_t port)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_mach_port1 = port;
	ar->k_ar.ar_valid_arg |= ARG_MACHPORT1;
}

void
audit_arg_mach_port2(mach_port_name_t port)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_mach_port2 = port;
	ar->k_ar.ar_valid_arg |= ARG_MACHPORT2;
}

/*
 * The close() system call uses it's own audit call to capture the 
 * path/vnode information because those pieces are not easily obtained
 * within the system call itself.
 */
void
audit_sysclose(struct proc *p, int fd)
{
	struct fileproc *fp;
	struct vnode *vp;

	audit_arg_fd(fd);

	if (fp_getfvp(p, fd, &fp, &vp) != 0)
		return;

	audit_arg_vnpath_withref((struct vnode *)fp->f_fglob->fg_data, ARG_VNODE1);
	file_drop(fd);
} 

#else /* !AUDIT */

void
audit_init(void)
{

}

void
audit_shutdown(void)
{

}

int
audit(struct proc *p, struct audit_args *uap, register_t *retval)
{
	return (ENOSYS);
}

int
auditon(struct proc *p, struct auditon_args *uap, register_t *retval)
{
	return (ENOSYS);
}

int
getauid(struct proc *p, struct getauid_args *uap, register_t *retval)
{
	return (ENOSYS);
}

int
setauid(struct proc *p, struct setauid_args *uap, register_t *retval)
{
	return (ENOSYS);
}

int
getaudit(struct proc *p, struct getaudit_args *uap, register_t *retval)
{
	return (ENOSYS);
}

int
setaudit(struct proc *p, struct setaudit_args *uap, register_t *retval)
{
	return (ENOSYS);
}

int
getaudit_addr(struct proc *p, struct getaudit_addr_args *uap, register_t *retval)
{
	return (ENOSYS);
}

int
setaudit_addr(struct proc *p, struct setaudit_addr_args *uap, register_t *retval)
{
	return (ENOSYS);
}

int
auditctl(struct proc *p, struct auditctl_args *uap, register_t *retval)
{
	return (ENOSYS);
}

#endif /* AUDIT */
