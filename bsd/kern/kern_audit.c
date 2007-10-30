/*
 * Copyright (c) 2003-2007 Apple Inc. All rights reserved.
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
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
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

#if CONFIG_MACF
#include <bsm/audit_record.h>
#include <security/mac.h>
#include <security/mac_framework.h>
#include <security/mac_policy.h>
#define MAC_ARG_PREFIX "arg: "
#define MAC_ARG_PREFIX_LEN 5
#endif

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>

#if AUDIT

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
    ((void) ((cond) ? 0 : panic("Assert failed: %s", # cond)))
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
static lck_grp_t			*audit_grp;
static lck_attr_t			*audit_attr;
static lck_grp_attr_t			*audit_grp_attr;
static lck_mtx_t			*audit_mtx;

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
#if CONFIG_MACF
static zone_t				audit_mac_label_zone;
#endif

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

extern zone_t mac_audit_data_zone;
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

#if CONFIG_MACF
	if (ar->k_ar.ar_vnode1_mac_labels != NULL) {
		zfree(audit_mac_label_zone, ar->k_ar.ar_vnode1_mac_labels);
	}
	if (ar->k_ar.ar_vnode2_mac_labels != NULL) {
		zfree(audit_mac_label_zone, ar->k_ar.ar_vnode2_mac_labels);
	}
	if (ar->k_ar.ar_cred_mac_labels != NULL) {
		zfree(audit_mac_label_zone, ar->k_ar.ar_cred_mac_labels);
	}
	if (ar->k_ar.ar_arg_mac_string != NULL) {
		kfree(ar->k_ar.ar_arg_mac_string,
		    MAC_MAX_LABEL_BUF_LEN + MAC_ARG_PREFIX_LEN);
	}

	/* Free the audit data from the MAC policies. */
	do {
		struct mac_audit_record *head, *next;

		head = LIST_FIRST(ar->k_ar.ar_mac_records);
		while (head != NULL) {
			next = LIST_NEXT(head, records);
			zfree(mac_audit_data_zone, head->data);
			kfree(head, sizeof(*head));
			head = next;
		}

		kfree(ar->k_ar.ar_mac_records,
		    sizeof(*ar->k_ar.ar_mac_records));
	} while (0);
#endif

	zfree(audit_zone, ar);
}

/*
 * Converts an audit record into the BSM format before writing out to the 
 * audit logfile. Will perform it's own vnode iocounting.
 *
 * Returns: 
 *	-1 if it could not get an ioreference on the vnode.
 *	EINVAL if the kaudit_record ar is not a valid audit record.
 */
static int
audit_write(struct vnode *vp, struct kaudit_record *ar, vfs_context_t ctx)
{
	struct vfsstatfs *mnt_stat = &vp->v_mount->mnt_vfsstat;
	int ret = 0;
	struct au_record *bsm;
	off_t file_size;

	mach_port_t audit_port;

	if (vnode_getwithref(vp))
		return ENOENT;

	/* 
	 * First, gather statistics on the audit log file and file system
	 * so that we know how we're doing on space.  In both cases,
	 * if we're unable to perform the operation, we drop the record
	 * and return.  However, this is arguably an assertion failure.
	 */
	ret = vfs_update_vfsstat(vp->v_mount, ctx, VFS_KERNEL_EVENT);
	if (ret)
		goto out;

	/* update the global stats struct */
	if ((ret = vnode_size(vp, &file_size, ctx)) != 0)
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
		    (file_size >= (off_t)audit_fstat.af_filesz)) {
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
		ret = vn_rdwr(UIO_WRITE, vp, (void *)ar->k_udata, ar->k_ulen,
			(off_t)0, UIO_SYSSPACE32, IO_APPEND|IO_UNIT, vfs_context_ucred(ctx), NULL, vfs_context_proc(ctx));
		if (ret)
			goto out;
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
	
	/* XXX:  We should break the write functionality
	 * away from the BSM record generation and have the BSM generation
	 * done before this function is called. This function will then
	 * take the BSM record as a parameter.
	 */
	ret = (vn_rdwr(UIO_WRITE, vp, (void *)bsm->data, bsm->len,
		       (off_t)0, UIO_SYSSPACE32, IO_APPEND|IO_UNIT, vfs_context_ucred(ctx), NULL, vfs_context_proc(ctx)));
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
		(void)VNOP_FSYNC(vp, MNT_WAIT, ctx);
		panic("Audit store overflow; record queue drained.");
	}

	vnode_put(vp);
	return (ret);
}

static void
audit_worker(void)
{
	int do_replacement_signal, error;
	TAILQ_HEAD(, kaudit_record) ar_worklist;
	struct kaudit_record *ar;
	struct vnode *audit_vp, *old_vp;
	kauth_cred_t audit_cred;
	proc_t audit_p;

	AUDIT_PRINTF(("audit_worker starting\n"));

	TAILQ_INIT(&ar_worklist);
	audit_cred = NOCRED;
	audit_p = current_proc();
	audit_vp = NULL;


	lck_mtx_lock(audit_mtx);
	while (1) {
		struct vfs_context context;

		/*
		 * First priority: replace the audit log target if requested.
		 *
		 * XXX It could well be we should drain existing records
		 * first to ensure that the timestamps and ordering
		 * are right.
		 */
		do_replacement_signal = 0;
		while (audit_replacement_flag != 0) {
			kauth_cred_t old_cred = audit_cred;

			old_vp = audit_vp;
			audit_cred = audit_replacement_cred;
			audit_vp = audit_replacement_vp;
			audit_replacement_cred = NOCRED;
			audit_replacement_vp = NULL;
			audit_replacement_flag = 0;

			audit_enabled = (audit_vp != NULL);

			/*
			 * XXX: What to do about write failures here?
			 */
			if (old_vp != NULL) {
				AUDIT_PRINTF(("Closing old audit file vnode %p\n", old_vp));
				if (vnode_get(old_vp) == 0) {
					vn_close(old_vp, audit_close_flags, vfs_context_kernel());
					vnode_put(old_vp); 
					AUDIT_PRINTF(("Audit file closed\n"));
				}
				else
					printf("audit_worker(): Couldn't close audit file.\n");
				kauth_cred_unref(&old_cred);
				old_vp = NULL;
			}
			if (audit_vp != NULL) {
				AUDIT_PRINTF(("Opening new audit file\n"));
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
			lck_mtx_unlock(audit_mtx);

			assert(ret == THREAD_WAITING);
			ret = thread_block(THREAD_CONTINUE_NULL);
			assert(ret == THREAD_AWAKENED);
			AUDIT_PRINTF(("audit_worker woken up\n"));
	AUDIT_PRINTF(("audit_worker: new vp = %p; value of flag %d\n",
	    audit_replacement_vp, audit_replacement_flag));

			lck_mtx_lock(audit_mtx);
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
			lck_mtx_unlock(audit_mtx);
			while ((ar = TAILQ_FIRST(&ar_worklist))) {
				TAILQ_REMOVE(&ar_worklist, ar, k_q);
				audit_free(ar);
			}
			lck_mtx_lock(audit_mtx);
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
		lck_mtx_unlock(audit_mtx);
		context.vc_thread = current_thread();
		context.vc_ucred = audit_cred;
		while ((ar = TAILQ_FIRST(&ar_worklist))) {
			TAILQ_REMOVE(&ar_worklist, ar, k_q);
			if (audit_vp != NULL) {
				/*
				 * XXX: What should happen if there's a write
				 * error here?
				 */
				error = audit_write(audit_vp, ar, &context);
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
		lck_mtx_lock(audit_mtx);
	}
}

void
audit_init(void)
{
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

	audit_grp_attr = lck_grp_attr_alloc_init();
	audit_grp = lck_grp_alloc_init("audit", audit_grp_attr);
	audit_attr = lck_attr_alloc_init();
	audit_mtx = lck_mtx_alloc_init(audit_grp, audit_attr);

	audit_wait_queue = wait_queue_alloc(SYNC_POLICY_FIFO);
	audit_zone = zinit(sizeof(struct kaudit_record), 
			   AQ_HIWATER*sizeof(struct kaudit_record),
			   8192,
			   "audit_zone");
#if CONFIG_MACF
	/* Assume 3 MAC labels for each audit record: two for vnodes,
	 * one for creds.
	 */
	audit_mac_label_zone = zinit(MAC_AUDIT_LABEL_LEN,
				     AQ_HIWATER * 3*MAC_AUDIT_LABEL_LEN,
				     8192,
				     "audit_mac_label_zone");
#endif

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
	lck_mtx_lock(audit_mtx);
	while (audit_replacement_flag != 0) {

		AUDIT_PRINTF(("audit_rotate_vnode: sleeping to wait for "
		    "flag\n"));
		ret = wait_queue_assert_wait(audit_wait_queue,
					     AUDIT_REPLACEMENT_EVENT,
					     THREAD_UNINT,
					     0);
		lck_mtx_unlock(audit_mtx);

		assert(ret == THREAD_WAITING);
		ret = thread_block(THREAD_CONTINUE_NULL);
		assert(ret == THREAD_AWAKENED);
		AUDIT_PRINTF(("audit_rotate_vnode: woken up (flag %d)\n",
		    audit_replacement_flag));

		lck_mtx_lock(audit_mtx);
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
	lck_mtx_unlock(audit_mtx);

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
	if (audit_mtx)
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
audit(proc_t p, struct audit_args *uap, __unused register_t *retval)
{
	int error;
	void * rec;
	struct kaudit_record *ar;
	struct uthread *uthr;

	error = suser(kauth_cred_get(), &p->p_acflag);
	if (error)
		return (error);

	lck_mtx_lock(audit_mtx);
	if ((uap->length <= 0) || (uap->length > (int)audit_qctrl.aq_bufsz)) {
		lck_mtx_unlock(audit_mtx);
		return (EINVAL);
	}
	lck_mtx_unlock(audit_mtx);

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

#if CONFIG_MACF
	error = mac_system_check_audit(kauth_cred_get(), rec, uap->length);
	if (error)
		goto free_out;
#endif

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
auditon(proc_t p, struct auditon_args *uap, __unused register_t *retval)
{
	int ret;
	int len;
	union auditon_udata udata;
	proc_t tp = PROC_NULL;
	kauth_cred_t my_cred;

	AUDIT_ARG(cmd, uap->cmd);
	ret = suser(kauth_cred_get(), &p->p_acflag);
	if (ret)
		return (ret);

#if CONFIG_MACF
	ret = mac_system_check_auditon(kauth_cred_get(), uap->cmd);
	if (ret)
		return (ret);
#endif

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
	lck_mtx_lock(audit_mtx);
	switch (uap->cmd) {
	case A_GETPOLICY:
		if (!audit_fail_stop)
			udata.au_policy |= AUDIT_CNT;
		if (audit_panic_on_write_fail)
			udata.au_policy |= AUDIT_AHLT;
		break;
	case A_SETPOLICY:
		if (udata.au_policy & ~(AUDIT_CNT|AUDIT_AHLT)) {
			ret = EINVAL;
			break;
		}
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
		    (udata.au_qctrl.aq_minfree > 100)) {
			ret = EINVAL;
			break;
		}

		audit_qctrl = udata.au_qctrl;
		/* XXX The queue delay value isn't used with the kernel. */
		audit_qctrl.aq_delay = -1;
		break;
	case A_GETCWD:
		ret = ENOSYS;
		break;
	case A_GETCAR:
		ret = ENOSYS;
		break;
	case A_GETSTAT:
		ret = ENOSYS;
		break;
	case A_SETSTAT:
		ret = ENOSYS;
		break;
	case A_SETUMASK:
		ret = ENOSYS;
		break;
	case A_SETSMASK:
		ret = ENOSYS;
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
		if (udata.au_aupinfo.ap_pid < 1) { 
			ret = EINVAL;
			break;
		}
		if ((tp = proc_find(udata.au_aupinfo.ap_pid)) == NULL) {
			ret = EINVAL;
			break;
		}

		lck_mtx_unlock(audit_mtx);
		my_cred = kauth_cred_proc_ref(tp);

		udata.au_aupinfo.ap_auid = my_cred->cr_au.ai_auid;
		udata.au_aupinfo.ap_mask.am_success = 
			my_cred->cr_au.ai_mask.am_success;
		udata.au_aupinfo.ap_mask.am_failure = 
			my_cred->cr_au.ai_mask.am_failure;
		udata.au_aupinfo.ap_termid.machine = 
			my_cred->cr_au.ai_termid.machine;
		udata.au_aupinfo.ap_termid.port = 
			my_cred->cr_au.ai_termid.port;
		udata.au_aupinfo.ap_asid = my_cred->cr_au.ai_asid;

		kauth_cred_unref(&my_cred);

		proc_rele(tp);
		tp = PROC_NULL;
		lck_mtx_lock(audit_mtx);
		break;
	case A_SETPMASK:
		if (udata.au_aupinfo.ap_pid < 1) { 
			ret = EINVAL;
			break;
		}
		if ((tp = proc_find(udata.au_aupinfo.ap_pid)) == NULL) {
			ret = EINVAL;
			break;
		}

		/*
		 * we are modifying the audit info in a credential so we need a new
		 * credential (or take another reference on an existing credential that
		 * matches our new one).  We must do this because the audit info in the 
		 * credential is used as part of our hash key.  Get current credential 
		 * in the target process and take a reference while we muck with it.
		 */
		lck_mtx_unlock(audit_mtx);
		for (;;) {
			kauth_cred_t my_new_cred;
			struct auditinfo temp_auditinfo;
			
			my_cred = kauth_cred_proc_ref(tp);
			/* 
			 * Set the credential with new info.  If there is no
			 * change, we get back the same credential we passed
			 * in; if there is a change, we drop the reference on
			 * the credential we passed in.  The subsequent
			 * compare is safe, because it is a pointer compare
			 * rather than a contents compare.
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
					kauth_cred_unref(&my_new_cred);
					/* try again */
					continue;
				}
				tp->p_ucred = my_new_cred;
				proc_unlock(tp);
			}
			/* drop old proc reference or our extra reference */
			kauth_cred_unref(&my_cred);
			break;
		}
		proc_rele(tp);
		lck_mtx_lock(audit_mtx);
		break;
	case A_SETFSIZE:
		if ((udata.au_fstat.af_filesz != 0) &&
		   (udata.au_fstat.af_filesz < MIN_AUDIT_FILE_SIZE)) {
			ret = EINVAL;
			break;
		}
		audit_fstat.af_filesz = udata.au_fstat.af_filesz;
		break;
	case A_GETFSIZE:
		udata.au_fstat.af_filesz = audit_fstat.af_filesz;
		udata.au_fstat.af_currsz = audit_fstat.af_currsz;
		break;
	case A_GETPINFO_ADDR:
		ret = ENOSYS;
		break;
	case A_GETKAUDIT:
		ret = ENOSYS;
		break;
	case A_SETKAUDIT:
		ret = ENOSYS;
		break;
	}
	/* Copy data back to userspace for the GET comands */
	if (ret == 0) {
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
			break;
		}
	}

	lck_mtx_unlock(audit_mtx);
	return (ret);
}

/* 
 * System calls to manage the user audit information.
 */
/* ARGSUSED */
int
getauid(__unused proc_t p, struct getauid_args *uap, __unused register_t *retval)
{
	int error;

#if CONFIG_MACF
	error = mac_proc_check_getauid(p);
	if (error)
		return (error);
#endif

	error = copyout((void *)&kauth_cred_get()->cr_au.ai_auid,
			uap->auid, sizeof(au_id_t));
	if (error)
		return (error);

	return (0);
}

/* ARGSUSED */
int
setauid(proc_t p, struct setauid_args *uap, __unused register_t *retval)
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
#if CONFIG_MACF
	error = mac_proc_check_setauid(p, temp_au_id);
	if (error)
		return (error);
#endif

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
		 * Set the credential with new info.  If there is no change,
		 * we get back the same credential we passed in; if there is
		 * a change, we drop the reference on the credential we
		 * passed in.  The subsequent compare is safe, because it is
		 * a pointer compare rather than a contents compare.
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
				kauth_cred_unref(&my_new_cred);
				/* try again */
				continue;
			}
			p->p_ucred = my_new_cred;
			proc_unlock(p);
		}
		/* drop old proc reference or our extra reference */
		kauth_cred_unref(&my_cred);
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
getaudit(proc_t p, struct getaudit_args *uap, __unused register_t *retval)
{
	struct auditinfo ai;
	int error;

#if CONFIG_MACF
	error = mac_proc_check_getaudit(p);
	if (error)
		return (error);
#endif

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
setaudit(proc_t p, struct setaudit_args *uap, __unused register_t *retval)
{
	int error;
	struct auditinfo temp_auditinfo;
	kauth_cred_t safecred;

	error = suser(kauth_cred_get(), &p->p_acflag);
	if (error)
		return (error);
	error = copyin(uap->auditinfo,
		       (void *)&temp_auditinfo, 
		       sizeof(temp_auditinfo));
	if (error)
		return (error);
#if CONFIG_MACF
	error = mac_proc_check_setaudit(p, &temp_auditinfo);
	if (error)
		return (error); 

#endif


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
		 * Set the credential with new info.  If there is no change,
		 * we get back the same credential we passed in; if there is
		 * a change, we drop the reference on the credential we
		 * passed in.  The subsequent compare is safe, because it is
		 * a pointer compare rather than a contents compare.
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
				kauth_cred_unref(&my_new_cred);
				/* try again */
				continue;
			}
			p->p_ucred = my_new_cred;
			proc_unlock(p);
		}
		/* drop old proc reference or our extra reference */
		kauth_cred_unref(&my_cred);
		break;
	}

	/* propagate the change from the process to Mach task */
	set_security_token(p);

	safecred = kauth_cred_proc_ref(p);
	audit_arg_auditinfo(&safecred->cr_au);
	kauth_cred_unref(&safecred);

	return (0);
}

/* ARGSUSED */
int
getaudit_addr(__unused proc_t p, __unused struct getaudit_addr_args *uap, __unused register_t *retval)
{
	return (ENOSYS);
}

/* ARGSUSED */
int
setaudit_addr(proc_t p, __unused struct setaudit_addr_args *uap, __unused register_t *retval)
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
auditctl(proc_t p, struct auditctl_args *uap, __unused register_t *retval)
{
	struct nameidata nd;
	kauth_cred_t cred;
	struct vnode *vp;
	int error;

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
	if (uap->path != USER_ADDR_NULL) {
		NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1, 
			(IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32),
			uap->path, vfs_context_current());
		error = vn_open(&nd, audit_open_flags, 0);
		if (error)
			goto out;
		vp = nd.ni_vp;

		if (vp->v_type != VREG) {
			vn_close(vp, audit_close_flags, vfs_context_current());
			vnode_put(vp);
			error = EINVAL;
			goto out;
		}
#if CONFIG_MACF
		/*
		 * Accessibility of the vnode was determined in
		 * vn_open; the mac_system_check_auditctl should only
		 * determine whether that vnode is appropriate for
		 * storing audit data, or that the caller was
		 * permitted to control the auditing system at all.
		 * For example, a confidentiality policy may want to
		 * ensure that audit files are always high
		 * sensitivity.
		 */

		error = mac_system_check_auditctl(kauth_cred_get(), vp);
		if (error) {
			vn_close(vp, audit_close_flags, vfs_context_current());
			vnode_put(vp);
			goto out;
		}
#endif
		cred = kauth_cred_get_with_ref();
		lck_mtx_lock(audit_mtx);
		audit_suspended = 0;
		lck_mtx_unlock(audit_mtx);
	}
#if CONFIG_MACF
	else {
		error = mac_system_check_auditctl(kauth_cred_get(), NULL);
		if (error)
			return (error);
	}
#endif
	
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
audit_new(int event, proc_t p, __unused struct uthread *uthread)
{
	struct kaudit_record *ar;
	int no_record;
	kauth_cred_t safecred;

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
		lck_mtx_lock(audit_mtx);
		no_record = (audit_suspended || !audit_enabled);
		lck_mtx_unlock(audit_mtx);
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

	bzero(ar, sizeof(*ar));
	ar->k_ar.ar_magic = AUDIT_RECORD_MAGIC;
	ar->k_ar.ar_event = event;
	nanotime(&ar->k_ar.ar_starttime);

	safecred = kauth_cred_proc_ref(p);
	/* Export the subject credential. */
	cru2x(safecred, &ar->k_ar.ar_subj_cred);

	ar->k_ar.ar_subj_ruid = safecred->cr_ruid;
	ar->k_ar.ar_subj_rgid = safecred->cr_rgid;
	ar->k_ar.ar_subj_egid = safecred->cr_groups[0];
	ar->k_ar.ar_subj_auid = safecred->cr_au.ai_auid;
	ar->k_ar.ar_subj_asid = safecred->cr_au.ai_asid;
	ar->k_ar.ar_subj_amask = safecred->cr_au.ai_mask;
	ar->k_ar.ar_subj_term = safecred->cr_au.ai_termid;
	kauth_cred_unref(&safecred);

	ar->k_ar.ar_subj_pid = p->p_pid;
	bcopy(p->p_comm, ar->k_ar.ar_subj_comm, MAXCOMLEN);

#if CONFIG_MACF
	do {
		struct mac mac;

		/* Retrieve the MAC labels for the process. */
		ar->k_ar.ar_cred_mac_labels =
		    (char *)zalloc(audit_mac_label_zone);
		if (ar->k_ar.ar_cred_mac_labels == NULL) {
			zfree(audit_zone, ar);
			return (NULL);
		}
		mac.m_buflen = MAC_AUDIT_LABEL_LEN;
		mac.m_string = ar->k_ar.ar_cred_mac_labels;
		mac_cred_label_externalize_audit(p, &mac);

		/*
		 * grab space for the reconds.
		 */
		ar->k_ar.ar_mac_records = (struct mac_audit_record_list_t *)
		    kalloc(sizeof(*ar->k_ar.ar_mac_records));
               if (ar->k_ar.ar_mac_records == NULL) {
                       zfree(audit_mac_label_zone,
			     ar->k_ar.ar_cred_mac_labels);
                       zfree(audit_zone, ar);
                       return (NULL);
               }

		LIST_INIT(ar->k_ar.ar_mac_records);

		ar->k_ar.ar_forced_by_mac = 0;

	} while (0);
#endif

	lck_mtx_lock(audit_mtx);
	audit_pre_q_len++;
	lck_mtx_unlock(audit_mtx);

	return (ar);
}

/*
 * MPSAFE
 * XXXAUDIT: So far, this is unused, and should probably be GC'd.
 */
void
audit_abort(struct kaudit_record *ar)
{
	lck_mtx_lock(audit_mtx);
	audit_pre_q_len--;
	lck_mtx_unlock(audit_mtx);
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
		lck_mtx_lock(audit_mtx);
		audit_pre_q_len--;
		lck_mtx_unlock(audit_mtx);
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

	lck_mtx_lock(audit_mtx);
	/*
	 * Note: it could be that some records initiated while audit was
	 * enabled should still be committed?
	 */
	if (audit_suspended || !audit_enabled) {
		audit_pre_q_len--;
		lck_mtx_unlock(audit_mtx);
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
		lck_mtx_unlock(audit_mtx);

		assert(ret == THREAD_WAITING);

		ret = thread_block(THREAD_CONTINUE_NULL);
		assert(ret == THREAD_AWAKENED);
		lck_mtx_lock(audit_mtx);
	}

	TAILQ_INSERT_TAIL(&audit_q, ar, k_q);
	audit_q_len++;
	audit_pre_q_len--;
	wait_queue_wakeup_one(audit_wait_queue, AUDIT_WORKER_EVENT, THREAD_AWAKENED);
	lck_mtx_unlock(audit_mtx);
}

/*
 * If we're out of space and need to suspend unprivileged
 * processes, do that here rather than trying to allocate
 * another audit record.
 */
static void
audit_new_wait(int audit_event, proc_t proc, struct uthread *uthread)
{
	int ret;

	if (audit_in_failure &&
	    suser(kauth_cred_get(), &proc->p_acflag) != 0) {
		ret = wait_queue_assert_wait(audit_wait_queue,
		    AUDIT_FAILURE_EVENT, THREAD_UNINT, 0);
		assert(ret == THREAD_WAITING);
		(void)thread_block(THREAD_CONTINUE_NULL);
		panic("audit_failing_stop: thread continued");
	}
	uthread->uu_ar = audit_new(audit_event, proc, uthread);
}

/*
 * Calls to set up and tear down audit structures associated with
 * each system call.
 */
void
audit_syscall_enter(unsigned short code, proc_t proc, 
			struct uthread *uthread)
{
	int audit_event;
	struct au_mask *aumask;
	kauth_cred_t my_cred;

	audit_event = sys_au_event[code];
	if (audit_event == AUE_NULL)
		return;

	assert(uthread->uu_ar == NULL);

	/* Check which audit mask to use; either the kernel non-attributable
	 * event mask or the process audit mask.
	 */
	my_cred = kauth_cred_proc_ref(proc);

	if (my_cred->cr_au.ai_auid == AU_DEFAUDITID)
		aumask = &audit_nae_mask;
	else
		aumask = &my_cred->cr_au.ai_mask;

	/*
	 * Allocate an audit record, if preselection allows it, and store 
	 * in the BSD thread for later use.
	 */

#if CONFIG_MACF
	do {
		int error;

		error = mac_audit_check_preselect(my_cred, code,
		    (void *) uthread->uu_arg);

		if (error == MAC_AUDIT_YES) {
			uthread->uu_ar = audit_new(audit_event, proc, uthread);
			uthread->uu_ar->k_ar.ar_forced_by_mac = 1;
			au_to_text("Forced by a MAC policy");  
		}	
		else if (error == MAC_AUDIT_NO) {
			uthread->uu_ar = NULL;
		}
		else if (error == MAC_AUDIT_DEFAULT &&
		    au_preselect(audit_event, &my_cred->cr_au.ai_mask,
			AU_PRS_FAILURE | AU_PRS_SUCCESS))
				audit_new_wait(audit_event, proc, uthread);
	} while (0);
#else
	if (au_preselect(audit_event, &my_cred->cr_au.ai_mask,
				AU_PRS_FAILURE | AU_PRS_SUCCESS)) {
		audit_new_wait(audit_event, proc, uthread);
	} else {
		uthread->uu_ar = NULL;
	}
#endif
	kauth_cred_unref(&my_cred);
}

/* 
 * Note: The audit_syscall_exit() parameter list was modified to support 
 * mac_audit_check_postselect(), which requires the Darwin syscall number.
 */
#if CONFIG_MACF
void
audit_syscall_exit(unsigned short code, int error, AUDIT_PRINTF_ONLY proc_t proc, struct uthread *uthread)
#else
void
audit_syscall_exit(int error, AUDIT_PRINTF_ONLY proc_t proc, struct uthread *uthread)
#endif
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

#if CONFIG_MACF
	do {
		int mac_error;
		
		if (uthread->uu_ar == NULL)  /* syscall wasn't audited */
			goto out;
			
		/*  
		 * Note, no other postselect mechanism exists.  If
		 * mac_audit_check_postselect returns MAC_AUDIT_NO, the
		 * record will be suppressed.  Other values at this
		 * point result in the audit record being committed.
		 * This suppression behavior will probably go away in
		 * the port to 10.3.4.
		 */
		mac_error = mac_audit_check_postselect(kauth_cred_get(), code,
		    (void *) uthread->uu_arg, error, retval,
		    uthread->uu_ar->k_ar.ar_forced_by_mac);

		if (mac_error == MAC_AUDIT_YES)
			uthread->uu_ar->k_ar_commit |= AR_COMMIT_KERNEL;
		else if (mac_error == MAC_AUDIT_NO) {
			audit_free(uthread->uu_ar);
			goto out;
		}

	} while (0);
	
#endif
	audit_commit(uthread->uu_ar, error, retval);
	if (uthread->uu_ar != NULL) {
		AUDIT_PRINTF(("audit record committed by pid %d\n", proc->p_pid));
	}

#if CONFIG_MACF
out:
#endif
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
	proc_t proc;
	struct au_mask *aumask;
	kauth_cred_t my_cred;

	if (audit_event == AUE_NULL)
		return;

	uthread = curuthread();
	if (uthread == NULL)
		return;

	proc = current_proc();
	if (proc == NULL) 
		return;

	assert(uthread->uu_ar == NULL);

	my_cred = kauth_cred_proc_ref(proc);

	/* Check which audit mask to use; either the kernel non-attributable
	 * event mask or the process audit mask.
	 */
	if (my_cred->cr_au.ai_auid == AU_DEFAUDITID)
		aumask = &audit_nae_mask;
	else
		aumask = &my_cred->cr_au.ai_mask;

	kauth_cred_unref(&my_cred);
	
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

	strlcpy(ar->k_ar.ar_arg_login, login, MAXLOGNAME);

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
audit_arg_process(proc_t p)
{
	struct kaudit_record *ar;
	kauth_cred_t my_cred;

	ar = currecord();
	if ((ar == NULL) || (p == NULL))
		return;

	my_cred = kauth_cred_proc_ref(p);
	ar->k_ar.ar_arg_auid = my_cred->cr_au.ai_auid;
	ar->k_ar.ar_arg_euid = my_cred->cr_uid;
	ar->k_ar.ar_arg_egid = my_cred->cr_groups[0];
	ar->k_ar.ar_arg_ruid = my_cred->cr_ruid;
	ar->k_ar.ar_arg_rgid = my_cred->cr_rgid;
	ar->k_ar.ar_arg_asid = my_cred->cr_au.ai_asid;
	ar->k_ar.ar_arg_termid = my_cred->cr_au.ai_termid;
	kauth_cred_unref(&my_cred);

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

/*
 * Note that the current working directory vp must be supplied at the audit
 * call site to permit per thread current working directories, and that it
 * must take a upath starting with '/' into account for chroot if the path
 * is absolute.  This results in the real (non-chroot) path being recorded
 * in the audit record.
 */
void
audit_arg_sockaddr(struct vnode *cwd_vp, struct sockaddr *so)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL || cwd_vp == NULL || so == NULL)
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
		audit_arg_upath(cwd_vp, ((struct sockaddr_un *)so)->sun_path, 
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

	strlcpy(ar->k_ar.ar_arg_text, text, MAXPATHLEN);
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
audit_arg_svipc_addr(user_addr_t addr)
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
audit_arg_file(__unused proc_t p, const struct fileproc *fp)
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
 * freed when the audit record is freed.  Note that the current working
 * directory vp must be supplied at the audit call site to permit per thread
 * current working directories, and that it must take a upath starting with
 * '/' into account for chroot if the path is absolute.  This results in the
 * real (non-chroot) path being recorded in the audit record.
 */
void
audit_arg_upath(struct vnode *cwd_vp, char *upath, u_int64_t flags)
{
	struct kaudit_record *ar;
	char **pathp;

	if (cwd_vp == NULL || upath == NULL) 
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

	if (canon_path(cwd_vp, upath, *pathp) == 0) {
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
	proc_t p;
#if CONFIG_MACF
	char **vnode_mac_labelp;
	struct mac mac;
#endif

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
#if CONFIG_MACF
		vnode_mac_labelp = &ar->k_ar.ar_vnode1_mac_labels;
#endif
	}
	else {
		ar->k_ar.ar_valid_arg &= (ARG_ALL ^ ARG_KPATH2);
		ar->k_ar.ar_valid_arg &= (ARG_ALL ^ ARG_VNODE2);
		pathp = &ar->k_ar.ar_arg_kpath2;
		vnp = &ar->k_ar.ar_arg_vnode2;
#if CONFIG_MACF
		vnode_mac_labelp = &ar->k_ar.ar_vnode2_mac_labels;
#endif
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

	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_mode);
	VATTR_WANTED(&va, va_uid);
	VATTR_WANTED(&va, va_gid);
	VATTR_WANTED(&va, va_rdev);
	VATTR_WANTED(&va, va_fsid);
	VATTR_WANTED(&va, va_fileid);
	VATTR_WANTED(&va, va_gen);
	error = vnode_getattr(vp, &va, vfs_context_current());
	if (error) {
		/* XXX: How to handle this case? */
		return;
	}

#if CONFIG_MACF
	if (*vnode_mac_labelp == NULL) {
		*vnode_mac_labelp = (char *)zalloc(audit_mac_label_zone);
		if (*vnode_mac_labelp != NULL) {
			mac.m_buflen = MAC_AUDIT_LABEL_LEN;
			mac.m_string = *vnode_mac_labelp;
			mac_vnode_label_externalize_audit(vp, &mac);
		}



	}
#endif

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
audit_sysclose(proc_t p, int fd)
{
	struct fileproc *fp;
	struct vnode *vp;

	audit_arg_fd(fd);

	if (fp_getfvp(p, fd, &fp, &vp) != 0)
		return;

	audit_arg_vnpath_withref((struct vnode *)fp->f_fglob->fg_data, ARG_VNODE1);
	file_drop(fd);
} 

#if CONFIG_MACF
/*
 * This function is called by the MAC Framework to add audit data
 * from a policy to the current audit record.
 */
int
audit_mac_data(int type, int len, u_char *data) {
	struct kaudit_record *cur;
	struct mac_audit_record *record;
	int ret = 0;

	if (audit_enabled == 0) {
		ret = ENOTSUP;
		goto out_fail;
	}

	cur = currecord();
	if (cur == NULL) {
		ret = ENOTSUP;
		goto out_fail;
	}

	/*
	 * XXX: Note that we silently drop the audit data if this
	 * allocation fails - this is consistent with the rest of the
	 * audit implementation.
	 */
	record = (struct mac_audit_record *)kalloc(sizeof(*record));
	if (record == NULL)
		goto out_fail;

	record->type = type;
	record->length = len;
	record->data = data;
	LIST_INSERT_HEAD(cur->k_ar.ar_mac_records, record, records);

	return (0);

out_fail:
	kfree(data, len);
	return (ret);
}

void
audit_arg_mac_string(const char *string)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	if (ar->k_ar.ar_arg_mac_string == NULL) {
		ar->k_ar.ar_arg_mac_string =
		    (char *)kalloc(MAC_MAX_LABEL_BUF_LEN + MAC_ARG_PREFIX_LEN);
		/* This should be a rare event. If kalloc() returns NULL, the
		 * system is low on kernel virtual memory. To be consistent with the
		 * rest of audit, just return (may need to panic if required to for audit6).
		 */
		if (ar->k_ar.ar_arg_mac_string == NULL)
			return;
	}
	strncpy(ar->k_ar.ar_arg_mac_string, MAC_ARG_PREFIX, MAC_ARG_PREFIX_LEN);
	strncpy(ar->k_ar.ar_arg_mac_string + MAC_ARG_PREFIX_LEN, string, MAC_MAX_LABEL_BUF_LEN);
	ar->k_ar.ar_valid_arg |= ARG_MAC_STRING;

}
#endif  /* MAC */

/*
 * kau_will_audit can be used by a security policy to determine
 * if an audit record will be stored, reducing wasted memory allocation
 * and string handling.
 */

int
kau_will_audit(void)
{

	return (audit_enabled && currecord() != NULL);
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
audit(proc_t p, struct audit_args *uap, register_t *retval)
{
	return (ENOSYS);
}

int
auditon(proc_t p, struct auditon_args *uap, register_t *retval)
{
	return (ENOSYS);
}

int
getauid(proc_t p, struct getauid_args *uap, register_t *retval)
{
	return (ENOSYS);
}

int
setauid(proc_t p, struct setauid_args *uap, register_t *retval)
{
	return (ENOSYS);
}

int
getaudit(proc_t p, struct getaudit_args *uap, register_t *retval)
{
	return (ENOSYS);
}

int
setaudit(proc_t p, struct setaudit_args *uap, register_t *retval)
{
	return (ENOSYS);
}

int
getaudit_addr(proc_t p, struct getaudit_addr_args *uap, register_t *retval)
{
	return (ENOSYS);
}

int
setaudit_addr(proc_t p, struct setaudit_addr_args *uap, register_t *retval)
{
	return (ENOSYS);
}

int
auditctl(proc_t p, struct auditctl_args *uap, register_t *retval)
{
	return (ENOSYS);
}

#if CONFIG_MACF
void
audit_mac_data(int type, int len, u_char *data)
{
}

int
kau_will_audit()
{
	return (0);
}
#endif

#endif /* AUDIT */
