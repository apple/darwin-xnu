/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/audit.h>
#include <sys/kern_audit.h>
#include <sys/user.h>
#include <sys/bsm_kevents.h>
#include <sys/bsm_klib.h>
#include <sys/syscall.h>
#include <sys/malloc.h>
#include <sys/un.h>

#include <kern/lock.h>
#include <kern/wait_queue.h>

#ifdef AUDIT

/*
 * The AUDIT_EXCESSIVELY_VERBOSE define enables a number of
 * gratuitously noisy printf's to the console.  Due to the
 * volume, it should be left off unless you want your system
 * to churn a lot whenever the audit record flow gets high.
 */
/* #define	AUDIT_EXCESSIVELY_VERBOSE */
#ifdef AUDIT_EXCESSIVELY_VERBOSE
#define	AUDIT_PRINTF(x)	printf x
#else
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
 * records at the tail, and remove records from the head.
 */
static TAILQ_HEAD(, kaudit_record)	 audit_q;

/*
 * Condition variable to signal to the worker that it has work to do:
 * either new records are in the queue, or a log replacement is taking
 * place.
 */
static wait_queue_t			 audit_wait_queue;

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
static wait_queue_t			 audit_replacement_wait_queue;

static int				 audit_replacement_flag;
static struct vnode			*audit_replacement_vp;
static struct ucred			*audit_replacement_cred;

/*
 * Flags to use on audit files when opening and closing.
 */
const static int		 audit_open_flags = FWRITE | O_APPEND;
const static int		 audit_close_flags = FWRITE | O_APPEND;

/*
 * XXX: Couldn't find the include file for this, so copied kern_exec.c's
 * behavior.
 */
extern task_t kernel_task;

static void
audit_free(struct kaudit_record *ar)
{
	if (ar->k_ar.ar_arg_upath1 != NULL) {
		kmem_free(kernel_map, ar->k_ar.ar_arg_upath1, MAXPATHLEN);
	}
	if (ar->k_ar.ar_arg_upath2 != NULL) {
		kmem_free(kernel_map, ar->k_ar.ar_arg_upath2, MAXPATHLEN);
	}
	if (ar->k_ar.ar_arg_kpath1 != NULL) {
		kmem_free(kernel_map, ar->k_ar.ar_arg_kpath1, MAXPATHLEN);
	}
	if (ar->k_ar.ar_arg_kpath2 != NULL) {
		kmem_free(kernel_map, ar->k_ar.ar_arg_kpath2, MAXPATHLEN);
	}
	if (ar->k_ar.ar_arg_text != NULL) {
		kmem_free(kernel_map, ar->k_ar.ar_arg_text, MAXPATHLEN);
	}
	if (ar->k_udata != NULL) {
		kmem_free(kernel_map, ar->k_udata, ar->k_ulen);
	}
	kmem_free(kernel_map, ar, sizeof(*ar));
}

static int
audit_write(struct vnode *vp, struct kaudit_record *ar, struct ucred *cred,
    struct proc *p)
{
	int ret;
	struct au_record *bsm;

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
	if (ar->k_udata != NULL) {
		vn_rdwr(UIO_WRITE, vp, (void *)ar->k_udata, ar->k_ulen,
		    (off_t)0, UIO_SYSSPACE, IO_APPEND|IO_UNIT, cred, NULL, p);
	}

	/* 
	 * Convert the internal kernel record to BSM format and write it
	 * out if everything's OK.
	 */
	ret = kaudit_to_bsm(ar, &bsm);
	if (ret == BSM_NOAUDIT)
		return (0);

	if (ret == BSM_FAILURE) {
		AUDIT_PRINTF(("BSM conversion failure\n"));
		return (-1);
	}
	
	/* XXX This function can be called with the kernel funnel held,
	 * which is not optimal. We should break the write functionality
	 * away from the BSM record generation and have the BSM generation
	 * done before this function is called. This function will then
	 * take the BSM record as a parameter.
	 */
	ret = (vn_rdwr(UIO_WRITE, vp, (void *)bsm->data, bsm->len,
	    (off_t)0, UIO_SYSSPACE, IO_APPEND|IO_UNIT, cred, NULL, p));

	kau_free(bsm);

	return (ret);
}

static void
audit_worker()
{
	int do_replacement_signal, error, release_funnel;
	TAILQ_HEAD(, kaudit_record) ar_worklist;
	struct kaudit_record *ar, *ar_start, *ar_stop;
	struct vnode *audit_vp, *old_vp;
	struct ucred *audit_cred, *old_cred;
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
				crfree(old_cred);
				old_cred = NULL;
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
			wait_queue_wakeup_all(audit_replacement_wait_queue,
			    0, THREAD_AWAKENED);

		/*
		 * Next, check to see if we have any records to drain into
		 * the vnode.  If not, go back to waiting for an event.
		 */
		if (TAILQ_EMPTY(&audit_q)) {
			int ret;

			AUDIT_PRINTF(("audit_worker waiting\n"));
			ret = wait_queue_assert_wait(audit_wait_queue, 0, 
			                             THREAD_UNINT);
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
				VOP_LEASE(audit_vp, audit_p, audit_cred,
				    LEASE_WRITE);
				error = audit_write(audit_vp, ar, audit_cred,
				    audit_p);
				if (error)
					printf("audit_worker: write error %d\n",
					    error);
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
	audit_enabled = 0;
	audit_suspended = 0;
	audit_replacement_cred = NULL;
	audit_replacement_flag = 0;
	audit_replacement_vp = NULL;
	audit_mtx = mutex_alloc(ETAP_NO_TRACE);
	audit_wait_queue = wait_queue_alloc(SYNC_POLICY_FIFO);
	audit_replacement_wait_queue = wait_queue_alloc(SYNC_POLICY_FIFO);

	/* Initialize the BSM audit subsystem. */
	kau_init();

	kernel_thread(kernel_task, audit_worker);
}

static void
audit_rotate_vnode(struct ucred *cred, struct vnode *vp)
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
		ret = wait_queue_assert_wait(audit_replacement_wait_queue, 0,
		                             THREAD_UNINT);
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
	 * Wake up the audit worker to perform the exchange once we
	 * release the mutex.
	 */
	wait_queue_wakeup_one(audit_wait_queue, 0, THREAD_AWAKENED);

	/*
	 * Wait for the audit_worker to broadcast that a replacement has
	 * taken place; we know that once this has happened, our vnode
	 * has been replaced in, so we can return successfully.
	 */
	AUDIT_PRINTF(("audit_rotate_vnode: waiting for news of "
	    "replacement\n"));
	ret = wait_queue_assert_wait(audit_replacement_wait_queue, 0,
	                             THREAD_UNINT);
	mutex_unlock(audit_mtx);

	assert(ret == THREAD_WAITING);
	ret = thread_block(THREAD_CONTINUE_NULL);
	assert(ret == THREAD_AWAKENED);
	AUDIT_PRINTF(("audit_rotate_vnode: change acknowledged by "
	    "audit_worker (flag " "now %d)\n", audit_replacement_flag));
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

	return (get_bsdthread_info(current_act()));
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
struct audit_args {
	void *	record;
	int	length;
};
/* ARGSUSED */
int
audit(struct proc *p, struct audit_args *uap, register_t *retval)
{
	register struct pcred *pc = p->p_cred;
	int error;
	void * rec;
	struct kaudit_record *ar;

	ar = currecord();

	/* XXX: What's the proper error code if a user audit record can't
	 * be written due to auditing off, or otherwise unavailable?
	 */
	if (ar == NULL)
		return (ENOTSUP);

	error = suser(pc->pc_ucred, &p->p_acflag);
	if (error)
		return (error);

	if (uap->length > MAX_AUDIT_RECORD_SIZE) 
		return (EINVAL);

	error = kmem_alloc(kernel_map, (vm_offset_t *)&rec, uap->length);
	if (error != KERN_SUCCESS)
		return(ENOMEM);

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
	ar->k_ulen  = uap->length;
	return (0);

free_out:
	kmem_free(kernel_map, (vm_offset_t)rec, uap->length);
	return (error);
}

/*
 *  System call to manipulate auditing.
 */
struct auditon_args {
	int	cmd;
	void *	data;
	int	length;
};
/* ARGSUSED */
int
auditon(struct proc *p, struct auditon_args *uap, register_t *retval)
{
	register struct pcred *pc = p->p_cred;
	int error;

	error = suser(pc->pc_ucred, &p->p_acflag);
	if (error)
		return (error);
	return (ENOSYS);
}

/*
 *  System call to pass in file descriptor for audit log.
 */
struct auditsvc_args {
	int	fd;
	int	limit;
};
/* ARGSUSED */
int
auditsvc(struct proc *p, struct auditsvc_args *uap, register_t *retval)
{
	register struct pcred *pc = p->p_cred;
	int error;

	error = suser(pc->pc_ucred, &p->p_acflag);
	if (error)
		return (error);
	return (ENOSYS);
}

/* 
 * System calls to manage the user audit information.
 * XXXAUDIT May need to lock the proc structure.
 */
struct getauid_args {
	au_id_t	*auid;
};
/* ARGSUSED */
int
getauid(struct proc *p, struct getauid_args *uap, register_t *retval)
{
	register struct pcred *pc = p->p_cred;
	int error;

	error = suser(pc->pc_ucred, &p->p_acflag);
	if (error)
		return (error);

	error = copyout((void *)&p->p_au->ai_auid, (void *)uap->auid, 
				sizeof(*uap->auid));
	if (error)
		return (error);

	return (0);
}

struct setauid_args {
	au_id_t	*auid;
};
/* ARGSUSED */
int
setauid(struct proc *p, struct setauid_args *uap, register_t *retval)
{
	register struct pcred *pc = p->p_cred;
	int error;

	error = suser(pc->pc_ucred, &p->p_acflag);
	if (error)
		return (error);

	error = copyin((void *)uap->auid, (void *)&p->p_au->ai_auid, 
				sizeof(p->p_au->ai_auid));
	if (error)
		return (error);

	audit_arg_auid(p->p_au->ai_auid);
	return (0);
}

/*
 *  System calls to get and set process audit information.
 */
struct getaudit_args {
	struct auditinfo	*auditinfo;
};
/* ARGSUSED */
int
getaudit(struct proc *p, struct getaudit_args *uap, register_t *retval)
{
	register struct pcred *pc = p->p_cred;
	int error;

	error = suser(pc->pc_ucred, &p->p_acflag);
	if (error)
		return (error);
	error = copyout((void *)p->p_au, (void *)uap->auditinfo, 
				sizeof(*uap->auditinfo));
	if (error)
		return (error);

	return (0);
}

struct setaudit_args {
	struct auditinfo	*auditinfo;
};
/* ARGSUSED */
int
setaudit(struct proc *p, struct setaudit_args *uap, register_t *retval)
{
	register struct pcred *pc = p->p_cred;
	int error;

	error = suser(pc->pc_ucred, &p->p_acflag);
	if (error)
		return (error);
	error = copyin((void *)uap->auditinfo, (void *)p->p_au, 
				sizeof(*p->p_au));
	if (error)
		return (error);

	return (0);
}

struct getaudit_addr_args {
	struct auditinfo_addr	*auditinfo_addr;
	int			length;
};
/* ARGSUSED */
int
getaudit_addr(struct proc *p, struct getaudit_addr_args *uap, register_t *retval)
{
	register struct pcred *pc = p->p_cred;
	int error;

	error = suser(pc->pc_ucred, &p->p_acflag);
	if (error)
		return (error);
	return (ENOSYS);
}

struct setaudit_addr_args {
	struct auditinfo_addr	*auditinfo_addr;
	int			length;
};
/* ARGSUSED */
int
setaudit_addr(struct proc *p, struct setaudit_addr_args *uap, register_t *retval)
{
	register struct pcred *pc = p->p_cred;
	int error;

	error = suser(pc->pc_ucred, &p->p_acflag);
	if (error)
		return (error);
	return (ENOSYS);
}

/*
 * Syscall to manage audit files.
 *
 * XXX: Should generate an audit event.
 */
struct auditctl_args {
	char	*path;
};
/* ARGSUSED */
int
auditctl(struct proc *p, struct auditctl_args *uap)
{
	struct kaudit_record *ar;
	struct nameidata nd;
	struct ucred *cred;
	struct vnode *vp;
	int error, flags, ret;

	error = suser(p->p_ucred, &p->p_acflag);
	if (error)
		return (error);

	vp = NULL;
	cred = NULL;

	/*
	 * If a path is specified, open the replacement vnode, perform
	 * validity checks, and grab another reference to the current
	 * credential.
	 */
	if (uap->path != NULL) {
		NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE,
		    uap->path, p);
		flags = audit_open_flags;
		error = vn_open(&nd, flags, 0);
		if (error)
			goto out;
		VOP_UNLOCK(nd.ni_vp, 0, p);
		vp = nd.ni_vp;
		if (vp->v_type != VREG) {
			vn_close(vp, audit_close_flags, p->p_ucred, p);
			error = EINVAL;
			goto out;
		}
		cred = p->p_ucred;
		crhold(cred);
	}

	audit_rotate_vnode(cred, vp);
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
audit_new(int event, struct proc *p, struct uthread *uthread)
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
	 * Eventually, we might want to have global event filtering
	 * by event type here.
	 */

	/*
	 * XXX: Process-based event preselection should occur here.
	 * Currently, we only post-select.
	 */

	/*
	 * Initialize the audit record header.
	 * XXX: Should probably use a zone; whatever we use must be
	 * safe to call from the non-BSD side of the house.
	 * XXX: We may want to fail-stop if allocation fails.
	 */
	(void)kmem_alloc(kernel_map, &ar, sizeof(*ar));
	if (ar == NULL)
		return NULL;

	bzero(ar, sizeof(*ar));
	ar->k_ar.ar_magic = AUDIT_RECORD_MAGIC;
	ar->k_ar.ar_event = event;
	nanotime(&ar->k_ar.ar_starttime);

	/* Export the subject credential. */
	cru2x(p->p_ucred, &ar->k_ar.ar_subj_cred);
	ar->k_ar.ar_subj_ruid = p->p_cred->p_ruid;
	ar->k_ar.ar_subj_rgid = p->p_cred->p_rgid;
	ar->k_ar.ar_subj_egid = p->p_ucred->cr_groups[0];
	ar->k_ar.ar_subj_auid = p->p_au->ai_auid;
	ar->k_ar.ar_subj_pid = p->p_pid;
	bcopy(p->p_comm, ar->k_ar.ar_subj_comm, MAXCOMLEN);
	bcopy(&p->p_au->ai_mask, &ar->k_ar.ar_subj_amask, 
			sizeof(p->p_au->ai_mask));

	return (ar);
}

/*
 * MPSAFE
 * XXXAUDIT: So far, this is unused, and should probably be GC'd.
 */
void
audit_abort(struct kaudit_record *ar)
{

	audit_free(ar);
}

/*
 * MPSAFE
 */
void
audit_commit(struct kaudit_record *ar, int error, int retval)
{

	if (ar == NULL)
		return;

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

	/*
	 * XXXAUDIT: The number of outstanding uncommitted audit records is
	 * limited by the number of concurrent threads servicing system
	 * calls in the kernel.  However, there is currently no bound on
	 * the size of the committed records in the audit event queue
	 * before they are sent to disk.  Probably, there should be a fixed
	 * size bound (perhaps configurable), and if that bound is reached,
	 * threads should sleep in audit_commit() until there's room.
	 */
	mutex_lock(audit_mtx);
	/*
	 * Note: it could be that some records initiated while audit was
	 * enabled should still be committed?
	 */
	if (audit_suspended || !audit_enabled) {
		mutex_unlock(audit_mtx);
		audit_free(ar);
		return;
	}
	TAILQ_INSERT_TAIL(&audit_q, ar, k_q);
	wait_queue_wakeup_one(audit_wait_queue, 0, THREAD_AWAKENED);
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

	assert(uthread->uu_ar == NULL);

	audit_event = sys_au_event[code];

	/*
	 * Allocate an audit record, if desired, and store in the BSD
	 * thread for later use.
	 */
	if (audit_event != AUE_NULL) {
#if 0
		AUDIT_PRINTF(("Allocated record type %d for syscall %d\n",
		    audit_event, code));
#endif
		if (au_preselect(audit_event, &proc->p_au->ai_mask,
				AU_PRS_FAILURE | AU_PRS_SUCCESS)) {
			uthread->uu_ar = audit_new(audit_event, proc, uthread);
		} else {
			uthread->uu_ar = NULL;
		}
	}
}

void
audit_syscall_exit(int error, struct proc *proc, struct uthread *uthread)
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
	if (uthread->uu_ar != NULL)
		AUDIT_PRINTF(("audit record committed by pid %d\n", proc->p_pid));
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
audit_arg_accmode(int accmode)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_accmode = accmode;
	ar->k_ar.ar_valid_arg |= ARG_ACCMODE;
}

void
audit_arg_cmode(int cmode)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_arg_cmode = cmode;
	ar->k_ar.ar_valid_arg |= ARG_CMODE;
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
audit_arg_groupset(gid_t *gidset, u_int gidset_size)
{
	int i;
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
audit_arg_login(char *login)
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

	ar->k_ar.ar_arg_sockinfo.sodomain = sodomain;
	ar->k_ar.ar_arg_sockinfo.sotype = sotype;
	ar->k_ar.ar_arg_sockinfo.soprotocol = soprotocol;
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
audit_arg_text(char *text)
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
		kmem_alloc(kernel_map, &ar->k_ar.ar_arg_text, MAXPATHLEN);
		if (ar->k_ar.ar_arg_text == NULL)
			return;	
	}

	strcpy(ar->k_ar.ar_arg_text, text);
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
audit_arg_svipc_perm(struct ipc_perm *perm)
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

/* 
 * Initialize the audit information for the a process, presumably the first 
 * process in the system.
 * XXX It is not clear what the initial values should be for audit ID, 
 * session ID, etc. 
 */
void
audit_proc_init(struct proc *p)
{
	MALLOC_ZONE(p->p_au, struct auditinfo *, sizeof(*p->p_au), 
			M_SUBPROC, M_WAITOK);

	bzero((void *)p->p_au, sizeof(*p->p_au));
}

/* 
 * Copy the audit info from the parent process to the child process when
 * a fork takes place.
 * XXX Need to check for failure from the memory allocation, in here
 * as well as in any functions that use the process auditing info.
 */
void
audit_proc_fork(struct proc *parent, struct proc *child)
{
	/* Always set up the audit information pointer as this function
	 * should only be called when the proc is new. If proc structures
	 * are ever cached and reused, then this behavior will leak memory.
	 */
	MALLOC_ZONE(child->p_au, struct auditinfo *, sizeof(*child->p_au), 
			M_SUBPROC, M_WAITOK);

	bcopy(parent->p_au, child->p_au, sizeof(*child->p_au));
}

/*
 * Free the auditing structure for the process. 
 */
void
audit_proc_free(struct proc *p)
{
	FREE_ZONE((void *)p->p_au, sizeof(*p->p_au), M_SUBPROC);
	p->p_au = NULL;
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

	if (flags & (ARG_UPATH1 | ARG_UPATH2) == 0)
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
		kmem_alloc(kernel_map, pathp, MAXPATHLEN);
		if (*pathp == NULL)
			return;
	}

	canon_path(p, upath, *pathp);

	if (flags & ARG_UPATH1)
		ar->k_ar.ar_valid_arg |= ARG_UPATH1;
	else
		ar->k_ar.ar_valid_arg |= ARG_UPATH2;
}

/*
 * Function to save the path and vnode attr information into the audit 
 * record. 
 *
 * It is assumed that the caller will hold any vnode locks necessary to
 * perform a VOP_GETATTR() on the passed vnode.
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
	struct vattr vattr;
	int error;
	int len;
	char **pathp;
	struct vnode_au_info *vnp;
	struct proc *p;

	if (vp == NULL)
		return;

	ar = currecord();
	if (ar == NULL)	/* This will be the case for unaudited system calls */
		return;

	if (flags & (ARG_VNODE1 | ARG_VNODE2) == 0)
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
		kmem_alloc(kernel_map, pathp, MAXPATHLEN);
		if (*pathp == NULL)
			return;
	}

	/* Copy the path looked up by the vn_getpath() function */
	len = MAXPATHLEN;
	vn_getpath(vp, *pathp, &len);
	if (flags & ARG_VNODE1)
		ar->k_ar.ar_valid_arg |= ARG_KPATH1;
	else
		ar->k_ar.ar_valid_arg |= ARG_KPATH2;

	/*
	 * XXX: We'd assert the vnode lock here, only Darwin doesn't
	 * appear to have vnode locking assertions.
	 */
	error = VOP_GETATTR(vp, &vattr, p->p_ucred, p);
	if (error) {
		/* XXX: How to handle this case? */
		return;
	}

	vnp->vn_mode = vattr.va_mode;
	vnp->vn_uid = vattr.va_uid;
	vnp->vn_gid = vattr.va_gid;
	vnp->vn_dev = vattr.va_rdev;
	vnp->vn_fsid = vattr.va_fsid;
	vnp->vn_fileid = vattr.va_fileid;
	vnp->vn_gen = vattr.va_gen;
	if (flags & ARG_VNODE1)
		ar->k_ar.ar_valid_arg |= ARG_VNODE1;
	else
		ar->k_ar.ar_valid_arg |= ARG_VNODE2;

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
auditsvc(struct proc *p, struct auditsvc_args *uap, register_t *retval)
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

void
audit_proc_init(struct proc *p)
{

}

void
audit_proc_fork(struct proc *parent, struct proc *child)
{

}

void
audit_proc_free(struct proc *p)
{

}

#endif /* AUDIT */
