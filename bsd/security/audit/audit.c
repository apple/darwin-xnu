/*-
 * Copyright (c) 1999-2009 Apple Inc.
 * Copyright (c) 2006-2007 Robert N. M. Watson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
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
#include <bsm/audit_internal.h>
#include <bsm/audit_kevents.h>

#include <security/audit/audit.h>
#include <security/audit/audit_bsd.h>
#include <security/audit/audit_private.h>

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

#if CONFIG_AUDIT
MALLOC_DEFINE(M_AUDITDATA, "audit_data", "Audit data storage");
MALLOC_DEFINE(M_AUDITPATH, "audit_path", "Audit path storage");
MALLOC_DEFINE(M_AUDITTEXT, "audit_text", "Audit text storage");

/*
 * Audit control settings that are set/read by system calls and are hence
 * non-static.
 *
 * Define the audit control flags.
 */
int			audit_enabled;
int			audit_suspended;

int			audit_syscalls;
au_class_t 		audit_kevent_mask;

/*
 * Flags controlling behavior in low storage situations.  Should we panic if
 * a write fails?  Should we fail stop if we're out of disk space?
 */
int			audit_panic_on_write_fail;
int			audit_fail_stop;
int			audit_argv;
int			audit_arge;

/*
 * Are we currently "failing stop" due to out of disk space?
 */
int			audit_in_failure;

/*
 * Global audit statistics.
 */
struct audit_fstat	audit_fstat;

/*
 * Preselection mask for non-attributable events.
 */
struct au_mask		audit_nae_mask;

/*
 * Mutex to protect global variables shared between various threads and
 * processes.
 */
struct mtx		audit_mtx;

/*
 * Queue of audit records ready for delivery to disk.  We insert new records
 * at the tail, and remove records from the head.  Also, a count of the
 * number of records used for checking queue depth.  In addition, a counter
 * of records that we have allocated but are not yet in the queue, which is
 * needed to estimate the total size of the combined set of records
 * outstanding in the system.
 */
struct kaudit_queue	audit_q;
int			audit_q_len;
int			audit_pre_q_len;

/*
 * Audit queue control settings (minimum free, low/high water marks, etc.)
 */
struct au_qctrl		audit_qctrl;

/*
 * Condition variable to signal to the worker that it has work to do: either
 * new records are in the queue, or a log replacement is taking place.
 */
struct cv		audit_worker_cv;

/*
 * Condition variable to signal when the worker is done draining the audit
 * queue.
 */
struct cv		audit_drain_cv;

/*
 * Condition variable to flag when crossing the low watermark, meaning that
 * threads blocked due to hitting the high watermark can wake up and continue
 * to commit records.
 */
struct cv		audit_watermark_cv;

/*
 * Condition variable for  auditing threads wait on when in fail-stop mode.
 * Threads wait on this CV forever (and ever), never seeing the light of day
 * again.
 */
static struct cv	audit_fail_cv;

static zone_t		audit_record_zone;

/*
 * Kernel audit information.  This will store the current audit address
 * or host information that the kernel will use when it's generating
 * audit records.  This data is modified by the A_GET{SET}KAUDIT auditon(2)
 * command.
 */
static struct auditinfo_addr	audit_kinfo;
static struct rwlock		audit_kinfo_lock;

#define	KINFO_LOCK_INIT()	rw_init(&audit_kinfo_lock,		\
					"audit_kinfo_lock")
#define	KINFO_RLOCK()		rw_rlock(&audit_kinfo_lock)
#define KINFO_WLOCK()		rw_wlock(&audit_kinfo_lock)
#define	KINFO_RUNLOCK()		rw_runlock(&audit_kinfo_lock)
#define	KINFO_WUNLOCK()		rw_wunlock(&audit_kinfo_lock)

void
audit_set_kinfo(struct auditinfo_addr *ak)
{

	KASSERT(ak->ai_termid.at_type == AU_IPv4 ||
	    ak->ai_termid.at_type == AU_IPv6,
	    ("audit_set_kinfo: invalid address type"));

	KINFO_WLOCK();
	bcopy(ak, &audit_kinfo, sizeof(audit_kinfo));
	KINFO_WUNLOCK();
}

void
audit_get_kinfo(struct auditinfo_addr *ak)
{

	KASSERT(audit_kinfo.ai_termid.at_type == AU_IPv4 ||
	    audit_kinfo.ai_termid.at_type == AU_IPv6,
	    ("audit_set_kinfo: invalid address type"));

	KINFO_RLOCK();
	bcopy(&audit_kinfo, ak, sizeof(*ak));
	KINFO_RUNLOCK();
}

/*
 * Construct an audit record for the passed thread.
 */
static void
audit_record_ctor(proc_t p, struct kaudit_record *ar)
{
	kauth_cred_t cred;

	bzero(ar, sizeof(*ar));
	ar->k_ar.ar_magic = AUDIT_RECORD_MAGIC;
	nanotime(&ar->k_ar.ar_starttime);

	if (PROC_NULL != p) {
		cred = kauth_cred_proc_ref(p);

		/*
	 	 * Export the subject credential.
	 	 */
		cru2x(cred, &ar->k_ar.ar_subj_cred);
		ar->k_ar.ar_subj_ruid = kauth_cred_getruid(cred);
		ar->k_ar.ar_subj_rgid = kauth_cred_getrgid(cred);
		ar->k_ar.ar_subj_egid = kauth_cred_getgid(cred);
		ar->k_ar.ar_subj_pid = p->p_pid;
		ar->k_ar.ar_subj_auid = cred->cr_audit.as_aia_p->ai_auid;
		ar->k_ar.ar_subj_asid = cred->cr_audit.as_aia_p->ai_asid;
		bcopy(&cred->cr_audit.as_mask, &ar->k_ar.ar_subj_amask,
    		    sizeof(struct au_mask));
		bcopy(&cred->cr_audit.as_aia_p->ai_termid,
		    &ar->k_ar.ar_subj_term_addr, sizeof(struct au_tid_addr));
		kauth_cred_unref(&cred);
	}
}

static void
audit_record_dtor(struct kaudit_record *ar)
{

	if (ar->k_ar.ar_arg_upath1 != NULL)
		free(ar->k_ar.ar_arg_upath1, M_AUDITPATH);
	if (ar->k_ar.ar_arg_upath2 != NULL)
		free(ar->k_ar.ar_arg_upath2, M_AUDITPATH);
	if (ar->k_ar.ar_arg_kpath1 != NULL)
		free(ar->k_ar.ar_arg_kpath1, M_AUDITPATH);
	if (ar->k_ar.ar_arg_kpath2 != NULL)
		free(ar->k_ar.ar_arg_kpath2, M_AUDITPATH);
	if (ar->k_ar.ar_arg_text != NULL)
		free(ar->k_ar.ar_arg_text, M_AUDITTEXT);
	if (ar->k_ar.ar_arg_opaque != NULL)
		free(ar->k_ar.ar_arg_opaque, M_AUDITDATA);
	if (ar->k_ar.ar_arg_data != NULL)
		free(ar->k_ar.ar_arg_data, M_AUDITDATA);
	if (ar->k_udata != NULL)
		free(ar->k_udata, M_AUDITDATA);
	if (ar->k_ar.ar_arg_argv != NULL)
		free(ar->k_ar.ar_arg_argv, M_AUDITTEXT);
	if (ar->k_ar.ar_arg_envv != NULL)
		free(ar->k_ar.ar_arg_envv, M_AUDITTEXT);
}

/*
 * Initialize the Audit subsystem: configuration state, work queue,
 * synchronization primitives, worker thread, and trigger device node.  Also
 * call into the BSM assembly code to initialize it.
 */
void
audit_init(void)
{

	audit_enabled = 0;
	audit_syscalls = 0;
	audit_kevent_mask = 0;
	audit_suspended = 0;
	audit_panic_on_write_fail = 0;
	audit_fail_stop = 0;
	audit_in_failure = 0;
	audit_argv = 0;
	audit_arge = 0;

	audit_fstat.af_filesz = 0;	/* '0' means unset, unbounded. */
	audit_fstat.af_currsz = 0;
	audit_nae_mask.am_success = 0;
	audit_nae_mask.am_failure = 0;

	TAILQ_INIT(&audit_q);
	audit_q_len = 0;
	audit_pre_q_len = 0;
	audit_qctrl.aq_hiwater = AQ_HIWATER;
	audit_qctrl.aq_lowater = AQ_LOWATER;
	audit_qctrl.aq_bufsz = AQ_BUFSZ;
	audit_qctrl.aq_minfree = AU_FS_MINFREE;

	audit_kinfo.ai_termid.at_type = AU_IPv4;
	audit_kinfo.ai_termid.at_addr[0] = INADDR_ANY;

	_audit_lck_grp_init();
	mtx_init(&audit_mtx, "audit_mtx", NULL, MTX_DEF);
	KINFO_LOCK_INIT();
	cv_init(&audit_worker_cv, "audit_worker_cv");
	cv_init(&audit_drain_cv, "audit_drain_cv");
	cv_init(&audit_watermark_cv, "audit_watermark_cv");
	cv_init(&audit_fail_cv, "audit_fail_cv");

	audit_record_zone = zinit(sizeof(struct kaudit_record),
	    AQ_HIWATER*sizeof(struct kaudit_record), 8192, "audit_zone");
#if CONFIG_MACF
	audit_mac_init();
#endif
	/* Init audit session subsystem. */
	audit_session_init();

	/* Initialize the BSM audit subsystem. */
	kau_init();

	/* audit_trigger_init(); */

	/* Start audit worker thread. */
	(void) audit_pipe_init();

	/* Start audit worker thread. */
	audit_worker_init();
}

/*
 * Drain the audit queue and close the log at shutdown.  Note that this can
 * be called both from the system shutdown path and also from audit
 * configuration syscalls, so 'arg' and 'howto' are ignored.
 */
void
audit_shutdown(void)
{

	audit_rotate_vnode(NULL, NULL);
}

/*
 * Return the current thread's audit record, if any.
 */
struct kaudit_record *
currecord(void)
{

	return (curthread()->uu_ar);
}

/*
 * XXXAUDIT: There are a number of races present in the code below due to
 * release and re-grab of the mutex.  The code should be revised to become
 * slightly less racy.
 *
 * XXXAUDIT: Shouldn't there be logic here to sleep waiting on available
 * pre_q space, suspending the system call until there is room?
 */
struct kaudit_record *
audit_new(int event, proc_t p, __unused struct uthread *uthread)
{
	struct kaudit_record *ar;
	int no_record;
	int audit_override;

	/*
	 * Override the audit_suspended and audit_enabled if it always
	 * audits session events.
	 *
	 * XXXss - This really needs to be a generalized call to a filter
	 * interface so if other things that use the audit subsystem in the
	 * future can simply plugged in.
	 */
	audit_override = (AUE_SESSION_START == event ||
	    AUE_SESSION_UPDATE == event || AUE_SESSION_END == event ||
	    AUE_SESSION_CLOSE == event);
	
	mtx_lock(&audit_mtx);
	no_record = (audit_suspended || !audit_enabled);
	mtx_unlock(&audit_mtx);
	if (!audit_override && no_record)
		return (NULL);

	/*
	 * Initialize the audit record header.
	 * XXX: We may want to fail-stop if allocation fails.
	 *
	 * Note: the number of outstanding uncommitted audit records is
	 * limited to the number of concurrent threads servicing system calls
	 * in the kernel.
	 */
	ar = zalloc(audit_record_zone);
	if (ar == NULL)
		return NULL;
	audit_record_ctor(p, ar);
	ar->k_ar.ar_event = event;

#if CONFIG_MACF
	if (PROC_NULL != p) {
		if (audit_mac_new(p, ar) != 0) {
			zfree(audit_record_zone, ar);
			return (NULL);
		}
	} else
		ar->k_ar.ar_mac_records = NULL;
#endif

	mtx_lock(&audit_mtx);
	audit_pre_q_len++;
	mtx_unlock(&audit_mtx);

	return (ar);
}

void
audit_free(struct kaudit_record *ar)
{

	audit_record_dtor(ar);
#if CONFIG_MACF
	if (NULL != ar->k_ar.ar_mac_records)
		audit_mac_free(ar);
#endif
	zfree(audit_record_zone, ar);
}

void
audit_commit(struct kaudit_record *ar, int error, int retval)
{
	au_event_t event;
	au_class_t class;
	au_id_t auid;
	int sorf;
	struct au_mask *aumask;
	int audit_override;

	if (ar == NULL)
		return;

	/*
	 * Decide whether to commit the audit record by checking the error
	 * value from the system call and using the appropriate audit mask.
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
		/*
		 * The open syscall always writes a AUE_OPEN_RWTC event;
		 * change it to the proper type of event based on the flags
		 * and the error value.
		 */
		ar->k_ar.ar_event = audit_flags_and_error_to_openevent(
		    ar->k_ar.ar_arg_fflags, error);
		break;

	case AUE_OPEN_EXTENDED_RWTC:
		/*
		 * The open_extended syscall always writes a
		 * AUE_OPEN_EXTENDEDRWTC event; change it to the proper type of
		 * event based on the flags and the error value.
		 */
		ar->k_ar.ar_event = audit_flags_and_error_to_openextendedevent(
		    ar->k_ar.ar_arg_fflags, error);
		break;

	case AUE_SYSCTL:
		ar->k_ar.ar_event = audit_ctlname_to_sysctlevent(
		    ar->k_ar.ar_arg_ctlname, ar->k_ar.ar_valid_arg);
		break;

	case AUE_AUDITON:
		/* Convert the auditon() command to an event. */
		ar->k_ar.ar_event = auditon_command_event(ar->k_ar.ar_arg_cmd);
		break;

	case AUE_FCNTL:
		/* Convert some fcntl() commands to their own events. */
		ar->k_ar.ar_event = audit_fcntl_command_event(
		    ar->k_ar.ar_arg_cmd, ar->k_ar.ar_arg_fflags, error);
		break;
	}

	auid = ar->k_ar.ar_subj_auid;
	event = ar->k_ar.ar_event;
	class = au_event_class(event);

	/*
	 * See if we need to override the audit_suspend and audit_enabled
	 * flags.
	 *
	 * XXXss - This check needs to be generalized so new filters can
	 * easily be added.
	 */
	audit_override = (AUE_SESSION_START == event ||
	    AUE_SESSION_UPDATE == event || AUE_SESSION_END == event ||
	    AUE_SESSION_CLOSE == event);

	ar->k_ar_commit |= AR_COMMIT_KERNEL;
	if (au_preselect(event, class, aumask, sorf) != 0)
		ar->k_ar_commit |= AR_PRESELECT_TRAIL;
	if (audit_pipe_preselect(auid, event, class, sorf,
	    ar->k_ar_commit & AR_PRESELECT_TRAIL) != 0)
		ar->k_ar_commit |= AR_PRESELECT_PIPE;
	if ((ar->k_ar_commit & (AR_PRESELECT_TRAIL | AR_PRESELECT_PIPE |
	    AR_PRESELECT_USER_TRAIL | AR_PRESELECT_USER_PIPE |
	    AR_PRESELECT_FILTER)) == 0) {
		mtx_lock(&audit_mtx);
		audit_pre_q_len--;
		mtx_unlock(&audit_mtx);
		audit_free(ar);
		return;
	}

	ar->k_ar.ar_errno = error;
	ar->k_ar.ar_retval = retval;
	nanotime(&ar->k_ar.ar_endtime);

	/*
	 * Note: it could be that some records initiated while audit was
	 * enabled should still be committed?
	 */
	mtx_lock(&audit_mtx);
	if (!audit_override && (audit_suspended || !audit_enabled)) {
		audit_pre_q_len--;
		mtx_unlock(&audit_mtx);
		audit_free(ar);
		return;
	}

	/*
	 * Constrain the number of committed audit records based on the
	 * configurable parameter.
	 */
	while (audit_q_len >= audit_qctrl.aq_hiwater)
		cv_wait(&audit_watermark_cv, &audit_mtx);

	TAILQ_INSERT_TAIL(&audit_q, ar, k_q);
	audit_q_len++;
	audit_pre_q_len--;
	cv_signal(&audit_worker_cv);
	mtx_unlock(&audit_mtx);
}

/*
 * audit_syscall_enter() is called on entry to each system call.  It is
 * responsible for deciding whether or not to audit the call (preselection),
 * and if so, allocating a per-thread audit record.  audit_new() will fill in
 * basic thread/credential properties.
 */
void
audit_syscall_enter(unsigned int code, proc_t proc, struct uthread *uthread)
{
	struct au_mask *aumask;
	au_class_t class;
	au_event_t event;
	au_id_t auid;
	kauth_cred_t cred;

	/*
	 * In FreeBSD, each ABI has its own system call table, and hence
	 * mapping of system call codes to audit events.  Convert the code to
	 * an audit event identifier using the process system call table
	 * reference.  In Darwin, there's only one, so we use the global
	 * symbol for the system call table.  No audit record is generated
	 * for bad system calls, as no operation has been performed.
	 *
	 * In Mac OS X, the audit events are stored in a table seperate from
	 * the syscall table(s).  This table is generated by makesyscalls.sh
	 * from syscalls.master and stored in audit_kevents.c.
	 */
	if (code > NUM_SYSENT)
		return;
	event = sys_au_event[code];
	if (event == AUE_NULL)
		return;

	KASSERT(uthread->uu_ar == NULL,
	    ("audit_syscall_enter: uthread->uu_ar != NULL"));

	/*
	 * Check which audit mask to use; either the kernel non-attributable
	 * event mask or the process audit mask.
	 */
	cred = kauth_cred_proc_ref(proc);
	auid = cred->cr_audit.as_aia_p->ai_auid;
	if (auid == AU_DEFAUDITID) 
		aumask = &audit_nae_mask;
	else
		aumask = &cred->cr_audit.as_mask;

	/*
	 * Allocate an audit record, if preselection allows it, and store in
	 * the thread for later use.
	 */
	class = au_event_class(event);
#if CONFIG_MACF
	/*
	 * Note: audit_mac_syscall_enter() may call audit_new() and allocate
	 * memory for the audit record (uu_ar).
	 */
	if (audit_mac_syscall_enter(code, proc, uthread, cred, event) == 0)
		goto out;
#endif
	if (au_preselect(event, class, aumask, AU_PRS_BOTH)) {
		/*
		 * If we're out of space and need to suspend unprivileged
		 * processes, do that here rather than trying to allocate
		 * another audit record.
		 *
		 * Note: we might wish to be able to continue here in the
		 * future, if the system recovers.  That should be possible
		 * by means of checking the condition in a loop around
		 * cv_wait().  It might be desirable to reevaluate whether an
		 * audit record is still required for this event by
		 * re-calling au_preselect().
		 */
		if (audit_in_failure &&
		    suser(cred, &proc->p_acflag) != 0) {
			cv_wait(&audit_fail_cv, &audit_mtx);
			panic("audit_failing_stop: thread continued");
		}
		if (uthread->uu_ar == NULL)
			uthread->uu_ar = audit_new(event, proc, uthread);
	} else if (audit_pipe_preselect(auid, event, class, AU_PRS_BOTH, 0)) {
		if (uthread->uu_ar == NULL)
			uthread->uu_ar = audit_new(event, proc, uthread);
	} 

out:
	kauth_cred_unref(&cred);
}

/*
 * audit_syscall_exit() is called from the return of every system call, or in
 * the event of exit1(), during the execution of exit1().  It is responsible
 * for committing the audit record, if any, along with return condition.
 *
 * Note: The audit_syscall_exit() parameter list was modified to support
 * mac_audit_check_postselect(), which requires the syscall number.
 */
#if CONFIG_MACF
void
audit_syscall_exit(unsigned int code, int error, __unused proc_t proc,
    struct uthread *uthread)
#else
void
audit_syscall_exit(int error, __unsed proc_t proc, struct uthread *uthread)
#endif
{
	int retval;

	/*
	 * Commit the audit record as desired; once we pass the record into
	 * audit_commit(), the memory is owned by the audit subsystem.  The
	 * return value from the system call is stored on the user thread.
	 * If there was an error, the return value is set to -1, imitating
	 * the behavior of the cerror routine.
	 */
	if (error)
		retval = -1;
	else
		retval = uthread->uu_rval[0];

#if CONFIG_MACF
	if (audit_mac_syscall_exit(code, uthread, error, retval) != 0)
		goto out;
#endif
	audit_commit(uthread->uu_ar, error, retval);

out:
	uthread->uu_ar = NULL;
}

/*
 * Calls to set up and tear down audit structures used during Mach system
 * calls.
 */
void
audit_mach_syscall_enter(unsigned short event)
{
	struct uthread *uthread;
	proc_t proc;
	struct au_mask *aumask;
	kauth_cred_t cred;
	au_class_t class;
	au_id_t auid;

	if (event == AUE_NULL)
		return;

	uthread = curthread();
	if (uthread == NULL)
		return;

	proc = current_proc();
	if (proc == NULL)
		return;

	KASSERT(uthread->uu_ar == NULL,
	    ("audit_mach_syscall_enter: uthread->uu_ar != NULL"));

	cred = kauth_cred_proc_ref(proc);
	auid = cred->cr_audit.as_aia_p->ai_auid;

	/*
	 * Check which audit mask to use; either the kernel non-attributable
	 * event mask or the process audit mask.
	 */
	if (auid == AU_DEFAUDITID) 
		aumask = &audit_nae_mask;
	else
		aumask = &cred->cr_audit.as_mask;

	/*
	 * Allocate an audit record, if desired, and store in the BSD thread
	 * for later use.
	 */
	class = au_event_class(event);
	if (au_preselect(event, class, aumask, AU_PRS_BOTH))
		uthread->uu_ar = audit_new(event, proc, uthread);
	else if (audit_pipe_preselect(auid, event, class, AU_PRS_BOTH, 0))
		uthread->uu_ar = audit_new(event, proc, uthread);
	else
		uthread->uu_ar = NULL;

	kauth_cred_unref(&cred);
}

void
audit_mach_syscall_exit(int retval, struct uthread *uthread)
{
	/*
	 * The error code from Mach system calls is the same as the
	 * return value
	 */
	/* XXX Is the above statement always true? */
	audit_commit(uthread->uu_ar, retval, retval);
	uthread->uu_ar = NULL;
}

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

void
audit_proc_coredump(proc_t proc, char *path, int errcode)
{
	struct kaudit_record *ar;
	struct au_mask *aumask;
	au_class_t class;
	int ret, sorf;
	char **pathp;
	au_id_t auid;
	kauth_cred_t my_cred;
	struct uthread *uthread;

	ret = 0;

	/*
	 * Make sure we are using the correct preselection mask.
	 */
	my_cred = kauth_cred_proc_ref(proc);
	auid = my_cred->cr_audit.as_aia_p->ai_auid;
	if (auid == AU_DEFAUDITID) 
		aumask = &audit_nae_mask;
	else
		aumask = &my_cred->cr_audit.as_mask;
	kauth_cred_unref(&my_cred);
	/*
	 * It's possible for coredump(9) generation to fail.  Make sure that
	 * we handle this case correctly for preselection.
	 */
	if (errcode != 0)
		sorf = AU_PRS_FAILURE;
	else
		sorf = AU_PRS_SUCCESS;
	class = au_event_class(AUE_CORE);
	if (au_preselect(AUE_CORE, class, aumask, sorf) == 0 &&
	    audit_pipe_preselect(auid, AUE_CORE, class, sorf, 0) == 0)
		return;
	/*
	 * If we are interested in seeing this audit record, allocate it.
	 * Where possible coredump records should contain a pathname and arg32
	 * (signal) tokens.
	 */
	uthread = curthread();
	ar = audit_new(AUE_CORE, proc, uthread);
	if (path != NULL) {
		pathp = &ar->k_ar.ar_arg_upath1;
		*pathp = malloc(MAXPATHLEN, M_AUDITPATH, M_WAITOK);
		if (audit_canon_path(vfs_context_cwd(vfs_context_current()), path,
		    *pathp))
			free(*pathp, M_AUDITPATH);
		else
			ARG_SET_VALID(ar, ARG_UPATH1);
	}
	ar->k_ar.ar_arg_signum = proc->p_sigacts->ps_sig;
	ARG_SET_VALID(ar, ARG_SIGNUM);
	if (errcode != 0)
		ret = 1;
	audit_commit(ar, errcode, ret);
}
#endif /* CONFIG_AUDIT */
