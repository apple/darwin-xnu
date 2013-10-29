/*-
 * Copyright (c) 2008-2009 Apple Inc.
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
 */

#include <stdarg.h>

#include <sys/kernel.h>
#include <sys/fcntl.h>
#include <sys/kauth.h>
#include <sys/conf.h>
#include <sys/poll.h>
#include <sys/queue.h>
#include <sys/signalvar.h>
#include <sys/syscall.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/user.h>

#include <miscfs/devfs/devfs.h>

#include <libkern/OSAtomic.h>

#include <bsm/audit.h>
#include <bsm/audit_internal.h>
#include <bsm/audit_kevents.h>

#include <security/audit/audit.h>
#include <security/audit/audit_bsd.h>
#include <security/audit/audit_ioctl.h>
#include <security/audit/audit_private.h>

#include <vm/vm_protos.h>
#include <mach/mach_port.h>
#include <kern/audit_sessionport.h>

#include <libkern/OSDebug.h>

/*
 * Audit Session Entry.  This is treated as an object with public and private
 * data.   The se_auinfo field is the only information that is public and
 * needs to be the first entry.
 */
struct au_sentry {
	auditinfo_addr_t	se_auinfo;	/* Public audit session data. */
#define	se_asid		se_auinfo.ai_asid
#define	se_auid		se_auinfo.ai_auid
#define	se_mask		se_auinfo.ai_mask
#define	se_termid	se_auinfo.ai_termid
#define	se_flags	se_auinfo.ai_flags

	long			se_refcnt;	/* Reference count. */
	long			se_procnt;	/* Processes in session. */
	ipc_port_t		se_port;	/* Session port. */
	LIST_ENTRY(au_sentry)	se_link; 	/* Hash bucket link list (1) */
};
typedef struct au_sentry au_sentry_t;

#define	AU_SENTRY_PTR(aia_p)	((au_sentry_t *)(aia_p))

/*
 * The default au_sentry/auditinfo_addr entry for ucred. 
 */

static au_sentry_t audit_default_se = {
	.se_auinfo = {
			.ai_auid = AU_DEFAUDITID,
			.ai_asid = AU_DEFAUDITSID,
			.ai_termid = { .at_type = AU_IPv4, },
	},
	.se_refcnt = 1, 
	.se_procnt = 1,
};

struct auditinfo_addr *audit_default_aia_p = &audit_default_se.se_auinfo;

kern_return_t ipc_object_copyin(ipc_space_t, mach_port_name_t,
    mach_msg_type_name_t, ipc_port_t *);
void ipc_port_release_send(ipc_port_t);

#if CONFIG_AUDIT


/*
 * Currently the hash table is a fixed size.
 */
#define HASH_TABLE_SIZE		97
#define	HASH_ASID(asid)		(audit_session_hash(asid) % HASH_TABLE_SIZE)

static struct rwlock	se_entry_lck;		/* (1) lock for se_link above */

LIST_HEAD(au_sentry_head, au_sentry);
static struct au_sentry_head *au_sentry_bucket = NULL;

#define AU_HISTORY_LOGGING 0
#if AU_HISTORY_LOGGING
typedef enum au_history_event {
	AU_HISTORY_EVENT_UNKNOWN = 0,
	AU_HISTORY_EVENT_REF     = 1,
	AU_HISTORY_EVENT_UNREF   = 2,
	AU_HISTORY_EVENT_BIRTH   = 3,
	AU_HISTORY_EVENT_DEATH   = 4,
	AU_HISTORY_EVENT_FIND    = 5
} au_history_event_t;

#define AU_HISTORY_MAX_STACK_DEPTH 8

struct au_history {
	struct au_sentry	*ptr;
	struct au_sentry	 se;
	void			*stack[AU_HISTORY_MAX_STACK_DEPTH];
	unsigned int		 stack_depth;
	au_history_event_t	 event;
};

static struct au_history *au_history;
static size_t		  au_history_size = 65536;
static unsigned int	  au_history_index;

static inline unsigned int
au_history_entries(void)
{
	if (au_history_index >= au_history_size)
		return au_history_size;
	else
		return au_history_index;
}

static inline void
au_history_record(au_sentry_t *se, au_history_event_t event)
{
	struct au_history *p;
	unsigned int i;

	i = OSAddAtomic(1, &au_history_index);
	p = &au_history[i % au_history_size];

	bzero(p, sizeof(*p));
	p->event = event;
	bcopy(se, &p->se, sizeof(p->se));
	p->stack_depth = OSBacktrace(&p->stack[0], AU_HISTORY_MAX_STACK_DEPTH);
	p->ptr = se;
}
#else
#define au_history_record(se, event) do {} while (0)
#endif

MALLOC_DEFINE(M_AU_SESSION, "audit_session", "Audit session data");

static void	audit_ref_session(au_sentry_t *se);
static void	audit_unref_session(au_sentry_t *se);

static void 	audit_session_event(int event, auditinfo_addr_t *aia_p);

/*
 * Audit session device.
 */

static MALLOC_DEFINE(M_AUDIT_SDEV, "audit_sdev", "Audit sdevs");
static MALLOC_DEFINE(M_AUDIT_SDEV_ENTRY, "audit_sdevent",
    "Audit sdev entries and buffers");

/*
 * Default audit sdev buffer parameters.
 */
#define	AUDIT_SDEV_QLIMIT_DEFAULT	128
#define	AUDIT_SDEV_QLIMIT_MIN		1
#define	AUDIT_SDEV_QLIMIT_MAX		1024

/*
 * Entry structure.
 */
struct	audit_sdev_entry {
	void				*ase_record;
	u_int		 		 ase_record_len;
	TAILQ_ENTRY(audit_sdev_entry)	 ase_queue;
};

/*
 * Per audit sdev structure.  
 */

struct audit_sdev {
	int		asdev_open;

#define	AUDIT_SDEV_ASYNC	0x00000001
#define	AUDIT_SDEV_NBIO		0x00000002

#define	AUDIT_SDEV_ALLSESSIONS	0x00010000
	u_int		asdev_flags;

	struct selinfo	asdev_selinfo;
	pid_t		asdev_sigio;

	au_id_t		asdev_auid;
	au_asid_t	asdev_asid;

	/* Per-sdev mutex for most fields in this struct. */
	struct mtx	asdev_mtx;

	/*
	 * Per-sdev sleep lock serializing user-generated reads and
	 * flushes. uiomove() is called to copy out the current head
	 * record's data whie the record remains in the queue, so we
	 * prevent other threads from removing it using this lock.
	 */
	struct slck	asdev_sx;

	/*
	 * Condition variable to signal when data has been delivered to 
	 * a sdev.
	 */
	struct cv	asdev_cv;

	/* Count and bound of records in the queue. */
	u_int		asdev_qlen;
	u_int		asdev_qlimit;

	/* The number of bytes of data across all records. */
	u_int		asdev_qbyteslen;
	
	/* 
	 * The amount read so far of the first record in the queue.
	 * (The number of bytes available for reading in the queue is
	 * qbyteslen - qoffset.)
	 */
	u_int		asdev_qoffset;

	/*
	 * Per-sdev operation statistics.
	 */
	u_int64_t	asdev_inserts;	/* Records added. */
	u_int64_t	asdev_reads;	/* Records read. */
	u_int64_t	asdev_drops;	/* Records dropped. */

	/*
	 * Current pending record list.  This is protected by a
	 * combination of asdev_mtx and asdev_sx.  Note that both
	 * locks are required to remove a record from the head of the
	 * queue, as an in-progress read may sleep while copying and,
	 * therefore, cannot hold asdev_mtx.
	 */
	TAILQ_HEAD(, audit_sdev_entry)	asdev_queue;

	/* Global sdev list. */
	TAILQ_ENTRY(audit_sdev)		asdev_list;
};

#define	AUDIT_SDEV_LOCK(asdev)		mtx_lock(&(asdev)->asdev_mtx)
#define	AUDIT_SDEV_LOCK_ASSERT(asdev)	mtx_assert(&(asdev)->asdev_mtx, \
					    MA_OWNED)
#define	AUDIT_SDEV_LOCK_DESTROY(asdev)	mtx_destroy(&(asdev)->asdev_mtx)
#define	AUDIT_SDEV_LOCK_INIT(asdev)	mtx_init(&(asdev)->asdev_mtx, \
					    "audit_sdev_mtx", NULL, MTX_DEF)
#define	AUDIT_SDEV_UNLOCK(asdev)	mtx_unlock(&(asdev)->asdev_mtx)
#define	AUDIT_SDEV_MTX(asdev)		(&(asdev)->asdev_mtx)

#define	AUDIT_SDEV_SX_LOCK_DESTROY(asd)	slck_destroy(&(asd)->asdev_sx)
#define	AUDIT_SDEV_SX_LOCK_INIT(asd)	slck_init(&(asd)->asdev_sx, \
    					    "audit_sdev_sx")
#define	AUDIT_SDEV_SX_XLOCK_ASSERT(asd)	slck_assert(&(asd)->asdev_sx, \
    					    SA_XLOCKED)
#define	AUDIT_SDEV_SX_XLOCK_SIG(asd)	slck_lock_sig(&(asd)->asdev_sx)
#define	AUDIT_SDEV_SX_XUNLOCK(asd)	slck_unlock(&(asd)->asdev_sx)

/*
 * Cloning variables and constants.
 */
#define	AUDIT_SDEV_NAME		"auditsessions"
#define	MAX_AUDIT_SDEVS		32

static int audit_sdev_major;
static void *devnode;

/*
 * Global list of audit sdevs.  The list is protected by a rw lock.
 * Individaul record queues are protected by  per-sdev locks.  These
 * locks synchronize between threads walking the list to deliver to 
 * individual sdevs and adds/removes of sdevs.
 */
static TAILQ_HEAD(, audit_sdev) audit_sdev_list;
static struct rwlock		audit_sdev_lock;

#define	AUDIT_SDEV_LIST_LOCK_INIT()	rw_init(&audit_sdev_lock, \
    					    "audit_sdev_list_lock")
#define	AUDIT_SDEV_LIST_RLOCK()		rw_rlock(&audit_sdev_lock)
#define	AUDIT_SDEV_LIST_RUNLOCK()	rw_runlock(&audit_sdev_lock)
#define	AUDIT_SDEV_LIST_WLOCK()         rw_wlock(&audit_sdev_lock)
#define	AUDIT_SDEV_LIST_WLOCK_ASSERT()	rw_assert(&audit_sdev_lock, \
    					    RA_WLOCKED)
#define	AUDIT_SDEV_LIST_WUNLOCK()       rw_wunlock(&audit_sdev_lock)

/*
 * dev_t doesn't have a pointer for "softc" data so we have to keep track of
 * it with the following global array (indexed by the minor number).
 *
 * XXX We may want to dynamically grow this as need.
 */
static struct audit_sdev	*audit_sdev_dtab[MAX_AUDIT_SDEVS];

/*
 * Special device methods and definition.
 */
static open_close_fcn_t		audit_sdev_open;
static open_close_fcn_t		audit_sdev_close;
static read_write_fcn_t		audit_sdev_read;
static ioctl_fcn_t		audit_sdev_ioctl; 
static select_fcn_t		audit_sdev_poll;

static struct cdevsw audit_sdev_cdevsw = {
	.d_open      =          audit_sdev_open,
	.d_close     =          audit_sdev_close,
	.d_read      =          audit_sdev_read,
	.d_write     =          eno_rdwrt,
	.d_ioctl     =          audit_sdev_ioctl,
	.d_stop      =          eno_stop,
	.d_reset     =          eno_reset,
	.d_ttys      =          NULL,
	.d_select    =          audit_sdev_poll,
	.d_mmap      =          eno_mmap,
	.d_strategy  =          eno_strat,
	.d_type      =          0
};

/*
 * Global statistics on audit sdevs.
 */
static int		audit_sdev_count;	/* Current number of sdevs. */
static u_int64_t	audit_sdev_ever;	/* Sdevs ever allocated. */
static u_int64_t	audit_sdev_records; 	/* Total records seen. */
static u_int64_t	audit_sdev_drops;	/* Global record drop count. */

static int audit_sdev_init(void);

#define	AUDIT_SENTRY_RWLOCK_INIT()	rw_init(&se_entry_lck, \
					    "se_entry_lck")
#define	AUDIT_SENTRY_RLOCK()		rw_rlock(&se_entry_lck)
#define	AUDIT_SENTRY_WLOCK()		rw_wlock(&se_entry_lck)
#define	AUDIT_SENTRY_RWLOCK_ASSERT()	rw_assert(&se_entry_lck, RA_LOCKED)
#define	AUDIT_SENTRY_RUNLOCK()		rw_runlock(&se_entry_lck)
#define	AUDIT_SENTRY_WUNLOCK()		rw_wunlock(&se_entry_lck)

/* Access control on the auditinfo_addr.ai_flags member. */
static uint64_t audit_session_superuser_set_sflags_mask;
static uint64_t audit_session_superuser_clear_sflags_mask;
static uint64_t audit_session_member_set_sflags_mask;
static uint64_t audit_session_member_clear_sflags_mask;
SYSCTL_NODE(, OID_AUTO, audit, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "Audit controls");
SYSCTL_NODE(_audit, OID_AUTO, session, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "Audit sessions");
SYSCTL_QUAD(_audit_session, OID_AUTO, superuser_set_sflags_mask, CTLFLAG_RW | CTLFLAG_LOCKED,
    &audit_session_superuser_set_sflags_mask,
    "Audit session flags settable by superuser");
SYSCTL_QUAD(_audit_session, OID_AUTO, superuser_clear_sflags_mask, CTLFLAG_RW | CTLFLAG_LOCKED,
    &audit_session_superuser_clear_sflags_mask,
    "Audit session flags clearable by superuser");
SYSCTL_QUAD(_audit_session, OID_AUTO, member_set_sflags_mask, CTLFLAG_RW | CTLFLAG_LOCKED,
    &audit_session_member_set_sflags_mask,
    "Audit session flags settable by a session member");
SYSCTL_QUAD(_audit_session, OID_AUTO, member_clear_sflags_mask, CTLFLAG_RW | CTLFLAG_LOCKED,
    &audit_session_member_clear_sflags_mask,
    "Audit session flags clearable by a session member");

#define	AUDIT_SESSION_DEBUG	0
#if	AUDIT_SESSION_DEBUG
/*
 * The following is debugging code that can be used to get a snapshot of the 
 * session state.  The audit session information is read out using sysctl:
 *
 * error = sysctlbyname("kern.audit_session_debug", buffer_ptr, &buffer_len,
 * 		NULL, 0);
 */
#include <kern/kalloc.h>

/*
 * The per session record structure for the snapshot data.
 */
struct au_sentry_debug {
	auditinfo_addr_t	se_auinfo;
	int64_t			se_refcnt;	/* refereence count */
	int64_t			se_procnt;	/* process count */
	int64_t			se_ptcnt;	/* process count from 
						   proc table */
};
typedef struct au_sentry_debug au_sentry_debug_t;

static int audit_sysctl_session_debug(struct sysctl_oid *oidp, void *arg1,
    int arg2, struct sysctl_req *req);

SYSCTL_PROC(_kern, OID_AUTO, audit_session_debug, CTLFLAG_RD | CTLFLAG_LOCKED,
    NULL, 0, audit_sysctl_session_debug, "S,audit_session_debug",
    "Current session debug info for auditing.");

/*
 * Callouts for proc_interate() which is used to reconcile the audit session
 * proc state information with the proc table.  We get everything we need
 * in the filterfn while the proc_lock() is held so we really don't need the
 * callout() function.
 */
static int 
audit_session_debug_callout(__unused proc_t p, __unused void *arg)
{

	return (PROC_RETURNED_DONE);
}

static int
audit_session_debug_filterfn(proc_t p, void *st)
{
	kauth_cred_t cred = p->p_ucred; 
	auditinfo_addr_t *aia_p = cred->cr_audit.as_aia_p;
	au_sentry_debug_t *sed_tab = (au_sentry_debug_t *) st;
	au_sentry_debug_t  *sdtp;
	au_sentry_t *se;

	if (IS_VALID_SESSION(aia_p)) {
		sdtp = &sed_tab[0];
		do {
			if (aia_p->ai_asid == sdtp->se_asid) {
				sdtp->se_ptcnt++;

				/* Do some santy checks. */
				se = AU_SENTRY_PTR(aia_p);
				if (se->se_refcnt != sdtp->se_refcnt) {
					sdtp->se_refcnt =
					    (int64_t)se->se_refcnt;
				}
				if (se->se_procnt != sdtp->se_procnt) {
					sdtp->se_procnt =
					    (int64_t)se->se_procnt;
				}
				break;
			}
			sdtp++;
		} while (sdtp->se_asid != 0 && sdtp->se_auid != 0);
	} else {
		/* add it to the default sesison */
		sed_tab->se_ptcnt++;
	}

	return (0);
}

/*
 * Copy out the session debug info via the sysctl interface.
 *
 */
static int
audit_sysctl_session_debug(__unused struct sysctl_oid *oidp,
    __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	au_sentry_t *se;
	au_sentry_debug_t *sed_tab, *next_sed;
	int i, entry_cnt = 0;
	size_t sz;
	int err = 0;

	/*
	 * This provides a read-only node.
	 */
	if (req->newptr != USER_ADDR_NULL)
		return (EPERM);

	/*
	 * Walk the audit session hash table to determine the size.
	 */
	AUDIT_SENTRY_RLOCK();
	for(i = 0; i < HASH_TABLE_SIZE; i++)
		LIST_FOREACH(se, &au_sentry_bucket[i], se_link)
		    if (se != NULL) 
			    entry_cnt++;

	entry_cnt++;  /* add one for the default entry */
	/*
	 * If just querying then return the space required.  There is an 
	 * obvious race condition here so we just fudge this by 3 in case
	 * the audit session table grows.
	 */
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = (entry_cnt + 3) * sizeof(au_sentry_debug_t);
		AUDIT_SENTRY_RUNLOCK();
		return (0);
	}

	/*
	 * Alloc a temporary buffer.
	 */
	if (req->oldlen < (entry_cnt * sizeof(au_sentry_debug_t))) {
		AUDIT_SENTRY_RUNLOCK();
		return (ENOMEM);
	}
	/*
	 * We hold the lock over the alloc since we don't want the table to
	 * grow on us.   Therefore, use the non-blocking version of kalloc().
	 */
	sed_tab = (au_sentry_debug_t *)kalloc_noblock(entry_cnt *
	    sizeof(au_sentry_debug_t));
	if (sed_tab == NULL) {
		AUDIT_SENTRY_RUNLOCK();
		return (ENOMEM);
	}
	bzero(sed_tab, entry_cnt * sizeof(au_sentry_debug_t));

	/*
	 * Walk the audit session hash table and build the record array.
	 */
	sz = 0;
	next_sed = sed_tab;
	/* add the first entry for processes not tracked in sessions. */
	bcopy(audit_default_aia_p, &next_sed->se_auinfo, sizeof (au_sentry_t));
	next_sed->se_refcnt = (int64_t)audit_default_se.se_refcnt;
	next_sed->se_procnt = (int64_t)audit_default_se.se_procnt;
	next_sed++;
	sz += sizeof(au_sentry_debug_t);
	for(i = 0; i < HASH_TABLE_SIZE; i++) {
		LIST_FOREACH(se, &au_sentry_bucket[i], se_link) {
			if (se != NULL) {
				next_sed->se_auinfo = se->se_auinfo;
				next_sed->se_refcnt = (int64_t)se->se_refcnt;
				next_sed->se_procnt = (int64_t)se->se_procnt;
				next_sed++;
				sz += sizeof(au_sentry_debug_t);
			}
		}
	}
	AUDIT_SENTRY_RUNLOCK();

	/* Reconcile with the process table. */
	(void) proc_iterate(PROC_ALLPROCLIST | PROC_ZOMBPROCLIST,
	    audit_session_debug_callout, NULL,
	    audit_session_debug_filterfn, (void *)&sed_tab[0]);


	req->oldlen = sz;
	err = SYSCTL_OUT(req, sed_tab, sz);
	kfree(sed_tab, entry_cnt * sizeof(au_sentry_debug_t));

	return (err);
}

#endif /* AUDIT_SESSION_DEBUG */

/*
 * Create and commit a session audit event. The proc and se arguments needs to
 * be that of the subject and not necessarily the current process.
 */
static void
audit_session_event(int event, auditinfo_addr_t *aia_p)
{
	struct kaudit_record *ar;

	KASSERT(AUE_SESSION_START == event || AUE_SESSION_UPDATE == event ||
	    AUE_SESSION_END == event || AUE_SESSION_CLOSE == event,
	    ("audit_session_event: invalid event: %d", event));

	if (NULL == aia_p)
		return;

	/* 
	 * Create a new audit record.  The record will contain the subject
	 * ruid, rgid, egid, pid, auid, asid, amask, and term_addr 
	 * (implicitly added by audit_new).
	 */
	ar = audit_new(event, PROC_NULL, /* Not used */ NULL);
	if (NULL == ar)
		return;

	/*
	 * Audit session events are always generated because they are used
	 * by some userland consumers so just set the preselect flag.
	 */
	ar->k_ar_commit |= AR_PRESELECT_FILTER;

	/* 
	 * Populate the subject information.  Note that the ruid, rgid,
	 * egid, and pid values are incorrect. We only need the  auditinfo_addr
	 * information.
	 */
	ar->k_ar.ar_subj_ruid = 0;
	ar->k_ar.ar_subj_rgid = 0;
	ar->k_ar.ar_subj_egid = 0;
	ar->k_ar.ar_subj_pid = 0;
	ar->k_ar.ar_subj_auid = aia_p->ai_auid;
	ar->k_ar.ar_subj_asid = aia_p->ai_asid;
	bcopy(&aia_p->ai_termid, &ar->k_ar.ar_subj_term_addr,
	    sizeof(struct au_tid_addr));

	/* Add the audit masks to the record. */
	ar->k_ar.ar_arg_amask.am_success = aia_p->ai_mask.am_success;
	ar->k_ar.ar_arg_amask.am_failure = aia_p->ai_mask.am_failure;
	ARG_SET_VALID(ar, ARG_AMASK);

	/* Add the audit session flags to the record. */
	ar->k_ar.ar_arg_value64 = aia_p->ai_flags; 
	ARG_SET_VALID(ar, ARG_VALUE64);


	/* Commit the record to the queue. */
	audit_commit(ar, 0, 0);
}

/*
 * Hash the audit session ID using a simple 32-bit mix.
 */
static inline uint32_t 
audit_session_hash(au_asid_t asid)
{
	uint32_t a = (uint32_t) asid;

	a = (a - (a << 6)) ^ (a >> 17); 
	a = (a - (a << 9)) ^ (a << 4);
	a = (a - (a << 3)) ^ (a << 10);
	a = a ^ (a >> 15);
	
	return (a);
}

/*
 * Do an hash lookup and find the session entry for a given ASID.  Return NULL
 * if not found. If the session is found then audit_session_find takes a 
 * reference. 
 */
static au_sentry_t *
audit_session_find(au_asid_t asid)
{
	uint32_t	 hkey;
	au_sentry_t	*found_se;

	AUDIT_SENTRY_RWLOCK_ASSERT();

	hkey = HASH_ASID(asid);

	LIST_FOREACH(found_se, &au_sentry_bucket[hkey], se_link)
		if (found_se->se_asid == asid) {
			au_history_record(found_se, AU_HISTORY_EVENT_FIND);
			audit_ref_session(found_se);
			return (found_se);
		}
	return (NULL);
}

/*
 * Remove the given audit_session entry from the hash table.
 */
static void
audit_session_remove(au_sentry_t *se)
{
	uint32_t	 hkey;
	au_sentry_t	*found_se, *tmp_se;

	au_history_record(se, AU_HISTORY_EVENT_DEATH);
	KASSERT(se->se_refcnt == 0, ("audit_session_remove: ref count != 0"));	
	KASSERT(se != &audit_default_se,
		("audit_session_remove: removing default session"));

	hkey = HASH_ASID(se->se_asid);

	AUDIT_SENTRY_WLOCK();
	/*
	 * Check and see if someone got a reference before we got the lock.
	 */
	if (se->se_refcnt != 0) {
		AUDIT_SENTRY_WUNLOCK();
		return;
	}

	audit_session_portdestroy(&se->se_port);
	LIST_FOREACH_SAFE(found_se, &au_sentry_bucket[hkey], se_link, tmp_se) {
		if (found_se == se) {

			/*
			 * Generate an audit event to notify userland of the
			 * session close.
			 */
			audit_session_event(AUE_SESSION_CLOSE,
			    &found_se->se_auinfo);

			LIST_REMOVE(found_se, se_link);
			AUDIT_SENTRY_WUNLOCK();
			free(found_se, M_AU_SESSION);

			return;
		}
	}
	AUDIT_SENTRY_WUNLOCK();
}

/*
 * Reference the session by incrementing the sentry ref count.
 */
static void
audit_ref_session(au_sentry_t *se)
{
	long old_val;

	if (se == NULL || se == &audit_default_se)
		return;

	au_history_record(se, AU_HISTORY_EVENT_REF);

	old_val = OSAddAtomicLong(1, &se->se_refcnt);
	KASSERT(old_val < 100000,
	    ("audit_ref_session: Too many references on session."));
}

/*
 * Decrement the sentry ref count and remove the session entry if last one.
 */
static void
audit_unref_session(au_sentry_t *se)
{
	long old_val;

	if (se == NULL || se == &audit_default_se)
		return;

	au_history_record(se, AU_HISTORY_EVENT_UNREF);

	old_val = OSAddAtomicLong(-1, &se->se_refcnt);
	if (old_val == 1)
		audit_session_remove(se);
	KASSERT(old_val > 0,
	    ("audit_unref_session: Too few references on session."));
}

/*
 * Increment the process count in the session.
 */
static void
audit_inc_procount(au_sentry_t *se)
{
	long old_val;

	if (se == NULL || se == &audit_default_se)
		return;
	
	old_val = OSAddAtomicLong(1, &se->se_procnt);
	KASSERT(old_val <= PID_MAX,
	    ("audit_inc_procount: proc count > PID_MAX"));
}

/*
 * Decrement the process count and add a knote if it is the last process
 * to exit the session.
 */
static void
audit_dec_procount(au_sentry_t *se)
{
	long old_val;

	if (se == NULL || se == &audit_default_se)
		return;

	old_val = OSAddAtomicLong(-1, &se->se_procnt);
	/*
	 * If this was the last process generate an audit event to notify
	 * userland of the session ending.
	 */
	if (old_val == 1)
		audit_session_event(AUE_SESSION_END, &se->se_auinfo);
	KASSERT(old_val >= 1,
	    ("audit_dec_procount: proc count < 0"));
}	

/*
 * Update the session entry and check to see if anything was updated.
 * Returns:
 *    0    Nothing was updated (We don't care about process preselection masks) 
 *    1    Something was updated.
 */
static int
audit_update_sentry(au_sentry_t *se, auditinfo_addr_t *new_aia)
{
	auditinfo_addr_t *aia = &se->se_auinfo;
	int update;

	KASSERT(new_aia != audit_default_aia_p, 
	  ("audit_update_sentry: Trying to update the default aia."));

	update = (aia->ai_auid != new_aia->ai_auid ||
	    bcmp(&aia->ai_termid, &new_aia->ai_termid,
		sizeof(new_aia->ai_termid)) ||
	    aia->ai_flags != new_aia->ai_flags);

	if (update)
		bcopy(new_aia, aia, sizeof(*aia));

	return (update);
}

/*
 * Return the next session ID.  The range of kernel generated audit session IDs
 * is ASSIGNED_ASID_MIN to ASSIGNED_ASID_MAX.
 */
static uint32_t 
audit_session_nextid(void)
{
	static uint32_t next_asid = ASSIGNED_ASID_MIN; 

	AUDIT_SENTRY_RWLOCK_ASSERT();

	if (next_asid > ASSIGNED_ASID_MAX)
		next_asid = ASSIGNED_ASID_MIN;

	return (next_asid++);
}

/*
 * Allocated a new audit_session entry and add it to the hash table.  If the
 * given ASID is set to AU_ASSIGN_ASID then audit_session_new() will pick an
 * audit session ID.  Otherwise, it attempts use the one given. It creates a
 * reference to the entry that must be unref'ed.
 */
static auditinfo_addr_t *
audit_session_new(auditinfo_addr_t *new_aia_p, auditinfo_addr_t *old_aia_p)
{
	au_asid_t new_asid;
	au_sentry_t *se = NULL;
	au_sentry_t *found_se = NULL;
	auditinfo_addr_t *aia = NULL;
	
	KASSERT(new_aia_p != NULL, ("audit_session_new: new_aia_p == NULL"));

	new_asid = new_aia_p->ai_asid; 

	/*
	 * Alloc a new session entry now so we don't wait holding the lock.
	 */
	se = malloc(sizeof(au_sentry_t), M_AU_SESSION, M_WAITOK | M_ZERO);

	/*
	 * Find an unique session ID, if desired.
	 */
	AUDIT_SENTRY_WLOCK();
	if (new_asid == AU_ASSIGN_ASID) {
		do {

			new_asid = (au_asid_t)audit_session_nextid();
			found_se = audit_session_find(new_asid);
			
			/* 
			 * If the session ID is currently active then drop the
			 * reference and try again.
			 */
			if (found_se != NULL)
				audit_unref_session(found_se);
			else
				break;
		} while(1);
	} else {

		/*
		 * Check to see if the requested ASID is already in the
		 * hash table.  If so, update it with the new auditinfo.
		 */	
		if ((found_se = audit_session_find(new_asid)) != NULL) {
			int updated;

			updated = audit_update_sentry(found_se, new_aia_p);

			AUDIT_SENTRY_WUNLOCK();
			free(se, M_AU_SESSION);

			/* If a different session then add this process in. */
			if (new_aia_p != old_aia_p)
				audit_inc_procount(found_se);

			/*
			 * If the session information was updated then
			 * generate an audit event to notify userland.
			 */
			if (updated)
				audit_session_event(AUE_SESSION_UPDATE,
				    &found_se->se_auinfo);

			return (&found_se->se_auinfo);
		}
	}

	/*
	 * Start the reference and proc count at 1 to account for the process
	 * that invoked this via setaudit_addr() (or friends).
	 */
	se->se_refcnt = se->se_procnt = 1;

	/*
	 * Populate the new session entry.  Note that process masks are stored
	 * in kauth ucred so just zero them here.
	 */
	se->se_port = IPC_PORT_NULL;
	aia = &se->se_auinfo;
	aia->ai_asid = new_asid;
	aia->ai_auid = new_aia_p->ai_auid;
	bzero(&new_aia_p->ai_mask, sizeof(new_aia_p->ai_mask));
	bcopy(&new_aia_p->ai_termid, &aia->ai_termid, sizeof(aia->ai_termid));
	aia->ai_flags = new_aia_p->ai_flags;

	/*
	 * Add it to the hash table.
	 */
	LIST_INSERT_HEAD(&au_sentry_bucket[HASH_ASID(new_asid)], se, se_link);
	AUDIT_SENTRY_WUNLOCK();

	/*
	 * Generate an audit event to notify userland of the new session.
	 */
	audit_session_event(AUE_SESSION_START, aia);
	au_history_record(se, AU_HISTORY_EVENT_BIRTH);
	return (aia);
}

/*
 * Lookup an existing session.  A copy of the audit session info for a given
 * ASID is returned in ret_aia.  Returns 0 on success.
 */
int
audit_session_lookup(au_asid_t asid, auditinfo_addr_t *ret_aia)
{
	au_sentry_t *se = NULL;

	if ((uint32_t)asid > ASSIGNED_ASID_MAX)
		return (-1);
	AUDIT_SENTRY_RLOCK();
	if ((se = audit_session_find(asid)) == NULL) {
		AUDIT_SENTRY_RUNLOCK();
		return (1);
	}
	/* We have a reference on the session so it is safe to drop the lock. */
	AUDIT_SENTRY_RUNLOCK();
	if (ret_aia != NULL)
		bcopy(&se->se_auinfo, ret_aia, sizeof(*ret_aia));
	audit_unref_session(se);

	return (0);
}

void
audit_session_aiaref(auditinfo_addr_t *aia_p)
{

	audit_ref_session(AU_SENTRY_PTR(aia_p));
}
	
/*
 * Add a reference to the session entry.
 */
void
audit_session_ref(kauth_cred_t cred)
{
	auditinfo_addr_t *aia_p;

	KASSERT(IS_VALID_CRED(cred),
	    ("audit_session_ref: Invalid kauth_cred."));

 	aia_p = cred->cr_audit.as_aia_p;
	audit_session_aiaref(aia_p);
}

void audit_session_aiaunref(auditinfo_addr_t *aia_p)
{

	audit_unref_session(AU_SENTRY_PTR(aia_p));
}

/* 
 * Remove a reference to the session entry.
 */
void
audit_session_unref(kauth_cred_t cred)
{
	auditinfo_addr_t *aia_p;

	KASSERT(IS_VALID_CRED(cred),
	    ("audit_session_unref: Invalid kauth_cred."));

 	aia_p = cred->cr_audit.as_aia_p;
	audit_session_aiaunref(aia_p);
}

/*
 * Increment the per audit session process count.  Assumes that the caller has
 * a reference on the process' cred.
 */
void
audit_session_procnew(proc_t p)
{
	kauth_cred_t cred = p->p_ucred;
	auditinfo_addr_t *aia_p;
	
	KASSERT(IS_VALID_CRED(cred), 
	    ("audit_session_procnew: Invalid kauth_cred."));

	aia_p = cred->cr_audit.as_aia_p; 

	audit_inc_procount(AU_SENTRY_PTR(aia_p));
}

/*
 * Decrement the per audit session process count.  Assumes that the caller has
 * a reference on the cred.
 */
void
audit_session_procexit(proc_t p)
{
	kauth_cred_t cred = p->p_ucred;
	auditinfo_addr_t *aia_p;

	KASSERT(IS_VALID_CRED(cred), 
	    ("audit_session_procexit: Invalid kauth_cred."));

	aia_p = cred->cr_audit.as_aia_p; 

	audit_dec_procount(AU_SENTRY_PTR(aia_p));
}

/*
 * Init the audit session code.  
 */
void
audit_session_init(void)
{
	int i;

	KASSERT((ASSIGNED_ASID_MAX - ASSIGNED_ASID_MIN) > PID_MAX,
	    ("audit_session_init: ASSIGNED_ASID_MAX is not large enough."));
	
	AUDIT_SENTRY_RWLOCK_INIT();

	au_sentry_bucket = malloc( sizeof(struct au_sentry) *
	    HASH_TABLE_SIZE, M_AU_SESSION, M_WAITOK | M_ZERO);

	for (i = 0; i < HASH_TABLE_SIZE; i++)
		LIST_INIT(&au_sentry_bucket[i]);

	(void)audit_sdev_init();
#if AU_HISTORY_LOGGING
	au_history = malloc(sizeof(struct au_history) * au_history_size,
	    M_AU_SESSION, M_WAITOK|M_ZERO);
#endif
}

static int
audit_session_update_check(kauth_cred_t cred, auditinfo_addr_t *old,
    auditinfo_addr_t *new)
{
	uint64_t n;

	/* If the current audit ID is not the default then it is immutable. */
	if (old->ai_auid != AU_DEFAUDITID && old->ai_auid != new->ai_auid)
		return (EINVAL);

	/* If the current termid is not the default then it is immutable. */
	if ((old->ai_termid.at_type != AU_IPv4 ||
	     old->ai_termid.at_port != 0 ||
	     old->ai_termid.at_addr[0] != 0) &&
	    (old->ai_termid.at_port != new->ai_termid.at_port ||
	     old->ai_termid.at_type != new->ai_termid.at_type ||
	     0 != bcmp(&old->ai_termid.at_addr, &new->ai_termid.at_addr,
		 sizeof (old->ai_termid.at_addr))))
		return (EINVAL);

	/* The flags may be set only according to the
	 * audit_session_*_set_sflags_masks.
	 */
	n = ~old->ai_flags & new->ai_flags;
	if (0 != n &&
	    !((n == (audit_session_superuser_set_sflags_mask & n) &&
		kauth_cred_issuser(cred)) ||
	      (n == (audit_session_member_set_sflags_mask & n)    &&
		old->ai_asid == new->ai_asid)))
		return (EINVAL);

	/* The flags may be cleared only according to the
	 * audit_session_*_clear_sflags_masks.
	 */
	n = ~new->ai_flags & old->ai_flags;
	if (0 != n &&
	    !((n == (audit_session_superuser_clear_sflags_mask & n) &&
		kauth_cred_issuser(cred)) ||
	      (n == (audit_session_member_clear_sflags_mask & n)    &&
		old->ai_asid == new->ai_asid)))
		return (EINVAL);

	/* The audit masks are mutable. */
	return (0);
}

/*
 * Safely update kauth cred of the given process with new the given audit info. 
 */
int
audit_session_setaia(proc_t p, auditinfo_addr_t *new_aia_p)
{
	kauth_cred_t my_cred, my_new_cred;
	struct au_session  as;
	struct au_session  tmp_as;
	auditinfo_addr_t caia, *old_aia_p;
	int ret;

	/*
	 * If this is going to modify an existing session then do some
	 * immutable checks.
	 */
	if (audit_session_lookup(new_aia_p->ai_asid, &caia) == 0) {
		my_cred = kauth_cred_proc_ref(p);
		ret = audit_session_update_check(my_cred, &caia, new_aia_p);
		kauth_cred_unref(&my_cred);
		if (ret)
			return (ret);
	}

	my_cred = kauth_cred_proc_ref(p);
	bcopy(&new_aia_p->ai_mask, &as.as_mask, sizeof(as.as_mask));
	old_aia_p = my_cred->cr_audit.as_aia_p;
	/* audit_session_new() adds a reference on the session */
	as.as_aia_p = audit_session_new(new_aia_p, old_aia_p);

	/* If the process left a session then update the process count. */
	if (old_aia_p != new_aia_p)
		audit_dec_procount(AU_SENTRY_PTR(old_aia_p));


	/*
	 * We are modifying the audit info in a credential so we need a new
	 * credential (or take another reference on an existing credential that
	 * matches our new one).  We must do this because the audit info in the
	 * credential is used as part of our hash key.	Get current credential
	 * in the target process and take a reference while we muck with it.
	 */
	for (;;) {

		/*
		 * Set the credential with new info.  If there is no change,
		 * we get back the same credential we passed in; if there is
		 * a change, we drop the reference on the credential we
		 * passed in.  The subsequent compare is safe, because it is
		 * a pointer compare rather than a contents compare.
		 */
		bcopy(&as, &tmp_as, sizeof(tmp_as));
		my_new_cred = kauth_cred_setauditinfo(my_cred, &tmp_as);

		if (my_cred != my_new_cred) {
			proc_lock(p);
			/* Need to protect for a race where another thread also
			 * changed the credential after we took our reference.
			 * If p_ucred has changed then we should restart this
			 * again with the new cred.
			 */
			if (p->p_ucred != my_cred) {
				proc_unlock(p);
				audit_session_unref(my_new_cred);
				kauth_cred_unref(&my_new_cred);
				/* try again */
				my_cred = kauth_cred_proc_ref(p);
				continue;
			}
			p->p_ucred = my_new_cred;
			/* update cred on proc */
			PROC_UPDATE_CREDS_ONPROC(p);
			proc_unlock(p);
		}
		/*
		 * Drop old proc reference or our extra reference.
		 */
		kauth_cred_unref(&my_cred);
		break;
	}

	/* Drop the reference taken by audit_session_new() above. */
	audit_unref_session(AU_SENTRY_PTR(as.as_aia_p));

	/* Propagate the change from the process to the Mach task. */
	set_security_token(p);

	return (0);
}

/*
 * audit_session_self  (system call)
 *
 * Description: Obtain a Mach send right for the current session.   
 *
 * Parameters:	p		Process calling audit_session_self().
 * 
 * Returns:	*ret_port	Named Mach send right, which may be
 * 				MACH_PORT_NULL in the failure case.
 *
 * Errno:	0		Success
 * 		EINVAL		The calling process' session has not be set.
 * 		ESRCH		Bad process, can't get valid cred for process. 
 * 		ENOMEM		Port allocation failed due to no free memory.
 */
int
audit_session_self(proc_t p, __unused struct audit_session_self_args *uap,
    mach_port_name_t *ret_port)
{
	ipc_port_t sendport = IPC_PORT_NULL;
	kauth_cred_t cred = NULL;
	auditinfo_addr_t *aia_p;
	au_sentry_t *se;
	int err = 0;

	cred = kauth_cred_proc_ref(p);
	if (!IS_VALID_CRED(cred)) {
		err = ESRCH;
		goto done;
	}

	aia_p = cred->cr_audit.as_aia_p;
	if (!IS_VALID_SESSION(aia_p)) {
		/* Can't join the default session. */
		err = EINVAL;
		goto done;
	}

	se = AU_SENTRY_PTR(aia_p); 

	/* 
	 * Processes that join using this mach port will inherit this process'
	 * pre-selection masks.
	 */
	if (se->se_port == IPC_PORT_NULL) 
		bcopy(&cred->cr_audit.as_mask, &se->se_mask,
		    sizeof(se->se_mask));

	/*
	 * Get a send right to the session's Mach port and insert it in the
	 * process' mach port namespace.
	 */
	sendport = audit_session_mksend(aia_p, &se->se_port);
	*ret_port = ipc_port_copyout_send(sendport, get_task_ipcspace(p->task));

done:
	if (cred != NULL)
		kauth_cred_unref(&cred);	
	if (err != 0)
		*ret_port = MACH_PORT_NULL;
	return (err);
}

/*
 * audit_session_port  (system call)
 *
 * Description: Obtain a Mach send right for the given session ID.
 *
 * Parameters:	p		Process calling audit_session_port().
 *              uap->asid       The target audit session ID.  The special
 *              		value -1 can be used to target the process's
 *              		own session.
 *              uap->portnamep  User address at which to place port name.
 *
 * Returns:	0		Success
 * 		EINVAL		The calling process' session has not be set.
 * 		EINVAL		The given session ID could not be found.
 * 		EINVAL		The Mach port right could not be copied out.
 * 		ESRCH		Bad process, can't get valid cred for process.
 * 		EPERM		Only the superuser can reference sessions other
 * 				than the process's own.
 * 		ENOMEM		Port allocation failed due to no free memory.
 */
int
audit_session_port(proc_t p, struct audit_session_port_args *uap,
    __unused int *retval)
{
	ipc_port_t sendport = IPC_PORT_NULL;
	mach_port_name_t portname = MACH_PORT_NULL;
	kauth_cred_t cred = NULL;
	auditinfo_addr_t *aia_p = NULL;
	au_sentry_t *se = NULL;
	int err = 0;

	/* Note: Currently this test will never be true, because
	 * ASSIGNED_ASID_MAX is effectively (uint32_t)-2.
	 */
	if (uap->asid != -1 && (uint32_t)uap->asid > ASSIGNED_ASID_MAX) {
		err = EINVAL;
		goto done;
	}
	cred = kauth_cred_proc_ref(p);
	if (!IS_VALID_CRED(cred)) {
		err = ESRCH;
		goto done;
	}
	aia_p = cred->cr_audit.as_aia_p;

	/* Find the session corresponding to the requested audit
	 * session ID.  If found, take a reference on it so that
	 * the session is not dropped until the join is later done.
	 */
	if (uap->asid == (au_asid_t)-1 ||
	    uap->asid == aia_p->ai_asid) {

		if (!IS_VALID_SESSION(aia_p)) {
			/* Can't join the default session. */
			err = EINVAL;
			goto done;
		}

		/* No privilege is required to obtain a port for our
		 * own session.
		 */
		se = AU_SENTRY_PTR(aia_p);
		audit_ref_session(se);
	} else if (kauth_cred_issuser(cred)) {
		/* The superuser may obtain a port for any existing
		 * session.
		 */
		AUDIT_SENTRY_RLOCK();
		se = audit_session_find(uap->asid);
		AUDIT_SENTRY_RUNLOCK();
		if (NULL == se) {
			err = EINVAL;
			goto done;
		}
		aia_p = &se->se_auinfo;
	} else {
		err = EPERM;
		goto done;
	}

	/*
	 * Processes that join using this mach port will inherit this process'
	 * pre-selection masks.
	 */
	if (se->se_port == IPC_PORT_NULL)
		bcopy(&cred->cr_audit.as_mask, &se->se_mask,
		    sizeof(se->se_mask));

	/*
	 * Use the session reference to create a mach port reference for the
	 * session (at which point we are free to drop the session reference)
	 * and then copy out the mach port to the process' mach port namespace.
	 */
	sendport = audit_session_mksend(aia_p, &se->se_port);
	portname = ipc_port_copyout_send(sendport, get_task_ipcspace(p->task));
	if (!MACH_PORT_VALID(portname)) {
		err = EINVAL;
		goto done;
	}
	err = copyout(&portname, uap->portnamep, sizeof(mach_port_name_t));
done:
	if (cred != NULL)
		kauth_cred_unref(&cred);
	if (NULL != se)
		audit_unref_session(se);
	if (MACH_PORT_VALID(portname) && 0 != err)
                (void)mach_port_deallocate(get_task_ipcspace(p->task),
		    portname);

	return (err);
}

static int
audit_session_join_internal(proc_t p, ipc_port_t port, au_asid_t *new_asid)
{
	auditinfo_addr_t *new_aia_p, *old_aia_p;
	kauth_cred_t my_cred = NULL;
	au_asid_t old_asid;
	int err = 0;

	*new_asid = AU_DEFAUDITSID;

	if ((new_aia_p = audit_session_porttoaia(port)) == NULL) {
		err = EINVAL;
		goto done;
	}

	proc_lock(p);
	kauth_cred_ref(p->p_ucred);
	my_cred = p->p_ucred;
	if (!IS_VALID_CRED(my_cred)) {
		kauth_cred_unref(&my_cred);	
		proc_unlock(p);
		err = ESRCH;
		goto done;
	}
	old_aia_p = my_cred->cr_audit.as_aia_p;
	old_asid = old_aia_p->ai_asid;
	*new_asid = new_aia_p->ai_asid;

	/*
	 * Add process in if not already in the session.
	 */
	if (*new_asid != old_asid) {
		kauth_cred_t my_new_cred;
		struct au_session new_as;

		bcopy(&new_aia_p->ai_mask, &new_as.as_mask,
			sizeof(new_as.as_mask));
		new_as.as_aia_p = new_aia_p;

		my_new_cred = kauth_cred_setauditinfo(my_cred, &new_as);
		p->p_ucred = my_new_cred;
		PROC_UPDATE_CREDS_ONPROC(p);

		/* Increment the proc count of new session */
		audit_inc_procount(AU_SENTRY_PTR(new_aia_p));

		proc_unlock(p);

		/* Propagate the change from the process to the Mach task. */
		set_security_token(p);

		/* Decrement the process count of the former session. */
		audit_dec_procount(AU_SENTRY_PTR(old_aia_p));
	} else  {
		proc_unlock(p);
	}
	kauth_cred_unref(&my_cred);

done:
	if (port != IPC_PORT_NULL)
		ipc_port_release_send(port);

	return (err);
}

/*
 * audit_session_spawnjoin
 *
 * Description: posix_spawn() interface to audit_session_join_internal().
 *
 * Returns:	0		Success
 * 		EINVAL		Invalid Mach port name.
 * 		ESRCH		Invalid calling process/cred.
 */
int
audit_session_spawnjoin(proc_t p, ipc_port_t port)
{
	au_asid_t new_asid;
	
	return (audit_session_join_internal(p, port, &new_asid));
}

/*
 * audit_session_join  (system call)
 *
 * Description:	Join the session for a given Mach port send right.
 * 
 * Parameters:	p		Process calling session join.
 * 		uap->port	A Mach send right.
 *
 * Returns:	*ret_asid	Audit session ID of new session.
 *				In the failure case the return value will be -1
 *				and 'errno' will be set to a non-zero value
 *				described below.
 *
 * Errno:	0		Success	
 * 		EINVAL		Invalid Mach port name.
 * 		ESRCH		Invalid calling process/cred.
 */
int
audit_session_join(proc_t p, struct audit_session_join_args *uap,
    au_asid_t *ret_asid)
{
	ipc_port_t port = IPC_PORT_NULL;
	mach_port_name_t send = uap->port;
	int err = 0;

	
	if (ipc_object_copyin(get_task_ipcspace(p->task), send,
		MACH_MSG_TYPE_COPY_SEND, &port) != KERN_SUCCESS) {
		*ret_asid = AU_DEFAUDITSID;
		err = EINVAL;
	} else
		err = audit_session_join_internal(p, port, ret_asid);

	return (err);
}

/*
 * Audit session device.
 */

/*
 * Free an audit sdev entry.
 */
static void
audit_sdev_entry_free(struct audit_sdev_entry *ase)
{

	free(ase->ase_record, M_AUDIT_SDEV_ENTRY);
	free(ase, M_AUDIT_SDEV_ENTRY);
}

/*
 * Append individual record to a queue.  Allocate queue-local buffer and
 * add to the queue.  If the queue is full or we can't allocate memory,
 * drop the newest record.
 */
static void
audit_sdev_append(struct audit_sdev *asdev, void *record, u_int record_len)
{
	struct audit_sdev_entry *ase;

	AUDIT_SDEV_LOCK_ASSERT(asdev);

	if (asdev->asdev_qlen >= asdev->asdev_qlimit) {
		asdev->asdev_drops++;
		audit_sdev_drops++;
		return;
	}

	ase = malloc(sizeof (*ase), M_AUDIT_SDEV_ENTRY, M_NOWAIT | M_ZERO);
	if (NULL == ase) {
		asdev->asdev_drops++;
		audit_sdev_drops++;
		return;
	}

	ase->ase_record = malloc(record_len, M_AUDIT_SDEV_ENTRY, M_NOWAIT);
	if (NULL == ase->ase_record) {
		free(ase, M_AUDIT_SDEV_ENTRY);
		asdev->asdev_drops++;
		audit_sdev_drops++;
		return;
	}

	bcopy(record, ase->ase_record, record_len);
	ase->ase_record_len = record_len;

	TAILQ_INSERT_TAIL(&asdev->asdev_queue, ase, ase_queue);
	asdev->asdev_inserts++;
	asdev->asdev_qlen++;
	asdev->asdev_qbyteslen += ase->ase_record_len;
	selwakeup(&asdev->asdev_selinfo);
	if (asdev->asdev_flags & AUDIT_SDEV_ASYNC)
		pgsigio(asdev->asdev_sigio, SIGIO);

	cv_broadcast(&asdev->asdev_cv);
}

/*
 * Submit an audit record to be queued in the audit session device.
 */
void
audit_sdev_submit(__unused au_id_t auid, __unused au_asid_t asid, void *record,
    u_int record_len)
{
	struct audit_sdev *asdev;

	/*
	 * Lockless read to avoid lock overhead if sessio devices are not in
	 * use.
	 */
	if (NULL == TAILQ_FIRST(&audit_sdev_list))
		return;

	AUDIT_SDEV_LIST_RLOCK();
	TAILQ_FOREACH(asdev, &audit_sdev_list, asdev_list) {
		AUDIT_SDEV_LOCK(asdev);
		
		/* 
		 * Only append to the sdev queue if the AUID and ASID match that
		 * of the process that opened this session device or if the
		 * ALLSESSIONS flag is set.
		 */
		if ((/* XXXss auid == asdev->asdev_auid && */
			asid == asdev->asdev_asid) ||
		    (asdev->asdev_flags & AUDIT_SDEV_ALLSESSIONS) != 0)
			audit_sdev_append(asdev, record, record_len);
		AUDIT_SDEV_UNLOCK(asdev);
	}
	AUDIT_SDEV_LIST_RUNLOCK();

	/* Unlocked increment. */
	audit_sdev_records++;
}

/*
 * Allocate a new audit sdev.  Connects the sdev, on succes, to the global
 * list and updates statistics.
 */
static struct audit_sdev *
audit_sdev_alloc(void)
{
	struct audit_sdev *asdev;

	AUDIT_SDEV_LIST_WLOCK_ASSERT();

	asdev = malloc(sizeof (*asdev), M_AUDIT_SDEV, M_WAITOK | M_ZERO);
	if (NULL == asdev)
		return (NULL);

	asdev->asdev_qlimit = AUDIT_SDEV_QLIMIT_DEFAULT;
	TAILQ_INIT(&asdev->asdev_queue);
	AUDIT_SDEV_LOCK_INIT(asdev);
	AUDIT_SDEV_SX_LOCK_INIT(asdev);
	cv_init(&asdev->asdev_cv, "audit_sdev_cv");

	/*
	 * Add to global list and update global statistics.
	 */
	TAILQ_INSERT_HEAD(&audit_sdev_list, asdev, asdev_list);
	audit_sdev_count++;
	audit_sdev_ever++;

	return (asdev);
}

/*
 * Flush all records currently present in an audit sdev.
 */
static void
audit_sdev_flush(struct audit_sdev *asdev)
{
	struct audit_sdev_entry *ase;

	AUDIT_SDEV_LOCK_ASSERT(asdev);

	while ((ase = TAILQ_FIRST(&asdev->asdev_queue)) != NULL) {
		TAILQ_REMOVE(&asdev->asdev_queue, ase, ase_queue);
		asdev->asdev_qbyteslen -= ase->ase_record_len;
		audit_sdev_entry_free(ase);
		asdev->asdev_qlen--;
	}
	asdev->asdev_qoffset = 0;

	KASSERT(0 == asdev->asdev_qlen, ("audit_sdev_flush: asdev_qlen"));
	KASSERT(0 == asdev->asdev_qbyteslen,
	    ("audit_sdev_flush: asdev_qbyteslen"));
}

/*
 * Free an audit sdev.
 */
static void
audit_sdev_free(struct audit_sdev *asdev)
{

	AUDIT_SDEV_LIST_WLOCK_ASSERT();
	AUDIT_SDEV_LOCK_ASSERT(asdev);

	/* XXXss - preselect hook here */
	audit_sdev_flush(asdev);
	cv_destroy(&asdev->asdev_cv);
	AUDIT_SDEV_SX_LOCK_DESTROY(asdev);
	AUDIT_SDEV_UNLOCK(asdev);
	AUDIT_SDEV_LOCK_DESTROY(asdev);

	TAILQ_REMOVE(&audit_sdev_list, asdev, asdev_list);
	free(asdev, M_AUDIT_SDEV);
	audit_sdev_count--;
}

/*
 * Get the auditinfo_addr of the proc and check to see if suser.  Will return
 * non-zero if not suser.
 */
static int
audit_sdev_get_aia(proc_t p, struct auditinfo_addr *aia_p)
{
	int error;
	kauth_cred_t scred;

	scred = kauth_cred_proc_ref(p);
	error = suser(scred, &p->p_acflag);

	if (NULL != aia_p)
		bcopy(scred->cr_audit.as_aia_p, aia_p, sizeof (*aia_p));
	kauth_cred_unref(&scred);

	return (error);
}

/*
 * Audit session dev open method.
 */
static int
audit_sdev_open(dev_t dev, __unused int flags,  __unused int devtype, proc_t p)
{
	struct audit_sdev *asdev;
	struct auditinfo_addr aia;
	int u;

	u = minor(dev);
	if (u < 0 || u > MAX_AUDIT_SDEVS)
		return (ENXIO);

	(void) audit_sdev_get_aia(p, &aia);

	AUDIT_SDEV_LIST_WLOCK();
	asdev = audit_sdev_dtab[u];
	if (NULL == asdev) {
		asdev = audit_sdev_alloc();
		if (NULL == asdev) {
			AUDIT_SDEV_LIST_WUNLOCK();
			return (ENOMEM);
		}
		audit_sdev_dtab[u] = asdev;
	} else {
		KASSERT(asdev->asdev_open, ("audit_sdev_open: Already open"));
		AUDIT_SDEV_LIST_WUNLOCK();
		return (EBUSY);
	}
	asdev->asdev_open = 1;
	asdev->asdev_auid = aia.ai_auid;
	asdev->asdev_asid = aia.ai_asid;
	asdev->asdev_flags = 0; 

	AUDIT_SDEV_LIST_WUNLOCK();

	return (0);
}

/*
 * Audit session dev close method.
 */
static int
audit_sdev_close(dev_t dev, __unused int flags, __unused int devtype,
    __unused proc_t p)
{
	struct audit_sdev *asdev;
	int u;

	u = minor(dev);
	asdev = audit_sdev_dtab[u];

	KASSERT(asdev != NULL, ("audit_sdev_close: asdev == NULL"));
	KASSERT(asdev->asdev_open, ("audit_sdev_close: !asdev_open"));

	AUDIT_SDEV_LIST_WLOCK();
	AUDIT_SDEV_LOCK(asdev);
	asdev->asdev_open = 0;
	audit_sdev_free(asdev);  /* sdev lock unlocked in audit_sdev_free() */
	audit_sdev_dtab[u] = NULL;
	AUDIT_SDEV_LIST_WUNLOCK();

	return (0);
}

/*
 * Audit session dev ioctl method.
 */
static int
audit_sdev_ioctl(dev_t dev, u_long cmd, caddr_t data,
    __unused int flag, proc_t p)
{
	struct audit_sdev *asdev;
	int error;

	asdev = audit_sdev_dtab[minor(dev)];
	KASSERT(asdev != NULL, ("audit_sdev_ioctl: asdev == NULL"));

	error = 0;

	switch (cmd) {
	case FIONBIO:
		AUDIT_SDEV_LOCK(asdev);
		if (*(int *)data)
			asdev->asdev_flags |= AUDIT_SDEV_NBIO;
		else
			asdev->asdev_flags &= ~AUDIT_SDEV_NBIO;
		AUDIT_SDEV_UNLOCK(asdev);
		break;

	case FIONREAD:
		AUDIT_SDEV_LOCK(asdev);
		*(int *)data = asdev->asdev_qbyteslen - asdev->asdev_qoffset;
		AUDIT_SDEV_UNLOCK(asdev);
		break;

	case AUDITSDEV_GET_QLEN:
		*(u_int *)data = asdev->asdev_qlen;
		break;

	case AUDITSDEV_GET_QLIMIT:
		*(u_int *)data = asdev->asdev_qlimit;
		break;

	case AUDITSDEV_SET_QLIMIT:
		if (*(u_int *)data >= AUDIT_SDEV_QLIMIT_MIN ||
		    *(u_int *)data <= AUDIT_SDEV_QLIMIT_MAX) {
			asdev->asdev_qlimit = *(u_int *)data;
		} else
			error = EINVAL;
		break;

	case AUDITSDEV_GET_QLIMIT_MIN:
		*(u_int *)data = AUDIT_SDEV_QLIMIT_MIN;
		break;

	case AUDITSDEV_GET_QLIMIT_MAX:
		*(u_int *)data = AUDIT_SDEV_QLIMIT_MAX;
		break;

	case AUDITSDEV_FLUSH:
		if (AUDIT_SDEV_SX_XLOCK_SIG(asdev) != 0)
			return (EINTR);
		AUDIT_SDEV_LOCK(asdev);
		audit_sdev_flush(asdev);
		AUDIT_SDEV_UNLOCK(asdev);
		AUDIT_SDEV_SX_XUNLOCK(asdev);
		break;

	case AUDITSDEV_GET_MAXDATA:
		*(u_int *)data = MAXAUDITDATA;
		break;

	/* XXXss these should be 64 bit, maybe. */
	case AUDITSDEV_GET_INSERTS:
		*(u_int *)data = asdev->asdev_inserts;
		break;

	case AUDITSDEV_GET_READS:
		*(u_int *)data = asdev->asdev_reads;
		break;

	case AUDITSDEV_GET_DROPS:
		*(u_int *)data = asdev->asdev_drops;
		break;

	case AUDITSDEV_GET_ALLSESSIONS:
		error = audit_sdev_get_aia(p, NULL);
		if (error)
			break;
		*(u_int *)data = (asdev->asdev_flags & AUDIT_SDEV_ALLSESSIONS) ?
		    1 : 0;
		break;

	case AUDITSDEV_SET_ALLSESSIONS:
		error = audit_sdev_get_aia(p, NULL);
		if (error)
			break;

		AUDIT_SDEV_LOCK(asdev);
		if (*(int *)data)
			asdev->asdev_flags |= AUDIT_SDEV_ALLSESSIONS;
		else
			asdev->asdev_flags &= ~AUDIT_SDEV_ALLSESSIONS;
		AUDIT_SDEV_UNLOCK(asdev);
		break;

	default:
		error = ENOTTY;
	}

	return (error);
}

/*
 * Audit session dev read method. 
 */
static int
audit_sdev_read(dev_t dev, struct uio *uio, __unused int flag)
{
	struct audit_sdev_entry *ase;
	struct audit_sdev *asdev;
	u_int toread;
	int error;

	asdev = audit_sdev_dtab[minor(dev)];
	KASSERT(NULL != asdev, ("audit_sdev_read: asdev == NULL"));

	/*
	 * We hold a sleep lock over read and flush because we rely on the
	 * stability of a record in the queue during uiomove.
	 */
	if (0 != AUDIT_SDEV_SX_XLOCK_SIG(asdev))
		return (EINTR);
	AUDIT_SDEV_LOCK(asdev);
	while (TAILQ_EMPTY(&asdev->asdev_queue)) {
		if (asdev->asdev_flags & AUDIT_SDEV_NBIO) {
			AUDIT_SDEV_UNLOCK(asdev);
			AUDIT_SDEV_SX_XUNLOCK(asdev);
			return (EAGAIN);
		}
		error = cv_wait_sig(&asdev->asdev_cv, AUDIT_SDEV_MTX(asdev));
		if (error) {
			AUDIT_SDEV_UNLOCK(asdev);
			AUDIT_SDEV_SX_XUNLOCK(asdev);
			return (error);
		}
	}

	/*
	 * Copy as many remaining bytes from the current record to userspace
	 * as we can. Keep processing records until we run out of records in
	 * the queue or until the user buffer runs out of space.
	 *
	 * We rely on the sleep lock to maintain ase's stability here.
	 */
	asdev->asdev_reads++;
	while ((ase = TAILQ_FIRST(&asdev->asdev_queue)) != NULL &&
	    uio_resid(uio) > 0) {
		AUDIT_SDEV_LOCK_ASSERT(asdev);

		KASSERT(ase->ase_record_len > asdev->asdev_qoffset,
		    ("audit_sdev_read: record_len > qoffset (1)"));
		toread = MIN((int)(ase->ase_record_len - asdev->asdev_qoffset),
		    uio_resid(uio));
		AUDIT_SDEV_UNLOCK(asdev);
		error = uiomove((char *) ase->ase_record + asdev->asdev_qoffset,
		    toread, uio);
		if (error) {
			AUDIT_SDEV_SX_XUNLOCK(asdev);
			return (error);
		}

		/*
		 * If the copy succeeded then update book-keeping, and if no
		 * bytes remain in the current record then free it.
		 */
		AUDIT_SDEV_LOCK(asdev);
		KASSERT(TAILQ_FIRST(&asdev->asdev_queue) == ase,
		    ("audit_sdev_read: queue out of sync after uiomove"));
		asdev->asdev_qoffset += toread;
		KASSERT(ase->ase_record_len >= asdev->asdev_qoffset,
		     ("audit_sdev_read: record_len >= qoffset (2)"));
		 if (asdev->asdev_qoffset == ase->ase_record_len) {
			 TAILQ_REMOVE(&asdev->asdev_queue, ase, ase_queue);
			 asdev->asdev_qbyteslen -= ase->ase_record_len;
			 audit_sdev_entry_free(ase);
			 asdev->asdev_qlen--;
			 asdev->asdev_qoffset = 0;
		 }
	}
	AUDIT_SDEV_UNLOCK(asdev);
	AUDIT_SDEV_SX_XUNLOCK(asdev);
	return (0);
}

/*
 * Audit session device poll method.
 */
static int
audit_sdev_poll(dev_t dev, int events, void *wql, struct proc *p)
{
	struct audit_sdev *asdev;
	int revents;

	revents = 0;
	asdev = audit_sdev_dtab[minor(dev)];
	KASSERT(NULL != asdev, ("audit_sdev_poll: asdev == NULL"));

	if (events & (POLLIN | POLLRDNORM)) {
		AUDIT_SDEV_LOCK(asdev);
		if (NULL != TAILQ_FIRST(&asdev->asdev_queue))
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(p, &asdev->asdev_selinfo, wql);
		AUDIT_SDEV_UNLOCK(asdev);
	}
	return (revents);
}

/*
 * Audit sdev clone routine.  Provides a new minor number or returns -1.
 * This called with DEVFS_LOCK held.
 */
static int
audit_sdev_clone(__unused dev_t dev, int action)
{
	int i;

	if (DEVFS_CLONE_ALLOC == action) {
		for(i = 0; i < MAX_AUDIT_SDEVS; i++)
			if (NULL == audit_sdev_dtab[i])
				return (i);

		/* 
		 * This really should return -1 here but that seems to
		 * hang things in devfs.  We instead return 0 and let
		 * audit_sdev_open tell userland the bad news.
		 */
		return (0);
	}

	return (-1);
}

static int
audit_sdev_init(void)
{
	dev_t dev;

	TAILQ_INIT(&audit_sdev_list);
	AUDIT_SDEV_LIST_LOCK_INIT();

	audit_sdev_major = cdevsw_add(-1, &audit_sdev_cdevsw);
	if (audit_sdev_major < 0)
		return (KERN_FAILURE);

	dev = makedev(audit_sdev_major, 0);
	devnode = devfs_make_node_clone(dev, DEVFS_CHAR, UID_ROOT, GID_WHEEL,
	    0644, audit_sdev_clone, AUDIT_SDEV_NAME, 0);

	if (NULL == devnode)
		return (KERN_FAILURE);

	return (KERN_SUCCESS);
}

/* XXXss
static int
audit_sdev_shutdown(void)
{

	devfs_remove(devnode);
	(void) cdevsw_remove(audit_sdev_major, &audit_sdev_cdevsw);

	return (KERN_SUCCESS);
}
*/

#else

int
audit_session_self(proc_t p, struct audit_session_self_args *uap,
    mach_port_name_t *ret_port)
{
#pragma unused(p, uap, ret_port)

	return (ENOSYS);
}

int
audit_session_join(proc_t p, struct audit_session_join_args *uap,
    au_asid_t *ret_asid)
{
#pragma unused(p, uap, ret_asid)

	return (ENOSYS);
}

int
audit_session_port(proc_t p, struct audit_session_port_args *uap, int *retval)
{
#pragma unused(p, uap, retval)

	return (ENOSYS);
}

#endif /* CONFIG_AUDIT */
