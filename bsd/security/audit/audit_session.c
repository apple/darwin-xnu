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

#include <sys/kernel.h>
#include <sys/event.h>
#include <sys/kauth.h>
#include <sys/queue.h>
#include <sys/syscall.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/ucred.h>

#include <libkern/OSAtomic.h>

#include <bsm/audit.h>
#include <security/audit/audit.h>
#include <security/audit/audit_bsd.h>
#include <security/audit/audit_private.h>

#include <vm/vm_protos.h>
#include <kern/audit_sessionport.h>

kern_return_t ipc_object_copyin(ipc_space_t, mach_port_name_t,
    mach_msg_type_name_t, ipc_port_t *);
void ipc_port_release_send(ipc_port_t);

/*
 * The default auditinfo_addr entry for ucred.
 */
struct auditinfo_addr audit_default_aia = {
	.ai_auid = AU_DEFAUDITID,
	.ai_asid = AU_DEFAUDITSID,
	.ai_termid = { .at_type = AU_IPv4, },
};

#if CONFIG_AUDIT

/*
 * Currently the hash table is a fixed size.
 */
#define HASH_TABLE_SIZE		97
#define	HASH_ASID(asid)		(audit_session_hash(asid) % HASH_TABLE_SIZE)

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
	struct klist		se_klist;	/* Knotes for session */
	struct mtx		se_klist_mtx;	/* se_klist mutex */
	LIST_ENTRY(au_sentry)	se_link; 	/* Hash bucket link list (1) */
};
typedef struct au_sentry au_sentry_t;

#define	AU_SENTRY_PTR(aia_p)	((au_sentry_t *)(aia_p))

static struct rwlock	se_entry_lck;		/* (1) lock for se_link above */

LIST_HEAD(au_sentry_head, au_sentry);
static struct au_sentry_head *au_sentry_bucket = NULL;

/*
 * Audit Propagation Knote List is a list of kevent knotes that are assosiated
 * with an any ASID knote.  If the any ASID gets modified or deleted these are
 * modified or deleted as well.
 */
struct au_plist {
	struct knote		*pl_knote;	/* ptr to per-session knote */
	LIST_ENTRY(au_plist)	 pl_link;	/* list link (2) */
};
typedef struct au_plist	au_plist_t;

struct au_plisthead {
	struct rlck		ph_rlck;	 /* (2) lock for pl_link list */
	LIST_HEAD(au_plhead, au_plist)	ph_head; /* list head */
};
typedef struct au_plisthead	au_plisthead_t;

#define	EV_ANY_ASID	EV_FLAG0

MALLOC_DEFINE(M_AU_SESSION, "audit_session", "Audit session data");
MALLOC_DEFINE(M_AU_EV_PLIST, "audit_ev_plist", "Audit session event plist");

/*
 * Kevent filters.
 */
static int	audit_filt_sessionattach(struct knote *kn);
static void	audit_filt_sessiondetach(struct knote *kn);
static void	audit_filt_sessiontouch(struct knote *kn,
    struct kevent64_s *kev, long type);
static int	audit_filt_session(struct knote *kn, long hint);

static void	audit_register_kevents(uint32_t asid, uint32_t auid);

struct filterops audit_session_filtops = {
	.f_attach	=	audit_filt_sessionattach,
	.f_detach	=	audit_filt_sessiondetach,
	.f_touch	=	audit_filt_sessiontouch,
	.f_event	=	audit_filt_session,
};

/*
 * The klist for consumers that are interested in any session (ASID). This list
 * is not associated with any data structure but is used for registering
 * new kevents when sessions are created.  This klist is lock by
 * anyas_klist_mtx.
 */ 
static struct klist	anyas_klist;
struct mtx		anyas_klist_mtx;

#define	AUDIT_ANYAS_KLIST_LOCK_INIT()	mtx_init(&anyas_klist_mtx, \
					"audit anyas_klist_mtx", NULL, MTX_DEF)
#define	AUDIT_ANYAS_KLIST_LOCK()	mtx_lock(&anyas_klist_mtx)
#define	AUDIT_ANYAS_KLIST_UNLOCK()	mtx_unlock(&anyas_klist_mtx)
#define	AUDIT_ANYAS_KLIST_LOCK_ASSERT()	mtx_assert(&anyas_klist_mtx, MA_OWNED)

#define	AUDIT_SENTRY_RWLOCK_INIT()	rw_init(&se_entry_lck, \
					    "audit se_entry_lck")
#define	AUDIT_SENTRY_RLOCK()		rw_rlock(&se_entry_lck)
#define	AUDIT_SENTRY_WLOCK()		rw_wlock(&se_entry_lck)
#define	AUDIT_SENTRY_RWLOCK_ASSERT()	rw_assert(&se_entry_lck, RA_LOCKED)
#define	AUDIT_SENTRY_RUNLOCK()		rw_runlock(&se_entry_lck)
#define	AUDIT_SENTRY_WUNLOCK()		rw_wunlock(&se_entry_lck)

#define	AUDIT_SE_KLIST_LOCK_INIT(se, n)	mtx_init(&(se)->se_klist_mtx, \
						n, NULL, MTX_DEF)
#define	AUDIT_SE_KLIST_LOCK(se)		mtx_lock(&(se)->se_klist_mtx)
#define	AUDIT_SE_KLIST_UNLOCK(se)	mtx_unlock(&(se)->se_klist_mtx)
#define	AUDIT_SE_KLIST_LOCK_DESTROY(se)	mtx_destroy(&(se)->se_klist_mtx)
#define	AUDIT_SE_KLIST_LOCK_ASSERT(se)	mtx_assert(&(se)->se_klist_mtx, \
    						MA_OWNED)

#define	AUDIT_PLIST_LOCK_INIT(pl)	rlck_init(&(pl)->ph_rlck, \
					    "audit ph_rlck")
#define	AUDIT_PLIST_LOCK(pl)		rlck_lock(&(pl)->ph_rlck)
#define	AUDIT_PLIST_UNLOCK(pl)		rlck_unlock(&(pl)->ph_rlck)
#define	AUDIT_PLIST_LOCK_DESTROY(pl)	rlck_destroy(&(pl)->ph_rlck)

#if	AUDIT_SESSION_DEBUG
#include <kern/kalloc.h>

struct au_sentry_debug {
	auditinfo_addr_t	se_auinfo;
	long			se_refcnt;
	long			se_procnt;
};
typedef struct au_sentry_debug au_sentry_debug_t;

static int audit_sysctl_session_debug(struct sysctl_oid *oidp, void *arg1,
    int arg2, struct sysctl_req *req);

SYSCTL_PROC(_kern, OID_AUTO, audit_session_debug, CTLFLAG_RD, NULL, 0,
    audit_sysctl_session_debug, "S,audit_session_debug",
    "Current session debug info for auditing.");

/*
 * Copy out the session debug info via the sysctl interface.  The userland code
 * is something like the following:
 *
 * error = sysctlbyname("kern.audit_session_debug", buffer_ptr, &buffer_len,
 * 		NULL, 0);
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
	for(i = 0; i < HASH_TABLE_SIZE; i++) {
		LIST_FOREACH(se, &au_sentry_bucket[i], se_link) {
			if (se != NULL) {
				bcopy(se, next_sed, sizeof(next_sed));
				next_sed++;
				sz += sizeof(au_sentry_debug_t);
			}
		}
	}
	AUDIT_SENTRY_RUNLOCK();

	req->oldlen = sz;
	err = SYSCTL_OUT(req, sed_tab, sz);
	kfree(sed_tab, entry_cnt * sizeof(au_sentry_debug_t));

	return (err);
}

#endif /* AUDIT_SESSION_DEBUG */

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
 * if not found.
 */
static au_sentry_t *
audit_session_find(au_asid_t asid)
{
	uint32_t	 hkey;
	au_sentry_t	*found_se;

	AUDIT_SENTRY_RWLOCK_ASSERT();

	hkey = HASH_ASID(asid);

	LIST_FOREACH(found_se, &au_sentry_bucket[hkey], se_link)
		if (found_se->se_asid == asid)
			return (found_se);
	return (NULL);
}

/*
 * Call kqueue knote while holding the session entry klist lock.
 */
static void
audit_session_knote(au_sentry_t *se, long hint)
{

	AUDIT_SE_KLIST_LOCK(se);
	KNOTE(&se->se_klist, hint);
	AUDIT_SE_KLIST_UNLOCK(se);
}

/*
 * Remove the given audit_session entry from the hash table.
 */
static void
audit_session_remove(au_sentry_t *se)
{
	uint32_t	 hkey;
	au_sentry_t	*found_se, *tmp_se;

	KASSERT(se->se_refcnt == 0, ("audit_session_remove: ref count != 0"));	

	hkey = HASH_ASID(se->se_asid);

	AUDIT_SENTRY_WLOCK();
	LIST_FOREACH_SAFE(found_se, &au_sentry_bucket[hkey], se_link, tmp_se) {
		if (found_se == se) {

			audit_session_knote(found_se, NOTE_AS_CLOSE);

			LIST_REMOVE(found_se, se_link);
			AUDIT_SENTRY_WUNLOCK();
			AUDIT_SE_KLIST_LOCK_DESTROY(found_se);
			found_se->se_refcnt = 0;
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

	old_val = OSAddAtomicLong(-1, &se->se_procnt);
	if (old_val == 1)
		audit_session_knote(se, NOTE_AS_END);
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

	KASSERT(new_aia != &audit_default_aia, 
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
audit_session_new(auditinfo_addr_t *new_aia, int newprocess)
{
	au_asid_t asid;
	au_sentry_t *se = NULL;
	auditinfo_addr_t *aia = NULL;
	char nm[LOCK_MAX_NAME];
	
	KASSERT(new_aia != NULL, ("audit_session_new: new_aia == NULL"));

	asid = new_aia->ai_asid; 

#if 0  /* XXX this assertion is currently broken by securityd/LoginWindow */
	KASSERT((asid != AU_ASSIGN_ASID && asid <= PID_MAX),
	    ("audit_session_new: illegal ASID value: %d", asid));
#endif
	
	/*
	 * Alloc a new session entry now so we don't wait holding the lock.
	 */
	se = malloc(sizeof(au_sentry_t), M_AU_SESSION, M_WAITOK | M_ZERO);

	snprintf(nm, sizeof(nm), "audit se_klist_mtx %d", asid);
	AUDIT_SE_KLIST_LOCK_INIT(se, nm);

	/*
	 * Find an unique session ID, if desired.
	 */
	AUDIT_SENTRY_WLOCK();
	if (asid == AU_ASSIGN_ASID) {
		do {
			asid = (au_asid_t)audit_session_nextid();
		} while(audit_session_find(asid) != NULL);
	} else {
		au_sentry_t *found_se = NULL;

		/*
		 * Check to see if the requested ASID is already in the
		 * hash table.  If so, update it with the new auditinfo.
		 */	
		if ((found_se = audit_session_find(asid)) != NULL) {
			int updated;

			updated = audit_update_sentry(found_se, new_aia);
			audit_ref_session(found_se);

			AUDIT_SENTRY_WUNLOCK();
			AUDIT_SE_KLIST_LOCK_DESTROY(se);
			free(se, M_AU_SESSION);

			if (updated) 
				audit_session_knote(found_se, NOTE_AS_UPDATE);

			/*
			 * If this is a new process joining this session then
			 * we need to update the proc count.
			 */
			if (newprocess)
				audit_inc_procount(found_se);

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
	aia->ai_asid = asid;
	aia->ai_auid = new_aia->ai_auid;
	bzero(&new_aia->ai_mask, sizeof(new_aia->ai_mask));
	bcopy(&new_aia->ai_termid, &aia->ai_termid, sizeof(aia->ai_termid));
	aia->ai_flags = new_aia->ai_flags;

	/*
	 * Add it to the hash table.
	 */
	LIST_INSERT_HEAD(&au_sentry_bucket[HASH_ASID(asid)], se, se_link);
	AUDIT_SENTRY_WUNLOCK();

	/*
	 * Register kevents for consumers wanting events for any ASID
	 * and knote the event.
	 */
	audit_register_kevents(se->se_asid, se->se_auid);
	audit_session_knote(se, NOTE_AS_START);

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
	if (ret_aia != NULL)
		bcopy(&se->se_auinfo, ret_aia, sizeof(*ret_aia));
	AUDIT_SENTRY_RUNLOCK();

	return (0);
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

	if (IS_VALID_SESSION(aia_p))
		audit_ref_session(AU_SENTRY_PTR(aia_p));
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

	if (IS_VALID_SESSION(aia_p))
		audit_unref_session(AU_SENTRY_PTR(aia_p));
}

void
audit_session_procnew(kauth_cred_t cred)
{
	auditinfo_addr_t *aia_p;
	
	KASSERT(IS_VALID_CRED(cred), 
	    ("audit_session_procnew: Invalid kauth_cred."));

	aia_p = cred->cr_audit.as_aia_p; 

	if (IS_VALID_SESSION(aia_p))
		audit_inc_procount(AU_SENTRY_PTR(aia_p));
}

void
audit_session_procexit(kauth_cred_t cred)
{
	auditinfo_addr_t *aia_p;

	KASSERT(IS_VALID_CRED(cred), 
	    ("audit_session_procexit: Invalid kauth_cred."));

	aia_p = cred->cr_audit.as_aia_p; 

	if (IS_VALID_SESSION(aia_p))
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
	AUDIT_ANYAS_KLIST_LOCK_INIT();

	au_sentry_bucket = malloc( sizeof(struct au_sentry) *
	    HASH_TABLE_SIZE, M_AU_SESSION, M_WAITOK | M_ZERO);

	for (i = 0; i < HASH_TABLE_SIZE; i++)
		LIST_INIT(&au_sentry_bucket[i]);
}

/*
 * Allocate a new kevent propagation list (plist).
 */
static caddr_t
audit_new_plist(void)
{
	au_plisthead_t *plhead;

	plhead = malloc(sizeof(au_plisthead_t), M_AU_EV_PLIST, M_WAITOK |
	    M_ZERO);

	LIST_INIT(&plhead->ph_head);
	AUDIT_PLIST_LOCK_INIT(plhead);

	return ((caddr_t) plhead);
}

/*
 * Destroy a kevent propagation list (plist).  The anyas_klist_mtx mutex must be
 * held by the caller. 
 */
static void
audit_destroy_plist(struct knote *anyas_kn)
{
	au_plisthead_t *plhead;
	au_plist_t *plentry, *ple_tmp;
	struct kevent64_s kev;
	
	KASSERT(anyas_kn != NULL, ("audit_destroy_plist: anyas = NULL"));
	plhead = (au_plisthead_t *)anyas_kn->kn_hook;
	KASSERT(plhead != NULL, ("audit_destroy_plist: plhead = NULL"));

	/*
	 * Delete everything in the propagation list.
	 */
	AUDIT_PLIST_LOCK(plhead);
	LIST_FOREACH_SAFE(plentry, &plhead->ph_head, pl_link, ple_tmp) {
		struct kqueue *kq = plentry->pl_knote->kn_kq;

		kev.ident = plentry->pl_knote->kn_id;
		kev.filter = EVFILT_SESSION;
		kev.flags = EV_DELETE;

		/*
		 * The plist entry gets removed in rm_from_plist() which is
		 * called indirectly by kevent_register().
		 */
		kevent_register(kq, &kev, NULL);
	}
	AUDIT_PLIST_UNLOCK(plhead);

	/*
	 * Remove the head.
	 */
	AUDIT_PLIST_LOCK_DESTROY(plhead);
	free(plhead, M_AU_EV_PLIST);
}

/*
 * Add a knote pointer entry to the kevent propagation list.
 */
static void
audit_add_to_plist(struct knote *anyas_kn, struct knote *kn)
{
	au_plisthead_t *plhead;
	au_plist_t *plentry;

	KASSERT(anyas_kn != NULL, ("audit_add_to_plist: anyas = NULL"));
	plhead = (au_plisthead_t *)anyas_kn->kn_hook;
	KASSERT(plhead != NULL, ("audit_add_to_plist: plhead = NULL"));

	plentry = malloc(sizeof(au_plist_t), M_AU_EV_PLIST, M_WAITOK | M_ZERO);

	plentry->pl_knote = kn;
	AUDIT_PLIST_LOCK(plhead);
	LIST_INSERT_HEAD(&plhead->ph_head, plentry, pl_link);
	AUDIT_PLIST_UNLOCK(plhead);
}

/*
 * Remote a knote pointer entry from the kevent propagation list.  The lock
 * on the plist may already be head (by audit_destroy_plist() above) so we use
 * a recursive lock.
 */
static void
audit_rm_from_plist(struct knote *kn)
{
	struct knote *anyas_kn;
	au_plisthead_t *plhd;
	au_plist_t *plentry, *ple_tmp;

	KASSERT(kn != NULL, ("audit_rm_from_plist: kn = NULL"));
	anyas_kn = (struct knote *)kn->kn_hook;
	KASSERT(anyas_kn != NULL, ("audit_rm_to_plist: anyas = NULL"));
	plhd = (au_plisthead_t *)anyas_kn->kn_hook;

	AUDIT_PLIST_LOCK(plhd);
	LIST_FOREACH_SAFE(plentry, &plhd->ph_head, pl_link, ple_tmp) {
		if (plentry->pl_knote == kn) {
			LIST_REMOVE(plentry, pl_link);
			free(plentry, M_AU_EV_PLIST);
			AUDIT_PLIST_UNLOCK(plhd);
			return;
		}
	}
	AUDIT_PLIST_UNLOCK(plhd);
}

/*
 * The attach filter for EVFILT_SESSION.
 */
static int
audit_filt_sessionattach(struct knote *kn)
{
	au_sentry_t *se = NULL;

	/*
	 * Check flags for the events we currently support. 
	 */
	if ((kn->kn_sfflags & (NOTE_AS_START | NOTE_AS_END | NOTE_AS_CLOSE
		    | NOTE_AS_UPDATE | NOTE_AS_ERR)) == 0)
		return (ENOTSUP);

	/*
	 * If the interest is in any session then add to the any ASID knote
	 * list.  Otherwise, add it to the knote list assosiated with the
	 * given session.
	 */
	if (kn->kn_id == AS_ANY_ASID) {
		
		kn->kn_flags |= EV_CLEAR;
		kn->kn_ptr.p_se = NULL;

		/*
		 * Attach a kevent propagation list for any kevents that get
		 * added. 
		 */
		kn->kn_hook = audit_new_plist();
	
		AUDIT_ANYAS_KLIST_LOCK();
		KNOTE_ATTACH(&anyas_klist, kn);
		AUDIT_ANYAS_KLIST_UNLOCK();

		return (0);
	} else {

		/*
		 * NOTE: The anyas klist lock will be held in this
		 * part of the code when indirectly called from
		 * audit_register_kevents() below.
		 */

		/*
		 * Check to make sure it is a valid ASID.
		 */
		if (kn->kn_id > ASSIGNED_ASID_MAX)
			return (EINVAL);

		AUDIT_SENTRY_RLOCK();
		se = audit_session_find(kn->kn_id);
		AUDIT_SENTRY_RUNLOCK();
		if (se == NULL)
			return (EINVAL);

		AUDIT_SE_KLIST_LOCK(se);
		kn->kn_flags |= EV_CLEAR;
		kn->kn_ptr.p_se = se;

		/*
		 * If this attach is the result of an "any ASID" (pseudo)
		 * kevent then attach the any session knote ptr to this knote.
		 * Also, add this knote to the its propagation list.
		 */
		if (kn->kn_flags & EV_ANY_ASID) {
			struct knote *anyas_kn =
			    (struct knote *)((uintptr_t)kn->kn_kevent.ext[0]);
			kn->kn_hook = (caddr_t) anyas_kn;
			kn->kn_flags &= ~EV_ANY_ASID;
			audit_add_to_plist(anyas_kn, kn);
		} else
			kn->kn_hook = NULL;
		KNOTE_ATTACH(&se->se_klist, kn);
		AUDIT_SE_KLIST_UNLOCK(se);

		return (0);
	}
}

/*
 * The detach filter for EVFILT_SESSION.
 */
static void
audit_filt_sessiondetach(struct knote *kn)
{
	au_sentry_t *se = NULL;

	if (kn->kn_id == AS_ANY_ASID) {

		AUDIT_ANYAS_KLIST_LOCK();
		audit_destroy_plist(kn);
		KNOTE_DETACH(&anyas_klist, kn);
		AUDIT_ANYAS_KLIST_UNLOCK();

	} else {
		/*
		 * If this knote was created by any ASID kevent then remove
		 * from kevent propagation list.
		 */
		if (kn->kn_hook != NULL) {
			audit_rm_from_plist(kn);
			kn->kn_hook = NULL;
		}

		/*
		 * Check to see if already detached.
		 */
		se = kn->kn_ptr.p_se;
		if (se != NULL) {
			AUDIT_SE_KLIST_LOCK(se);
			kn->kn_ptr.p_se = NULL;
			KNOTE_DETACH(&se->se_klist, kn);
			AUDIT_SE_KLIST_UNLOCK(se);
		}
	}
}

/*
 * The touch filter for EVFILT_SESSION.  Check for any ASID kevent updates and
 * propagate the change.
 */
static void
audit_filt_sessiontouch(struct knote *kn, struct kevent64_s *kev, long type)
{
	struct knote *ple_kn;
	struct kqueue *kq;
	au_sentry_t *se;
	au_plisthead_t *plhead;
	au_plist_t *plentry;
	struct kevent64_s newkev;

	switch (type) {
	case EVENT_REGISTER:
		kn->kn_sfflags = kev->fflags;
		kn->kn_sdata = kev->data;
		/*
		 * If an any ASID kevent was updated then we may need to
		 * propagate the update.
		 */
		if (kev->ident == AS_ANY_ASID && kn->kn_hook != NULL) {

			/*
			 * Propagate the change to each of the session kevents
			 * that were created by this any ASID kevent.
			 */
			plhead = (au_plisthead_t *)kn->kn_hook;
			AUDIT_PLIST_LOCK(plhead);
			LIST_FOREACH(plentry, &plhead->ph_head, pl_link) {

				if ((ple_kn = plentry->pl_knote) == NULL)
					continue;
				if ((se = ple_kn->kn_ptr.p_se) == NULL)
					continue;
				if ((kq = ple_kn->kn_kq) == NULL)
					continue;

				newkev.ident = plentry->pl_knote->kn_id;
				newkev.filter = EVFILT_SESSION;
				newkev.flags = kev->flags;
				newkev.fflags = kev->fflags;
				newkev.data = kev->data;
				newkev.udata = kev->udata;
				kevent_register(kq, &newkev, NULL);
			}
			AUDIT_PLIST_UNLOCK(plhead);
		}
		break;

	case EVENT_PROCESS:
		*kev = kn->kn_kevent;
		if (kn->kn_flags & EV_CLEAR) {
			kn->kn_data = 0;
			kn->kn_fflags = 0;
		}
		break;

	default:
		KASSERT((type == EVENT_REGISTER || type == EVENT_PROCESS),
		    ("filt_sessiontouch(): invalid type (%ld)", type));
		break;
	}
}

/*
 * Event filter for EVFILT_SESSION.  The AUDIT_SE_KLIST_LOCK should be held
 * by audit_session_knote().
 */
static int
audit_filt_session(struct knote *kn, long hint)
{
	int events = (int)hint;
	au_sentry_t *se = kn->kn_ptr.p_se;

	if (hint != 0 && se != NULL) {

		if (kn->kn_sfflags & events) {
			kn->kn_fflags |= events;
			kn->kn_data = se->se_auid;
		}
		
		/*
		 * If this is the last possible event for the knote,
		 * detach the knote from the audit session before the
		 * session goes away.
		 */
		if (events & NOTE_AS_CLOSE) {

			/*
			 * If created by any ASID kevent then remove from 
			 * propagation list.
			 */
			if (kn->kn_hook != NULL) {
				audit_rm_from_plist(kn);
				kn->kn_hook = NULL;
			}
			kn->kn_flags |= (EV_EOF | EV_ONESHOT);
			kn->kn_ptr.p_se = NULL;
			AUDIT_SE_KLIST_LOCK_ASSERT(se);
			KNOTE_DETACH(&se->se_klist, kn);

			return (1);
		}
	}
	return (kn->kn_fflags != 0);
}

/*
 * For all the consumers wanting events for all sessions, register new
 * kevents associated with the session for the given ASID.  The actual
 * attachment is done by the EVFILT_SESSION attach filter above.
 */
static void
audit_register_kevents(uint32_t asid, uint32_t auid)
{
	struct knote *kn;

	AUDIT_ANYAS_KLIST_LOCK();
	SLIST_FOREACH(kn, &anyas_klist, kn_selnext) {
		struct kqueue *kq = kn->kn_kq;
		struct kevent64_s kev;
		int err;

		kev.ident = asid;
		kev.filter = EVFILT_SESSION;
		kev.flags = kn->kn_flags | EV_ADD | EV_ENABLE | EV_ANY_ASID;
		kev.fflags = kn->kn_sfflags;
		kev.data = auid;
		kev.udata = kn->kn_kevent.udata;

		/*
		 * Save the knote ptr for this "any ASID" knote for the attach
		 * filter.
		 */
		kev.ext[0] = (uint64_t)((uintptr_t)kn);

		/*
		 * XXX kevent_register() may block here alloc'ing a new knote.
		 * We may want to think about using a lockless linked list or
		 * at least a sleep rwlock for the anyas_klist.
		 */
		err = kevent_register(kq, &kev, NULL);
		if (err)
			kn->kn_fflags |= NOTE_AS_ERR;
	}
	AUDIT_ANYAS_KLIST_UNLOCK();
}

/*
 * Safely update kauth cred of the given process with new the given audit info. 
 * If the newprocess flag is set then we need to account for this process in
 * the proc count.
 */
int
audit_session_setaia(proc_t p, auditinfo_addr_t *aia_p, int newprocess)
{
	kauth_cred_t my_cred, my_new_cred;
	struct au_session  as;
	struct au_session  tmp_as;
	auditinfo_addr_t caia;

	/*
	 * If this is going to modify an existing session then do some
	 * immutable checks.
	 */
	if (audit_session_lookup(aia_p->ai_asid, &caia) == 0) {

		/* 
		 * If the current audit ID is not the default then it is
		 * immutable. 
		 */
		if (caia.ai_auid != AU_DEFAUDITID &&
		    caia.ai_auid != aia_p->ai_auid)
			return (EINVAL);

		/*
		 * If the current termid is not the default then it is
		 * immutable.
		 */
		if ((caia.ai_termid.at_type != AU_IPv4 || 
			caia.ai_termid.at_port != 0 || 
			caia.ai_termid.at_addr[0] != 0) &&
		    (caia.ai_termid.at_port != aia_p->ai_termid.at_port ||
		     caia.ai_termid.at_type != aia_p->ai_termid.at_type ||
		     bcmp(&caia.ai_termid.at_addr, &aia_p->ai_termid.at_addr,
			 sizeof (caia.ai_termid.at_addr) )) )
			return (EINVAL);

		/* The audit flags are immutable. */
		if (caia.ai_flags != aia_p->ai_flags)
			return (EINVAL);

		/* The audit masks are mutable. */
	}

	my_cred = kauth_cred_proc_ref(p);
	bcopy(&aia_p->ai_mask, &as.as_mask, sizeof(as.as_mask));
	as.as_aia_p = audit_session_new(aia_p, newprocess);

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
			proc_unlock(p);
		}
		/*
		 * Drop old proc reference or our extra reference.
		 */
		kauth_cred_unref(&my_cred);
		break;
	}
	audit_session_unref(my_new_cred);

	/*
	 * Propagate the change from the process to the Mach task.
	 */
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

	if ((sendport = audit_session_mksend(aia_p, &se->se_port)) == NULL) {
		/* failed to alloc new port */
		err = ENOMEM;
		goto done;
	}

	/*
	 * This reference on the session is unref'ed in
	 * audit_session_port_destory().  This reference is needed so the
	 * session doesn't get dropped until the session join is done.
	 */
	audit_ref_session(se);


done:
	if (cred != NULL)
		kauth_cred_unref(&cred);	
	if (err == 0)
		*ret_port = ipc_port_copyout_send(sendport,
		    get_task_ipcspace(p->task));
	else
		*ret_port = MACH_PORT_NULL;

	return (err);
}

void
audit_session_portaiadestroy(struct auditinfo_addr *port_aia_p)
{
	au_sentry_t *se;

	KASSERT(port_aia_p != NULL,
	    ("audit_session_infodestroy: port_aia_p = NULL"));

	se = AU_SENTRY_PTR(port_aia_p);

	/*
	 * Drop the reference added in audit_session_self().
	 */
	if (se != NULL) {
		se->se_port = IPC_PORT_NULL;
		audit_unref_session(se);
	}

}

static int
audit_session_join_internal(proc_t p, ipc_port_t port, au_asid_t *new_asid)
{
	auditinfo_addr_t *port_aia_p, *old_aia_p;
	kauth_cred_t cred = NULL;
	au_asid_t old_asid;
	int err = 0;

	*new_asid = AU_DEFAUDITSID;

	if ((port_aia_p = audit_session_porttoaia(port)) == NULL) {
		err = EINVAL;
		goto done;
	}
	*new_asid = port_aia_p->ai_asid;

	cred = kauth_cred_proc_ref(p);
	if (!IS_VALID_CRED(cred)) {
		kauth_cred_unref(&cred);	
		err = ESRCH;
		goto done;
	}
	old_aia_p = cred->cr_audit.as_aia_p;
	old_asid = old_aia_p->ai_asid;

	/*
	 * Add process in if not already in the session.
	 */
	if (*new_asid != old_asid) {
		audit_session_setaia(p, port_aia_p, 1);
		/*
		 * If this process was in a valid session before then we
		 * need to decrement the process count of the session it
		 * came from.
		 */
		if (IS_VALID_SESSION(old_aia_p))
			audit_dec_procount(AU_SENTRY_PTR(old_aia_p));
	}
	kauth_cred_unref(&cred);	

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
 * Returns:	*ret_asid	Audit session ID of new session, which may
 * 				be AU_DEFAUDITSID in the failure case.
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

#endif /* CONFIG_AUDIT */
