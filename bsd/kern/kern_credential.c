/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */

/*
 * Kernel Authorization framework: Management of process/thread credentials and identity information.
 */


#include <sys/param.h>	/* XXX trim includes */
#include <sys/acct.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/proc_internal.h>
#include <sys/user.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <sys/malloc.h>
#include <sys/kauth.h>
#include <sys/kernel.h>

#include <bsm/audit_kernel.h>

#include <sys/mount.h>
#include <sys/sysproto.h>
#include <mach/message.h>
#include <mach/host_security.h>

#include <libkern/OSAtomic.h>

#include <kern/task.h>
#include <kern/lock.h>
#ifdef MACH_ASSERT
# undef MACH_ASSERT
#endif
#define MACH_ASSERT 1	/* XXX so bogus */
#include <kern/assert.h>

#define CRED_DIAGNOSTIC 1

# define NULLCRED_CHECK(_c)	do {if (((_c) == NOCRED) || ((_c) == FSCRED)) panic("bad credential %p", _c);} while(0)

/*
 * Interface to external identity resolver.
 *
 * The architecture of the interface is simple; the external resolver calls in to
 * get work, then calls back with completed work.  It also calls us to let us know
 * that it's (re)started, so that we can resubmit work if it times out.
 */

static lck_mtx_t *kauth_resolver_mtx;
#define KAUTH_RESOLVER_LOCK()	lck_mtx_lock(kauth_resolver_mtx);
#define KAUTH_RESOLVER_UNLOCK()	lck_mtx_unlock(kauth_resolver_mtx);

static volatile pid_t	kauth_resolver_identity;
static int	kauth_resolver_registered;
static uint32_t	kauth_resolver_sequence;

struct kauth_resolver_work {
	TAILQ_ENTRY(kauth_resolver_work) kr_link;
	struct kauth_identity_extlookup kr_work;
	uint32_t	kr_seqno;
	int		kr_refs;
	int		kr_flags;
#define KAUTH_REQUEST_UNSUBMITTED	(1<<0)
#define KAUTH_REQUEST_SUBMITTED		(1<<1)
#define KAUTH_REQUEST_DONE		(1<<2)
	int		kr_result;
};

TAILQ_HEAD(kauth_resolver_unsubmitted_head, kauth_resolver_work) kauth_resolver_unsubmitted;
TAILQ_HEAD(kauth_resolver_submitted_head, kauth_resolver_work)	kauth_resolver_submitted;
TAILQ_HEAD(kauth_resolver_done_head, kauth_resolver_work)	kauth_resolver_done;

static int	kauth_resolver_submit(struct kauth_identity_extlookup *lkp);
static int	kauth_resolver_complete(user_addr_t message);
static int	kauth_resolver_getwork(user_addr_t message);

#define KAUTH_CRED_PRIMES_COUNT 7
static const int kauth_cred_primes[KAUTH_CRED_PRIMES_COUNT] = {97, 241, 397, 743, 1499, 3989, 7499};
static int	kauth_cred_primes_index = 0;
static int	kauth_cred_table_size = 0;

TAILQ_HEAD(kauth_cred_entry_head, ucred);
static struct kauth_cred_entry_head * kauth_cred_table_anchor = NULL;

#define KAUTH_CRED_HASH_DEBUG 0

static int kauth_cred_add(kauth_cred_t new_cred);
static void kauth_cred_remove(kauth_cred_t cred);
static inline u_long kauth_cred_hash(const uint8_t *datap, int data_len, u_long start_key);
static u_long kauth_cred_get_hashkey(kauth_cred_t cred);
static kauth_cred_t kauth_cred_update(kauth_cred_t old_cred, kauth_cred_t new_cred, boolean_t retain_auditinfo);

#if KAUTH_CRED_HASH_DEBUG
static int	kauth_cred_count = 0;
static void kauth_cred_hash_print(void);
static void kauth_cred_print(kauth_cred_t cred);
#endif

void
kauth_resolver_init(void)
{
	TAILQ_INIT(&kauth_resolver_unsubmitted);
	TAILQ_INIT(&kauth_resolver_submitted);
	TAILQ_INIT(&kauth_resolver_done);
	kauth_resolver_sequence = 31337;
	kauth_resolver_mtx = lck_mtx_alloc_init(kauth_lck_grp, 0/*LCK_ATTR_NULL*/);
}

/*
 * Allocate a work queue entry, submit the work and wait for completion.
 *
 * XXX do we want an 'interruptible' flag vs. always being interruptible?
 */
static int
kauth_resolver_submit(struct kauth_identity_extlookup *lkp)
{
	struct kauth_resolver_work *workp, *killp;
	struct timespec ts;
	int	error, shouldfree;
	
	/* no point actually blocking if the resolver isn't up yet */
	if (kauth_resolver_identity == 0) {
		/*
		 * We've already waited an initial 30 seconds with no result.
		 * Sleep on a stack address so no one wakes us before timeout;
		 * we sleep a half a second in case we are a high priority
		 * process, so that memberd doesn't starve while we are in a
		 * tight loop between user and kernel, eating all the CPU.
		 */
		error = tsleep(&ts, PZERO | PCATCH, "kr_submit", hz/2);
		if (kauth_resolver_identity == 0) {
			/*
			 * if things haven't changed while we were asleep,
			 * tell the caller we couldn't get an authoritative
			 * answer.
			 */
			return(EWOULDBLOCK);
		}
	}
		
	MALLOC(workp, struct kauth_resolver_work *, sizeof(*workp), M_KAUTH, M_WAITOK);
	if (workp == NULL)
		return(ENOMEM);

	workp->kr_work = *lkp;
	workp->kr_refs = 1;
	workp->kr_flags = KAUTH_REQUEST_UNSUBMITTED;
	workp->kr_result = 0;

	/*
	 * We insert the request onto the unsubmitted queue, the call in from the
	 * resolver will it to the submitted thread when appropriate.
	 */
	KAUTH_RESOLVER_LOCK();
	workp->kr_seqno = workp->kr_work.el_seqno = kauth_resolver_sequence++;
	workp->kr_work.el_result = KAUTH_EXTLOOKUP_INPROG;

	/* XXX as an optimisation, we could check the queue for identical items and coalesce */
	TAILQ_INSERT_TAIL(&kauth_resolver_unsubmitted, workp, kr_link);

	wakeup_one((caddr_t)&kauth_resolver_unsubmitted);
	for (;;) {
		/* we could compute a better timeout here */
		ts.tv_sec = 30;
		ts.tv_nsec = 0;
		error = msleep(workp, kauth_resolver_mtx, PCATCH, "kr_submit", &ts);
		/* request has been completed? */
		if ((error == 0) && (workp->kr_flags & KAUTH_REQUEST_DONE))
			break;
		/* woken because the resolver has died? */
		if (kauth_resolver_identity == 0) {
			error = EIO;
			break;
		}
		/* an error? */
		if (error != 0)
			break;
	}
	/* if the request was processed, copy the result */
	if (error == 0)
		*lkp = workp->kr_work;
	
	/*
	 * If the request timed out and was never collected, the resolver is dead and
	 * probably not coming back anytime soon.  In this case we revert to no-resolver
	 * behaviour, and punt all the other sleeping requests to clear the backlog.
	 */
	if ((error == EWOULDBLOCK) && (workp->kr_flags & KAUTH_REQUEST_UNSUBMITTED)) {
		KAUTH_DEBUG("RESOLVER - request timed out without being collected for processing, resolver dead");
		kauth_resolver_identity = 0;
		/* kill all the other requestes that are waiting as well */
		TAILQ_FOREACH(killp, &kauth_resolver_submitted, kr_link)
		    wakeup(killp);
		TAILQ_FOREACH(killp, &kauth_resolver_unsubmitted, kr_link)
		    wakeup(killp);
	}
	
	/* drop our reference on the work item, and note whether we should free it or not */
	if (--workp->kr_refs <= 0) {
		/* work out which list we have to remove it from */
		if (workp->kr_flags & KAUTH_REQUEST_DONE) {
			TAILQ_REMOVE(&kauth_resolver_done, workp, kr_link);
		} else if (workp->kr_flags & KAUTH_REQUEST_SUBMITTED) {
			TAILQ_REMOVE(&kauth_resolver_submitted, workp, kr_link);
		} else if (workp->kr_flags & KAUTH_REQUEST_UNSUBMITTED) {
			TAILQ_REMOVE(&kauth_resolver_unsubmitted, workp, kr_link);
		} else {
			KAUTH_DEBUG("RESOLVER - completed request has no valid queue");
		}
		shouldfree = 1;
	} else {
		/* someone else still has a reference on this request */
		shouldfree = 0;
	}
	/* collect request result */
	if (error == 0)
		error = workp->kr_result;
	KAUTH_RESOLVER_UNLOCK();
	/*
	 * If we dropped the last reference, free the request.
	 */
	if (shouldfree)
		FREE(workp, M_KAUTH);

	KAUTH_DEBUG("RESOLVER - returning %d", error);
	return(error);
}

/*
 * System call interface for the external identity resolver.
 */
int
identitysvc(__unused struct proc *p, struct identitysvc_args *uap, __unused register_t *retval)
{
	int opcode = uap->opcode;
	user_addr_t message = uap->message;
	struct kauth_resolver_work *workp;
	int error;
	pid_t new_id;

	/*
	 * New server registering itself.
	 */
	if (opcode == KAUTH_EXTLOOKUP_REGISTER) {
		new_id = current_proc()->p_pid;
		if ((error = kauth_authorize_generic(kauth_cred_get(), KAUTH_GENERIC_ISSUSER)) != 0) {
			KAUTH_DEBUG("RESOLVER - pid %d refused permission to become identity resolver", new_id);
			return(error);
		}
		KAUTH_RESOLVER_LOCK();
		if (kauth_resolver_identity != new_id) {
			KAUTH_DEBUG("RESOLVER - new resolver %d taking over from old %d", new_id, kauth_resolver_identity);
			/*
			 * We have a new server, so assume that all the old requests have been lost.
			 */
			while ((workp = TAILQ_LAST(&kauth_resolver_submitted, kauth_resolver_submitted_head)) != NULL) {
				TAILQ_REMOVE(&kauth_resolver_submitted, workp, kr_link);
				workp->kr_flags &= ~KAUTH_REQUEST_SUBMITTED;
				workp->kr_flags |= KAUTH_REQUEST_UNSUBMITTED;
				TAILQ_INSERT_HEAD(&kauth_resolver_unsubmitted, workp, kr_link);
			}
			kauth_resolver_identity = new_id;
			kauth_resolver_registered = 1;
			wakeup(&kauth_resolver_unsubmitted);
		}
		KAUTH_RESOLVER_UNLOCK();
		return(0);
	}

	/*
	 * Beyond this point, we must be the resolver process.
	 */
	if (current_proc()->p_pid != kauth_resolver_identity) {
		KAUTH_DEBUG("RESOLVER - call from bogus resolver %d\n", current_proc()->p_pid);
		return(EPERM);
	}
	
	/*
	 * Got a result returning?
	 */
	if (opcode & KAUTH_EXTLOOKUP_RESULT) {
		if ((error = kauth_resolver_complete(message)) != 0)
			return(error);
	}

	/*
	 * Caller wants to take more work?
	 */
	if (opcode & KAUTH_EXTLOOKUP_WORKER) {
		if ((error = kauth_resolver_getwork(message)) != 0)
			return(error);
	}

	return(0);
}

/*
 * Get work for a caller.
 */
static int
kauth_resolver_getwork(user_addr_t message)
{
	struct kauth_resolver_work *workp;
	int		error;

	KAUTH_RESOLVER_LOCK();
	error = 0;
	while ((workp = TAILQ_FIRST(&kauth_resolver_unsubmitted)) == NULL) {
		error = msleep(&kauth_resolver_unsubmitted, kauth_resolver_mtx, PCATCH, "GRGetWork", 0);
		if (error != 0)
			break;
	}
	if (workp != NULL) {
		if ((error = copyout(&workp->kr_work, message, sizeof(workp->kr_work))) != 0) {
			KAUTH_DEBUG("RESOLVER - error submitting work to resolve");
			goto out;
		}
		TAILQ_REMOVE(&kauth_resolver_unsubmitted, workp, kr_link);
		workp->kr_flags &= ~KAUTH_REQUEST_UNSUBMITTED;
		workp->kr_flags |= KAUTH_REQUEST_SUBMITTED;
		TAILQ_INSERT_TAIL(&kauth_resolver_submitted, workp, kr_link);
	}

out:
	KAUTH_RESOLVER_UNLOCK();
	return(error);
}

/*
 * Return a result from userspace.
 */
static int
kauth_resolver_complete(user_addr_t message)
{
	struct kauth_identity_extlookup	extl;
	struct kauth_resolver_work *workp;
	int error, result;

	if ((error = copyin(message, &extl, sizeof(extl))) != 0) {
		KAUTH_DEBUG("RESOLVER - error getting completed work\n");
		return(error);
	}

	KAUTH_RESOLVER_LOCK();

	error = 0;
	result = 0;
	switch (extl.el_result) {
	case KAUTH_EXTLOOKUP_INPROG:
	{
		static int once = 0;

		/* XXX this should go away once memberd is updated */
		if (!once) {
			printf("kauth_resolver: memberd is not setting valid result codes (assuming always successful)\n");
			once = 1;
		}
	}
	/* FALLTHROUGH */
	case KAUTH_EXTLOOKUP_SUCCESS:
		break;

	case KAUTH_EXTLOOKUP_FATAL:
		/* fatal error means the resolver is dead */
		KAUTH_DEBUG("RESOLVER - resolver %d died, waiting for a new one", kauth_resolver_identity);
		kauth_resolver_identity = 0;
		/* XXX should we terminate all outstanding requests? */
		error = EIO;
		break;
	case KAUTH_EXTLOOKUP_BADRQ:
		KAUTH_DEBUG("RESOLVER - resolver reported invalid request %d", extl.el_seqno);
		result = EINVAL;
		break;
	case KAUTH_EXTLOOKUP_FAILURE:
		KAUTH_DEBUG("RESOLVER - resolver reported transient failure for request %d", extl.el_seqno);
		result = EIO;
		break;
	default:
		KAUTH_DEBUG("RESOLVER - resolver returned unexpected status %d", extl.el_result);
		result = EIO;
		break;
	}

	/*
	 * In the case of a fatal error, we assume that the resolver will restart
	 * quickly and re-collect all of the outstanding requests.  Thus, we don't
	 * complete the request which returned the fatal error status.
	 */
	if (extl.el_result != KAUTH_EXTLOOKUP_FATAL) {
		/* scan our list for this request */
		TAILQ_FOREACH(workp, &kauth_resolver_submitted, kr_link) {
			/* found it? */
			if (workp->kr_seqno == extl.el_seqno) {
				/* copy result */
				workp->kr_work = extl;
				/* move onto completed list and wake up requester(s) */
				TAILQ_REMOVE(&kauth_resolver_submitted, workp, kr_link);
				workp->kr_flags &= ~KAUTH_REQUEST_SUBMITTED;
				workp->kr_flags |= KAUTH_REQUEST_DONE;
				workp->kr_result = result;
				TAILQ_INSERT_TAIL(&kauth_resolver_done, workp, kr_link);
				wakeup(workp);
				break;
			}
		}
	}
	/*
	 * Note that it's OK for us not to find anything; if the request has
	 * timed out the work record will be gone.
	 */
	KAUTH_RESOLVER_UNLOCK();
	
	return(error);
}


/*
 * Identity cache.
 */

struct kauth_identity {
	TAILQ_ENTRY(kauth_identity) ki_link;
	int	ki_valid;
#define	KI_VALID_UID	(1<<0)		/* UID and GID are mutually exclusive */
#define KI_VALID_GID	(1<<1)
#define KI_VALID_GUID	(1<<2)
#define KI_VALID_NTSID	(1<<3)
	uid_t	ki_uid;
	gid_t	ki_gid;
	guid_t	ki_guid;
	ntsid_t ki_ntsid;
	/*
	 * Expiry times are the earliest time at which we will disregard the cached state and go to
	 * userland.  Before then if the valid bit is set, we will return the cached value.  If it's
	 * not set, we will not go to userland to resolve, just assume that there is no answer
	 * available.
	 */
	time_t	ki_guid_expiry;
	time_t	ki_ntsid_expiry;
};

static TAILQ_HEAD(kauth_identity_head, kauth_identity) kauth_identities;
#define KAUTH_IDENTITY_CACHEMAX		100	/* XXX sizing? */
static int kauth_identity_count;

static lck_mtx_t *kauth_identity_mtx;
#define KAUTH_IDENTITY_LOCK()	lck_mtx_lock(kauth_identity_mtx);
#define KAUTH_IDENTITY_UNLOCK()	lck_mtx_unlock(kauth_identity_mtx);


static struct kauth_identity *kauth_identity_alloc(uid_t uid, gid_t gid, guid_t *guidp, time_t guid_expiry,
    ntsid_t *ntsidp, time_t ntsid_expiry);
static void	kauth_identity_register(struct kauth_identity *kip);
static void	kauth_identity_updatecache(struct kauth_identity_extlookup *elp, struct kauth_identity *kip);
static void	kauth_identity_lru(struct kauth_identity *kip);
static int	kauth_identity_guid_expired(struct kauth_identity *kip);
static int	kauth_identity_ntsid_expired(struct kauth_identity *kip);
static int	kauth_identity_find_uid(uid_t uid, struct kauth_identity *kir);
static int	kauth_identity_find_gid(gid_t gid, struct kauth_identity *kir);
static int	kauth_identity_find_guid(guid_t *guidp, struct kauth_identity *kir);
static int	kauth_identity_find_ntsid(ntsid_t *ntsid, struct kauth_identity *kir);

void
kauth_identity_init(void)
{
	TAILQ_INIT(&kauth_identities);
	kauth_identity_mtx = lck_mtx_alloc_init(kauth_lck_grp, 0/*LCK_ATTR_NULL*/);
}

static int
kauth_identity_resolve(__unused struct kauth_identity_extlookup *el)
{
	return(kauth_resolver_submit(el));
}

static struct kauth_identity *
kauth_identity_alloc(uid_t uid, gid_t gid, guid_t *guidp, time_t guid_expiry, ntsid_t *ntsidp, time_t ntsid_expiry)
{
	struct kauth_identity *kip;
	
	/* get and fill in a new identity */
	MALLOC(kip, struct kauth_identity *, sizeof(*kip), M_KAUTH, M_WAITOK | M_ZERO);
	if (kip != NULL) {
		if (gid != KAUTH_GID_NONE) {
			kip->ki_gid = gid;
			kip->ki_valid = KI_VALID_GID;
		}
		if (uid != KAUTH_UID_NONE) {
			if (kip->ki_valid & KI_VALID_GID)
				panic("can't allocate kauth identity with both uid and gid");
			kip->ki_uid = uid;
			kip->ki_valid = KI_VALID_UID;
		}
		if (guidp != NULL) {
			kip->ki_guid = *guidp;
			kip->ki_valid |= KI_VALID_GUID;
		}
		kip->ki_guid_expiry = guid_expiry;
		if (ntsidp != NULL) {
			kip->ki_ntsid = *ntsidp;
			kip->ki_valid |= KI_VALID_NTSID;
		}
		kip->ki_ntsid_expiry = ntsid_expiry;
	}
	return(kip);
}

/*
 * Register an association between identity tokens.
 */
static void
kauth_identity_register(struct kauth_identity *kip)
{
	struct kauth_identity *ip;

	/*
	 * We search the cache for the UID listed in the incoming association.  If we
	 * already have an entry, the new information is merged.
	 */
	ip = NULL;
	KAUTH_IDENTITY_LOCK();
	if (kip->ki_valid & KI_VALID_UID) {
		if (kip->ki_valid & KI_VALID_GID)
			panic("kauth_identity: can't insert record with both UID and GID as key");
		TAILQ_FOREACH(ip, &kauth_identities, ki_link)
		    if ((ip->ki_valid & KI_VALID_UID) && (ip->ki_uid == kip->ki_uid))
				break;
	} else if (kip->ki_valid & KI_VALID_GID) {
		TAILQ_FOREACH(ip, &kauth_identities, ki_link)
		    if ((ip->ki_valid & KI_VALID_GID) && (ip->ki_gid == kip->ki_gid))
				break;
	} else {
		panic("kauth_identity: can't insert record without UID or GID as key");
	}
		
	if (ip != NULL) {
		/* we already have an entry, merge/overwrite */
		if (kip->ki_valid & KI_VALID_GUID) {
			ip->ki_guid = kip->ki_guid;
			ip->ki_valid |= KI_VALID_GUID;
		}
		ip->ki_guid_expiry = kip->ki_guid_expiry;
		if (kip->ki_valid & KI_VALID_NTSID) {
			ip->ki_ntsid = kip->ki_ntsid;
			ip->ki_valid |= KI_VALID_NTSID;
		}
		ip->ki_ntsid_expiry = kip->ki_ntsid_expiry;
		/* and discard the incoming identity */
		FREE(kip, M_KAUTH);
		ip = NULL;
	} else {
		/* don't have any information on this identity, so just add it */
		TAILQ_INSERT_HEAD(&kauth_identities, kip, ki_link);
		if (++kauth_identity_count > KAUTH_IDENTITY_CACHEMAX) {
			ip = TAILQ_LAST(&kauth_identities, kauth_identity_head);
			TAILQ_REMOVE(&kauth_identities, ip, ki_link);
			kauth_identity_count--;
		}
	}
	KAUTH_IDENTITY_UNLOCK();
	/* have to drop lock before freeing expired entry */
	if (ip != NULL)
		FREE(ip, M_KAUTH);
}

/*
 * Given a lookup result, add any associations that we don't
 * currently have.
 */
static void
kauth_identity_updatecache(struct kauth_identity_extlookup *elp, struct kauth_identity *rkip)
{
	struct timeval tv;
	struct kauth_identity *kip;

	microuptime(&tv);
	
	/* user identity? */
	if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_UID) {
		KAUTH_IDENTITY_LOCK();
		TAILQ_FOREACH(kip, &kauth_identities, ki_link) {
			/* matching record */
			if ((kip->ki_valid & KI_VALID_UID) && (kip->ki_uid == elp->el_uid)) {
				if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_UGUID) {
					kip->ki_guid = elp->el_uguid;
					kip->ki_valid |= KI_VALID_GUID;
				}
				kip->ki_guid_expiry = tv.tv_sec + elp->el_uguid_valid;
				if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_USID) {
					kip->ki_ntsid = elp->el_usid;
					kip->ki_valid |= KI_VALID_NTSID;
				}
				kip->ki_ntsid_expiry = tv.tv_sec + elp->el_usid_valid;
				kauth_identity_lru(kip);
				if (rkip != NULL)
					*rkip = *kip;
				KAUTH_DEBUG("CACHE - refreshed %d is " K_UUID_FMT, kip->ki_uid, K_UUID_ARG(kip->ki_guid));
				break;
			}
		}
		KAUTH_IDENTITY_UNLOCK();
		/* not found in cache, add new record */
		if (kip == NULL) {
			kip = kauth_identity_alloc(elp->el_uid, KAUTH_GID_NONE,
			    (elp->el_flags & KAUTH_EXTLOOKUP_VALID_UGUID) ? &elp->el_uguid : NULL,
			    tv.tv_sec + elp->el_uguid_valid,
			    (elp->el_flags & KAUTH_EXTLOOKUP_VALID_USID) ? &elp->el_usid : NULL,
			    tv.tv_sec + elp->el_usid_valid);
			if (kip != NULL) {
				if (rkip != NULL)
					*rkip = *kip;
				KAUTH_DEBUG("CACHE - learned %d is " K_UUID_FMT, kip->ki_uid, K_UUID_ARG(kip->ki_guid));
				kauth_identity_register(kip);
			}
		}
	}

	/* group identity? */
	if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_GID) {
		KAUTH_IDENTITY_LOCK();
		TAILQ_FOREACH(kip, &kauth_identities, ki_link) {
			/* matching record */
			if ((kip->ki_valid & KI_VALID_GID) && (kip->ki_gid == elp->el_gid)) {
				if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_GGUID) {
					kip->ki_guid = elp->el_gguid;
					kip->ki_valid |= KI_VALID_GUID;
				}
				kip->ki_guid_expiry = tv.tv_sec + elp->el_gguid_valid;
				if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_GSID) {
					kip->ki_ntsid = elp->el_gsid;
					kip->ki_valid |= KI_VALID_NTSID;
				}
				kip->ki_ntsid_expiry = tv.tv_sec + elp->el_gsid_valid;
				kauth_identity_lru(kip);
				if (rkip != NULL)
					*rkip = *kip;
				KAUTH_DEBUG("CACHE - refreshed %d is " K_UUID_FMT, kip->ki_uid, K_UUID_ARG(kip->ki_guid));
				break;
			}
		}
		KAUTH_IDENTITY_UNLOCK();
		/* not found in cache, add new record */
		if (kip == NULL) {
			kip = kauth_identity_alloc(KAUTH_UID_NONE, elp->el_gid,
			    (elp->el_flags & KAUTH_EXTLOOKUP_VALID_GGUID) ? &elp->el_gguid : NULL,
			    tv.tv_sec + elp->el_gguid_valid,
			    (elp->el_flags & KAUTH_EXTLOOKUP_VALID_GSID) ? &elp->el_gsid : NULL,
			    tv.tv_sec + elp->el_gsid_valid);
			if (kip != NULL) {
				if (rkip != NULL)
					*rkip = *kip;
				KAUTH_DEBUG("CACHE - learned %d is " K_UUID_FMT, kip->ki_uid, K_UUID_ARG(kip->ki_guid));
				kauth_identity_register(kip);
			}
		}
	}

}

/*
 * Promote the entry to the head of the LRU, assumes the cache is locked.
 *
 * This is called even if the entry has expired; typically an expired entry
 * that's been looked up is about to be revalidated, and having it closer to
 * the head of the LRU means finding it quickly again when the revalidation
 * comes through.
 */
static void
kauth_identity_lru(struct kauth_identity *kip)
{
	if (kip != TAILQ_FIRST(&kauth_identities)) {
		TAILQ_REMOVE(&kauth_identities, kip, ki_link);
		TAILQ_INSERT_HEAD(&kauth_identities, kip, ki_link);
	}
}

/*
 * Handly lazy expiration of translations.
 */
static int
kauth_identity_guid_expired(struct kauth_identity *kip)
{
	struct timeval tv;

	microuptime(&tv);
	KAUTH_DEBUG("CACHE - GUID expires @ %d now %d", kip->ki_guid_expiry, tv.tv_sec);
	return((kip->ki_guid_expiry <= tv.tv_sec) ? 1 : 0);
}

static int
kauth_identity_ntsid_expired(struct kauth_identity *kip)
{
	struct timeval tv;

	microuptime(&tv);
	KAUTH_DEBUG("CACHE - NTSID expires @ %d now %d", kip->ki_ntsid_expiry, tv.tv_sec);
	return((kip->ki_ntsid_expiry <= tv.tv_sec) ? 1 : 0);
}

/*
 * Search for an entry by UID.  Returns a copy of the entry, ENOENT if no valid
 * association exists for the UID.
 */
static int
kauth_identity_find_uid(uid_t uid, struct kauth_identity *kir)
{
	struct kauth_identity *kip;

	KAUTH_IDENTITY_LOCK();
	TAILQ_FOREACH(kip, &kauth_identities, ki_link) {
		if ((kip->ki_valid & KI_VALID_UID) && (uid == kip->ki_uid)) {
			kauth_identity_lru(kip);
			*kir = *kip;
			break;
		}
	}
	KAUTH_IDENTITY_UNLOCK();
	return((kip == NULL) ? ENOENT : 0);
}


/*
 * Search for an entry by GID. Returns a copy of the entry, ENOENT if no valid
 * association exists for the GID.
 */
static int
kauth_identity_find_gid(uid_t gid, struct kauth_identity *kir)
{
	struct kauth_identity *kip;

	KAUTH_IDENTITY_LOCK();
	TAILQ_FOREACH(kip, &kauth_identities, ki_link) {
		if ((kip->ki_valid & KI_VALID_GID) && (gid == kip->ki_gid)) {
			kauth_identity_lru(kip);
			*kir = *kip;
			break;
		}
	}
	KAUTH_IDENTITY_UNLOCK();
	return((kip == NULL) ? ENOENT : 0);
}


/*
 * Search for an entry by GUID. Returns a copy of the entry, ENOENT if no valid
 * association exists for the GUID.  Note that the association may be expired,
 * in which case the caller may elect to call out to userland to revalidate.
 */
static int
kauth_identity_find_guid(guid_t *guidp, struct kauth_identity *kir)
{
	struct kauth_identity *kip;

	KAUTH_IDENTITY_LOCK();
	TAILQ_FOREACH(kip, &kauth_identities, ki_link) {
		if ((kip->ki_valid & KI_VALID_GUID) && (kauth_guid_equal(guidp, &kip->ki_guid))) {
			kauth_identity_lru(kip);
			*kir = *kip;
			break;
		}
	}
	KAUTH_IDENTITY_UNLOCK();
	return((kip == NULL) ? ENOENT : 0);
}

/*
 * Search for an entry by NT Security ID. Returns a copy of the entry, ENOENT if no valid
 * association exists for the SID.  Note that the association may be expired,
 * in which case the caller may elect to call out to userland to revalidate.
 */
static int
kauth_identity_find_ntsid(ntsid_t *ntsid, struct kauth_identity *kir)
{
	struct kauth_identity *kip;

	KAUTH_IDENTITY_LOCK();
	TAILQ_FOREACH(kip, &kauth_identities, ki_link) {
		if ((kip->ki_valid & KI_VALID_NTSID) && (kauth_ntsid_equal(ntsid, &kip->ki_ntsid))) {
			kauth_identity_lru(kip);
			*kir = *kip;
			break;
		}
	}
	KAUTH_IDENTITY_UNLOCK();
	return((kip == NULL) ? ENOENT : 0);
}

/*
 * GUID handling.
 */
guid_t kauth_null_guid;

int
kauth_guid_equal(guid_t *guid1, guid_t *guid2)
{
	return(!bcmp(guid1, guid2, sizeof(*guid1)));
}

/*
 * Look for well-known GUIDs.
 */
int
kauth_wellknown_guid(guid_t *guid)
{
	static char	fingerprint[] = {0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef};
	int		code;
	/*
	 * All WKGs begin with the same 12 bytes.
	 */
	if (!bcmp((void *)guid, fingerprint, 12)) {
		/*
		 * The final 4 bytes are our code.
		 */
		code = *(u_int32_t *)&guid->g_guid[12];
		switch(code) {
		case 0x0000000c:
			return(KAUTH_WKG_EVERYBODY);
		case 0xfffffffe:
			return(KAUTH_WKG_NOBODY);
		case 0x0000000a:
			return(KAUTH_WKG_OWNER);
		case 0x00000010:
			return(KAUTH_WKG_GROUP);
		}
	}
	return(KAUTH_WKG_NOT);
}


/*
 * NT Security Identifier handling.
 */
int
kauth_ntsid_equal(ntsid_t *sid1, ntsid_t *sid2)
{
	/* check sizes for equality, also sanity-check size while we're at it */
	if ((KAUTH_NTSID_SIZE(sid1) == KAUTH_NTSID_SIZE(sid2)) &&
	    (KAUTH_NTSID_SIZE(sid1) <= sizeof(*sid1)) &&
	    !bcmp(sid1, sid2, KAUTH_NTSID_SIZE(sid1)))
		return(1);
	return(0);
}

/*
 * Identity KPI
 *
 * We support four tokens representing identity:
 *  - Credential reference
 *  - UID
 *  - GUID
 *  - NT security identifier
 *
 * Of these, the UID is the ubiquitous identifier; cross-referencing should
 * be done using it.
 */

static int	kauth_cred_cache_lookup(int from, int to, void *src, void *dst);

/*
 * Fetch UID from credential.
 */
uid_t
kauth_cred_getuid(kauth_cred_t cred)
{
	NULLCRED_CHECK(cred);
	return(cred->cr_uid);
}

/*
 * Fetch GID from credential.
 */
uid_t
kauth_cred_getgid(kauth_cred_t cred)
{
	NULLCRED_CHECK(cred);
	return(cred->cr_gid);
}

/*
 * Fetch UID from GUID.
 */
int
kauth_cred_guid2uid(guid_t *guidp, uid_t *uidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_GUID, KI_VALID_UID, guidp, uidp));
}

/*
 * Fetch GID from GUID.
 */
int
kauth_cred_guid2gid(guid_t *guidp, gid_t *gidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_GUID, KI_VALID_GID, guidp, gidp));
}

/*
 * Fetch UID from NT SID.
 */
int
kauth_cred_ntsid2uid(ntsid_t *sidp, uid_t *uidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_NTSID, KI_VALID_UID, sidp, uidp));
}

/*
 * Fetch GID from NT SID.
 */
int
kauth_cred_ntsid2gid(ntsid_t *sidp, gid_t *gidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_NTSID, KI_VALID_GID, sidp, gidp));
}

/*
 * Fetch GUID from NT SID.
 */
int
kauth_cred_ntsid2guid(ntsid_t *sidp, guid_t *guidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_NTSID, KI_VALID_GUID, sidp, guidp));
}

/*
 * Fetch GUID from UID.
 */
int
kauth_cred_uid2guid(uid_t uid, guid_t *guidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_UID, KI_VALID_GUID, &uid, guidp));
}

/*
 * Fetch user GUID from credential.
 */
int
kauth_cred_getguid(kauth_cred_t cred, guid_t *guidp)
{
	NULLCRED_CHECK(cred);
	return(kauth_cred_uid2guid(kauth_cred_getuid(cred), guidp));
}

/*
 * Fetch GUID from GID.
 */
int
kauth_cred_gid2guid(gid_t gid, guid_t *guidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_GID, KI_VALID_GUID, &gid, guidp));
}

/*
 * Fetch NT SID from UID.
 */
int
kauth_cred_uid2ntsid(uid_t uid, ntsid_t *sidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_UID, KI_VALID_NTSID, &uid, sidp));
}

/*
 * Fetch NT SID from credential.
 */
int
kauth_cred_getntsid(kauth_cred_t cred, ntsid_t *sidp)
{
	NULLCRED_CHECK(cred);
	return(kauth_cred_uid2ntsid(kauth_cred_getuid(cred), sidp));
}

/*
 * Fetch NT SID from GID.
 */
int
kauth_cred_gid2ntsid(gid_t gid, ntsid_t *sidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_GID, KI_VALID_NTSID, &gid, sidp));
}

/*
 * Fetch NT SID from GUID.
 */
int
kauth_cred_guid2ntsid(guid_t *guidp, ntsid_t *sidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_GUID, KI_VALID_NTSID, guidp, sidp));
}



/*
 * Lookup a translation in the cache.
 */
static int
kauth_cred_cache_lookup(int from, int to, void *src, void *dst)
{
	struct kauth_identity ki;
	struct kauth_identity_extlookup el;
	int error;
	int (* expired)(struct kauth_identity *kip);

	KAUTH_DEBUG("CACHE - translate %d to %d", from, to);
	
	/*
	 * Look for an existing cache entry for this association.
	 * If the entry has not expired, return the cached information.
	 */
	ki.ki_valid = 0;
	switch(from) {
	case KI_VALID_UID:
		error = kauth_identity_find_uid(*(uid_t *)src, &ki);
		break;
	case KI_VALID_GID:
		error = kauth_identity_find_gid(*(gid_t *)src, &ki);
		break;
	case KI_VALID_GUID:
		error = kauth_identity_find_guid((guid_t *)src, &ki);
		break;
	case KI_VALID_NTSID:
		error = kauth_identity_find_ntsid((ntsid_t *)src, &ki);
		break;
	default:
		return(EINVAL);
	}
	/* lookup failure or error */
	if (error != 0) {
		/* any other error is fatal */
		if (error != ENOENT) {
			KAUTH_DEBUG("CACHE - cache search error %d", error);
			return(error);
		}
	} else {
		/* do we have a translation? */
		if (ki.ki_valid & to) {
			/* found a valid cached entry, check expiry */
			switch(to) {
			case KI_VALID_GUID:
				expired = kauth_identity_guid_expired;
				break;
			case KI_VALID_NTSID:
				expired = kauth_identity_ntsid_expired;
				break;
			default:
				switch(from) {
				case KI_VALID_GUID:
					expired = kauth_identity_guid_expired;
					break;
				case KI_VALID_NTSID:
					expired = kauth_identity_ntsid_expired;
					break;
				default:
					expired = NULL;
				}
			}
			KAUTH_DEBUG("CACHE - found matching entry with valid %d", ki.ki_valid);
			/*
			 * If no expiry function, or not expired, we have found
			 * a hit.
			 */
			if (!expired) {
				KAUTH_DEBUG("CACHE - no expiry function");
				goto found;
			}
			if (!expired(&ki)) {
				KAUTH_DEBUG("CACHE - entry valid, unexpired");
				goto found;
			}
			/*
			 * We leave ki_valid set here; it contains a translation but the TTL has
			 * expired.  If we can't get a result from the resolver, we will
			 * use it as a better-than nothing alternative.
			 */
			KAUTH_DEBUG("CACHE - expired entry found");
		}
	}

	/*
	 * Call the resolver.  We ask for as much data as we can get.
	 */
	switch(from) {
	case KI_VALID_UID:
		el.el_flags = KAUTH_EXTLOOKUP_VALID_UID;
		el.el_uid = *(uid_t *)src;
		break;
	case KI_VALID_GID:
		el.el_flags = KAUTH_EXTLOOKUP_VALID_GID;
		el.el_gid = *(gid_t *)src;
		break;
	case KI_VALID_GUID:
		el.el_flags = KAUTH_EXTLOOKUP_VALID_UGUID | KAUTH_EXTLOOKUP_VALID_GGUID;
		el.el_uguid = *(guid_t *)src;
		el.el_gguid = *(guid_t *)src;
		break;
	case KI_VALID_NTSID:
		el.el_flags = KAUTH_EXTLOOKUP_VALID_USID | KAUTH_EXTLOOKUP_VALID_GSID;
		el.el_usid = *(ntsid_t *)src;
		el.el_gsid = *(ntsid_t *)src;
		break;
	default:
		return(EINVAL);
	}
	/*
	 * Here we ask for everything all at once, to avoid having to work
	 * out what we really want now, or might want soon.
	 *
	 * Asking for SID translations when we don't know we need them right
	 * now is going to cause excess work to be done if we're connected
	 * to a network that thinks it can translate them.  This list needs
	 * to get smaller/smarter.
	 */
	el.el_flags |= KAUTH_EXTLOOKUP_WANT_UID | KAUTH_EXTLOOKUP_WANT_GID |
	    KAUTH_EXTLOOKUP_WANT_UGUID | KAUTH_EXTLOOKUP_WANT_GGUID |
	    KAUTH_EXTLOOKUP_WANT_USID | KAUTH_EXTLOOKUP_WANT_GSID;
	KAUTH_DEBUG("CACHE - calling resolver for %x", el.el_flags);
	error = kauth_identity_resolve(&el);
	KAUTH_DEBUG("CACHE - resolver returned %d", error);
	/* was the lookup successful? */
	if (error == 0) {
		/*
		 * Save the results from the lookup - may have other information even if we didn't
		 * get a guid.
		 */
		kauth_identity_updatecache(&el, &ki);
	}
	/*
	 * Check to see if we have a valid result.
	 */
	if (!error && !(ki.ki_valid & to))
		error = ENOENT;
	if (error)
		return(error);
found:
	switch(to) {
	case KI_VALID_UID:
		*(uid_t *)dst = ki.ki_uid;
		break;
	case KI_VALID_GID:
		*(gid_t *)dst = ki.ki_gid;
		break;
	case KI_VALID_GUID:
		*(guid_t *)dst = ki.ki_guid;
		break;
	case KI_VALID_NTSID:
		*(ntsid_t *)dst = ki.ki_ntsid;
		break;
	default:
		return(EINVAL);
	}
	KAUTH_DEBUG("CACHE - returned successfully");
	return(0);
}


/*
 * Group membership cache.
 *
 * XXX the linked-list implementation here needs to be optimized.
 */

struct kauth_group_membership {
	TAILQ_ENTRY(kauth_group_membership) gm_link;
	uid_t	gm_uid;		/* the identity whose membership we're recording */
	gid_t	gm_gid;		/* group of which they are a member */
	time_t	gm_expiry;	/* TTL for the membership */
	int	gm_flags;
#define KAUTH_GROUP_ISMEMBER	(1<<0)
};

TAILQ_HEAD(kauth_groups_head, kauth_group_membership) kauth_groups;
#define KAUTH_GROUPS_CACHEMAX		100	/* XXX sizing? */
static int kauth_groups_count;

static lck_mtx_t *kauth_groups_mtx;
#define KAUTH_GROUPS_LOCK()	lck_mtx_lock(kauth_groups_mtx);
#define KAUTH_GROUPS_UNLOCK()	lck_mtx_unlock(kauth_groups_mtx);

static int	kauth_groups_expired(struct kauth_group_membership *gm);
static void	kauth_groups_lru(struct kauth_group_membership *gm);
static void	kauth_groups_updatecache(struct kauth_identity_extlookup *el);

void
kauth_groups_init(void)
{
	TAILQ_INIT(&kauth_groups);
	kauth_groups_mtx = lck_mtx_alloc_init(kauth_lck_grp, 0/*LCK_ATTR_NULL*/);
}

static int
kauth_groups_expired(struct kauth_group_membership *gm)
{
	struct timeval tv;

	microuptime(&tv);
	return((gm->gm_expiry <= tv.tv_sec) ? 1 : 0);
}

static void
kauth_groups_lru(struct kauth_group_membership *gm)
{
	if (gm != TAILQ_FIRST(&kauth_groups)) {
		TAILQ_REMOVE(&kauth_groups, gm, gm_link);
		TAILQ_INSERT_HEAD(&kauth_groups, gm, gm_link);
	}
}

static void
kauth_groups_updatecache(struct kauth_identity_extlookup *el)
{
	struct kauth_group_membership *gm;
	struct timeval tv;
	
	/* need a valid response if we are to cache anything */
	if ((el->el_flags &
		(KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_GID | KAUTH_EXTLOOKUP_VALID_MEMBERSHIP)) !=
	    (KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_GID | KAUTH_EXTLOOKUP_VALID_MEMBERSHIP))
		return;

	microuptime(&tv);

	/* search for an existing record for this association before inserting */
	KAUTH_GROUPS_LOCK();
	TAILQ_FOREACH(gm, &kauth_groups, gm_link) {
		if ((el->el_uid == gm->gm_uid) &&
		    (el->el_gid == gm->gm_gid)) {
			if (el->el_flags & KAUTH_EXTLOOKUP_ISMEMBER) {
				gm->gm_flags |= KAUTH_GROUP_ISMEMBER;
			} else {
				gm->gm_flags &= ~KAUTH_GROUP_ISMEMBER;
			}
			gm->gm_expiry = el->el_member_valid + tv.tv_sec;
			kauth_groups_lru(gm);
			break;
		}
	}
	KAUTH_GROUPS_UNLOCK();

	/* if we found an entry to update, stop here */
	if (gm != NULL)
		return;

	/* allocate a new record */
	MALLOC(gm, struct kauth_group_membership *, sizeof(*gm), M_KAUTH, M_WAITOK);
	if (gm != NULL) {
		gm->gm_uid = el->el_uid;
		gm->gm_gid = el->el_gid;
		if (el->el_flags & KAUTH_EXTLOOKUP_ISMEMBER) {
			gm->gm_flags |= KAUTH_GROUP_ISMEMBER;
		} else {
			gm->gm_flags &= ~KAUTH_GROUP_ISMEMBER;
		}
		gm->gm_expiry = el->el_member_valid + tv.tv_sec;
	}		

	/*
	 * Insert the new entry.  Note that it's possible to race ourselves here
	 * and end up with duplicate entries in the list.  Wasteful, but harmless
	 * since the first into the list will never be looked up, and thus will
	 * eventually just fall off the end.
	 */
	KAUTH_GROUPS_LOCK();
	TAILQ_INSERT_HEAD(&kauth_groups, gm, gm_link);
	if (kauth_groups_count++ > KAUTH_GROUPS_CACHEMAX) {
		gm = TAILQ_LAST(&kauth_groups, kauth_groups_head);
		TAILQ_REMOVE(&kauth_groups, gm, gm_link);
		kauth_groups_count--;
	} else {
		gm = NULL;
	}
	KAUTH_GROUPS_UNLOCK();

	/* free expired cache entry */
	if (gm != NULL)
		FREE(gm, M_KAUTH);
}

/*
 * Group membership KPI
 */
/*
 * This function guarantees not to modify resultp when returning an error.
 */
int
kauth_cred_ismember_gid(kauth_cred_t cred, gid_t gid, int *resultp)
{
	struct kauth_group_membership *gm;
	struct kauth_identity_extlookup el;
	int i, error;

	/*
	 * Check the per-credential list of override groups.
	 *
	 * We can conditionalise this on cred->cr_gmuid == KAUTH_UID_NONE since
	 * the cache should be used for that case.
	 */
	for (i = 0; i < cred->cr_ngroups; i++) {
		if (gid == cred->cr_groups[i]) {
			*resultp = 1;
			return(0);
		}
	}

	/*
	 * If we don't have a UID for group membership checks, the in-cred list
	 * was authoritative and we can stop here.
	 */
	if (cred->cr_gmuid == KAUTH_UID_NONE) {
		*resultp = 0;
		return(0);
	}
		
	
	/*
	 * If the resolver hasn't checked in yet, we are early in the boot phase and
	 * the local group list is complete and authoritative.
	 */
	if (!kauth_resolver_registered) {
		*resultp = 0;
		return(0);
	}
	
	/* TODO: */
	/* XXX check supplementary groups */
	/* XXX check whiteout groups */
	/* XXX nesting of supplementary/whiteout groups? */

	/*
	 * Check the group cache.
	 */
	KAUTH_GROUPS_LOCK();
	TAILQ_FOREACH(gm, &kauth_groups, gm_link) {
		if ((gm->gm_uid == cred->cr_gmuid) && (gm->gm_gid == gid) && !kauth_groups_expired(gm)) {
			kauth_groups_lru(gm);
			break;
		}
	}

	/* did we find a membership entry? */
	if (gm != NULL)
		*resultp = (gm->gm_flags & KAUTH_GROUP_ISMEMBER) ? 1 : 0;
	KAUTH_GROUPS_UNLOCK();

	/* if we did, we can return now */
	if (gm != NULL)
		return(0);
	
	/* nothing in the cache, need to go to userland */
	el.el_flags = KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_GID | KAUTH_EXTLOOKUP_WANT_MEMBERSHIP;
	el.el_uid = cred->cr_gmuid;
	el.el_gid = gid;
	error = kauth_identity_resolve(&el);
	if (error != 0)
		return(error);
	/* save the results from the lookup */
	kauth_groups_updatecache(&el);

	/* if we successfully ascertained membership, report */
	if (el.el_flags & KAUTH_EXTLOOKUP_VALID_MEMBERSHIP) {
		*resultp = (el.el_flags & KAUTH_EXTLOOKUP_ISMEMBER) ? 1 : 0;
		return(0);
	}

	return(ENOENT);
}

/*
 * Determine whether the supplied credential is a member of the
 * group nominated by GUID.
 */
int
kauth_cred_ismember_guid(kauth_cred_t cred, guid_t *guidp, int *resultp)
{
	gid_t gid;
	int error, wkg;

	error = 0;
	wkg = kauth_wellknown_guid(guidp);
	switch(wkg) {
	case KAUTH_WKG_NOBODY:
		*resultp = 0;
		break;
	case KAUTH_WKG_EVERYBODY:
		*resultp = 1;
		break;
	default:
		/* translate guid to gid */
		if ((error = kauth_cred_guid2gid(guidp, &gid)) != 0) {
			/*
			 * If we have no guid -> gid translation, it's not a group and
			 * thus the cred can't be a member.
			 */
			if (error == ENOENT) {
				*resultp = 0;
				error = 0;
			}
		} else {
			error = kauth_cred_ismember_gid(cred, gid, resultp);
		}
	}
	return(error);
}

/*
 * Fast replacement for issuser()
 */
int
kauth_cred_issuser(kauth_cred_t cred)
{
	return(cred->cr_uid == 0);
}

/*
 * Credential KPI
 */

/* lock protecting credential hash table */
static lck_mtx_t *kauth_cred_hash_mtx;
#define KAUTH_CRED_HASH_LOCK()		lck_mtx_lock(kauth_cred_hash_mtx);
#define KAUTH_CRED_HASH_UNLOCK()	lck_mtx_unlock(kauth_cred_hash_mtx);

void
kauth_cred_init(void)
{
	int		i;
	
	kauth_cred_hash_mtx = lck_mtx_alloc_init(kauth_lck_grp, 0/*LCK_ATTR_NULL*/);
	kauth_cred_table_size = kauth_cred_primes[kauth_cred_primes_index];

	/*allocate credential hash table */
	MALLOC(kauth_cred_table_anchor, struct kauth_cred_entry_head *, 
			(sizeof(struct kauth_cred_entry_head) * kauth_cred_table_size), 
			M_KAUTH, M_WAITOK | M_ZERO);
	for (i = 0; i < kauth_cred_table_size; i++) {
		TAILQ_INIT(&kauth_cred_table_anchor[i]);
	}
}

/*
 * Return the current thread's effective UID.
 */
uid_t
kauth_getuid(void)
{
	return(kauth_cred_get()->cr_uid);
}

/*
 * Return the current thread's real UID.
 */
uid_t
kauth_getruid(void)
{
	return(kauth_cred_get()->cr_ruid);
}

/*
 * Return the current thread's effective GID.
 */
gid_t
kauth_getgid(void)
{
	return(kauth_cred_get()->cr_groups[0]);
}

/*
 * Return the current thread's real GID.
 */
gid_t
kauth_getrgid(void)
{
	return(kauth_cred_get()->cr_rgid);
}

/*
 * Returns a pointer to the current thread's credential, does not take a
 * reference (so the caller must not do anything that would let the thread's
 * credential change while using the returned value).
 */
kauth_cred_t
kauth_cred_get(void)
{
	struct proc *p;
	struct uthread *uthread;

	uthread = get_bsdthread_info(current_thread());
	/* sanity */
	if (uthread == NULL)
		panic("thread wants credential but has no BSD thread info");
	/*
	 * We can lazy-bind credentials to threads, as long as their processes have them.
	 * If we later inline this function, the code in this block should probably be
	 * called out in a function.
	 */
	if (uthread->uu_ucred == NOCRED) {
		if ((p = (proc_t) get_bsdtask_info(get_threadtask(current_thread()))) == NULL)
			panic("thread wants credential but has no BSD process");
		proc_lock(p);
		kauth_cred_ref(uthread->uu_ucred = p->p_ucred);
		proc_unlock(p);
	}
	return(uthread->uu_ucred);
}

/*
 * Returns a pointer to the current thread's credential, takes a reference.
 */
kauth_cred_t
kauth_cred_get_with_ref(void)
{
	struct proc *procp;
	struct uthread *uthread;

	uthread = get_bsdthread_info(current_thread());
	/* sanity checks */
	if (uthread == NULL)
		panic("%s - thread wants credential but has no BSD thread info", __FUNCTION__);
	if ((procp = (proc_t) get_bsdtask_info(get_threadtask(current_thread()))) == NULL)
		panic("%s - thread wants credential but has no BSD process", __FUNCTION__);

	/*
	 * We can lazy-bind credentials to threads, as long as their processes have them.
	 * If we later inline this function, the code in this block should probably be
	 * called out in a function.
	 */
	proc_lock(procp);
	if (uthread->uu_ucred == NOCRED) {
		/* take reference for new cred in thread */
		kauth_cred_ref(uthread->uu_ucred = proc_ucred(procp));
	}
	/* take a reference for our caller */
	kauth_cred_ref(uthread->uu_ucred);
	proc_unlock(procp);
	return(uthread->uu_ucred);
}

/*
 * Returns a pointer to the given process's credential, takes a reference.
 */
kauth_cred_t
kauth_cred_proc_ref(proc_t procp)
{
	kauth_cred_t 	cred;
	
	proc_lock(procp);
	cred = proc_ucred(procp);
	kauth_cred_ref(cred);
	proc_unlock(procp);
	return(cred);
}

/*
 * Allocates a new credential.
 */
kauth_cred_t
kauth_cred_alloc(void)
{
	kauth_cred_t newcred;
	
	MALLOC(newcred, kauth_cred_t, sizeof(*newcred), M_KAUTH, M_WAITOK | M_ZERO);
	if (newcred != 0) {
		newcred->cr_ref = 1;
		/* must do this, or cred has same group membership as uid 0 */
		newcred->cr_gmuid = KAUTH_UID_NONE;
#if CRED_DIAGNOSTIC
	} else {
		panic("kauth_cred_alloc: couldn't allocate credential");
#endif		
	}

#if KAUTH_CRED_HASH_DEBUG
	kauth_cred_count++;
#endif

	return(newcred);
}

/*
 * Looks to see if we already have a known credential and if found bumps the
 *	reference count and returns it.  If there are no credentials that match 
 *	the given credential then we allocate a new credential.
 *
 * Note that the gmuid is hard-defaulted to the UID specified.  Since we maintain
 * this field, we can't expect callers to know how it needs to be set.  Callers
 * should be prepared for this field to be overwritten.
 */
kauth_cred_t
kauth_cred_create(kauth_cred_t cred)
{
	kauth_cred_t 	found_cred, new_cred = NULL;

	cred->cr_gmuid = cred->cr_uid;
	
	for (;;) {
		KAUTH_CRED_HASH_LOCK();
		found_cred = kauth_cred_find(cred);
		if (found_cred != NULL) {
			/* found an existing credential so we'll bump reference count and return */
			kauth_cred_ref(found_cred);
			KAUTH_CRED_HASH_UNLOCK();
			return(found_cred);
		}
		KAUTH_CRED_HASH_UNLOCK();
	
		/* no existing credential found.  create one and add it to our hash table */
		new_cred = kauth_cred_alloc();
		if (new_cred != NULL) {
			int		err;
			new_cred->cr_uid = cred->cr_uid;
			new_cred->cr_ruid = cred->cr_ruid;
			new_cred->cr_svuid = cred->cr_svuid;
			new_cred->cr_rgid = cred->cr_rgid;
			new_cred->cr_svgid = cred->cr_svgid;
			new_cred->cr_gmuid = cred->cr_gmuid;
			new_cred->cr_ngroups = cred->cr_ngroups;	
			bcopy(&cred->cr_groups[0], &new_cred->cr_groups[0], sizeof(new_cred->cr_groups));
			KAUTH_CRED_HASH_LOCK();
			err = kauth_cred_add(new_cred);
			KAUTH_CRED_HASH_UNLOCK();
			
			/* retry if kauth_cred_add returns non zero value */
			if (err == 0)
				break;
			FREE(new_cred, M_KAUTH);
			new_cred = NULL;
		}
	}

	return(new_cred);
}

/*
 * Update the given credential using the uid argument.  The given uid is used
 *	set the effective user ID, real user ID, and saved user ID.  We only 
 *	allocate a new credential when the given uid actually results in changes to
 *	the existing credential.
 */
kauth_cred_t
kauth_cred_setuid(kauth_cred_t cred, uid_t uid)
{
	struct ucred temp_cred;

	NULLCRED_CHECK(cred);

	/* don't need to do anything if the effective, real and saved user IDs are
	 * already the same as the user ID passed in
	 */
	if (cred->cr_uid == uid && cred->cr_ruid == uid && cred->cr_svuid == uid) {
		/* no change needed */
		return(cred);
	}

	/* look up in cred hash table to see if we have a matching credential
	 * with new values.
	 */
	bcopy(cred, &temp_cred, sizeof(temp_cred));
	temp_cred.cr_uid = uid;
	temp_cred.cr_ruid = uid;
	temp_cred.cr_svuid = uid;
	temp_cred.cr_gmuid = uid;

	return(kauth_cred_update(cred, &temp_cred, TRUE));
}

/*
 * Update the given credential using the euid argument.  The given uid is used
 *	set the effective user ID.  We only allocate a new credential when the given 
 *	uid actually results in changes to the existing credential.
 */
kauth_cred_t
kauth_cred_seteuid(kauth_cred_t cred, uid_t euid)
{
	struct ucred temp_cred;

	NULLCRED_CHECK(cred);

	/* don't need to do anything if the given effective user ID is already the 
	 *	same as the effective user ID in the credential.
	 */
	if (cred->cr_uid == euid) {
		/* no change needed */
		return(cred);
	}

	/* look up in cred hash table to see if we have a matching credential
	 * with new values.
	 */
	bcopy(cred, &temp_cred, sizeof(temp_cred));
	temp_cred.cr_uid = euid;

	return(kauth_cred_update(cred, &temp_cred, TRUE));
}

/*
 * Update the given credential using the gid argument.  The given gid is used
 *	set the effective group ID, real group ID, and saved group ID.  We only 
 *	allocate a new credential when the given gid actually results in changes to
 *	the existing credential.
 */
kauth_cred_t
kauth_cred_setgid(kauth_cred_t cred, gid_t gid)
{
	struct ucred 	temp_cred;

	NULLCRED_CHECK(cred);

	/* don't need to do anything if the given group ID is already the 
	 *	same as the group ID in the credential.
	 */
	if (cred->cr_groups[0] == gid && cred->cr_rgid == gid && cred->cr_svgid == gid) {
		/* no change needed */
		return(cred);
	}

	/* look up in cred hash table to see if we have a matching credential
	 * with new values.
	 */
	bcopy(cred, &temp_cred, sizeof(temp_cred));
	temp_cred.cr_groups[0] = gid;
	temp_cred.cr_rgid = gid;
	temp_cred.cr_svgid = gid;

	return(kauth_cred_update(cred, &temp_cred, TRUE));
}

/*
 * Update the given credential using the egid argument.  The given gid is used
 *	set the effective user ID.  We only allocate a new credential when the given 
 *	gid actually results in changes to the existing credential.
 */
kauth_cred_t
kauth_cred_setegid(kauth_cred_t cred, gid_t egid)
{
	struct ucred temp_cred;

	NULLCRED_CHECK(cred);

	/* don't need to do anything if the given group ID is already the 
	 *	same as the group Id in the credential.
	 */
	if (cred->cr_groups[0] == egid) {
		/* no change needed */
		return(cred);
	}

	/* look up in cred hash table to see if we have a matching credential
	 * with new values.
	 */
	bcopy(cred, &temp_cred, sizeof(temp_cred));
	temp_cred.cr_groups[0] = egid;

	return(kauth_cred_update(cred, &temp_cred, TRUE));
}

/*
 * Update the given credential with the given groups.  We only allocate a new 
 *	credential when the given gid actually results in changes to the existing 
 *	credential.
 *	The gmuid argument supplies a new uid (or KAUTH_UID_NONE to opt out)
 *	which will be used for group membership checking.
 */
kauth_cred_t
kauth_cred_setgroups(kauth_cred_t cred, gid_t *groups, int groupcount, uid_t gmuid)
{
	int		i;
	struct ucred temp_cred;

	NULLCRED_CHECK(cred);

	/* don't need to do anything if the given list of groups does not change.
	 */
	if ((cred->cr_gmuid == gmuid) && (cred->cr_ngroups == groupcount)) {
		for (i = 0; i < groupcount; i++) {
			if (cred->cr_groups[i] != groups[i])
				break;
		}
		if (i == groupcount) {
			/* no change needed */
			return(cred);
		}
	}

	/* look up in cred hash table to see if we have a matching credential
	 * with new values.
	 */
	bcopy(cred, &temp_cred, sizeof(temp_cred));
	temp_cred.cr_ngroups = groupcount;
	bcopy(groups, temp_cred.cr_groups, sizeof(temp_cred.cr_groups));
	temp_cred.cr_gmuid = gmuid;

	return(kauth_cred_update(cred, &temp_cred, TRUE));
}

/*
 * Update the given credential using the uid and gid arguments.  The given uid 
 *	is used set the effective user ID, real user ID, and saved user ID.  
 * 	The given gid is used set the effective group ID, real group ID, and saved 
 *	group ID.
 *	We only allocate a new credential when the given uid and gid actually results 
 *	in changes to the existing credential.
 */
kauth_cred_t
kauth_cred_setuidgid(kauth_cred_t cred, uid_t uid, gid_t gid)
{
	struct ucred temp_cred;

	NULLCRED_CHECK(cred);

	/* don't need to do anything if the effective, real and saved user IDs are
	 * already the same as the user ID passed in
	 */
	if (cred->cr_uid == uid && cred->cr_ruid == uid && cred->cr_svuid == uid &&
		cred->cr_groups[0] == gid && cred->cr_rgid == gid && cred->cr_svgid == gid) {
		/* no change needed */
		return(cred);
	}

	/* look up in cred hash table to see if we have a matching credential
	 * with new values.
	 */
	bzero(&temp_cred, sizeof(temp_cred));
	temp_cred.cr_uid = uid;
	temp_cred.cr_ruid = uid;
	temp_cred.cr_svuid = uid;
	temp_cred.cr_gmuid = uid;
	temp_cred.cr_ngroups = 1;
	temp_cred.cr_groups[0] = gid;
	temp_cred.cr_rgid = gid;
	temp_cred.cr_svgid = gid;

	return(kauth_cred_update(cred, &temp_cred, TRUE));
}

/*
 * Update the given credential using the uid and gid arguments.  The given uid 
 *	is used to set the saved user ID.  The given gid is used to set the 
 *	saved group ID.
 *	We only allocate a new credential when the given uid and gid actually results 
 *	in changes to the existing credential.
 */
kauth_cred_t
kauth_cred_setsvuidgid(kauth_cred_t cred, uid_t uid, gid_t gid)
{
	struct ucred temp_cred;

	NULLCRED_CHECK(cred);

	/* don't need to do anything if the effective, real and saved user IDs are
	 * already the same as the user ID passed in
	 */
	if (cred->cr_svuid == uid && cred->cr_svgid == gid) {
		/* no change needed */
		return(cred);
	}

	/* look up in cred hash table to see if we have a matching credential
	 * with new values.
	 */
	bcopy(cred, &temp_cred, sizeof(temp_cred));
	temp_cred.cr_svuid = uid;
	temp_cred.cr_svgid = gid;

	return(kauth_cred_update(cred, &temp_cred, TRUE));
}

/*
 * Update the given credential using the given auditinfo_t.
 *	We only allocate a new credential when the given auditinfo_t actually results 
 *	in changes to the existing credential.
 */
kauth_cred_t
kauth_cred_setauditinfo(kauth_cred_t cred, auditinfo_t *auditinfo_p)
{
	struct ucred temp_cred;

	NULLCRED_CHECK(cred);

	/* don't need to do anything if the audit info is already the same as the 
	 * audit info in the credential passed in
	 */
	if (bcmp(&cred->cr_au, auditinfo_p, sizeof(cred->cr_au)) == 0) {
		/* no change needed */
		return(cred);
	}

	/* look up in cred hash table to see if we have a matching credential
	 * with new values.
	 */
	bcopy(cred, &temp_cred, sizeof(temp_cred));
	bcopy(auditinfo_p, &temp_cred.cr_au, sizeof(temp_cred.cr_au));

	return(kauth_cred_update(cred, &temp_cred, FALSE));
}

/*
 * Add a reference to the passed credential.
 */
void
kauth_cred_ref(kauth_cred_t cred)
{
	int		old_value;
	
	NULLCRED_CHECK(cred);

	old_value = OSAddAtomic(1, &cred->cr_ref);

	if (old_value < 1)
		panic("kauth_cred_ref: trying to take a reference on a cred with no references");
		
	return;
}

/*
 * Drop a reference from the passed credential, potentially destroying it.
 */
void
kauth_cred_rele(kauth_cred_t cred)
{
	int		old_value;

	NULLCRED_CHECK(cred);

	KAUTH_CRED_HASH_LOCK();
	old_value = OSAddAtomic(-1, &cred->cr_ref);

#if DIAGNOSTIC
	if (old_value == 0)
		panic("kauth_cred_rele: dropping a reference on a cred with no references");
#endif

	if (old_value < 3) {
		/* the last reference is our credential hash table */
		kauth_cred_remove(cred);
	}
	KAUTH_CRED_HASH_UNLOCK();
}

/*
 * Duplicate a credential.
 * 	NOTE - caller should call kauth_cred_add after any credential changes are made.
 */
kauth_cred_t
kauth_cred_dup(kauth_cred_t cred)
{
	kauth_cred_t newcred;
	
#if CRED_DIAGNOSTIC
	if (cred == NOCRED || cred == FSCRED)
		panic("kauth_cred_dup: bad credential");
#endif
	newcred = kauth_cred_alloc();
	if (newcred != NULL) {
		bcopy(cred, newcred, sizeof(*newcred));
		newcred->cr_ref = 1;
	}
	return(newcred);
}

/*
 * Returns a credential based on the passed credential but which
 * reflects the real rather than effective UID and GID.
 * NOTE - we do NOT decrement cred reference count on passed in credential
 */
kauth_cred_t
kauth_cred_copy_real(kauth_cred_t cred)
{
	kauth_cred_t newcred = NULL, found_cred;
	struct ucred temp_cred;

	/* if the credential is already 'real', just take a reference */
	if ((cred->cr_ruid == cred->cr_uid) &&
	    (cred->cr_rgid == cred->cr_gid)) {
		kauth_cred_ref(cred);
		return(cred);
	}

	/* look up in cred hash table to see if we have a matching credential
	 * with new values.
	 */
	bcopy(cred, &temp_cred, sizeof(temp_cred));
	temp_cred.cr_uid = cred->cr_ruid;
	temp_cred.cr_groups[0] = cred->cr_rgid;
	/* if the cred is not opted out, make sure we are using the r/euid for group checks */
	if (temp_cred.cr_gmuid != KAUTH_UID_NONE)
		temp_cred.cr_gmuid = cred->cr_ruid;

	for (;;) {
		int		err;
		
		KAUTH_CRED_HASH_LOCK();
		found_cred = kauth_cred_find(&temp_cred);
		if (found_cred == cred) {
			/* same cred so just bail */
			KAUTH_CRED_HASH_UNLOCK();
			return(cred); 
		}
		if (found_cred != NULL) {
			/* found a match so we bump reference count on new one and decrement 
			 * reference count on the old one.
			 */
			kauth_cred_ref(found_cred);
			KAUTH_CRED_HASH_UNLOCK();
			return(found_cred);
		}
	
		/* must allocate a new credential, copy in old credential data and update
		 * with real user and group IDs.
		 */
		newcred = kauth_cred_dup(&temp_cred);
		err = kauth_cred_add(newcred);
		KAUTH_CRED_HASH_UNLOCK();

		/* retry if kauth_cred_add returns non zero value */
		if (err == 0)
			break;
		FREE(newcred, M_KAUTH);
		newcred = NULL;
	}
	
	return(newcred);
}
	
/*
 * common code to update a credential.  model_cred is a temporary, non reference
 * counted credential used only for comparison and modeling purposes.  old_cred
 * is a live reference counted credential that we intend to update using model_cred
 * as our model.
 */
static kauth_cred_t kauth_cred_update(kauth_cred_t old_cred, kauth_cred_t model_cred, boolean_t retain_auditinfo)
{	
	kauth_cred_t found_cred, new_cred = NULL;
	
	/* make sure we carry the auditinfo forward to the new credential unless
	 * we are actually updating the auditinfo.
	 */
	if (retain_auditinfo)
		bcopy(&old_cred->cr_au, &model_cred->cr_au, sizeof(model_cred->cr_au));
	
	for (;;) {
		int		err;

		KAUTH_CRED_HASH_LOCK();
		found_cred = kauth_cred_find(model_cred);
		if (found_cred == old_cred) {
			/* same cred so just bail */
			KAUTH_CRED_HASH_UNLOCK();
			return(old_cred); 
		}
		if (found_cred != NULL) {
			/* found a match so we bump reference count on new one and decrement 
			 * reference count on the old one.
			 */
			kauth_cred_ref(found_cred);
			KAUTH_CRED_HASH_UNLOCK();
			kauth_cred_rele(old_cred);
			return(found_cred);
		}
	
		/* must allocate a new credential using the model.  also
		 * adds the new credential to the credential hash table.
		 */
		new_cred = kauth_cred_dup(model_cred);
		err = kauth_cred_add(new_cred);
		KAUTH_CRED_HASH_UNLOCK();

		/* retry if kauth_cred_add returns non zero value */
		if (err == 0)
			break;
		FREE(new_cred, M_KAUTH);
		new_cred = NULL;
	}

	kauth_cred_rele(old_cred);
	return(new_cred);
}

/* 
 *	Add the given credential to our credential hash table and take an additional
 *	reference to account for our use of the credential in the hash table.
 *	NOTE - expects caller to hold KAUTH_CRED_HASH_LOCK!
 */
static int kauth_cred_add(kauth_cred_t new_cred)
{
	u_long			hash_key;
	
	hash_key = kauth_cred_get_hashkey(new_cred);
	hash_key %= kauth_cred_table_size;

	/* race fix - there is a window where another matching credential 
	 * could have been inserted between the time this one was created and we
	 * got the hash lock.  If we find a match return an error and have the 
	 * the caller retry.
	 */
	if (kauth_cred_find(new_cred) != NULL) {
		return(-1);
	}
	
	/* take a reference for our use in credential hash table */ 
	kauth_cred_ref(new_cred);

	/* insert the credential into the hash table */
	TAILQ_INSERT_HEAD(&kauth_cred_table_anchor[hash_key], new_cred, cr_link);
	
	return(0);
}

/* 
 *	Remove the given credential from our credential hash table.
 *	NOTE - expects caller to hold KAUTH_CRED_HASH_LOCK!
 */
static void kauth_cred_remove(kauth_cred_t cred)
{
	u_long			hash_key;
	kauth_cred_t	found_cred;

	hash_key = kauth_cred_get_hashkey(cred);
	hash_key %= kauth_cred_table_size;

	/* avoid race */
	if (cred->cr_ref < 1)
		panic("cred reference underflow");
	if (cred->cr_ref > 1)
		return;		/* someone else got a ref */
		
	/* find cred in the credential hash table */
	TAILQ_FOREACH(found_cred, &kauth_cred_table_anchor[hash_key], cr_link) {
		if (found_cred == cred) {
			/* found a match, remove it from the hash table */
			TAILQ_REMOVE(&kauth_cred_table_anchor[hash_key], found_cred, cr_link);
			FREE(cred, M_KAUTH);
#if KAUTH_CRED_HASH_DEBUG
			kauth_cred_count--;
#endif
			return;
		}
	}

	/* did not find a match.  this should not happen! */
	printf("%s - %d - %s - did not find a match \n", __FILE__, __LINE__, __FUNCTION__);
	return;
}

/* 
 *	Using the given credential data, look for a match in our credential hash
 *	table.
 *	NOTE - expects caller to hold KAUTH_CRED_HASH_LOCK!
 */
kauth_cred_t kauth_cred_find(kauth_cred_t cred)
{
	u_long			hash_key;
	kauth_cred_t	found_cred;
	
#if KAUTH_CRED_HASH_DEBUG
	static int		test_count = 0; 

	test_count++;
	if ((test_count % 200) == 0) {
		kauth_cred_hash_print();
	}
#endif

	hash_key = kauth_cred_get_hashkey(cred);
	hash_key %= kauth_cred_table_size;

	/* find cred in the credential hash table */
	TAILQ_FOREACH(found_cred, &kauth_cred_table_anchor[hash_key], cr_link) {
		if (bcmp(&found_cred->cr_uid, &cred->cr_uid, (sizeof(struct ucred) - offsetof(struct ucred, cr_uid))) == 0) {
			/* found a match */
			return(found_cred);
		}
	}
	/* no match found */
	return(NULL);
}

/*
 * Generates a hash key using data that makes up a credential.  Based on ElfHash.
 */
static u_long kauth_cred_get_hashkey(kauth_cred_t cred)
{
	u_long	hash_key = 0;
	
	hash_key = kauth_cred_hash((uint8_t *)&cred->cr_uid, 
							   (sizeof(struct ucred) - offsetof(struct ucred, cr_uid)), 
							   hash_key);
	return(hash_key);
}

/*
 * Generates a hash key using data that makes up a credential.  Based on ElfHash.
 */
static inline u_long kauth_cred_hash(const uint8_t *datap, int data_len, u_long start_key)
{
	u_long	hash_key = start_key;
	u_long	temp;

	while (data_len > 0) {
		hash_key = (hash_key << 4) + *datap++;
		temp = hash_key & 0xF0000000;
		if (temp) {
			hash_key ^= temp >> 24;
		}
		hash_key &= ~temp;
		data_len--;
	}
	return(hash_key);
}

#if KAUTH_CRED_HASH_DEBUG
static void kauth_cred_hash_print(void) 
{
	int 			i, j;
	kauth_cred_t	found_cred;
		
	printf("\n\t kauth credential hash table statistics - current cred count %d \n", kauth_cred_count);
	/* count slot hits, misses, collisions, and max depth */
	for (i = 0; i < kauth_cred_table_size; i++) {
		printf("[%02d] ", i);
		j = 0;
		TAILQ_FOREACH(found_cred, &kauth_cred_table_anchor[i], cr_link) {
			if (j > 0) {
				printf("---- ");
			}
			j++;
			kauth_cred_print(found_cred);
			printf("\n");
		}
		if (j == 0) {
			printf("NOCRED \n");
		}
	}
}


static void kauth_cred_print(kauth_cred_t cred) 
{
	int 	i;
	
	printf("0x%02X - refs %d uids %d %d %d ", cred, cred->cr_ref, cred->cr_uid, cred->cr_ruid, cred->cr_svuid);
	printf("group count %d gids ", cred->cr_ngroups);
	for (i = 0; i < NGROUPS; i++) {
		printf("%d ", cred->cr_groups[i]);
	}
	printf("%d %d %d ", cred->cr_rgid, cred->cr_svgid, cred->cr_gmuid);
	printf("auditinfo %d %d %d %d %d %d ", 
		cred->cr_au.ai_auid, cred->cr_au.ai_mask.am_success, cred->cr_au.ai_mask.am_failure, 
		cred->cr_au.ai_termid.port, cred->cr_au.ai_termid.machine, cred->cr_au.ai_asid);
	
}
#endif
