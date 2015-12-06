/*
 * Copyright (c) 2004-2011 Apple Inc. All rights reserved.
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
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

/*
 * Kernel Authorization framework: Management of process/thread credentials
 * and identity information.
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
#include <sys/sdt.h>

#include <security/audit/audit.h>

#include <sys/mount.h>
#include <sys/stat.h>	/* For manifest constants in posix_cred_access */
#include <sys/sysproto.h>
#include <mach/message.h>
#include <mach/host_security.h>

#include <libkern/OSAtomic.h>

#include <kern/task.h>
#include <kern/locks.h>
#ifdef MACH_ASSERT
# undef MACH_ASSERT
#endif
#define MACH_ASSERT 1	/* XXX so bogus */
#include <kern/assert.h>

#if CONFIG_MACF
#include <security/mac.h>
#include <security/mac_framework.h>
#include <security/_label.h>
#endif

void mach_kauth_cred_uthread_update( void );

#define CRED_DIAGNOSTIC 0

# define NULLCRED_CHECK(_c)	do {if (!IS_VALID_CRED(_c)) panic("%s: bad credential %p", __FUNCTION__,_c);} while(0)

/* Set to 1 to turn on KAUTH_DEBUG for kern_credential.c */
#if 0
#ifdef KAUTH_DEBUG
#undef KAUTH_DEBUG
#endif

#ifdef K_UUID_FMT
#undef K_UUID_FMT
#endif

#ifdef K_UUID_ARG
#undef K_UUID_ARG
#endif

# define K_UUID_FMT "%08x:%08x:%08x:%08x"
# define K_UUID_ARG(_u) *(int *)&_u.g_guid[0],*(int *)&_u.g_guid[4],*(int *)&_u.g_guid[8],*(int *)&_u.g_guid[12]
# define KAUTH_DEBUG(fmt, args...)      do { printf("%s:%d: " fmt "\n", __PRETTY_FUNCTION__, __LINE__ , ##args); } while (0)
#endif

/*
 * Credential debugging; we can track entry into a function that might
 * change a credential, and we can track actual credential changes that
 * result.
 *
 * Note:	Does *NOT* currently include per-thread credential changes
 */

#if DEBUG_CRED
#define	DEBUG_CRED_ENTER		printf
#define	DEBUG_CRED_CHANGE		printf
extern void kauth_cred_print(kauth_cred_t cred);

#include <libkern/OSDebug.h>	/* needed for get_backtrace( ) */

int is_target_cred( kauth_cred_t the_cred );
void get_backtrace( void );

static int sysctl_dump_creds( __unused struct sysctl_oid *oidp, __unused void *arg1, 
							  __unused int arg2, struct sysctl_req *req );
static int
sysctl_dump_cred_backtraces( __unused struct sysctl_oid *oidp, __unused void *arg1, 
							 __unused int arg2, struct sysctl_req *req );

#define MAX_STACK_DEPTH 8
struct cred_backtrace {
	int				depth;
	void *			stack[ MAX_STACK_DEPTH ];
};
typedef struct cred_backtrace cred_backtrace;

#define MAX_CRED_BUFFER_SLOTS 200
struct cred_debug_buffer {
	int				next_slot;
	cred_backtrace	stack_buffer[ MAX_CRED_BUFFER_SLOTS ];	
};
typedef struct cred_debug_buffer cred_debug_buffer;
cred_debug_buffer * cred_debug_buf_p = NULL;

#else	/* !DEBUG_CRED */

#define	DEBUG_CRED_ENTER(fmt, ...)	do {} while (0)
#define	DEBUG_CRED_CHANGE(fmt, ...)	do {} while (0)

#endif	/* !DEBUG_CRED */

#if CONFIG_EXT_RESOLVER
/*
 * Interface to external identity resolver.
 *
 * The architecture of the interface is simple; the external resolver calls
 * in to get work, then calls back with completed work.  It also calls us
 * to let us know that it's (re)started, so that we can resubmit work if it
 * times out.
 */

static lck_mtx_t *kauth_resolver_mtx;
#define KAUTH_RESOLVER_LOCK()	lck_mtx_lock(kauth_resolver_mtx);
#define KAUTH_RESOLVER_UNLOCK()	lck_mtx_unlock(kauth_resolver_mtx);

static volatile pid_t	kauth_resolver_identity;
static int	kauth_identitysvc_has_registered;
static int	kauth_resolver_registered;
static uint32_t	kauth_resolver_sequence;
static int	kauth_resolver_timeout = 30;	/* default: 30 seconds */

struct kauth_resolver_work {
	TAILQ_ENTRY(kauth_resolver_work) kr_link;
	struct kauth_identity_extlookup kr_work;
	uint64_t	kr_extend;
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

/* Number of resolver timeouts between logged complaints */
#define KAUTH_COMPLAINT_INTERVAL 1000
int kauth_resolver_timeout_cnt = 0;

static int	kauth_resolver_submit(struct kauth_identity_extlookup *lkp, uint64_t extend_data);
static int	kauth_resolver_complete(user_addr_t message);
static int	kauth_resolver_getwork(user_addr_t message);
static int	kauth_resolver_getwork2(user_addr_t message);
static __attribute__((noinline)) int __KERNEL_IS_WAITING_ON_EXTERNAL_CREDENTIAL_RESOLVER__(
	struct kauth_resolver_work *); 

#define	KAUTH_CACHES_MAX_SIZE 10000 /* Max # entries for both groups and id caches */

struct kauth_identity {
	TAILQ_ENTRY(kauth_identity) ki_link;
	int	ki_valid;
	uid_t	ki_uid;
	gid_t	ki_gid;
	int	ki_supgrpcnt;
	gid_t	ki_supgrps[NGROUPS];
	guid_t	ki_guid;
	ntsid_t ki_ntsid;
	const char	*ki_name;	/* string name from string cache */
	/*
	 * Expiry times are the earliest time at which we will disregard the
	 * cached state and go to userland.  Before then if the valid bit is
	 * set, we will return the cached value.  If it's not set, we will
	 * not go to userland to resolve, just assume that there is no answer
	 * available.
	 */
	time_t	ki_groups_expiry;
	time_t	ki_guid_expiry;
	time_t	ki_ntsid_expiry;
};

static TAILQ_HEAD(kauth_identity_head, kauth_identity) kauth_identities;
static lck_mtx_t *kauth_identity_mtx;
#define KAUTH_IDENTITY_LOCK()	lck_mtx_lock(kauth_identity_mtx);
#define KAUTH_IDENTITY_UNLOCK()	lck_mtx_unlock(kauth_identity_mtx);
#define KAUTH_IDENTITY_CACHEMAX_DEFAULT 100	/* XXX default sizing? */
static int kauth_identity_cachemax = KAUTH_IDENTITY_CACHEMAX_DEFAULT;
static int kauth_identity_count;

static struct kauth_identity *kauth_identity_alloc(uid_t uid, gid_t gid, guid_t *guidp, time_t guid_expiry,
	ntsid_t *ntsidp, time_t ntsid_expiry, int supgrpcnt, gid_t *supgrps, time_t groups_expiry,
	const char *name, int nametype);
static void	kauth_identity_register_and_free(struct kauth_identity *kip);
static void	kauth_identity_updatecache(struct kauth_identity_extlookup *elp, struct kauth_identity *kip, uint64_t extend_data);
static void	kauth_identity_trimcache(int newsize);
static void	kauth_identity_lru(struct kauth_identity *kip);
static int	kauth_identity_guid_expired(struct kauth_identity *kip);
static int	kauth_identity_ntsid_expired(struct kauth_identity *kip);
static int	kauth_identity_find_uid(uid_t uid, struct kauth_identity *kir, char *getname);
static int	kauth_identity_find_gid(gid_t gid, struct kauth_identity *kir, char *getname);
static int	kauth_identity_find_guid(guid_t *guidp, struct kauth_identity *kir, char *getname);
static int	kauth_identity_find_ntsid(ntsid_t *ntsid, struct kauth_identity *kir, char *getname);
static int	kauth_identity_find_nam(char *name, int valid, struct kauth_identity *kir);

struct kauth_group_membership {
	TAILQ_ENTRY(kauth_group_membership) gm_link;
	uid_t	gm_uid;		/* the identity whose membership we're recording */
	gid_t	gm_gid;		/* group of which they are a member */
	time_t	gm_expiry;	/* TTL for the membership, or 0 for persistent entries */
	int	gm_flags;
#define KAUTH_GROUP_ISMEMBER	(1<<0)
};

TAILQ_HEAD(kauth_groups_head, kauth_group_membership) kauth_groups;
static lck_mtx_t *kauth_groups_mtx;
#define KAUTH_GROUPS_LOCK()	lck_mtx_lock(kauth_groups_mtx);
#define KAUTH_GROUPS_UNLOCK()	lck_mtx_unlock(kauth_groups_mtx);
#define KAUTH_GROUPS_CACHEMAX_DEFAULT 100	/* XXX default sizing? */
static int kauth_groups_cachemax = KAUTH_GROUPS_CACHEMAX_DEFAULT;
static int kauth_groups_count;

static int	kauth_groups_expired(struct kauth_group_membership *gm);
static void	kauth_groups_lru(struct kauth_group_membership *gm);
static void	kauth_groups_updatecache(struct kauth_identity_extlookup *el);
static void	kauth_groups_trimcache(int newsize);

#endif	/* CONFIG_EXT_RESOLVER */

#define KAUTH_CRED_TABLE_SIZE 97

TAILQ_HEAD(kauth_cred_entry_head, ucred);
static struct kauth_cred_entry_head * kauth_cred_table_anchor = NULL;

#define KAUTH_CRED_HASH_DEBUG	0

static int kauth_cred_add(kauth_cred_t new_cred);
static boolean_t kauth_cred_remove(kauth_cred_t cred);
static inline u_long kauth_cred_hash(const uint8_t *datap, int data_len, u_long start_key);
static u_long kauth_cred_get_hashkey(kauth_cred_t cred);
static kauth_cred_t kauth_cred_update(kauth_cred_t old_cred, kauth_cred_t new_cred, boolean_t retain_auditinfo);
static boolean_t kauth_cred_unref_hashlocked(kauth_cred_t *credp);

#if KAUTH_CRED_HASH_DEBUG
static int	kauth_cred_count = 0;
static void kauth_cred_hash_print(void);
static void kauth_cred_print(kauth_cred_t cred);
#endif

#if CONFIG_EXT_RESOLVER

/*
 *  __KERNEL_IS_WAITING_ON_EXTERNAL_CREDENTIAL_RESOLVER__
 *
 * Description:  Waits for the user space daemon to respond to the request
 *               we made. Function declared non inline to be visible in 
 *               stackshots and spindumps as well as debugging.
 *
 * Parameters:   workp                     Work queue entry.
 *
 * Returns:      0                         on Success.
 *               EIO                       if Resolver is dead.
 *               EINTR                     thread interrupted in msleep
 *               EWOULDBLOCK               thread timed out in msleep
 *               ERESTART                  returned by msleep.
 *
 */
static __attribute__((noinline)) int 
__KERNEL_IS_WAITING_ON_EXTERNAL_CREDENTIAL_RESOLVER__(
	struct kauth_resolver_work  *workp)
{
	int error = 0;
	struct timespec ts;
	for (;;) {
		/* we could compute a better timeout here */
		ts.tv_sec = kauth_resolver_timeout;
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
	return error;
}


/*
 * kauth_resolver_init
 *
 * Description:	Initialize the daemon side of the credential identity resolver
 *
 * Parameters:	(void)
 *
 * Returns:	(void)
 *
 * Notes:	Initialize the credential identity resolver for use; the
 *		credential identity resolver is the KPI used by the user
 *		space credential identity resolver daemon to communicate
 *		with the kernel via the identitysvc() system call..
 *
 *		This is how membership in more than 16 groups (1 effective
 *		and 15 supplementary) is supported, and also how UID's,
 *		UUID's, and so on, are translated to/from POSIX credential
 *		values.
 *
 *		The credential identity resolver operates by attempting to
 *		determine identity first from the credential, then from
 *		the kernel credential identity cache, and finally by
 *		enqueueing a request to a user space daemon.
 *
 *		This function is called from kauth_init() in the file
 *		kern_authorization.c.
 */
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
 * kauth_resolver_submit
 *
 * Description:	Submit an external credential identity resolution request to
 *		the user space daemon.
 *
 * Parameters:	lkp				A pointer to an external
 *						lookup request
 *		extend_data			extended data for kr_extend
 *
 * Returns:	0				Success
 *		EWOULDBLOCK			No resolver registered
 *		EINTR				Operation interrupted (e.g. by
 *						a signal)
 *		ENOMEM				Could not allocate work item
 *	copyinstr:EFAULT			Bad message from user space
 *	workp->kr_result:???			An error from the user space
 *						daemon (includes ENOENT!)
 *
 * Implicit returns:
 *		*lkp				Modified
 *
 * Notes:	Allocate a work queue entry, submit the work and wait for
 *		the operation to either complete or time out.  Outstanding
 *		operations may also be cancelled.
 *
 *		Submission is by means of placing the item on a work queue
 *		which is serviced by an external resolver thread calling
 *		into the kernel.  The caller then sleeps until timeout,
 *		cancellation, or an external resolver thread calls in with
 *		a result message to kauth_resolver_complete().  All of these
 *		events wake the caller back up.
 *
 *		This code is called from either kauth_cred_ismember_gid()
 *		for a group membership request, or it is called from
 *		kauth_cred_cache_lookup() when we get a cache miss.
 */
static int
kauth_resolver_submit(struct kauth_identity_extlookup *lkp, uint64_t extend_data)
{
	struct kauth_resolver_work *workp, *killp;
	struct timespec ts;
	int	error, shouldfree;
	
	/* no point actually blocking if the resolver isn't up yet */
	if (kauth_resolver_identity == 0) {
		/*
		 * We've already waited an initial <kauth_resolver_timeout>
		 * seconds with no result.
		 *
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
	workp->kr_extend = extend_data;
	workp->kr_refs = 1;
	workp->kr_flags = KAUTH_REQUEST_UNSUBMITTED;
	workp->kr_result = 0;

	/*
	 * We insert the request onto the unsubmitted queue, the call in from
	 * the resolver will it to the submitted thread when appropriate.
	 */
	KAUTH_RESOLVER_LOCK();
	workp->kr_seqno = workp->kr_work.el_seqno = kauth_resolver_sequence++;
	workp->kr_work.el_result = KAUTH_EXTLOOKUP_INPROG;

	/*
	 * XXX We *MUST NOT* attempt to coalesce identical work items due to
	 * XXX the inability to ensure order of update of the request item
	 * XXX extended data vs. the wakeup; instead, we let whoever is waiting
	 * XXX for each item repeat the update when they wake up.
	 */
	TAILQ_INSERT_TAIL(&kauth_resolver_unsubmitted, workp, kr_link);

	/*
	 * Wake up an external resolver thread to deal with the new work; one
	 * may not be available, and if not, then the request will be grabbed
	 * when a resolver thread comes back into the kernel to request new
	 * work.
	 */
	wakeup_one((caddr_t)&kauth_resolver_unsubmitted);
	error = __KERNEL_IS_WAITING_ON_EXTERNAL_CREDENTIAL_RESOLVER__(workp);

	/* if the request was processed, copy the result */
	if (error == 0)
		*lkp = workp->kr_work;
	
	if (error == EWOULDBLOCK) {
	        if ((kauth_resolver_timeout_cnt++ % KAUTH_COMPLAINT_INTERVAL) == 0) {
                        printf("kauth external resolver timed out (%d timeout(s) of %d seconds).\n",
                                kauth_resolver_timeout_cnt, kauth_resolver_timeout);
                }
                
	        if (workp->kr_flags & KAUTH_REQUEST_UNSUBMITTED) {
	                /*
                	 * If the request timed out and was never collected, the resolver
                	 * is dead and probably not coming back anytime soon.  In this
                	 * case we revert to no-resolver behaviour, and punt all the other
                	 * sleeping requests to clear the backlog.
                	 */
                        KAUTH_DEBUG("RESOLVER - request timed out without being collected for processing, resolver dead");

                        /*
                        * Make the current resolver non-authoritative, and mark it as
                        * no longer registered to prevent kauth_cred_ismember_gid()
                        * enqueueing more work until a new one is registered.  This
                        * mitigates the damage a crashing resolver may inflict.
                        */
                        kauth_resolver_identity = 0;
                        kauth_resolver_registered = 0;

                        /* kill all the other requestes that are waiting as well */
                        TAILQ_FOREACH(killp, &kauth_resolver_submitted, kr_link)
                                wakeup(killp);
                        TAILQ_FOREACH(killp, &kauth_resolver_unsubmitted, kr_link)
                                wakeup(killp);
                        /* Cause all waiting-for-work threads to return EIO */
                        wakeup((caddr_t)&kauth_resolver_unsubmitted);
                }
        }

	/*
	 * drop our reference on the work item, and note whether we should
	 * free it or not
	 */
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
	if (error == 0) {
		error = workp->kr_result;
	}
	KAUTH_RESOLVER_UNLOCK();

	/*
	 * If we dropped the last reference, free the request.
	 */
	if (shouldfree) {
		FREE(workp, M_KAUTH);
	}

	KAUTH_DEBUG("RESOLVER - returning %d", error);
	return(error);
}


/*
 * identitysvc
 *
 * Description:	System call interface for the external identity resolver.
 *
 * Parameters:	uap->message			Message from daemon to kernel
 *
 * Returns:	0				Successfully became resolver
 *		EPERM				Not the resolver process
 *	kauth_authorize_generic:EPERM		Not root user
 *	kauth_resolver_complete:EIO
 *	kauth_resolver_complete:EFAULT
 *	kauth_resolver_getwork:EINTR
 *	kauth_resolver_getwork:EFAULT
 *
 * Notes:	This system call blocks until there is work enqueued, at
 *		which time the kernel wakes it up, and a message from the
 *		kernel is copied out to the identity resolution daemon, which
 *		proceed to attempt to resolve it.  When the resolution has
 *		completed (successfully or not), the daemon called back into
 *		this system call to give the result to the kernel, and wait
 *		for the next request.
 */
int
identitysvc(__unused struct proc *p, struct identitysvc_args *uap, __unused int32_t *retval)
{
	int opcode = uap->opcode;
	user_addr_t message = uap->message;
	struct kauth_resolver_work *workp;
	struct kauth_cache_sizes sz_arg;
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
			/*
			 * Allow user space resolver to override the
			 * external resolution timeout
			 */
			if (message > 30 && message < 10000) {
				kauth_resolver_timeout = message;
				KAUTH_DEBUG("RESOLVER - new resolver changes timeout to %d seconds\n", (int)message);
			}
			kauth_resolver_identity = new_id;
			kauth_resolver_registered = 1;
			kauth_identitysvc_has_registered = 1;
			wakeup(&kauth_resolver_unsubmitted);
		}
		KAUTH_RESOLVER_UNLOCK();
		return(0);
	}

	/*
	 * Beyond this point, we must be the resolver process. We verify this
	 * by confirming the resolver credential and pid.
	 */
	if ((kauth_cred_getuid(kauth_cred_get()) != 0) || (current_proc()->p_pid != kauth_resolver_identity)) {
		KAUTH_DEBUG("RESOLVER - call from bogus resolver %d\n", current_proc()->p_pid);
		return(EPERM);
	}
	
	if (opcode == KAUTH_GET_CACHE_SIZES) {
		KAUTH_IDENTITY_LOCK();
		sz_arg.kcs_id_size = kauth_identity_cachemax;
		KAUTH_IDENTITY_UNLOCK();
		
		KAUTH_GROUPS_LOCK();
		sz_arg.kcs_group_size = kauth_groups_cachemax;
		KAUTH_GROUPS_UNLOCK();

		if ((error = copyout(&sz_arg, uap->message, sizeof (sz_arg))) != 0) {
			return (error);
		}
		
		return (0);
	} else if (opcode == KAUTH_SET_CACHE_SIZES) {
		if ((error = copyin(uap->message, &sz_arg, sizeof (sz_arg))) != 0) {
			return (error);
		}
		
		if ((sz_arg.kcs_group_size > KAUTH_CACHES_MAX_SIZE) ||
		    (sz_arg.kcs_id_size > KAUTH_CACHES_MAX_SIZE)) {
			return (EINVAL);
		}
		
		KAUTH_IDENTITY_LOCK();
		kauth_identity_cachemax = sz_arg.kcs_id_size;
		kauth_identity_trimcache(kauth_identity_cachemax);
		KAUTH_IDENTITY_UNLOCK();
		
		KAUTH_GROUPS_LOCK();
		kauth_groups_cachemax = sz_arg.kcs_group_size;
		kauth_groups_trimcache(kauth_groups_cachemax);
		KAUTH_GROUPS_UNLOCK();
		
		return (0);
	} else if (opcode == KAUTH_CLEAR_CACHES) {
		KAUTH_IDENTITY_LOCK();
		kauth_identity_trimcache(0);
		KAUTH_IDENTITY_UNLOCK();
		
		KAUTH_GROUPS_LOCK();
		kauth_groups_trimcache(0);
		KAUTH_GROUPS_UNLOCK();
	} else if (opcode == KAUTH_EXTLOOKUP_DEREGISTER) {
		/*
		 * Terminate outstanding requests; without an authoritative
		 * resolver, we are now back on our own authority.
		 */
		struct kauth_resolver_work *killp;

		KAUTH_RESOLVER_LOCK();

		/*
		 * Clear the identity, but also mark it as unregistered so
		 * there is no explicit future expectation of us getting a
		 * new resolver any time soon.
		 */
		kauth_resolver_identity = 0;
		kauth_resolver_registered = 0;

		TAILQ_FOREACH(killp, &kauth_resolver_submitted, kr_link)
		    wakeup(killp);
		TAILQ_FOREACH(killp, &kauth_resolver_unsubmitted, kr_link)
		    wakeup(killp);
		/* Cause all waiting-for-work threads to return EIO */
		wakeup((caddr_t)&kauth_resolver_unsubmitted);
		KAUTH_RESOLVER_UNLOCK();
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
 * kauth_resolver_getwork_continue
 *		
 * Description:	Continuation for kauth_resolver_getwork
 *
 * Parameters:	result				Error code or 0 for the sleep
 *						that got us to this function
 *
 * Returns:	0				Success
 *		EINTR				Interrupted (e.g. by signal)
 *	kauth_resolver_getwork2:EFAULT
 *
 * Notes:	See kauth_resolver_getwork(0 and kauth_resolver_getwork2() for
 *		more information.
 */
static int
kauth_resolver_getwork_continue(int result)
{
	thread_t thread;
	struct uthread *ut;
	user_addr_t message;

	if (result) {
		KAUTH_RESOLVER_UNLOCK();
		return(result);
	}

	/*
	 * If we lost a race with another thread/memberd restarting, then we
	 * need to go back to sleep to look for more work.  If it was memberd
	 * restarting, then the msleep0() will error out here, as our thread
	 * will already be "dead".
	 */
	if (TAILQ_FIRST(&kauth_resolver_unsubmitted) == NULL) {
		int error;

		error = msleep0(&kauth_resolver_unsubmitted, kauth_resolver_mtx, PCATCH, "GRGetWork", 0, kauth_resolver_getwork_continue);
		/*
		 * If this is a wakeup from another thread in the resolver
		 * deregistering it, error out the request-for-work thread
		 */
		if (!kauth_resolver_identity)
			error = EIO;
		KAUTH_RESOLVER_UNLOCK();
		return(error);
	}

	thread = current_thread();
	ut = get_bsdthread_info(thread);
	message = ut->uu_kevent.uu_kauth.message;
	return(kauth_resolver_getwork2(message));
}


/*
 * kauth_resolver_getwork2
 *
 * Decription:	Common utility function to copy out a identity resolver work
 *		item from the kernel to user space as part of the user space
 *		identity resolver requesting work.
 *
 * Parameters:	message				message to user space
 *
 * Returns:	0				Success
 *		EFAULT				Bad user space message address
 *
 * Notes:	This common function exists to permit the use of continuations
 *		in the identity resolution process.  This frees up the stack
 *		while we are waiting for the user space resolver to complete
 *		a request.  This is specifically used so that our per thread
 *		cost can be small, and we will therefore be willing to run a
 *		larger number of threads in the user space identity resolver.
 */
static int
kauth_resolver_getwork2(user_addr_t message)
{
	struct kauth_resolver_work *workp;
	int		error;

	/*
	 * Note: We depend on the caller protecting us from a NULL work item
	 * queue, since we must have the kauth resolver lock on entry to this
	 * function.
	 */
	workp = TAILQ_FIRST(&kauth_resolver_unsubmitted);

	/*
	 * Copy out the external lookup structure for the request, not
	 * including the el_extend field, which contains the address of the
	 * external buffer provided by the external resolver into which we
	 * copy the extension request information.
	 */
	/* BEFORE FIELD */
	if ((error = copyout(&workp->kr_work, message, offsetof(struct kauth_identity_extlookup, el_extend))) != 0) {
		KAUTH_DEBUG("RESOLVER - error submitting work to resolve");
		goto out;
	}
	/* AFTER FIELD */
	if ((error = copyout(&workp->kr_work.el_info_reserved_1,
			message + offsetof(struct kauth_identity_extlookup, el_info_reserved_1),
		sizeof(struct kauth_identity_extlookup) - offsetof(struct kauth_identity_extlookup, el_info_reserved_1))) != 0) {
		KAUTH_DEBUG("RESOLVER - error submitting work to resolve");
		goto out;
	}

	/*
	 * Handle extended requests here; if we have a request of a type where
	 * the kernel wants a translation of extended information, then we need
	 * to copy it out into the extended buffer, assuming the buffer is
	 * valid; we only attempt to get the buffer address if we have request
	 * data to copy into it.
	 */

	/*
	 * translate a user@domain string into a uid/gid/whatever
	 */
	if (workp->kr_work.el_flags & (KAUTH_EXTLOOKUP_VALID_PWNAM | KAUTH_EXTLOOKUP_VALID_GRNAM)) {
		uint64_t uaddr;

		error = copyin(message + offsetof(struct kauth_identity_extlookup, el_extend), &uaddr, sizeof(uaddr));
		if (!error) {
			size_t actual;	/* not used */
			/*
			 * Use copyoutstr() to reduce the copy size; we let
			 * this catch a NULL uaddr because we shouldn't be
			 * asking in that case anyway.
			 */
			error = copyoutstr(CAST_DOWN(void *,workp->kr_extend), uaddr, MAXPATHLEN, &actual);
		}
		if (error) {
			KAUTH_DEBUG("RESOLVER - error submitting work to resolve");
			goto out;
		}
	}
	TAILQ_REMOVE(&kauth_resolver_unsubmitted, workp, kr_link);
	workp->kr_flags &= ~KAUTH_REQUEST_UNSUBMITTED;
	workp->kr_flags |= KAUTH_REQUEST_SUBMITTED;
	TAILQ_INSERT_TAIL(&kauth_resolver_submitted, workp, kr_link);

out:
	KAUTH_RESOLVER_UNLOCK();
	return(error);
}


/*
 * kauth_resolver_getwork
 *
 * Description:	Get a work item from the enqueued requests from the kernel and
 *		give it to the user space daemon.
 *
 * Parameters:	message				message to user space
 *
 * Returns:	0				Success
 *		EINTR				Interrupted (e.g. by signal)
 *	kauth_resolver_getwork2:EFAULT
 *
 * Notes:	This function blocks in a continuation if there are no work
 *		items available for processing at the time the user space
 *		identity resolution daemon makes a request for work.  This
 *		permits a large number of threads to be used by the daemon,
 *		without using a lot of wired kernel memory when there are no
 *		actual request outstanding.
 */
static int
kauth_resolver_getwork(user_addr_t message)
{
	struct kauth_resolver_work *workp;
	int		error;

	KAUTH_RESOLVER_LOCK();
	error = 0;
	while ((workp = TAILQ_FIRST(&kauth_resolver_unsubmitted)) == NULL) {
		thread_t thread = current_thread();
		struct uthread *ut = get_bsdthread_info(thread);

		ut->uu_kevent.uu_kauth.message = message;
		error = msleep0(&kauth_resolver_unsubmitted, kauth_resolver_mtx, PCATCH, "GRGetWork", 0, kauth_resolver_getwork_continue);
		KAUTH_RESOLVER_UNLOCK();
		/*
		 * If this is a wakeup from another thread in the resolver
		 * deregistering it, error out the request-for-work thread
		 */
		if (!kauth_resolver_identity)
			error = EIO;
		return(error);
	}
	return kauth_resolver_getwork2(message);
}


/*
 * kauth_resolver_complete
 *
 * Description:	Return a result from userspace.
 *
 * Parameters:	message				message from user space
 *
 * Returns:	0				Success
 *		EIO				The resolver is dead
 *	copyin:EFAULT				Bad message from user space
 */
static int
kauth_resolver_complete(user_addr_t message)
{
	struct kauth_identity_extlookup	extl;
	struct kauth_resolver_work *workp;
	struct kauth_resolver_work *killp;
	int error, result, request_flags;

	/*
	 * Copy in the mesage, including the extension field, since we are
	 * copying into a local variable.
	 */
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
		/*
		 * Terminate outstanding requests; without an authoritative
		 * resolver, we are now back on our own authority.  Tag the
		 * resolver unregistered to prevent kauth_cred_ismember_gid()
		 * enqueueing more work until a new one is registered.  This
		 * mitigates the damage a crashing resolver may inflict.
		 */
		kauth_resolver_identity = 0;
		kauth_resolver_registered = 0;

		TAILQ_FOREACH(killp, &kauth_resolver_submitted, kr_link)
		    wakeup(killp);
		TAILQ_FOREACH(killp, &kauth_resolver_unsubmitted, kr_link)
		    wakeup(killp);
		/* Cause all waiting-for-work threads to return EIO */
		wakeup((caddr_t)&kauth_resolver_unsubmitted);
		/* and return EIO to the caller */
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
	 * In the case of a fatal error, we assume that the resolver will
	 * restart quickly and re-collect all of the outstanding requests.
	 * Thus, we don't complete the request which returned the fatal
	 * error status.
	 */
	if (extl.el_result != KAUTH_EXTLOOKUP_FATAL) {
		/* scan our list for this request */
		TAILQ_FOREACH(workp, &kauth_resolver_submitted, kr_link) {
			/* found it? */
			if (workp->kr_seqno == extl.el_seqno) {
				/*
				 * Take a snapshot of the original request flags.
				 */
				request_flags = workp->kr_work.el_flags;

				/*
				 * Get the request of the submitted queue so
				 * that it is not cleaned up out from under
				 * us by a timeout.
				 */
				TAILQ_REMOVE(&kauth_resolver_submitted, workp, kr_link);
				workp->kr_flags &= ~KAUTH_REQUEST_SUBMITTED;
				workp->kr_flags |= KAUTH_REQUEST_DONE;
				workp->kr_result = result;

				/* Copy the result message to the work item. */
				memcpy(&workp->kr_work, &extl, sizeof(struct kauth_identity_extlookup));

				/*
				 * Check if we have a result in the extension
				 * field; if we do, then we need to separately
				 * copy the data from the message el_extend
				 * into the request buffer that's in the work
				 * item.  We have to do it here because we do
				 * not want to wake up the waiter until the
				 * data is in their buffer, and because the
				 * actual request response may be destroyed
				 * by the time the requester wakes up, and they
				 * do not have access to the user space buffer
				 * address.
				 *
				 * It is safe to drop and reacquire the lock
				 * here because we've already removed the item
				 * from the submission queue, but have not yet
				 * moved it to the completion queue.  Note that
				 * near simultaneous requests may result in
				 * duplication of requests for items in this
				 * window. This should not be a performance
				 * issue and is easily detectable by comparing
				 * time to live on last response vs. time of
				 * next request in the resolver logs.
				 *
				 * A malicious/faulty resolver could overwrite
				 * part of a user's address space if they return
				 * flags that mismatch the original request's flags.
				 */
				if ((extl.el_flags & request_flags) & (KAUTH_EXTLOOKUP_VALID_PWNAM|KAUTH_EXTLOOKUP_VALID_GRNAM)) {
					size_t actual;	/* notused */

					KAUTH_RESOLVER_UNLOCK();
					error = copyinstr(extl.el_extend, CAST_DOWN(void *, workp->kr_extend), MAXPATHLEN, &actual);
					KAUTH_RESOLVER_LOCK();
				} else if (extl.el_flags &  (KAUTH_EXTLOOKUP_VALID_PWNAM|KAUTH_EXTLOOKUP_VALID_GRNAM)) {
					error = EFAULT;
					KAUTH_DEBUG("RESOLVER - resolver returned mismatching extension flags (%d), request contained (%d)",
							extl.el_flags, request_flags);
				}

				/*
				 * Move the completed work item to the
				 * completion queue and wake up requester(s)
				 */
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
#endif /* CONFIG_EXT_RESOLVER */


/*
 * Identity cache.
 */

#define	KI_VALID_UID	(1<<0)		/* UID and GID are mutually exclusive */
#define KI_VALID_GID	(1<<1)
#define KI_VALID_GUID	(1<<2)
#define KI_VALID_NTSID	(1<<3)
#define KI_VALID_PWNAM	(1<<4)	/* Used for translation */
#define KI_VALID_GRNAM	(1<<5)	/* Used for translation */
#define KI_VALID_GROUPS (1<<6)

#if CONFIG_EXT_RESOLVER
/*
 * kauth_identity_init
 *
 * Description:	Initialize the kernel side of the credential identity resolver
 *
 * Parameters:	(void)
 *
 * Returns:	(void)
 *
 * Notes:	Initialize the credential identity resolver for use; the
 *		credential identity resolver is the KPI used to communicate
 *		with a user space credential identity resolver daemon.
 *
 *		This function is called from kauth_init() in the file
 *		kern_authorization.c.
 */
void
kauth_identity_init(void)
{
	TAILQ_INIT(&kauth_identities);
	kauth_identity_mtx = lck_mtx_alloc_init(kauth_lck_grp, 0/*LCK_ATTR_NULL*/);
}


/*
 * kauth_identity_alloc
 *
 * Description:	Allocate and fill out a kauth_identity structure for
 *		translation between {UID|GID}/GUID/NTSID
 *
 * Parameters:	uid
 *
 * Returns:	NULL				Insufficient memory to satisfy
 *						the request or bad parameters
 *		!NULL				A pointer to the allocated
 *						structure, filled in
 *
 * Notes:	It is illegal to translate between UID and GID; any given UUID
 *		or NTSID can only refer to an NTSID or UUID (respectively),
 *		and *either* a UID *or* a GID, but not both.
 */
static struct kauth_identity *
kauth_identity_alloc(uid_t uid, gid_t gid, guid_t *guidp, time_t guid_expiry,
	ntsid_t *ntsidp, time_t ntsid_expiry, int supgrpcnt, gid_t *supgrps, time_t groups_expiry,
	const char *name, int nametype)
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
		if (supgrpcnt) {
			/*
			 * A malicious/faulty resolver could return bad values
			 */
			assert(supgrpcnt >= 0);
			assert(supgrpcnt <= NGROUPS);
			assert(supgrps != NULL);

			if ((supgrpcnt < 0) || (supgrpcnt > NGROUPS) || (supgrps == NULL)) {
				return NULL;
			}
			if (kip->ki_valid & KI_VALID_GID)
				panic("can't allocate kauth identity with both gid and supplementary groups");
			kip->ki_supgrpcnt = supgrpcnt;
			memcpy(kip->ki_supgrps, supgrps, sizeof(supgrps[0]) * supgrpcnt);
			kip->ki_valid |= KI_VALID_GROUPS;
		}
		kip->ki_groups_expiry = groups_expiry;
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
		if (name != NULL) {
			kip->ki_name = name;
			kip->ki_valid |= nametype;
		}
	}
	return(kip);
}


/*
 * kauth_identity_register_and_free
 *
 * Description:	Register an association between identity tokens.  The passed
 *		'kip' is consumed by this function.
 *
 * Parameters:	kip				Pointer to kauth_identity
 *						structure to register
 *
 * Returns:	(void)
 *
 * Notes:	The memory pointer to by 'kip' is assumed to have been
 *		previously allocated via kauth_identity_alloc().
 */
static void
kauth_identity_register_and_free(struct kauth_identity *kip)
{
	struct kauth_identity *ip;

	/*
	 * We search the cache for the UID listed in the incoming association.
	 * If we already have an entry, the new information is merged.
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
		/* a valid ki_name field overwrites the previous name field */
		if (kip->ki_valid & (KI_VALID_PWNAM | KI_VALID_GRNAM)) {
			/* if there's an old one, discard it */
			const char *oname = NULL;
			if (ip->ki_valid & (KI_VALID_PWNAM | KI_VALID_GRNAM))
				oname = ip->ki_name;
			ip->ki_name = kip->ki_name;
			kip->ki_name = oname;
		}
		/* and discard the incoming entry */
		ip = kip;
	} else {
		/*
		 * if we don't have any information on this identity, add it;
		 * if it pushes us over our limit, discard the oldest one.
		 */
		TAILQ_INSERT_HEAD(&kauth_identities, kip, ki_link);
		if (++kauth_identity_count > kauth_identity_cachemax) {
			ip = TAILQ_LAST(&kauth_identities, kauth_identity_head);
			TAILQ_REMOVE(&kauth_identities, ip, ki_link);
			kauth_identity_count--;
		}
	}
	KAUTH_IDENTITY_UNLOCK();
	/* have to drop lock before freeing expired entry (it may be in use) */
	if (ip != NULL) {
		/* if the ki_name field is used, clear it first */
		if (ip->ki_valid & (KI_VALID_PWNAM | KI_VALID_GRNAM))
			vfs_removename(ip->ki_name);
		/* free the expired entry */
		FREE(ip, M_KAUTH);
	}
}


/*
 * kauth_identity_updatecache
 *
 * Description:	Given a lookup result, add any associations that we don't
 *		currently have; replace ones which have changed.
 *
 * Parameters:	elp				External lookup result from
 *						user space daemon to kernel
 *		rkip				pointer to returned kauth
 *						identity, or NULL
 *		extend_data			Extended data (can vary)
 *
 * Returns:	(void)
 *
 * Implicit returns:
 *		*rkip				Modified (if non-NULL)
 *
 * Notes:	For extended information requests, this code relies on the fact
 *		that elp->el_flags is never used as an rvalue, and is only
 *		ever bit-tested for valid lookup information we are willing
 *		to cache.
 *
 * XXX:		We may have to do the same in the case that extended data was
 *		passed out to user space to ensure that the request string
 *		gets cached; we may also be able to use the rkip as an
 *		input to avoid this.  The jury is still out.
 *
 * XXX:		This codes performance could be improved for multiple valid
 *		results by combining the loop iteration in a single loop.
 */
static void
kauth_identity_updatecache(struct kauth_identity_extlookup *elp, struct kauth_identity *rkip, uint64_t extend_data)
{
	struct timeval tv;
	struct kauth_identity *kip;
	const char *speculative_name = NULL;

	microuptime(&tv);

	/*
	 * If there is extended data, and that data represents a name rather
	 * than something else, speculatively create an entry for it in the
	 * string cache.  We do this to avoid holding the KAUTH_IDENTITY_LOCK
	 * over the allocation later.
	 */
	if (elp->el_flags & (KAUTH_EXTLOOKUP_VALID_PWNAM | KAUTH_EXTLOOKUP_VALID_GRNAM)) {
		const char *tmp = CAST_DOWN(const char *,extend_data);
		speculative_name = vfs_addname(tmp, strnlen(tmp, MAXPATHLEN - 1), 0, 0);
	}
	
	/* user identity? */
	if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_UID) {
		KAUTH_IDENTITY_LOCK();
		TAILQ_FOREACH(kip, &kauth_identities, ki_link) {
			/* matching record */
			if ((kip->ki_valid & KI_VALID_UID) && (kip->ki_uid == elp->el_uid)) {
				if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_SUPGRPS) {
					assert(elp->el_sup_grp_cnt <= NGROUPS);
					kip->ki_supgrpcnt = elp->el_sup_grp_cnt;
					memcpy(kip->ki_supgrps, elp->el_sup_groups, sizeof(elp->el_sup_groups[0]) * kip->ki_supgrpcnt);
					kip->ki_valid |= KI_VALID_GROUPS;
					kip->ki_groups_expiry = (elp->el_member_valid) ? tv.tv_sec + elp->el_member_valid : 0;
				}
				if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_UGUID) {
					kip->ki_guid = elp->el_uguid;
					kip->ki_valid |= KI_VALID_GUID;
				}
				kip->ki_guid_expiry = (elp->el_uguid_valid) ? tv.tv_sec + elp->el_uguid_valid : 0;
				if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_USID) {
					kip->ki_ntsid = elp->el_usid;
					kip->ki_valid |= KI_VALID_NTSID;
				}
				kip->ki_ntsid_expiry = (elp->el_usid_valid) ? tv.tv_sec + elp->el_usid_valid : 0;
				if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_PWNAM) {
					const char *oname = kip->ki_name;
					kip->ki_name = speculative_name;
					speculative_name = NULL;
					kip->ki_valid |= KI_VALID_PWNAM;
					if (oname) {
						/*
						 * free oname (if any) outside
						 * the lock
						 */
						speculative_name = oname;
					}
				}
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
			    (elp->el_uguid_valid) ? tv.tv_sec + elp->el_uguid_valid : 0,
			    (elp->el_flags & KAUTH_EXTLOOKUP_VALID_USID) ? &elp->el_usid : NULL,
			    (elp->el_usid_valid) ? tv.tv_sec + elp->el_usid_valid : 0,
			    (elp->el_flags & KAUTH_EXTLOOKUP_VALID_SUPGRPS) ? elp->el_sup_grp_cnt : 0,
			    (elp->el_flags & KAUTH_EXTLOOKUP_VALID_SUPGRPS) ? elp->el_sup_groups : NULL,
			    (elp->el_member_valid) ? tv.tv_sec + elp->el_member_valid : 0,
			    (elp->el_flags & KAUTH_EXTLOOKUP_VALID_PWNAM) ? speculative_name : NULL,
			    KI_VALID_PWNAM);
			if (kip != NULL) {
				if (rkip != NULL)
					*rkip = *kip;
				if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_PWNAM)
					speculative_name = NULL;
				KAUTH_DEBUG("CACHE - learned %d is " K_UUID_FMT, kip->ki_uid, K_UUID_ARG(kip->ki_guid));
				kauth_identity_register_and_free(kip);
			}
		}
	}

	/* group identity? (ignore, if we already processed it as a user) */
	if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_GID && !(elp->el_flags & KAUTH_EXTLOOKUP_VALID_UID)) {
		KAUTH_IDENTITY_LOCK();
		TAILQ_FOREACH(kip, &kauth_identities, ki_link) {
			/* matching record */
			if ((kip->ki_valid & KI_VALID_GID) && (kip->ki_gid == elp->el_gid)) {
				if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_GGUID) {
					kip->ki_guid = elp->el_gguid;
					kip->ki_valid |= KI_VALID_GUID;
				}
				kip->ki_guid_expiry = (elp->el_gguid_valid) ? tv.tv_sec + elp->el_gguid_valid : 0;
				if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_GSID) {
					kip->ki_ntsid = elp->el_gsid;
					kip->ki_valid |= KI_VALID_NTSID;
				}
				kip->ki_ntsid_expiry = (elp->el_gsid_valid) ? tv.tv_sec + elp->el_gsid_valid : 0;
				if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_GRNAM) {
					const char *oname = kip->ki_name;
					kip->ki_name = speculative_name;
					speculative_name = NULL;
					kip->ki_valid |= KI_VALID_GRNAM;
					if (oname) {
						/*
						 * free oname (if any) outside
						 * the lock
						 */
						speculative_name = oname;
					}
				}
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
			    (elp->el_gguid_valid) ? tv.tv_sec + elp->el_gguid_valid : 0,
			    (elp->el_flags & KAUTH_EXTLOOKUP_VALID_GSID) ? &elp->el_gsid : NULL,
			    (elp->el_gsid_valid) ? tv.tv_sec + elp->el_gsid_valid : 0,
			    (elp->el_flags & KAUTH_EXTLOOKUP_VALID_SUPGRPS) ? elp->el_sup_grp_cnt : 0,
			    (elp->el_flags & KAUTH_EXTLOOKUP_VALID_SUPGRPS) ? elp->el_sup_groups : NULL,
			    (elp->el_member_valid) ? tv.tv_sec + elp->el_member_valid : 0,
			    (elp->el_flags & KAUTH_EXTLOOKUP_VALID_GRNAM) ? speculative_name : NULL,
			    KI_VALID_GRNAM);
			if (kip != NULL) {
				if (rkip != NULL)
					*rkip = *kip;
				if (elp->el_flags & KAUTH_EXTLOOKUP_VALID_GRNAM)
					speculative_name = NULL;
				KAUTH_DEBUG("CACHE - learned %d is " K_UUID_FMT, kip->ki_uid, K_UUID_ARG(kip->ki_guid));
				kauth_identity_register_and_free(kip);
			}
		}
	}

	/* If we have a name reference to drop, drop it here */
	if (speculative_name != NULL) {
		vfs_removename(speculative_name);
	}
}


/*
 * Trim older entries from the identity cache.
 *
 * Must be called with the identity cache lock held.
 */
static void
kauth_identity_trimcache(int newsize) {
	struct kauth_identity 		*kip;
	
	lck_mtx_assert(kauth_identity_mtx, LCK_MTX_ASSERT_OWNED);
		
	while (kauth_identity_count > newsize) {
		kip = TAILQ_LAST(&kauth_identities, kauth_identity_head);
		TAILQ_REMOVE(&kauth_identities, kip, ki_link);
		kauth_identity_count--;
		FREE(kip, M_KAUTH);
	}
}

/*
 * kauth_identity_lru
 *
 * Description:	Promote the entry to the head of the LRU, assumes the cache
 *		is locked.
 *
 * Parameters:	kip				kauth identity to move to the
 *						head of the LRU list, if it's
 *						not already there
 *
 * Returns:	(void)
 *
 * Notes:	This is called even if the entry has expired; typically an
 *		expired entry that's been looked up is about to be revalidated,
 *		and having it closer to the head of the LRU means finding it
 *		quickly again when the revalidation comes through.
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
 * kauth_identity_guid_expired
 *
 * Description:	Handle lazy expiration of GUID translations.
 *
 * Parameters:	kip				kauth identity to check for
 *						GUID expiration
 *
 * Returns:	1				Expired
 *		0				Not expired
 */
static int
kauth_identity_guid_expired(struct kauth_identity *kip)
{
	struct timeval tv;

	/*
	 * Expiration time of 0 means this entry is persistent.
	 */
	if (kip->ki_guid_expiry == 0)
		return (0);

	microuptime(&tv);
	KAUTH_DEBUG("CACHE - GUID expires @ %ld now %ld", kip->ki_guid_expiry, tv.tv_sec);

	return((kip->ki_guid_expiry <= tv.tv_sec) ? 1 : 0);
}


/*
 * kauth_identity_ntsid_expired
 *
 * Description:	Handle lazy expiration of NTSID translations.
 *
 * Parameters:	kip				kauth identity to check for
 *						NTSID expiration
 *
 * Returns:	1				Expired
 *		0				Not expired
 */
static int
kauth_identity_ntsid_expired(struct kauth_identity *kip)
{
	struct timeval tv;

	/*
	 * Expiration time of 0 means this entry is persistent.
	 */
	if (kip->ki_ntsid_expiry == 0)
		return (0);

	microuptime(&tv);
	KAUTH_DEBUG("CACHE - NTSID expires @ %ld now %ld", kip->ki_ntsid_expiry, tv.tv_sec);

	return((kip->ki_ntsid_expiry <= tv.tv_sec) ? 1 : 0);
}

/*
 * kauth_identity_groups_expired
 *
 * Description:	Handle lazy expiration of supplemental group translations.
 *
 * Parameters:	kip				kauth identity to check for
 *						groups expiration
 *
 * Returns:	1				Expired
 *		0				Not expired
 */
static int
kauth_identity_groups_expired(struct kauth_identity *kip)
{
	struct timeval tv;

	/*
	 * Expiration time of 0 means this entry is persistent.
	 */
	if (kip->ki_groups_expiry == 0)
		return (0);

	microuptime(&tv);
	KAUTH_DEBUG("CACHE - GROUPS expires @ %ld now %ld\n", kip->ki_groups_expiry, tv.tv_sec);

	return((kip->ki_groups_expiry <= tv.tv_sec) ? 1 : 0);
}

/*
 * kauth_identity_find_uid
 *
 * Description: Search for an entry by UID
 *
 * Parameters:	uid				UID to find
 *		kir				Pointer to return area
 *		getname				Name buffer, if ki_name wanted
 *
 * Returns:	0				Found
 *		ENOENT				Not found
 *
 * Implicit returns:
 *		*klr				Modified, if found
 */
static int
kauth_identity_find_uid(uid_t uid, struct kauth_identity *kir, char *getname)
{
	struct kauth_identity *kip;

	KAUTH_IDENTITY_LOCK();
	TAILQ_FOREACH(kip, &kauth_identities, ki_link) {
		if ((kip->ki_valid & KI_VALID_UID) && (uid == kip->ki_uid)) {
			kauth_identity_lru(kip);
			/* Copy via structure assignment */
			*kir = *kip;
			/* If a name is wanted and one exists, copy it out */
			if (getname != NULL && (kip->ki_valid & (KI_VALID_PWNAM | KI_VALID_GRNAM)))
				strlcpy(getname, kip->ki_name, MAXPATHLEN);
			break;
		}
	}
	KAUTH_IDENTITY_UNLOCK();
	return((kip == NULL) ? ENOENT : 0);
}


/*
 * kauth_identity_find_gid
 *
 * Description: Search for an entry by GID
 *
 * Parameters:	gid				GID to find
 *		kir				Pointer to return area
 *		getname				Name buffer, if ki_name wanted
 *
 * Returns:	0				Found
 *		ENOENT				Not found
 *
 * Implicit returns:
 *		*klr				Modified, if found
 */
static int
kauth_identity_find_gid(uid_t gid, struct kauth_identity *kir, char *getname)
{
	struct kauth_identity *kip;

	KAUTH_IDENTITY_LOCK();
	TAILQ_FOREACH(kip, &kauth_identities, ki_link) {
		if ((kip->ki_valid & KI_VALID_GID) && (gid == kip->ki_gid)) {
			kauth_identity_lru(kip);
			/* Copy via structure assignment */
			*kir = *kip;
			/* If a name is wanted and one exists, copy it out */
			if (getname != NULL && (kip->ki_valid & (KI_VALID_PWNAM | KI_VALID_GRNAM)))
				strlcpy(getname, kip->ki_name, MAXPATHLEN);
			break;
		}
	}
	KAUTH_IDENTITY_UNLOCK();
	return((kip == NULL) ? ENOENT : 0);
}


/*
 * kauth_identity_find_guid
 *
 * Description: Search for an entry by GUID
 *
 * Parameters:	guidp				Pointer to GUID to find
 *		kir				Pointer to return area
 *		getname				Name buffer, if ki_name wanted
 *
 * Returns:	0				Found
 *		ENOENT				Not found
 *
 * Implicit returns:
 *		*klr				Modified, if found
 *
 * Note:	The association may be expired, in which case the caller
 *		may elect to call out to userland to revalidate.
 */
static int
kauth_identity_find_guid(guid_t *guidp, struct kauth_identity *kir, char *getname)
{
	struct kauth_identity *kip;

	KAUTH_IDENTITY_LOCK();
	TAILQ_FOREACH(kip, &kauth_identities, ki_link) {
		if ((kip->ki_valid & KI_VALID_GUID) && (kauth_guid_equal(guidp, &kip->ki_guid))) {
			kauth_identity_lru(kip);
			/* Copy via structure assignment */
			*kir = *kip;
			/* If a name is wanted and one exists, copy it out */
			if (getname != NULL && (kip->ki_valid & (KI_VALID_PWNAM | KI_VALID_GRNAM)))
				strlcpy(getname, kip->ki_name, MAXPATHLEN);
			break;
		}
	}
	KAUTH_IDENTITY_UNLOCK();
	return((kip == NULL) ? ENOENT : 0);
}

/*
 * kauth_identity_find_nam
 *
 * Description:	Search for an entry by name
 *
 * Parameters:	name				Pointer to name to find
 *		valid				KI_VALID_PWNAM or KI_VALID_GRNAM
 *		kir				Pointer to return area
 *
 * Returns:	0				Found
 *		ENOENT				Not found
 *
 * Implicit returns:
 *		*klr				Modified, if found
 */
static int
kauth_identity_find_nam(char *name, int valid, struct kauth_identity *kir)
{
	struct kauth_identity *kip;

	KAUTH_IDENTITY_LOCK();
	TAILQ_FOREACH(kip, &kauth_identities, ki_link) {
		if ((kip->ki_valid & valid) && !strcmp(name, kip->ki_name)) {
			kauth_identity_lru(kip);
			/* Copy via structure assignment */
			*kir = *kip;
			break;
		}
	}
	KAUTH_IDENTITY_UNLOCK();
	return((kip == NULL) ? ENOENT : 0);
}


/*
 * kauth_identity_find_ntsid
 *
 * Description: Search for an entry by NTSID
 *
 * Parameters:	ntsid				Pointer to NTSID to find
 *		kir				Pointer to return area
 *		getname				Name buffer, if ki_name wanted
 *
 * Returns:	0				Found
 *		ENOENT				Not found
 *
 * Implicit returns:
 *		*klr				Modified, if found
 *
 * Note:	The association may be expired, in which case the caller
 *		may elect to call out to userland to revalidate.
 */
static int
kauth_identity_find_ntsid(ntsid_t *ntsid, struct kauth_identity *kir, char *getname)
{
	struct kauth_identity *kip;

	KAUTH_IDENTITY_LOCK();
	TAILQ_FOREACH(kip, &kauth_identities, ki_link) {
		if ((kip->ki_valid & KI_VALID_NTSID) && (kauth_ntsid_equal(ntsid, &kip->ki_ntsid))) {
			kauth_identity_lru(kip);
			/* Copy via structure assignment */
			*kir = *kip;
			/* If a name is wanted and one exists, copy it out */
			if (getname != NULL && (kip->ki_valid & (KI_VALID_PWNAM | KI_VALID_GRNAM)))
				strlcpy(getname, kip->ki_name, MAXPATHLEN);
			break;
		}
	}
	KAUTH_IDENTITY_UNLOCK();
	return((kip == NULL) ? ENOENT : 0);
}
#endif	/* CONFIG_EXT_RESOLVER */


/*
 * GUID handling.
 */
guid_t kauth_null_guid;


/*
 * kauth_guid_equal
 *
 * Description:	Determine the equality of two GUIDs
 *
 * Parameters:	guid1				Pointer to first GUID
 *		guid2				Pointer to second GUID
 *
 * Returns:	0				If GUIDs are unequal
 *		!0				If GUIDs are equal
 */
int
kauth_guid_equal(guid_t *guid1, guid_t *guid2)
{
	return(bcmp(guid1, guid2, sizeof(*guid1)) == 0);
}


/*
 * kauth_wellknown_guid
 *
 * Description:	Determine if a GUID is a well-known GUID
 *
 * Parameters:	guid				Pointer to GUID to check
 *
 * Returns:	KAUTH_WKG_NOT			Not a well known GUID
 *		KAUTH_WKG_EVERYBODY		"Everybody"
 *		KAUTH_WKG_NOBODY		"Nobody"
 *		KAUTH_WKG_OWNER			"Other"
 *		KAUTH_WKG_GROUP			"Group"
 */
int
kauth_wellknown_guid(guid_t *guid)
{
	static char	fingerprint[] = {0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef};
	uint32_t		code;
	/*
	 * All WKGs begin with the same 12 bytes.
	 */
	if (bcmp((void *)guid, fingerprint, 12) == 0) {
		/*
		 * The final 4 bytes are our code (in network byte order).
		 */
		code = OSSwapHostToBigInt32(*(uint32_t *)&guid->g_guid[12]);
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
 * kauth_ntsid_equal
 *
 * Description:	Determine the equality of two NTSIDs (NT Security Identifiers) 
 *
 * Parameters:	sid1				Pointer to first NTSID
 *		sid2				Pointer to second NTSID
 *
 * Returns:	0				If GUIDs are unequal
 *		!0				If GUIDs are equal
 */
int
kauth_ntsid_equal(ntsid_t *sid1, ntsid_t *sid2)
{
	/* check sizes for equality, also sanity-check size while we're at it */
	if ((KAUTH_NTSID_SIZE(sid1) == KAUTH_NTSID_SIZE(sid2)) &&
	    (KAUTH_NTSID_SIZE(sid1) <= sizeof(*sid1)) &&
	    bcmp(sid1, sid2, KAUTH_NTSID_SIZE(sid1)) == 0)
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



/*
 * kauth_cred_change_egid
 *
 * Description:	Set EGID by changing the first element of cr_groups for the
 *		passed credential; if the new EGID exists in the list of
 *		groups already, then rotate the old EGID into its position,
 *		otherwise replace it
 *
 * Parameters:	cred			Pointer to the credential to modify
 *		new_egid		The new EGID to set
 *
 * Returns:	0			The egid did not displace a member of
 *					the supplementary group list
 *		1			The egid being set displaced a member
 *					of the supplementary groups list
 *
 * Note:	Utility function; internal use only because of locking.
 *
 *		This function operates on the credential passed; the caller
 *		must operate either on a newly allocated credential (one for
 *		which there is no hash cache reference and no externally
 *		visible pointer reference), or a template credential.
 */
static int
kauth_cred_change_egid(kauth_cred_t cred, gid_t new_egid)
{
	int	i;
	int	displaced = 1;
#if radar_4600026
	int	is_member;
#endif	/* radar_4600026 */
	gid_t	old_egid = kauth_cred_getgid(cred);
	posix_cred_t pcred = posix_cred_get(cred);

	/* Ignoring the first entry, scan for a match for the new egid */
	for (i = 1; i < pcred->cr_ngroups; i++) {
		/*
		 * If we find a match, swap them so we don't lose overall
		 * group information
		 */
		if (pcred->cr_groups[i] == new_egid) {
			pcred->cr_groups[i] = old_egid;
			DEBUG_CRED_CHANGE("kauth_cred_change_egid: unset displaced\n");
			displaced = 0;
			break;
		}
	}

#if radar_4600026
#error Fix radar 4600026 first!!!

/*
This is correct for memberd behaviour, but incorrect for POSIX; to address
this, we would need to automatically opt-out any SUID/SGID binary, and force
it to use initgroups to opt back in.  We take the approach of considering it
opt'ed out in any group of 16 displacement instead, since it's a much more
conservative approach (i.e. less likely to cause things to break).
*/

	/*
	 * If we displaced a member of the supplementary groups list of the
	 * credential, and we have not opted out of memberd, then if memberd
	 * says that the credential is a member of the group, then it has not
	 * actually been displaced.
	 *
	 * NB:	This is typically a cold code path.
	 */
	if (displaced && !(pcred->cr_flags & CRF_NOMEMBERD) &&
	    kauth_cred_ismember_gid(cred, new_egid, &is_member) == 0 &&
	    is_member) {
	    	displaced = 0;
		DEBUG_CRED_CHANGE("kauth_cred_change_egid: reset displaced\n");
	}
#endif	/* radar_4600026 */

	/* set the new EGID into the old spot */
	pcred->cr_groups[0] = new_egid;

	return (displaced);
}


/*
 * kauth_cred_getuid
 *
 * Description:	Fetch UID from credential
 *
 * Parameters:	cred				Credential to examine
 *
 * Returns:	(uid_t)				UID associated with credential
 */
uid_t
kauth_cred_getuid(kauth_cred_t cred)
{
	NULLCRED_CHECK(cred);
	return(posix_cred_get(cred)->cr_uid);
}


/*
 * kauth_cred_getruid
 *
 * Description:	Fetch RUID from credential
 *
 * Parameters:	cred				Credential to examine
 *
 * Returns:	(uid_t)				RUID associated with credential
 */
uid_t
kauth_cred_getruid(kauth_cred_t cred)
{
	NULLCRED_CHECK(cred);
	return(posix_cred_get(cred)->cr_ruid);
}


/*
 * kauth_cred_getsvuid
 *
 * Description:	Fetch SVUID from credential
 *
 * Parameters:	cred				Credential to examine
 *
 * Returns:	(uid_t)				SVUID associated with credential
 */
uid_t
kauth_cred_getsvuid(kauth_cred_t cred)
{
	NULLCRED_CHECK(cred);
	return(posix_cred_get(cred)->cr_svuid);
}


/*
 * kauth_cred_getgid
 *
 * Description:	Fetch GID from credential
 *
 * Parameters:	cred				Credential to examine
 *
 * Returns:	(gid_t)				GID associated with credential
 */
gid_t
kauth_cred_getgid(kauth_cred_t cred)
{
	NULLCRED_CHECK(cred);
	return(posix_cred_get(cred)->cr_gid);
}


/*
 * kauth_cred_getrgid
 *
 * Description:	Fetch RGID from credential
 *
 * Parameters:	cred				Credential to examine
 *
 * Returns:	(gid_t)				RGID associated with credential
 */
gid_t
kauth_cred_getrgid(kauth_cred_t cred)
{
	NULLCRED_CHECK(cred);
	return(posix_cred_get(cred)->cr_rgid);
}


/*
 * kauth_cred_getsvgid
 *
 * Description:	Fetch SVGID from credential
 *
 * Parameters:	cred				Credential to examine
 *
 * Returns:	(gid_t)				SVGID associated with credential
 */
gid_t
kauth_cred_getsvgid(kauth_cred_t cred)
{
	NULLCRED_CHECK(cred);
	return(posix_cred_get(cred)->cr_svgid);
}


static int	kauth_cred_cache_lookup(int from, int to, void *src, void *dst);

#if CONFIG_EXT_RESOLVER == 0
/*
 * If there's no resolver, short-circuit the kauth_cred_x2y() lookups.
 */
static __inline int
kauth_cred_cache_lookup(__unused int from, __unused int to,
	__unused void *src, __unused void *dst)
{
	return (EWOULDBLOCK);

}
#endif

#if defined(CONFIG_EXT_RESOLVER) && (CONFIG_EXT_RESOLVER)
/*
 * Structure to hold supplemental groups. Used for impedance matching with 
 * kauth_cred_cache_lookup below.
 */
struct supgroups {
	int *count;
	gid_t *groups;
};

/*
 * kauth_cred_uid2groups
 *
 * Description:	Fetch supplemental GROUPS from UID
 *
 * Parameters:	uid				UID to examine
 *		groups				pointer to an array of gid_ts
 *		gcount				pointer to the number of groups wanted/returned
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*groups				Modified, if successful
 *		*gcount				Modified, if successful
 *
 */
static int
kauth_cred_uid2groups(uid_t *uid, gid_t *groups, int *gcount)
{
	int rv;

	struct supgroups supgroups;
	supgroups.count = gcount;
	supgroups.groups = groups;

	rv = kauth_cred_cache_lookup(KI_VALID_UID, KI_VALID_GROUPS, uid, &supgroups);

	return (rv);
}
#endif

/*
 * kauth_cred_guid2pwnam
 *
 * Description:	Fetch PWNAM from GUID
 *
 * Parameters:	guidp				Pointer to GUID to examine
 *		pwnam				Pointer to user@domain buffer
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*pwnam				Modified, if successful
 *
 * Notes:	pwnam is assumed to point to a buffer of MAXPATHLEN in size
 */
int
kauth_cred_guid2pwnam(guid_t *guidp, char *pwnam)
{
	return(kauth_cred_cache_lookup(KI_VALID_GUID, KI_VALID_PWNAM, guidp, pwnam));
}


/*
 * kauth_cred_guid2grnam
 *
 * Description:	Fetch GRNAM from GUID
 *
 * Parameters:	guidp				Pointer to GUID to examine
 *		grnam				Pointer to group@domain buffer
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*grnam				Modified, if successful
 *
 * Notes:	grnam is assumed to point to a buffer of MAXPATHLEN in size
 */
int
kauth_cred_guid2grnam(guid_t *guidp, char *grnam)
{
	return(kauth_cred_cache_lookup(KI_VALID_GUID, KI_VALID_GRNAM, guidp, grnam));
}


/*
 * kauth_cred_pwnam2guid
 *
 * Description:	Fetch PWNAM from GUID
 *
 * Parameters:	pwnam				String containing user@domain
 *		guidp				Pointer to buffer for GUID
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*guidp				Modified, if successful
 *
 * Notes:	pwnam should not point to a request larger than MAXPATHLEN
 *		bytes in size, including the NUL termination of the string.
 */
int
kauth_cred_pwnam2guid(char *pwnam, guid_t *guidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_PWNAM, KI_VALID_GUID, pwnam, guidp));
}


/*
 * kauth_cred_grnam2guid
 *
 * Description:	Fetch GRNAM from GUID
 *
 * Parameters:	grnam				String containing group@domain
 *		guidp				Pointer to buffer for GUID
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*guidp				Modified, if successful
 *
 * Notes:	grnam should not point to a request larger than MAXPATHLEN
 *		bytes in size, including the NUL termination of the string.
 */
int
kauth_cred_grnam2guid(char *grnam, guid_t *guidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_GRNAM, KI_VALID_GUID, grnam, guidp));
}


/*
 * kauth_cred_guid2uid
 *
 * Description:	Fetch UID from GUID
 *
 * Parameters:	guidp				Pointer to GUID to examine
 *		uidp				Pointer to buffer for UID
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*uidp				Modified, if successful
 */
int
kauth_cred_guid2uid(guid_t *guidp, uid_t *uidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_GUID, KI_VALID_UID, guidp, uidp));
}


/*
 * kauth_cred_guid2gid
 *
 * Description:	Fetch GID from GUID
 *
 * Parameters:	guidp				Pointer to GUID to examine
 *		gidp				Pointer to buffer for GID
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*gidp				Modified, if successful
 */
int
kauth_cred_guid2gid(guid_t *guidp, gid_t *gidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_GUID, KI_VALID_GID, guidp, gidp));
}


/*
 * kauth_cred_ntsid2uid
 *
 * Description:	Fetch UID from NTSID
 *
 * Parameters:	sidp				Pointer to NTSID to examine
 *		uidp				Pointer to buffer for UID
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*uidp				Modified, if successful
 */
int
kauth_cred_ntsid2uid(ntsid_t *sidp, uid_t *uidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_NTSID, KI_VALID_UID, sidp, uidp));
}


/*
 * kauth_cred_ntsid2gid
 *
 * Description:	Fetch GID from NTSID
 *
 * Parameters:	sidp				Pointer to NTSID to examine
 *		gidp				Pointer to buffer for GID
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*gidp				Modified, if successful
 */
int
kauth_cred_ntsid2gid(ntsid_t *sidp, gid_t *gidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_NTSID, KI_VALID_GID, sidp, gidp));
}


/*
 * kauth_cred_ntsid2guid
 *
 * Description:	Fetch GUID from NTSID
 *
 * Parameters:	sidp				Pointer to NTSID to examine
 *		guidp				Pointer to buffer for GUID
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*guidp				Modified, if successful
 */
int
kauth_cred_ntsid2guid(ntsid_t *sidp, guid_t *guidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_NTSID, KI_VALID_GUID, sidp, guidp));
}


/*
 * kauth_cred_uid2guid
 *
 * Description:	Fetch GUID from UID
 *
 * Parameters:	uid				UID to examine
 *		guidp				Pointer to buffer for GUID
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*guidp				Modified, if successful
 */
int
kauth_cred_uid2guid(uid_t uid, guid_t *guidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_UID, KI_VALID_GUID, &uid, guidp));
}


/*
 * kauth_cred_getguid
 *
 * Description:	Fetch GUID from credential
 *
 * Parameters:	cred				Credential to examine
 *		guidp				Pointer to buffer for GUID
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*guidp				Modified, if successful
 */
int
kauth_cred_getguid(kauth_cred_t cred, guid_t *guidp)
{
	NULLCRED_CHECK(cred);
	return(kauth_cred_uid2guid(kauth_cred_getuid(cred), guidp));
}


/*
 * kauth_cred_getguid
 *
 * Description:	Fetch GUID from GID
 *
 * Parameters:	gid				GID to examine
 *		guidp				Pointer to buffer for GUID
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*guidp				Modified, if successful
 */
int
kauth_cred_gid2guid(gid_t gid, guid_t *guidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_GID, KI_VALID_GUID, &gid, guidp));
}


/*
 * kauth_cred_uid2ntsid
 *
 * Description:	Fetch NTSID from UID
 *
 * Parameters:	uid				UID to examine
 *		sidp				Pointer to buffer for NTSID
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*sidp				Modified, if successful
 */
int
kauth_cred_uid2ntsid(uid_t uid, ntsid_t *sidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_UID, KI_VALID_NTSID, &uid, sidp));
}


/*
 * kauth_cred_getntsid
 *
 * Description:	Fetch NTSID from credential
 *
 * Parameters:	cred				Credential to examine
 *		sidp				Pointer to buffer for NTSID
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*sidp				Modified, if successful
 */
int
kauth_cred_getntsid(kauth_cred_t cred, ntsid_t *sidp)
{
	NULLCRED_CHECK(cred);
	return(kauth_cred_uid2ntsid(kauth_cred_getuid(cred), sidp));
}


/*
 * kauth_cred_gid2ntsid
 *
 * Description:	Fetch NTSID from GID
 *
 * Parameters:	gid				GID to examine
 *		sidp				Pointer to buffer for NTSID
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*sidp				Modified, if successful
 */
int
kauth_cred_gid2ntsid(gid_t gid, ntsid_t *sidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_GID, KI_VALID_NTSID, &gid, sidp));
}


/*
 * kauth_cred_guid2ntsid
 *
 * Description:	Fetch NTSID from GUID
 *
 * Parameters:	guidp				Pointer to GUID to examine
 *		sidp				Pointer to buffer for NTSID
 *
 * Returns:	0				Success
 *	kauth_cred_cache_lookup:EINVAL
 *
 * Implicit returns:
 *		*sidp				Modified, if successful
 */
int
kauth_cred_guid2ntsid(guid_t *guidp, ntsid_t *sidp)
{
	return(kauth_cred_cache_lookup(KI_VALID_GUID, KI_VALID_NTSID, guidp, sidp));
}


/*
 * kauth_cred_cache_lookup
 *
 * Description:	Lookup a translation in the cache; if one is not found, and
 *		the attempt was not fatal, submit the request to the resolver
 *		instead, and wait for it to complete or be aborted.
 *
 * Parameters:	from				Identity information we have
 *		to				Identity information we want
 *		src				Pointer to buffer containing
 *						the source identity
 *		dst				Pointer to buffer to receive
 *						the target identity
 *
 * Returns:	0				Success
 *		EINVAL				Unknown source identity type
 */
#if CONFIG_EXT_RESOLVER
static int
kauth_cred_cache_lookup(int from, int to, void *src, void *dst)
{
	struct kauth_identity ki;
	struct kauth_identity_extlookup el;
	int error;
	uint64_t extend_data = 0ULL;
	int (* expired)(struct kauth_identity *kip);
	char *namebuf = NULL;

	KAUTH_DEBUG("CACHE - translate %d to %d", from, to);
	
	/*
	 * Look for an existing cache entry for this association.
	 * If the entry has not expired, return the cached information.
	 * We do not cache user@domain translations here; they use too
	 * much memory to hold onto forever, and can not be updated
	 * atomically.
	 */
	if (to == KI_VALID_PWNAM || to == KI_VALID_GRNAM) {
		namebuf = dst;
	}
	ki.ki_valid = 0;
	switch(from) {
	case KI_VALID_UID:
		error = kauth_identity_find_uid(*(uid_t *)src, &ki, namebuf);
		break;
	case KI_VALID_GID:
		error = kauth_identity_find_gid(*(gid_t *)src, &ki, namebuf);
		break;
	case KI_VALID_GUID:
		error = kauth_identity_find_guid((guid_t *)src, &ki, namebuf);
		break;
	case KI_VALID_NTSID:
		error = kauth_identity_find_ntsid((ntsid_t *)src, &ki, namebuf);
		break;
	case KI_VALID_PWNAM:
	case KI_VALID_GRNAM:
		/* Names are unique in their 'from' space */
		error = kauth_identity_find_nam((char *)src, from, &ki);
		break;
	default:
		return(EINVAL);
	}
	/* lookup failure or error */
	if (error != 0) {
		/* any other error is fatal */
		if (error != ENOENT) {
			/* XXX bogus check - this is not possible */
			KAUTH_DEBUG("CACHE - cache search error %d", error);
			return(error);
		}
	} else {
		/* found a valid cached entry, check expiry */
		switch(to) {
		case KI_VALID_GUID:
			expired = kauth_identity_guid_expired;
			break;
		case KI_VALID_NTSID:
			expired = kauth_identity_ntsid_expired;
			break;
		case KI_VALID_GROUPS:
			expired = kauth_identity_groups_expired;
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

		/*
		 * If no expiry function, or not expired, we have found
		 * a hit.
		 */
		if (expired) {
			if (!expired(&ki)) {
				KAUTH_DEBUG("CACHE - entry valid, unexpired");
				expired = NULL; /* must clear it is used as a flag */
			} else {
				/*
				 * We leave ki_valid set here; it contains a
				 * translation but the TTL has expired.  If we can't
				 * get a result from the resolver, we will use it as
				 * a better-than nothing alternative.
				 */
				
				KAUTH_DEBUG("CACHE - expired entry found");
			}
		} else {
			KAUTH_DEBUG("CACHE - no expiry function");
		}
		
		if (!expired) {
			/* do we have a translation? */
			if (ki.ki_valid & to) {
				KAUTH_DEBUG("CACHE - found matching entry with valid 0x%08x", ki.ki_valid);
				DTRACE_PROC4(kauth__identity__cache__hit, int, from, int, to, void *, src, void *, dst);
				goto found;
			} else {
				/*
				 * GUIDs and NTSIDs map to either a UID or a GID, but not both. 
				 * If we went looking for a translation from GUID or NTSID and 
				 * found a translation that wasn't for our desired type, then 
				 * don't bother calling the resolver. We know that this 
				 * GUID/NTSID can't translate to our desired type.
				 */
				switch(from) {
				case KI_VALID_GUID:
				case KI_VALID_NTSID:
					switch(to) {
					case KI_VALID_GID:
						if ((ki.ki_valid & KI_VALID_UID)) {
							KAUTH_DEBUG("CACHE - unexpected entry 0x%08x & %x", ki.ki_valid, KI_VALID_GID);
							return (ENOENT);
						}
						break;
					case KI_VALID_UID:
						if ((ki.ki_valid & KI_VALID_GID)) {
							KAUTH_DEBUG("CACHE - unexpected entry 0x%08x & %x", ki.ki_valid, KI_VALID_UID);
							return (ENOENT);
						}
						break;
					}
					break;
				}
			}
		}
	}

	/*
	 * We failed to find a cache entry; call the resolver.
	 *
	 * Note:	We ask for as much non-extended data as we can get,
	 *		and only provide (or ask for) extended information if
	 *		we have a 'from' (or 'to') which requires it.  This
	 *		way we don't pay for the extra transfer overhead for
	 *		data we don't need.
	 */
	bzero(&el, sizeof(el));
	el.el_info_pid = current_proc()->p_pid;
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
	case KI_VALID_PWNAM:
		/* extra overhead */
		el.el_flags = KAUTH_EXTLOOKUP_VALID_PWNAM;
		extend_data = CAST_USER_ADDR_T(src);
		break;
	case KI_VALID_GRNAM:
		/* extra overhead */
		el.el_flags = KAUTH_EXTLOOKUP_VALID_GRNAM;
		extend_data = CAST_USER_ADDR_T(src);
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
	if (to == KI_VALID_PWNAM) {
		/* extra overhead */
		el.el_flags |= KAUTH_EXTLOOKUP_WANT_PWNAM;
		extend_data = CAST_USER_ADDR_T(dst);
	}
	if (to == KI_VALID_GRNAM) {
		/* extra overhead */
		el.el_flags |= KAUTH_EXTLOOKUP_WANT_GRNAM;
		extend_data = CAST_USER_ADDR_T(dst);
	}
	if (to == KI_VALID_GROUPS) {
		/* Expensive and only useful for an NFS client not using kerberos */
		el.el_flags |= KAUTH_EXTLOOKUP_WANT_SUPGRPS;
		if (ki.ki_valid & KI_VALID_GROUPS) {
			/*
			 * Copy the current supplemental groups for the resolver. 
			 * The resolver should check these groups first and if
			 * the user (uid) is still a member it should endeavor to 
			 * keep them in the list. Otherwise NFS clients could get
			 * changing access to server file system objects on each
			 * expiration.
			 */
			el.el_sup_grp_cnt = ki.ki_supgrpcnt;

			memcpy(el.el_sup_groups, ki.ki_supgrps, sizeof (el.el_sup_groups[0]) * ki.ki_supgrpcnt);
			/* Let the resolver know these were the previous valid groups */
			el.el_flags |= KAUTH_EXTLOOKUP_VALID_SUPGRPS;
			KAUTH_DEBUG("GROUPS: Sending previously valid GROUPS");
		} else
			KAUTH_DEBUG("GROUPS: no valid groups to send");
	}

	/* Call resolver */
	KAUTH_DEBUG("CACHE - calling resolver for %x", el.el_flags);

	DTRACE_PROC3(kauth__id__resolver__submitted, int, from, int, to, uintptr_t, src);
	
	error = kauth_resolver_submit(&el, extend_data);

	DTRACE_PROC2(kauth__id__resolver__returned, int, error, struct kauth_identity_extlookup *, &el)
	
	KAUTH_DEBUG("CACHE - resolver returned %d", error);

	/* was the external lookup successful? */
	if (error == 0) {
		/*
		 * Save the results from the lookup - we may have other
		 * information, even if we didn't get a guid or the
		 * extended data.
		 *
		 * If we came from a name, we know the extend_data is valid.
		 */
		if (from == KI_VALID_PWNAM)
			el.el_flags |= KAUTH_EXTLOOKUP_VALID_PWNAM;
		else if (from == KI_VALID_GRNAM)
			el.el_flags |= KAUTH_EXTLOOKUP_VALID_GRNAM;

		kauth_identity_updatecache(&el, &ki, extend_data);

		/*
		 * Check to see if we have a valid cache entry
		 * originating from the result.
		 */
		if (!(ki.ki_valid & to)) {
			error = ENOENT;
		}
	}
	if (error)
		return(error);
found:
	/*
	 * Copy from the appropriate struct kauth_identity cache entry
	 * structure into the destination buffer area.
	 */
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
	case KI_VALID_GROUPS: {
			struct supgroups *gp = (struct supgroups *)dst;
			u_int32_t limit = ki.ki_supgrpcnt;
			
			if (gp->count) {
				limit = MIN(ki.ki_supgrpcnt, *gp->count);
				*gp->count = limit;
			}
			
			memcpy(gp->groups, ki.ki_supgrps, sizeof(gid_t) * limit);
		}
		break;
	case KI_VALID_PWNAM:
	case KI_VALID_GRNAM:
		/* handled in kauth_resolver_complete() */
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

/*
 * kauth_groups_init
 *
 * Description:	Initialize the groups cache
 *
 * Parameters:	(void)
 *
 * Returns:	(void)
 *
 * Notes:	Initialize the groups cache for use; the group cache is used
 *		to avoid unnecessary calls out to user space.
 *
 *		This function is called from kauth_init() in the file
 *		kern_authorization.c.
 */
void
kauth_groups_init(void)
{
	TAILQ_INIT(&kauth_groups);
	kauth_groups_mtx = lck_mtx_alloc_init(kauth_lck_grp, 0/*LCK_ATTR_NULL*/);
}


/*
 * kauth_groups_expired
 *
 * Description:	Handle lazy expiration of group membership cache entries
 *
 * Parameters:	gm				group membership entry to
 *						check for expiration
 *
 * Returns:	1				Expired
 *		0				Not expired
 */
static int
kauth_groups_expired(struct kauth_group_membership *gm)
{
	struct timeval tv;

	/*
	 * Expiration time of 0 means this entry is persistent.
	 */
	if (gm->gm_expiry == 0)
		return (0);
		
	microuptime(&tv);
	
	return((gm->gm_expiry <= tv.tv_sec) ? 1 : 0);
}


/*
 * kauth_groups_lru
 *
 * Description:	Promote the entry to the head of the LRU, assumes the cache
 *		is locked.
 *
 * Parameters:	kip				group membership entry to move
 *						to the head of the LRU list,
 *						if it's not already there
 *
 * Returns:	(void)
 *
 * Notes:	This is called even if the entry has expired; typically an
 *		expired entry that's been looked up is about to be revalidated,
 *		and having it closer to the head of the LRU means finding it
 *		quickly again when the revalidation comes through.
 */
static void
kauth_groups_lru(struct kauth_group_membership *gm)
{
	if (gm != TAILQ_FIRST(&kauth_groups)) {
		TAILQ_REMOVE(&kauth_groups, gm, gm_link);
		TAILQ_INSERT_HEAD(&kauth_groups, gm, gm_link);
	}
}


/*
 * kauth_groups_updatecache
 *
 * Description:	Given a lookup result, add any group cache associations that
 *		we don't currently have.
 *
 * Parameters:	elp				External lookup result from
 *						user space daemon to kernel
 *		rkip				pointer to returned kauth
 *						identity, or NULL
 *
 * Returns:	(void)
 */
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

	/*
	 * Search for an existing record for this association before inserting
	 * a new one; if we find one, update it instead of creating a new one
	 */
	KAUTH_GROUPS_LOCK();
	TAILQ_FOREACH(gm, &kauth_groups, gm_link) {
		if ((el->el_uid == gm->gm_uid) &&
		    (el->el_gid == gm->gm_gid)) {
			if (el->el_flags & KAUTH_EXTLOOKUP_ISMEMBER) {
				gm->gm_flags |= KAUTH_GROUP_ISMEMBER;
			} else {
				gm->gm_flags &= ~KAUTH_GROUP_ISMEMBER;
			}
			gm->gm_expiry = (el->el_member_valid) ? el->el_member_valid + tv.tv_sec : 0;
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
		gm->gm_expiry = (el->el_member_valid) ? el->el_member_valid + tv.tv_sec : 0;
	}		

	/*
	 * Insert the new entry.  Note that it's possible to race ourselves
	 * here and end up with duplicate entries in the list.  Wasteful, but
	 * harmless since the first into the list will never be looked up,
	 * and thus will eventually just fall off the end.
	 */
	KAUTH_GROUPS_LOCK();
	TAILQ_INSERT_HEAD(&kauth_groups, gm, gm_link);
	if (++kauth_groups_count > kauth_groups_cachemax) {
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
 * Trim older entries from the group membership cache.
 *
 * Must be called with the group cache lock held.
 */
static void
kauth_groups_trimcache(int new_size) {
        struct kauth_group_membership *gm;

	lck_mtx_assert(kauth_groups_mtx, LCK_MTX_ASSERT_OWNED);
        
	while (kauth_groups_count > new_size) {
		gm = TAILQ_LAST(&kauth_groups, kauth_groups_head);
		TAILQ_REMOVE(&kauth_groups, gm, gm_link);
		kauth_groups_count--;
		FREE(gm, M_KAUTH);
	}
}
#endif	/* CONFIG_EXT_RESOLVER */

/*
 * Group membership KPI
 */

/*
 * kauth_cred_ismember_gid
 *
 * Description:	Given a credential and a GID, determine if the GID is a member
 *		of one of the supplementary groups associated with the given
 *		credential
 *
 * Parameters:	cred				Credential to check in
 *		gid				GID to check for membership
 *		resultp				Pointer to int to contain the
 *						result of the call
 *
 * Returns:	0				Success
 *		ENOENT				Could not perform lookup
 *	kauth_resolver_submit:EWOULDBLOCK
 *	kauth_resolver_submit:EINTR
 *	kauth_resolver_submit:ENOMEM
 *	kauth_resolver_submit:ENOENT		User space daemon did not vend
 *						this credential.
 *	kauth_resolver_submit:???		Unlikely error from user space
 *
 * Implicit returns:
 *		*resultp (modified)	1	Is member
 *					0	Is not member
 *
 * Notes:	This function guarantees not to modify resultp when returning
 *		an error.
 *
 *		This function effectively checks the EGID as well, since the
 *		EGID is cr_groups[0] as an implementation detail.
 */
int
kauth_cred_ismember_gid(kauth_cred_t cred, gid_t gid, int *resultp)
{
	posix_cred_t pcred = posix_cred_get(cred);
	int i;

	/*
	 * Check the per-credential list of override groups.
	 *
	 * We can conditionalise this on cred->cr_gmuid == KAUTH_UID_NONE since
	 * the cache should be used for that case.
	 */
	for (i = 0; i < pcred->cr_ngroups; i++) {
		if (gid == pcred->cr_groups[i]) {
			*resultp = 1;
			return(0);
		}
	}

	/*
	 * If we don't have a UID for group membership checks, the in-cred list
	 * was authoritative and we can stop here.
	 */
	if (pcred->cr_gmuid == KAUTH_UID_NONE) {
		*resultp = 0;
		return(0);
	}
		
#if CONFIG_EXT_RESOLVER
	struct kauth_group_membership *gm;
	struct kauth_identity_extlookup el;
	int error;

	/*
	 * If the resolver hasn't checked in yet, we are early in the boot
	 * phase and the local group list is complete and authoritative.
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
		if ((gm->gm_uid == pcred->cr_gmuid) && (gm->gm_gid == gid) && !kauth_groups_expired(gm)) {
			kauth_groups_lru(gm);
			break;
		}
	}

	/* did we find a membership entry? */
	if (gm != NULL)
		*resultp = (gm->gm_flags & KAUTH_GROUP_ISMEMBER) ? 1 : 0;
	KAUTH_GROUPS_UNLOCK();

	/* if we did, we can return now */
	if (gm != NULL) {
		DTRACE_PROC2(kauth__group__cache__hit, int, pcred->cr_gmuid, int, gid);
		return(0);
	}

	/* nothing in the cache, need to go to userland */
	bzero(&el, sizeof(el));
	el.el_info_pid = current_proc()->p_pid;
	el.el_flags = KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_GID | KAUTH_EXTLOOKUP_WANT_MEMBERSHIP;
	el.el_uid = pcred->cr_gmuid;
	el.el_gid = gid;
	el.el_member_valid = 0;		/* XXX set by resolver? */

	DTRACE_PROC2(kauth__group__resolver__submitted, int, el.el_uid, int, el.el_gid);
	
	error = kauth_resolver_submit(&el, 0ULL);
	
	DTRACE_PROC2(kauth__group__resolver__returned, int, error, int, el.el_flags);
	
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
#else
	*resultp = 0;
	return(0);
#endif
}

/*
 * kauth_cred_ismember_guid
 *
 * Description:	Determine whether the supplied credential is a member of the
 *		group nominated by GUID.
 *
 * Parameters:	cred				Credential to check in
 *		guidp				Pointer to GUID whose group
 *						we are testing for membership
 *		resultp				Pointer to int to contain the
 *						result of the call
 *
 * Returns:	0				Success
 *	kauth_cred_guid2gid:EINVAL
 *	kauth_cred_ismember_gid:ENOENT
 *	kauth_resolver_submit:ENOENT		User space daemon did not vend
 *						this credential.
 *	kauth_cred_ismember_gid:EWOULDBLOCK
 *	kauth_cred_ismember_gid:EINTR
 *	kauth_cred_ismember_gid:ENOMEM
 *	kauth_cred_ismember_gid:???		Unlikely error from user space
 *
 * Implicit returns:
 *		*resultp (modified)	1	Is member
 *					0	Is not member
 */
int
kauth_cred_ismember_guid(__unused kauth_cred_t cred, guid_t *guidp, int *resultp)
{
	int error = 0;

	switch (kauth_wellknown_guid(guidp)) {
	case KAUTH_WKG_NOBODY:
		*resultp = 0;
		break;
	case KAUTH_WKG_EVERYBODY:
		*resultp = 1;
		break;
	default:
#if CONFIG_EXT_RESOLVER
	{
		struct kauth_identity ki;
		gid_t gid;
#if 6603280
		/*
		 * Grovel the identity cache looking for this GUID.
		 * If we find it, and it is for a user record, return
		 * false because it's not a group.
		 *
		 * This is necessary because we don't have -ve caching
		 * of group memberships, and we really want to avoid
		 * calling out to the resolver if at all possible.
		 *
		 * Because we're called by the ACL evaluator, and the
		 * ACL evaluator is likely to encounter ACEs for users,
		 * this is expected to be a common case.
		 */
		ki.ki_valid = 0;
		if ((error = kauth_identity_find_guid(guidp, &ki, NULL)) == 0 &&
		    !kauth_identity_guid_expired(&ki)) {
			if (ki.ki_valid & KI_VALID_GID) {
				/* It's a group after all... */
				gid = ki.ki_gid;
				goto do_check;
			}
			if (ki.ki_valid & KI_VALID_UID) {
				*resultp = 0;
				return (0);
			}
		}
#endif /* 6603280 */
		/*
		 * Attempt to translate the GUID to a GID.  Even if
		 * this fails, we will have primed the cache if it is
		 * a user record and we'll see it above the next time
		 * we're asked.
		 */
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
 do_check:
			error = kauth_cred_ismember_gid(cred, gid, resultp);
		}
	}
#else	/* CONFIG_EXT_RESOLVER */
		error = ENOENT;
#endif	/* CONFIG_EXT_RESOLVER */
		break;
	}
	return(error);
}

/*
 * kauth_cred_gid_subset
 *
 * Description:	Given two credentials, determine if all GIDs associated with 
 * 		the first are also associated with the second
 *
 * Parameters:	cred1				Credential to check for
 * 		cred2				Credential to check in
 *		resultp				Pointer to int to contain the
 *						result of the call
 *
 * Returns:	0				Success
 *		non-zero			See kauth_cred_ismember_gid for
 *						error codes
 *
 * Implicit returns:
 *		*resultp (modified)	1	Is subset
 *					0	Is not subset
 *
 * Notes:	This function guarantees not to modify resultp when returning
 *		an error.
 */
int	
kauth_cred_gid_subset(kauth_cred_t cred1, kauth_cred_t cred2, int *resultp)
{
	int i, err, res = 1;
	gid_t gid;
	posix_cred_t pcred1 = posix_cred_get(cred1);
	posix_cred_t pcred2 = posix_cred_get(cred2);

	/* First, check the local list of groups */
	for (i = 0; i < pcred1->cr_ngroups; i++) {
		gid = pcred1->cr_groups[i];
		if ((err = kauth_cred_ismember_gid(cred2, gid, &res)) != 0) {
			return err;
		}

		if (!res && gid != pcred2->cr_rgid && gid != pcred2->cr_svgid) {
			*resultp = 0;
			return 0;
		}
	}

	/* Check real gid */
	if ((err = kauth_cred_ismember_gid(cred2, pcred1->cr_rgid, &res)) != 0) {
		return err;
	}

	if (!res && pcred1->cr_rgid != pcred2->cr_rgid &&
			pcred1->cr_rgid != pcred2->cr_svgid) {
		*resultp = 0;
		return 0;
	}

	/* Finally, check saved gid */
	if ((err = kauth_cred_ismember_gid(cred2, pcred1->cr_svgid, &res)) != 0){
		return err;
	}

	if (!res && pcred1->cr_svgid != pcred2->cr_rgid &&
			pcred1->cr_svgid != pcred2->cr_svgid) {
		*resultp = 0;
		return 0;
	}

	*resultp = 1;
	return 0;
}


/*
 * kauth_cred_issuser
 *
 * Description:	Fast replacement for issuser()
 *
 * Parameters:	cred				Credential to check for super
 *						user privileges
 *
 * Returns:	0				Not super user
 *		!0				Is super user
 *
 * Notes:	This function uses a magic number which is not a manifest
 *		constant; this is bad practice.
 */
int
kauth_cred_issuser(kauth_cred_t cred)
{
	return(kauth_cred_getuid(cred) == 0);
}


/*
 * Credential KPI
 */

/* lock protecting credential hash table */
static lck_mtx_t *kauth_cred_hash_mtx;
#define KAUTH_CRED_HASH_LOCK()		lck_mtx_lock(kauth_cred_hash_mtx);
#define KAUTH_CRED_HASH_UNLOCK()	lck_mtx_unlock(kauth_cred_hash_mtx);
#if KAUTH_CRED_HASH_DEBUG
#define KAUTH_CRED_HASH_LOCK_ASSERT()	lck_mtx_assert(kauth_cred_hash_mtx, LCK_MTX_ASSERT_OWNED)
#else	/* !KAUTH_CRED_HASH_DEBUG */
#define KAUTH_CRED_HASH_LOCK_ASSERT()
#endif	/* !KAUTH_CRED_HASH_DEBUG */


/*
 * kauth_cred_init
 *
 * Description:	Initialize the credential hash cache
 *
 * Parameters:	(void)
 *
 * Returns:	(void)
 *
 * Notes:	Intialize the credential hash cache for use; the credential
 *		hash cache is used convert duplicate credentials into a
 *		single reference counted credential in order to save wired
 *		kernel memory.  In practice, this generally means a desktop
 *		system runs with a few tens of credentials, instead of one
 *		per process, one per thread, one per vnode cache entry, and
 *		so on.  This generally results in savings of 200K or more
 *		(potentially much more on server systems).
 *
 *		The hash cache internally has a reference on the credential
 *		for itself as a means of avoiding a reclaim race for a
 *		credential in the process of having it's last non-hash
 *		reference released.  This would otherwise result in the
 *		possibility of a freed credential that was still in uses due
 *		a race.  This use is protected by the KAUTH_CRED_HASH_LOCK.
 *
 *		On final release, the hash reference is droped, and the
 *		credential is freed back to the system.
 *
 *		This function is called from kauth_init() in the file
 *		kern_authorization.c.
 */
void
kauth_cred_init(void)
{
	int		i;
	
	kauth_cred_hash_mtx = lck_mtx_alloc_init(kauth_lck_grp, 0/*LCK_ATTR_NULL*/);

	/*allocate credential hash table */
	MALLOC(kauth_cred_table_anchor, struct kauth_cred_entry_head *, 
			(sizeof(struct kauth_cred_entry_head) * KAUTH_CRED_TABLE_SIZE),
			M_KAUTH, M_WAITOK | M_ZERO);
	if (kauth_cred_table_anchor == NULL)
		panic("startup: kauth_cred_init");
	for (i = 0; i < KAUTH_CRED_TABLE_SIZE; i++) {
		TAILQ_INIT(&kauth_cred_table_anchor[i]);
	}
}


/*
 * kauth_getuid
 *
 * Description:	Get the current thread's effective UID.
 *
 * Parameters:	(void)
 *
 * Returns:	(uid_t)				The effective UID of the
 *						current thread
 */
uid_t
kauth_getuid(void)
{
	return(kauth_cred_getuid(kauth_cred_get()));
}


/*
 * kauth_getruid
 *
 * Description:	Get the current thread's real UID.
 *
 * Parameters:	(void)
 *
 * Returns:	(uid_t)				The real UID of the current
 *						thread
 */
uid_t
kauth_getruid(void)
{
	return(kauth_cred_getruid(kauth_cred_get()));
}


/*
 * kauth_getgid
 *
 * Description:	Get the current thread's effective GID.
 *
 * Parameters:	(void)
 *
 * Returns:	(gid_t)				The effective GID of the
 *						current thread
 */
gid_t
kauth_getgid(void)
{
	return(kauth_cred_getgid(kauth_cred_get()));
}


/*
 * kauth_getgid
 *
 * Description:	Get the current thread's real GID.
 *
 * Parameters:	(void)
 *
 * Returns:	(gid_t)				The real GID of the current
 *						thread
 */
gid_t
kauth_getrgid(void)
{
	return(kauth_cred_getrgid(kauth_cred_get()));
}


/*
 * kauth_cred_get
 *
 * Description:	Returns a pointer to the current thread's credential
 *
 * Parameters:	(void)
 *
 * Returns:	(kauth_cred_t)			Pointer to the current thread's
 *						credential
 *
 * Notes:	This function does not take a reference; because of this, the
 *		caller MUST NOT do anything that would let the thread's
 *		credential change while using the returned value, without
 *		first explicitly taking their own reference.
 *
 *		If a caller intends to take a reference on the resulting
 *		credential pointer from calling this function, it is strongly
 *		recommended that the caller use kauth_cred_get_with_ref()
 *		instead, to protect against any future changes to the cred
 *		locking protocols; such changes could otherwise potentially
 *		introduce race windows in the callers code.
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
	 * We can lazy-bind credentials to threads, as long as their processes
	 * have them.
	 *
	 * XXX If we later inline this function, the code in this block
	 * XXX should probably be called out in a function.
	 */
	if (uthread->uu_ucred == NOCRED) {
		if ((p = (proc_t) get_bsdtask_info(get_threadtask(current_thread()))) == NULL)
			panic("thread wants credential but has no BSD process");
		uthread->uu_ucred = kauth_cred_proc_ref(p);
	}
	return(uthread->uu_ucred);
}

void
mach_kauth_cred_uthread_update(void)
{
	uthread_t uthread;
	proc_t proc;

	uthread = get_bsdthread_info(current_thread());
	proc = current_proc();

	kauth_cred_uthread_update(uthread, proc);
}

/*
 * kauth_cred_uthread_update
 *
 * Description:	Given a uthread, a proc, and whether or not the proc is locked,
 *		late-bind the uthread cred to the proc cred.
 *
 * Parameters:	uthread_t			The uthread to update
 *		proc_t				The process to update to
 *
 * Returns:	(void)
 *
 * Notes:	This code is common code called from system call or trap entry
 *		in the case that the process thread may have been changed
 *		since the last time the thread entered the kernel.  It is
 *		generally only called with the current uthread and process as
 *		parameters.
 */
void
kauth_cred_uthread_update(uthread_t uthread, proc_t proc)
{
	if (uthread->uu_ucred != proc->p_ucred &&
	    (uthread->uu_flag & UT_SETUID) == 0) {
		kauth_cred_t old = uthread->uu_ucred;
		uthread->uu_ucred = kauth_cred_proc_ref(proc);
		if (IS_VALID_CRED(old))
			kauth_cred_unref(&old);
	}
}


/*
 * kauth_cred_get_with_ref
 *
 * Description:	Takes a reference on the current thread's credential, and then
 *		returns a pointer to it to the caller.
 *
 * Parameters:	(void)
 *
 * Returns:	(kauth_cred_t)			Pointer to the current thread's
 *						newly referenced credential
 *
 * Notes:	This function takes a reference on the credential before
 *		returning it to the caller.
 *
 *		It is the responsibility of the calling code to release this
 *		reference when the credential is no longer in use.
 *
 *		Since the returned reference may be a persistent reference
 *		(e.g. one cached in another data structure with a lifetime
 *		longer than the calling function), this release may be delayed
 *		until such time as the persistent reference is to be destroyed.
 *		An example of this would be the per vnode credential cache used
 *		to accelerate lookup operations.
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
	 * We can lazy-bind credentials to threads, as long as their processes
	 * have them.
	 *
	 * XXX If we later inline this function, the code in this block
	 * XXX should probably be called out in a function.
	 */
	if (uthread->uu_ucred == NOCRED) {
		/* take reference for new cred in thread */
		uthread->uu_ucred = kauth_cred_proc_ref(procp);
	}
	/* take a reference for our caller */
	kauth_cred_ref(uthread->uu_ucred);
	return(uthread->uu_ucred);
}


/*
 * kauth_cred_proc_ref
 *
 * Description:	Takes a reference on the current process's credential, and
 *		then returns a pointer to it to the caller.
 *
 * Parameters:	procp				Process whose credential we
 *						intend to take a reference on
 *
 * Returns:	(kauth_cred_t)			Pointer to the process's
 *						newly referenced credential
 *
 * Locks:	PROC_LOCK is held before taking the reference and released
 *		after the refeence is taken to protect the p_ucred field of
 *		the process referred to by procp.
 *
 * Notes:	This function takes a reference on the credential before
 *		returning it to the caller.
 *
 *		It is the responsibility of the calling code to release this
 *		reference when the credential is no longer in use.
 *
 *		Since the returned reference may be a persistent reference
 *		(e.g. one cached in another data structure with a lifetime
 *		longer than the calling function), this release may be delayed
 *		until such time as the persistent reference is to be destroyed.
 *		An example of this would be the per vnode credential cache used
 *		to accelerate lookup operations.
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
 * kauth_cred_alloc
 *
 * Description:	Allocate a new credential
 *
 * Parameters:	(void)
 *
 * Returns:	!NULL				Newly allocated credential
 *		NULL				Insufficient memory
 *
 * Notes:	The newly allocated credential is zero'ed as part of the
 *		allocation process, with the exception of the reference
 *		count, which is set to 1 to indicate a single reference
 *		held by the caller.
 *
 *		Since newly allocated credentials have no external pointers
 *		referencing them, prior to making them visible in an externally
 *		visible pointer (e.g. by adding them to the credential hash
 *		cache) is the only legal time in which an existing credential
 *		can be safely iinitialized or modified directly.
 *
 *		After initialization, the caller is expected to call the
 *		function kauth_cred_add() to add the credential to the hash
 *		cache, after which time it's frozen and becomes publically
 *		visible.
 *
 *		The release protocol depends on kauth_hash_add() being called
 *		before kauth_cred_rele() (there is a diagnostic panic which
 *		will trigger if this protocol is not observed).
 *
 * XXX:		This function really ought to be static, rather than being
 *		exported as KPI, since a failure of kauth_cred_add() can only
 *		be handled by an explicit free of the credential; such frees
 *		depend on knowlegdge of the allocation method used, which is
 *		permitted to change between kernel revisions.
 *
 * XXX:		In the insufficient resource case, this code panic's rather
 *		than returning a NULL pointer; the code that calls this
 *		function needs to be audited before this can be changed.
 */
kauth_cred_t
kauth_cred_alloc(void)
{
	kauth_cred_t newcred;
	
	MALLOC_ZONE(newcred, kauth_cred_t, sizeof(*newcred), M_CRED, M_WAITOK);
	if (newcred != 0) {
		posix_cred_t newpcred = posix_cred_get(newcred);
		bzero(newcred, sizeof(*newcred));
		newcred->cr_ref = 1;
		newcred->cr_audit.as_aia_p = audit_default_aia_p;
		/* must do this, or cred has same group membership as uid 0 */
		newpcred->cr_gmuid = KAUTH_UID_NONE;
#if CRED_DIAGNOSTIC
	} else {
		panic("kauth_cred_alloc: couldn't allocate credential");
#endif		
	}

#if KAUTH_CRED_HASH_DEBUG
	kauth_cred_count++;
#endif

#if CONFIG_MACF
	mac_cred_label_init(newcred);
#endif

	return(newcred);
}


/*
 * kauth_cred_create
 *
 * Description:	Look to see if we already have a known credential in the hash
 *		cache; if one is found, bump the reference count and return
 *		it.  If there are no credentials that match the given
 *		credential, then allocate a new credential.
 *
 * Parameters:	cred				Template for credential to
 *						be created
 *
 * Returns:	(kauth_cred_t)			The credential that was found
 *						in the hash or created
 *		NULL				kauth_cred_add() failed, or
 *						there was not an egid specified
 *
 * Notes:	The gmuid is hard-defaulted to the UID specified.  Since we
 *		maintain this field, we can't expect callers to know how it
 *		needs to be set.  Callers should be prepared for this field
 *		to be overwritten.
 *
 * XXX:		This code will tight-loop if memory for a new credential is
 *		persistently unavailable; this is perhaps not the wisest way
 *		to handle this condition, but current callers do not expect
 *		a failure.
 */
kauth_cred_t
kauth_cred_create(kauth_cred_t cred)
{
	kauth_cred_t 	found_cred, new_cred = NULL;
	posix_cred_t	pcred = posix_cred_get(cred);
	int is_member = 0;

	KAUTH_CRED_HASH_LOCK_ASSERT();

	if (pcred->cr_flags & CRF_NOMEMBERD) {
		pcred->cr_gmuid = KAUTH_UID_NONE;
	} else {
		/*
		 * If the template credential is not opting out of external
		 * group membership resolution, then we need to check that
		 * the UID we will be using is resolvable by the external
		 * resolver.  If it's not, then we opt it out anyway, since
		 * all future external resolution requests will be failing
		 * anyway, and potentially taking a long time to do it.  We
		 * use gid 0 because we always know it will exist and not
		 * trigger additional lookups. This is OK, because we end up
		 * precatching the information here as a result.
		 */
		if (!kauth_cred_ismember_gid(cred, 0, &is_member)) {
			/*
			 * It's a recognized value; we don't really care about
			 * the answer, so long as it's something the external
			 * resolver could have vended.
			 */
			pcred->cr_gmuid = pcred->cr_uid;
		} else {
			/*
			 * It's not something the external resolver could
			 * have vended, so we don't want to ask it more
			 * questions about the credential in the future. This
			 * speeds up future lookups, as long as the caller
			 * caches results; otherwise, it the same recurring
			 * cost.  Since most credentials are used multiple
			 * times, we still get some performance win from this.
			 */
			pcred->cr_gmuid = KAUTH_UID_NONE;
			pcred->cr_flags |= CRF_NOMEMBERD;
		}
	}

	/* Caller *must* specify at least the egid in cr_groups[0] */
	if (pcred->cr_ngroups < 1)
		return(NULL);
	
	for (;;) {
		KAUTH_CRED_HASH_LOCK();
		found_cred = kauth_cred_find(cred);
		if (found_cred != NULL) {
			/*
			 * Found an existing credential so we'll bump
			 * reference count and return
			 */
			kauth_cred_ref(found_cred);
			KAUTH_CRED_HASH_UNLOCK();
			return(found_cred);
		}
		KAUTH_CRED_HASH_UNLOCK();
	
		/*
		 * No existing credential found.  Create one and add it to
		 * our hash table.
		 */
		new_cred = kauth_cred_alloc();
		if (new_cred != NULL) {
			int		err;
			posix_cred_t	new_pcred = posix_cred_get(new_cred);
			new_pcred->cr_uid = pcred->cr_uid;
			new_pcred->cr_ruid = pcred->cr_ruid;
			new_pcred->cr_svuid = pcred->cr_svuid;
			new_pcred->cr_rgid = pcred->cr_rgid;
			new_pcred->cr_svgid = pcred->cr_svgid;
			new_pcred->cr_gmuid = pcred->cr_gmuid;
			new_pcred->cr_ngroups = pcred->cr_ngroups;	
			bcopy(&pcred->cr_groups[0], &new_pcred->cr_groups[0], sizeof(new_pcred->cr_groups));
#if CONFIG_AUDIT
			bcopy(&cred->cr_audit, &new_cred->cr_audit, 
			    sizeof(new_cred->cr_audit));
#endif
			new_pcred->cr_flags = pcred->cr_flags;
			
			KAUTH_CRED_HASH_LOCK();
			err = kauth_cred_add(new_cred);
			KAUTH_CRED_HASH_UNLOCK();
			
			/* Retry if kauth_cred_add returns non zero value */
			if (err == 0)
				break;
#if CONFIG_MACF
			mac_cred_label_destroy(new_cred);
#endif
			AUDIT_SESSION_UNREF(new_cred);

			FREE_ZONE(new_cred, sizeof(*new_cred), M_CRED);
			new_cred = NULL;
		}
	}

	return(new_cred);
}


/*
 * kauth_cred_setresuid
 *
 * Description:	Update the given credential using the UID arguments.  The given
 *		UIDs are used to set the effective UID, real UID, saved UID,
 *		and GMUID (used for group membership checking).
 *
 * Parameters:	cred				The original credential
 *		ruid				The new real UID
 *		euid				The new effective UID
 *		svuid				The new saved UID
 *		gmuid				KAUTH_UID_NONE -or- the new
 *						group membership UID
 *
 * Returns:	(kauth_cred_t)			The updated credential
 *
 * Note:	gmuid is different in that a KAUTH_UID_NONE is a valid
 *		setting, so if you don't want it to change, pass it the
 *		previous value, explicitly.
 *
 * IMPORTANT:	This function is implemented via kauth_cred_update(), which,
 *		if it returns a credential other than the one it is passed,
 *		will have dropped the reference on the passed credential.  All
 *		callers should be aware of this, and treat this function as an
 *		unref + ref, potentially on different credentials.
 *
 *		Because of this, the caller is expected to take its own
 *		reference on the credential passed as the first parameter,
 *		and be prepared to release the reference on the credential
 *		that is returned to them, if it is not intended to be a
 *		persistent reference.
 */
kauth_cred_t
kauth_cred_setresuid(kauth_cred_t cred, uid_t ruid, uid_t euid, uid_t svuid, uid_t gmuid)
{
	struct ucred temp_cred;
	posix_cred_t temp_pcred = posix_cred_get(&temp_cred);
	posix_cred_t pcred = posix_cred_get(cred);

	NULLCRED_CHECK(cred);

	/*
	 * We don't need to do anything if the UIDs we are changing are
	 * already the same as the UIDs passed in
	 */
	if ((euid == KAUTH_UID_NONE || pcred->cr_uid == euid) &&
	    (ruid == KAUTH_UID_NONE || pcred->cr_ruid == ruid) &&
	    (svuid == KAUTH_UID_NONE || pcred->cr_svuid == svuid) &&
	    (pcred->cr_gmuid == gmuid)) {
		/* no change needed */
		return(cred);
	}

	/*
	 * Look up in cred hash table to see if we have a matching credential
	 * with the new values; this is done by calling kauth_cred_update().
	 */
	bcopy(cred, &temp_cred, sizeof(temp_cred));
	if (euid != KAUTH_UID_NONE) {
		temp_pcred->cr_uid = euid;
	}
	if (ruid != KAUTH_UID_NONE) {
		temp_pcred->cr_ruid = ruid;
	}
	if (svuid != KAUTH_UID_NONE) {
		temp_pcred->cr_svuid = svuid;
	}

	/*
	 * If we are setting the gmuid to KAUTH_UID_NONE, then we want to
	 * opt out of participation in external group resolution, unless we
	 * unless we explicitly opt back in later.
	 */
	if ((temp_pcred->cr_gmuid = gmuid) == KAUTH_UID_NONE) {
		temp_pcred->cr_flags |= CRF_NOMEMBERD;
	}

	return(kauth_cred_update(cred, &temp_cred, TRUE));
}


/*
 * kauth_cred_setresgid
 *
 * Description:	Update the given credential using the GID arguments.  The given
 *		GIDs are used to set the effective GID, real GID, and saved
 *		GID.
 *
 * Parameters:	cred				The original credential
 *		rgid				The new real GID
 *		egid				The new effective GID
 *		svgid				The new saved GID
 *
 * Returns:	(kauth_cred_t)			The updated credential
 *
 * IMPORTANT:	This function is implemented via kauth_cred_update(), which,
 *		if it returns a credential other than the one it is passed,
 *		will have dropped the reference on the passed credential.  All
 *		callers should be aware of this, and treat this function as an
 *		unref + ref, potentially on different credentials.
 *
 *		Because of this, the caller is expected to take its own
 *		reference on the credential passed as the first parameter,
 *		and be prepared to release the reference on the credential
 *		that is returned to them, if it is not intended to be a
 *		persistent reference.
 */
kauth_cred_t
kauth_cred_setresgid(kauth_cred_t cred, gid_t rgid, gid_t egid, gid_t svgid)
{
	struct ucred 	temp_cred;
	posix_cred_t temp_pcred = posix_cred_get(&temp_cred);
	posix_cred_t pcred = posix_cred_get(cred);

	NULLCRED_CHECK(cred);
	DEBUG_CRED_ENTER("kauth_cred_setresgid %p %d %d %d\n", cred, rgid, egid, svgid);

	/*
	 * We don't need to do anything if the given GID are already the 
	 * same as the GIDs in the credential.
	 */
	if (pcred->cr_groups[0] == egid &&
	    pcred->cr_rgid == rgid &&
	    pcred->cr_svgid == svgid) {
		/* no change needed */
		return(cred);
	}

	/*
	 * Look up in cred hash table to see if we have a matching credential
	 * with the new values; this is done by calling kauth_cred_update().
	 */
	bcopy(cred, &temp_cred, sizeof(temp_cred));
	if (egid != KAUTH_GID_NONE) {
		/* displacing a supplementary group opts us out of memberd */
		if (kauth_cred_change_egid(&temp_cred, egid)) {
			DEBUG_CRED_CHANGE("displaced!\n");
			temp_pcred->cr_flags |= CRF_NOMEMBERD;
			temp_pcred->cr_gmuid = KAUTH_UID_NONE;
		} else {
			DEBUG_CRED_CHANGE("not displaced\n");
		}
	}
	if (rgid != KAUTH_GID_NONE) {
		temp_pcred->cr_rgid = rgid;
	}
	if (svgid != KAUTH_GID_NONE) {
		temp_pcred->cr_svgid = svgid;
	}

	return(kauth_cred_update(cred, &temp_cred, TRUE));
}


/*
 * Update the given credential with the given groups.  We only allocate a new 
 *	credential when the given gid actually results in changes to the existing 
 *	credential.
 *	The gmuid argument supplies a new uid (or KAUTH_UID_NONE to opt out)
 *	which will be used for group membership checking.
 */
/*
 * kauth_cred_setgroups
 *
 * Description:	Update the given credential using the provide supplementary
 *		group list and group membership UID
 *
 * Parameters:	cred				The original credential
 *		groups				Pointer to gid_t array which
 *						contains the new group list
 *		groupcount			The count of valid groups which
 *						are contained in 'groups'
 *		gmuid				KAUTH_UID_NONE -or- the new
 *						group membership UID
 *
 * Returns:	(kauth_cred_t)			The updated credential
 *
 * Note:	gmuid is different in that a KAUTH_UID_NONE is a valid
 *		setting, so if you don't want it to change, pass it the
 *		previous value, explicitly.
 *
 * IMPORTANT:	This function is implemented via kauth_cred_update(), which,
 *		if it returns a credential other than the one it is passed,
 *		will have dropped the reference on the passed credential.  All
 *		callers should be aware of this, and treat this function as an
 *		unref + ref, potentially on different credentials.
 *
 *		Because of this, the caller is expected to take its own
 *		reference on the credential passed as the first parameter,
 *		and be prepared to release the reference on the credential
 *		that is returned to them, if it is not intended to be a
 *		persistent reference.
 *
 * XXX:		Changes are determined in ordinal order - if the caller passes
 *		in the same groups list that is already present in the
 *		credential, but the members are in a different order, even if
 *		the EGID is not modified (i.e. cr_groups[0] is the same), it
 *		is considered a modification to the credential, and a new
 *		credential is created.
 *
 *		This should perhaps be better optimized, but it is considered
 *		to be the caller's problem.
 */
kauth_cred_t
kauth_cred_setgroups(kauth_cred_t cred, gid_t *groups, int groupcount, uid_t gmuid)
{
	int		i;
	struct ucred temp_cred;
	posix_cred_t temp_pcred = posix_cred_get(&temp_cred);
	posix_cred_t pcred;

	NULLCRED_CHECK(cred);

	pcred = posix_cred_get(cred);

	/*
	 * We don't need to do anything if the given list of groups does not
	 * change.
	 */
	if ((pcred->cr_gmuid == gmuid) && (pcred->cr_ngroups == groupcount)) {
		for (i = 0; i < groupcount; i++) {
			if (pcred->cr_groups[i] != groups[i])
				break;
		}
		if (i == groupcount) {
			/* no change needed */
			return(cred);
		}
	}

	/*
	 * Look up in cred hash table to see if we have a matching credential
	 * with new values.  If we are setting or clearing the gmuid, then
	 * update the cr_flags, since clearing it is sticky.  This permits an
	 * opt-out of memberd processing using setgroups(), and an opt-in
	 * using initgroups().  This is required for POSIX conformance.
	 */
	bcopy(cred, &temp_cred, sizeof(temp_cred));
	temp_pcred->cr_ngroups = groupcount;
	bcopy(groups, temp_pcred->cr_groups, sizeof(temp_pcred->cr_groups));
	temp_pcred->cr_gmuid = gmuid;
	if (gmuid == KAUTH_UID_NONE)
		temp_pcred->cr_flags |= CRF_NOMEMBERD;
	else
		temp_pcred->cr_flags &= ~CRF_NOMEMBERD;

	return(kauth_cred_update(cred, &temp_cred, TRUE));
}

/*
 * Notes:	The return value exists to account for the possibility of a
 *		kauth_cred_t without a POSIX label.  This will be the case in
 *		the future (see posix_cred_get() below, for more details).
 */
#if CONFIG_EXT_RESOLVER
int kauth_external_supplementary_groups_supported = 1;

SYSCTL_INT(_kern, OID_AUTO, ds_supgroups_supported, CTLFLAG_RW | CTLFLAG_LOCKED, &kauth_external_supplementary_groups_supported, 0, "");
#endif

int
kauth_cred_getgroups(kauth_cred_t cred, gid_t *grouplist, int *countp)
{
	int limit = NGROUPS;
	posix_cred_t pcred;
	
	pcred = posix_cred_get(cred);

#if CONFIG_EXT_RESOLVER  
	/*
	 * If we've not opted out of using the resolver, then convert the cred to a list
	 * of supplemental groups. We do this only if there has been a resolver to talk to,
	 * since we may be too early in boot, or in an environment that isn't using DS.
	 */
	if (kauth_identitysvc_has_registered && kauth_external_supplementary_groups_supported && (pcred->cr_flags & CRF_NOMEMBERD) == 0) {		
		uid_t uid = kauth_cred_getuid(cred);
		int err;
		
		err = kauth_cred_uid2groups(&uid, grouplist, countp);
		if (!err)
			return 0;

		/* On error just fall through */
		KAUTH_DEBUG("kauth_cred_getgroups failed %d\n", err);
	}
#endif /* CONFIG_EXT_RESOLVER */

	/*
	 * If they just want a copy of the groups list, they may not care
	 * about the actual count.  If they specify an input count, however,
	 * treat it as an indicator of the buffer size available in grouplist,
	 * and limit the returned list to that size.
	 */
	if (countp) {
		limit = MIN(*countp, pcred->cr_ngroups);
		*countp = limit;
	}

	memcpy(grouplist, pcred->cr_groups, sizeof(gid_t) * limit);

	return 0;
}


/*
 * kauth_cred_setuidgid
 *
 * Description:	Update the given credential using the UID and GID arguments.
 *		The given UID is used to set the effective UID, real UID, and
 *		saved UID.  The given GID is used to set the effective GID,
 *		real GID, and saved GID.
 *
 * Parameters:	cred				The original credential
 *		uid				The new UID to use
 *		gid				The new GID to use
 *
 * Returns:	(kauth_cred_t)			The updated credential
 *
 * Notes:	We set the gmuid to uid if the credential we are inheriting
 *		from has not opted out of memberd participation; otherwise
 *		we set it to KAUTH_UID_NONE
 *
 *		This code is only ever called from the per-thread credential
 *		code path in the "set per thread credential" case; and in
 *		posix_spawn() in the case that the POSIX_SPAWN_RESETIDS
 *		flag is set.
 *
 * IMPORTANT:	This function is implemented via kauth_cred_update(), which,
 *		if it returns a credential other than the one it is passed,
 *		will have dropped the reference on the passed credential.  All
 *		callers should be aware of this, and treat this function as an
 *		unref + ref, potentially on different credentials.
 *
 *		Because of this, the caller is expected to take its own
 *		reference on the credential passed as the first parameter,
 *		and be prepared to release the reference on the credential
 *		that is returned to them, if it is not intended to be a
 *		persistent reference.
 */
kauth_cred_t
kauth_cred_setuidgid(kauth_cred_t cred, uid_t uid, gid_t gid)
{
	struct ucred temp_cred;
	posix_cred_t temp_pcred = posix_cred_get(&temp_cred);
	posix_cred_t pcred;

	NULLCRED_CHECK(cred);

	pcred = posix_cred_get(cred);

	/*
	 * We don't need to do anything if the effective, real and saved
	 * user IDs are already the same as the user ID passed into us.
	 */
	if (pcred->cr_uid == uid && pcred->cr_ruid == uid && pcred->cr_svuid == uid &&
		pcred->cr_gid == gid && pcred->cr_rgid == gid && pcred->cr_svgid == gid) {
		/* no change needed */
		return(cred);
	}

	/*
	 * Look up in cred hash table to see if we have a matching credential
	 * with the new values.
	 */
	bzero(&temp_cred, sizeof(temp_cred));
	temp_pcred->cr_uid = uid;
	temp_pcred->cr_ruid = uid;
	temp_pcred->cr_svuid = uid;
	temp_pcred->cr_flags = pcred->cr_flags;
	/* inherit the opt-out of memberd */
	if (pcred->cr_flags & CRF_NOMEMBERD) {
		temp_pcred->cr_gmuid = KAUTH_UID_NONE;
		temp_pcred->cr_flags |= CRF_NOMEMBERD;
	} else {
		temp_pcred->cr_gmuid = uid;
		temp_pcred->cr_flags &= ~CRF_NOMEMBERD;
	}
	temp_pcred->cr_ngroups = 1;
	/* displacing a supplementary group opts us out of memberd */
	if (kauth_cred_change_egid(&temp_cred, gid)) {
		temp_pcred->cr_gmuid = KAUTH_UID_NONE;
		temp_pcred->cr_flags |= CRF_NOMEMBERD;
	}
	temp_pcred->cr_rgid = gid;
	temp_pcred->cr_svgid = gid;
#if CONFIG_MACF
	temp_cred.cr_label = cred->cr_label;
#endif

	return(kauth_cred_update(cred, &temp_cred, TRUE));
}


/*
 * kauth_cred_setsvuidgid
 *
 * Description:	Function used by execve to set the saved uid and gid values
 *		for suid/sgid programs
 *
 * Parameters:	cred				The credential to update
 *		uid				The saved uid to set
 *		gid				The saved gid to set
 *
 * Returns:	(kauth_cred_t)			The updated credential
 *
 * IMPORTANT:	This function is implemented via kauth_cred_update(), which,
 *		if it returns a credential other than the one it is passed,
 *		will have dropped the reference on the passed credential.  All
 *		callers should be aware of this, and treat this function as an
 *		unref + ref, potentially on different credentials.
 *
 *		Because of this, the caller is expected to take its own
 *		reference on the credential passed as the first parameter,
 *		and be prepared to release the reference on the credential
 *		that is returned to them, if it is not intended to be a
 *		persistent reference.
 */
kauth_cred_t
kauth_cred_setsvuidgid(kauth_cred_t cred, uid_t uid, gid_t gid)
{
	struct ucred temp_cred;
	posix_cred_t temp_pcred = posix_cred_get(&temp_cred);
	posix_cred_t pcred;

	NULLCRED_CHECK(cred);

	pcred = posix_cred_get(cred);

	DEBUG_CRED_ENTER("kauth_cred_setsvuidgid: %p u%d->%d g%d->%d\n", cred, cred->cr_svuid, uid, cred->cr_svgid, gid);

	/*
	 * We don't need to do anything if the effective, real and saved
	 * uids are already the same as the uid provided.  This check is
	 * likely insufficient.
	 */
	if (pcred->cr_svuid == uid && pcred->cr_svgid == gid) {
		/* no change needed */
		return(cred);
	}
	DEBUG_CRED_CHANGE("kauth_cred_setsvuidgid: cred change\n");

	/* look up in cred hash table to see if we have a matching credential
	 * with new values.
	 */
	bcopy(cred, &temp_cred, sizeof(temp_cred));
	temp_pcred->cr_svuid = uid;
	temp_pcred->cr_svgid = gid;

	return(kauth_cred_update(cred, &temp_cred, TRUE));
}


/*
 * kauth_cred_setauditinfo
 * 
 * Description:	Update the given credential using the given au_session_t.
 *
 * Parameters:	cred				The original credential
 *		auditinfo_p			Pointer to ne audit information
 *
 * Returns:	(kauth_cred_t)			The updated credential
 *
 * IMPORTANT:	This function is implemented via kauth_cred_update(), which,
 *		if it returns a credential other than the one it is passed,
 *		will have dropped the reference on the passed credential.  All
 *		callers should be aware of this, and treat this function as an
 *		unref + ref, potentially on different credentials.
 *
 *		Because of this, the caller is expected to take its own
 *		reference on the credential passed as the first parameter,
 *		and be prepared to release the reference on the credential
 *		that is returned to them, if it is not intended to be a
 *		persistent reference.
 */
kauth_cred_t
kauth_cred_setauditinfo(kauth_cred_t cred, au_session_t *auditinfo_p)
{
	struct ucred temp_cred;

	NULLCRED_CHECK(cred);

	/*
	 * We don't need to do anything if the audit info is already the
	 * same as the audit info in the credential provided.
	 */
	if (bcmp(&cred->cr_audit, auditinfo_p, sizeof(cred->cr_audit)) == 0) {
		/* no change needed */
		return(cred);
	}

	bcopy(cred, &temp_cred, sizeof(temp_cred));
	bcopy(auditinfo_p, &temp_cred.cr_audit, sizeof(temp_cred.cr_audit));

	return(kauth_cred_update(cred, &temp_cred, FALSE));
}

#if CONFIG_MACF
/*
 * kauth_cred_label_update
 * 
 * Description:	Update the MAC label associated with a credential
 *
 * Parameters:	cred				The original credential
 *		label				The MAC label to set
 *
 * Returns:	(kauth_cred_t)			The updated credential
 *
 * IMPORTANT:	This function is implemented via kauth_cred_update(), which,
 *		if it returns a credential other than the one it is passed,
 *		will have dropped the reference on the passed credential.  All
 *		callers should be aware of this, and treat this function as an
 *		unref + ref, potentially on different credentials.
 *
 *		Because of this, the caller is expected to take its own
 *		reference on the credential passed as the first parameter,
 *		and be prepared to release the reference on the credential
 *		that is returned to them, if it is not intended to be a
 *		persistent reference.
 */
kauth_cred_t
kauth_cred_label_update(kauth_cred_t cred, struct label *label)
{
	kauth_cred_t newcred;
	struct ucred temp_cred;

	bcopy(cred, &temp_cred, sizeof(temp_cred));

	mac_cred_label_init(&temp_cred);
	mac_cred_label_associate(cred, &temp_cred);
	mac_cred_label_update(&temp_cred, label);

	newcred = kauth_cred_update(cred, &temp_cred, TRUE);
	mac_cred_label_destroy(&temp_cred);
	return (newcred);
}

/*
 * kauth_cred_label_update_execve
 * 
 * Description:	Update the MAC label associated with a credential as
 *		part of exec
 *
 * Parameters:	cred				The original credential
 *		vp				The exec vnode
 *		scriptl				The script MAC label
 *		execl				The executable MAC label
 *		disjointp			Pointer to flag to set if old
 *						and returned credentials are
 *						disjoint
 *
 * Returns:	(kauth_cred_t)			The updated credential
 *
 * Implicit returns:
 *		*disjointp			Set to 1 for disjoint creds
 *
 * IMPORTANT:	This function is implemented via kauth_cred_update(), which,
 *		if it returns a credential other than the one it is passed,
 *		will have dropped the reference on the passed credential.  All
 *		callers should be aware of this, and treat this function as an
 *		unref + ref, potentially on different credentials.
 *
 *		Because of this, the caller is expected to take its own
 *		reference on the credential passed as the first parameter,
 *		and be prepared to release the reference on the credential
 *		that is returned to them, if it is not intended to be a
 *		persistent reference.
 */

static
kauth_cred_t
kauth_cred_label_update_execve(kauth_cred_t cred, vfs_context_t ctx,
	struct vnode *vp, off_t offset, struct vnode *scriptvp, struct label *scriptl,
	struct label *execl, unsigned int *csflags, void *macextensions, int *disjointp, int *labelupdateerror)
{
	kauth_cred_t newcred;
	struct ucred temp_cred;

	bcopy(cred, &temp_cred, sizeof(temp_cred));

	mac_cred_label_init(&temp_cred);
	mac_cred_label_associate(cred, &temp_cred);
	mac_cred_label_update_execve(ctx, &temp_cred, 
						  vp, offset, scriptvp, scriptl, execl, csflags,
						  macextensions, disjointp, labelupdateerror);

	newcred = kauth_cred_update(cred, &temp_cred, TRUE);
	mac_cred_label_destroy(&temp_cred);
	return (newcred);
}

/*
 *  kauth_proc_label_update
 *
 * Description:  Update the label inside the credential associated with the process.
 *
 * Parameters:	p			The process to modify
 *				label		The label to place in the process credential
 *
 * Notes:		The credential associated with the process may change as a result
 *				of this call.  The caller should not assume the process reference to
 *				the old credential still exists.
 */
int kauth_proc_label_update(struct proc *p, struct label *label)
{
	kauth_cred_t my_cred, my_new_cred;

	my_cred = kauth_cred_proc_ref(p);

	DEBUG_CRED_ENTER("kauth_proc_label_update: %p\n", my_cred);

	/* get current credential and take a reference while we muck with it */
	for (;;) {

  		/* 
		 * Set the credential with new info.  If there is no change,
		 * we get back the same credential we passed in; if there is
		 * a change, we drop the reference on the credential we
		 * passed in.  The subsequent compare is safe, because it is
		 * a pointer compare rather than a contents compare.
  		 */
		my_new_cred = kauth_cred_label_update(my_cred, label);
		if (my_cred != my_new_cred) {

			DEBUG_CRED_CHANGE("kauth_proc_setlabel_unlocked CH(%d): %p/0x%08x -> %p/0x%08x\n", p->p_pid, my_cred, my_cred->cr_flags, my_new_cred, my_new_cred->cr_flags);

			proc_lock(p);
			/*
			 * We need to protect for a race where another thread
			 * also changed the credential after we took our
			 * reference.  If p_ucred has changed then we should
			 * restart this again with the new cred.
			 */
			if (p->p_ucred != my_cred) {
				proc_unlock(p);
				kauth_cred_unref(&my_new_cred);
				my_cred = kauth_cred_proc_ref(p);
				/* try again */
				continue;
			}
			p->p_ucred = my_new_cred;
			/* update cred on proc */
			PROC_UPDATE_CREDS_ONPROC(p);

			mac_proc_set_enforce(p, MAC_ALL_ENFORCE);
			proc_unlock(p);
		}
		break;
	}
	/* Drop old proc reference or our extra reference */
	kauth_cred_unref(&my_cred);
	
	return (0);
}

/*
 *  kauth_proc_label_update_execve
 *
 * Description: Update the label inside the credential associated with the
 *		process as part of a transitioning execve.  The label will
 *		be updated by the policies as part of this processing, not
 *		provided up front.
 *
 * Parameters:	p			The process to modify
 *		ctx			The context of the exec
 *		vp			The vnode being exec'ed
 *		scriptl			The script MAC label
 *		execl			The executable MAC label
 *		lupdateerror	The error place holder for MAC label authority 
 *						to update about possible termination
 *
 * Returns:	0			Label update did not make credential
 *					disjoint
 *		1			Label update caused credential to be
 *					disjoint
 *
 * Notes:	The credential associated with the process WILL change as a
 *		result of this call.  The caller should not assume the process
 *		reference to the old credential still exists.
 */
 
void
kauth_proc_label_update_execve(struct proc *p, vfs_context_t ctx,
	struct vnode *vp, off_t offset, struct vnode *scriptvp, struct label *scriptl,
	struct label *execl, unsigned int *csflags, void *macextensions, int *disjoint, int *update_return)
{
	kauth_cred_t my_cred, my_new_cred;
	my_cred = kauth_cred_proc_ref(p);

	DEBUG_CRED_ENTER("kauth_proc_label_update_execve: %p\n", my_cred);

	/* get current credential and take a reference while we muck with it */
	for (;;) {

  		/* 
		 * Set the credential with new info.  If there is no change,
		 * we get back the same credential we passed in; if there is
		 * a change, we drop the reference on the credential we
		 * passed in.  The subsequent compare is safe, because it is
		 * a pointer compare rather than a contents compare.
  		 */
		my_new_cred = kauth_cred_label_update_execve(my_cred, ctx, vp, offset, scriptvp, scriptl, execl, csflags, macextensions, disjoint, update_return);
		if (my_cred != my_new_cred) {

			DEBUG_CRED_CHANGE("kauth_proc_label_update_execve_unlocked CH(%d): %p/0x%08x -> %p/0x%08x\n", p->p_pid, my_cred, my_cred->cr_flags, my_new_cred, my_new_cred->cr_flags);

			proc_lock(p);
			/*
			 * We need to protect for a race where another thread
			 * also changed the credential after we took our
			 * reference.  If p_ucred has changed then we should
			 * restart this again with the new cred.
			 */
			if (p->p_ucred != my_cred) {
				proc_unlock(p);
				kauth_cred_unref(&my_new_cred);
				my_cred = kauth_cred_proc_ref(p);
				/* try again */
				continue;
			}
			p->p_ucred = my_new_cred;
			/* update cred on proc */
			PROC_UPDATE_CREDS_ONPROC(p);
			mac_proc_set_enforce(p, MAC_ALL_ENFORCE);
			proc_unlock(p);
		}
		break;
	}
	/* Drop old proc reference or our extra reference */
	kauth_cred_unref(&my_cred);
}

#if 1
/*
 * for temporary binary compatibility
 */
kauth_cred_t	kauth_cred_setlabel(kauth_cred_t cred, struct label *label);
kauth_cred_t
kauth_cred_setlabel(kauth_cred_t cred, struct label *label)
{
	return kauth_cred_label_update(cred, label);
}

int kauth_proc_setlabel(struct proc *p, struct label *label);
int
kauth_proc_setlabel(struct proc *p, struct label *label)
{
	return kauth_proc_label_update(p, label);
}
#endif

#else

/* this is a temp hack to cover us when MACF is not built in a kernel configuration. 
 * Since we cannot build our export lists based on the kernel configuration we need
 * to define a stub. 
 */
kauth_cred_t
kauth_cred_label_update(__unused kauth_cred_t cred, __unused void *label)
{
	return(NULL);
}

int
kauth_proc_label_update(__unused struct proc *p, __unused void *label)
{
	return (0);
}

#if 1
/*
 * for temporary binary compatibility
 */
kauth_cred_t	kauth_cred_setlabel(kauth_cred_t cred, void *label);
kauth_cred_t
kauth_cred_setlabel(__unused kauth_cred_t cred, __unused void *label)
{
	return NULL;
}

int kauth_proc_setlabel(struct proc *p, void *label);
int
kauth_proc_setlabel(__unused struct proc *p, __unused void *label)
{
	return (0);
}
#endif
#endif

/*
 * kauth_cred_ref
 *
 * Description:	Add a reference to the passed credential
 *
 * Parameters:	cred				The credential to reference
 *
 * Returns:	(void)
 *
 * Notes:	This function adds a reference to the provided credential;
 *		the existing reference on the credential is assumed to be
 *		held stable over this operation by taking the appropriate
 *		lock to protect the pointer from which it is being referenced,
 *		if necessary (e.g. the proc lock is held over the call if the
 *		credential being referenced is from p_ucred, the vnode lock
 *		if from the per vnode name cache cred cache, and so on).
 *
 *		This is safe from the kauth_cred_unref() path, since an atomic
 *		add is used, and the unref path specifically checks to see that
 *		the value has not been changed to add a reference between the
 *		time the credential is unreferenced by another pointer and the
 *		time it is unreferenced from the cred hash cache.
 */
void
kauth_cred_ref(kauth_cred_t cred)
{
	int		old_value;
	
	NULLCRED_CHECK(cred);

	old_value = OSAddAtomicLong(1, (long*)&cred->cr_ref);

	if (old_value < 1)
		panic("kauth_cred_ref: trying to take a reference on a cred with no references");

#if 0 // use this to watch a specific credential
	if ( is_target_cred( cred ) != 0 ) {
 		get_backtrace( );
	}
#endif
		
	return;
}


/*
 * kauth_cred_unref_hashlocked
 *
 * Description:	release a credential reference; when the last reference is
 *		released, the credential will be freed.
 *
 * Parameters:	credp				Pointer to address containing
 *						credential to be freed
 *
 * Returns:	TRUE if the credential must be destroyed by the caller.
 *		FALSE otherwise.
 *
 * Implicit returns:
 *		*credp				Set to NOCRED
 *
 * Notes:	This function assumes the credential hash lock is held.
 *
 *		This function is internal use only, since the hash lock is
 *		scoped to this compilation unit.
 *
 *		This function destroys the contents of the pointer passed by
 *		the caller to prevent the caller accidentally attempting to
 *		release a given reference twice in error.
 *
 *		The last reference is considered to be released when a release
 *		of a credential of a reference count of 2 occurs; this is an
 *		intended effect, to take into account the reference held by
 *		the credential hash, which is released at the same time.
 */
static boolean_t
kauth_cred_unref_hashlocked(kauth_cred_t *credp)
{
	int		old_value;
	boolean_t	destroy_it = FALSE;

	KAUTH_CRED_HASH_LOCK_ASSERT();
	NULLCRED_CHECK(*credp);

	old_value = OSAddAtomicLong(-1, (long*)&(*credp)->cr_ref);

#if DIAGNOSTIC
	if (old_value == 0)
		panic("%s:0x%08x kauth_cred_unref_hashlocked: dropping a reference on a cred with no references", current_proc()->p_comm, *credp);
	if (old_value == 1)
		panic("%s:0x%08x kauth_cred_unref_hashlocked: dropping a reference on a cred with no hash entry", current_proc()->p_comm, *credp);
#endif

#if 0 // use this to watch a specific credential
	if ( is_target_cred( *credp ) != 0 ) {
		get_backtrace( );
	}
#endif

	/*
	 * If the old_value is 2, then we have just released the last external
	 * reference to this credential
	 */
	if (old_value < 3) {
		/* The last absolute reference is our credential hash table */
		destroy_it = kauth_cred_remove(*credp);
	}

	if (destroy_it == FALSE) {
		*credp = NOCRED;
	}

	return (destroy_it);
}


/*
 * kauth_cred_unref
 *
 * Description:	Release a credential reference while holding the credential
 *		hash lock; when the last reference is released, the credential
 *		will be freed.
 *
 * Parameters:	credp				Pointer to address containing
 *						credential to be freed
 *
 * Returns:	(void)
 *
 * Implicit returns:
 *		*credp				Set to NOCRED
 *
 * Notes:	See kauth_cred_unref_hashlocked() for more information.
 *
 */
void
kauth_cred_unref(kauth_cred_t *credp)
{
	boolean_t destroy_it;

	KAUTH_CRED_HASH_LOCK();
	destroy_it = kauth_cred_unref_hashlocked(credp);
	KAUTH_CRED_HASH_UNLOCK();

	if (destroy_it == TRUE) {
		assert(*credp != NOCRED);
#if CONFIG_MACF
		mac_cred_label_destroy(*credp);
#endif
		AUDIT_SESSION_UNREF(*credp);

		(*credp)->cr_ref = 0;
		FREE_ZONE(*credp, sizeof(*(*credp)), M_CRED);
		*credp = NOCRED;
	}
}


#ifndef __LP64__
/*
 * kauth_cred_rele
 *
 * Description:	release a credential reference; when the last reference is
 *		released, the credential will be freed
 *
 * Parameters:	cred				Credential to release
 *
 * Returns:	(void)
 *
 * DEPRECATED:	This interface is obsolete due to a failure to clear out the
 *		clear the pointer in the caller to avoid multiple releases of
 *		the same credential.  The currently recommended interface is
 *		kauth_cred_unref().
 */
void
kauth_cred_rele(kauth_cred_t cred)
{
	kauth_cred_unref(&cred);
}
#endif /* !__LP64__ */


/*
 * kauth_cred_dup
 *
 * Description:	Duplicate a credential via alloc and copy; the new credential
 *		has only it's own
 *
 * Parameters:	cred				The credential to duplicate
 *
 * Returns:	(kauth_cred_t)			The duplicate credential
 *
 * Notes:	The typical value to calling this routine is if you are going
 *		to modify an existing credential, and expect to need a new one
 *		from the hash cache.
 *
 *		This should probably not be used in the majority of cases;
 *		if you are using it instead of kauth_cred_create(), you are
 *		likely making a mistake.
 *
 *		The newly allocated credential is copied as part of the
 *		allocation process, with the exception of the reference
 *		count, which is set to 1 to indicate a single reference
 *		held by the caller.
 *
 *		Since newly allocated credentials have no external pointers
 *		referencing them, prior to making them visible in an externally
 *		visible pointer (e.g. by adding them to the credential hash
 *		cache) is the only legal time in which an existing credential
 *		can be safely initialized or modified directly.
 *
 *		After initialization, the caller is expected to call the
 *		function kauth_cred_add() to add the credential to the hash
 *		cache, after which time it's frozen and becomes publicly
 *		visible.
 *
 *		The release protocol depends on kauth_hash_add() being called
 *		before kauth_cred_rele() (there is a diagnostic panic which
 *		will trigger if this protocol is not observed).
 *
 */
kauth_cred_t
kauth_cred_dup(kauth_cred_t cred)
{
	kauth_cred_t newcred;
#if CONFIG_MACF
	struct label *temp_label;
#endif
	
#if CRED_DIAGNOSTIC
	if (cred == NOCRED || cred == FSCRED)
		panic("kauth_cred_dup: bad credential");
#endif
	newcred = kauth_cred_alloc();
	if (newcred != NULL) {
#if CONFIG_MACF
		temp_label = newcred->cr_label;
#endif
		bcopy(cred, newcred, sizeof(*newcred));
#if CONFIG_MACF
		newcred->cr_label = temp_label;
		mac_cred_label_associate(cred, newcred);
#endif
		AUDIT_SESSION_REF(cred);
		newcred->cr_ref = 1;
	}
	return(newcred);
}

/*
 * kauth_cred_copy_real
 *
 * Description:	Returns a credential based on the passed credential but which
 *		reflects the real rather than effective UID and GID.
 *
 * Parameters:	cred				The credential from which to
 *						derive the new credential
 *
 * Returns:	(kauth_cred_t)			The copied credential
 *
 * IMPORTANT:	This function DOES NOT utilize kauth_cred_update(); as a
 *		result, the caller is responsible for dropping BOTH the
 *		additional reference on the passed cred (if any), and the
 *		credential returned by this function.  The drop should be
 *		via the kauth_cred_unref() KPI.
 */
kauth_cred_t
kauth_cred_copy_real(kauth_cred_t cred)
{
	kauth_cred_t newcred = NULL, found_cred;
	struct ucred temp_cred;
	posix_cred_t temp_pcred = posix_cred_get(&temp_cred);
	posix_cred_t pcred = posix_cred_get(cred);

	/* if the credential is already 'real', just take a reference */
	if ((pcred->cr_ruid == pcred->cr_uid) &&
	    (pcred->cr_rgid == pcred->cr_gid)) {
		kauth_cred_ref(cred);
		return(cred);
	}

	/*
	 * Look up in cred hash table to see if we have a matching credential
	 * with the new values.
	 */
	bcopy(cred, &temp_cred, sizeof(temp_cred));
	temp_pcred->cr_uid = pcred->cr_ruid;
	/* displacing a supplementary group opts us out of memberd */
	if (kauth_cred_change_egid(&temp_cred, pcred->cr_rgid)) {
		temp_pcred->cr_flags |= CRF_NOMEMBERD;
		temp_pcred->cr_gmuid = KAUTH_UID_NONE;
	}
	/*
	 * If the cred is not opted out, make sure we are using the r/euid
	 * for group checks
	 */
	if (temp_pcred->cr_gmuid != KAUTH_UID_NONE)
		temp_pcred->cr_gmuid = pcred->cr_ruid;

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
			/*
			 * Found a match so we bump reference count on new
			 * one.  We leave the old one alone.
			 */
			kauth_cred_ref(found_cred);
			KAUTH_CRED_HASH_UNLOCK();
			return(found_cred);
		}
	
		/*
		 * Must allocate a new credential, copy in old credential
		 * data and update the real user and group IDs.
		 */
		newcred = kauth_cred_dup(&temp_cred);
		err = kauth_cred_add(newcred);
		KAUTH_CRED_HASH_UNLOCK();

		/* Retry if kauth_cred_add() fails */
		if (err == 0)
			break;
#if CONFIG_MACF
		mac_cred_label_destroy(newcred);
#endif
		AUDIT_SESSION_UNREF(newcred);

		FREE_ZONE(newcred, sizeof(*newcred), M_CRED);
		newcred = NULL;
	}
	
	return(newcred);
}


/*
 * kauth_cred_update
 *
 * Description:	Common code to update a credential
 *
 * Parameters:	old_cred			Reference counted credential
 *						to update
 *		model_cred			Non-reference counted model
 *						credential to apply to the
 *						credential to be updated
 *		retain_auditinfo		Flag as to whether or not the
 *						audit information should be
 *						copied from the old_cred into
 *						the model_cred
 *
 * Returns:	(kauth_cred_t)			The updated credential
 *
 * IMPORTANT:	This function will potentially return a credential other than
 *		the one it is passed, and if so, it will have dropped the
 *		reference on the passed credential.  All callers should be
 *		aware of this, and treat this function as an unref + ref,
 *		potentially on different credentials.
 *
 *		Because of this, the caller is expected to take its own
 *		reference on the credential passed as the first parameter,
 *		and be prepared to release the reference on the credential
 *		that is returned to them, if it is not intended to be a
 *		persistent reference.
 */
static kauth_cred_t
kauth_cred_update(kauth_cred_t old_cred, kauth_cred_t model_cred,
	boolean_t retain_auditinfo)
{	
	kauth_cred_t found_cred, new_cred = NULL;
	
	/*
	 * Make sure we carry the auditinfo forward to the new credential
	 * unless we are actually updating the auditinfo.
	 */
	if (retain_auditinfo) {
		bcopy(&old_cred->cr_audit, &model_cred->cr_audit, 
		    sizeof(model_cred->cr_audit));
	}
	
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
			boolean_t destroy_it;

			DEBUG_CRED_CHANGE("kauth_cred_update(cache hit): %p -> %p\n", old_cred, found_cred);
			/*
			 * Found a match so we bump reference count on new
			 * one and decrement reference count on the old one.
			 */
			kauth_cred_ref(found_cred);
			destroy_it = kauth_cred_unref_hashlocked(&old_cred);
			KAUTH_CRED_HASH_UNLOCK();
			if (destroy_it == TRUE) {
				assert(old_cred != NOCRED);
#if CONFIG_MACF
				mac_cred_label_destroy(old_cred);
#endif
				AUDIT_SESSION_UNREF(old_cred);

				old_cred->cr_ref = 0;
				FREE_ZONE(old_cred, sizeof(*old_cred), M_CRED);
				old_cred = NOCRED;

			}
			return(found_cred);
		}

		/*
		 * Must allocate a new credential using the model.  also
		 * adds the new credential to the credential hash table.
		 */
		new_cred = kauth_cred_dup(model_cred);
		err = kauth_cred_add(new_cred);
		KAUTH_CRED_HASH_UNLOCK();

		/* retry if kauth_cred_add returns non zero value */
		if (err == 0)
			break;
#if CONFIG_MACF
		mac_cred_label_destroy(new_cred);
#endif
		AUDIT_SESSION_UNREF(new_cred);

		FREE_ZONE(new_cred, sizeof(*new_cred), M_CRED);
		new_cred = NULL;
	}

	DEBUG_CRED_CHANGE("kauth_cred_update(cache miss): %p -> %p\n", old_cred, new_cred);
	kauth_cred_unref(&old_cred);
	return(new_cred);
}


/*
 * kauth_cred_add
 *
 * Description:	Add the given credential to our credential hash table and
 *		take an additional reference to account for our use of the
 *		credential in the hash table
 *
 * Parameters:	new_cred			Credential to insert into cred
 *						hash cache
 *
 * Returns:	0				Success
 *		-1				Hash insertion failed: caller
 *						should retry
 *
 * Locks:	Caller is expected to hold KAUTH_CRED_HASH_LOCK
 *
 * Notes:	The 'new_cred' MUST NOT already be in the cred hash cache
 */
static int
kauth_cred_add(kauth_cred_t new_cred)
{
	u_long			hash_key;

	KAUTH_CRED_HASH_LOCK_ASSERT();

	hash_key = kauth_cred_get_hashkey(new_cred);
	hash_key %= KAUTH_CRED_TABLE_SIZE;

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
 * kauth_cred_remove
 *
 * Description:	Remove the given credential from our credential hash table
 *
 * Parameters:	cred				Credential to remove from cred
 *						hash cache
 *
 * Returns:	TRUE if the cred was found & removed from the hash; FALSE if not.
 *
 * Locks:	Caller is expected to hold KAUTH_CRED_HASH_LOCK
 *
 * Notes:	The check for the reference increment after entry is generally
 *		agree to be safe, since we use atomic operations, and the
 *		following code occurs with the hash lock held; in theory, this
 *		protects us from the 2->1 reference that gets us here.
 */
static boolean_t
kauth_cred_remove(kauth_cred_t cred)
{
	u_long			hash_key;
	kauth_cred_t	found_cred;

	hash_key = kauth_cred_get_hashkey(cred);
	hash_key %= KAUTH_CRED_TABLE_SIZE;

	/* Avoid race */
	if (cred->cr_ref < 1)
		panic("cred reference underflow");
	if (cred->cr_ref > 1)
		return (FALSE);		/* someone else got a ref */
		
	/* Find cred in the credential hash table */
	TAILQ_FOREACH(found_cred, &kauth_cred_table_anchor[hash_key], cr_link) {
		if (found_cred == cred) {
			/* found a match, remove it from the hash table */
			TAILQ_REMOVE(&kauth_cred_table_anchor[hash_key], found_cred, cr_link);
#if KAUTH_CRED_HASH_DEBUG
			kauth_cred_count--;
#endif
			return (TRUE);
		}
	}

	/* Did not find a match... this should not happen! XXX Make panic? */
	printf("%s:%d - %s - %s - did not find a match for %p\n", __FILE__, __LINE__, __FUNCTION__, current_proc()->p_comm, cred);
	return (FALSE);
}


/* 
 * kauth_cred_find
 *
 * Description:	Using the given credential data, look for a match in our
 *		credential hash table
 *
 * Parameters:	cred				Credential to lookup in cred
 *						hash cache
 *
 * Returns:	NULL				Not found
 *		!NULL				Matching credential already in
 *						cred hash cache
 *
 * Locks:	Caller is expected to hold KAUTH_CRED_HASH_LOCK
 */
kauth_cred_t
kauth_cred_find(kauth_cred_t cred)
{
	u_long			hash_key;
	kauth_cred_t	found_cred;
	posix_cred_t pcred = posix_cred_get(cred);

	KAUTH_CRED_HASH_LOCK_ASSERT();

#if KAUTH_CRED_HASH_DEBUG
	static int		test_count = 0; 

	test_count++;
	if ((test_count % 200) == 0) {
		kauth_cred_hash_print();
	}
#endif

	hash_key = kauth_cred_get_hashkey(cred);
	hash_key %= KAUTH_CRED_TABLE_SIZE;

	/* Find cred in the credential hash table */
	TAILQ_FOREACH(found_cred, &kauth_cred_table_anchor[hash_key], cr_link) {
		boolean_t match;
		posix_cred_t found_pcred = posix_cred_get(found_cred);

		/*
		 * don't worry about the label unless the flags in
		 * either credential tell us to.
		 */
		match = (bcmp(found_pcred, pcred, sizeof (*pcred)) == 0) ? TRUE : FALSE;
		match = match && ((bcmp(&found_cred->cr_audit, &cred->cr_audit,
			sizeof(cred->cr_audit)) == 0) ? TRUE : FALSE);
#if CONFIG_MACF
		if (((found_pcred->cr_flags & CRF_MAC_ENFORCE) != 0) ||
		    ((pcred->cr_flags & CRF_MAC_ENFORCE) != 0)) {
			match = match && mac_cred_label_compare(found_cred->cr_label,
				cred->cr_label);
		}
#endif
		if (match) {
			/* found a match */
			return(found_cred);
		}
	}
	/* No match found */

	return(NULL);
}


/*
 * kauth_cred_hash
 *
 * Description:	Generates a hash key using data that makes up a credential;
 *		based on ElfHash
 *
 * Parameters:	datap				Pointer to data to hash
 *		data_len			Count of bytes to hash
 *		start_key			Start key value
 *
 * Returns:	(u_long)			Returned hash key
 */
static inline u_long
kauth_cred_hash(const uint8_t *datap, int data_len, u_long start_key)
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


/*
 * kauth_cred_get_hashkey
 *
 * Description:	Generate a hash key using data that makes up a credential;
 *		based on ElfHash.  We hash on the entire credential data,
 *		not including the ref count or the TAILQ, which are mutable;
 *		everything else isn't.
 *
 * Parameters:	cred				Credential for which hash is
 *						desired
 *
 * Returns:	(u_long)			Returned hash key
 *
 * Notes:	When actually moving the POSIX credential into a real label,
 *		remember to update this hash computation.
 */
static u_long
kauth_cred_get_hashkey(kauth_cred_t cred)
{
#if CONFIG_MACF
	posix_cred_t pcred = posix_cred_get(cred);
#endif
	u_long	hash_key = 0;

	hash_key = kauth_cred_hash((uint8_t *)&cred->cr_posix, 
							   sizeof (struct posix_cred),
							   hash_key);
	hash_key = kauth_cred_hash((uint8_t *)&cred->cr_audit, 
							   sizeof(struct au_session),
							   hash_key);
#if CONFIG_MACF
	if (pcred->cr_flags & CRF_MAC_ENFORCE) {
		hash_key = kauth_cred_hash((uint8_t *)cred->cr_label, 
								   sizeof (struct label),
								   hash_key);
	}
#endif
	return(hash_key);
}


#if KAUTH_CRED_HASH_DEBUG
/*
 * kauth_cred_hash_print
 *
 * Description:	Print out cred hash cache table information for debugging
 *		purposes, including the credential contents
 *
 * Parameters:	(void)
 *
 * Returns:	(void)
 *
 * Implicit returns:	Results in console output
 */
static void
kauth_cred_hash_print(void) 
{
	int 			i, j;
	kauth_cred_t	found_cred;
		
	printf("\n\t kauth credential hash table statistics - current cred count %d \n", kauth_cred_count);
	/* count slot hits, misses, collisions, and max depth */
	for (i = 0; i < KAUTH_CRED_TABLE_SIZE; i++) {
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
#endif	/* KAUTH_CRED_HASH_DEBUG */


#if (defined(KAUTH_CRED_HASH_DEBUG) && (KAUTH_CRED_HASH_DEBUG != 0)) || defined(DEBUG_CRED)
/*
 * kauth_cred_print
 *
 * Description:	Print out an individual credential's contents for debugging
 *		purposes
 *
 * Parameters:	cred				The credential to print out
 *
 * Returns:	(void)
 *
 * Implicit returns:	Results in console output
 */
void
kauth_cred_print(kauth_cred_t cred) 
{
	int 	i;

	printf("%p - refs %lu flags 0x%08x uids e%d r%d sv%d gm%d ", cred, cred->cr_ref, cred->cr_flags, cred->cr_uid, cred->cr_ruid, cred->cr_svuid, cred->cr_gmuid);
	printf("group count %d gids ", cred->cr_ngroups);
	for (i = 0; i < NGROUPS; i++) {
		if (i == 0)
			printf("e");
		printf("%d ", cred->cr_groups[i]);
	}
	printf("r%d sv%d ", cred->cr_rgid, cred->cr_svgid);
	printf("auditinfo_addr %d %d %d %d %d %d\n", 
		cred->cr_audit.s_aia_p->ai_auid,
		cred->cr_audit.as_mask.am_success,
		cred->cr_audit.as_mask.am_failure,
		cred->cr_audit.as_aia_p->ai_termid.at_port,
		cred->cr_audit.as_aia_p->ai_termid.at_addr[0],
		cred->cr_audit.as_aia_p->ai_asid);
}

int is_target_cred( kauth_cred_t the_cred )
{
	if ( the_cred->cr_uid != 0 ) 
		return( 0 );
	if ( the_cred->cr_ruid != 0 ) 
		return( 0 );
	if ( the_cred->cr_svuid != 0 ) 
		return( 0 );
	if ( the_cred->cr_ngroups != 11 ) 
		return( 0 );
	if ( the_cred->cr_groups[0] != 11 ) 
		return( 0 );
	if ( the_cred->cr_groups[1] != 81 ) 
		return( 0 );
	if ( the_cred->cr_groups[2] != 63947 ) 
		return( 0 );
	if ( the_cred->cr_groups[3] != 80288 ) 
		return( 0 );
	if ( the_cred->cr_groups[4] != 89006 ) 
		return( 0 );
	if ( the_cred->cr_groups[5] != 52173 ) 
		return( 0 );
	if ( the_cred->cr_groups[6] != 84524 ) 
		return( 0 );
	if ( the_cred->cr_groups[7] != 79 ) 
		return( 0 );
	if ( the_cred->cr_groups[8] != 80292 ) 
		return( 0 );
	if ( the_cred->cr_groups[9] != 80 ) 
		return( 0 );
	if ( the_cred->cr_groups[10] != 90824 ) 
		return( 0 );
	if ( the_cred->cr_rgid != 11 ) 
		return( 0 );
	if ( the_cred->cr_svgid != 11 ) 
		return( 0 );
	if ( the_cred->cr_gmuid != 3475 ) 
		return( 0 );
	if ( the_cred->cr_audit.as_aia_p->ai_auid != 3475 ) 
		return( 0 );
/*
	if ( the_cred->cr_audit.as_mask.am_success != 0 ) 
		return( 0 );
	if ( the_cred->cr_audit.as_mask.am_failure != 0 ) 
		return( 0 );
	if ( the_cred->cr_audit.as_aia_p->ai_termid.at_port != 0 ) 
		return( 0 );
	if ( the_cred->cr_audit.as_aia_p->ai_termid.at_addr[0] != 0 ) 
		return( 0 );
	if ( the_cred->cr_audit.as_aia_p->ai_asid != 0 ) 
		return( 0 );
	if ( the_cred->cr_flags != 0 ) 
		return( 0 );
*/
	return( -1 ); // found target cred
}

void get_backtrace( void )
{
	int				my_slot;
	void *			my_stack[ MAX_STACK_DEPTH ];
	int				i, my_depth;
	
	if ( cred_debug_buf_p == NULL ) {
		MALLOC(cred_debug_buf_p, cred_debug_buffer *, sizeof(*cred_debug_buf_p), M_KAUTH, M_WAITOK);
		bzero(cred_debug_buf_p, sizeof(*cred_debug_buf_p));
	}	

	if ( cred_debug_buf_p->next_slot > (MAX_CRED_BUFFER_SLOTS - 1) ) {
		/* buffer is full */
		return;
	}
	
	my_depth = OSBacktrace(&my_stack[0], MAX_STACK_DEPTH);
	if ( my_depth == 0 ) {
		printf("%s - OSBacktrace failed \n", __FUNCTION__);
		return;
	}
	
	/* fill new backtrace */
	my_slot = cred_debug_buf_p->next_slot;
	cred_debug_buf_p->next_slot++;
	cred_debug_buf_p->stack_buffer[ my_slot ].depth = my_depth;
	for ( i = 0; i < my_depth; i++ ) {
		cred_debug_buf_p->stack_buffer[ my_slot ].stack[ i ] = my_stack[ i ];
	}

	return;
}


/* subset of struct ucred for use in sysctl_dump_creds */
struct debug_ucred {
	void	*credp;
	u_long	cr_ref;				/* reference count */
	uid_t	cr_uid;				/* effective user id */
	uid_t	cr_ruid;			/* real user id */
	uid_t	cr_svuid;			/* saved user id */
	short	cr_ngroups;			/* number of groups in advisory list */
	gid_t	cr_groups[NGROUPS];	/* advisory group list */
	gid_t	cr_rgid;			/* real group id */
	gid_t	cr_svgid;			/* saved group id */
	uid_t	cr_gmuid;			/* UID for group membership purposes */
	struct auditinfo_addr cr_audit;	/* user auditing data. */
	void	*cr_label;			/* MACF label */
	int		cr_flags;			/* flags on credential */
};
typedef struct debug_ucred debug_ucred;

SYSCTL_PROC(_kern, OID_AUTO, dump_creds, CTLFLAG_RD,
    NULL, 0, sysctl_dump_creds, "S,debug_ucred", "List of credentials in the cred hash");

/*	accessed by:      
 *	err = sysctlbyname( "kern.dump_creds", bufp, &len, NULL, 0 );
 */

static int
sysctl_dump_creds( __unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req )
{
	int 			i, j, counter = 0;
	int				error;
	size_t			space;
	kauth_cred_t	found_cred;
	debug_ucred *	cred_listp;
	debug_ucred *	nextp;

	/* This is a readonly node. */
	if (req->newptr != USER_ADDR_NULL)
		return (EPERM);

	/* calculate space needed */
	for (i = 0; i < KAUTH_CRED_TABLE_SIZE; i++) {
		TAILQ_FOREACH(found_cred, &kauth_cred_table_anchor[i], cr_link) {
			counter++;
		}
	}

	/* they are querying us so just return the space required. */
	if (req->oldptr == USER_ADDR_NULL) {
		counter += 10; // add in some padding;
		req->oldidx = counter * sizeof(debug_ucred);
		return 0;
	}

	MALLOC( cred_listp, debug_ucred *, req->oldlen, M_TEMP, M_WAITOK );
	if ( cred_listp == NULL ) {
		return (ENOMEM);
	}
	
	/* fill in creds to send back */
	nextp = cred_listp;
	space = 0;
	for (i = 0; i < KAUTH_CRED_TABLE_SIZE; i++) {
		TAILQ_FOREACH(found_cred, &kauth_cred_table_anchor[i], cr_link) {
			nextp->credp = found_cred;
			nextp->cr_ref = found_cred->cr_ref;
			nextp->cr_uid = found_cred->cr_uid;
			nextp->cr_ruid = found_cred->cr_ruid;
			nextp->cr_svuid = found_cred->cr_svuid;
			nextp->cr_ngroups = found_cred->cr_ngroups;
			for ( j = 0; j < nextp->cr_ngroups; j++ ) {
				nextp->cr_groups[ j ] = found_cred->cr_groups[ j ];
			}
			nextp->cr_rgid = found_cred->cr_rgid;
			nextp->cr_svgid = found_cred->cr_svgid;
			nextp->cr_gmuid = found_cred->cr_gmuid;
			nextp->cr_audit.ai_auid =
			    found_cred->cr_audit.as_aia_p->ai_auid;
			nextp->cr_audit.ai_mask.am_success =
			    found_cred->cr_audit.as_mask.am_success;
			nextp->cr_audit.ai_mask.am_failure =
			    found_cred->cr_audit.as_mask.am_failure;
			nextp->cr_audit.ai_termid.at_port =
			    found_cred->cr_audit.as_aia_p->ai_termid.at_port;
			nextp->cr_audit.ai_termid.at_type =
			    found_cred->cr_audit.as_aia_p->ai_termid.at_type;
			nextp->cr_audit.ai_termid.at_addr[0] =
			    found_cred->cr_audit.as_aia_p->ai_termid.at_addr[0];
			nextp->cr_audit.ai_termid.at_addr[1] =
			    found_cred->cr_audit.as_aia_p->ai_termid.at_addr[1];
			nextp->cr_audit.ai_termid.at_addr[2] =
			    found_cred->cr_audit.as_aia_p->ai_termid.at_addr[2];
			nextp->cr_audit.ai_termid.at_addr[3] =
			    found_cred->cr_audit.as_aia_p->ai_termid.at_addr[3];
			nextp->cr_audit.ai_asid =
			    found_cred->cr_audit.as_aia_p->ai_asid;
			nextp->cr_audit.ai_flags =
			    found_cred->cr_audit.as_aia_p->ai_flags;
			nextp->cr_label = found_cred->cr_label;
			nextp->cr_flags = found_cred->cr_flags;
			nextp++;
			space += sizeof(debug_ucred);
			if ( space > req->oldlen ) {
				FREE(cred_listp, M_TEMP);
				return (ENOMEM);
			}
		}
	}
	req->oldlen = space;
	error = SYSCTL_OUT(req, cred_listp, req->oldlen);
	FREE(cred_listp, M_TEMP);
	return (error);
}


SYSCTL_PROC(_kern, OID_AUTO, cred_bt, CTLFLAG_RD,
    NULL, 0, sysctl_dump_cred_backtraces, "S,cred_debug_buffer", "dump credential backtrace");

/*	accessed by:      
 *	err = sysctlbyname( "kern.cred_bt", bufp, &len, NULL, 0 );
 */

static int
sysctl_dump_cred_backtraces( __unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req )
{
	int 			i, j;
	int				error;
	size_t			space;
	cred_debug_buffer *	bt_bufp;
	cred_backtrace *	nextp;

	/* This is a readonly node. */
	if (req->newptr != USER_ADDR_NULL)
		return (EPERM);

	if ( cred_debug_buf_p == NULL ) {
		return (EAGAIN);
	}

	/* calculate space needed */
	space = sizeof( cred_debug_buf_p->next_slot );
	space += (sizeof( cred_backtrace ) * cred_debug_buf_p->next_slot);

	/* they are querying us so just return the space required. */
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = space;
		return 0;
	}

	if ( space > req->oldlen ) {
		return (ENOMEM);
	}

	MALLOC( bt_bufp, cred_debug_buffer *, req->oldlen, M_TEMP, M_WAITOK );
	if ( bt_bufp == NULL ) {
		return (ENOMEM);
	}
	
	/* fill in backtrace info to send back */
	bt_bufp->next_slot = cred_debug_buf_p->next_slot;
	space = sizeof(bt_bufp->next_slot);
	
	nextp = &bt_bufp->stack_buffer[ 0 ];
	for (i = 0; i < cred_debug_buf_p->next_slot; i++) {
		nextp->depth = cred_debug_buf_p->stack_buffer[ i ].depth;
		for ( j = 0; j < nextp->depth; j++ ) {
			nextp->stack[ j ] = cred_debug_buf_p->stack_buffer[ i ].stack[ j ];
		}
		space += sizeof(*nextp);
		nextp++;
	}
	req->oldlen = space;
	error = SYSCTL_OUT(req, bt_bufp, req->oldlen);
	FREE(bt_bufp, M_TEMP);
	return (error);
}

#endif	/* KAUTH_CRED_HASH_DEBUG || DEBUG_CRED */


/*
 **********************************************************************
 * The following routines will be moved to a policy_posix.c module at
 * some future point.
 **********************************************************************
 */

/*
 * posix_cred_create
 *
 * Description:	Helper function to create a kauth_cred_t credential that is
 *		initally labelled with a specific POSIX credential label
 *
 * Parameters:	pcred			The posix_cred_t to use as the initial
 *					label value
 *
 * Returns:	(kauth_cred_t)		The credential that was found in the
 *					hash or creates
 *		NULL			kauth_cred_add() failed, or there was
 *					no egid specified, or we failed to
 *					attach a label to the new credential
 *
 * Notes:	This function currently wraps kauth_cred_create(), and is the
 *		only consumer of that ill-fated function, apart from bsd_init().
 *		It exists solely to support the NFS server code creation of
 *		credentials based on the over-the-wire RPC calls containing
 *		traditional POSIX credential information being tunneled to
 *		the server host from the client machine.
 *
 *		In the future, we hope this function goes away.
 *
 *		In the short term, it creates a temporary credential, puts
 *		the POSIX information from NFS into it, and then calls
 *		kauth_cred_create(), as an internal implementation detail.
 *
 *		If we have to keep it around in the medium term, it will
 *		create a new kauth_cred_t, then label it with a POSIX label
 *		corresponding to the contents of the kauth_cred_t.  If the
 *		policy_posix MACF module is not loaded, it will instead
 *		substitute a posix_cred_t which GRANTS all access (effectively
 *		a "root" credential) in order to not prevent NFS from working
 *		in the case that we are not supporting POSIX credentials.
 */
kauth_cred_t
posix_cred_create(posix_cred_t pcred)
{
	struct ucred temp_cred;

	bzero(&temp_cred, sizeof(temp_cred));
	temp_cred.cr_posix = *pcred;

	return kauth_cred_create(&temp_cred);
}


/*
 * posix_cred_get
 *
 * Description:	Given a kauth_cred_t, return the POSIX credential label, if
 *		any, which is associated with it.
 *
 * Parameters:	cred			The credential to obtain the label from
 *
 * Returns:	posix_cred_t		The POSIX credential label
 *
 * Notes:	In the event that the policy_posix MACF module IS NOT loaded,
 *		this function will return a pointer to a posix_cred_t which
 *		GRANTS all access (effectively, a "root" credential).  This is
 *		necessary to support legacy code which insists on tightly
 *		integrating POSIX credentials into its APIs, including, but
 *		not limited to, System V IPC mechanisms, POSIX IPC mechanisms,
 *		NFSv3, signals, dtrace, and a large number of kauth routines
 *		used to implement POSIX permissions related system calls.
 *
 *		In the event that the policy_posix MACF module IS loaded, and
 *		there is no POSIX label on the kauth_cred_t credential, this
 *		function will return a pointer to a posix_cred_t which DENIES
 *		all access (effectively, a "deny rights granted by POSIX"
 *		credential).  This is necessary to support the concept of a
 *		transiently loaded POSIX policy, or kauth_cred_t credentials
 *		which can not be used in conjunctions with POSIX permissions
 *		checks.
 *
 *		This function currently returns the address of the cr_posix
 *		field of the supplied kauth_cred_t credential, and as such
 *		currently can not fail.  In the future, this will not be the
 *		case.
 */
posix_cred_t
posix_cred_get(kauth_cred_t cred)
{
	return(&cred->cr_posix);
}


/*
 * posix_cred_label
 *
 * Description:	Label a kauth_cred_t with a POSIX credential label
 *
 * Parameters:	cred			The credential to label
 *		pcred			The POSIX credential t label it with
 *
 * Returns:	(void)
 *
 * Notes:	This function is currently void in order to permit it to fit
 *		in with the current MACF framework label methods which allow
 *		labeling to fail silently.  This is like acceptable for
 *		mandatory access controls, but not for POSIX, since those
 *		access controls are advisory.  We will need to consider a
 *		return value in a future version of the MACF API.
 *
 *		This operation currently cannot fail, as currently the POSIX
 *		credential is a subfield of the kauth_cred_t (ucred), which
 *		MUST be valid.  In the future, this will not be the case.
 */
void
posix_cred_label(kauth_cred_t cred, posix_cred_t pcred)
{
	cred->cr_posix = *pcred;	/* structure assign for now */
}


/*
 * posix_cred_access
 *
 * Description:	Perform a POSIX access check for a protected object
 *
 * Parameters:	cred			The credential to check
 *		object_uid		The POSIX UID of the protected object
 *		object_gid		The POSIX GID of the protected object
 *		object_mode		The POSIX mode of the protected object
 *		mode_req		The requested POSIX access rights
 *
 * Returns	0			Access is granted
 *		EACCES			Access is denied
 *
 * Notes:	This code optimizes the case where the world and group rights
 *		would both grant the requested rights to avoid making a group
 *		membership query.  This is a big performance win in the case
 *		where this is true.
 */
int
posix_cred_access(kauth_cred_t cred, id_t object_uid, id_t object_gid, mode_t object_mode, mode_t mode_req)
{
	int is_member;
	mode_t mode_owner = (object_mode & S_IRWXU);
	mode_t mode_group = (object_mode & S_IRWXG) << 3;
	mode_t mode_world = (object_mode & S_IRWXO) << 6;

	/*
	 * Check first for owner rights
	 */
	if (kauth_cred_getuid(cred) == object_uid && (mode_req & mode_owner) == mode_req)
		return (0);

	/*
	 * Combined group and world rights check, if we don't have owner rights
	 *
	 * OPTIMIZED: If group and world rights would grant the same bits, and
	 * they set of requested bits is in both, then we can simply check the
	 * world rights, avoiding a group membership check, which is expensive.
	 */
	if ((mode_req & mode_group & mode_world) == mode_req) {
		return (0);
	} else {
		/*
		 * NON-OPTIMIZED: requires group membership check.
		 */
		if ((mode_req & mode_group) != mode_req) {
			/*
			 * exclusion group : treat errors as "is a member"
			 *
			 * NON-OPTIMIZED: +group would deny; must check group
			 */
			if (!kauth_cred_ismember_gid(cred, object_gid, &is_member) && is_member) {
				/*
				 * DENY: +group denies
				 */
				return (EACCES);
			} else {
				if ((mode_req & mode_world) != mode_req) {
					/*
					 * DENY: both -group & world would deny
					 */
					return (EACCES);
				} else {
					/*
					 * ALLOW: allowed by -group and +world
					 */
					return (0);
				}
			}
		} else {
			/*
			 * inclusion group; treat errors as "not a member"
			 *
			 * NON-OPTIMIZED: +group allows, world denies; must
			 * check group
			 */
			if (!kauth_cred_ismember_gid(cred, object_gid, &is_member) && is_member) {
				/*
				 * ALLOW: allowed by +group
				 */
				return (0);
			} else {
				if ((mode_req & mode_world) != mode_req) {
					/*
					 * DENY: both -group & world would deny
					 */
					return (EACCES);
				} else {
					/*
					 * ALLOW: allowed by -group and +world
					 */
					return (0);
				}
			}
		}
	}
}
