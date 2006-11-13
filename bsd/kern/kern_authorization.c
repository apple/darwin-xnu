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
 * Centralized authorisation framework.
 */

#include <sys/appleapiopts.h>
#include <sys/param.h>	/* XXX trim includes */
#include <sys/acct.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/proc_internal.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <sys/malloc.h>
#include <sys/vnode_internal.h>
#include <sys/kauth.h>
#include <sys/stat.h>

#include <bsm/audit_kernel.h>

#include <sys/mount.h>
#include <sys/sysproto.h>
#include <mach/message.h>
#include <mach/host_security.h>

#include <kern/locks.h>


/*
 * Authorization scopes.
 */

lck_grp_t *kauth_lck_grp;
static lck_mtx_t *kauth_scope_mtx;
#define KAUTH_SCOPELOCK()	lck_mtx_lock(kauth_scope_mtx);
#define KAUTH_SCOPEUNLOCK()	lck_mtx_unlock(kauth_scope_mtx);

/*
 * We support listeners for scopes that have not been registered yet.
 * If a listener comes in for a scope that is not active we hang the listener
 * off our kauth_dangling_listeners list and once the scope becomes active we
 * remove it from kauth_dangling_listeners and add it to the active scope.
 */
struct kauth_listener {
	TAILQ_ENTRY(kauth_listener)	kl_link;
	const char *				kl_identifier;
	kauth_scope_callback_t		kl_callback;
	void *						kl_idata;
};

/* XXX - kauth_todo - there is a race if a scope listener is removed while we
 * we are in the kauth_authorize_action code path.  We intentionally do not take
 * a scope lock in order to get the best possible performance.  we will fix this 
 * post Tiger. 
 * Until the race is fixed our kext clients are responsible for all active 
 * requests that may be in their callback code or on the way to their callback
 * code before they free kauth_listener.kl_callback or kauth_listener.kl_idata.
 * We keep copies of these in our kauth_local_listener in an attempt to limit 
 * our expose to unlisten race. 
 */
struct kauth_local_listener {
	kauth_listener_t			kll_listenerp;
	kauth_scope_callback_t		kll_callback;
	void *						kll_idata;
};
typedef struct kauth_local_listener *kauth_local_listener_t;

static TAILQ_HEAD(,kauth_listener) kauth_dangling_listeners;

/* 
 * Scope listeners need to be reworked to be dynamic.
 * We intentionally used a static table to avoid locking issues with linked 
 * lists.  The listeners may be called quite often.
 * XXX - kauth_todo
 */
#define KAUTH_SCOPE_MAX_LISTENERS  15

struct kauth_scope {
	TAILQ_ENTRY(kauth_scope)	ks_link;
	volatile struct kauth_local_listener  ks_listeners[KAUTH_SCOPE_MAX_LISTENERS];
	const char *				ks_identifier;
	kauth_scope_callback_t		ks_callback;
	void *						ks_idata;
	u_int						ks_flags;
};

/* values for kauth_scope.ks_flags */
#define KS_F_HAS_LISTENERS		(1 << 0)

static TAILQ_HEAD(,kauth_scope)	kauth_scopes;

static int kauth_add_callback_to_scope(kauth_scope_t sp, kauth_listener_t klp);
static void	kauth_scope_init(void);
static kauth_scope_t kauth_alloc_scope(const char *identifier, kauth_scope_callback_t callback, void *idata);
static kauth_listener_t kauth_alloc_listener(const char *identifier, kauth_scope_callback_t callback, void *idata);
#if 0
static int	kauth_scope_valid(kauth_scope_t scope);
#endif

kauth_scope_t	kauth_scope_process;
static int	kauth_authorize_process_callback(kauth_cred_t _credential, void *_idata, kauth_action_t _action,
    uintptr_t arg0, uintptr_t arg1, __unused uintptr_t arg2, __unused uintptr_t arg3);
kauth_scope_t	kauth_scope_generic;
static int	kauth_authorize_generic_callback(kauth_cred_t _credential, void *_idata, kauth_action_t _action,
    uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);
kauth_scope_t	kauth_scope_fileop;

extern int 		cansignal(struct proc *, kauth_cred_t, struct proc *, int);
extern char *	get_pathbuff(void);
extern void		release_pathbuff(char *path);

/*
 * Initialization.
 */
void
kauth_init(void)
{
	lck_grp_attr_t	*grp_attributes;

	TAILQ_INIT(&kauth_scopes);
	TAILQ_INIT(&kauth_dangling_listeners);

	/* set up our lock group */
	grp_attributes = lck_grp_attr_alloc_init();
	kauth_lck_grp = lck_grp_alloc_init("kauth", grp_attributes);
	lck_grp_attr_free(grp_attributes);

	/* bring up kauth subsystem components */
	kauth_cred_init();
	kauth_identity_init();
	kauth_groups_init();
	kauth_scope_init();
	kauth_resolver_init();

	/* can't alloc locks after this */
	lck_grp_free(kauth_lck_grp);
	kauth_lck_grp = NULL;
}

static void
kauth_scope_init(void)
{
	kauth_scope_mtx = lck_mtx_alloc_init(kauth_lck_grp, 0 /*LCK_ATTR_NULL*/);
	kauth_scope_process = kauth_register_scope(KAUTH_SCOPE_PROCESS, kauth_authorize_process_callback, NULL);
	kauth_scope_generic = kauth_register_scope(KAUTH_SCOPE_GENERIC, kauth_authorize_generic_callback, NULL);
	kauth_scope_fileop = kauth_register_scope(KAUTH_SCOPE_FILEOP, NULL, NULL);
}

/*
 * Scope registration.
 */

static kauth_scope_t
kauth_alloc_scope(const char *identifier, kauth_scope_callback_t callback, void *idata)
{
	kauth_scope_t	sp;

	/*
	 * Allocate and populate the scope structure.
	 */
	MALLOC(sp, kauth_scope_t, sizeof(*sp), M_KAUTH, M_WAITOK);
	if (sp == NULL)
		return(NULL);
	bzero(&sp->ks_listeners, sizeof(sp->ks_listeners));
	sp->ks_flags = 0;
	sp->ks_identifier = identifier;
	sp->ks_idata = idata;
	sp->ks_callback = callback;
	return(sp);
}

static kauth_listener_t
kauth_alloc_listener(const char *identifier, kauth_scope_callback_t callback, void *idata)
{
	kauth_listener_t lsp;

	/*
	 * Allocate and populate the listener structure.
	 */
	MALLOC(lsp, kauth_listener_t, sizeof(*lsp), M_KAUTH, M_WAITOK);
	if (lsp == NULL)
		return(NULL);
	lsp->kl_identifier = identifier;
	lsp->kl_idata = idata;
	lsp->kl_callback = callback;
	return(lsp);
}

kauth_scope_t
kauth_register_scope(const char *identifier, kauth_scope_callback_t callback, void *idata)
{
	kauth_scope_t		sp, tsp;
	kauth_listener_t	klp;

	if ((sp = kauth_alloc_scope(identifier, callback, idata)) == NULL)
		return(NULL);

	/*
	 * Lock the list and insert.
	 */
	KAUTH_SCOPELOCK();
	TAILQ_FOREACH(tsp, &kauth_scopes, ks_link) {
		/* duplicate! */
		if (strcmp(tsp->ks_identifier, identifier) == 0) {
			KAUTH_SCOPEUNLOCK();
			FREE(sp, M_KAUTH);
			return(NULL);
		}
	}
	TAILQ_INSERT_TAIL(&kauth_scopes, sp, ks_link);

	/*
	 * Look for listeners waiting for this scope, move them to the active scope
	 * listener table.
	 * Note that we have to restart the scan every time we remove an entry
	 * from the list, since we can't remove the current item from the list.
	 */
restart:
	TAILQ_FOREACH(klp, &kauth_dangling_listeners, kl_link) {
		if (strcmp(klp->kl_identifier, sp->ks_identifier) == 0) {
			/* found a match on the dangling listener list.  add it to the
			 * the active scope.
			 */
			if (kauth_add_callback_to_scope(sp, klp) == 0) {
				TAILQ_REMOVE(&kauth_dangling_listeners, klp, kl_link);
			}
			else {
#if 0
				printf("%s - failed to add listener to scope \"%s\" \n", __FUNCTION__, sp->ks_identifier);
#endif
				break;
			}
			goto restart;
		}
	}

	KAUTH_SCOPEUNLOCK();
	return(sp);
}



void
kauth_deregister_scope(kauth_scope_t scope)
{
	int		i;

	KAUTH_SCOPELOCK();

	TAILQ_REMOVE(&kauth_scopes, scope, ks_link);
	
	/* relocate listeners back to the waiting list */
	for (i = 0; i < KAUTH_SCOPE_MAX_LISTENERS; i++) {
		if (scope->ks_listeners[i].kll_listenerp != NULL) {
			TAILQ_INSERT_TAIL(&kauth_dangling_listeners, scope->ks_listeners[i].kll_listenerp, kl_link);
			scope->ks_listeners[i].kll_listenerp = NULL;
			/* 
			 * XXX - kauth_todo - WARNING, do not clear kll_callback or
			 * kll_idata here.  they are part of our scope unlisten race hack
			 */
		}
	}
	KAUTH_SCOPEUNLOCK();
	FREE(scope, M_KAUTH);
	
	return;
}

kauth_listener_t
kauth_listen_scope(const char *identifier, kauth_scope_callback_t callback, void *idata)
{
	kauth_listener_t klp;
	kauth_scope_t	sp;

	if ((klp = kauth_alloc_listener(identifier, callback, idata)) == NULL)
		return(NULL);

	/*
	 * Lock the scope list and check to see whether this scope already exists.
	 */
	KAUTH_SCOPELOCK();
	TAILQ_FOREACH(sp, &kauth_scopes, ks_link) {
		if (strcmp(sp->ks_identifier, identifier) == 0) {
			/* scope exists, add it to scope listener table */
			if (kauth_add_callback_to_scope(sp, klp) == 0) {
				KAUTH_SCOPEUNLOCK();
				return(klp);
			}
			/* table already full */
			KAUTH_SCOPEUNLOCK();
			FREE(klp, M_KAUTH);
			return(NULL);
		}
	}
	
	/* scope doesn't exist, put on waiting list. */
	TAILQ_INSERT_TAIL(&kauth_dangling_listeners, klp, kl_link);

	KAUTH_SCOPEUNLOCK();

	return(klp);
}

void
kauth_unlisten_scope(kauth_listener_t listener)
{
	kauth_scope_t		sp;
	kauth_listener_t 	klp;
	int					i, listener_count, do_free;
	
	KAUTH_SCOPELOCK();

	/* search the active scope for this listener */
	TAILQ_FOREACH(sp, &kauth_scopes, ks_link) {
		do_free = 0;
		if ((sp->ks_flags & KS_F_HAS_LISTENERS) != 0) {
			listener_count = 0;
			for (i = 0; i < KAUTH_SCOPE_MAX_LISTENERS; i++) {
				if (sp->ks_listeners[i].kll_listenerp == listener) {
					sp->ks_listeners[i].kll_listenerp = NULL;
					do_free = 1;
					/* 
					 * XXX - kauth_todo - WARNING, do not clear kll_callback or
					 * kll_idata here.  they are part of our scope unlisten race hack
					 */
				}
				else if (sp->ks_listeners[i].kll_listenerp != NULL) {
					listener_count++;
				}
			}
			if (do_free) {
				if (listener_count == 0) {
					sp->ks_flags &= ~KS_F_HAS_LISTENERS;
				}
				KAUTH_SCOPEUNLOCK();
				FREE(listener, M_KAUTH);
				return;
			}
		}
	}

	/* if not active, check the dangling list */
	TAILQ_FOREACH(klp, &kauth_dangling_listeners, kl_link) {
		if (klp == listener) {
			TAILQ_REMOVE(&kauth_dangling_listeners, klp, kl_link);
			KAUTH_SCOPEUNLOCK();
			FREE(listener, M_KAUTH);
			return;
		}
	}

	KAUTH_SCOPEUNLOCK();
	return;
}

/*
 * Authorization requests.
 */
int
kauth_authorize_action(kauth_scope_t scope, kauth_cred_t credential, kauth_action_t action,
    uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
	int result, ret, i;

	/* ask the scope */
	if (scope->ks_callback != NULL)
		result = scope->ks_callback(credential, scope->ks_idata, action, arg0, arg1, arg2, arg3);
	else
		result = KAUTH_RESULT_DEFER;

	/* check with listeners */
	if ((scope->ks_flags & KS_F_HAS_LISTENERS) != 0) {
		for (i = 0; i < KAUTH_SCOPE_MAX_LISTENERS; i++) {
			/* XXX - kauth_todo - there is a race here if listener is removed - we will fix this post Tiger. 
			 * Until the race is fixed our kext clients are responsible for all active requests that may
			 * be in their callbacks or on the way to their callbacks before they free kl_callback or kl_idata.
			 * We keep copies of these in our kauth_local_listener in an attempt to limit our expose to 
			 * unlisten race. 
			 */
			if (scope->ks_listeners[i].kll_listenerp == NULL || 
				scope->ks_listeners[i].kll_callback == NULL) 
				continue;

			ret = scope->ks_listeners[i].kll_callback(
					credential, scope->ks_listeners[i].kll_idata, 
					action, arg0, arg1, arg2, arg3);
			if ((ret == KAUTH_RESULT_DENY) ||
				(result == KAUTH_RESULT_DEFER))
				result = ret;
		}
	}

	/* we need an explicit allow, or the auth fails */
 	/* XXX need a mechanism for auth failure to be signalled vs. denial */
 	return(result == KAUTH_RESULT_ALLOW ? 0 : EPERM);
}

/*
 * Default authorization handlers.
 */
int
kauth_authorize_allow(__unused kauth_cred_t credential, __unused void *idata, __unused kauth_action_t action,
     __unused uintptr_t arg0, __unused uintptr_t arg1, __unused uintptr_t arg2, __unused uintptr_t arg3)
{

	return(KAUTH_RESULT_ALLOW);
}

#if 0
/*
 * Debugging support.
 */
static int
kauth_scope_valid(kauth_scope_t scope)
{
	kauth_scope_t	sp;

	KAUTH_SCOPELOCK();
	TAILQ_FOREACH(sp, &kauth_scopes, ks_link) {
		if (sp == scope)
			break;
	}
	KAUTH_SCOPEUNLOCK();
	return((sp == NULL) ? 0 : 1);
}
#endif

/*
 * Process authorization scope.
 */

int
kauth_authorize_process(kauth_cred_t credential, kauth_action_t action, struct proc *process, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
	return(kauth_authorize_action(kauth_scope_process, credential, action, (uintptr_t)process, arg1, arg2, arg3));
}

static int
kauth_authorize_process_callback(kauth_cred_t credential, __unused void *idata, kauth_action_t action,
    uintptr_t arg0, uintptr_t arg1, __unused uintptr_t arg2, __unused uintptr_t arg3)
{
	switch(action) {
	case KAUTH_PROCESS_CANSIGNAL:
		panic("KAUTH_PROCESS_CANSIGNAL not implemented");
		/* XXX credential wrong here */
		/* arg0 - process to signal
		 * arg1 - signal to send the process
		 */
		if (cansignal(current_proc(), credential, (struct proc *)arg0, (int)arg1))
			return(KAUTH_RESULT_ALLOW);
		break;
	case KAUTH_PROCESS_CANTRACE:
		/* current_proc() - process that will do the tracing 
		 * arg0 - process to be traced 
		 * arg1 - pointer to int - reason (errno) for denial 
		 */
		if (cantrace(current_proc(), credential, (proc_t)arg0, (int *)arg1))
			return(KAUTH_RESULT_ALLOW);
		break;
	}

	/* no explicit result, so defer to others in the chain */
	return(KAUTH_RESULT_DEFER);
}

/*
 * File system operation authorization scope.  This is really only a notification
 * of the file system operation, not an authorization check.  Thus the result is
 * not relevant.
 * arguments passed to KAUTH_FILEOP_OPEN listeners
 *		arg0 is pointer to vnode (vnode *) for given user path.
 *		arg1 is pointer to path (char *) passed in to open.
 * arguments passed to KAUTH_FILEOP_CLOSE listeners
 *		arg0 is pointer to vnode (vnode *) for file to be closed.
 *		arg1 is pointer to path (char *) of file to be closed.
 *		arg2 is close flags.
 * arguments passed to KAUTH_FILEOP_RENAME listeners
 *		arg0 is pointer to "from" path (char *).
 *		arg1 is pointer to "to" path (char *).
 * arguments passed to KAUTH_FILEOP_EXCHANGE listeners
 *		arg0 is pointer to file 1 path (char *).
 *		arg1 is pointer to file 2 path (char *).
 * arguments passed to KAUTH_FILEOP_EXEC listeners
 *		arg0 is pointer to vnode (vnode *) for executable.
 *		arg1 is pointer to path (char *) to executable.
 */

int
kauth_authorize_fileop_has_listeners(void)
{
	/*
	 * return 1 if we have any listeners for the fileop scope
	 * otherwize return 0
	 */
	if ((kauth_scope_fileop->ks_flags & KS_F_HAS_LISTENERS) != 0) {
		return(1);
	}
	return (0);
}

int
kauth_authorize_fileop(kauth_cred_t credential, kauth_action_t action, uintptr_t arg0, uintptr_t arg1)
{
	char 		*namep = NULL;
	int			name_len;
	uintptr_t	arg2 = 0;
	
	/* we do not have a primary handler for the fileop scope so bail out if 
	 * there are no listeners.
	 */
	if ((kauth_scope_fileop->ks_flags & KS_F_HAS_LISTENERS) == 0) {
		return(0);
	}

	if (action == KAUTH_FILEOP_OPEN || action == KAUTH_FILEOP_CLOSE || action == KAUTH_FILEOP_EXEC) {
		/* get path to the given vnode as a convenience to our listeners.
		 */
		namep = get_pathbuff();
		name_len = MAXPATHLEN;
		if (vn_getpath((vnode_t)arg0, namep, &name_len) != 0) {
			release_pathbuff(namep);
			return(0);
		}
		if (action == KAUTH_FILEOP_CLOSE) {
			arg2 = arg1;  /* close has some flags that come in via arg1 */
		}
		arg1 = (uintptr_t)namep;
	}	
	kauth_authorize_action(kauth_scope_fileop, credential, action, arg0, arg1, arg2, 0);
	
	if (namep != NULL) {
		release_pathbuff(namep);
	}
	
	return(0);
}

/*
 * Generic authorization scope.
 */

int
kauth_authorize_generic(kauth_cred_t credential, kauth_action_t action)
{
	if (credential == NULL)
		panic("auth against NULL credential");

	return(kauth_authorize_action(kauth_scope_generic, credential, action, 0, 0, 0, 0));
		
}

static int
kauth_authorize_generic_callback(kauth_cred_t credential, __unused void *idata, kauth_action_t action,
     __unused uintptr_t arg0, __unused uintptr_t arg1, __unused uintptr_t arg2, __unused uintptr_t arg3)
{
	switch(action) {
	case KAUTH_GENERIC_ISSUSER:
		/* XXX == 0 ? */
		return((kauth_cred_getuid(credential) == 0) ?
		    KAUTH_RESULT_ALLOW : KAUTH_RESULT_DENY);
		break;
	}

	/* no explicit result, so defer to others in the chain */
	return(KAUTH_RESULT_DEFER);
}

/*
 * ACL evaluator.
 *
 * Determines whether the credential has the requested rights for an object secured by the supplied
 * ACL.
 *
 * Evaluation proceeds from the top down, with access denied if any ACE denies any of the requested
 * rights, or granted if all of the requested rights are satisfied by the ACEs so far.
 */
int
kauth_acl_evaluate(kauth_cred_t cred, kauth_acl_eval_t eval)
{
	int applies, error, i;
	kauth_ace_t ace;
	guid_t guid;
	uint32_t rights;
	int wkguid;

	/* always allowed to do nothing */
	if (eval->ae_requested == 0) {
		eval->ae_result = KAUTH_RESULT_ALLOW;
		return(0);
	}

	eval->ae_residual = eval->ae_requested;

	/*
	 * Get our guid for comparison purposes.
	 */
	if ((error = kauth_cred_getguid(cred, &guid)) != 0) {
		eval->ae_result = KAUTH_RESULT_DENY;
		KAUTH_DEBUG("    ACL - can't get credential GUID (%d), ACL denied", error);
		return(error);
	}

	KAUTH_DEBUG("    ACL - %d entries, initial residual %x", eval->ae_count, eval->ae_residual);
	for (i = 0, ace = eval->ae_acl; i < eval->ae_count; i++, ace++) {

		/*
		 * Skip inherit-only entries.
		 */
		if (ace->ace_flags & KAUTH_ACE_ONLY_INHERIT)
			continue;

		/*
		 * Expand generic rights, if appropriate.
		 */
		rights = ace->ace_rights;
		if (rights & KAUTH_ACE_GENERIC_ALL)
			rights |= eval->ae_exp_gall;
		if (rights & KAUTH_ACE_GENERIC_READ)
			rights |= eval->ae_exp_gread;
		if (rights & KAUTH_ACE_GENERIC_WRITE)
			rights |= eval->ae_exp_gwrite;
		if (rights & KAUTH_ACE_GENERIC_EXECUTE)
			rights |= eval->ae_exp_gexec;

		/*
		 * Determine whether this entry applies to the current request.  This
		 * saves us checking the GUID if the entry has nothing to do with what
		 * we're currently doing.
		 */
		switch(ace->ace_flags & KAUTH_ACE_KINDMASK) {
		case KAUTH_ACE_PERMIT:
			if (!(eval->ae_residual & rights))
				continue;
			break;
		case KAUTH_ACE_DENY:
			if (!(eval->ae_requested & rights))
				continue;
			break;
		default:
			/* we don't recognise this ACE, skip it */
			continue;
		}
		
		/*
		 * Verify whether this entry applies to the credential.
		 */
		wkguid = kauth_wellknown_guid(&ace->ace_applicable);
		switch(wkguid) {
		case KAUTH_WKG_OWNER:
			applies = eval->ae_options & KAUTH_AEVAL_IS_OWNER;
			break;
		case KAUTH_WKG_GROUP:
			applies = eval->ae_options & KAUTH_AEVAL_IN_GROUP;
			break;
		/* we short-circuit these here rather than wasting time calling the group membership code */
		case KAUTH_WKG_EVERYBODY:
			applies = 1;
			break;
		case KAUTH_WKG_NOBODY:
			applies = 0;
			break;

		default:
			/* check to see whether it's exactly us, or a group we are a member of */
			applies = kauth_guid_equal(&guid, &ace->ace_applicable);
			KAUTH_DEBUG("    ACL - ACE applicable " K_UUID_FMT " caller " K_UUID_FMT " %smatched",
			    K_UUID_ARG(ace->ace_applicable), K_UUID_ARG(guid), applies ? "" : "not ");
		
			if (!applies) {
				error = kauth_cred_ismember_guid(cred, &ace->ace_applicable, &applies);
				/*
				 * If we can't resolve group membership, we have to limit misbehaviour.
				 * If the ACE is an 'allow' ACE, assume the cred is not a member (avoid
				 * granting excess access).  If the ACE is a 'deny' ACE, assume the cred
				 * is a member (avoid failing to deny).
				 */
				if (error != 0) {
					KAUTH_DEBUG("    ACL[%d] - can't get membership, making pessimistic assumption", i);
					switch(ace->ace_flags & KAUTH_ACE_KINDMASK) {
					case KAUTH_ACE_PERMIT:
						applies = 0;
						break;
					case KAUTH_ACE_DENY:
						applies = 1;
						break;
					}
				} else {
					KAUTH_DEBUG("    ACL - %s group member", applies ? "is" : "not");
				}
			} else {
				KAUTH_DEBUG("    ACL - entry matches caller");
			}
		}
		if (!applies)
			continue;

		/*
		 * Apply ACE to outstanding rights.
		 */
		switch(ace->ace_flags & KAUTH_ACE_KINDMASK) {
		case KAUTH_ACE_PERMIT:
			/* satisfy any rights that this ACE grants */
			eval->ae_residual = eval->ae_residual & ~rights;
			KAUTH_DEBUG("    ACL[%d] - rights %x leave residual %x", i, rights, eval->ae_residual);
			/* all rights satisfied? */
			if (eval->ae_residual == 0) {
				eval->ae_result = KAUTH_RESULT_ALLOW;
				return(0);
			}
			break;
		case KAUTH_ACE_DENY:
			/* deny the request if any of the requested rights is denied */
			if (eval->ae_requested & rights) {
				KAUTH_DEBUG("    ACL[%d] - denying based on %x", i, rights);
				eval->ae_result = KAUTH_RESULT_DENY;
				return(0);
			}
			break;
		default:
			KAUTH_DEBUG("    ACL - unknown entry kind %d", ace->ace_flags & KAUTH_ACE_KINDMASK);
			break;
		}
	}
	/* if not permitted, defer to other modes of authorisation */
	eval->ae_result = KAUTH_RESULT_DEFER;
	return(0);
}

/*
 * Perform ACL inheritance and umask-ACL handling.
 *
 * Entries are inherited from the ACL on dvp.  A caller-supplied
 * ACL is in initial, and the result is output into product.
 * If the process has a umask ACL and one is not supplied, we use
 * the umask ACL.
 * If isdir is set, the resultant ACL is for a directory, otherwise it is for a file.
 */
int
kauth_acl_inherit(vnode_t dvp, kauth_acl_t initial, kauth_acl_t *product, int isdir, vfs_context_t ctx)
{
	int	entries, error, index;
	unsigned int i;
	struct vnode_attr dva;
	kauth_acl_t inherit, result;

	/*
	 * Fetch the ACL from the directory.  This should never fail.  Note that we don't
	 * manage inheritance when the remote server is doing authorization; we just
	 * want to compose the umask-ACL and any initial ACL.
	 */
	inherit = NULL;
	if ((dvp != NULL) && !vfs_authopaque(vnode_mount(dvp))) {
		VATTR_INIT(&dva);
		VATTR_WANTED(&dva, va_acl);
		if ((error = vnode_getattr(dvp, &dva, ctx)) != 0) {
			KAUTH_DEBUG("    ERROR - could not get parent directory ACL for inheritance");
			return(error);
		}
		if (VATTR_IS_SUPPORTED(&dva, va_acl))
			inherit = dva.va_acl;
	}

	/*
	 * Compute the number of entries in the result ACL by scanning the input lists.
	 */
	entries = 0;
	if (inherit != NULL) {
		for (i = 0; i < inherit->acl_entrycount; i++) {
			if (inherit->acl_ace[i].ace_flags & (isdir ? KAUTH_ACE_DIRECTORY_INHERIT : KAUTH_ACE_FILE_INHERIT))
				entries++;
		}
	}

	if (initial == NULL) {
		/* XXX 3634665 TODO: fetch umask ACL from the process, set in initial */
	}

	if (initial != NULL) {
		entries += initial->acl_entrycount;
	}

	/*
	 * If there is no initial ACL, and no inheritable entries, the
	 * object should have no ACL at all.
	 * Note that this differs from the case where the initial ACL
	 * is empty, in which case the object must also have an empty ACL.
	 */
	if ((entries == 0) && (initial == NULL)) {
		*product = NULL;
		error = 0;
		goto out;
	}
	
	/*
	 * Allocate the result buffer.
	 */
	if ((result = kauth_acl_alloc(entries)) == NULL) {
		KAUTH_DEBUG("    ERROR - could not allocate %d-entry result buffer for inherited ACL");
		error = ENOMEM;
		goto out;
	}

	/*
	 * Composition is simply:
	 *  - initial
	 *  - inherited
	 */
	index = 0;
	if (initial != NULL) {
		for (i = 0; i < initial->acl_entrycount; i++)
			result->acl_ace[index++] = initial->acl_ace[i];
		KAUTH_DEBUG("    INHERIT - applied %d initial entries", index);
	}
	if (inherit != NULL) {
		for (i = 0; i < inherit->acl_entrycount; i++) {
			/* inherit onto this object? */
			if (inherit->acl_ace[i].ace_flags & (isdir ? KAUTH_ACE_DIRECTORY_INHERIT : KAUTH_ACE_FILE_INHERIT)) {
				result->acl_ace[index] = inherit->acl_ace[i];
				result->acl_ace[index].ace_flags |= KAUTH_ACE_INHERITED;
				/* don't re-inherit? */
				if (result->acl_ace[index].ace_flags & KAUTH_ACE_LIMIT_INHERIT)
					result->acl_ace[index].ace_flags &=
					    ~(KAUTH_ACE_DIRECTORY_INHERIT | KAUTH_ACE_FILE_INHERIT | KAUTH_ACE_LIMIT_INHERIT);
				index++;
			}
		}
	}
	result->acl_entrycount = index;
	*product = result;
	KAUTH_DEBUG("    INHERIT - product ACL has %d entries", index);
	error = 0;
out:
	if (inherit != NULL)
		kauth_acl_free(inherit);
	return(error);
}

/*
 * Optimistically copy in a kauth_filesec structure
 *
 * Parameters:	xsecurity		user space kauth_filesec_t
 *		xsecdstpp		pointer to kauth_filesec_t to be
 *					modified to contain the contain a
 *					pointer to an allocated copy of the
 *					user space argument
 *
 * Returns:	0			Success
 *		ENOMEM			Insufficient memory for the copy.
 *		EINVAL			The user space data was invalid, or
 *					there were too many ACE entries.
 *		EFAULT			The user space address was invalid;
 *					this may mean 'fsec_entrycount' in
 *					the user copy is corrupt/incorrect.
 *
 * Implicit returns: xsecdestpp, modified (only if successful!)
 *
 * Notes:	The returned kauth_filesec_t is in host byte order
 *
 *		The caller is responsible for freeing the returned
 *		kauth_filesec_t in the success case using the function
 *		kauth_filesec_free()
 *
 *		Our largest initial guess is 32; this needs to move to
 *		a manifest constant in <sys/kauth.h>.
 */
int
kauth_copyinfilesec(user_addr_t xsecurity, kauth_filesec_t *xsecdestpp)
{
	user_addr_t uaddr, known_bound;
	int error;
	kauth_filesec_t fsec;
	u_int32_t count;
	size_t copysize;
	
	error = 0;
	fsec = NULL;

	/*
	 * Make a guess at the size of the filesec.  We start with the base
	 * pointer, and look at how much room is left on the page, clipped
	 * to a sensible upper bound.  If it turns out this isn't enough,
	 * we'll size based on the actual ACL contents and come back again.
	 *
	 * The upper bound must be less than KAUTH_ACL_MAX_ENTRIES.  The
	 * value here is fairly arbitrary.  It's ok to have a zero count.
	 */
	known_bound = xsecurity + sizeof(struct kauth_filesec);
	uaddr = mach_vm_round_page(known_bound);
	count = (uaddr - known_bound) / sizeof(struct kauth_ace);
	if (count > 32)
		count = 32;
restart:
	if ((fsec = kauth_filesec_alloc(count)) == NULL) {
		error = ENOMEM;
		goto out;
	}
	copysize = KAUTH_FILESEC_SIZE(count);
	if ((error = copyin(xsecurity, (caddr_t)fsec, copysize)) != 0)
		goto out;

	/* validate the filesec header */
	if (fsec->fsec_magic != KAUTH_FILESEC_MAGIC) {
		error = EINVAL;
		goto out;
	}

	/*
	 * Is there an ACL payload, and is it too big?
	 */
	if ((fsec->fsec_entrycount != KAUTH_FILESEC_NOACL) &&
	    (fsec->fsec_entrycount > count)) {
		if (fsec->fsec_entrycount > KAUTH_ACL_MAX_ENTRIES) {
			/* XXX This should be E2BIG */
			error = EINVAL;
			goto out;
		}
		count = fsec->fsec_entrycount;
		kauth_filesec_free(fsec);
		goto restart;
	}
	
out:
	if (error) {
		if (fsec)
			kauth_filesec_free(fsec);
	} else {
		*xsecdestpp = fsec;
	}
	return(error);
}

/*
 * Allocate a block of memory containing a filesec structure, immediately
 * followed by 'count' kauth_ace structures.
 *
 * Parameters:	count			Number of kauth_ace structures needed
 *
 * Returns:	!NULL			A pointer to the allocated block
 *		NULL			Invalid 'count' or insufficient memory
 *
 * Notes:	Returned memory area assumes that the structures are packed
 *		densely, so this function may only be used by code that also
 *		assumes no padding following structures.
 *
 *		The returned structure must be freed by the caller using the
 *		function kauth_filesec_free(), in case we decide to use an
 *		allocation mechanism that is aware of the object size at some
 *		point, since the object size is only available by introspecting
 *		the object itself.
 */
kauth_filesec_t
kauth_filesec_alloc(int count)
{
	kauth_filesec_t	fsp;
	
	/* if the caller hasn't given us a valid size hint, assume the worst */
	if ((count < 0) || (count > KAUTH_ACL_MAX_ENTRIES))
		return(NULL);

	MALLOC(fsp, kauth_filesec_t, KAUTH_FILESEC_SIZE(count), M_KAUTH, M_WAITOK);
	if (fsp != NULL) {
		fsp->fsec_magic = KAUTH_FILESEC_MAGIC;
		fsp->fsec_owner = kauth_null_guid;
		fsp->fsec_group = kauth_null_guid;
		fsp->fsec_entrycount = KAUTH_FILESEC_NOACL;
		fsp->fsec_flags = 0;
	}
	return(fsp);
}	

/*
 * Free a kauth_filesec_t that was previous allocated, either by a direct
 * call to kauth_filesec_alloc() or by calling a function that calls it.
 *
 * Parameters:	fsp			kauth_filesec_t to free
 *
 * Returns:	(void)
 *
 * Notes:	The kauth_filesec_t to be freed is assumed to be in host
 *		byte order so that this function can introspect it in the
 *		future to determine its size, if necesssary.
 */
void
kauth_filesec_free(kauth_filesec_t fsp)
{
#ifdef KAUTH_DEBUG_ENABLE
	if (fsp == KAUTH_FILESEC_NONE)
		panic("freeing KAUTH_FILESEC_NONE");
	if (fsp == KAUTH_FILESEC_WANTED)
		panic("freeing KAUTH_FILESEC_WANTED");
#endif
	FREE(fsp, M_KAUTH);
}

/*
 * Set the endianness of a filesec and an ACL; if 'acl' is NULL, use the 
 * ACL interior to 'fsec' instead.  If the endianness doesn't change, then
 * this function will have no effect.
 *
 * Parameters:	kendian			The endianness to set; this is either
 *					KAUTH_ENDIAN_HOST or KAUTH_ENDIAN_DISK.
 *		fsec			The filesec to convert.
 *		acl			The ACL to convert (optional)
 *
 * Returns:	(void)
 *
 * Notes:	We use ntohl() because it has a transitive property on Intel
 *		machines and no effect on PPC mancines.  This guarantees us
 *		that the swapping only occurs if the endiannes is wrong.
 */
void
kauth_filesec_acl_setendian(int kendian, kauth_filesec_t fsec, kauth_acl_t acl)
{
 	uint32_t	compare_magic = KAUTH_FILESEC_MAGIC;
	uint32_t	invert_magic = ntohl(KAUTH_FILESEC_MAGIC);
	uint32_t	compare_acl_entrycount;
	uint32_t	i;

	if (compare_magic == invert_magic)
		return;

	/* If no ACL, use ACL interior to 'fsec' instead */
	if (acl == NULL)
		acl = &fsec->fsec_acl;

	compare_acl_entrycount = acl->acl_entrycount;

	/*
	 * Only convert what needs to be converted, and only if the arguments
	 * are valid.  The following switch and tests effectively reject
	 * conversions on invalid magic numbers as a desirable side effect.
	 */
 	switch(kendian) {
	case KAUTH_ENDIAN_HOST:		/* not in host, convert to host */
		if (fsec->fsec_magic != invert_magic)
			return;
		/* acl_entrycount is byteswapped */
		compare_acl_entrycount = ntohl(acl->acl_entrycount);
		break;
	case KAUTH_ENDIAN_DISK:		/* not in disk, convert to disk */
		if (fsec->fsec_magic != compare_magic)
			return;
		break;
	default:			/* bad argument */
		return;
	}
	
	/* We are go for conversion */
	fsec->fsec_magic = ntohl(fsec->fsec_magic);
	acl->acl_entrycount = ntohl(acl->acl_entrycount);
	if (compare_acl_entrycount != KAUTH_FILESEC_NOACL) {
		acl->acl_flags = ntohl(acl->acl_flags);

		/* swap ACE rights and flags */
		for (i = 0; i < compare_acl_entrycount; i++) {
			acl->acl_ace[i].ace_flags = ntohl(acl->acl_ace[i].ace_flags);
			acl->acl_ace[i].ace_rights = ntohl(acl->acl_ace[i].ace_rights);
		}
	}
 }


/*
 * Allocate an ACL buffer.
 */
kauth_acl_t
kauth_acl_alloc(int count)
{
	kauth_acl_t	aclp;
	
	/* if the caller hasn't given us a valid size hint, assume the worst */
	if ((count < 0) || (count > KAUTH_ACL_MAX_ENTRIES))
		return(NULL);

	MALLOC(aclp, kauth_acl_t, KAUTH_ACL_SIZE(count), M_KAUTH, M_WAITOK);
	if (aclp != NULL) {
		aclp->acl_entrycount = 0;
		aclp->acl_flags = 0;
	}
	return(aclp);
}	

void
kauth_acl_free(kauth_acl_t aclp)
{
	FREE(aclp, M_KAUTH);
}


/*
 * WARNING - caller must hold KAUTH_SCOPELOCK
 */
static int kauth_add_callback_to_scope(kauth_scope_t sp, kauth_listener_t klp)
{
	int		i;

	for (i = 0; i < KAUTH_SCOPE_MAX_LISTENERS; i++) {
		if (sp->ks_listeners[i].kll_listenerp == NULL) {
			sp->ks_listeners[i].kll_callback = klp->kl_callback;
			sp->ks_listeners[i].kll_idata = klp->kl_idata;
			sp->ks_listeners[i].kll_listenerp = klp;
			sp->ks_flags |= KS_F_HAS_LISTENERS;
			return(0);
		}
	}
	return(ENOSPC);
}
