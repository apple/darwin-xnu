/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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
#include <sys/kernel.h>
#include <sys/kernel_types.h>
#include <sys/persona.h>

#if CONFIG_PERSONAS
#include <kern/assert.h>
#include <kern/simple_lock.h>
#include <kern/task.h>
#include <kern/zalloc.h>

#include <sys/param.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/proc_info.h>
#include <sys/resourcevar.h>

#define pna_info(fmt, ...) \
	printf("%s:  " fmt "\n", __func__, ## __VA_ARGS__)

#define pna_err(fmt, ...) \
	printf("ERROR[%s]:  " fmt "\n", __func__, ## __VA_ARGS__)

#define MAX_PERSONAS     512

#define TEMP_PERSONA_ID  499

#define FIRST_PERSONA_ID 501
#define PERSONA_ID_STEP   10

#define PERSONA_SYSTEM_UID    ((uid_t)99)
#define PERSONA_SYSTEM_LOGIN  "system"

#define PERSONA_MAGIC         (0x0aa55aa0)
#define persona_valid(p)      ((p)->pna_valid == PERSONA_MAGIC)
#define persona_mkinvalid(p)  ((p)->pna_valid = ~(PERSONA_MAGIC))

static LIST_HEAD(personalist, persona) all_personas;
static uint32_t g_total_personas;
uint32_t g_max_personas = MAX_PERSONAS;

struct persona *g_system_persona = NULL;

static uid_t g_next_persona_id;

lck_mtx_t all_personas_lock;
lck_attr_t *persona_lck_attr;
lck_grp_t *persona_lck_grp;
lck_grp_attr_t *persona_lck_grp_attr;

static zone_t persona_zone;

kauth_cred_t g_default_persona_cred;

#define lock_personas()    lck_mtx_lock(&all_personas_lock)
#define unlock_personas()  lck_mtx_unlock(&all_personas_lock)


extern void mach_kauth_cred_uthread_update(void);

void personas_bootstrap(void)
{
	struct posix_cred pcred;

	persona_dbg("Initializing persona subsystem");
	LIST_INIT(&all_personas);
	g_total_personas = 0;

	g_next_persona_id = FIRST_PERSONA_ID;

	persona_lck_grp_attr = lck_grp_attr_alloc_init();
	lck_grp_attr_setstat(persona_lck_grp_attr);

	persona_lck_grp = lck_grp_alloc_init("personas", persona_lck_grp_attr);
	persona_lck_attr = lck_attr_alloc_init();

	lck_mtx_init(&all_personas_lock, persona_lck_grp, persona_lck_attr);

	persona_zone = zinit(sizeof(struct persona),
			     MAX_PERSONAS * sizeof(struct persona),
			     MAX_PERSONAS, "personas");
	assert(persona_zone != NULL);

	/*
	 * setup the default credentials that a persona temporarily
	 * inherits (to work around kauth APIs)
	 */
	bzero(&pcred, sizeof(pcred));
	pcred.cr_uid = pcred.cr_ruid = pcred.cr_svuid = TEMP_PERSONA_ID;
	pcred.cr_rgid = pcred.cr_svgid = TEMP_PERSONA_ID;
	pcred.cr_groups[0] = TEMP_PERSONA_ID;
	pcred.cr_ngroups = 1;
	pcred.cr_flags = CRF_NOMEMBERD;
	pcred.cr_gmuid = KAUTH_UID_NONE;

	g_default_persona_cred = posix_cred_create(&pcred);
	if (!g_default_persona_cred)
		panic("couldn't create default persona credentials!");

	g_system_persona = persona_alloc(PERSONA_SYSTEM_UID,
					 PERSONA_SYSTEM_LOGIN,
					 PERSONA_SYSTEM, NULL);
	assert(g_system_persona != NULL);
}

struct persona *persona_alloc(uid_t id, const char *login, int type, int *error)
{
	struct persona *persona, *tmp;
	int err = 0;
	kauth_cred_t tmp_cred;
	gid_t new_group;

	if (!login) {
		pna_err("Must provide a login name for a new persona!");
		if (error)
			*error = EINVAL;
		return NULL;
	}

	if (type <= PERSONA_INVALID || type > PERSONA_TYPE_MAX) {
		pna_err("Invalid type: %d", type);
		if (error)
			*error = EINVAL;
		return NULL;
	}

	persona = (struct persona *)zalloc(persona_zone);
	if (!persona) {
		if (error)
			*error = ENOMEM;
		return NULL;
	}

	bzero(persona, sizeof(*persona));

	if (hw_atomic_add(&g_total_personas, 1) > MAX_PERSONAS) {
		/* too many personas! */
		pna_err("too many active personas!");
		err = EBUSY;
		goto out_error;
	}

	strncpy(persona->pna_login, login, sizeof(persona->pna_login)-1);

	LIST_INIT(&persona->pna_members);
	lck_mtx_init(&persona->pna_lock, persona_lck_grp, persona_lck_attr);
	persona->pna_refcount = 1;

	/*
	 * Setup initial (temporary) kauth_cred structure
	 * We need to do this here because all kauth calls require
	 * an existing cred structure.
	 */
	persona->pna_cred = kauth_cred_create(g_default_persona_cred);
	if (!persona->pna_cred) {
		pna_err("could not copy initial credentials!");
		err = EIO;
		goto out_error;
	}

	lock_personas();
try_again:
	if (id != PERSONA_ID_NONE)
		persona->pna_id = id;
	else
		persona->pna_id = g_next_persona_id;

	persona_dbg("Adding %d (%s) to global list...", persona->pna_id, persona->pna_login);

	err = 0;
	LIST_FOREACH(tmp, &all_personas, pna_list) {
		if (id == PERSONA_ID_NONE && tmp->pna_id == id) {
			/*
			 * someone else manually claimed this ID, and we're
			 * trying to allocate an ID for the caller: try again
			 */
			g_next_persona_id += PERSONA_ID_STEP;
			goto try_again;
		}
		if (strncmp(tmp->pna_login, login, sizeof(tmp->pna_login)) == 0
		    || tmp->pna_id == id) {
			/*
			 * Disallow use of identical login names and re-use
			 * of previously allocated persona IDs
			 */
			err = EEXIST;
			break;
		}
	}
	if (err)
		goto out_unlock;

	/* ensure the cred has proper UID/GID defaults */
	kauth_cred_ref(persona->pna_cred);
	tmp_cred = kauth_cred_setuidgid(persona->pna_cred,
					persona->pna_id,
					persona->pna_id);
	kauth_cred_unref(&persona->pna_cred);
	if (tmp_cred != persona->pna_cred)
		persona->pna_cred = tmp_cred;

	if (!persona->pna_cred) {
		err = EACCES;
		goto out_unlock;
	}

	/* it should be a member of exactly 1 group (equal to its UID) */
	new_group = (gid_t)persona->pna_id;

	kauth_cred_ref(persona->pna_cred);
	/* opt _out_ of memberd as a default */
	tmp_cred = kauth_cred_setgroups(persona->pna_cred,
					&new_group, 1, KAUTH_UID_NONE);
	kauth_cred_unref(&persona->pna_cred);
	if (tmp_cred != persona->pna_cred)
		persona->pna_cred = tmp_cred;

	if (!persona->pna_cred) {
		err = EACCES;
		goto out_unlock;
	}

	persona->pna_type = type;

	/* insert the, now valid, persona into the global list! */
	persona->pna_valid = PERSONA_MAGIC;
	LIST_INSERT_HEAD(&all_personas, persona, pna_list);

	/* if the kernel supplied the persona ID, increment for next time */
	if (id == PERSONA_ID_NONE)
		g_next_persona_id += PERSONA_ID_STEP;

out_unlock:
	unlock_personas();

	if (err) {
		switch (err) {
		case EEXIST:
			persona_dbg("Login '%s' (%d) already exists",
				    login, persona->pna_id);
			break;
		case EACCES:
			persona_dbg("kauth_error for persona:%d", persona->pna_id);
			break;
		default:
			persona_dbg("Unknown error:%d", err);
		}
		goto out_error;
	}

	return persona;

out_error:
	(void)hw_atomic_add(&g_total_personas, -1);
	zfree(persona_zone, persona);
	if (error)
		*error = err;
	return NULL;
}

int persona_invalidate(struct persona *persona)
{
	int error = 0;
	if (!persona)
		return EINVAL;

	lock_personas();
	persona_lock(persona);

	if (!persona_valid(persona))
		panic("Double-invalidation of persona %p", persona);

	LIST_REMOVE(persona, pna_list);
	if (hw_atomic_add(&g_total_personas, -1) == UINT_MAX)
		panic("persona ref count underflow!\n");
	persona_mkinvalid(persona);

	persona_unlock(persona);
	unlock_personas();

	return error;
}

static struct persona *persona_get_locked(struct persona *persona)
{
	if (persona->pna_refcount) {
		persona->pna_refcount++;
		return persona;
	}
	return NULL;
}

struct persona *persona_get(struct persona *persona)
{
	struct persona *ret;
	if (!persona)
		return NULL;
	persona_lock(persona);
	ret = persona_get_locked(persona);
	persona_unlock(persona);

	return ret;
}

void persona_put(struct persona *persona)
{
	int destroy = 0;

	if (!persona)
		return;

	persona_lock(persona);
	if (persona->pna_refcount >= 0) {
		if (--(persona->pna_refcount) == 0)
			destroy = 1;
	}
	persona_unlock(persona);

	if (!destroy)
		return;

	persona_dbg("Destroying persona %s", persona_desc(persona, 0));

	/* release our credential reference */
	if (persona->pna_cred)
		kauth_cred_unref(&persona->pna_cred);

	/* remove it from the global list and decrement the count */
	lock_personas();
	if (persona_valid(persona)) {
		LIST_REMOVE(persona, pna_list);
		if (hw_atomic_add(&g_total_personas, -1) == UINT_MAX)
			panic("persona count underflow!\n");
		persona_mkinvalid(persona);
	}
	unlock_personas();

	assert(LIST_EMPTY(&persona->pna_members));
	memset(persona, 0, sizeof(*persona));
	zfree(persona_zone, persona);
}

uid_t persona_get_id(struct persona *persona)
{
	if (persona)
		return persona->pna_id;
	return PERSONA_ID_NONE;
}

struct persona *persona_lookup(uid_t id)
{
	struct persona *persona, *tmp;

	persona = NULL;

	/*
	 * simple, linear lookup for now: there shouldn't be too many
	 * of these in memory at any given time.
	 */
	lock_personas();
	LIST_FOREACH(tmp, &all_personas, pna_list) {
		persona_lock(tmp);
		if (tmp->pna_id == id && persona_valid(tmp)) {
			persona = persona_get_locked(tmp);
			persona_unlock(tmp);
			break;
		}
		persona_unlock(tmp);
	}
	unlock_personas();

	return persona;
}

int persona_find(const char *login, uid_t uid,
		 struct persona **persona, size_t *plen)
{
	struct persona *tmp;
	int match = 0;
	size_t found = 0;

	if (login)
		match++;
	if (uid != PERSONA_ID_NONE)
		match++;

	if (match == 0)
		return EINVAL;

	persona_dbg("Searching with %d parameters (l:\"%s\", u:%d)",
		    match, login, uid);

	lock_personas();
	LIST_FOREACH(tmp, &all_personas, pna_list) {
		int m = 0;
		persona_lock(tmp);
		if (login && strncmp(tmp->pna_login, login, sizeof(tmp->pna_login)) == 0)
			m++;
		if (uid != PERSONA_ID_NONE && uid == tmp->pna_id)
			m++;
		if (m == match) {
			if (persona && *plen > found)
				persona[found] = persona_get_locked(tmp);
			found++;
		}
#ifdef PERSONA_DEBUG
		if (m > 0)
			persona_dbg("ID:%d Matched %d/%d, found:%d, *plen:%d",
				    tmp->pna_id, m, match, (int)found, (int)*plen);
#endif
		persona_unlock(tmp);
	}
	unlock_personas();

	*plen = found;
	if (!found)
		return ESRCH;
	return 0;
}

struct persona *persona_proc_get(pid_t pid)
{
	struct persona *persona;
	proc_t p = proc_find(pid);

	if (!p)
		return NULL;

	proc_lock(p);
	persona = persona_get(p->p_persona);
	proc_unlock(p);

	proc_rele(p);

	return persona;
}

struct persona *current_persona_get(void)
{
	proc_t p = current_proc();
	struct persona *persona;

	proc_lock(p);
	persona = persona_get(p->p_persona);
	proc_unlock(p);

	return persona;
}

/**
 * inherit a persona from parent to child
 */
int persona_proc_inherit(proc_t child, proc_t parent)
{
	if (child->p_persona != NULL) {
		persona_dbg("proc_inherit: child already in persona: %s",
			    persona_desc(child->p_persona, 0));
		return -1;
	}

	/* no persona to inherit */
	if (parent->p_persona == NULL)
		return 0;

	return persona_proc_adopt(child, parent->p_persona, parent->p_ucred);
}

int persona_proc_adopt_id(proc_t p, uid_t id, kauth_cred_t auth_override)
{
	int ret;
	struct persona *persona;

	persona = persona_lookup(id);
	if (!persona)
		return ESRCH;

	ret = persona_proc_adopt(p, persona, auth_override);

	/* put the reference from the lookup() */
	persona_put(persona);

	return ret;
}


typedef enum e_persona_reset_op {
	PROC_REMOVE_PERSONA = 1,
	PROC_RESET_OLD_PERSONA = 2,
} persona_reset_op_t;

/*
 * internal cleanup routine for proc_set_cred_internal
 *
 */
static struct persona *proc_reset_persona_internal(proc_t p, persona_reset_op_t op,
						   struct persona *old_persona,
						   struct persona *new_persona)
{
#if (DEVELOPMENT || DEBUG)
	persona_lock_assert_held(new_persona);
#endif

	switch (op) {
	case PROC_REMOVE_PERSONA:
		old_persona = p->p_persona;
		/* fall through */
	case PROC_RESET_OLD_PERSONA:
		break;
	default:
		/* invalid arguments */
		return NULL;
	}

	/* unlock the new persona (locked on entry) */
	persona_unlock(new_persona);
	/* lock the old persona and the process */
	persona_lock(old_persona);
	proc_lock(p);

	switch (op) {
	case PROC_REMOVE_PERSONA:
		LIST_REMOVE(p, p_persona_list);
		p->p_persona = NULL;
		break;
	case PROC_RESET_OLD_PERSONA:
		p->p_persona = old_persona;
		LIST_INSERT_HEAD(&old_persona->pna_members, p, p_persona_list);
		break;
	}

	proc_unlock(p);
	persona_unlock(old_persona);

	/* re-lock the new persona */
	persona_lock(new_persona);
	return old_persona;
}

/*
 * Assumes persona is locked.
 * On success, takes a reference to 'persona' and returns the
 * previous persona the process had adopted. The caller is
 * responsible to release the reference.
 */
static struct persona *proc_set_cred_internal(proc_t p, struct persona *persona,
					      kauth_cred_t auth_override, int *rlim_error)
{
	struct persona *old_persona = NULL;
	kauth_cred_t my_cred, my_new_cred;
	uid_t old_uid, new_uid;
	int count;

	/*
	 * This operation must be done under the proc trans lock
	 * by the thread which took the trans lock!
	 */
	assert(((p->p_lflag & P_LINTRANSIT) == P_LINTRANSIT) &&
	       p->p_transholder == current_thread());
	assert(persona != NULL);

	/* no work to do if we "re-adopt" the same persona */
	if (p->p_persona == persona)
		return NULL;

	/*
	 * If p is in a persona, then we need to remove 'p' from the list of
	 * processes in that persona. To do this, we need to drop the lock
	 * held on the incoming (new) persona and lock the old one.
	 */
	if (p->p_persona) {
		old_persona = proc_reset_persona_internal(p, PROC_REMOVE_PERSONA,
							  NULL, persona);
	}

	if (auth_override)
		my_new_cred = auth_override;
	else
		my_new_cred = persona->pna_cred;

	if (!my_new_cred)
		panic("NULL credentials (persona:%p)", persona);

	*rlim_error = 0;

	kauth_cred_ref(my_new_cred);

	new_uid = persona->pna_id;

	/*
	 * Check to see if we will hit a proc rlimit by moving the process
	 * into the persona. If so, we'll bail early before actually moving
	 * the process or changing its credentials.
	 */
	if (new_uid != 0 &&
	    (rlim_t)chgproccnt(new_uid, 0) > p->p_rlimit[RLIMIT_NPROC].rlim_cur) {
		pna_err("PID:%d hit proc rlimit in new persona(%d): %s",
			p->p_pid, new_uid, persona_desc(persona, 1));
		*rlim_error = EACCES;
		(void)proc_reset_persona_internal(p, PROC_RESET_OLD_PERSONA,
						  old_persona, persona);
		kauth_cred_unref(&my_new_cred);
		return NULL;
	}

	/*
	 * Set the new credentials on the proc
	 */
set_proc_cred:
	my_cred = kauth_cred_proc_ref(p);
	persona_dbg("proc_adopt PID:%d, %s -> %s",
		    p->p_pid,
		    persona_desc(old_persona, 1),
		    persona_desc(persona, 1));

	old_uid = kauth_cred_getruid(my_cred);

	if (my_cred != my_new_cred) {
		kauth_cred_t old_cred = my_cred;

		proc_ucred_lock(p);
		/*
		 * We need to protect against a race where another thread
		 * also changed the credential after we took our
		 * reference.  If p_ucred has changed then we should
		 * restart this again with the new cred.
		 */
		if (p->p_ucred != my_cred) {
			proc_ucred_unlock(p);
			kauth_cred_unref(&my_cred);
			/* try again */
			goto set_proc_cred;
		}

		/* update the credential and take a ref for the proc */
		kauth_cred_ref(my_new_cred);
		p->p_ucred = my_new_cred;

		/* update cred on proc (and current thread) */
		mach_kauth_cred_uthread_update();
		PROC_UPDATE_CREDS_ONPROC(p);

		/* drop the proc's old ref on the credential */
		kauth_cred_unref(&old_cred);
		proc_ucred_unlock(p);
	}

	/* drop this function's reference to the old cred */
	kauth_cred_unref(&my_cred);

	/*
	 * Update the proc count.
	 * If the UIDs are the same, then there is no work to do.
	 */
	if (old_persona)
		old_uid = old_persona->pna_id;

	if (new_uid != old_uid) {
		count = chgproccnt(old_uid, -1);
		persona_dbg("Decrement %s:%d proc_count to: %d",
			    old_persona ? "Persona" : "UID", old_uid, count);

		/*
		 * Increment the proc count on the UID associated with
		 * the new persona. Enforce the resource limit just
		 * as in fork1()
		 */
		count = chgproccnt(new_uid, 1);
		persona_dbg("Increment Persona:%d (UID:%d) proc_count to: %d",
			    new_uid, kauth_cred_getuid(my_new_cred), count);
	}

	OSBitOrAtomic(P_ADOPTPERSONA, &p->p_flag);

	proc_lock(p);
	p->p_persona = persona_get_locked(persona);
	LIST_INSERT_HEAD(&persona->pna_members, p, p_persona_list);
	proc_unlock(p);

	kauth_cred_unref(&my_new_cred);

	return old_persona;
}

int persona_proc_adopt(proc_t p, struct persona *persona, kauth_cred_t auth_override)
{
	int error;
	struct persona *old_persona;
	struct session * sessp;

	if (!persona)
		return EINVAL;

	persona_dbg("%d adopting Persona %d (%s)", proc_pid(p),
		    persona->pna_id, persona_desc(persona, 0));

	persona_lock(persona);
	if (!persona->pna_cred || !persona_valid(persona)) {
		persona_dbg("Invalid persona (%s): NULL credentials!", persona_desc(persona, 1));
		persona_unlock(persona);
		return EINVAL;
	}

	/* the persona credentials can no longer be adjusted */
	persona->pna_cred_locked = 1;

	/*
	 * assume the persona: this may drop and re-acquire the persona lock!
	 */
	error = 0;
	old_persona = proc_set_cred_internal(p, persona, auth_override, &error);

	/* join the process group associated with the persona */
	if (persona->pna_pgid) {
		uid_t uid = kauth_cred_getuid(persona->pna_cred);
		persona_dbg(" PID:%d, pgid:%d%s",
			    p->p_pid, persona->pna_pgid,
			    persona->pna_pgid == uid ? ", new_session" : ".");
		enterpgrp(p, persona->pna_pgid, persona->pna_pgid == uid);
	}

	/* set the login name of the session */
	sessp = proc_session(p);
	if (sessp != SESSION_NULL) {
		session_lock(sessp);
		bcopy(persona->pna_login, sessp->s_login, MAXLOGNAME);
		session_unlock(sessp);
		session_rele(sessp);
	}

	persona_unlock(persona);

	set_security_token(p);

	/*
	 * Drop the reference to the old persona.
	 */
	if (old_persona)
		persona_put(old_persona);

	persona_dbg("%s", error == 0 ? "SUCCESS" : "FAILED");
	return error;
}

int persona_proc_drop(proc_t p)
{
	struct persona *persona = NULL;

	persona_dbg("PID:%d, %s -> <none>", p->p_pid, persona_desc(p->p_persona, 0));

	/*
	 * There are really no other credentials for us to assume,
	 * so we'll just continue running with the credentials
	 * we got from the persona.
	 */

	/*
	 * the locks must be taken in reverse order here, so
	 * we have to be careful not to cause deadlock
	 */
try_again:
	proc_lock(p);
	if (p->p_persona) {
		uid_t puid, ruid;
		if (!persona_try_lock(p->p_persona)) {
			proc_unlock(p);
			mutex_pause(0); /* back-off time */
			goto try_again;
		}
		persona = p->p_persona;
		LIST_REMOVE(p, p_persona_list);
		p->p_persona = NULL;

		ruid = kauth_cred_getruid(p->p_ucred);
		puid = kauth_cred_getuid(persona->pna_cred);
		proc_unlock(p);
		(void)chgproccnt(ruid, 1);
		(void)chgproccnt(puid, -1);
	} else {
		proc_unlock(p);
	}

	/*
	 * if the proc had a persona, then it is still locked here
	 * (preserving proper lock ordering)
	 */

	if (persona) {
		persona_unlock(persona);
		persona_put(persona);
	}

	return 0;
}

int persona_get_type(struct persona *persona)
{
	int type;

	if (!persona)
		return PERSONA_INVALID;

	persona_lock(persona);
	if (!persona_valid(persona)) {
		persona_unlock(persona);
		return PERSONA_INVALID;
	}
	type = persona->pna_type;
	persona_unlock(persona);

	return type;
}

int persona_set_cred(struct persona *persona, kauth_cred_t cred)
{
	int ret = 0;
	kauth_cred_t my_cred;
	if (!persona || !cred)
		return EINVAL;

	persona_lock(persona);
	if (!persona_valid(persona)) {
		ret = EINVAL;
		goto out_unlock;
	}
	if (persona->pna_cred_locked) {
		ret = EPERM;
		goto out_unlock;
	}

	/* create a new cred from the passed-in cred */
	my_cred = kauth_cred_create(cred);

	/* ensure that the UID matches the persona ID */
	my_cred = kauth_cred_setresuid(my_cred, persona->pna_id,
				       persona->pna_id, persona->pna_id,
				       KAUTH_UID_NONE);

	/* TODO: clear the saved GID?! */

	/* replace the persona's cred with the new one */
	if (persona->pna_cred)
		kauth_cred_unref(&persona->pna_cred);
	persona->pna_cred = my_cred;

out_unlock:
	persona_unlock(persona);
	return ret;
}

int persona_set_cred_from_proc(struct persona *persona, proc_t proc)
{
	int ret = 0;
	kauth_cred_t parent_cred, my_cred;
	if (!persona || !proc)
		return EINVAL;

	persona_lock(persona);
	if (!persona_valid(persona)) {
		ret = EINVAL;
		goto out_unlock;
	}
	if (persona->pna_cred_locked) {
		ret = EPERM;
		goto out_unlock;
	}

	parent_cred = kauth_cred_proc_ref(proc);

	/* TODO: clear the saved UID/GID! */

	/* create a new cred from the proc's cred */
	my_cred = kauth_cred_create(parent_cred);

	/* ensure that the UID matches the persona ID */
	my_cred = kauth_cred_setresuid(my_cred, persona->pna_id,
				       persona->pna_id, persona->pna_id,
				       KAUTH_UID_NONE);

	/* replace the persona's cred with the new one */
	if (persona->pna_cred)
		kauth_cred_unref(&persona->pna_cred);
	persona->pna_cred = my_cred;

	kauth_cred_unref(&parent_cred);

out_unlock:
	persona_unlock(persona);
	return ret;
}

kauth_cred_t persona_get_cred(struct persona *persona)
{
	kauth_cred_t cred = NULL;

	if (!persona)
		return NULL;

	persona_lock(persona);
	if (!persona_valid(persona))
		goto out_unlock;

	if (persona->pna_cred) {
		kauth_cred_ref(persona->pna_cred);
		cred = persona->pna_cred;
	}

out_unlock:
	persona_unlock(persona);

	return cred;
}

uid_t persona_get_uid(struct persona *persona)
{
	uid_t uid = UID_MAX;

	if (!persona || !persona->pna_cred)
		return UID_MAX;

	persona_lock(persona);
	if (persona_valid(persona)) {
		uid = kauth_cred_getuid(persona->pna_cred);
		assert(uid == persona->pna_id);
	}
	persona_unlock(persona);

	return uid;
}

int persona_set_gid(struct persona *persona, gid_t gid)
{
	int ret = 0;
	kauth_cred_t my_cred, new_cred;

	if (!persona || !persona->pna_cred)
		return EINVAL;

	persona_lock(persona);
	if (!persona_valid(persona)) {
		ret = EINVAL;
		goto out_unlock;
	}
	if (persona->pna_cred_locked) {
		ret = EPERM;
		goto out_unlock;
	}

	my_cred = persona->pna_cred;
	kauth_cred_ref(my_cred);
	new_cred = kauth_cred_setresgid(my_cred, gid, gid, gid);
	if (new_cred != my_cred)
		persona->pna_cred = new_cred;
	kauth_cred_unref(&my_cred);

out_unlock:
	persona_unlock(persona);
	return ret;
}

gid_t persona_get_gid(struct persona *persona)
{
	gid_t gid = GID_MAX;

	if (!persona || !persona->pna_cred)
		return GID_MAX;

	persona_lock(persona);
	if (persona_valid(persona))
		gid = kauth_cred_getgid(persona->pna_cred);
	persona_unlock(persona);

	return gid;
}

int persona_set_groups(struct persona *persona, gid_t *groups, int ngroups, uid_t gmuid)
{
	int ret = 0;
	kauth_cred_t my_cred, new_cred;

	if (!persona || !persona->pna_cred)
		return EINVAL;
	if (ngroups > NGROUPS_MAX)
		return EINVAL;

	persona_lock(persona);
	if (!persona_valid(persona)) {
		ret = EINVAL;
		goto out_unlock;
	}
	if (persona->pna_cred_locked) {
		ret = EPERM;
		goto out_unlock;
	}

	my_cred = persona->pna_cred;
	kauth_cred_ref(my_cred);
	new_cred = kauth_cred_setgroups(my_cred, groups, ngroups, gmuid);
	if (new_cred != my_cred)
		persona->pna_cred = new_cred;
	kauth_cred_unref(&my_cred);

out_unlock:
	persona_unlock(persona);
	return ret;
}

int persona_get_groups(struct persona *persona, int *ngroups, gid_t *groups, int groups_sz)
{
	int ret = EINVAL;
	if (!persona || !persona->pna_cred || !groups || !ngroups)
		return EINVAL;

	*ngroups = groups_sz;

	persona_lock(persona);
	if (persona_valid(persona)) {
		kauth_cred_getgroups(persona->pna_cred, groups, ngroups);
		ret = 0;
	}
	persona_unlock(persona);

	return ret;
}

uid_t persona_get_gmuid(struct persona *persona)
{
	uid_t gmuid = KAUTH_UID_NONE;

	if (!persona || !persona->pna_cred)
		return gmuid;

	persona_lock(persona);
	if (!persona_valid(persona))
		goto out_unlock;

	posix_cred_t pcred = posix_cred_get(persona->pna_cred);
	gmuid = pcred->cr_gmuid;

out_unlock:
	persona_unlock(persona);
	return gmuid;
}

int persona_get_login(struct persona *persona, char login[MAXLOGNAME+1])
{
	int ret = EINVAL;
	if (!persona || !persona->pna_cred)
		return EINVAL;

	persona_lock(persona);
	if (!persona_valid(persona))
		goto out_unlock;

	strlcpy(login, persona->pna_login, MAXLOGNAME);
	ret = 0;

out_unlock:
	persona_unlock(persona);
	login[MAXLOGNAME] = 0;

	return ret;
}

#else /* !CONFIG_PERSONAS */

/*
 * symbol exports for kext compatibility
 */

uid_t persona_get_id(__unused struct persona *persona)
{
	return PERSONA_ID_NONE;
}

int persona_get_type(__unused struct persona *persona)
{
	return PERSONA_INVALID;
}

kauth_cred_t persona_get_cred(__unused struct persona *persona)
{
	return NULL;
}

struct persona *persona_lookup(__unused uid_t id)
{
	return NULL;
}

int persona_find(__unused const char *login,
		 __unused uid_t uid,
		 __unused struct persona **persona,
		 __unused size_t *plen)
{
	return ENOTSUP;
}

struct persona *current_persona_get(void)
{
	return NULL;
}

struct persona *persona_get(struct persona *persona)
{
	return persona;
}

void persona_put(__unused struct persona *persona)
{
	return;
}
#endif
