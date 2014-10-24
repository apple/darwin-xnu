/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
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
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/priv.h>

#include <sys/sysproto.h>
#include <sys/proc_uuid_policy.h>

#include <kern/locks.h>
#include <uuid/uuid.h>

#include <string.h>
#include <libkern/OSAtomic.h>

#define PROC_UUID_POLICY_DEBUG 0

#if PROC_UUID_POLICY_DEBUG
#define dprintf(...) printf(__VA_ARGS__)
#else
#define dprintf(...) do { } while(0)
#endif

static lck_grp_attr_t  *proc_uuid_policy_subsys_lck_grp_attr;
static lck_grp_t       *proc_uuid_policy_subsys_lck_grp;
static lck_attr_t      *proc_uuid_policy_subsys_lck_attr;
static lck_mtx_t        proc_uuid_policy_subsys_mutex;

#define PROC_UUID_POLICY_SUBSYS_LOCK() lck_mtx_lock(&proc_uuid_policy_subsys_mutex)
#define PROC_UUID_POLICY_SUBSYS_UNLOCK() lck_mtx_unlock(&proc_uuid_policy_subsys_mutex)

#define PROC_UUID_POLICY_HASH_SIZE 64
u_long proc_uuid_policy_hash_mask;

/* Assume first byte of UUIDs are evenly distributed */
#define UUIDHASH(uuid) (&proc_uuid_policy_hashtbl[uuid[0] & proc_uuid_policy_hash_mask])
static LIST_HEAD(proc_uuid_policy_hashhead, proc_uuid_policy_entry) *proc_uuid_policy_hashtbl;

/*
 * On modification, invalidate cached lookups by bumping the generation count.
 * Other calls will need to take the slowpath of taking
 * the subsystem lock.
 */
static volatile int32_t proc_uuid_policy_table_gencount;
#define BUMP_PROC_UUID_POLICY_GENERATION_COUNT() do {									\
		if (OSIncrementAtomic(&proc_uuid_policy_table_gencount) == (INT32_MAX - 1)) {	\
			proc_uuid_policy_table_gencount = 1;										\
		}																				\
	} while (0)

#define MAX_PROC_UUID_POLICY_COUNT 10240
static volatile int32_t proc_uuid_policy_count;

struct proc_uuid_policy_entry {
	LIST_ENTRY(proc_uuid_policy_entry) entries;
	uuid_t		uuid;	/* Mach-O executable UUID */
	uint32_t	flags;	/* policy flag for that UUID */
};

static int
proc_uuid_policy_insert(uuid_t uuid, uint32_t flags);

static struct proc_uuid_policy_entry *
proc_uuid_policy_remove_locked(uuid_t uuid, uint32_t flags, int *should_delete);

static int
proc_uuid_policy_remove(uuid_t uuid, uint32_t flags);

static struct proc_uuid_policy_entry *
proc_uuid_policy_lookup_locked(uuid_t uuid);

static int
proc_uuid_policy_clear(uint32_t flags);

void
proc_uuid_policy_init(void)
{
	proc_uuid_policy_subsys_lck_grp_attr = lck_grp_attr_alloc_init();
	proc_uuid_policy_subsys_lck_grp = lck_grp_alloc_init("proc_uuid_policy_subsys_lock", proc_uuid_policy_subsys_lck_grp_attr);
	proc_uuid_policy_subsys_lck_attr = lck_attr_alloc_init();
	lck_mtx_init(&proc_uuid_policy_subsys_mutex, proc_uuid_policy_subsys_lck_grp, proc_uuid_policy_subsys_lck_attr);

	proc_uuid_policy_hashtbl = hashinit(PROC_UUID_POLICY_HASH_SIZE, M_PROC_UUID_POLICY, &proc_uuid_policy_hash_mask);
	proc_uuid_policy_table_gencount = 1;
	proc_uuid_policy_count = 0;
}

static int
proc_uuid_policy_insert(uuid_t uuid, uint32_t flags)
{
	struct proc_uuid_policy_entry *entry, *foundentry = NULL;
	int error;

#if PROC_UUID_POLICY_DEBUG
	uuid_string_t uuidstr;
	uuid_unparse(uuid, uuidstr);
#endif

	if (uuid_is_null(uuid))
		return EINVAL;

	MALLOC(entry, struct proc_uuid_policy_entry *, sizeof(*entry), M_PROC_UUID_POLICY, M_WAITOK|M_ZERO);

	memcpy(entry->uuid, uuid, sizeof(uuid_t));
	entry->flags = flags;

	PROC_UUID_POLICY_SUBSYS_LOCK();

	foundentry = proc_uuid_policy_lookup_locked(uuid);
	if (foundentry != NULL) {
		/* The UUID is already in the list. Update the flags. */
		foundentry->flags |= flags;
		error = 0;
		FREE(entry, M_PROC_UUID_POLICY);
		entry = NULL;
		BUMP_PROC_UUID_POLICY_GENERATION_COUNT();
	} else {
		/* Our target UUID is not in the list, insert it now */
		if (proc_uuid_policy_count < MAX_PROC_UUID_POLICY_COUNT) {
			LIST_INSERT_HEAD(UUIDHASH(uuid), entry, entries);
			proc_uuid_policy_count++;
			error = 0;
			BUMP_PROC_UUID_POLICY_GENERATION_COUNT();
		} else {
			error = ENOMEM;
		}
	}

	PROC_UUID_POLICY_SUBSYS_UNLOCK();

	if (error) {
		FREE(entry, M_PROC_UUID_POLICY);
		dprintf("Failed to insert proc uuid policy (%s,0x%08x), table full\n", uuidstr, flags);
	} else {
		dprintf("Inserted proc uuid policy (%s,0x%08x)\n", uuidstr, flags);
	}

	return error;
}

static struct proc_uuid_policy_entry *
proc_uuid_policy_remove_locked(uuid_t uuid, uint32_t flags, int *should_delete)
{
	struct proc_uuid_policy_entry *foundentry = NULL;
	if (should_delete) {
		*should_delete = 0;
	}
	
	foundentry = proc_uuid_policy_lookup_locked(uuid);
	if (foundentry) {
		if (foundentry->flags == flags) {
			LIST_REMOVE(foundentry, entries);
			proc_uuid_policy_count--;
			if (should_delete) {
				*should_delete = 1;
			}
		} else {
			foundentry->flags &= ~flags;
		}
	}
	
	return foundentry;
}

static int
proc_uuid_policy_remove(uuid_t uuid, uint32_t flags)
{
	struct proc_uuid_policy_entry *delentry = NULL;
	int error;
	int should_delete = 0;

#if PROC_UUID_POLICY_DEBUG
	uuid_string_t uuidstr;
	uuid_unparse(uuid, uuidstr);
#endif

	if (uuid_is_null(uuid))
		return EINVAL;

	PROC_UUID_POLICY_SUBSYS_LOCK();

	delentry = proc_uuid_policy_remove_locked(uuid, flags, &should_delete);

	if (delentry) {
		error = 0;
		BUMP_PROC_UUID_POLICY_GENERATION_COUNT();
	} else {
		error = ENOENT;
	}

	PROC_UUID_POLICY_SUBSYS_UNLOCK();

	/* If we had found a pre-existing entry, deallocate its memory now */
	if (delentry && should_delete) {
		FREE(delentry, M_PROC_UUID_POLICY);
	}

	if (error) {
		dprintf("Failed to remove proc uuid policy (%s), entry not present\n", uuidstr);
	} else {
		dprintf("Removed proc uuid policy (%s)\n", uuidstr);
	}

	return error;
}

static struct proc_uuid_policy_entry *
proc_uuid_policy_lookup_locked(uuid_t uuid)
{
	struct proc_uuid_policy_entry *tmpentry, *searchentry, *foundentry = NULL;
	
	LIST_FOREACH_SAFE(searchentry, UUIDHASH(uuid), entries, tmpentry) {
		if (0 == memcmp(searchentry->uuid, uuid, sizeof(uuid_t))) {
			foundentry = searchentry;
			break;
		}
	}
	
	return foundentry;
}

int
proc_uuid_policy_lookup(uuid_t uuid, uint32_t *flags, int32_t *gencount)
{
	struct proc_uuid_policy_entry *foundentry = NULL;
	int error;

#if PROC_UUID_POLICY_DEBUG
	uuid_string_t uuidstr;
	uuid_unparse(uuid, uuidstr);
#endif

	if (uuid_is_null(uuid) || !flags || !gencount)
		return EINVAL;

	if (*gencount == proc_uuid_policy_table_gencount) {
		/*
		 * Generation count hasn't changed, so old flags should be valid.
		 * We avoid taking the lock here by assuming any concurrent modifications
		 * to the table will invalidate the generation count.
		 */
		return 0;
	}

	PROC_UUID_POLICY_SUBSYS_LOCK();

	foundentry = proc_uuid_policy_lookup_locked(uuid);

	if (foundentry) {
		*flags = foundentry->flags;
		*gencount = proc_uuid_policy_table_gencount;
		error = 0;
	} else {
		error = ENOENT;
	}

	PROC_UUID_POLICY_SUBSYS_UNLOCK();

	if (error == 0) {
		dprintf("Looked up proc uuid policy (%s,0x%08x)\n", uuidstr, *flags);
	}

	return error;
}

static int
proc_uuid_policy_clear(uint32_t flags)
{
	struct proc_uuid_policy_entry *tmpentry, *searchentry;
	struct proc_uuid_policy_hashhead deletehead = LIST_HEAD_INITIALIZER(deletehead);
	unsigned long hashslot;
	
	/* If clear call includes no flags, infer 'No Cellular' flag */
	if (flags == PROC_UUID_POLICY_FLAGS_NONE) {
		flags = PROC_UUID_NO_CELLULAR;
	}

	PROC_UUID_POLICY_SUBSYS_LOCK();

	if (proc_uuid_policy_count > 0) {

		for (hashslot=0; hashslot <= proc_uuid_policy_hash_mask; hashslot++) {
			struct proc_uuid_policy_hashhead *headp = &proc_uuid_policy_hashtbl[hashslot];
			
			LIST_FOREACH_SAFE(searchentry, headp, entries, tmpentry) {
				if ((searchentry->flags & flags) == searchentry->flags) {
					/* We are clearing all flags for this entry, move entry to our delete list */
					LIST_REMOVE(searchentry, entries);
					proc_uuid_policy_count--;
					LIST_INSERT_HEAD(&deletehead, searchentry, entries);
				} else {
					searchentry->flags &= ~flags;
				}
			}
		}

		BUMP_PROC_UUID_POLICY_GENERATION_COUNT();
	}

	PROC_UUID_POLICY_SUBSYS_UNLOCK();

	/* Memory deallocation happens after the hash lock is dropped */
	LIST_FOREACH_SAFE(searchentry, &deletehead, entries, tmpentry) {
		LIST_REMOVE(searchentry, entries);
		FREE(searchentry, M_PROC_UUID_POLICY);
	}

	dprintf("Clearing proc uuid policy table\n");
	
	return 0;
}

int proc_uuid_policy_kernel(uint32_t operation, uuid_t uuid, uint32_t flags)
{
	int error = 0;
	
	switch (operation) {
		case PROC_UUID_POLICY_OPERATION_CLEAR:
			error = proc_uuid_policy_clear(flags);
			break;
			
		case PROC_UUID_POLICY_OPERATION_ADD:
			error = proc_uuid_policy_insert(uuid, flags);
			break;
			
		case PROC_UUID_POLICY_OPERATION_REMOVE:
			error = proc_uuid_policy_remove(uuid, flags);
			break;
			
		default:
			error = EINVAL;
			break;
	}
	
	return error;
}

int proc_uuid_policy(struct proc *p __unused, struct proc_uuid_policy_args *uap, int32_t *retval __unused)
{
	int error = 0;
	uuid_t uuid;

	/* Need privilege for policy changes */
	error = priv_check_cred(kauth_cred_get(), PRIV_PROC_UUID_POLICY, 0);
	if (error) {
		dprintf("%s failed privilege check for proc_uuid_policy: %d\n", p->p_comm, error);
		return (error);
	} else {
		dprintf("%s succeeded privilege check for proc_uuid_policy\n", p->p_comm);
	}
	
	if (uap->uuid) {
		if (uap->uuidlen != sizeof(uuid_t))
			return ERANGE;
		
		error = copyin(uap->uuid, uuid, sizeof(uuid_t));
		if (error)
			return error;
	}
	
	return proc_uuid_policy_kernel(uap->operation, uuid, uap->flags);
}
