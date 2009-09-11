/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * Implementation of SVID semaphores
 *
 * Author:  Daniel Boulet
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 */
/*
 * John Bellardo modified the implementation for Darwin. 12/2000
 */
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 * Copyright (c) 2005-2006 SPARTA, Inc.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/sem_internal.h>
#include <sys/malloc.h>
#include <mach/mach_types.h>

#include <sys/filedesc.h>
#include <sys/file_internal.h>
#include <sys/sysctl.h>
#include <sys/ipcs.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#include <security/audit/audit.h>

#if SYSV_SEM


/* Uncomment this line to see the debugging output */
/* #define SEM_DEBUG */

/* Uncomment this line to see MAC debugging output. */
/* #define	MAC_DEBUG */
#if CONFIG_MACF_DEBUG
#define	MPRINTF(a)	printf(a)
#else
#define	MPRINTF(a)
#endif

#define M_SYSVSEM	M_TEMP


/* Hard system limits to avoid resource starvation / DOS attacks.
 * These are not needed if we can make the semaphore pages swappable.
 */
static struct seminfo limitseminfo = {
	SEMMAP,        /* # of entries in semaphore map */
	SEMMNI,        /* # of semaphore identifiers */
	SEMMNS,        /* # of semaphores in system */
	SEMMNU,        /* # of undo structures in system */
	SEMMSL,        /* max # of semaphores per id */
	SEMOPM,        /* max # of operations per semop call */
	SEMUME,        /* max # of undo entries per process */
	SEMUSZ,        /* size in bytes of undo structure */
	SEMVMX,        /* semaphore maximum value */
	SEMAEM         /* adjust on exit max value */
};

/* Current system allocations.  We use this structure to track how many
 * resources we have allocated so far.  This way we can set large hard limits
 * and not allocate the memory for them up front.
 */
struct seminfo seminfo = {
	SEMMAP,	/* Unused, # of entries in semaphore map */
	0,	/* # of semaphore identifiers */
	0,	/* # of semaphores in system */
	0,	/* # of undo entries in system */
	SEMMSL,	/* max # of semaphores per id */
	SEMOPM,	/* max # of operations per semop call */
	SEMUME,	/* max # of undo entries per process */
	SEMUSZ,	/* size in bytes of undo structure */
	SEMVMX,	/* semaphore maximum value */
	SEMAEM	/* adjust on exit max value */
};


static int semu_alloc(struct proc *p);
static int semundo_adjust(struct proc *p, int *supidx, 
		int semid, int semnum, int adjval);
static void semundo_clear(int semid, int semnum);

/* XXX casting to (sy_call_t *) is bogus, as usual. */
static sy_call_t *semcalls[] = {
	(sy_call_t *)semctl, (sy_call_t *)semget,
	(sy_call_t *)semop
};

static int		semtot = 0;		/* # of used semaphores */
struct semid_kernel	*sema = NULL;		/* semaphore id pool */
struct sem		*sem_pool =  NULL;	/* semaphore pool */
static int	 	semu_list_idx = -1;	/* active undo structures */
struct sem_undo		*semu = NULL;		/* semaphore undo pool */


void sysv_sem_lock_init(void);
static lck_grp_t       *sysv_sem_subsys_lck_grp;
static lck_grp_attr_t  *sysv_sem_subsys_lck_grp_attr;
static lck_attr_t      *sysv_sem_subsys_lck_attr;
static lck_mtx_t        sysv_sem_subsys_mutex;

#define SYSV_SEM_SUBSYS_LOCK() lck_mtx_lock(&sysv_sem_subsys_mutex)
#define SYSV_SEM_SUBSYS_UNLOCK() lck_mtx_unlock(&sysv_sem_subsys_mutex)


__private_extern__ void
sysv_sem_lock_init( void )
{

    sysv_sem_subsys_lck_grp_attr = lck_grp_attr_alloc_init();

    sysv_sem_subsys_lck_grp = lck_grp_alloc_init("sysv_sem_subsys_lock", sysv_sem_subsys_lck_grp_attr);

    sysv_sem_subsys_lck_attr = lck_attr_alloc_init();
    lck_mtx_init(&sysv_sem_subsys_mutex, sysv_sem_subsys_lck_grp, sysv_sem_subsys_lck_attr);
}

static __inline__ user_time_t
sysv_semtime(void)
{
	struct timeval	tv;
	microtime(&tv);
	return (tv.tv_sec);
}

/*
 * XXX conversion of internal user_time_t to external tume_t loses
 * XXX precision; not an issue for us now, since we are only ever
 * XXX setting 32 bits worth of time into it.
 *
 * pad field contents are not moved correspondingly; contents will be lost
 *
 * NOTE: Source and target may *NOT* overlap! (target is smaller)
 */
static void
semid_ds_kernelto32(struct user_semid_ds *in, struct user32_semid_ds *out)
{
	out->sem_perm = in->sem_perm;
	out->sem_base = CAST_DOWN_EXPLICIT(__int32_t,in->sem_base);
	out->sem_nsems = in->sem_nsems;
	out->sem_otime = in->sem_otime;		/* XXX loses precision */
	out->sem_ctime = in->sem_ctime;		/* XXX loses precision */
}

static void
semid_ds_kernelto64(struct user_semid_ds *in, struct user64_semid_ds *out)
{
	out->sem_perm = in->sem_perm;
	out->sem_base = CAST_DOWN_EXPLICIT(__int32_t,in->sem_base);
	out->sem_nsems = in->sem_nsems;
	out->sem_otime = in->sem_otime;		/* XXX loses precision */
	out->sem_ctime = in->sem_ctime;		/* XXX loses precision */
}

/*
 * pad field contents are not moved correspondingly; contents will be lost
 *
 * NOTE: Source and target may are permitted to overlap! (source is smaller);
 * this works because we copy fields in order from the end of the struct to
 * the beginning.
 *
 * XXX use CAST_USER_ADDR_T() for lack of a CAST_USER_TIME_T(); net effect
 * XXX is the same.
 */
static void
semid_ds_32tokernel(struct user32_semid_ds *in, struct user_semid_ds *out)
{
	out->sem_ctime = in->sem_ctime;
	out->sem_otime = in->sem_otime;
	out->sem_nsems = in->sem_nsems;
	out->sem_base = (void *)(uintptr_t)in->sem_base;
	out->sem_perm = in->sem_perm;
}

static void
semid_ds_64tokernel(struct user64_semid_ds *in, struct user_semid_ds *out)
{
	out->sem_ctime = in->sem_ctime;
	out->sem_otime = in->sem_otime;
	out->sem_nsems = in->sem_nsems;
	out->sem_base = (void *)(uintptr_t)in->sem_base;
	out->sem_perm = in->sem_perm;
}


/*
 * semsys
 *
 * Entry point for all SEM calls: semctl, semget, semop
 *
 * Parameters:	p	Process requesting the call
 * 		uap	User argument descriptor (see below)
 * 		retval	Return value of the selected sem call
 *
 * Indirect parameters:	uap->which	sem call to invoke (index in array of sem calls)
 * 			uap->a2		User argument descriptor
 *                 
 * Returns:	0	Success
 *		!0	Not success
 *
 * Implicit returns: retval	Return value of the selected sem call
 *
 * DEPRECATED:  This interface should not be used to call the other SEM
 * 		functions (semctl, semget, semop). The correct usage is
 * 		to call the other SEM functions directly.
 *
 */
int
semsys(struct proc *p, struct semsys_args *uap, int32_t *retval)
{

	/* The individual calls handling the locking now */

	if (uap->which >= sizeof(semcalls)/sizeof(semcalls[0]))
		return (EINVAL);
	return ((*semcalls[uap->which])(p, &uap->a2, retval));
}

/*
 * Expand the semu array to the given capacity.  If the expansion fails
 * return 0, otherwise return 1.
 *
 * Assumes we already have the subsystem lock.
 */
static int
grow_semu_array(int newSize)
{
	register int i;
	register struct sem_undo *newSemu;

	if (newSize <= seminfo.semmnu)
		return 1;
	if (newSize > limitseminfo.semmnu) /* enforce hard limit */
	{
#ifdef SEM_DEBUG
		printf("undo structure hard limit of %d reached, requested %d\n",
			limitseminfo.semmnu, newSize);
#endif
		return 0;
	}
	newSize = (newSize/SEMMNU_INC + 1) * SEMMNU_INC;
	newSize = newSize > limitseminfo.semmnu ? limitseminfo.semmnu : newSize;

#ifdef SEM_DEBUG
	printf("growing semu[] from %d to %d\n", seminfo.semmnu, newSize);
#endif
	MALLOC(newSemu, struct sem_undo *, sizeof (struct sem_undo) * newSize,
	       M_SYSVSEM, M_WAITOK | M_ZERO);
	if (NULL == newSemu)
	{
#ifdef SEM_DEBUG
		printf("allocation failed.  no changes made.\n");
#endif
		return 0;
	}

       	/* copy the old data to the new array */
	for (i = 0; i < seminfo.semmnu; i++)
	{
		newSemu[i] = semu[i];
	}
	/*
	 * The new elements (from newSemu[i] to newSemu[newSize-1]) have their
	 * "un_proc" set to 0 (i.e. NULL) by the M_ZERO flag to MALLOC() above,
	 * so they're already marked as "not in use".
	 */

	/* Clean up the old array */
	if (semu)
		FREE(semu, M_SYSVSEM);

	semu = newSemu;
	seminfo.semmnu = newSize;
#ifdef SEM_DEBUG
	printf("expansion successful\n");
#endif
	return 1;
}

/*
 * Expand the sema array to the given capacity.  If the expansion fails
 * we return 0, otherwise we return 1.
 *
 * Assumes we already have the subsystem lock.
 */
static int
grow_sema_array(int newSize)
{
	register struct semid_kernel *newSema;
	register int i;

	if (newSize <= seminfo.semmni)
		return 0;
	if (newSize > limitseminfo.semmni) /* enforce hard limit */
	{
#ifdef SEM_DEBUG
		printf("identifier hard limit of %d reached, requested %d\n",
			limitseminfo.semmni, newSize);
#endif
		return 0;
	}
	newSize = (newSize/SEMMNI_INC + 1) * SEMMNI_INC;
	newSize = newSize > limitseminfo.semmni ? limitseminfo.semmni : newSize;

#ifdef SEM_DEBUG
	printf("growing sema[] from %d to %d\n", seminfo.semmni, newSize);
#endif
	MALLOC(newSema, struct semid_kernel *,
	       sizeof (struct semid_kernel) * newSize,
	       M_SYSVSEM, M_WAITOK | M_ZERO);
	if (NULL == newSema)
	{
#ifdef SEM_DEBUG
		printf("allocation failed.  no changes made.\n");
#endif
		return 0;
	}

	/* copy over the old ids */
	for (i = 0; i < seminfo.semmni; i++)
	{
		newSema[i] = sema[i];
		/* This is a hack.  What we really want to be able to
		 * do is change the value a process is waiting on
		 * without waking it up, but I don't know how to do
		 * this with the existing code, so we wake up the
		 * process and let it do a lot of work to determine the
		 * semaphore set is really not available yet, and then
		 * sleep on the correct, reallocated semid_kernel pointer.
		 */
		if (sema[i].u.sem_perm.mode & SEM_ALLOC)
			wakeup((caddr_t)&sema[i]);
	}

#if CONFIG_MACF
	for (i = seminfo.semmni; i < newSize; i++)
	{
		mac_sysvsem_label_init(&newSema[i]);
	}
#endif
	
	/*
	 * The new elements (from newSema[i] to newSema[newSize-1]) have their
	 * "sem_base" and "sem_perm.mode" set to 0 (i.e. NULL) by the M_ZERO
	 * flag to MALLOC() above, so they're already marked as "not in use".
	 */

	/* Clean up the old array */
	if (sema)
		FREE(sema, M_SYSVSEM);

	sema = newSema;
	seminfo.semmni = newSize;
#ifdef SEM_DEBUG
	printf("expansion successful\n");
#endif
	return 1;
}

/*
 * Expand the sem_pool array to the given capacity.  If the expansion fails
 * we return 0 (fail), otherwise we return 1 (success).
 *
 * Assumes we already hold the subsystem lock.
 */
static int
grow_sem_pool(int new_pool_size)
{
	struct sem *new_sem_pool = NULL;
	struct sem *sem_free;
	int i;

	if (new_pool_size < semtot)
		return 0;
	/* enforce hard limit */
	if (new_pool_size > limitseminfo.semmns) {
#ifdef SEM_DEBUG
		printf("semaphore hard limit of %d reached, requested %d\n",
			limitseminfo.semmns, new_pool_size);
#endif
		return 0;
	}

	new_pool_size = (new_pool_size/SEMMNS_INC + 1) * SEMMNS_INC;
	new_pool_size = new_pool_size > limitseminfo.semmns ? limitseminfo.semmns : new_pool_size;

#ifdef SEM_DEBUG
	printf("growing sem_pool array from %d to %d\n", seminfo.semmns, new_pool_size);
#endif
	MALLOC(new_sem_pool, struct sem *, sizeof (struct sem) * new_pool_size,
	       M_SYSVSEM, M_WAITOK | M_ZERO);
	if (NULL == new_sem_pool) {
#ifdef SEM_DEBUG
		printf("allocation failed.  no changes made.\n");
#endif
		return 0;
	}

	/* We have our new memory, now copy the old contents over */
	if (sem_pool)
		for(i = 0; i < seminfo.semmns; i++)
			new_sem_pool[i] = sem_pool[i];

	/* Update our id structures to point to the new semaphores */
	for(i = 0; i < seminfo.semmni; i++) {
		if (sema[i].u.sem_perm.mode & SEM_ALLOC)  /* ID in use */
			sema[i].u.sem_base += (new_sem_pool - sem_pool);
	}

	sem_free = sem_pool;
	sem_pool = new_sem_pool;

	/* clean up the old array */
	if (sem_free != NULL)
		FREE(sem_free, M_SYSVSEM);

	seminfo.semmns = new_pool_size;
#ifdef SEM_DEBUG
	printf("expansion complete\n");
#endif
	return 1;
}

/*
 * Allocate a new sem_undo structure for a process
 * (returns ptr to structure or NULL if no more room)
 *
 * Assumes we already hold the subsystem lock.
 */

static int
semu_alloc(struct proc *p)
{
	register int i;
	register struct sem_undo *suptr;
	int *supidx;
	int attempt;

	/*
	 * Try twice to allocate something.
	 * (we'll purge any empty structures after the first pass so
	 * two passes are always enough)
	 */

	for (attempt = 0; attempt < 2; attempt++) {
		/*
		 * Look for a free structure.
		 * Fill it in and return it if we find one.
		 */

		for (i = 0; i < seminfo.semmnu; i++) {
			suptr = SEMU(i);
			if (suptr->un_proc == NULL) {
				suptr->un_next_idx = semu_list_idx;
				semu_list_idx = i;
				suptr->un_cnt = 0;
				suptr->un_ent = NULL;
				suptr->un_proc = p;
				return i;
			}
		}

		/*
		 * We didn't find a free one, if this is the first attempt
		 * then try to free some structures.
		 */

		if (attempt == 0) {
			/* All the structures are in use - try to free some */
			int did_something = 0;

			supidx = &semu_list_idx;
			while (*supidx != -1) {
				suptr = SEMU(*supidx);
				if (suptr->un_cnt == 0)  {
					suptr->un_proc = NULL;
					*supidx = suptr->un_next_idx;
					did_something = 1;
				} else
					supidx = &(suptr->un_next_idx);
			}

			/* If we didn't free anything. Try expanding
			 * the semu[] array.  If that doesn't work
			 * then fail.  We expand last to get the
			 * most reuse out of existing resources.
			 */
			if (!did_something)
				if (!grow_semu_array(seminfo.semmnu + 1))
					return -1;
		} else {
			/*
			 * The second pass failed even though we freed
			 * something after the first pass!
			 * This is IMPOSSIBLE!
			 */
			panic("semu_alloc - second attempt failed");
		}
	}
	return -1;
}

/*
 * Adjust a particular entry for a particular proc
 *
 * Assumes we already hold the subsystem lock.
 */
static int
semundo_adjust(struct proc *p, int *supidx, int semid,
	int semnum, int adjval)
{
	register struct sem_undo *suptr;
	int suidx;
	register struct undo *sueptr, **suepptr, *new_sueptr;
	int i;

	/*
	 * Look for and remember the sem_undo if the caller doesn't provide it
	 */

	suidx = *supidx;
	if (suidx == -1) {
		for (suidx = semu_list_idx; suidx != -1;
		    suidx = suptr->un_next_idx) {
			suptr = SEMU(suidx);
			if (suptr->un_proc == p) {
				*supidx = suidx;
				break;
			}
		}
		if (suidx == -1) {
			if (adjval == 0)
				return(0);
			suidx = semu_alloc(p);
			if (suidx == -1)
				return(ENOSPC);
			*supidx = suidx;
		}
	}

	/*
	 * Look for the requested entry and adjust it (delete if adjval becomes
	 * 0).
	 */
	suptr = SEMU(suidx);
	new_sueptr = NULL;
	for (i = 0, suepptr = &suptr->un_ent, sueptr = suptr->un_ent;
	     i < suptr->un_cnt;
	     i++, suepptr = &sueptr->une_next, sueptr = sueptr->une_next) {
		if (sueptr->une_id != semid || sueptr->une_num != semnum)
			continue;
		if (adjval == 0)
			sueptr->une_adjval = 0;
		else
			sueptr->une_adjval += adjval;
		if (sueptr->une_adjval == 0) {
			suptr->un_cnt--;
			*suepptr = sueptr->une_next;
			FREE(sueptr, M_SYSVSEM);
			sueptr = NULL;
		}
		return 0;
	}

	/* Didn't find the right entry - create it */
	if (adjval == 0) {
		/* no adjustment: no need for a new entry */
		return 0;
	}

	if (suptr->un_cnt == limitseminfo.semume) {
		/* reached the limit number of semaphore undo entries */
		return EINVAL;
	}

	/* allocate a new semaphore undo entry */
	MALLOC(new_sueptr, struct undo *, sizeof (struct undo),
	       M_SYSVSEM, M_WAITOK);
	if (new_sueptr == NULL) {
		return ENOMEM;
	}

	/* fill in the new semaphore undo entry */
	new_sueptr->une_next = suptr->un_ent;
	suptr->un_ent = new_sueptr;
	suptr->un_cnt++;
	new_sueptr->une_adjval = adjval;
	new_sueptr->une_id = semid;
	new_sueptr->une_num = semnum;

	return 0;
}

/* Assumes we already hold the subsystem lock.
 */
static void
semundo_clear(int semid, int semnum)
{
	struct sem_undo *suptr;
	int suidx;

	for (suidx = semu_list_idx; suidx != -1; suidx = suptr->un_next_idx) {
		struct undo *sueptr;
		struct undo **suepptr;
		int i = 0;

		suptr = SEMU(suidx);
		sueptr = suptr->un_ent;
		suepptr = &suptr->un_ent;
		while (i < suptr->un_cnt) {
			if (sueptr->une_id == semid) {
				if (semnum == -1 || sueptr->une_num == semnum) {
					suptr->un_cnt--;
					*suepptr = sueptr->une_next;
					FREE(sueptr, M_SYSVSEM);
					sueptr = *suepptr;
					continue;
				}
				if (semnum != -1)
					break;
			}
			i++;
			suepptr = &sueptr->une_next;
			sueptr = sueptr->une_next;
		}
	}
}

/*
 * Note that the user-mode half of this passes a union coerced to a
 * user_addr_t.  The union contains either an int or a pointer, and
 * so we have to coerce it back, variant on whether the calling
 * process is 64 bit or not.  The coercion works for the 'val' element
 * because the alignment is the same in user and kernel space.
 */
int
semctl(struct proc *p, struct semctl_args *uap, int32_t *retval)
{
	int semid = uap->semid;
	int semnum = uap->semnum;
	int cmd = uap->cmd;
	user_semun_t user_arg = (user_semun_t)uap->arg;
	kauth_cred_t cred = kauth_cred_get();
	int i, rval, eval;
	struct user_semid_ds sbuf;
	struct semid_kernel *semakptr;
	

	AUDIT_ARG(svipc_cmd, cmd);
	AUDIT_ARG(svipc_id, semid);

	SYSV_SEM_SUBSYS_LOCK();

#ifdef SEM_DEBUG
	printf("call to semctl(%d, %d, %d, 0x%qx)\n", semid, semnum, cmd, user_arg);
#endif

	semid = IPCID_TO_IX(semid);

	if (semid < 0 || semid >= seminfo.semmni) {
#ifdef SEM_DEBUG
		printf("Invalid semid\n");
#endif
		eval = EINVAL;
		goto semctlout;
	}

	semakptr = &sema[semid];
	if ((semakptr->u.sem_perm.mode & SEM_ALLOC) == 0 ||
	    semakptr->u.sem_perm._seq != IPCID_TO_SEQ(uap->semid)) {
		eval = EINVAL;
		goto semctlout;
	}
#if CONFIG_MACF
	eval = mac_sysvsem_check_semctl(cred, semakptr, cmd);
	if (eval)
		goto semctlout;
#endif

	eval = 0;
	rval = 0;

	switch (cmd) {
	case IPC_RMID:
		if ((eval = ipcperm(cred, &semakptr->u.sem_perm, IPC_M))) 
			goto semctlout;

		semakptr->u.sem_perm.cuid = kauth_cred_getuid(cred);
		semakptr->u.sem_perm.uid = kauth_cred_getuid(cred);
		semtot -= semakptr->u.sem_nsems;
		for (i = semakptr->u.sem_base - sem_pool; i < semtot; i++)
			sem_pool[i] = sem_pool[i + semakptr->u.sem_nsems];
		for (i = 0; i < seminfo.semmni; i++) {
			if ((sema[i].u.sem_perm.mode & SEM_ALLOC) &&
			    sema[i].u.sem_base > semakptr->u.sem_base)
				sema[i].u.sem_base -= semakptr->u.sem_nsems;
		}
		semakptr->u.sem_perm.mode = 0;
#if CONFIG_MACF
		mac_sysvsem_label_recycle(semakptr);
#endif
		semundo_clear(semid, -1);
		wakeup((caddr_t)semakptr);
		break;

	case IPC_SET:
		if ((eval = ipcperm(cred, &semakptr->u.sem_perm, IPC_M)))
				goto semctlout;

		if (IS_64BIT_PROCESS(p)) {
			struct user64_semid_ds ds64;
			eval = copyin(user_arg.buf, &ds64, sizeof(ds64));
			semid_ds_64tokernel(&ds64, &sbuf);
		} else {
			struct user32_semid_ds ds32;
			eval = copyin(user_arg.buf, &ds32, sizeof(ds32));
			semid_ds_32tokernel(&ds32, &sbuf);
		}
		
		if (eval != 0) {
			goto semctlout;
		}

		semakptr->u.sem_perm.uid = sbuf.sem_perm.uid;
		semakptr->u.sem_perm.gid = sbuf.sem_perm.gid;
		semakptr->u.sem_perm.mode = (semakptr->u.sem_perm.mode &
		    ~0777) | (sbuf.sem_perm.mode & 0777);
		semakptr->u.sem_ctime = sysv_semtime();
		break;

	case IPC_STAT:
		if ((eval = ipcperm(cred, &semakptr->u.sem_perm, IPC_R)))
				goto semctlout;

		if (IS_64BIT_PROCESS(p)) {
			struct user64_semid_ds semid_ds64;
			semid_ds_kernelto64(&semakptr->u, &semid_ds64);
			eval = copyout(&semid_ds64, user_arg.buf, sizeof(semid_ds64));
		} else {
			struct user32_semid_ds semid_ds32;
			semid_ds_kernelto32(&semakptr->u, &semid_ds32);
			eval = copyout(&semid_ds32, user_arg.buf, sizeof(semid_ds32));
		}
		break;

	case GETNCNT:
		if ((eval = ipcperm(cred, &semakptr->u.sem_perm, IPC_R)))
				goto semctlout;
		if (semnum < 0 || semnum >= semakptr->u.sem_nsems) {
			eval = EINVAL;
			goto semctlout;
		}
		rval = semakptr->u.sem_base[semnum].semncnt;
		break;

	case GETPID:
		if ((eval = ipcperm(cred, &semakptr->u.sem_perm, IPC_R)))
				goto semctlout;
		if (semnum < 0 || semnum >= semakptr->u.sem_nsems) {
			eval = EINVAL;
			goto semctlout;
		}
		rval = semakptr->u.sem_base[semnum].sempid;
		break;

	case GETVAL:
		if ((eval = ipcperm(cred, &semakptr->u.sem_perm, IPC_R)))
				goto semctlout;
		if (semnum < 0 || semnum >= semakptr->u.sem_nsems) {
			eval = EINVAL;
			goto semctlout;
		}
		rval = semakptr->u.sem_base[semnum].semval;
		break;

	case GETALL:
		if ((eval = ipcperm(cred, &semakptr->u.sem_perm, IPC_R)))
				goto semctlout;
/* XXXXXXXXXXXXXXXX TBD XXXXXXXXXXXXXXXX */
		for (i = 0; i < semakptr->u.sem_nsems; i++) {
			/* XXX could be done in one go... */
			eval = copyout((caddr_t)&semakptr->u.sem_base[i].semval,
			    user_arg.array + (i * sizeof(unsigned short)),
			    sizeof(unsigned short));
			if (eval != 0)
				break;
		}
		break;

	case GETZCNT:
		if ((eval = ipcperm(cred, &semakptr->u.sem_perm, IPC_R)))
				goto semctlout;
		if (semnum < 0 || semnum >= semakptr->u.sem_nsems) {
			eval = EINVAL;
			goto semctlout;
		}
		rval = semakptr->u.sem_base[semnum].semzcnt;
		break;

	case SETVAL:
		if ((eval = ipcperm(cred, &semakptr->u.sem_perm, IPC_W)))
                {
#ifdef SEM_DEBUG
			printf("Invalid credentials for write\n");
#endif
				goto semctlout;
		}
		if (semnum < 0 || semnum >= semakptr->u.sem_nsems)
		{
#ifdef SEM_DEBUG
			printf("Invalid number out of range for set\n");
#endif
			eval = EINVAL;
			goto semctlout;
		}
		/*
		 * Cast down a pointer instead of using 'val' member directly
		 * to avoid introducing endieness and a pad field into the
		 * header file.  Ugly, but it works.
		 */
		semakptr->u.sem_base[semnum].semval = CAST_DOWN_EXPLICIT(int,user_arg.buf);
		semakptr->u.sem_base[semnum].sempid = p->p_pid;
		/* XXX scottl Should there be a MAC call here? */
		semundo_clear(semid, semnum);
		wakeup((caddr_t)semakptr);
		break;

	case SETALL:
		if ((eval = ipcperm(cred, &semakptr->u.sem_perm, IPC_W)))
				goto semctlout;
/*** XXXXXXXXXXXX TBD ********/
		for (i = 0; i < semakptr->u.sem_nsems; i++) {
			/* XXX could be done in one go... */
			eval = copyin(user_arg.array + (i * sizeof(unsigned short)),
			    (caddr_t)&semakptr->u.sem_base[i].semval,
			    sizeof(unsigned short));
			if (eval != 0)
				break;
			semakptr->u.sem_base[i].sempid = p->p_pid;
		}
		/* XXX scottl Should there be a MAC call here? */
		semundo_clear(semid, -1);
		wakeup((caddr_t)semakptr);
		break;

	default:
			eval = EINVAL;
			goto semctlout;
	}

	if (eval == 0)
		*retval = rval;
semctlout:
	SYSV_SEM_SUBSYS_UNLOCK();
	return(eval);
}

int
semget(__unused struct proc *p, struct semget_args *uap, int32_t *retval)
{
	int semid, eval;
	int key = uap->key;
	int nsems = uap->nsems;
	int semflg = uap->semflg;
	kauth_cred_t cred = kauth_cred_get();

#ifdef SEM_DEBUG
	if (key != IPC_PRIVATE)
		printf("semget(0x%x, %d, 0%o)\n", key, nsems, semflg);
	else
		printf("semget(IPC_PRIVATE, %d, 0%o)\n", nsems, semflg);
#endif


	SYSV_SEM_SUBSYS_LOCK();

    
	if (key != IPC_PRIVATE) {
		for (semid = 0; semid < seminfo.semmni; semid++) {
			if ((sema[semid].u.sem_perm.mode & SEM_ALLOC) &&
			    sema[semid].u.sem_perm._key == key)
				break;
		}
		if (semid < seminfo.semmni) {
#ifdef SEM_DEBUG
			printf("found public key\n");
#endif
			if ((eval = ipcperm(cred, &sema[semid].u.sem_perm,
			    semflg & 0700)))
				goto semgetout;
			if (nsems < 0 || sema[semid].u.sem_nsems < nsems) {
#ifdef SEM_DEBUG
				printf("too small\n");
#endif
				eval = EINVAL;
				goto semgetout;
			}
			if ((semflg & IPC_CREAT) && (semflg & IPC_EXCL)) {
#ifdef SEM_DEBUG
				printf("not exclusive\n");
#endif
				eval = EEXIST;
				goto semgetout;
			}
#if CONFIG_MACF
			eval = mac_sysvsem_check_semget(cred, &sema[semid]);
			if (eval) 
				goto semgetout;
#endif
			goto found;
		}
	}

#ifdef SEM_DEBUG
	printf("need to allocate an id for the request\n");
#endif
	if (key == IPC_PRIVATE || (semflg & IPC_CREAT)) {
		if (nsems <= 0 || nsems > limitseminfo.semmsl) {
#ifdef SEM_DEBUG
			printf("nsems out of range (0<%d<=%d)\n", nsems,
			    seminfo.semmsl);
#endif
			eval = EINVAL;
			goto semgetout;
		}
		if (nsems > seminfo.semmns - semtot) {
#ifdef SEM_DEBUG
			printf("not enough semaphores left (need %d, got %d)\n",
			    nsems, seminfo.semmns - semtot);
#endif
			if (!grow_sem_pool(semtot + nsems)) {
#ifdef SEM_DEBUG
				printf("failed to grow the sem array\n");
#endif
				eval = ENOSPC;
				goto semgetout;
			}
		}
		for (semid = 0; semid < seminfo.semmni; semid++) {
			if ((sema[semid].u.sem_perm.mode & SEM_ALLOC) == 0)
				break;
		}
		if (semid == seminfo.semmni) {
#ifdef SEM_DEBUG
			printf("no more id's available\n");
#endif
			if (!grow_sema_array(seminfo.semmni + 1))
			{
#ifdef SEM_DEBUG
				printf("failed to grow sema array\n");
#endif
				eval = ENOSPC;
				goto semgetout;
			}
		}
#ifdef SEM_DEBUG
		printf("semid %d is available\n", semid);
#endif
		sema[semid].u.sem_perm._key = key;
		sema[semid].u.sem_perm.cuid = kauth_cred_getuid(cred);
		sema[semid].u.sem_perm.uid = kauth_cred_getuid(cred);
		sema[semid].u.sem_perm.cgid = cred->cr_gid;
		sema[semid].u.sem_perm.gid = cred->cr_gid;
		sema[semid].u.sem_perm.mode = (semflg & 0777) | SEM_ALLOC;
		sema[semid].u.sem_perm._seq =
		    (sema[semid].u.sem_perm._seq + 1) & 0x7fff;
		sema[semid].u.sem_nsems = nsems;
		sema[semid].u.sem_otime = 0;
		sema[semid].u.sem_ctime = sysv_semtime();
		sema[semid].u.sem_base = &sem_pool[semtot];
		semtot += nsems;
		bzero(sema[semid].u.sem_base,
		    sizeof(sema[semid].u.sem_base[0])*nsems);
#if CONFIG_MACF
		mac_sysvsem_label_associate(cred, &sema[semid]);
#endif
#ifdef SEM_DEBUG
		printf("sembase = 0x%x, next = 0x%x\n", sema[semid].u.sem_base,
		    &sem_pool[semtot]);
#endif
	} else {
#ifdef SEM_DEBUG
		printf("didn't find it and wasn't asked to create it\n");
#endif
		eval = ENOENT;
		goto semgetout;
	}

found:
	*retval = IXSEQ_TO_IPCID(semid, sema[semid].u.sem_perm);
	AUDIT_ARG(svipc_id, *retval);
#ifdef SEM_DEBUG
	printf("semget is done, returning %d\n", *retval);
#endif
	eval = 0;

semgetout:
	SYSV_SEM_SUBSYS_UNLOCK();
	return(eval);
}

int
semop(struct proc *p, struct semop_args *uap, int32_t *retval)
{
	int semid = uap->semid;
	int nsops = uap->nsops;
	struct sembuf sops[MAX_SOPS];
	register struct semid_kernel *semakptr;
	register struct sembuf *sopptr = NULL;	/* protected by 'semptr' */
	register struct sem *semptr = NULL;	/* protected by 'if' */
	int supidx = -1;
	int i, j, eval;
	int do_wakeup, do_undos;

	AUDIT_ARG(svipc_id, uap->semid);

	SYSV_SEM_SUBSYS_LOCK();

#ifdef SEM_DEBUG
	printf("call to semop(%d, 0x%x, %d)\n", semid, sops, nsops);
#endif

	semid = IPCID_TO_IX(semid);	/* Convert back to zero origin */

	if (semid < 0 || semid >= seminfo.semmni) {
		eval = EINVAL;
		goto semopout;
	}

	semakptr = &sema[semid];
	if ((semakptr->u.sem_perm.mode & SEM_ALLOC) == 0) {
		eval = EINVAL;
		goto semopout;
	}
	if (semakptr->u.sem_perm._seq != IPCID_TO_SEQ(uap->semid)) {
		eval = EINVAL;
		goto semopout;
	}

	if ((eval = ipcperm(kauth_cred_get(), &semakptr->u.sem_perm, IPC_W))) {
#ifdef SEM_DEBUG
		printf("eval = %d from ipaccess\n", eval);
#endif
		goto semopout;
	}

	if (nsops < 0 || nsops > MAX_SOPS) {
#ifdef SEM_DEBUG
		printf("too many sops (max=%d, nsops=%d)\n", MAX_SOPS, nsops);
#endif
		eval = E2BIG;
		goto semopout;
	}

#if CONFIG_MACF
	/*
	 * Initial pass thru sops to see what permissions are needed.
	 */
	j = 0;		/* permission needed */
	for (i = 0; i < nsops; i++)
		j |= (sops[i].sem_op == 0) ? SEM_R : SEM_A;

	/*
	 * The MAC hook checks whether the thread has read (and possibly
	 * write) permissions to the semaphore array based on the
	 * sopptr->sem_op value.
	 */
	eval = mac_sysvsem_check_semop(kauth_cred_get(), semakptr, j);
	if (eval)
		goto semopout;
#endif

	/*  OK for LP64, since sizeof(struct sembuf) is currently invariant */
	if ((eval = copyin(uap->sops, &sops, nsops * sizeof(struct sembuf))) != 0) {
#ifdef SEM_DEBUG
		printf("eval = %d from copyin(%08x, %08x, %ld)\n", eval,
		    uap->sops, &sops, nsops * sizeof(struct sembuf));
#endif
		goto semopout;
	}

	/*
	 * Loop trying to satisfy the vector of requests.
	 * If we reach a point where we must wait, any requests already
	 * performed are rolled back and we go to sleep until some other
	 * process wakes us up.  At this point, we start all over again.
	 *
	 * This ensures that from the perspective of other tasks, a set
	 * of requests is atomic (never partially satisfied).
	 */
	do_undos = 0;

	for (;;) {
		do_wakeup = 0;

		for (i = 0; i < nsops; i++) {
			sopptr = &sops[i];

			if (sopptr->sem_num >= semakptr->u.sem_nsems) {
				eval = EFBIG;
				goto semopout;
			}

			semptr = &semakptr->u.sem_base[sopptr->sem_num];

#ifdef SEM_DEBUG
			printf("semop:  semakptr=%x, sem_base=%x, semptr=%x, sem[%d]=%d : op=%d, flag=%s\n",
			    semakptr, semakptr->u.sem_base, semptr,
			    sopptr->sem_num, semptr->semval, sopptr->sem_op,
			    (sopptr->sem_flg & IPC_NOWAIT) ? "nowait" : "wait");
#endif

			if (sopptr->sem_op < 0) {
				if (semptr->semval + sopptr->sem_op < 0) {
#ifdef SEM_DEBUG
					printf("semop:  can't do it now\n");
#endif
					break;
				} else {
					semptr->semval += sopptr->sem_op;
					if (semptr->semval == 0 &&
					    semptr->semzcnt > 0)
						do_wakeup = 1;
				}
				if (sopptr->sem_flg & SEM_UNDO)
					do_undos = 1;
			} else if (sopptr->sem_op == 0) {
				if (semptr->semval > 0) {
#ifdef SEM_DEBUG
					printf("semop:  not zero now\n");
#endif
					break;
				}
			} else {
				if (semptr->semncnt > 0)
					do_wakeup = 1;
				semptr->semval += sopptr->sem_op;
				if (sopptr->sem_flg & SEM_UNDO)
					do_undos = 1;
			}
		}

		/*
		 * Did we get through the entire vector?
		 */
		if (i >= nsops)
			goto done;

		/*
		 * No ... rollback anything that we've already done
		 */
#ifdef SEM_DEBUG
		printf("semop:  rollback 0 through %d\n", i-1);
#endif
		for (j = 0; j < i; j++)
			semakptr->u.sem_base[sops[j].sem_num].semval -=
			    sops[j].sem_op;

		/*
		 * If the request that we couldn't satisfy has the
		 * NOWAIT flag set then return with EAGAIN.
		 */
		if (sopptr->sem_flg & IPC_NOWAIT) {
			eval = EAGAIN;
			goto semopout;
		}

		if (sopptr->sem_op == 0)
			semptr->semzcnt++;
		else
			semptr->semncnt++;

#ifdef SEM_DEBUG
		printf("semop:  good night!\n");
#endif
		/* Release our lock on the semaphore subsystem so
		 * another thread can get at the semaphore we are
		 * waiting for. We will get the lock back after we
		 * wake up.
		 */
		eval = msleep((caddr_t)semakptr, &sysv_sem_subsys_mutex , (PZERO - 4) | PCATCH,
		    "semwait", 0);
                
#ifdef SEM_DEBUG
		printf("semop:  good morning (eval=%d)!\n", eval);
#endif
		if (eval != 0) {
			eval = EINTR;
		}

		/*
		 * IMPORTANT: while we were asleep, the semaphore array might
		 * have been reallocated somewhere else (see grow_sema_array()).
		 * When we wake up, we have to re-lookup the semaphore 
		 * structures and re-validate them.
		 */

		semptr = NULL;

		/*
		 * Make sure that the semaphore still exists
		 *
		 * XXX POSIX: Third test this 'if' and 'EINTR' precedence may
		 * fail testing; if so, we will need to revert this code.
		 */
	 	semakptr = &sema[semid];   /* sema may have been reallocated */
		if ((semakptr->u.sem_perm.mode & SEM_ALLOC) == 0 ||
		    semakptr->u.sem_perm._seq != IPCID_TO_SEQ(uap->semid) ||
		    sopptr->sem_num >= semakptr->u.sem_nsems) {
			/* The man page says to return EIDRM. */
			/* Unfortunately, BSD doesn't define that code! */
			if (eval == EINTR) {
				/*
				 * EINTR takes precedence over the fact that
				 * the semaphore disappeared while we were
				 * sleeping...
				 */
			} else {
#ifdef EIDRM
				eval = EIDRM;
#else
				eval = EINVAL;		/* Ancient past */
#endif
			}
			goto semopout;
		}

		/*
		 * The semaphore is still alive.  Readjust the count of
		 * waiting processes. semptr needs to be recomputed
		 * because the sem[] may have been reallocated while
		 * we were sleeping, updating our sem_base pointer.
		 */
		semptr = &semakptr->u.sem_base[sopptr->sem_num];
		if (sopptr->sem_op == 0)
			semptr->semzcnt--;
		else
			semptr->semncnt--;

		if (eval != 0) { /* EINTR */
			goto semopout;
		}
	}

done:
	/*
	 * Process any SEM_UNDO requests.
	 */
	if (do_undos) {
		for (i = 0; i < nsops; i++) {
			/*
			 * We only need to deal with SEM_UNDO's for non-zero
			 * op's.
			 */
			int adjval;

			if ((sops[i].sem_flg & SEM_UNDO) == 0)
				continue;
			adjval = sops[i].sem_op;
			if (adjval == 0)
				continue;
			eval = semundo_adjust(p, &supidx, semid,
			    sops[i].sem_num, -adjval);
			if (eval == 0)
				continue;

			/*
			 * Oh-Oh!  We ran out of either sem_undo's or undo's.
			 * Rollback the adjustments to this point and then
			 * rollback the semaphore ups and down so we can return
			 * with an error with all structures restored.  We
			 * rollback the undo's in the exact reverse order that
			 * we applied them.  This guarantees that we won't run
			 * out of space as we roll things back out.
			 */
			for (j = i - 1; j >= 0; j--) {
				if ((sops[j].sem_flg & SEM_UNDO) == 0)
					continue;
				adjval = sops[j].sem_op;
				if (adjval == 0)
					continue;
				if (semundo_adjust(p, &supidx, semid,
				    sops[j].sem_num, adjval) != 0)
					panic("semop - can't undo undos");
			}

			for (j = 0; j < nsops; j++)
				semakptr->u.sem_base[sops[j].sem_num].semval -=
				    sops[j].sem_op;

#ifdef SEM_DEBUG
			printf("eval = %d from semundo_adjust\n", eval);
#endif
			goto semopout;
		} /* loop through the sops */
	} /* if (do_undos) */

	/* We're definitely done - set the sempid's */
	for (i = 0; i < nsops; i++) {
		sopptr = &sops[i];
		semptr = &semakptr->u.sem_base[sopptr->sem_num];
		semptr->sempid = p->p_pid;
	}
	semakptr->u.sem_otime = sysv_semtime();

	if (do_wakeup) {
#ifdef SEM_DEBUG
		printf("semop:  doing wakeup\n");
#ifdef SEM_WAKEUP
		sem_wakeup((caddr_t)semakptr);
#else
		wakeup((caddr_t)semakptr);
#endif
		printf("semop:  back from wakeup\n");
#else
		wakeup((caddr_t)semakptr);
#endif
	}
#ifdef SEM_DEBUG
	printf("semop:  done\n");
#endif
	*retval = 0;
	eval = 0;
semopout:
	SYSV_SEM_SUBSYS_UNLOCK();
	return(eval);
}

/*
 * Go through the undo structures for this process and apply the adjustments to
 * semaphores.
 */
void
semexit(struct proc *p)
{
	register struct sem_undo *suptr = NULL;
	int suidx;
	int *supidx;
	int did_something;

	/* If we have not allocated our semaphores yet there can't be
	 * anything to undo, but we need the lock to prevent
	 * dynamic memory race conditions.
	 */
	SYSV_SEM_SUBSYS_LOCK();

	if (!sem_pool)
	{
		SYSV_SEM_SUBSYS_UNLOCK();
		return;
	}
	did_something = 0;

	/*
	 * Go through the chain of undo vectors looking for one
	 * associated with this process.
	 */

	for (supidx = &semu_list_idx; (suidx = *supidx) != -1;
	    supidx = &suptr->un_next_idx) {
		suptr = SEMU(suidx);
		if (suptr->un_proc == p)
			break;
	}

	if (suidx == -1)
		goto unlock;

#ifdef SEM_DEBUG
	printf("proc @%08x has undo structure with %d entries\n", p,
	    suptr->un_cnt);
#endif

	/*
	 * If there are any active undo elements then process them.
	 */
	if (suptr->un_cnt > 0) {
		while (suptr->un_ent != NULL) {
			struct undo *sueptr;
			int semid;
			int semnum;
			int adjval;
			struct semid_kernel *semakptr;

			sueptr = suptr->un_ent;
			semid = sueptr->une_id;
			semnum = sueptr->une_num;
			adjval = sueptr->une_adjval;

			semakptr = &sema[semid];
			if ((semakptr->u.sem_perm.mode & SEM_ALLOC) == 0)
				panic("semexit - semid not allocated");
			if (semnum >= semakptr->u.sem_nsems)
				panic("semexit - semnum out of range");

#ifdef SEM_DEBUG
			printf("semexit:  %08x id=%d num=%d(adj=%d) ; sem=%d\n",
			       suptr->un_proc,
			       semid,
			       semnum,
			       adjval,
			       semakptr->u.sem_base[semnum].semval);
#endif

			if (adjval < 0) {
				if (semakptr->u.sem_base[semnum].semval < -adjval)
					semakptr->u.sem_base[semnum].semval = 0;
				else
					semakptr->u.sem_base[semnum].semval +=
					    adjval;
			} else
				semakptr->u.sem_base[semnum].semval += adjval;

		/* Maybe we should build a list of semakptr's to wake
		 * up, finish all access to data structures, release the
		 * subsystem lock, and wake all the processes.  Something
		 * to think about.  It wouldn't buy us anything unless
		 * wakeup had the potential to block, or the syscall
		 * funnel state was changed to allow multiple threads
		 * in the BSD code at once.
		 */
#ifdef SEM_WAKEUP
			sem_wakeup((caddr_t)semakptr);
#else
			wakeup((caddr_t)semakptr);
#endif
#ifdef SEM_DEBUG
			printf("semexit:  back from wakeup\n");
#endif
			suptr->un_cnt--;
			suptr->un_ent = sueptr->une_next;
			FREE(sueptr, M_SYSVSEM);
			sueptr = NULL;
		}
	}

	/*
	 * Deallocate the undo vector.
	 */
#ifdef SEM_DEBUG
	printf("removing vector\n");
#endif
	suptr->un_proc = NULL;
	*supidx = suptr->un_next_idx;

unlock:
	/*
         * There is a semaphore leak (i.e. memory leak) in this code.
         * We should be deleting the IPC_PRIVATE semaphores when they are
         * no longer needed, and we dont. We would have to track which processes
         * know about which IPC_PRIVATE semaphores, updating the list after
         * every fork.  We can't just delete them semaphore when the process
         * that created it dies, because that process may well have forked
         * some children.  So we need to wait until all of it's children have
         * died, and so on.  Maybe we should tag each IPC_PRIVATE sempahore
         * with the creating group ID, count the number of processes left in
         * that group, and delete the semaphore when the group is gone.
         * Until that code gets implemented we will leak IPC_PRIVATE semaphores.
         * There is an upper bound on the size of our semaphore array, so   
         * leaking the semaphores should not work as a DOS attack.
         *
         * Please note that the original BSD code this file is based on had the
         * same leaky semaphore problem.
         */

	SYSV_SEM_SUBSYS_UNLOCK();
}


/* (struct sysctl_oid *oidp, void *arg1, int arg2, \
        struct sysctl_req *req) */
static int
sysctl_seminfo(__unused struct sysctl_oid *oidp, void *arg1,
	__unused int arg2, struct sysctl_req *req)
{
	int error = 0;

	error = SYSCTL_OUT(req, arg1, sizeof(int));
	if (error || req->newptr == USER_ADDR_NULL)
		return(error);

	SYSV_SEM_SUBSYS_LOCK();

	/* Set the values only if shared memory is not initialised */
	if ((sem_pool == NULL) && 
		(sema == NULL) && 
		(semu == NULL) && 
		(semu_list_idx == -1)) {
			if ((error = SYSCTL_IN(req, arg1, sizeof(int)))) {
				goto out;
			}
	} else 
		error = EINVAL;
out:
	SYSV_SEM_SUBSYS_UNLOCK();
	return(error);
	
}

/* SYSCTL_NODE(_kern, KERN_SYSV, sysv, CTLFLAG_RW, 0, "SYSV"); */
extern struct sysctl_oid_list sysctl__kern_sysv_children;
SYSCTL_PROC(_kern_sysv, OID_AUTO, semmni, CTLTYPE_INT | CTLFLAG_RW,
    &limitseminfo.semmni, 0, &sysctl_seminfo ,"I","semmni");

SYSCTL_PROC(_kern_sysv, OID_AUTO, semmns, CTLTYPE_INT | CTLFLAG_RW,
    &limitseminfo.semmns, 0, &sysctl_seminfo ,"I","semmns");

SYSCTL_PROC(_kern_sysv, OID_AUTO, semmnu, CTLTYPE_INT | CTLFLAG_RW,
    &limitseminfo.semmnu, 0, &sysctl_seminfo ,"I","semmnu");

SYSCTL_PROC(_kern_sysv, OID_AUTO, semmsl, CTLTYPE_INT | CTLFLAG_RW,
    &limitseminfo.semmsl, 0, &sysctl_seminfo ,"I","semmsl");
    
SYSCTL_PROC(_kern_sysv, OID_AUTO, semume, CTLTYPE_INT | CTLFLAG_RW,
    &limitseminfo.semume, 0, &sysctl_seminfo ,"I","semume");


static int
IPCS_sem_sysctl(__unused struct sysctl_oid *oidp, __unused void *arg1,
	__unused int arg2, struct sysctl_req *req)
{
	int error;
	int cursor;
	union {
		struct user32_IPCS_command u32;
		struct user_IPCS_command u64;
	} ipcs;
	struct user32_semid_ds semid_ds32;	/* post conversion, 32 bit version */
	struct user64_semid_ds semid_ds64;	/* post conversion, 64 bit version */
	void *semid_dsp;
	size_t ipcs_sz;
	size_t semid_ds_sz;
	struct proc *p = current_proc();

	if (IS_64BIT_PROCESS(p)) {
		ipcs_sz = sizeof(struct user_IPCS_command);
		semid_ds_sz = sizeof(struct user64_semid_ds);
	} else {
		ipcs_sz = sizeof(struct user32_IPCS_command);
		semid_ds_sz = sizeof(struct user32_semid_ds);
	}

	/* Copy in the command structure */
	if ((error = SYSCTL_IN(req, &ipcs, ipcs_sz)) != 0) {
		return(error);
	}

	if (!IS_64BIT_PROCESS(p)) /* convert in place */
		ipcs.u64.ipcs_data = CAST_USER_ADDR_T(ipcs.u32.ipcs_data);

	/* Let us version this interface... */
	if (ipcs.u64.ipcs_magic != IPCS_MAGIC) {
		return(EINVAL);
	}

	SYSV_SEM_SUBSYS_LOCK();
	switch(ipcs.u64.ipcs_op) {
	case IPCS_SEM_CONF:	/* Obtain global configuration data */
		if (ipcs.u64.ipcs_datalen != sizeof(struct seminfo)) {
			error = ERANGE;
			break;
		}
		if (ipcs.u64.ipcs_cursor != 0) {	/* fwd. compat. */
			error = EINVAL;
			break;
		}
		error = copyout(&seminfo, ipcs.u64.ipcs_data, ipcs.u64.ipcs_datalen);
		break;

	case IPCS_SEM_ITER:	/* Iterate over existing segments */
		cursor = ipcs.u64.ipcs_cursor;
		if (cursor < 0 || cursor >= seminfo.semmni) {
			error = ERANGE;
			break;
		}
		if (ipcs.u64.ipcs_datalen != (int)semid_ds_sz ) {
			error = EINVAL;
			break;
		}
		for( ; cursor < seminfo.semmni; cursor++) {
			if (sema[cursor].u.sem_perm.mode & SEM_ALLOC)
				break;
			continue;
		}
		if (cursor == seminfo.semmni) {
			error = ENOENT;
			break;
		}

		semid_dsp = &sema[cursor].u;	/* default: 64 bit */

		/*
		 * If necessary, convert the 64 bit kernel segment
		 * descriptor to a 32 bit user one.
		 */
		if (!IS_64BIT_PROCESS(p)) {
			semid_ds_kernelto32(semid_dsp, &semid_ds32);
			semid_dsp = &semid_ds32;
		} else {
			semid_ds_kernelto64(semid_dsp, &semid_ds64);
			semid_dsp = &semid_ds64;
		}

		error = copyout(semid_dsp, ipcs.u64.ipcs_data, ipcs.u64.ipcs_datalen);
		if (!error) {
			/* update cursor */
			ipcs.u64.ipcs_cursor = cursor + 1;

			if (!IS_64BIT_PROCESS(p))       /* convert in place */
				ipcs.u32.ipcs_data = CAST_DOWN_EXPLICIT(user32_addr_t,ipcs.u64.ipcs_data);

			error = SYSCTL_OUT(req, &ipcs, ipcs_sz);
		}
		break;

	default:
		error = EINVAL;
		break;
	}
	SYSV_SEM_SUBSYS_UNLOCK();
	return(error);
}

SYSCTL_DECL(_kern_sysv_ipcs);
SYSCTL_PROC(_kern_sysv_ipcs, OID_AUTO, sem, CTLFLAG_RW|CTLFLAG_ANYBODY,
	0, 0, IPCS_sem_sysctl,
	"S,IPCS_sem_command",
	"ipcs sem command interface");

#endif /* SYSV_SEM */
