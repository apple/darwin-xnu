/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/sem.h>
#include <sys/malloc.h>
#include <sys/filedesc.h>
#include <sys/file.h>
#include <sys/sysctl.h>

#include <bsm/audit_kernel.h>

#include <mach/mach_types.h>

/*#include <sys/sysproto.h>*/
/*#include <sys/sysent.h>*/

/* Uncomment this line to see the debugging output */
/* #define SEM_DEBUG */

/* Macros to deal with the semaphore subsystem lock.  The lock currently uses
 * the semlock_holder static variable as a mutex.  NULL means no lock, any
 * value other than NULL means locked.  semlock_holder is used because it was
 * present in the code before the Darwin port, and for no other reason.
 * When the time comes to relax the funnel requirements of the kernel only
 * these macros should need to be changed.  A spin lock would work well.
 */
/* Aquire the lock */
#define SUBSYSTEM_LOCK_AQUIRE(p) { sysv_sem_aquiring_threads++; \
    while (semlock_holder != NULL) \
        (void) tsleep((caddr_t)&semlock_holder, (PZERO - 4), "sysvsem", 0); \
    semlock_holder = p; \
    sysv_sem_aquiring_threads--; }

/* Release the lock */
#define SUBSYSTEM_LOCK_RELEASE { semlock_holder = NULL; wakeup((caddr_t)&semlock_holder); }

/* Release the lock and return a value */
#define UNLOCK_AND_RETURN(ret) { SUBSYSTEM_LOCK_RELEASE; return(ret); }

#define M_SYSVSEM	M_SUBPROC

#if 0
static void seminit __P((void *));
SYSINIT(sysv_sem, SI_SUB_SYSV_SEM, SI_ORDER_FIRST, seminit, NULL)
#endif 0

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

/* A counter so the module unload code knows when there are no more processes using
 * the sysv_sem code */
static long sysv_sem_sleeping_threads = 0;
static long sysv_sem_aquiring_threads = 0;

struct semctl_args;
int semctl __P((struct proc *p, struct semctl_args *uap, int *));
struct semget_args;
int semget __P((struct proc *p, struct semget_args *uap, int *));
struct semop_args;
int semop __P((struct proc *p, struct semop_args *uap, int *));
struct semconfig_args;
int semconfig __P((struct proc *p, struct semconfig_args *uap, int *));


static struct sem_undo *semu_alloc __P((struct proc *p));
static int semundo_adjust __P((struct proc *p, struct sem_undo **supptr, 
		int semid, int semnum, int adjval));
static void semundo_clear __P((int semid, int semnum));

typedef int     sy_call_t __P((struct proc *, void *, int *));

/* XXX casting to (sy_call_t *) is bogus, as usual. */
static sy_call_t *semcalls[] = {
	(sy_call_t *)semctl, (sy_call_t *)semget,
	(sy_call_t *)semop, (sy_call_t *)semconfig
};

static int	semtot = 0;			/* # of used semaphores */
struct semid_ds *sema = NULL;			/* semaphore id pool */
struct sem *sem =  NULL;			/* semaphore pool */
static struct sem_undo *semu_list = NULL;   /* list of active undo structures */
struct sem_undo *semu = NULL;			/* semaphore undo pool */

static struct proc *semlock_holder = NULL;

/* seminit no longer needed.  The data structures are grown dynamically */
void
seminit()
{
}

/*
 * Entry point for all SEM calls
 *
 * In Darwin this is no longer the entry point.  It will be removed after
 *  the code has been tested better.
 */
struct semsys_args {
	u_int	which;
	int	a2;
	int	a3;
	int	a4;
	int	a5;
};
int
semsys(p, uap, retval)
	struct proc *p;
	/* XXX actually varargs. */
	struct semsys_args *uap;
	register_t *retval;
{

	/* The individual calls handling the locking now */
	/*while (semlock_holder != NULL && semlock_holder != p)
		(void) tsleep((caddr_t)&semlock_holder, (PZERO - 4), "semsys", 0);
	 */

	if (uap->which >= sizeof(semcalls)/sizeof(semcalls[0]))
		return (EINVAL);
	return ((*semcalls[uap->which])(p, &uap->a2, retval));
}

/*
 * Lock or unlock the entire semaphore facility.
 *
 * This will probably eventually evolve into a general purpose semaphore
 * facility status enquiry mechanism (I don't like the "read /dev/kmem"
 * approach currently taken by ipcs and the amount of info that we want
 * to be able to extract for ipcs is probably beyond what the capability
 * of the getkerninfo facility.
 *
 * At the time that the current version of semconfig was written, ipcs is
 * the only user of the semconfig facility.  It uses it to ensure that the
 * semaphore facility data structures remain static while it fishes around
 * in /dev/kmem.
 */

#ifndef _SYS_SYSPROTO_H_
struct semconfig_args {
	semconfig_ctl_t	flag;
};
#endif

int
semconfig(p, uap, retval)
	struct proc *p;
	struct semconfig_args *uap;
	register_t *retval;
{
	int eval = 0;

	switch (uap->flag) {
	case SEM_CONFIG_FREEZE:
		SUBSYSTEM_LOCK_AQUIRE(p);
		break;

	case SEM_CONFIG_THAW:
		SUBSYSTEM_LOCK_RELEASE;
		break;

	default:
		printf("semconfig: unknown flag parameter value (%d) - ignored\n",
		    uap->flag);
		eval = EINVAL;
		break;
	}

	*retval = 0;
	return(eval);
}

/* Expand the semu array to the given capacity.  If the expansion fails
 * return 0, otherwise return 1.
 *
 * Assumes we already have the subsystem lock.
 */
static int
grow_semu_array(newSize)
	int newSize;
{
	register int i, j;
	register struct sem_undo *newSemu;
	if (newSize <= seminfo.semmnu)
		return 0;
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
	MALLOC(newSemu, struct sem_undo*, sizeof(struct sem_undo)*newSize,
		M_SYSVSEM, M_WAITOK);
	if (NULL == newSemu)
	{
#ifdef SEM_DEBUG
		printf("allocation failed.  no changes made.\n");
#endif
		return 0;
	}

       	/* Initialize our structure.  */
	for (i = 0; i < seminfo.semmnu; i++)
	{
		newSemu[i] = semu[i];
		for(j = 0; j < SEMUME; j++)   /* Is this really needed? */
			newSemu[i].un_ent[j] = semu[i].un_ent[j];
	}
       	for (i = seminfo.semmnu; i < newSize; i++)
        {
               	newSemu[i].un_proc = NULL;
        }

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
grow_sema_array(newSize)
	int newSize;
{
	register struct semid_ds *newSema;
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
	MALLOC(newSema, struct semid_ds*, sizeof(struct semid_ds)*newSize,
		M_SYSVSEM, M_WAITOK);
	if (NULL == newSema)
	{
#ifdef SEM_DEBUG
		printf("allocation failed.  no changes made.\n");
#endif
		return 0;
	}

	/* Initialize our new ids, and copy over the old ones */
	for (i = 0; i < seminfo.semmni; i++)
	{
		newSema[i] = sema[i];
		/* This is a hack.  What we really want to be able to
		 * do is change the value a process is waiting on
		 * without waking it up, but I don't know how to do
		 * this with the existing code, so we wake up the
		 * process and let it do a lot of work to determine the
		 * semaphore set is really not available yet, and then
		 * sleep on the correct, reallocated semid_ds pointer.
		 */
		if (sema[i].sem_perm.mode & SEM_ALLOC)
			wakeup((caddr_t)&sema[i]);
	}

	for (i = seminfo.semmni; i < newSize; i++)
	{
		newSema[i].sem_base = 0;
		newSema[i].sem_perm.mode = 0;
	}

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
 * Expand the sem array to the given capacity.  If the expansion fails
 * we return 0 (fail), otherwise we return 1 (success).
 *
 * Assumes we already hold the subsystem lock.
 */
static int
grow_sem_array(newSize)
		int newSize;
{
	register struct sem *newSem = NULL;
	register int i;

	if (newSize < semtot)
		return 0;
	if (newSize > limitseminfo.semmns) /* enforce hard limit */
	{
#ifdef SEM_DEBUG
		printf("semaphore hard limit of %d reached, requested %d\n",
			limitseminfo.semmns, newSize);
#endif
		return 0;
	}
	newSize = (newSize/SEMMNS_INC + 1) * SEMMNS_INC;
	newSize = newSize > limitseminfo.semmns ? limitseminfo.semmns : newSize;

#ifdef SEM_DEBUG
	printf("growing sem array from %d to %d\n", seminfo.semmns, newSize);
#endif
	MALLOC(newSem, struct sem*, sizeof(struct sem)*newSize,
		M_SYSVSEM, M_WAITOK);
	if (NULL == newSem)
	{
#ifdef SEM_DEBUG
		printf("allocation failed.  no changes made.\n");
#endif
		return 0;
	}

	/* We have our new memory, now copy the old contents over */
	if (sem)
		for(i = 0; i < seminfo.semmns; i++)
			newSem[i] = sem[i];

	/* Update our id structures to point to the new semaphores */
	for(i = 0; i < seminfo.semmni; i++)
		if (sema[i].sem_perm.mode & SEM_ALLOC)  /* ID in use */
		{
			if (newSem > sem)
				sema[i].sem_base += newSem - sem;
			else
				sema[i].sem_base -= sem - newSem;
		}

	/* clean up the old array */
	if (sem)
		FREE(sem, M_SYSVSEM);

	sem = newSem;
	seminfo.semmns = newSize;
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

static struct sem_undo *
semu_alloc(p)
	struct proc *p;
{
	register int i;
	register struct sem_undo *suptr;
	register struct sem_undo **supptr;
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
				suptr->un_next = semu_list;
				semu_list = suptr;
				suptr->un_cnt = 0;
				suptr->un_proc = p;
				return(suptr);
			}
		}

		/*
		 * We didn't find a free one, if this is the first attempt
		 * then try to free some structures.
		 */

		if (attempt == 0) {
			/* All the structures are in use - try to free some */
			int did_something = 0;

			supptr = &semu_list;
			while ((suptr = *supptr) != NULL) {
				if (suptr->un_cnt == 0)  {
					suptr->un_proc = NULL;
					*supptr = suptr->un_next;
					did_something = 1;
				} else
					supptr = &(suptr->un_next);
			}

			/* If we didn't free anything. Try expanding
			 * the semu[] array.  If that doesn't work
			 * then fail.  We expand last to get the
			 * most reuse out of existing resources.
			 */
			if (!did_something)
				if (!grow_semu_array(seminfo.semmnu + 1))
					return(NULL);
		} else {
			/*
			 * The second pass failed even though we freed
			 * something after the first pass!
			 * This is IMPOSSIBLE!
			 */
			panic("semu_alloc - second attempt failed");
		}
	}
	return (NULL);
}

/*
 * Adjust a particular entry for a particular proc
 *
 * Assumes we already hold the subsystem lock.
 */

static int
semundo_adjust(p, supptr, semid, semnum, adjval)
	register struct proc *p;
	struct sem_undo **supptr;
	int semid, semnum;
	int adjval;
{
	register struct sem_undo *suptr;
	register struct undo *sunptr;
	int i;

	/* Look for and remember the sem_undo if the caller doesn't provide
	   it */

	suptr = *supptr;
	if (suptr == NULL) {
		for (suptr = semu_list; suptr != NULL;
		    suptr = suptr->un_next) {
			if (suptr->un_proc == p) {
				*supptr = suptr;
				break;
			}
		}
		if (suptr == NULL) {
			if (adjval == 0)
				return(0);
			suptr = semu_alloc(p);
			if (suptr == NULL)
				return(ENOSPC);
			*supptr = suptr;
		}
	}

	/*
	 * Look for the requested entry and adjust it (delete if adjval becomes
	 * 0).
	 */
	sunptr = &suptr->un_ent[0];
	for (i = 0; i < suptr->un_cnt; i++, sunptr++) {
		if (sunptr->un_id != semid || sunptr->un_num != semnum)
			continue;
		if (adjval == 0)
			sunptr->un_adjval = 0;
		else
			sunptr->un_adjval += adjval;
		if (sunptr->un_adjval == 0) {
			suptr->un_cnt--;
			if (i < suptr->un_cnt)
				suptr->un_ent[i] =
				    suptr->un_ent[suptr->un_cnt];
		}
		return(0);
	}

	/* Didn't find the right entry - create it */
	if (adjval == 0)
		return(0);
	if (suptr->un_cnt != limitseminfo.semume) {
		sunptr = &suptr->un_ent[suptr->un_cnt];
		suptr->un_cnt++;
		sunptr->un_adjval = adjval;
		sunptr->un_id = semid; sunptr->un_num = semnum;
	} else
		return(EINVAL);
	return(0);
}

/* Assumes we already hold the subsystem lock.
 */
static void
semundo_clear(semid, semnum)
	int semid, semnum;
{
	register struct sem_undo *suptr;

	for (suptr = semu_list; suptr != NULL; suptr = suptr->un_next) {
		register struct undo *sunptr = &suptr->un_ent[0];
		register int i = 0;

		while (i < suptr->un_cnt) {
			if (sunptr->un_id == semid) {
				if (semnum == -1 || sunptr->un_num == semnum) {
					suptr->un_cnt--;
					if (i < suptr->un_cnt) {
						suptr->un_ent[i] =
						  suptr->un_ent[suptr->un_cnt];
						continue;
					}
				}
				if (semnum != -1)
					break;
			}
			i++, sunptr++;
		}
	}
}

/*
 * Note that the user-mode half of this passes a union, not a pointer
 */
#ifndef _SYS_SYSPROTO_H_
struct semctl_args {
	int	semid;
	int	semnum;
	int	cmd;
	union	semun arg;
};
#endif

int
semctl(p, uap, retval)
	struct proc *p;
	register struct semctl_args *uap;
	register_t *retval;
{
	int semid = uap->semid;
	int semnum = uap->semnum;
	int cmd = uap->cmd;
	union semun arg = uap->arg;
	union semun real_arg;
	struct ucred *cred = p->p_ucred;
	int i, rval, eval;
	struct semid_ds sbuf;
	register struct semid_ds *semaptr;

	AUDIT_ARG(svipc_cmd, cmd);
	AUDIT_ARG(svipc_id, semid);
	SUBSYSTEM_LOCK_AQUIRE(p);
#ifdef SEM_DEBUG
	printf("call to semctl(%d, %d, %d, 0x%x)\n", semid, semnum, cmd, arg);
#endif

	semid = IPCID_TO_IX(semid);
	if (semid < 0 || semid >= seminfo.semmni)
{
#ifdef SEM_DEBUG
		printf("Invalid semid\n");
#endif
		UNLOCK_AND_RETURN(EINVAL);
}

	semaptr = &sema[semid];
	if ((semaptr->sem_perm.mode & SEM_ALLOC) == 0 ||
	    semaptr->sem_perm.seq != IPCID_TO_SEQ(uap->semid))
		UNLOCK_AND_RETURN(EINVAL);

	eval = 0;
	rval = 0;

	switch (cmd) {
	case IPC_RMID:
		if ((eval = ipcperm(cred, &semaptr->sem_perm, IPC_M)))
			UNLOCK_AND_RETURN(eval);
		semaptr->sem_perm.cuid = cred->cr_uid;
		semaptr->sem_perm.uid = cred->cr_uid;
		semtot -= semaptr->sem_nsems;
		for (i = semaptr->sem_base - sem; i < semtot; i++)
			sem[i] = sem[i + semaptr->sem_nsems];
		for (i = 0; i < seminfo.semmni; i++) {
			if ((sema[i].sem_perm.mode & SEM_ALLOC) &&
			    sema[i].sem_base > semaptr->sem_base)
				sema[i].sem_base -= semaptr->sem_nsems;
		}
		semaptr->sem_perm.mode = 0;
		semundo_clear(semid, -1);
		wakeup((caddr_t)semaptr);
		break;

	case IPC_SET:
		if ((eval = ipcperm(cred, &semaptr->sem_perm, IPC_M)))
			UNLOCK_AND_RETURN(eval);
		/*if ((eval = copyin(arg, &real_arg, sizeof(real_arg))) != 0)
			UNLOCK_AND_RETURN(eval);*/
		if ((eval = copyin(arg.buf, (caddr_t)&sbuf,
		    sizeof(sbuf))) != 0)
			UNLOCK_AND_RETURN(eval);
		semaptr->sem_perm.uid = sbuf.sem_perm.uid;
		semaptr->sem_perm.gid = sbuf.sem_perm.gid;
		semaptr->sem_perm.mode = (semaptr->sem_perm.mode & ~0777) |
		    (sbuf.sem_perm.mode & 0777);
		semaptr->sem_ctime = time_second;
		break;

	case IPC_STAT:
		if ((eval = ipcperm(cred, &semaptr->sem_perm, IPC_R)))
			UNLOCK_AND_RETURN(eval);
		/*if ((eval = copyin(arg, &real_arg, sizeof(real_arg))) != 0)
			UNLOCK_AND_RETURN(eval);*/
		eval = copyout((caddr_t)semaptr, arg.buf,
		    sizeof(struct semid_ds));
		break;

	case GETNCNT:
		if ((eval = ipcperm(cred, &semaptr->sem_perm, IPC_R)))
			UNLOCK_AND_RETURN(eval);
		if (semnum < 0 || semnum >= semaptr->sem_nsems)
			UNLOCK_AND_RETURN(EINVAL);
		rval = semaptr->sem_base[semnum].semncnt;
		break;

	case GETPID:
		if ((eval = ipcperm(cred, &semaptr->sem_perm, IPC_R)))
			UNLOCK_AND_RETURN(eval);
		if (semnum < 0 || semnum >= semaptr->sem_nsems)
			UNLOCK_AND_RETURN(EINVAL);
		rval = semaptr->sem_base[semnum].sempid;
		break;

	case GETVAL:
		if ((eval = ipcperm(cred, &semaptr->sem_perm, IPC_R)))
			UNLOCK_AND_RETURN(eval);
		if (semnum < 0 || semnum >= semaptr->sem_nsems)
			UNLOCK_AND_RETURN(EINVAL);
		rval = semaptr->sem_base[semnum].semval;
		break;

	case GETALL:
		if ((eval = ipcperm(cred, &semaptr->sem_perm, IPC_R)))
			UNLOCK_AND_RETURN(eval);
		/*if ((eval = copyin(arg, &real_arg, sizeof(real_arg))) != 0)
			UNLOCK_AND_RETURN(eval);*/
		for (i = 0; i < semaptr->sem_nsems; i++) {
			eval = copyout((caddr_t)&semaptr->sem_base[i].semval,
			    &arg.array[i], sizeof(arg.array[0]));
			if (eval != 0)
				break;
		}
		break;

	case GETZCNT:
		if ((eval = ipcperm(cred, &semaptr->sem_perm, IPC_R)))
			UNLOCK_AND_RETURN(eval);
		if (semnum < 0 || semnum >= semaptr->sem_nsems)
			UNLOCK_AND_RETURN(EINVAL);
		rval = semaptr->sem_base[semnum].semzcnt;
		break;

	case SETVAL:
		if ((eval = ipcperm(cred, &semaptr->sem_perm, IPC_W)))
                {
#ifdef SEM_DEBUG
			printf("Invalid credentials for write\n");
#endif
			UNLOCK_AND_RETURN(eval);
		}
		if (semnum < 0 || semnum >= semaptr->sem_nsems)
		{
#ifdef SEM_DEBUG
			printf("Invalid number out of range for set\n");
#endif
			UNLOCK_AND_RETURN(EINVAL);
		}
		/*if ((eval = copyin(arg, &real_arg, sizeof(real_arg))) != 0)
		{
#ifdef SEM_DEBUG
			printf("Error during value copyin\n");
#endif
			UNLOCK_AND_RETURN(eval);
		}*/
		semaptr->sem_base[semnum].semval = arg.val;
		semundo_clear(semid, semnum);
		wakeup((caddr_t)semaptr);
		break;

	case SETALL:
		if ((eval = ipcperm(cred, &semaptr->sem_perm, IPC_W)))
			UNLOCK_AND_RETURN(eval);
		/*if ((eval = copyin(arg, &real_arg, sizeof(real_arg))) != 0)
			UNLOCK_AND_RETURN(eval);*/
		for (i = 0; i < semaptr->sem_nsems; i++) {
			eval = copyin(&arg.array[i],
			    (caddr_t)&semaptr->sem_base[i].semval,
			    sizeof(arg.array[0]));
			if (eval != 0)
				break;
		}
		semundo_clear(semid, -1);
		wakeup((caddr_t)semaptr);
		break;

	default:
		UNLOCK_AND_RETURN(EINVAL);
	}

	if (eval == 0)
		*retval = rval;
	UNLOCK_AND_RETURN(eval);
}

#ifndef _SYS_SYSPROTO_H_
struct semget_args {
	key_t	key;
	int	nsems;
	int	semflg;
};
#endif

int
semget(p, uap, retval)
	struct proc *p;
	register struct semget_args *uap;
	register_t *retval;
{
	int semid, eval;
	int key = uap->key;
	int nsems = uap->nsems;
	int semflg = uap->semflg;
	struct ucred *cred = p->p_ucred;

	SUBSYSTEM_LOCK_AQUIRE(p);
#ifdef SEM_DEBUG
	if (key != IPC_PRIVATE)
		printf("semget(0x%x, %d, 0%o)\n", key, nsems, semflg);
	else
		printf("semget(IPC_PRIVATE, %d, 0%o)\n", nsems, semflg);
#endif
    
	if (key != IPC_PRIVATE) {
		for (semid = 0; semid < seminfo.semmni; semid++) {
			if ((sema[semid].sem_perm.mode & SEM_ALLOC) &&
			    sema[semid].sem_perm.key == key)
				break;
		}
		if (semid < seminfo.semmni) {
#ifdef SEM_DEBUG
			printf("found public key\n");
#endif
			if ((eval = ipcperm(cred, &sema[semid].sem_perm,
			    semflg & 0700)))
				UNLOCK_AND_RETURN(eval);
			if (nsems > 0 && sema[semid].sem_nsems < nsems) {
#ifdef SEM_DEBUG
				printf("too small\n");
#endif
				UNLOCK_AND_RETURN(EINVAL);
			}
			if ((semflg & IPC_CREAT) && (semflg & IPC_EXCL)) {
#ifdef SEM_DEBUG
				printf("not exclusive\n");
#endif
				UNLOCK_AND_RETURN(EEXIST);
			}
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
			UNLOCK_AND_RETURN(EINVAL);
		}
		if (nsems > seminfo.semmns - semtot) {
#ifdef SEM_DEBUG
			printf("not enough semaphores left (need %d, got %d)\n",
			    nsems, seminfo.semmns - semtot);
#endif
			if (!grow_sem_array(semtot + nsems))
			{
#ifdef SEM_DEBUG
				printf("failed to grow the sem array\n");
#endif
				UNLOCK_AND_RETURN(ENOSPC);
			}
		}
		for (semid = 0; semid < seminfo.semmni; semid++) {
			if ((sema[semid].sem_perm.mode & SEM_ALLOC) == 0)
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
				UNLOCK_AND_RETURN(ENOSPC);
			}
		}
#ifdef SEM_DEBUG
		printf("semid %d is available\n", semid);
#endif
		sema[semid].sem_perm.key = key;
		sema[semid].sem_perm.cuid = cred->cr_uid;
		sema[semid].sem_perm.uid = cred->cr_uid;
		sema[semid].sem_perm.cgid = cred->cr_gid;
		sema[semid].sem_perm.gid = cred->cr_gid;
		sema[semid].sem_perm.mode = (semflg & 0777) | SEM_ALLOC;
		sema[semid].sem_perm.seq =
		    (sema[semid].sem_perm.seq + 1) & 0x7fff;
		sema[semid].sem_nsems = nsems;
		sema[semid].sem_otime = 0;
		sema[semid].sem_ctime = time_second;
		sema[semid].sem_base = &sem[semtot];
		semtot += nsems;
		bzero(sema[semid].sem_base,
		    sizeof(sema[semid].sem_base[0])*nsems);
#ifdef SEM_DEBUG
		printf("sembase = 0x%x, next = 0x%x\n", sema[semid].sem_base,
		    &sem[semtot]);
#endif
	} else {
#ifdef SEM_DEBUG
		printf("didn't find it and wasn't asked to create it\n");
#endif
		UNLOCK_AND_RETURN(ENOENT);
	}

found:
	*retval = IXSEQ_TO_IPCID(semid, sema[semid].sem_perm);
	AUDIT_ARG(svipc_id, *retval);
#ifdef SEM_DEBUG
	printf("semget is done, returning %d\n", *retval);
#endif
	SUBSYSTEM_LOCK_RELEASE;
	return(0);
}

#ifndef _SYS_SYSPROTO_H_
struct semop_args {
	int	semid;
	struct	sembuf *sops;
	int	nsops;
};
#endif

int
semop(p, uap, retval)
	struct proc *p;
	register struct semop_args *uap;
	register_t *retval;
{
	int semid = uap->semid;
	int nsops = uap->nsops;
	struct sembuf sops[MAX_SOPS];
	register struct semid_ds *semaptr;
	register struct sembuf *sopptr;
	register struct sem *semptr;
	struct sem_undo *suptr = NULL;
	struct ucred *cred = p->p_ucred;
	int i, j, eval;
	int do_wakeup, do_undos;

	AUDIT_ARG(svipc_id, uap->semid);
	SUBSYSTEM_LOCK_AQUIRE(p);
#ifdef SEM_DEBUG
	printf("call to semop(%d, 0x%x, %d)\n", semid, sops, nsops);
#endif

	semid = IPCID_TO_IX(semid);	/* Convert back to zero origin */

	if (semid < 0 || semid >= seminfo.semmni)
		UNLOCK_AND_RETURN(EINVAL);

	semaptr = &sema[semid];
	if ((semaptr->sem_perm.mode & SEM_ALLOC) == 0)
		UNLOCK_AND_RETURN(EINVAL);
	if (semaptr->sem_perm.seq != IPCID_TO_SEQ(uap->semid))
		UNLOCK_AND_RETURN(EINVAL);

	if ((eval = ipcperm(cred, &semaptr->sem_perm, IPC_W))) {
#ifdef SEM_DEBUG
		printf("eval = %d from ipaccess\n", eval);
#endif
		UNLOCK_AND_RETURN(eval);
	}

	if (nsops < 0 || nsops > MAX_SOPS) {
#ifdef SEM_DEBUG
		printf("too many sops (max=%d, nsops=%d)\n", MAX_SOPS, nsops);
#endif
		UNLOCK_AND_RETURN(E2BIG);
	}

	if ((eval = copyin(uap->sops, &sops, nsops * sizeof(sops[0]))) != 0) {
#ifdef SEM_DEBUG
		printf("eval = %d from copyin(%08x, %08x, %ld)\n", eval,
		    uap->sops, &sops, nsops * sizeof(sops[0]));
#endif
		UNLOCK_AND_RETURN(eval);
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

			if (sopptr->sem_num >= semaptr->sem_nsems)
				UNLOCK_AND_RETURN(EFBIG);

			semptr = &semaptr->sem_base[sopptr->sem_num];

#ifdef SEM_DEBUG
			printf("semop:  semaptr=%x, sem_base=%x, semptr=%x, sem[%d]=%d : op=%d, flag=%s\n",
			    semaptr, semaptr->sem_base, semptr,
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
			semaptr->sem_base[sops[j].sem_num].semval -=
			    sops[j].sem_op;

		/*
		 * If the request that we couldn't satisfy has the
		 * NOWAIT flag set then return with EAGAIN.
		 */
		if (sopptr->sem_flg & IPC_NOWAIT)
			UNLOCK_AND_RETURN(EAGAIN);

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
		SUBSYSTEM_LOCK_RELEASE;
                sysv_sem_sleeping_threads++;
		eval = tsleep((caddr_t)semaptr, (PZERO - 4) | PCATCH,
		    "semwait", 0);
                sysv_sem_sleeping_threads--;
                
#ifdef SEM_DEBUG
		printf("semop:  good morning (eval=%d)!\n", eval);
#endif
		/* There is no need to get the lock if we are just
		 * going to return without performing more semaphore
		 * operations.
		 */
		if (eval != 0)
			return(EINTR);

		SUBSYSTEM_LOCK_AQUIRE(p);	/* Get it back */
		suptr = NULL;	/* sem_undo may have been reallocated */
	 	semaptr = &sema[semid];	   /* sema may have been reallocated */


#ifdef SEM_DEBUG
		printf("semop:  good morning!\n");
#endif

		/*
		 * Make sure that the semaphore still exists
		 */
		if ((semaptr->sem_perm.mode & SEM_ALLOC) == 0 ||
		    semaptr->sem_perm.seq != IPCID_TO_SEQ(uap->semid)) {
			/* The man page says to return EIDRM. */
			/* Unfortunately, BSD doesn't define that code! */
#ifdef EIDRM
			UNLOCK_AND_RETURN(EIDRM);
#else
			UNLOCK_AND_RETURN(EINVAL);
#endif
		}

		/*
		 * The semaphore is still alive.  Readjust the count of
		 * waiting processes. semptr needs to be recomputed
		 * because the sem[] may have been reallocated while
		 * we were sleeping, updating our sem_base pointer.
		 */
		semptr = &semaptr->sem_base[sopptr->sem_num];
		if (sopptr->sem_op == 0)
			semptr->semzcnt--;
		else
			semptr->semncnt--;
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
			eval = semundo_adjust(p, &suptr, semid,
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
				if (semundo_adjust(p, &suptr, semid,
				    sops[j].sem_num, adjval) != 0)
					panic("semop - can't undo undos");
			}

			for (j = 0; j < nsops; j++)
				semaptr->sem_base[sops[j].sem_num].semval -=
				    sops[j].sem_op;

#ifdef SEM_DEBUG
			printf("eval = %d from semundo_adjust\n", eval);
#endif
			UNLOCK_AND_RETURN(eval);
		} /* loop through the sops */
	} /* if (do_undos) */

	/* We're definitely done - set the sempid's */
	for (i = 0; i < nsops; i++) {
		sopptr = &sops[i];
		semptr = &semaptr->sem_base[sopptr->sem_num];
		semptr->sempid = p->p_pid;
	}

	/* Do a wakeup if any semaphore was up'd.
	 *  we will release our lock on the semaphore subsystem before
	 *  we wakeup other processes to prevent a little thrashing.
	 *  Note that this is fine because we are done using the
	 *  semaphore structures at this point in time.  We only use
	 *  a local variable pointer value, and the retval
	 *  parameter.
	 *  Note 2: Future use of sem_wakeup may reqiure the lock.
	 */
	SUBSYSTEM_LOCK_RELEASE;
	if (do_wakeup) {
#ifdef SEM_DEBUG
		printf("semop:  doing wakeup\n");
#ifdef SEM_WAKEUP
		sem_wakeup((caddr_t)semaptr);
#else
		wakeup((caddr_t)semaptr);
#endif
		printf("semop:  back from wakeup\n");
#else
		wakeup((caddr_t)semaptr);
#endif
	}
#ifdef SEM_DEBUG
	printf("semop:  done\n");
#endif
	*retval = 0;
	return(0);
}

/*
 * Go through the undo structures for this process and apply the adjustments to
 * semaphores.
 */
void
semexit(p)
	struct proc *p;
{
	register struct sem_undo *suptr;
	register struct sem_undo **supptr;
	int did_something;

	/* If we have not allocated our semaphores yet there can't be
	 * anything to undo, but we need the lock to prevent
	 * dynamic memory race conditions.
	 */
	SUBSYSTEM_LOCK_AQUIRE(p);
	if (!sem)
	{
		SUBSYSTEM_LOCK_RELEASE;
		return;
	}
	did_something = 0;

	/*
	 * Go through the chain of undo vectors looking for one
	 * associated with this process.
	 */

	for (supptr = &semu_list; (suptr = *supptr) != NULL;
	    supptr = &suptr->un_next) {
		if (suptr->un_proc == p)
			break;
	}

	if (suptr == NULL)
		goto unlock;

#ifdef SEM_DEBUG
	printf("proc @%08x has undo structure with %d entries\n", p,
	    suptr->un_cnt);
#endif

	/*
	 * If there are any active undo elements then process them.
	 */
	if (suptr->un_cnt > 0) {
		int ix;

		for (ix = 0; ix < suptr->un_cnt; ix++) {
			int semid = suptr->un_ent[ix].un_id;
			int semnum = suptr->un_ent[ix].un_num;
			int adjval = suptr->un_ent[ix].un_adjval;
			struct semid_ds *semaptr;

			semaptr = &sema[semid];
			if ((semaptr->sem_perm.mode & SEM_ALLOC) == 0)
				panic("semexit - semid not allocated");
			if (semnum >= semaptr->sem_nsems)
				panic("semexit - semnum out of range");

#ifdef SEM_DEBUG
			printf("semexit:  %08x id=%d num=%d(adj=%d) ; sem=%d\n",
			    suptr->un_proc, suptr->un_ent[ix].un_id,
			    suptr->un_ent[ix].un_num,
			    suptr->un_ent[ix].un_adjval,
			    semaptr->sem_base[semnum].semval);
#endif

			if (adjval < 0) {
				if (semaptr->sem_base[semnum].semval < -adjval)
					semaptr->sem_base[semnum].semval = 0;
				else
					semaptr->sem_base[semnum].semval +=
					    adjval;
			} else
				semaptr->sem_base[semnum].semval += adjval;

		/* Maybe we should build a list of semaptr's to wake
		 * up, finish all access to data structures, release the
		 * subsystem lock, and wake all the processes.  Something
		 * to think about.  It wouldn't buy us anything unless
		 * wakeup had the potential to block, or the syscall
		 * funnel state was changed to allow multiple threads
		 * in the BSD code at once.
		 */
#ifdef SEM_WAKEUP
			sem_wakeup((caddr_t)semaptr);
#else
			wakeup((caddr_t)semaptr);
#endif
#ifdef SEM_DEBUG
			printf("semexit:  back from wakeup\n");
#endif
		}
	}

	/*
	 * Deallocate the undo vector.
	 */
#ifdef SEM_DEBUG
	printf("removing vector\n");
#endif
	suptr->un_proc = NULL;
	*supptr = suptr->un_next;

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

	SUBSYSTEM_LOCK_RELEASE;
}
/* (struct sysctl_oid *oidp, void *arg1, int arg2, \
        struct sysctl_req *req) */
static int
sysctl_seminfo SYSCTL_HANDLER_ARGS
{
	int error = 0;

	error = SYSCTL_OUT(req, arg1, sizeof(int));
	if (error || !req->newptr)
		return(error);

	SUBSYSTEM_LOCK_AQUIRE(current_proc());
	/* Set the values only if shared memory is not initialised */
	if ((sem == (struct sem *) 0) && 
		(sema == (struct semid_ds *) 0) && 
		(semu == (struct semid_ds *) 0) && 
		(semu_list == (struct sem_undo *) 0)) {
			if (error = SYSCTL_IN(req, arg1, sizeof(int))) {
				goto out;
			}
	} else 
		error = EINVAL;
out:
	SUBSYSTEM_LOCK_RELEASE;
	return(error);
	
}

/* SYSCTL_NODE(_kern, KERN_SYSV, sysv, CTLFLAG_RW, 0, "SYSV"); */
extern struct sysctl_oid_list sysctl__kern_sysv_children;
SYSCTL_PROC(_kern_sysv, KSYSV_SEMMNI, semmni, CTLTYPE_INT | CTLFLAG_RW,
    &limitseminfo.semmni, 0, &sysctl_seminfo ,"I","semmni");

SYSCTL_PROC(_kern_sysv, KSYSV_SEMMNS, semmns, CTLTYPE_INT | CTLFLAG_RW,
    &limitseminfo.semmns, 0, &sysctl_seminfo ,"I","semmns");

SYSCTL_PROC(_kern_sysv, KSYSV_SEMMNU, semmnu, CTLTYPE_INT | CTLFLAG_RW,
    &limitseminfo.semmnu, 0, &sysctl_seminfo ,"I","semmnu");

SYSCTL_PROC(_kern_sysv, KSYSV_SEMMSL, semmsl, CTLTYPE_INT | CTLFLAG_RW,
    &limitseminfo.semmsl, 0, &sysctl_seminfo ,"I","semmsl");
    
SYSCTL_PROC(_kern_sysv, KSYSV_SEMUNE, semume, CTLTYPE_INT | CTLFLAG_RW,
    &limitseminfo.semume, 0, &sysctl_seminfo ,"I","semume");


