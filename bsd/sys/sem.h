/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/*	$NetBSD: sem.h,v 1.5 1994/06/29 06:45:15 cgd Exp $	*/

/*
 * SVID compatible sem.h file
 *
 * Author:  Daniel Boulet
 */
/*
 * John Bellardo modified the implementation for Darwin. 12/2000
 */

#ifndef _SYS_SEM_H_
#define _SYS_SEM_H_

#include <sys/appleapiopts.h>
#include <sys/ipc.h>

struct sem {
	u_short	semval;		/* semaphore value */
	pid_t	sempid;		/* pid of last operation */
	u_short	semncnt;	/* # awaiting semval > cval */
	u_short	semzcnt;	/* # awaiting semval = 0 */
};

struct semid_ds {
	struct	ipc_perm sem_perm;	/* operation permission struct */
	struct	sem *sem_base;	/* pointer to first semaphore in set */
	u_short	sem_nsems;	/* number of sems in set */
	time_t	sem_otime;	/* last operation time */
	long	sem_pad1;	/* SVABI/386 says I need this here */
	time_t	sem_ctime;	/* last change time */
    				/* Times measured in secs since */
    				/* 00:00:00 GMT, Jan. 1, 1970 */
	long	sem_pad2;	/* SVABI/386 says I need this here */
	long	sem_pad3[4];	/* SVABI/386 says I need this here */
};

/*
 * semop's sops parameter structure
 */
struct sembuf {
	u_short	sem_num;	/* semaphore # */
	short	sem_op;		/* semaphore operation */
	short	sem_flg;	/* operation flags */
};
#define SEM_UNDO	010000

#define MAX_SOPS	5	/* maximum # of sembuf's per semop call */

/*
 * semctl's arg parameter structure
 */
union semun {
	int	val;		/* value for SETVAL */
	struct	semid_ds *buf;	/* buffer for IPC_STAT & IPC_SET */
	u_short	*array;		/* array for GETALL & SETALL */
};

/*
 * commands for semctl
 */
#define GETNCNT	3	/* Return the value of semncnt {READ} */
#define GETPID	4	/* Return the value of sempid {READ} */
#define GETVAL	5	/* Return the value of semval {READ} */
#define GETALL	6	/* Return semvals into arg.array {READ} */
#define GETZCNT	7	/* Return the value of semzcnt {READ} */
#define SETVAL	8	/* Set the value of semval to arg.val {ALTER} */
#define SETALL	9	/* Set semvals from arg.array {ALTER} */

/*
 * Permissions
 */
#define SEM_A		0200	/* alter permission */
#define SEM_R		0400	/* read permission */

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE
/*
 * Kernel implementation stuff
 */
#define SEMVMX	32767		/* semaphore maximum value */
#define SEMAEM	16384		/* adjust on exit max value */

/*
 * Configuration parameters.  SEMMNI, SEMMNS, and SEMMNU are hard limits.
 * The code dynamically allocates enough memory to satisfy the current
 * demand in even increments of SEMMNI_INC, SEMMNS_INC, and SEMMNU_INC.
 * The code will never allocate more than the hard limits.  The *_INC's
 * are defined in the kernel section of the header.
 */
/*
 * Configuration parameters
 */
#ifndef SEMMNS			/* # of semaphores in system */
#define SEMMNS	(1048576/sizeof(struct sem))
#endif				/* no more than 1M of semaphore data */
#ifndef SEMMNI			/* # of semaphore identifiers */
#define SEMMNI	SEMMNS		/* max of 1 for each semaphore */
#endif
#ifndef SEMUME
#define SEMUME	10		/* max # of undo entries per process */
#endif
#ifndef SEMMNU			/* # of undo structures in system */
#define SEMMNU	SEMMNS		/* 1 for each semaphore.  This is quite large */
#endif				/* This should be max 1 for each process */

/* shouldn't need tuning */
#ifndef SEMMAP
#define SEMMAP	30		/* # of entries in semaphore map */
#endif
#ifndef SEMMSL
#define SEMMSL	SEMMNS		/* max # of semaphores per id */
#endif
#ifndef SEMOPM
#define SEMOPM	100		/* max # of operations per semop call */
#endif


/*
 * Undo structure (one per process)
 */
struct sem_undo {
	struct	sem_undo *un_next;	/* ptr to next active undo structure */
	struct	proc *un_proc;		/* owner of this structure */
	short	un_cnt;			/* # of active entries */
	struct undo {
		short	un_adjval;	/* adjust on exit values */
		short	un_num;		/* semaphore # */
		int	un_id;		/* semid */
	} un_ent[SEMUME];		/* undo entries */
};

/*
 * semaphore info struct
 */
struct seminfo {
	int	semmap,		/* # of entries in semaphore map */
		semmni,		/* # of semaphore identifiers */
		semmns,		/* # of semaphores in system */
		semmnu,		/* # of undo structures in system */
		semmsl,		/* max # of semaphores per id */
		semopm,		/* max # of operations per semop call */
		semume,		/* max # of undo entries per process */
		semusz,		/* size in bytes of undo structure */
		semvmx,		/* semaphore maximum value */
		semaem;		/* adjust on exit max value */
};
extern struct seminfo	seminfo;

/* internal "mode" bits */
#define	SEM_ALLOC	01000	/* semaphore is allocated */
#define	SEM_DEST	02000	/* semaphore will be destroyed on last detach */

#define SEMMNI_INC	8	/* increment value for semaphore identifiers */
#define SEMMNS_INC	64	/* increment value for semaphores */
#define SEMMNU_INC	32	/* increment value for undo structures */

/*
 * Due to the way semaphore memory is allocated, we have to ensure that
 * SEMUSZ is properly aligned.
 *
 * We are not doing strange semaphore memory allocation anymore, so
 * these macros are no longer needed.
 */

/*
 * #define SEM_ALIGN(bytes) (((bytes) + (sizeof(long) - 1)) & ~(sizeof(long) - 1))
 */

/* actual size of an undo structure */
/*
 * #define SEMUSZ	SEM_ALIGN(offsetof(struct sem_undo, un_ent[SEMUME]))
 */
#define SEMUSZ		sizeof(struct sem_undo)

extern struct semid_ds *sema;	/* semaphore id pool */
extern struct sem *sem;		/* semaphore pool */
/* This is now a struct sem_undo with the new memory allocation 
 * extern int	*semu;		/* undo structure pool
 */
extern struct sem_undo	*semu;		/* undo structure pool */

/*
 * Macro to find a particular sem_undo vector
 */
/* Until we can initialize seminfo.semusz to SEMUSZ, we hard code the size macro
 * in SEMU.  This should be fixed when (if) we implement dynamic pool sizes
 *
 * #define SEMU(ix)     ((struct sem_undo *)(((intptr_t)semu)+ix * seminfo.semusz))
 */
/*
 * This macro doesn't work because we are using a staticly allocated array
 * for semu now.
 * #define SEMU(ix)        ((struct sem_undo *)(((intptr_t)semu)+ix * SEMUSZ)) 
 */
#define SEMU(ix)        (&semu[ix])


/*
 * Process sem_undo vectors at proc exit.
 */
void	semexit __P((struct proc *p));

/*
 * Parameters to the semconfig system call
 */
typedef enum {
	SEM_CONFIG_FREEZE,	/* Freeze the semaphore facility. */
	SEM_CONFIG_THAW		/* Thaw the semaphore facility. */
} semconfig_ctl_t;

#endif /* __APPLE_API_PRIVATE */

#endif /* KERNEL */

#ifndef KERNEL
#include <sys/cdefs.h>

__BEGIN_DECLS
int semsys __P((int, ...));
int semctl __P((int, int, int, ...));
int semget __P((key_t, int, int));
int semop __P((int, struct sembuf *,unsigned));
__END_DECLS
#endif /* !KERNEL */

#endif /* !_SEM_H_ */
