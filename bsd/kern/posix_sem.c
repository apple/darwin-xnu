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
 *	Copyright (c) 1990, 1996-1998 Apple Computer, Inc.
 *	All Rights Reserved.
 */
/*
 * posix_shm.c : Support for POSIX semaphore APIs
 *
 *	File:	posix_sem.c
 *	Author:	Ananthakrishna Ramesh
 *
 * HISTORY
 * 2-Sep-1999	A.Ramesh
 *	Created for MacOSX
 *
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/file_internal.h>
#include <sys/filedesc.h>
#include <sys/stat.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/malloc.h>
#include <sys/semaphore.h>
#include <sys/sysproto.h>
#include <sys/proc_info.h>

#include <bsm/audit_kernel.h>

#include <mach/mach_types.h>
#include <mach/vm_prot.h>
#include <mach/semaphore.h>
#include <mach/sync_policy.h>
#include <mach/task.h>
#include <kern/kern_types.h>
#include <kern/task.h>
#include <kern/clock.h>
#include <mach/kern_return.h>

#if KTRACE
#include <sys/ktrace.h>
#endif

#define f_flag f_fglob->fg_flag
#define f_type f_fglob->fg_type
#define f_msgcount f_fglob->fg_msgcount
#define f_cred f_fglob->fg_cred
#define f_ops f_fglob->fg_ops
#define f_offset f_fglob->fg_offset
#define f_data f_fglob->fg_data
#define	PSEMNAMLEN	31	/* maximum name segment length we bother with */

struct pseminfo {
	unsigned int	psem_flags;
	unsigned int	psem_usecount;
	mode_t		psem_mode;
	uid_t		psem_uid;
	gid_t		psem_gid;
	char		psem_name[PSEMNAMLEN + 1];	/* segment name */
	semaphore_t	psem_semobject;
	struct proc *	sem_proc;
};
#define PSEMINFO_NULL (struct pseminfo *)0

#define	PSEM_NONE	1
#define	PSEM_DEFINED	2
#define	PSEM_ALLOCATED	4
#define	PSEM_MAPPED	8
#define	PSEM_INUSE	0x10
#define	PSEM_REMOVED	0x20
#define	PSEM_INCREATE	0x40
#define	PSEM_INDELETE	0x80

struct	psemcache {
	LIST_ENTRY(psemcache) psem_hash;	/* hash chain */
	struct	pseminfo *pseminfo;		/* vnode the name refers to */
	int	psem_nlen;		/* length of name */
	char	psem_name[PSEMNAMLEN + 1];	/* segment name */
};
#define PSEMCACHE_NULL (struct psemcache *)0

struct	psemstats {
	long	goodhits;		/* hits that we can really use */
	long	neghits;		/* negative hits that we can use */
	long	badhits;		/* hits we must drop */
	long	falsehits;		/* hits with id mismatch */
	long	miss;		/* misses */
	long	longnames;		/* long names that ignore cache */
};

struct psemname {
	char	*psem_nameptr;	/* pointer to looked up name */
	long	psem_namelen;	/* length of looked up component */
	u_long	psem_hash;	/* hash value of looked up name */
};

struct psemnode {
	struct pseminfo *pinfo;
#if DIAGNOSTIC
	unsigned int readcnt;
	unsigned int writecnt;
#endif
};
#define PSEMNODE_NULL (struct psemnode *)0


#define PSEMHASH(pnp) \
	(&psemhashtbl[(pnp)->psem_hash & psemhash])
LIST_HEAD(psemhashhead, psemcache) *psemhashtbl;	/* Hash Table */
u_long	psemhash;				/* size of hash table - 1 */
long	psemnument;			/* number of cache entries allocated */
long	posix_sem_max = 10000;		/* tunable for max POSIX semaphores */
					/* 10000 limits to ~1M of memory */
SYSCTL_NODE(_kern, KERN_POSIX, posix, CTLFLAG_RW,  0, "Posix");
SYSCTL_NODE(_kern_posix, OID_AUTO, sem, CTLFLAG_RW, 0, "Semaphores");
SYSCTL_INT (_kern_posix_sem, OID_AUTO, max, CTLFLAG_RW, &posix_sem_max, 0, "max");

struct psemstats psemstats;		/* cache effectiveness statistics */

static int psem_access(struct pseminfo *pinfo, int mode, kauth_cred_t cred);
static int psem_cache_search(struct pseminfo **,
				struct psemname *, struct psemcache **);
static int psem_delete(struct pseminfo * pinfo);

static int psem_read (struct fileproc *fp, struct uio *uio,
			    kauth_cred_t cred, int flags, struct proc *p);
static int psem_write (struct fileproc *fp, struct uio *uio,
			    kauth_cred_t cred, int flags, struct proc *p);
static int psem_ioctl (struct fileproc *fp, u_long com,
			    caddr_t data, struct proc *p);
static int psem_select (struct fileproc *fp, int which, void *wql, struct proc *p);
static int psem_closefile (struct fileglob *fp, struct proc *p);

static int psem_kqfilter (struct fileproc *fp, struct knote *kn, struct proc *p);

struct 	fileops psemops =
	{ psem_read, psem_write, psem_ioctl, psem_select, psem_closefile, psem_kqfilter, 0 };


static lck_grp_t       *psx_sem_subsys_lck_grp;
static lck_grp_attr_t  *psx_sem_subsys_lck_grp_attr;
static lck_attr_t      *psx_sem_subsys_lck_attr;
static lck_mtx_t        psx_sem_subsys_mutex;

#define PSEM_SUBSYS_LOCK() lck_mtx_lock(& psx_sem_subsys_mutex)
#define PSEM_SUBSYS_UNLOCK() lck_mtx_unlock(& psx_sem_subsys_mutex)


static int psem_cache_add(struct pseminfo *psemp, struct psemname *pnp, struct psemcache *pcp);
/* Initialize the mutex governing access to the posix sem subsystem */
__private_extern__ void
psem_lock_init( void )
{

    psx_sem_subsys_lck_grp_attr = lck_grp_attr_alloc_init();

    psx_sem_subsys_lck_grp = lck_grp_alloc_init("posix shared memory", psx_sem_subsys_lck_grp_attr);

    psx_sem_subsys_lck_attr = lck_attr_alloc_init();
    lck_mtx_init(& psx_sem_subsys_mutex, psx_sem_subsys_lck_grp, psx_sem_subsys_lck_attr);
}

/*
 * Lookup an entry in the cache 
 * 
 * 
 * status of -1 is returned if matches
 * If the lookup determines that the name does not exist
 * (negative cacheing), a status of ENOENT is returned. If the lookup
 * fails, a status of zero is returned.
 */

static int
psem_cache_search(psemp, pnp, pcache)
	struct pseminfo **psemp;
	struct psemname *pnp;
	struct psemcache **pcache;
{
	struct psemcache *pcp, *nnp;
	struct psemhashhead *pcpp;

	if (pnp->psem_namelen > PSEMNAMLEN) {
		psemstats.longnames++;
		return (0);
	}

	pcpp = PSEMHASH(pnp);
	for (pcp = pcpp->lh_first; pcp != 0; pcp = nnp) {
		nnp = pcp->psem_hash.le_next;
		if (pcp->psem_nlen == pnp->psem_namelen &&
		    !bcmp(pcp->psem_name, pnp->psem_nameptr, 						(u_int)pcp-> psem_nlen))
			break;
	}

	if (pcp == 0) {
		psemstats.miss++;
		return (0);
	}

	/* We found a "positive" match, return the vnode */
        if (pcp->pseminfo) {
		psemstats.goodhits++;
		/* TOUCH(ncp); */
		*psemp = pcp->pseminfo;
		*pcache = pcp;
		return (-1);
	}

	/*
	 * We found a "negative" match, ENOENT notifies client of this match.
	 * The nc_vpid field records whether this is a whiteout.
	 */
	psemstats.neghits++;
	return (ENOENT);
}

/*
 * Add an entry to the cache.
 */
static int
psem_cache_add(struct pseminfo *psemp, struct psemname *pnp, struct psemcache *pcp)
{
	struct psemhashhead *pcpp;
	struct pseminfo *dpinfo;
	struct psemcache *dpcp;

#if DIAGNOSTIC
	if (pnp->psem_namelen > NCHNAMLEN)
		panic("cache_enter: name too long");
#endif


	/*  if the entry has already been added by some one else return */
	if (psem_cache_search(&dpinfo, pnp, &dpcp) == -1) {
		return(EEXIST);
	}
	if (psemnument >= posix_sem_max)
		return(ENOSPC);
	psemnument++;
	/*
	 * Fill in cache info, if vp is NULL this is a "negative" cache entry.
	 * For negative entries, we have to record whether it is a whiteout.
	 * the whiteout flag is stored in the nc_vpid field which is
	 * otherwise unused.
	 */
	pcp->pseminfo = psemp;
	pcp->psem_nlen = pnp->psem_namelen;
	bcopy(pnp->psem_nameptr, pcp->psem_name, (unsigned)pcp->psem_nlen);
	pcpp = PSEMHASH(pnp);
#if DIAGNOSTIC
	{
		struct psemcache *p;

		for (p = pcpp->lh_first; p != 0; p = p->psem_hash.le_next)
			if (p == pcp)
				panic("psem:cache_enter duplicate");
	}
#endif
	LIST_INSERT_HEAD(pcpp, pcp, psem_hash);
	return(0);
}

/*
 * Name cache initialization, from vfs_init() when we are booting
 */
void
psem_cache_init(void)
{
	psemhashtbl = hashinit(desiredvnodes, M_SHM, &psemhash);
}

static void
psem_cache_delete(struct psemcache *pcp)
{
#if DIAGNOSTIC
	if (pcp->psem_hash.le_prev == 0)
		panic("psem namecache purge le_prev");
	if (pcp->psem_hash.le_next == pcp)
		panic("namecache purge le_next");
#endif /* DIAGNOSTIC */
	LIST_REMOVE(pcp, psem_hash);
	pcp->psem_hash.le_prev = 0;	
	psemnument--;
}

#if NOT_USED
/*
 * Invalidate a all entries to particular vnode.
 * 
 * We actually just increment the v_id, that will do it. The entries will
 * be purged by lookup as they get found. If the v_id wraps around, we
 * need to ditch the entire cache, to avoid confusion. No valid vnode will
 * ever have (v_id == 0).
 */
static void
psem_cache_purge(void)
{
	struct psemcache *pcp;
	struct psemhashhead *pcpp;

	for (pcpp = &psemhashtbl[psemhash]; pcpp >= psemhashtbl; pcpp--) {
		while ( (pcp = pcpp->lh_first) )
			psem_cache_delete(pcp);
	}
}
#endif	/* NOT_USED */

int
sem_open(struct proc *p, struct sem_open_args *uap, user_addr_t *retval)
{
	struct fileproc *fp;
	size_t i;
	struct fileproc *nfp;
	int indx, error;
	struct psemname nd;
	struct pseminfo *pinfo;
	struct psemcache *pcp;
	char * pnbuf;
	char * nameptr;
	char * cp;
	size_t pathlen, plen;
	int fmode ;
	int cmode = uap->mode;
	int value = uap->value;
	int incache = 0;
	struct psemnode * pnode = PSEMNODE_NULL;
	struct psemcache * pcache = PSEMCACHE_NULL;
	kern_return_t kret = KERN_SUCCESS;
	int pinfo_alloc = 0;

	AUDIT_ARG(fflags, uap->oflag);
	AUDIT_ARG(mode, uap->mode);
	AUDIT_ARG(value, uap->value);

	pinfo = PSEMINFO_NULL;

	MALLOC_ZONE(pnbuf, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if (pnbuf == NULL)
		return(ENOSPC);

	pathlen = MAXPATHLEN;
	error = copyinstr(uap->name, pnbuf, MAXPATHLEN, &pathlen);
	if (error) {
		goto bad;
	}
	AUDIT_ARG(text, pnbuf);
	if ( (pathlen > PSEMNAMLEN) ) {
		error = ENAMETOOLONG;
		goto bad;
	}

#ifdef PSXSEM_NAME_RESTRICT
	nameptr = pnbuf;
	if (*nameptr == '/') {
		while (*(nameptr++) == '/') {
			plen--;
			error = EINVAL;
			goto bad;
		}
        } else {
		error = EINVAL;
		goto bad;
	}
#endif /* PSXSEM_NAME_RESTRICT */

	plen = pathlen;
	nameptr = pnbuf;
	nd.psem_nameptr = nameptr;
	nd.psem_namelen = plen;
	nd. psem_hash =0;

        for (cp = nameptr, i=1; *cp != 0 && i <= plen; i++, cp++) {
               nd.psem_hash += (unsigned char)*cp * i;
	}

#if KTRACE
	if (KTRPOINT(p, KTR_NAMEI))
		ktrnamei(p->p_tracep, nameptr);
#endif
	
	PSEM_SUBSYS_LOCK();
	error = psem_cache_search(&pinfo, &nd, &pcache);

	if (error == ENOENT) {
		PSEM_SUBSYS_UNLOCK();
		error = EINVAL;
		goto bad;

	}
	if (!error) {
		incache = 0;
	} else
		incache = 1;
	fmode = FFLAGS(uap->oflag);

	PSEM_SUBSYS_UNLOCK();
	error = falloc(p, &nfp, &indx);
	if (error)
		goto bad;

	PSEM_SUBSYS_LOCK();
	fp = nfp;
	cmode &=  ALLPERMS;

	if (((fmode & (O_CREAT | O_EXCL))==(O_CREAT | O_EXCL)) &&  incache) {
		/* sem exists and opened O_EXCL */
#if notyet
		if (pinfo->psem_flags & PSEM_INDELETE) {
		}
#endif 
		AUDIT_ARG(posix_ipc_perm, pinfo->psem_uid,
			pinfo->psem_gid, pinfo->psem_mode);
		PSEM_SUBSYS_UNLOCK();
		error = EEXIST;
		goto bad1;
	}
	if (((fmode & (O_CREAT | O_EXCL))== O_CREAT) &&  incache) {
		/* As per POSIX, O_CREAT has no effect */
		fmode &= ~O_CREAT;
	}

	if ( (fmode & O_CREAT) ) {
		if((value < 0) && (value > SEM_VALUE_MAX)) {
			PSEM_SUBSYS_UNLOCK();
			error = EINVAL;
			goto bad1;
		}
		PSEM_SUBSYS_UNLOCK();
		MALLOC(pinfo, struct pseminfo *, sizeof(struct pseminfo), M_SHM, M_WAITOK|M_ZERO);
		if (pinfo == NULL) {
			error = ENOSPC;
			goto bad1;
		}
		PSEM_SUBSYS_LOCK();

		pinfo_alloc = 1;
		pinfo->psem_flags = PSEM_DEFINED | PSEM_INCREATE;
		pinfo->psem_usecount = 1;
		pinfo->psem_mode = cmode;
		pinfo->psem_uid = kauth_cred_getuid(kauth_cred_get());
		pinfo->psem_gid = kauth_cred_get()->cr_gid;
		bcopy(pnbuf, &pinfo->psem_name[0], PSEMNAMLEN);
		pinfo->psem_name[PSEMNAMLEN]= 0;
		PSEM_SUBSYS_UNLOCK();
   		kret = semaphore_create(kernel_task, &pinfo->psem_semobject,
                            SYNC_POLICY_FIFO, value);
		if(kret != KERN_SUCCESS) 
			goto bad3;
		PSEM_SUBSYS_LOCK();
		pinfo->psem_flags &= ~PSEM_DEFINED;
		pinfo->psem_flags |= PSEM_ALLOCATED;
		pinfo->sem_proc = p;
	} else {
		/* semaphore should exist as it is without  O_CREAT */
		if (!incache) {
			PSEM_SUBSYS_UNLOCK();
			error = ENOENT;
			goto bad1;
		}
		if( pinfo->psem_flags & PSEM_INDELETE) {
			PSEM_SUBSYS_UNLOCK();
			error = ENOENT;
			goto bad1;
		}	
		AUDIT_ARG(posix_ipc_perm, pinfo->psem_uid,
			pinfo->psem_gid, pinfo->psem_mode);
		if ( (error = psem_access(pinfo, fmode, kauth_cred_get())) ) {
			PSEM_SUBSYS_UNLOCK();
			goto bad1;
		}
	}
	PSEM_SUBSYS_UNLOCK();
	MALLOC(pnode, struct psemnode *, sizeof(struct psemnode), M_SHM, M_WAITOK|M_ZERO);
	if (pnode == NULL) {
		error = ENOSPC;
		goto bad1;
	}
	if (!incache) {
		/*
	 	* We allocate a new entry if we are less than the maximum
	 	* allowed and the one at the front of the LRU list is in use.
	 	* Otherwise we use the one at the front of the LRU list.
	 	*/
		MALLOC(pcp, struct psemcache *, sizeof(struct psemcache), M_SHM, M_WAITOK|M_ZERO);
		if (pcp == NULL) {
			error = ENOMEM;
			goto bad2;
		}

	}
	PSEM_SUBSYS_LOCK();
	if (!incache) {
		if ( (error = psem_cache_add(pinfo, &nd, pcp)) ) {
			PSEM_SUBSYS_UNLOCK();
			FREE(pcp, M_SHM);
			goto bad2;
		}
	}
	pinfo->psem_flags &= ~PSEM_INCREATE;
	pinfo->psem_usecount++;
	pnode->pinfo = pinfo;
	PSEM_SUBSYS_UNLOCK();

	proc_fdlock(p);
	fp->f_flag = fmode & FMASK;
	fp->f_type = DTYPE_PSXSEM;
	fp->f_ops = &psemops;
	fp->f_data = (caddr_t)pnode;
	procfdtbl_releasefd(p, indx, NULL);
	fp_drop(p, indx, fp, 1);
	proc_fdunlock(p);

	*retval = CAST_USER_ADDR_T(indx);
	FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	return (0);

bad3:
	switch (kret) {
	case KERN_RESOURCE_SHORTAGE:
		error = ENOMEM;
	case KERN_PROTECTION_FAILURE:
		error = EACCES;
	default:
		error = EINVAL;
	}
	goto bad1;
bad2:
	FREE(pnode, M_SHM);
bad1:
	if (pinfo_alloc)
		FREE(pinfo, M_SHM);
	fp_free(p, indx, nfp);
bad:
	FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	return (error);
}

/*
 * XXX This code is repeated in several places
 */
static int
psem_access(struct pseminfo *pinfo, int mode, kauth_cred_t cred)
{
	mode_t mask;
	int is_member;

	/* Otherwise, user id 0 always gets access. */
	if (!suser(cred, NULL))
		return (0);

	mask = 0;

	/* Otherwise, check the owner. */
	if (kauth_cred_getuid(cred) == pinfo->psem_uid) {
		if (mode & FREAD)
			mask |= S_IRUSR;
		if (mode & FWRITE)
			mask |= S_IWUSR;
		return ((pinfo->psem_mode & mask) == mask ? 0 : EACCES);
	}

	/* Otherwise, check the groups. */
	if (kauth_cred_ismember_gid(cred, pinfo->psem_gid, &is_member) == 0 && is_member) {
		if (mode & FREAD)
			mask |= S_IRGRP;
		if (mode & FWRITE)
			mask |= S_IWGRP;
		return ((pinfo->psem_mode & mask) == mask ? 0 : EACCES);
	}

	/* Otherwise, check everyone else. */
	if (mode & FREAD)
		mask |= S_IROTH;
	if (mode & FWRITE)
		mask |= S_IWOTH;
	return ((pinfo->psem_mode & mask) == mask ? 0 : EACCES);
}

int
sem_unlink(__unused struct proc *p, struct sem_unlink_args *uap, __unused register_t *retval)
{
	size_t i;
	int error=0;
	struct psemname nd;
	struct pseminfo *pinfo;
	char * pnbuf;
	char * nameptr;
	char * cp;
	size_t pathlen, plen;
	int incache = 0;
	struct psemcache *pcache = PSEMCACHE_NULL;

	pinfo = PSEMINFO_NULL;

	MALLOC_ZONE(pnbuf, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if (pnbuf == NULL) {
		return(ENOSPC);		/* XXX non-standard */
	}
	pathlen = MAXPATHLEN;
	error = copyinstr(uap->name, pnbuf, MAXPATHLEN, &pathlen);
	if (error) {
		goto bad;
	}
	AUDIT_ARG(text, pnbuf);
	if (pathlen > PSEMNAMLEN) {
		error = ENAMETOOLONG;
		goto bad;
	}


#ifdef PSXSEM_NAME_RESTRICT
	nameptr = pnbuf;
	if (*nameptr == '/') {
		while (*(nameptr++) == '/') {
			plen--;
			error = EINVAL;
			goto bad;
		}
        } else {
		error = EINVAL;
		goto bad;
	}
#endif /* PSXSEM_NAME_RESTRICT */

	plen = pathlen;
	nameptr = pnbuf;
	nd.psem_nameptr = nameptr;
	nd.psem_namelen = plen;
	nd. psem_hash =0;

        for (cp = nameptr, i=1; *cp != 0 && i <= plen; i++, cp++) {
               nd.psem_hash += (unsigned char)*cp * i;
	}

	PSEM_SUBSYS_LOCK();
	error = psem_cache_search(&pinfo, &nd, &pcache);

	if (error == ENOENT) {
		PSEM_SUBSYS_UNLOCK();
		error = EINVAL;
		goto bad;

	}
	if (!error) {
		PSEM_SUBSYS_UNLOCK();
		error = EINVAL;
		goto bad;
	} else
		incache = 1;
	if ( (error = psem_access(pinfo, pinfo->psem_mode, kauth_cred_get())) ) {
		PSEM_SUBSYS_UNLOCK();
		goto bad;
	}

	if ((pinfo->psem_flags & (PSEM_DEFINED | PSEM_ALLOCATED))==0) {
		PSEM_SUBSYS_UNLOCK();
		return (EINVAL);
	}

	if ( (pinfo->psem_flags & PSEM_INDELETE) ) {
		PSEM_SUBSYS_UNLOCK();
		error = 0;
		goto bad;
	}

	AUDIT_ARG(posix_ipc_perm, pinfo->psem_uid, pinfo->psem_gid,
		  pinfo->psem_mode);

	pinfo->psem_flags |= PSEM_INDELETE;
	pinfo->psem_usecount--;

	if (!pinfo->psem_usecount) {
		psem_delete(pinfo);
		FREE(pinfo,M_SHM);
	} else
		pinfo->psem_flags |= PSEM_REMOVED;

	psem_cache_delete(pcache);
	PSEM_SUBSYS_UNLOCK();
	FREE(pcache, M_SHM);
	error = 0;
bad:
	FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	return (error);
}

int
sem_close(struct proc *p, struct sem_close_args *uap, __unused register_t *retval)
{
	int fd = CAST_DOWN(int,uap->sem);
	struct fileproc *fp;
	int error = 0;

	AUDIT_ARG(fd, fd); /* XXX This seems wrong; uap->sem is a pointer */

	proc_fdlock(p);
	error = fp_lookup(p,fd, &fp, 1);
	if (error) {
		proc_fdunlock(p);
		return(error);
	}
	fdrelse(p, fd);
	error = closef_locked(fp, fp->f_fglob, p);
	FREE_ZONE(fp, sizeof *fp, M_FILEPROC);
	proc_fdunlock(p);
	return(error);
}

int
sem_wait(struct proc *p, struct sem_wait_args *uap, __unused register_t *retval)
{
	int fd = CAST_DOWN(int,uap->sem);
	struct fileproc *fp;
	struct pseminfo * pinfo;
	struct psemnode * pnode ;
	kern_return_t kret;
	int error;

	error = fp_getfpsem(p, fd, &fp, &pnode);
	if (error)
		return (error);
	if (((pnode = (struct psemnode *)fp->f_data)) == PSEMNODE_NULL )  {
		error = EINVAL;
		goto out;
	}
	PSEM_SUBSYS_LOCK();
	if ((pinfo = pnode->pinfo) == PSEMINFO_NULL) {
		PSEM_SUBSYS_UNLOCK();
		error = EINVAL;
		goto out;
	}
	if ((pinfo->psem_flags & (PSEM_DEFINED | PSEM_ALLOCATED)) 
			!= PSEM_ALLOCATED) {
		PSEM_SUBSYS_UNLOCK();
		error = EINVAL;
		goto out;
	}

	PSEM_SUBSYS_UNLOCK();
	kret = semaphore_wait(pinfo->psem_semobject);
	switch (kret) {
	case KERN_INVALID_ADDRESS:
	case KERN_PROTECTION_FAILURE:
		error = EACCES;
		break;
	case KERN_ABORTED:
	case KERN_OPERATION_TIMED_OUT:
		error = EINTR;
		break;
	case KERN_SUCCESS:
		error = 0;
		break;
	default:
		error = EINVAL;
		break;
	}
out:
	fp_drop(p, fd, fp, 0);
	return(error);

}

int
sem_trywait(struct proc *p, struct sem_trywait_args *uap, __unused register_t *retval)
{
	int fd = CAST_DOWN(int,uap->sem);
	struct fileproc *fp;
	struct pseminfo * pinfo;
	struct psemnode * pnode ;
	kern_return_t kret;
	mach_timespec_t wait_time;
	int error;
	
	error = fp_getfpsem(p, fd, &fp, &pnode);
	if (error)
		return (error);
	if (((pnode = (struct psemnode *)fp->f_data)) == PSEMNODE_NULL )  {
		error = EINVAL;
		goto out;
	}
	PSEM_SUBSYS_LOCK();
	if ((pinfo = pnode->pinfo) == PSEMINFO_NULL) {
		PSEM_SUBSYS_UNLOCK();
		error = EINVAL;
		goto out;
	}
	if ((pinfo->psem_flags & (PSEM_DEFINED | PSEM_ALLOCATED)) 
			!= PSEM_ALLOCATED) {
		PSEM_SUBSYS_UNLOCK();
		error = EINVAL;
		goto out;
	}

	PSEM_SUBSYS_UNLOCK();
	wait_time.tv_sec = 0;
	wait_time.tv_nsec = 0;

	kret = semaphore_timedwait(pinfo->psem_semobject, MACH_TIMESPEC_ZERO);
	switch (kret) {
	case KERN_INVALID_ADDRESS:
	case KERN_PROTECTION_FAILURE:
		error = EINVAL;
		break;
	case KERN_ABORTED:
		error = EINTR;
		break;
	case KERN_OPERATION_TIMED_OUT:
		error = EAGAIN;
		break;
	case KERN_SUCCESS:
		error = 0;
		break;
	default:
		error = EINVAL;
		break;
	}
out:
	fp_drop(p, fd, fp, 0);
	return(error);
}

int
sem_post(struct proc *p, struct sem_post_args *uap, __unused register_t *retval)
{
	int fd = CAST_DOWN(int,uap->sem);
	struct fileproc *fp;
	struct pseminfo * pinfo;
	struct psemnode * pnode ;
	kern_return_t kret;
	int error;

	error = fp_getfpsem(p, fd, &fp, &pnode);
	if (error)
		return (error);
	if (((pnode = (struct psemnode *)fp->f_data)) == PSEMNODE_NULL )  {
		error = EINVAL;
		goto out;
	}
	PSEM_SUBSYS_LOCK();
	if ((pinfo = pnode->pinfo) == PSEMINFO_NULL) {
		PSEM_SUBSYS_UNLOCK();
		error = EINVAL;
		goto out;
	}
	if ((pinfo->psem_flags & (PSEM_DEFINED | PSEM_ALLOCATED)) 
			!= PSEM_ALLOCATED) {
		PSEM_SUBSYS_UNLOCK();
		error = EINVAL;
		goto out;
	}

	PSEM_SUBSYS_UNLOCK();
	kret = semaphore_signal(pinfo->psem_semobject);
	switch (kret) {
	case KERN_INVALID_ADDRESS:
	case KERN_PROTECTION_FAILURE:
		error = EINVAL;
		break;
	case KERN_ABORTED:
	case KERN_OPERATION_TIMED_OUT:
		error = EINTR;
		break;
	case KERN_SUCCESS:
		error = 0;
		break;
	default:
		error = EINVAL;
		break;
	}
out:
	fp_drop(p, fd, fp, 0);
	return(error);
}

int
sem_init(__unused struct proc *p, __unused struct sem_init_args *uap, __unused register_t *retval)
{
	return(ENOSYS);
}

int
sem_destroy(__unused struct proc *p, __unused struct sem_destroy_args *uap, __unused register_t *retval)
{
	return(ENOSYS);
}

int
sem_getvalue(__unused struct proc *p, __unused struct sem_getvalue_args *uap, __unused register_t *retval)
{
	return(ENOSYS);
}

static int
psem_close(struct psemnode *pnode, __unused int flags, 
		__unused kauth_cred_t cred, __unused struct proc *p)
{
	int error=0;
	register struct pseminfo *pinfo;

	PSEM_SUBSYS_LOCK();
	if ((pinfo = pnode->pinfo) == PSEMINFO_NULL){
		PSEM_SUBSYS_UNLOCK();
		return(EINVAL);
	}

	if ((pinfo->psem_flags & PSEM_ALLOCATED) != PSEM_ALLOCATED) {
		PSEM_SUBSYS_UNLOCK();
		return(EINVAL);
	}
#if DIAGNOSTIC
	if(!pinfo->psem_usecount) {
		kprintf("negative usecount in psem_close\n");
	}
#endif /* DIAGNOSTIC */
	pinfo->psem_usecount--;

 	if ((pinfo->psem_flags & PSEM_REMOVED) && !pinfo->psem_usecount) {
		PSEM_SUBSYS_UNLOCK();
		/* lock dropped as only semaphore is destroyed here */
		error = psem_delete(pinfo);
		FREE(pinfo,M_SHM);
	} else {
		PSEM_SUBSYS_UNLOCK();
	}
	/* subsystem lock is dropped when we get here */
	FREE(pnode, M_SHM);
	return (error);
}

static int
psem_closefile(fg, p)
	struct fileglob *fg;
	struct proc *p;
{
	int error;

	/* Not locked as psem_close is called only from here and is locked properly */
	error =  psem_close(((struct psemnode *)fg->fg_data), fg->fg_flag,
		fg->fg_cred, p);

	return(error);
}

static int 
psem_delete(struct pseminfo * pinfo)
{
	kern_return_t kret;

	kret = semaphore_destroy(kernel_task, pinfo->psem_semobject);

	switch (kret) {
	case KERN_INVALID_ADDRESS:
	case KERN_PROTECTION_FAILURE:
		return (EINVAL);
	case KERN_ABORTED:
	case KERN_OPERATION_TIMED_OUT:
		return (EINTR);
	case KERN_SUCCESS:
		return(0);
	default:
		return (EINVAL);
	}
}

static int
psem_read(__unused struct fileproc *fp, __unused struct uio *uio, 
		  __unused kauth_cred_t cred, __unused int flags, 
		  __unused struct proc *p)
{
	return(ENOTSUP);
}

static int
psem_write(__unused struct fileproc *fp, __unused struct uio *uio, 
		   __unused kauth_cred_t cred, __unused int flags, 
		   __unused struct proc *p)
{
	return(ENOTSUP);
}

static int
psem_ioctl(__unused struct fileproc *fp, __unused u_long com, 
			__unused caddr_t data, __unused struct proc *p)
{
	return(ENOTSUP);
}

static int
psem_select(__unused struct fileproc *fp, __unused int which, 
			__unused void *wql, __unused struct proc *p)
{
	return(ENOTSUP);
}

static int
psem_kqfilter(__unused struct fileproc *fp, __unused struct knote *kn, 
				__unused struct proc *p)
{
	return (ENOTSUP);
}

int
fill_pseminfo(struct psemnode *pnode, struct psem_info * info)
{
	register struct pseminfo *pinfo;
	struct stat *sb;

	PSEM_SUBSYS_LOCK();
	if ((pinfo = pnode->pinfo) == PSEMINFO_NULL){
		PSEM_SUBSYS_UNLOCK();
		return(EINVAL);
	}

#if 0
	if ((pinfo->psem_flags & PSEM_ALLOCATED) != PSEM_ALLOCATED) {
		PSEM_SUBSYS_UNLOCK();
		return(EINVAL);
	}
#endif

	sb = &info->psem_stat;
	bzero(sb, sizeof(struct stat));

    	sb->st_mode = pinfo->psem_mode;
    	sb->st_uid = pinfo->psem_uid;
    	sb->st_gid = pinfo->psem_gid;
    	sb->st_size = pinfo->psem_usecount;
	bcopy(&pinfo->psem_name[0], &info->psem_name[0], PSEMNAMLEN+1);

	PSEM_SUBSYS_UNLOCK();
	return(0);
}

