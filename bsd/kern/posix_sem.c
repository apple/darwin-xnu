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
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/malloc.h>
#include <sys/semaphore.h>
#include <mach/mach_types.h>
#include <mach/vm_prot.h>
#include <mach/semaphore.h>
#include <mach/sync_policy.h>
#include <kern/task.h>
#include <kern/clock.h>
#include <mach/kern_return.h>

#define	PSEMNAMLEN	31	/* maximum name segment length we bother with */

struct pseminfo {
	unsigned int	psem_flags;
	unsigned int	psem_usecount;
	mode_t		psem_mode;
	uid_t		psem_uid;
	gid_t		psem_gid;
	char		psem_name[PSEMNAMLEN + 1];	/* segment name */
	void *		psem_semobject;
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
struct psemstats psemstats;		/* cache effectiveness statistics */

static int psem_cache_search __P((struct pseminfo **,
				struct psemname *, struct psemcache **));

static int psem_read  __P((struct file *fp, struct uio *uio,
			    struct ucred *cred, int flags, struct proc *p));
static int psem_write  __P((struct file *fp, struct uio *uio,
			    struct ucred *cred, int flags, struct proc *p));
static int psem_ioctl  __P((struct file *fp, u_long com,
			    caddr_t data, struct proc *p));
static int psem_select  __P((struct file *fp, int which, void *wql,
			    struct proc *p));
static int psem_closefile  __P((struct file *fp, struct proc *p));

struct 	fileops psemops =
	{ psem_read, psem_write, psem_ioctl, psem_select, psem_closefile };

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
	register struct psemcache *pcp, *nnp;
	register struct psemhashhead *pcpp;

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
psem_cache_add(psemp, pnp)
	struct pseminfo *psemp;
	struct psemname *pnp;
{
	register struct psemcache *pcp;
	register struct psemhashhead *pcpp;
	struct pseminfo *dpinfo;
	struct psemcache *dpcp;

#if DIAGNOSTIC
	if (pnp->psem_namelen > NCHNAMLEN)
		panic("cache_enter: name too long");
#endif

	/*
	 * We allocate a new entry if we are less than the maximum
	 * allowed and the one at the front of the LRU list is in use.
	 * Otherwise we use the one at the front of the LRU list.
	 */
	pcp = (struct psemcache *)_MALLOC(sizeof(struct psemcache), M_SHM, M_WAITOK);
	/*  if the entry has already been added by some one else return */
	if (psem_cache_search(&dpinfo, pnp, &dpcp) == -1) {
		_FREE(pcp, M_SHM);
		return(EEXIST);
	}
	psemnument++;

	bzero(pcp, sizeof(struct psemcache));
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
		register struct psemcache *p;

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
psem_cache_init()
{
	psemhashtbl = hashinit(desiredvnodes, M_SHM, &psemhash);
}

static void
psem_cache_delete(pcp)
	struct psemcache *pcp;
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

/*
 * Invalidate a all entries to particular vnode.
 * 
 * We actually just increment the v_id, that will do it. The entries will
 * be purged by lookup as they get found. If the v_id wraps around, we
 * need to ditch the entire cache, to avoid confusion. No valid vnode will
 * ever have (v_id == 0).
 */
void
psem_cache_purge(void)
{
	struct psemcache *pcp;
	struct psemhashhead *pcpp;

	for (pcpp = &psemhashtbl[psemhash]; pcpp >= psemhashtbl; pcpp--) {
		while (pcp = pcpp->lh_first)
			psem_cache_delete(pcp);
	}
}

struct sem_open_args {
	const char *name;
	int oflag;
	int mode;
	int value;
};

int
sem_open(p, uap, retval)
	struct proc *p;
	register struct sem_open_args *uap;
	register_t *retval;
{
	register struct filedesc *fdp = p->p_fd;
	register struct file *fp;
	register struct vnode *vp;
	int flags, i;
	struct file *nfp;
	int type, indx, error;
	struct psemname nd;
	struct pseminfo *pinfo;
	extern struct fileops psemops;
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

	pinfo = PSEMINFO_NULL;

	MALLOC_ZONE(pnbuf, caddr_t,
			MAXPATHLEN, M_NAMEI, M_WAITOK);
	pathlen = MAXPATHLEN;
	error = copyinstr(uap->name, pnbuf,
		MAXPATHLEN, &pathlen);
	if (error) {
		goto bad;
	}
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

	error = psem_cache_search(&pinfo, &nd, &pcache);

	if (error == ENOENT) {
		error = EINVAL;
		goto bad;

	}
	if (!error) {
		incache = 0;
	} else
		incache = 1;
	fmode = FFLAGS(uap->oflag);

	if (error = falloc(p, &nfp, &indx)) {
		goto bad;
	}

	fp = nfp;
	cmode &=  ALLPERMS;

	if (((fmode & (O_CREAT | O_EXCL))==(O_CREAT | O_EXCL)) &&  incache) {
		/* sem exists and opened O_EXCL */
#if notyet
		if (pinfo->psem_flags & PSEM_INDELETE) {
		}
#endif 
		error = EEXIST;
		goto bad1;
	}
	if (((fmode & (O_CREAT | O_EXCL))== O_CREAT) &&  incache) {
		/* As per POSIX, O_CREAT has no effect */
		fmode &= ~O_CREAT;
	}

	if (fmode & O_CREAT) {
		if((value < 0) && (value > SEM_VALUE_MAX)) {
			error = EINVAL;
			goto bad1;
		}
		pinfo = (struct pseminfo *)_MALLOC(sizeof(struct pseminfo), M_SHM, M_WAITOK);
		bzero(pinfo, sizeof(struct pseminfo));
		pinfo_alloc = 1;
		pinfo->psem_flags = PSEM_DEFINED | PSEM_INCREATE;
		pinfo->psem_usecount = 1;
		pinfo->psem_mode = cmode;
		pinfo->psem_uid = p->p_ucred->cr_uid;
		pinfo->psem_gid = p->p_ucred->cr_gid;
   		kret = semaphore_create(kernel_task, &pinfo->psem_semobject,
                            SYNC_POLICY_FIFO, value);
		if(kret != KERN_SUCCESS) 
			goto bad3;
		pinfo->psem_flags &= ~PSEM_DEFINED;
		pinfo->psem_flags |= PSEM_ALLOCATED;
		pinfo->sem_proc = p;
	} else {
		/* semaphore should exist as it is without  O_CREAT */
		if (!incache) {
			error = ENOENT;
			goto bad1;
		}
		if( pinfo->psem_flags & PSEM_INDELETE) {
			error = ENOENT;
			goto bad1;
		}	
		if (error = psem_access(pinfo, fmode, p->p_ucred, p))
			goto bad1;
	}
	pnode = (struct psemnode *)_MALLOC(sizeof(struct psemnode), M_SHM, M_WAITOK);
	bzero(pnode, sizeof(struct psemnode));

	if (!incache) {
		if (error = psem_cache_add(pinfo, &nd)) {
		goto bad2;
		}
	}
	pinfo->psem_flags &= ~PSEM_INCREATE;
	pinfo->psem_usecount++;
	pnode->pinfo = pinfo;
	fp->f_flag = flags & FMASK;
	fp->f_type = DTYPE_PSXSEM;
	fp->f_ops = &psemops;
	fp->f_data = (caddr_t)pnode;
	*fdflags(p, indx) &= ~UF_RESERVED;
	*retval = indx;
	_FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
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
	_FREE(pnode, M_SHM);
	if (pinfo_alloc)
		_FREE(pinfo, M_SHM);
bad1:
	fdrelse(p, indx);
	ffree(nfp);
bad:
	_FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	return (error);
}

int
psem_access(pinfo, mode, cred, p)
	struct pseminfo *pinfo;
	int mode;
	struct ucred *cred;
	struct proc *p;
{
	mode_t mask;
	register gid_t *gp;
	int i, error;

	/* Otherwise, user id 0 always gets access. */
	if (cred->cr_uid == 0)
		return (0);

	mask = 0;

	/* Otherwise, check the owner. */
	if (cred->cr_uid == pinfo->psem_uid) {
		if (mode & FREAD)
			mask |= S_IRUSR;
		if (mode & FWRITE)
			mask |= S_IWUSR;
		return ((pinfo->psem_mode & mask) == mask ? 0 : EACCES);
	}

	/* Otherwise, check the groups. */
	for (i = 0, gp = cred->cr_groups; i < cred->cr_ngroups; i++, gp++)
		if (pinfo->psem_gid == *gp) {
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

struct sem_unlink_args {
	const char *name;
};

int
sem_unlink(p, uap, retval)
	struct proc *p;
	register struct sem_unlink_args *uap;
	register_t *retval;
{
	register struct filedesc *fdp = p->p_fd;
	register struct file *fp;
	int flags, i;
	int error=0;
	struct psemname nd;
	struct pseminfo *pinfo;
	extern struct fileops psemops;
	char * pnbuf;
	char * nameptr;
	char * cp;
	size_t pathlen, plen;
	int fmode, cmode ;
	int incache = 0;
	struct psemnode * pnode = PSEMNODE_NULL;
	struct psemcache *pcache = PSEMCACHE_NULL;
	kern_return_t kret;

	pinfo = PSEMINFO_NULL;

	MALLOC_ZONE(pnbuf, caddr_t,
			MAXPATHLEN, M_NAMEI, M_WAITOK);
	pathlen = MAXPATHLEN;
	error = copyinstr(uap->name, pnbuf,
		MAXPATHLEN, &pathlen);
	if (error) {
		goto bad;
	}
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

	error = psem_cache_search(&pinfo, &nd, &pcache);

	if (error == ENOENT) {
		error = EINVAL;
		goto bad;

	}
	if (!error) {
		error = EINVAL;
		goto bad;
	} else
		incache = 1;
	if (error = psem_access(pinfo, pinfo->psem_mode, p->p_ucred, p))
		goto bad;

	if ((pinfo->psem_flags & (PSEM_DEFINED | PSEM_ALLOCATED))==0) {
		return (EINVAL);
	}

	if (pinfo->psem_flags & PSEM_INDELETE) {
		error = 0;
		goto bad;
	}
	pinfo->psem_flags |= PSEM_INDELETE;
	pinfo->psem_usecount--;

	if (!pinfo->psem_usecount) {
		psem_delete(pinfo);
		_FREE(pinfo,M_SHM);
	} else
		pinfo->psem_flags |= PSEM_REMOVED;

	psem_cache_delete(pcache);
	_FREE(pcache, M_SHM);
	error = 0;
bad:
	_FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	return (error);
}

struct sem_close_args {
	sem_t *sem;
};

int
sem_close(p, uap, retval)
	struct proc *p;
	struct sem_close_args *uap;
	register_t *retval;
{
	int fd = (int)uap->sem;
	register struct filedesc *fdp = p->p_fd;
	register struct file *fp;
	int error = 0;


	if ((u_int)fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			(fdp->fd_ofileflags[fd] & UF_RESERVED))
		return (EBADF);
	fdrelse(p, fd);
	if( error = closef(fp, p))
		return(error);
	return(0);
}

struct sem_wait_args {
	sem_t *sem;
};

int
sem_wait(p, uap, retval)
	struct proc *p;
	struct sem_wait_args *uap;
	register_t *retval;
{
	int fd = (int)uap->sem;
	register struct filedesc *fdp = p->p_fd;
	struct file *fp;
	struct pseminfo * pinfo;
	struct psemnode * pnode ;
	kern_return_t kret;
	int error;

	if (error = fdgetf(p, (int)uap->sem, &fp))
		return (error);
	if (fp->f_type != DTYPE_PSXSEM)
		return(EBADF);
	if (((pnode = (struct psemnode *)fp->f_data)) == PSEMNODE_NULL )
		return(EINVAL);
	if ((pinfo = pnode->pinfo) == PSEMINFO_NULL)
		return(EINVAL);
	if ((pinfo->psem_flags & (PSEM_DEFINED | PSEM_ALLOCATED)) 
			!= PSEM_ALLOCATED) {
		return(EINVAL);
	}

	kret = semaphore_wait(pinfo->psem_semobject);
	switch (kret) {
	case KERN_INVALID_ADDRESS:
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	case KERN_ABORTED:
	case KERN_OPERATION_TIMED_OUT:
		return (EINTR);
	case KERN_SUCCESS:
		return(0);
	default:
		return (EINVAL);
	}
}

struct sem_trywait_args {
	sem_t *sem;
};

int
sem_trywait(p, uap, retval)
	struct proc *p;
	struct sem_trywait_args *uap;
	register_t *retval;
{
	int fd = (int)uap->sem;
	register struct filedesc *fdp = p->p_fd;
	struct file *fp;
	struct pseminfo * pinfo;
	struct psemnode * pnode ;
	kern_return_t kret;
	mach_timespec_t wait_time;
	int error;
	
	if (error = fdgetf(p, (int)uap->sem, &fp))
		return (error);
	if (fp->f_type != DTYPE_PSXSEM)
		return(EBADF);
	if (((pnode = (struct psemnode *)fp->f_data)) == PSEMNODE_NULL )
		return(EINVAL);
	if ((pinfo = pnode->pinfo) == PSEMINFO_NULL)
		return(EINVAL);
	if ((pinfo->psem_flags & (PSEM_DEFINED | PSEM_ALLOCATED)) 
			!= PSEM_ALLOCATED) {
		return(EINVAL);
	}

	wait_time.tv_sec = 0;
	wait_time.tv_nsec = 0;

	kret = semaphore_timedwait(pinfo->psem_semobject, MACH_TIMESPEC_ZERO);
	switch (kret) {
	case KERN_INVALID_ADDRESS:
	case KERN_PROTECTION_FAILURE:
		return (EINVAL);
	case KERN_ABORTED:
		return (EINTR);
	case KERN_OPERATION_TIMED_OUT:
		return (EAGAIN);
	case KERN_SUCCESS:
		return(0);
	default:
		return (EINVAL);
	}
}

struct sem_post_args {
	sem_t *sem;
};

int
sem_post(p, uap, retval)
	struct proc *p;
	struct sem_post_args *uap;
	register_t *retval;
{
	int fd = (int)uap->sem;
	register struct filedesc *fdp = p->p_fd;
	struct file *fp;
	struct pseminfo * pinfo;
	struct psemnode * pnode ;
	kern_return_t kret;
	int error;

	if (error = fdgetf(p, (int)uap->sem, &fp))
		return (error);
	if (fp->f_type != DTYPE_PSXSEM)
		return(EBADF);
	if (((pnode = (struct psemnode *)fp->f_data)) == PSEMNODE_NULL )
		return(EINVAL);
	if ((pinfo = pnode->pinfo) == PSEMINFO_NULL)
		return(EINVAL);
	if ((pinfo->psem_flags & (PSEM_DEFINED | PSEM_ALLOCATED)) 
			!= PSEM_ALLOCATED) {
		return(EINVAL);
	}

	kret = semaphore_signal(pinfo->psem_semobject);
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

struct sem_init_args {
	sem_t *sem;
	int phsared;
	unsigned int value;
};

int
sem_init(p, uap, retval)
	struct proc *p;
	struct sem_init_args *uap;
	register_t *retval;
{
	return(ENOSYS);
}

struct sem_destroy_args {
	sem_t *sem;
};

int
sem_destroy(p, uap, retval)
	struct proc *p;
	struct sem_destroy_args *uap;
	register_t *retval;
{
	return(ENOSYS);
}

struct sem_getvalue_args {
	sem_t *sem;
	int * sval;
};

int
sem_getvalue(p, uap, retval)
	struct proc *p;
	struct sem_getvalue_args *uap;
	register_t *retval;
{
	return(ENOSYS);
}

static int
psem_close(pnode, flags, cred, p)
	register struct psemnode *pnode;
	int flags;
	struct ucred *cred;
	struct proc *p;
{
	int error=0;
	kern_return_t kret;
	register struct pseminfo *pinfo;

	if ((pinfo = pnode->pinfo) == PSEMINFO_NULL)
		return(EINVAL);

	if ((pinfo->psem_flags & PSEM_ALLOCATED) != PSEM_ALLOCATED) {
		return(EINVAL);
	}
#if DIAGNOSTIC
	if(!pinfo->psem_usecount) {
		kprintf("negative usecount in psem_close\n");
	}
#endif /* DIAGNOSTIC */
	pinfo->psem_usecount--;

 	if ((pinfo->psem_flags & PSEM_REMOVED) && !pinfo->psem_usecount) {
		error = psem_delete(pinfo);
		_FREE(pinfo,M_SHM);
	}
	_FREE(pnode, M_SHM);
	return (error);
}

static int
psem_closefile(fp, p)
	struct file *fp;
	struct proc *p;
{

	return (psem_close(((struct psemnode *)fp->f_data), fp->f_flag,
		fp->f_cred, p));
}

int 
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
psem_read(fp, uio, cred, flags, p)
	struct file *fp;
	struct uio *uio;
	struct ucred *cred;
	int flags;
	struct proc *p;
{
	return(EOPNOTSUPP);
}

static int
psem_write(fp, uio, cred, flags, p)
	struct file *fp;
	struct uio *uio;
	struct ucred *cred;
	int flags;
	struct proc *p;
{
	return(EOPNOTSUPP);
}

static int
psem_ioctl(fp, com, data, p)
	struct file *fp;
	u_long com;
	caddr_t data;
	struct proc *p;
{
	return(EOPNOTSUPP);
}

static int
psem_select(fp, which, wql, p)
	struct file *fp;
	int which;
	void *wql;
	struct proc *p;
{
	return(EOPNOTSUPP);
}
