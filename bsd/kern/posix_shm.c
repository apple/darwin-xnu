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
 * posix_shm.c : Support for POSIX shared memory APIs
 *
 *	File:	posix_shm.c
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
#include <sys/mman.h>
#include <sys/stat.h>
#include <mach/mach_types.h>
#include <mach/vm_prot.h>
#include <mach/vm_inherit.h>
#include <mach/kern_return.h>
#include <mach/memory_object_control.h>


#define	PSHMNAMLEN	31	/* maximum name segment length we bother with */

struct pshminfo {
	unsigned int	pshm_flags;
	unsigned int	pshm_usecount;
	off_t		pshm_length;
	mode_t		pshm_mode;
	uid_t		pshm_uid;
	gid_t		pshm_gid;
	char		pshm_name[PSHMNAMLEN + 1];	/* segment name */
	void *		pshm_memobject;
#if DIAGNOSTIC
	unsigned int 	pshm_readcount;
	unsigned int 	pshm_writecount;
	struct proc *	pshm_proc;
#endif /* DIAGNOSTIC */
};
#define PSHMINFO_NULL (struct pshminfo *)0

#define	PSHM_NONE	1
#define	PSHM_DEFINED	2
#define	PSHM_ALLOCATED	4
#define	PSHM_MAPPED	8
#define	PSHM_INUSE	0x10
#define	PSHM_REMOVED	0x20
#define	PSHM_INCREATE	0x40
#define	PSHM_INDELETE	0x80

struct	pshmcache {
	LIST_ENTRY(pshmcache) pshm_hash;	/* hash chain */
	struct	pshminfo *pshminfo;		/* vnode the name refers to */
	int	pshm_nlen;		/* length of name */
	char	pshm_name[PSHMNAMLEN + 1];	/* segment name */
};
#define PSHMCACHE_NULL (struct pshmcache *)0

struct	pshmstats {
	long	goodhits;		/* hits that we can really use */
	long	neghits;		/* negative hits that we can use */
	long	badhits;		/* hits we must drop */
	long	falsehits;		/* hits with id mismatch */
	long	miss;		/* misses */
	long	longnames;		/* long names that ignore cache */
};

struct pshmname {
	char	*pshm_nameptr;	/* pointer to looked up name */
	long	pshm_namelen;	/* length of looked up component */
	u_long	pshm_hash;	/* hash value of looked up name */
};

struct pshmnode {
	off_t  mapp_addr;
	size_t	map_size;
	struct pshminfo *pinfo;
	unsigned int	pshm_usecount;
#if DIAGNOSTIC
	unsigned int readcnt;
	unsigned int writecnt;
#endif
};
#define PSHMNODE_NULL (struct pshmnode *)0


#define PSHMHASH(pnp) \
	(&pshmhashtbl[(pnp)->pshm_hash & pshmhash])
LIST_HEAD(pshmhashhead, pshmcache) *pshmhashtbl;	/* Hash Table */
u_long	pshmhash;				/* size of hash table - 1 */
long	pshmnument;			/* number of cache entries allocated */
struct pshmstats pshmstats;		/* cache effectiveness statistics */

static int pshm_read  __P((struct file *fp, struct uio *uio,
		    struct ucred *cred, int flags, struct proc *p));
static int pshm_write  __P((struct file *fp, struct uio *uio,
		    struct ucred *cred, int flags, struct proc *p));
static int pshm_ioctl  __P((struct file *fp, u_long com,
		    caddr_t data, struct proc *p));
static int pshm_select  __P((struct file *fp, int which, void *wql,
		    struct proc *p));
static int pshm_closefile  __P((struct file *fp, struct proc *p));

static int pshm_kqfilter __P((struct file *fp, struct knote *kn, struct proc *p));

struct 	fileops pshmops =
	{ pshm_read, pshm_write, pshm_ioctl, pshm_select, pshm_closefile, pshm_kqfilter };

/*
 * Lookup an entry in the cache 
 * 
 * 
 * status of -1 is returned if matches
 * If the lookup determines that the name does not exist
 * (negative cacheing), a status of ENOENT is returned. If the lookup
 * fails, a status of zero is returned.
 */

int
pshm_cache_search(pshmp, pnp, pcache)
	struct pshminfo **pshmp;
	struct pshmname *pnp;
	struct pshmcache **pcache;
{
	register struct pshmcache *pcp, *nnp;
	register struct pshmhashhead *pcpp;

	if (pnp->pshm_namelen > PSHMNAMLEN) {
		pshmstats.longnames++;
		return (0);
	}

	pcpp = PSHMHASH(pnp);
	for (pcp = pcpp->lh_first; pcp != 0; pcp = nnp) {
		nnp = pcp->pshm_hash.le_next;
		if (pcp->pshm_nlen == pnp->pshm_namelen &&
		    !bcmp(pcp->pshm_name, pnp->pshm_nameptr, 						(u_int)pcp-> pshm_nlen))
			break;
	}

	if (pcp == 0) {
		pshmstats.miss++;
		return (0);
	}

	/* We found a "positive" match, return the vnode */
        if (pcp->pshminfo) {
		pshmstats.goodhits++;
		/* TOUCH(ncp); */
		*pshmp = pcp->pshminfo;
		*pcache = pcp;
		return (-1);
	}

	/*
	 * We found a "negative" match, ENOENT notifies client of this match.
	 * The nc_vpid field records whether this is a whiteout.
	 */
	pshmstats.neghits++;
	return (ENOENT);
}

/*
 * Add an entry to the cache.
 */
int
pshm_cache_add(pshmp, pnp)
	struct pshminfo *pshmp;
	struct pshmname *pnp;
{
	register struct pshmcache *pcp;
	register struct pshmhashhead *pcpp;
	struct pshminfo *dpinfo;
	struct pshmcache *dpcp;

#if DIAGNOSTIC
	if (pnp->pshm_namelen > NCHNAMLEN)
		panic("cache_enter: name too long");
#endif

	/*
	 * We allocate a new entry if we are less than the maximum
	 * allowed and the one at the front of the LRU list is in use.
	 * Otherwise we use the one at the front of the LRU list.
	 */
	pcp = (struct pshmcache *)_MALLOC(sizeof(struct pshmcache), M_SHM, M_WAITOK);
	/*  if the entry has already been added by some one else return */
	if (pshm_cache_search(&dpinfo, pnp, &dpcp) == -1) {
		_FREE(pcp, M_SHM);
		return(EEXIST);
	}
	pshmnument++;

	bzero(pcp, sizeof(struct pshmcache));
	/*
	 * Fill in cache info, if vp is NULL this is a "negative" cache entry.
	 * For negative entries, we have to record whether it is a whiteout.
	 * the whiteout flag is stored in the nc_vpid field which is
	 * otherwise unused.
	 */
	pcp->pshminfo = pshmp;
	pcp->pshm_nlen = pnp->pshm_namelen;
	bcopy(pnp->pshm_nameptr, pcp->pshm_name, (unsigned)pcp->pshm_nlen);
	pcpp = PSHMHASH(pnp);
#if DIAGNOSTIC
	{
		register struct pshmcache *p;

		for (p = pcpp->lh_first; p != 0; p = p->pshm_hash.le_next)
			if (p == pcp)
				panic("cache_enter: duplicate");
	}
#endif
	LIST_INSERT_HEAD(pcpp, pcp, pshm_hash);
	return(0);
}

/*
 * Name cache initialization, from vfs_init() when we are booting
 */
void
pshm_cache_init()
{
	pshmhashtbl = hashinit(desiredvnodes, M_SHM, &pshmhash);
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
pshm_cache_purge(void)
{
	struct pshmcache *pcp;
	struct pshmhashhead *pcpp;

	for (pcpp = &pshmhashtbl[pshmhash]; pcpp >= pshmhashtbl; pcpp--) {
		while (pcp = pcpp->lh_first)
			pshm_cache_delete(pcp);
	}
}

pshm_cache_delete(pcp)
	struct pshmcache *pcp;
{
#if DIAGNOSTIC
	if (pcp->pshm_hash.le_prev == 0)
		panic("namecache purge le_prev");
	if (pcp->pshm_hash.le_next == pcp)
		panic("namecache purge le_next");
#endif /* DIAGNOSTIC */
	LIST_REMOVE(pcp, pshm_hash);
	pcp->pshm_hash.le_prev = 0;	
	pshmnument--;
}


struct shm_open_args {
	const char *name;
	int oflag;
	int mode;
};

int
shm_open(p, uap, retval)
	struct proc *p;
	register struct shm_open_args *uap;
	register_t *retval;
{
	register struct filedesc *fdp = p->p_fd;
	register struct file *fp;
	register struct vnode *vp;
	int  i;
	struct file *nfp;
	int type, indx, error;
	struct pshmname nd;
	struct pshminfo *pinfo;
	extern struct fileops pshmops;
	char * pnbuf;
	char * nameptr;
	char * cp;
	size_t pathlen, plen;
	int fmode ;
	int cmode = uap->mode;
	int incache = 0;
	struct pshmnode * pnode = PSHMNODE_NULL;
	struct pshmcache * pcache = PSHMCACHE_NULL;
	int pinfo_alloc=0;


	pinfo = PSHMINFO_NULL;

	MALLOC_ZONE(pnbuf, caddr_t,
			MAXPATHLEN, M_NAMEI, M_WAITOK);
	pathlen = MAXPATHLEN;
	error = copyinstr((void *)uap->name, (void *)pnbuf,
		MAXPATHLEN, &pathlen);
	if (error) {
		goto bad;
	}
	if (pathlen > PSHMNAMLEN) {
		error = ENAMETOOLONG;
		goto bad;
	}


#ifdef PSXSHM_NAME_RESTRICT
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
#endif /* PSXSHM_NAME_RESTRICT */

	plen = pathlen;
	nameptr = pnbuf;
	nd.pshm_nameptr = nameptr;
	nd.pshm_namelen = plen;
	nd. pshm_hash =0;

        for (cp = nameptr, i=1; *cp != 0 && i <= plen; i++, cp++) {
               nd.pshm_hash += (unsigned char)*cp * i;
	}

	error = pshm_cache_search(&pinfo, &nd, &pcache);

	if (error == ENOENT) {
		error = EINVAL;
		goto bad;

	}
	if (!error) {
		incache = 0;
	} else
		incache = 1;
	fmode = FFLAGS(uap->oflag);
	if ((fmode & (FREAD | FWRITE))==0) {
		error = EINVAL;
		goto bad;
	}

	if (error = falloc(p, &nfp, &indx))
		goto bad;
	fp = nfp;

	cmode &=  ALLPERMS;

	if (fmode & O_CREAT) {
		if ((fmode & O_EXCL) && incache) {
			/* shm obj exists and opened O_EXCL */
#if notyet
                        if (pinfo->pshm_flags & PSHM_INDELETE) {
                        }
#endif 
                        error = EEXIST;
                        goto bad1;
                } 
                if (!incache) {
                    /*  create a new one */
                    pinfo = (struct pshminfo *)_MALLOC(sizeof(struct pshminfo), M_SHM, M_WAITOK);
                    bzero(pinfo, sizeof(struct pshminfo));
			pinfo_alloc = 1;
                    pinfo->pshm_flags = PSHM_DEFINED | PSHM_INCREATE;
                    pinfo->pshm_usecount = 1;
                    pinfo->pshm_mode = cmode;
                    pinfo->pshm_uid = p->p_ucred->cr_uid;
                    pinfo->pshm_gid = p->p_ucred->cr_gid;
                } else {
                    /*  already exists */
                        if( pinfo->pshm_flags & PSHM_INDELETE) {
                            error = ENOENT;
                            goto bad1;
                        }	
                        if (error = pshm_access(pinfo, fmode, p->p_ucred, p))
                            goto bad1;
                }
	} else {
		if (!incache) {
			/* O_CREAT  is not set and the shm obecj does not exist */
			error = ENOENT;
			goto bad1;
		}
		if( pinfo->pshm_flags & PSHM_INDELETE) {
			error = ENOENT;
			goto bad1;
		}	
		if (error = pshm_access(pinfo, fmode, p->p_ucred, p))
			goto bad1;
	}
	if (fmode & O_TRUNC) {
		error = EINVAL;
		goto bad2;
	}
#if DIAGNOSTIC 
	if (fmode & FWRITE)
		pinfo->pshm_writecount++;
	if (fmode & FREAD)
		pinfo->pshm_readcount++;
#endif
	pnode = (struct pshmnode *)_MALLOC(sizeof(struct pshmnode), M_SHM, M_WAITOK);
	bzero(pnode, sizeof(struct pshmnode));

	if (!incache) {
		if (error = pshm_cache_add(pinfo, &nd)) {
		goto bad3;
		}
	}
	pinfo->pshm_flags &= ~PSHM_INCREATE;
	pinfo->pshm_usecount++;
	pnode->pinfo = pinfo;
	fp->f_flag = fmode & FMASK;
	fp->f_type = DTYPE_PSXSHM;
	fp->f_ops = &pshmops;
	fp->f_data = (caddr_t)pnode;
	*fdflags(p, indx) &= ~UF_RESERVED;
	*retval = indx;
	FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	return (0);
bad3:
	_FREE(pnode, M_SHM);
		
bad2:
	if (pinfo_alloc)
		_FREE(pinfo, M_SHM);
bad1:
	fdrelse(p, indx);
	ffree(nfp);
bad:
	FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	return (error);
}


/* ARGSUSED */
int
pshm_truncate(p, fp, fd, length, retval)
	struct proc *p;
	struct file *fp;
	int fd;
	off_t length;
	register_t *retval;
{
	struct pshminfo * pinfo;
	struct pshmnode * pnode ;
	kern_return_t kret;
	vm_offset_t user_addr;
	void * mem_object;
	vm_size_t size;

	if (fp->f_type != DTYPE_PSXSHM) {
		return(EINVAL);
	}
	

	if (((pnode = (struct pshmnode *)fp->f_data)) == PSHMNODE_NULL )
		return(EINVAL);

	if ((pinfo = pnode->pinfo) == PSHMINFO_NULL)
		return(EINVAL);
	if ((pinfo->pshm_flags & (PSHM_DEFINED | PSHM_ALLOCATED)) 
			!= PSHM_DEFINED) {
		return(EINVAL);
	}

	size = round_page_64(length);
	kret = vm_allocate(current_map(), &user_addr, size, TRUE);
	if (kret != KERN_SUCCESS) 
		goto out;

	kret = mach_make_memory_entry (current_map(), &size,
			user_addr, VM_PROT_DEFAULT, &mem_object, 0);

	if (kret != KERN_SUCCESS) 
		goto out;
	
	vm_deallocate(current_map(), user_addr, size);

	pinfo->pshm_flags &= ~PSHM_DEFINED;
	pinfo->pshm_flags = PSHM_ALLOCATED;
	pinfo->pshm_memobject = mem_object;
	pinfo->pshm_length = size;
	return(0);

out:
	switch (kret) {
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		return (ENOMEM);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	default:
		return (EINVAL);
	
	}
}

int
pshm_stat(pnode, sb)
struct pshmnode *pnode;
struct stat *sb;
{
	struct pshminfo *pinfo;
	
	if ((pinfo = pnode->pinfo) == PSHMINFO_NULL)
		return(EINVAL);

	bzero(sb, sizeof(struct stat)); 
	sb->st_mode = pinfo->pshm_mode;
	sb->st_uid = pinfo->pshm_uid;
	sb->st_gid = pinfo->pshm_gid;
	sb->st_size = pinfo->pshm_length;

	return(0);
}

int
pshm_access(struct pshminfo *pinfo, int mode, struct ucred *cred, struct proc *p)
{
	mode_t mask;
	register gid_t *gp;
	int i, error;

	/* Otherwise, user id 0 always gets access. */
	if (cred->cr_uid == 0)
		return (0);

	mask = 0;

	/* Otherwise, check the owner. */
	if (cred->cr_uid == pinfo->pshm_uid) {
		if (mode & FREAD)
			mask |= S_IRUSR;
		if (mode & FWRITE)
			mask |= S_IWUSR;
		return ((pinfo->pshm_mode & mask) == mask ? 0 : EACCES);
	}

	/* Otherwise, check the groups. */
	for (i = 0, gp = cred->cr_groups; i < cred->cr_ngroups; i++, gp++)
		if (pinfo->pshm_gid == *gp) {
			if (mode & FREAD)
				mask |= S_IRGRP;
			if (mode & FWRITE)
				mask |= S_IWGRP;
			return ((pinfo->pshm_mode & mask) == mask ? 0 : EACCES);
		}

	/* Otherwise, check everyone else. */
	if (mode & FREAD)
		mask |= S_IROTH;
	if (mode & FWRITE)
		mask |= S_IWOTH;
	return ((pinfo->pshm_mode & mask) == mask ? 0 : EACCES);
}

struct mmap_args {
		caddr_t addr;
		size_t len;
		int prot;
		int flags;
		int fd;
#ifdef DOUBLE_ALIGN_PARAMS
		long pad;
#endif
		off_t pos;
};

int
pshm_mmap(struct proc *p, struct mmap_args *uap, register_t *retval, struct file *fp, vm_size_t pageoff) 
{
	vm_offset_t	user_addr = (vm_offset_t)uap->addr;
	vm_size_t	user_size = (vm_size_t)uap->len ;
	int prot = uap->prot;
	int flags = uap->flags;
	vm_object_offset_t file_pos = (vm_object_offset_t)uap->pos;
	int fd = uap->fd;
	vm_map_t	user_map;
	boolean_t	find_space,docow;
	kern_return_t	kret;
	struct pshminfo * pinfo;
	struct pshmnode * pnode;
	void * mem_object;

	if (user_size == 0) 
		return(0);

	if ((flags & MAP_SHARED) == 0)
		return(EINVAL);


	if ((prot & PROT_WRITE) && ((fp->f_flag & FWRITE) == 0)) {
		return(EPERM);
	}

	if (((pnode = (struct pshmnode *)fp->f_data)) == PSHMNODE_NULL )
		return(EINVAL);

	if ((pinfo = pnode->pinfo) == PSHMINFO_NULL)
		return(EINVAL);

	if ((pinfo->pshm_flags & PSHM_ALLOCATED) != PSHM_ALLOCATED) {
		return(EINVAL);
	}
	if (user_size > pinfo->pshm_length) {
		return(EINVAL);
	}
	if ((off_t)user_size  + file_pos > pinfo->pshm_length) {
		return(EINVAL);
	}
	if ((mem_object =  pinfo->pshm_memobject) == NULL) {
		return(EINVAL);
	}

	
	user_map = current_map();

	if ((flags & MAP_FIXED) == 0) {
		find_space = TRUE;
		user_addr = round_page_32(user_addr); 
	} else {
		if (user_addr != trunc_page_32(user_addr))
			return (EINVAL);
		find_space = FALSE;
		(void) vm_deallocate(user_map, user_addr, user_size);
	}
	docow = FALSE;	

	kret = vm_map_64(user_map, &user_addr, user_size,
			0, find_space, pinfo->pshm_memobject, file_pos, docow,
      	                prot, VM_PROT_DEFAULT, 
			VM_INHERIT_DEFAULT);

	if (kret != KERN_SUCCESS) 
			goto out;
	kret = vm_inherit(user_map, user_addr, user_size,
				VM_INHERIT_SHARE);
	if (kret != KERN_SUCCESS) {
		(void) vm_deallocate(user_map, user_addr, user_size);
		goto out;
	}
	pnode->mapp_addr = user_addr;
	pnode->map_size = user_size;
	pinfo->pshm_flags |= (PSHM_MAPPED | PSHM_INUSE);
out:
	switch (kret) {
	case KERN_SUCCESS:
		*fdflags(p, fd) |= UF_MAPPED;
		*retval = (register_t)(user_addr + pageoff);
		return (0);
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		return (ENOMEM);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	default:
		return (EINVAL);
	}

}

struct shm_unlink_args {
	const char *name;
};

int
shm_unlink(p, uap, retval)
	struct proc *p;
	register struct shm_unlink_args *uap;
	register_t *retval;
{
	register struct filedesc *fdp = p->p_fd;
	register struct file *fp;
	int flags, i;
	int error=0;
	struct pshmname nd;
	struct pshminfo *pinfo;
	extern struct fileops pshmops;
	char * pnbuf;
	char * nameptr;
	char * cp;
	size_t pathlen, plen;
	int fmode, cmode ;
	int incache = 0;
	struct pshmnode * pnode = PSHMNODE_NULL;
	struct pshmcache *pcache = PSHMCACHE_NULL;
	kern_return_t kret;

	pinfo = PSHMINFO_NULL;

	MALLOC_ZONE(pnbuf, caddr_t,
			MAXPATHLEN, M_NAMEI, M_WAITOK);
	pathlen = MAXPATHLEN;
	error = copyinstr((void *)uap->name, (void *)pnbuf,
		MAXPATHLEN, &pathlen);
	if (error) {
		goto bad;
	}
	if (pathlen > PSHMNAMLEN) {
		error = ENAMETOOLONG;
		goto bad;
	}


#ifdef PSXSHM_NAME_RESTRICT
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
#endif /* PSXSHM_NAME_RESTRICT */

	plen = pathlen;
	nameptr = pnbuf;
	nd.pshm_nameptr = nameptr;
	nd.pshm_namelen = plen;
	nd. pshm_hash =0;

        for (cp = nameptr, i=1; *cp != 0 && i <= plen; i++, cp++) {
               nd.pshm_hash += (unsigned char)*cp * i;
	}

	error = pshm_cache_search(&pinfo, &nd, &pcache);

	if (error == ENOENT) {
		error = EINVAL;
		goto bad;

	}
	if (!error) {
		error = EINVAL;
		goto bad;
	} else
		incache = 1;

	if ((pinfo->pshm_flags & (PSHM_DEFINED | PSHM_ALLOCATED))==0) {
		return (EINVAL);
	}

	if (pinfo->pshm_flags & PSHM_INDELETE) {
		error = 0;
		goto bad;
	}

	if (pinfo->pshm_memobject == NULL) {
		error = EINVAL;
		goto bad;
	}

	pinfo->pshm_flags |= PSHM_INDELETE;
	pinfo->pshm_usecount--;
	kret = mach_destroy_memory_entry(pinfo->pshm_memobject);
	pshm_cache_delete(pcache);
	_FREE(pcache, M_SHM);
	pinfo->pshm_flags |= PSHM_REMOVED;
	error = 0;
bad:
	FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	return (error);
out:
	switch (kret) {
	case KERN_INVALID_ADDRESS:
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	default:
		return (EINVAL);
	}
}

int
pshm_close(pnode, flags, cred, p)
	register struct pshmnode *pnode;
	int flags;
	struct ucred *cred;
	struct proc *p;
{
	int error=0;
	kern_return_t kret;
	register struct pshminfo *pinfo;

	if ((pinfo = pnode->pinfo) == PSHMINFO_NULL)
		return(EINVAL);

	if ((pinfo->pshm_flags & PSHM_ALLOCATED) != PSHM_ALLOCATED) {
		return(EINVAL);
	}
#if DIAGNOSTIC
	if(!pinfo->pshm_usecount) {
		kprintf("negative usecount in pshm_close\n");
	}
#endif /* DIAGNOSTIC */
	pinfo->pshm_usecount--;

 	if ((pinfo->pshm_flags & PSHM_REMOVED) && !pinfo->pshm_usecount) {
		_FREE(pinfo,M_SHM);
	}
	_FREE(pnode, M_SHM);
	return (error);
}

static int
pshm_closefile(fp, p)
	struct file *fp;
	struct proc *p;
{
	return (pshm_close(((struct pshmnode *)fp->f_data), fp->f_flag,
		fp->f_cred, p));
}

static int
pshm_read(fp, uio, cred, flags, p)
	struct file *fp;
	struct uio *uio;
	struct ucred *cred;
	int flags;
	struct proc *p;
{
	return(EOPNOTSUPP);
}

static int
pshm_write(fp, uio, cred, flags, p)
	struct file *fp;
	struct uio *uio;
	struct ucred *cred;
	int flags;
	struct proc *p;
{
	return(EOPNOTSUPP);
}

static int
pshm_ioctl(fp, com, data, p)
	struct file *fp;
	u_long com;
	caddr_t data;
	struct proc *p;
{
	return(EOPNOTSUPP);
}

static int
pshm_select(fp, which, wql, p)
	struct file *fp;
	int which;
	void *wql;
	struct proc *p;
{
	return(EOPNOTSUPP);
}

static int
pshm_kqfilter(fp, kn, p)
	struct file *fp;
	struct knote *kn;
	struct proc *p;
{
	return(EOPNOTSUPP);
}
