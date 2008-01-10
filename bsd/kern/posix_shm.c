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
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysproto.h>
#include <sys/proc_info.h>

#include <bsm/audit_kernel.h>

#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach/vm_prot.h>
#include <mach/vm_inherit.h>
#include <mach/kern_return.h>
#include <mach/memory_object_control.h>

#include <vm/vm_map.h>
#include <vm/vm_protos.h>
#include <vm/vm_shared_memory_server.h>

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
	off_t  		mapp_addr;
	user_size_t	map_size;
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

static int pshm_read (struct fileproc *fp, struct uio *uio,
		    kauth_cred_t cred, int flags, struct proc *p);
static int pshm_write (struct fileproc *fp, struct uio *uio,
		    kauth_cred_t cred, int flags, struct proc *p);
static int pshm_ioctl (struct fileproc *fp, u_long com,
		    caddr_t data, struct proc *p);
static int pshm_select (struct fileproc *fp, int which, void *wql, struct proc *p);
static int pshm_close(struct pshmnode *pnode);
static int pshm_closefile (struct fileglob *fg, struct proc *p);

static int pshm_kqfilter(struct fileproc *fp, struct knote *kn, struct proc *p);

int pshm_access(struct pshminfo *pinfo, int mode, kauth_cred_t cred, struct proc *p);
static int pshm_cache_add(struct pshminfo *pshmp, struct pshmname *pnp, struct pshmcache *pcp);
static void pshm_cache_delete(struct pshmcache *pcp);
#if NOT_USED
static void pshm_cache_purge(void);
#endif	/* NOT_USED */
static int pshm_cache_search(struct pshminfo **pshmp, struct pshmname *pnp,
	struct pshmcache **pcache);

struct 	fileops pshmops =
	{ pshm_read, pshm_write, pshm_ioctl, pshm_select, pshm_closefile, pshm_kqfilter, 0 };

static lck_grp_t       *psx_shm_subsys_lck_grp;
static lck_grp_attr_t  *psx_shm_subsys_lck_grp_attr;
static lck_attr_t      *psx_shm_subsys_lck_attr;
static lck_mtx_t        psx_shm_subsys_mutex;

#define PSHM_SUBSYS_LOCK() lck_mtx_lock(& psx_shm_subsys_mutex)
#define PSHM_SUBSYS_UNLOCK() lck_mtx_unlock(& psx_shm_subsys_mutex)


/* Initialize the mutex governing access to the posix shm subsystem */
__private_extern__ void
pshm_lock_init( void )
{

    psx_shm_subsys_lck_grp_attr = lck_grp_attr_alloc_init();

    psx_shm_subsys_lck_grp = lck_grp_alloc_init("posix shared memory", psx_shm_subsys_lck_grp_attr);

    psx_shm_subsys_lck_attr = lck_attr_alloc_init();
    lck_mtx_init(& psx_shm_subsys_mutex, psx_shm_subsys_lck_grp, psx_shm_subsys_lck_attr);
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
pshm_cache_search(struct pshminfo **pshmp, struct pshmname *pnp,
	struct pshmcache **pcache)
{
	struct pshmcache *pcp, *nnp;
	struct pshmhashhead *pcpp;

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
 * XXX should be static?
 */
static int
pshm_cache_add(struct pshminfo *pshmp, struct pshmname *pnp, struct pshmcache *pcp)
{
	struct pshmhashhead *pcpp;
	struct pshminfo *dpinfo;
	struct pshmcache *dpcp;

#if DIAGNOSTIC
	if (pnp->pshm_namelen > NCHNAMLEN)
		panic("cache_enter: name too long");
#endif


	/*  if the entry has already been added by some one else return */
	if (pshm_cache_search(&dpinfo, pnp, &dpcp) == -1) {
		return(EEXIST);
	}
	pshmnument++;

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
		struct pshmcache *p;

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
pshm_cache_init(void)
{
	pshmhashtbl = hashinit(desiredvnodes, M_SHM, &pshmhash);
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
pshm_cache_purge(void)
{
	struct pshmcache *pcp;
	struct pshmhashhead *pcpp;

	for (pcpp = &pshmhashtbl[pshmhash]; pcpp >= pshmhashtbl; pcpp--) {
		while ( (pcp = pcpp->lh_first) )
			pshm_cache_delete(pcp);
	}
}
#endif	/* NOT_USED */

static void
pshm_cache_delete(struct pshmcache *pcp)
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


int
shm_open(struct proc *p, struct shm_open_args *uap, register_t *retval)
{
	struct fileproc *fp;
	size_t  i;
	struct fileproc *nfp;
	int indx, error;
	struct pshmname nd;
	struct pshminfo *pinfo;
	char * pnbuf;
	char * nameptr;
	char * cp;
	size_t pathlen, plen;
	int fmode ;
	int cmode = uap->mode;
	int incache = 0;
	struct pshmnode * pnode = PSHMNODE_NULL;
	struct pshmcache * pcache = PSHMCACHE_NULL;
	struct pshmcache *pcp;
	int pinfo_alloc=0;

	AUDIT_ARG(fflags, uap->oflag);
	AUDIT_ARG(mode, uap->mode);

	pinfo = PSHMINFO_NULL;

	MALLOC_ZONE(pnbuf, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if (pnbuf == NULL) {
		return(ENOSPC);
	}

	pathlen = MAXPATHLEN;
	error = copyinstr(uap->name, (void *)pnbuf, MAXPATHLEN, &pathlen);
	if (error) {
		goto bad;
	}
	AUDIT_ARG(text, pnbuf);
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

#if KTRACE
	if (KTRPOINT(p, KTR_NAMEI))
		ktrnamei(p->p_tracep, nameptr);
#endif
	
	PSHM_SUBSYS_LOCK();
	error = pshm_cache_search(&pinfo, &nd, &pcache);

	if (error == ENOENT) {
		PSHM_SUBSYS_UNLOCK();
		error = EINVAL;
		goto bad;

	}
	if (!error) {
		incache = 0;
	} else
		incache = 1;
	fmode = FFLAGS(uap->oflag);
	if ((fmode & (FREAD | FWRITE))==0) {
		PSHM_SUBSYS_UNLOCK();
		error = EINVAL;
		goto bad;
	}

	/*
	 * XXXXXXXXXX TBD XXXXXXXXXX
	 * There is a race that existed with the funnels as well.
     * Need to be fixed later
	 */
	PSHM_SUBSYS_UNLOCK();
	error = falloc(p, &nfp, &indx);
	if (error ) 
		goto bad;
	PSHM_SUBSYS_LOCK();

	fp = nfp;

	cmode &=  ALLPERMS;

	if (fmode & O_CREAT) {
		if ((fmode & O_EXCL) && incache) {
			AUDIT_ARG(posix_ipc_perm, pinfo->pshm_uid,
				  pinfo->pshm_gid, pinfo->pshm_mode);

			/* shm obj exists and opened O_EXCL */
#if notyet
                        if (pinfo->pshm_flags & PSHM_INDELETE) {
                        }
#endif 
                        error = EEXIST;
						PSHM_SUBSYS_UNLOCK();
                        goto bad1;
                } 
                if (!incache) {
					PSHM_SUBSYS_UNLOCK();
                    /*  create a new one */
                    MALLOC(pinfo, struct pshminfo *, sizeof(struct pshminfo), M_SHM, M_WAITOK|M_ZERO);
		    		if (pinfo == NULL) {
		    			error = ENOSPC;
		    			goto bad1;
		    		}
					PSHM_SUBSYS_LOCK();
					pinfo_alloc = 1;
                    pinfo->pshm_flags = PSHM_DEFINED | PSHM_INCREATE;
                    pinfo->pshm_usecount = 1; /* existence reference */
                    pinfo->pshm_mode = cmode;
                    pinfo->pshm_uid = kauth_cred_getuid(kauth_cred_get());
                    pinfo->pshm_gid = kauth_cred_get()->cr_gid;
			bcopy(pnbuf, &pinfo->pshm_name[0], PSHMNAMLEN);
			pinfo->pshm_name[PSHMNAMLEN]=0;
                } else {
                    /*  already exists */
                        if( pinfo->pshm_flags & PSHM_INDELETE) {
							PSHM_SUBSYS_UNLOCK();
                            error = ENOENT;
                            goto bad1;
                        }	
						AUDIT_ARG(posix_ipc_perm, pinfo->pshm_uid,
						pinfo->pshm_gid, pinfo->pshm_mode);
                        if ( (error = pshm_access(pinfo, fmode, kauth_cred_get(), p)) ) {
							PSHM_SUBSYS_UNLOCK();
                            goto bad1;
						}
                }
	} else {
		if (!incache) {
			/* O_CREAT  is not set and the shm obecj does not exist */
			PSHM_SUBSYS_UNLOCK();
			error = ENOENT;
			goto bad1;
		}
		if( pinfo->pshm_flags & PSHM_INDELETE) {
			PSHM_SUBSYS_UNLOCK();
			error = ENOENT;
			goto bad1;
		}	
		if ( (error = pshm_access(pinfo, fmode, kauth_cred_get(), p)) ) {
			PSHM_SUBSYS_UNLOCK();
			goto bad1;
		}
	}
	if (fmode & O_TRUNC) {
		PSHM_SUBSYS_UNLOCK();
		error = EINVAL;
		goto bad2;
	}
#if DIAGNOSTIC 
	if (fmode & FWRITE)
		pinfo->pshm_writecount++;
	if (fmode & FREAD)
		pinfo->pshm_readcount++;
#endif
	PSHM_SUBSYS_UNLOCK();
	MALLOC(pnode, struct pshmnode *, sizeof(struct pshmnode), M_SHM, M_WAITOK|M_ZERO);
	if (pnode == NULL) {
		error = ENOSPC;
		goto bad2;
	}
	if (!incache) {
		/*
	 	* We allocate a new entry if we are less than the maximum
	 	* allowed and the one at the front of the LRU list is in use.
	 	* Otherwise we use the one at the front of the LRU list.
	 	*/
		MALLOC(pcp, struct pshmcache *, sizeof(struct pshmcache), M_SHM, M_WAITOK|M_ZERO);
		if (pcp == NULL) {
			error = ENOSPC;
			goto bad2;
		}

	}
	PSHM_SUBSYS_LOCK();

	if (!incache) {
		if ( (error = pshm_cache_add(pinfo, &nd, pcp)) ) {
			PSHM_SUBSYS_UNLOCK();
			FREE(pcp, M_SHM);
			goto bad3;
		}
	}
	pinfo->pshm_flags &= ~PSHM_INCREATE;
	pinfo->pshm_usecount++; /* extra reference for the new fd */
	pnode->pinfo = pinfo;

	PSHM_SUBSYS_UNLOCK();
	proc_fdlock(p);
	fp->f_flag = fmode & FMASK;
	fp->f_type = DTYPE_PSXSHM;
	fp->f_ops = &pshmops;
	fp->f_data = (caddr_t)pnode;
	procfdtbl_releasefd(p, indx, NULL);
	fp_drop(p, indx, fp, 1);
	proc_fdunlock(p);

	*retval = indx;
	FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	return (0);
bad3:
	FREE(pnode, M_SHM);
		
bad2:
	if (pinfo_alloc)
		FREE(pinfo, M_SHM);
bad1:
	fp_free(p, indx, fp);
bad:
	FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	return (error);
}


int
pshm_truncate(__unused struct proc *p, struct fileproc *fp, __unused int fd, 
				off_t length, __unused register_t *retval)
{
	struct pshminfo * pinfo;
	struct pshmnode * pnode ;
	kern_return_t kret;
	mach_vm_offset_t user_addr;
	mem_entry_name_port_t mem_object;
	mach_vm_size_t size;

	if (fp->f_type != DTYPE_PSXSHM) {
		return(EINVAL);
	}
	

	if (((pnode = (struct pshmnode *)fp->f_data)) == PSHMNODE_NULL )
		return(EINVAL);

	PSHM_SUBSYS_LOCK();
	if ((pinfo = pnode->pinfo) == PSHMINFO_NULL) {
		PSHM_SUBSYS_UNLOCK();
		return(EINVAL);
	}
	if ((pinfo->pshm_flags & (PSHM_DEFINED | PSHM_ALLOCATED)) 
			!= PSHM_DEFINED) {
		PSHM_SUBSYS_UNLOCK();
		return(EINVAL);
	}

	PSHM_SUBSYS_UNLOCK();
	size = round_page_64(length);
	kret = mach_vm_allocate(current_map(), &user_addr, size, VM_FLAGS_ANYWHERE);
	if (kret != KERN_SUCCESS) 
		goto out;

	kret = mach_make_memory_entry_64 (current_map(), &size,
			user_addr, VM_PROT_DEFAULT, &mem_object, 0);

	if (kret != KERN_SUCCESS) 
		goto out;
	
	mach_vm_deallocate(current_map(), user_addr, size);

	PSHM_SUBSYS_LOCK();
	pinfo->pshm_flags &= ~PSHM_DEFINED;
	pinfo->pshm_flags = PSHM_ALLOCATED;
	pinfo->pshm_memobject = (void *)mem_object;
	pinfo->pshm_length = size;
	PSHM_SUBSYS_UNLOCK();
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
pshm_stat(struct pshmnode *pnode, struct stat *sb)
{
	struct pshminfo *pinfo;
	
	PSHM_SUBSYS_LOCK();
	if ((pinfo = pnode->pinfo) == PSHMINFO_NULL){
		PSHM_SUBSYS_UNLOCK();
		return(EINVAL);
	}

	bzero(sb, sizeof(struct stat)); 
	sb->st_mode = pinfo->pshm_mode;
	sb->st_uid = pinfo->pshm_uid;
	sb->st_gid = pinfo->pshm_gid;
	sb->st_size = pinfo->pshm_length;
	PSHM_SUBSYS_UNLOCK();

	return(0);
}

/*
 * This is called only from shm_open which holds pshm_lock();
 * XXX This code is repeated many times
 */
int
pshm_access(struct pshminfo *pinfo, int mode, kauth_cred_t cred, __unused struct proc *p)
{
	mode_t mask;
	int is_member;

	/* Otherwise, user id 0 always gets access. */
	if (!suser(cred, NULL))
		return (0);

	mask = 0;

	/* Otherwise, check the owner. */
	if (kauth_cred_getuid(cred) == pinfo->pshm_uid) {
		if (mode & FREAD)
			mask |= S_IRUSR;
		if (mode & FWRITE)
			mask |= S_IWUSR;
		return ((pinfo->pshm_mode & mask) == mask ? 0 : EACCES);
	}

	/* Otherwise, check the groups. */
	if (kauth_cred_ismember_gid(cred, pinfo->pshm_gid, &is_member) == 0 && is_member) {
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

int
pshm_mmap(struct proc *p, struct mmap_args *uap, user_addr_t *retval, struct fileproc *fp, off_t pageoff) 
{
	mach_vm_offset_t	user_addr = (mach_vm_offset_t)uap->addr;
	mach_vm_size_t		user_size = (mach_vm_size_t)uap->len ;
	int prot = uap->prot;
	int flags = uap->flags;
	vm_object_offset_t file_pos = (vm_object_offset_t)uap->pos;
	int fd = uap->fd;
	vm_map_t	user_map;
	int		alloc_flags;
	boolean_t 	docow;
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

	PSHM_SUBSYS_LOCK();
	if ((pinfo = pnode->pinfo) == PSHMINFO_NULL) {
		PSHM_SUBSYS_UNLOCK();
		return(EINVAL);
	}

	if ((pinfo->pshm_flags & PSHM_ALLOCATED) != PSHM_ALLOCATED) {
		PSHM_SUBSYS_UNLOCK();
		return(EINVAL);
	}
	if ((off_t)user_size > pinfo->pshm_length) {
		PSHM_SUBSYS_UNLOCK();
		return(EINVAL);
	}
	if ((off_t)(user_size + file_pos) > pinfo->pshm_length) {
		PSHM_SUBSYS_UNLOCK();
		return(EINVAL);
	}
	if ((mem_object =  pinfo->pshm_memobject) == NULL) {
		PSHM_SUBSYS_UNLOCK();
		return(EINVAL);
	}


	PSHM_SUBSYS_UNLOCK();
	user_map = current_map();

	if ((flags & MAP_FIXED) == 0) {
		alloc_flags = VM_FLAGS_ANYWHERE;
		user_addr = mach_vm_round_page(user_addr); 
	} else {
		if (user_addr != mach_vm_trunc_page(user_addr))
			return (EINVAL);
		/*
		 * We do not get rid of the existing mappings here because
		 * it wouldn't be atomic (see comment in mmap()).  We let
		 * Mach VM know that we want it to replace any existing
		 * mapping with the new one.
		 */
		alloc_flags = VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE;
	}
	docow = FALSE;	

	kret = mach_vm_map(user_map, &user_addr, user_size,
			0, alloc_flags, pinfo->pshm_memobject, file_pos, docow,
      	                prot, VM_PROT_DEFAULT, 
			VM_INHERIT_SHARE);
	if (kret != KERN_SUCCESS) 
			goto out;
	/* LP64todo - this should be superfluous at this point */
	kret = mach_vm_inherit(user_map, user_addr, user_size,
				VM_INHERIT_SHARE);
	if (kret != KERN_SUCCESS) {
		(void) mach_vm_deallocate(user_map, user_addr, user_size);
		goto out;
	}
	PSHM_SUBSYS_LOCK();
	pnode->mapp_addr = user_addr;
	pnode->map_size = user_size;
	pinfo->pshm_flags |= (PSHM_MAPPED | PSHM_INUSE);
	PSHM_SUBSYS_UNLOCK();
out:
	switch (kret) {
	case KERN_SUCCESS:
		*retval = (user_addr + pageoff);
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

int
shm_unlink(__unused struct proc *p, struct shm_unlink_args *uap, 
			__unused register_t *retval)
{
	size_t i;
	int error=0;
	struct pshmname nd;
	struct pshminfo *pinfo;
	char * pnbuf;
	char * nameptr;
	char * cp;
	size_t pathlen, plen;
	int incache = 0;
	struct pshmcache *pcache = PSHMCACHE_NULL;

	pinfo = PSHMINFO_NULL;

	MALLOC_ZONE(pnbuf, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if (pnbuf == NULL) {
		return(ENOSPC);		/* XXX non-standard */
	}
	pathlen = MAXPATHLEN;
	error = copyinstr(uap->name, (void *)pnbuf, MAXPATHLEN, &pathlen);
	if (error) {
		goto bad;
	}
	AUDIT_ARG(text, pnbuf);
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

	PSHM_SUBSYS_LOCK();
	error = pshm_cache_search(&pinfo, &nd, &pcache);

	if (error == ENOENT) {
		PSHM_SUBSYS_UNLOCK();
		error = EINVAL;
		goto bad;

	}
	if (!error) {
		PSHM_SUBSYS_UNLOCK();
		error = EINVAL;
		goto bad;
	} else
		incache = 1;

	if ((pinfo->pshm_flags & (PSHM_DEFINED | PSHM_ALLOCATED))==0) {
		PSHM_SUBSYS_UNLOCK();
		return (EINVAL);
	}

	if (pinfo->pshm_flags & PSHM_INDELETE) {
		PSHM_SUBSYS_UNLOCK();
		error = 0;
		goto bad;
	}

	AUDIT_ARG(posix_ipc_perm, pinfo->pshm_uid, pinfo->pshm_gid,
		  pinfo->pshm_mode);

	/*
	 * JMM - How should permissions be checked?
	 */

	pinfo->pshm_flags |= PSHM_INDELETE;
	pshm_cache_delete(pcache);
	pinfo->pshm_flags |= PSHM_REMOVED;
	/* release the existence reference */
 	if (!--pinfo->pshm_usecount) {
		PSHM_SUBSYS_UNLOCK();
		/*
		 * If this is the last reference going away on the object,
		 * then we need to destroy the backing object.  The name
		 * has an implied but uncounted reference on the object,
		 * once it's created, since it's used as a rendesvous, and
		 * therefore may be subsequently reopened.
		 */
		if (pinfo->pshm_memobject != NULL)
			mach_memory_entry_port_release(pinfo->pshm_memobject);
		PSHM_SUBSYS_LOCK();
		FREE(pinfo,M_SHM);
	}
	PSHM_SUBSYS_UNLOCK();
	FREE(pcache, M_SHM);
	error = 0;
bad:
	FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	return (error);
}

/* already called locked */
static int
pshm_close(struct pshmnode *pnode)
{
	int error=0;
	struct pshminfo *pinfo;

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
	pinfo->pshm_usecount--; /* release this fd's reference */

 	if ((pinfo->pshm_flags & PSHM_REMOVED) && !pinfo->pshm_usecount) {
		PSHM_SUBSYS_UNLOCK();
		/*
		 * If this is the last reference going away on the object,
		 * then we need to destroy the backing object.
		 */
		if (pinfo->pshm_memobject != NULL)
			mach_memory_entry_port_release(pinfo->pshm_memobject);
		PSHM_SUBSYS_LOCK();
		FREE(pinfo,M_SHM);
	}
	FREE(pnode, M_SHM);
	return (error);
}

/* struct proc passed to match prototype for struct fileops */
static int
pshm_closefile(struct fileglob *fg, __unused struct proc *p)
{
	int error;

	PSHM_SUBSYS_LOCK();
	error =  pshm_close(((struct pshmnode *)fg->fg_data));
	PSHM_SUBSYS_UNLOCK();
	return(error);
}

static int
pshm_read(__unused struct fileproc *fp, __unused struct uio *uio, 
			__unused kauth_cred_t cred, __unused int flags, 
			__unused struct proc *p)
{
	return(ENOTSUP);
}

static int
pshm_write(__unused struct fileproc *fp, __unused struct uio *uio, 
			__unused kauth_cred_t cred, __unused int flags, 
			__unused struct proc *p)
{
	return(ENOTSUP);
}

static int
pshm_ioctl(__unused struct fileproc *fp, __unused u_long com, 
			__unused caddr_t data, __unused struct proc *p)
{
	return(ENOTSUP);
}

static int
pshm_select(__unused struct fileproc *fp, __unused int which, __unused void *wql, 
			__unused struct proc *p)
{
	return(ENOTSUP);
}

static int
pshm_kqfilter(__unused struct fileproc *fp, __unused struct knote *kn, 
				__unused struct proc *p)
{
	return(ENOTSUP);
}

int
fill_pshminfo(struct pshmnode * pshm, struct pshm_info * info)
{
	struct pshminfo *pinfo;
	struct stat *sb;
	
	PSHM_SUBSYS_LOCK();
	if ((pinfo = pshm->pinfo) == PSHMINFO_NULL){
		PSHM_SUBSYS_UNLOCK();
		return(EINVAL);
	}

	sb = &info->pshm_stat;

	bzero(sb, sizeof(struct stat)); 
	sb->st_mode = pinfo->pshm_mode;
	sb->st_uid = pinfo->pshm_uid;
	sb->st_gid = pinfo->pshm_gid;
	sb->st_size = pinfo->pshm_length;

	info->pshm_mappaddr = pshm->mapp_addr;
	bcopy(&pinfo->pshm_name[0], &info->pshm_name[0], PSHMNAMLEN+1); 

	PSHM_SUBSYS_UNLOCK();
	return(0);
}


