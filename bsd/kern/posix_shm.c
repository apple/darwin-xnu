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
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
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
#include <sys/vnode_internal.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysproto.h>
#include <sys/proc_info.h>
#include <security/audit/audit.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach/vm_prot.h>
#include <mach/vm_inherit.h>
#include <mach/kern_return.h>
#include <mach/memory_object_control.h>

#include <vm/vm_map.h>
#include <vm/vm_protos.h>

#define f_flag f_fglob->fg_flag
#define f_type f_fglob->fg_ops->fo_type
#define f_msgcount f_fglob->fg_msgcount
#define f_cred f_fglob->fg_cred
#define f_ops f_fglob->fg_ops
#define f_offset f_fglob->fg_offset
#define f_data f_fglob->fg_data
#define	PSHMNAMLEN	31	/* maximum name segment length we bother with */

struct pshmobj {
	void *			pshmo_memobject;
	memory_object_size_t	pshmo_size;
	struct pshmobj *	pshmo_next;
};

struct pshminfo {
	unsigned int	pshm_flags;
	unsigned int	pshm_usecount;
	off_t		pshm_length;
	mode_t		pshm_mode;
	uid_t		pshm_uid;
	gid_t		pshm_gid;
	char		pshm_name[PSHMNAMLEN + 1];	/* segment name */
	struct pshmobj *pshm_memobjects;
#if DIAGNOSTIC
	unsigned int 	pshm_readcount;
	unsigned int 	pshm_writecount;
	proc_t		pshm_proc;
#endif /* DIAGNOSTIC */
	struct label*	pshm_label;
};
#define PSHMINFO_NULL (struct pshminfo *)0

#define	PSHM_NONE	0x001
#define	PSHM_DEFINED	0x002
#define	PSHM_ALLOCATED	0x004
#define	PSHM_MAPPED	0x008
#define	PSHM_INUSE	0x010
#define	PSHM_REMOVED	0x020
#define	PSHM_INCREATE	0x040
#define	PSHM_INDELETE	0x080
#define PSHM_ALLOCATING	0x100

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
	user_size_t	map_size;	/* XXX unused ? */
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
		    int flags, vfs_context_t ctx);
static int pshm_write (struct fileproc *fp, struct uio *uio,
		    int flags, vfs_context_t ctx);
static int pshm_ioctl (struct fileproc *fp, u_long com,
		    caddr_t data, vfs_context_t ctx);
static int pshm_select (struct fileproc *fp, int which, void *wql, vfs_context_t ctx);
static int pshm_close(struct pshminfo *pinfo, int dropref);
static int pshm_closefile (struct fileglob *fg, vfs_context_t ctx);

static int pshm_kqfilter(struct fileproc *fp, struct knote *kn, vfs_context_t ctx);

int pshm_access(struct pshminfo *pinfo, int mode, kauth_cred_t cred, proc_t p);
static int pshm_cache_add(struct pshminfo *pshmp, struct pshmname *pnp, struct pshmcache *pcp);
static void pshm_cache_delete(struct pshmcache *pcp);
#if NOT_USED
static void pshm_cache_purge(void);
#endif	/* NOT_USED */
static int pshm_cache_search(struct pshminfo **pshmp, struct pshmname *pnp,
	struct pshmcache **pcache, int addref);

static const struct fileops pshmops = {
	DTYPE_PSXSHM,
	pshm_read,
	pshm_write,
	pshm_ioctl,
	pshm_select,
	pshm_closefile,
	pshm_kqfilter,
	0
};

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
	struct pshmcache **pcache, int addref)
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
		if (addref)
			pcp->pshminfo->pshm_usecount++;
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
	if (pnp->pshm_namelen > PSHMNAMLEN)
		panic("cache_enter: name too long");
#endif


	/*  if the entry has already been added by some one else return */
	if (pshm_cache_search(&dpinfo, pnp, &dpcp, 0) == -1) {
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
	pshmhashtbl = hashinit(desiredvnodes / 8, M_SHM, &pshmhash);
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
shm_open(proc_t p, struct shm_open_args *uap, int32_t *retval)
{
	size_t  i;
	int indx, error;
	struct pshmname nd;
	struct pshminfo *pinfo;
	struct fileproc *fp = NULL;
	char *pnbuf = NULL;
	struct pshminfo *new_pinfo = PSHMINFO_NULL;
	struct pshmnode *new_pnode = PSHMNODE_NULL;
	struct pshmcache *pcache = PSHMCACHE_NULL;	/* ignored on return */
	char * nameptr;
	char * cp;
	size_t pathlen, plen;
	int fmode ;
	int cmode = uap->mode;
	int incache = 0;
	struct pshmcache *pcp = NULL;

	AUDIT_ARG(fflags, uap->oflag);
	AUDIT_ARG(mode, uap->mode);

	pinfo = PSHMINFO_NULL;

	/*
	 * Preallocate everything we might need up front to avoid taking
	 * and dropping the lock, opening us up to race conditions.
	 */
	MALLOC_ZONE(pnbuf, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if (pnbuf == NULL) {
		error = ENOSPC;
		goto bad;
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

	/*
	 * attempt to allocate a new fp; if unsuccessful, the fp will be
	 * left unmodified (NULL).
	 */
	error = falloc(p, &fp, &indx, vfs_context_current());
	if (error) 
		goto bad;

	cmode &=  ALLPERMS;

	fmode = FFLAGS(uap->oflag);
	if ((fmode & (FREAD | FWRITE)) == 0) {
		error = EINVAL;
		goto bad;
	}

	/*
	 * We allocate a new entry if we are less than the maximum
	 * allowed and the one at the front of the LRU list is in use.
	 * Otherwise we use the one at the front of the LRU list.
	 */
	MALLOC(pcp, struct pshmcache *, sizeof(struct pshmcache), M_SHM, M_WAITOK|M_ZERO);
	if (pcp == NULL) {
		error = ENOSPC;
		goto bad;
	}

	MALLOC(new_pinfo, struct pshminfo *, sizeof(struct pshminfo), M_SHM, M_WAITOK|M_ZERO);
	if (new_pinfo == PSHMINFO_NULL) {
		error = ENOSPC;
		goto bad;
	}
#if CONFIG_MACF
	mac_posixshm_label_init(new_pinfo);
#endif

	MALLOC(new_pnode, struct pshmnode *, sizeof(struct pshmnode), M_SHM, M_WAITOK|M_ZERO);
	if (new_pnode == PSHMNODE_NULL) {
		error = ENOSPC;
		goto bad;
	}

	PSHM_SUBSYS_LOCK();

	/*
	 * If we find the entry in the cache, this will take a reference,
	 * allowing us to unlock it for the permissions check.
	 */
	error = pshm_cache_search(&pinfo, &nd, &pcache, 1);

	PSHM_SUBSYS_UNLOCK();

	if (error == ENOENT) {
		error = EINVAL;
		goto bad;
	}

	if (!error) {
		incache = 0;
		if (fmode & O_CREAT) {
			/*  create a new one (commit the allocation) */
			pinfo = new_pinfo;
			pinfo->pshm_flags = PSHM_DEFINED | PSHM_INCREATE;
			pinfo->pshm_usecount = 1; /* existence reference */
			pinfo->pshm_mode = cmode;
			pinfo->pshm_uid = kauth_getuid();
			pinfo->pshm_gid = kauth_getgid();
			bcopy(pnbuf, &pinfo->pshm_name[0], pathlen);
			pinfo->pshm_name[pathlen]=0;
#if CONFIG_MACF
			error = mac_posixshm_check_create(kauth_cred_get(), nameptr);
			if (error) {
				goto bad;
			}
			mac_posixshm_label_associate(kauth_cred_get(), pinfo, nameptr);
#endif
		}
	} else {
		incache = 1;
		if (fmode & O_CREAT) {
			/*  already exists */
			if ((fmode & O_EXCL)) {
				AUDIT_ARG(posix_ipc_perm, pinfo->pshm_uid,
						pinfo->pshm_gid,
						pinfo->pshm_mode);

				/* shm obj exists and opened O_EXCL */
				error = EEXIST;
				goto bad;
			} 

			if( pinfo->pshm_flags & PSHM_INDELETE) {
				error = ENOENT;
				goto bad;
			}	
			AUDIT_ARG(posix_ipc_perm, pinfo->pshm_uid,
					pinfo->pshm_gid, pinfo->pshm_mode);
#if CONFIG_MACF	
			if ((error = mac_posixshm_check_open(kauth_cred_get(), pinfo, fmode))) {
				goto bad;
			}
#endif
			if ( (error = pshm_access(pinfo, fmode, kauth_cred_get(), p)) ) {
				goto bad;
			}
		}
	}
	if (!(fmode & O_CREAT)) {
		if (!incache) {
			/* O_CREAT is not set and the object does not exist */
			error = ENOENT;
			goto bad;
		}
		if( pinfo->pshm_flags & PSHM_INDELETE) {
			error = ENOENT;
			goto bad;
		}	
#if CONFIG_MACF	
		if ((error = mac_posixshm_check_open(kauth_cred_get(), pinfo, fmode))) {
			goto bad;
		}
#endif

		if ((error = pshm_access(pinfo, fmode, kauth_cred_get(), p))) {
			goto bad;
		}
	}
	if (fmode & O_TRUNC) {
		error = EINVAL;
		goto bad;
	}


	PSHM_SUBSYS_LOCK();

#if DIAGNOSTIC 
	if (fmode & FWRITE)
		pinfo->pshm_writecount++;
	if (fmode & FREAD)
		pinfo->pshm_readcount++;
#endif
	if (!incache) {
		/* if successful, this will consume the pcp */
		if ( (error = pshm_cache_add(pinfo, &nd, pcp)) ) {
			goto bad_locked;
		}
		/*
		 * add reference for the new entry; otherwise, we obtained
		 * one from the cache hit earlier.
		 */
		pinfo->pshm_usecount++;
	}
	pinfo->pshm_flags &= ~PSHM_INCREATE;
	new_pnode->pinfo = pinfo;

	PSHM_SUBSYS_UNLOCK();

	/*
	 * if incache, we did not use the new pcp or new_pinfo and must
	 * free them
	 */
	if (incache) {
		FREE(pcp, M_SHM);

		if (new_pinfo != PSHMINFO_NULL) {
#if CONFIG_MACF
			mac_posixshm_label_destroy(new_pinfo);
#endif
			FREE(new_pinfo, M_SHM);
		}
	}

	proc_fdlock(p);
	fp->f_flag = fmode & FMASK;
	fp->f_ops = &pshmops;
	fp->f_data = (caddr_t)new_pnode;
	*fdflags(p, indx) |= UF_EXCLOSE;
	procfdtbl_releasefd(p, indx, NULL);
	fp_drop(p, indx, fp, 1);
	proc_fdunlock(p);

	*retval = indx;
	FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	return (0);

bad_locked:
	PSHM_SUBSYS_UNLOCK();
bad:
	/*
	 * If we obtained the entry from the cache, we need to drop the
	 * reference; holding the reference may have prevented unlinking,
	 * so we need to call pshm_close() to get the full effect.
	 */
	if (incache) {
		PSHM_SUBSYS_LOCK();
		pshm_close(pinfo, 1);
		PSHM_SUBSYS_UNLOCK();
	}

	if (pcp != NULL)
		FREE(pcp, M_SHM);

	if (new_pnode != PSHMNODE_NULL)
		FREE(new_pnode, M_SHM);

	if (fp != NULL)
		fp_free(p, indx, fp);

	if (new_pinfo != PSHMINFO_NULL) {
#if CONFIG_MACF
		mac_posixshm_label_destroy(new_pinfo);
#endif
		FREE(new_pinfo, M_SHM);
	}
	if (pnbuf != NULL)
		FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	return (error);
}


int
pshm_truncate(__unused proc_t p, struct fileproc *fp, __unused int fd, 
				off_t length, __unused int32_t *retval)
{
	struct pshminfo * pinfo;
	struct pshmnode * pnode ;
	kern_return_t kret;
	mem_entry_name_port_t mem_object;
	mach_vm_size_t total_size, alloc_size;
	memory_object_size_t mosize;
	struct pshmobj *pshmobj, *pshmobj_next, **pshmobj_next_p;
	vm_map_t	user_map;
#if CONFIG_MACF
	int error;
#endif

	user_map = current_map();

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
	if ((pinfo->pshm_flags & (PSHM_DEFINED|PSHM_ALLOCATING|PSHM_ALLOCATED)) 
			!= PSHM_DEFINED) {
		PSHM_SUBSYS_UNLOCK();
		return(EINVAL);
	}
#if CONFIG_MACF
	error = mac_posixshm_check_truncate(kauth_cred_get(), pinfo, length);
	if (error) {
		PSHM_SUBSYS_UNLOCK();
		return(error);
	}
#endif

	pinfo->pshm_flags |= PSHM_ALLOCATING;
	total_size = vm_map_round_page(length,
				       vm_map_page_mask(user_map));
	pshmobj_next_p = &pinfo->pshm_memobjects;

	for (alloc_size = 0;
	     alloc_size < total_size;
	     alloc_size += mosize) {

		PSHM_SUBSYS_UNLOCK();

		mosize = MIN(total_size - alloc_size, ANON_MAX_SIZE);
		kret = mach_make_memory_entry_64(
			VM_MAP_NULL,
			&mosize,
			0,
			MAP_MEM_NAMED_CREATE | VM_PROT_DEFAULT,
			&mem_object,
			0);

		if (kret != KERN_SUCCESS) 
			goto out;

		MALLOC(pshmobj, struct pshmobj *, sizeof (struct pshmobj),
		       M_SHM, M_WAITOK);
		if (pshmobj == NULL) {
			kret = KERN_NO_SPACE;
			mach_memory_entry_port_release(mem_object);
			mem_object = NULL;
			goto out;
		}

		PSHM_SUBSYS_LOCK();

		pshmobj->pshmo_memobject = (void *) mem_object;
		pshmobj->pshmo_size = mosize;
		pshmobj->pshmo_next = NULL;
		
		*pshmobj_next_p = pshmobj;
		pshmobj_next_p = &pshmobj->pshmo_next;
	}
	
	pinfo->pshm_flags = PSHM_ALLOCATED;
	pinfo->pshm_length = total_size;
	PSHM_SUBSYS_UNLOCK();
	return(0);

out:
	PSHM_SUBSYS_LOCK();
	for (pshmobj = pinfo->pshm_memobjects;
	     pshmobj != NULL;
	     pshmobj = pshmobj_next) {
		pshmobj_next = pshmobj->pshmo_next;
		mach_memory_entry_port_release(pshmobj->pshmo_memobject);
		FREE(pshmobj, M_SHM);
	}
	pinfo->pshm_memobjects = NULL;
	pinfo->pshm_flags &= ~PSHM_ALLOCATING;
	PSHM_SUBSYS_UNLOCK();

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
pshm_stat(struct pshmnode *pnode, void *ub, int isstat64)
{
	struct stat *sb = (struct stat *)0;	/* warning avoidance ; protected by isstat64 */
	struct stat64 * sb64 = (struct stat64 *)0;  /* warning avoidance ; protected by isstat64 */
	struct pshminfo *pinfo;
#if CONFIG_MACF
	int error;
#endif
	
	PSHM_SUBSYS_LOCK();
	if ((pinfo = pnode->pinfo) == PSHMINFO_NULL){
		PSHM_SUBSYS_UNLOCK();
		return(EINVAL);
	}

#if CONFIG_MACF
	error = mac_posixshm_check_stat(kauth_cred_get(), pinfo);
	if (error) {
		PSHM_SUBSYS_UNLOCK();
		return(error);
	}
#endif

	if (isstat64 != 0) {
		sb64 = (struct stat64 *)ub;
		bzero(sb64, sizeof(struct stat64)); 
		sb64->st_mode = pinfo->pshm_mode;
		sb64->st_uid = pinfo->pshm_uid;
		sb64->st_gid = pinfo->pshm_gid;
		sb64->st_size = pinfo->pshm_length;
	} else {
		sb = (struct stat *)ub;
		bzero(sb, sizeof(struct stat)); 
		sb->st_mode = pinfo->pshm_mode;
		sb->st_uid = pinfo->pshm_uid;
		sb->st_gid = pinfo->pshm_gid;
		sb->st_size = pinfo->pshm_length;
	}
	PSHM_SUBSYS_UNLOCK();

	return(0);
}

/*
 * This is called only from shm_open which holds pshm_lock();
 * XXX This code is repeated many times
 */
int
pshm_access(struct pshminfo *pinfo, int mode, kauth_cred_t cred, __unused proc_t p)
{
	int mode_req = ((mode & FREAD) ? S_IRUSR : 0) |
		       ((mode & FWRITE) ? S_IWUSR : 0);

	/* Otherwise, user id 0 always gets access. */
	if (!suser(cred, NULL))
		return (0);

	return(posix_cred_access(cred, pinfo->pshm_uid, pinfo->pshm_gid, pinfo->pshm_mode, mode_req));
}

int
pshm_mmap(__unused proc_t p, struct mmap_args *uap, user_addr_t *retval, struct fileproc *fp, off_t pageoff) 
{
	vm_map_offset_t	user_addr = (vm_map_offset_t)uap->addr;
	vm_map_size_t	user_size = (vm_map_size_t)uap->len ;
	vm_map_offset_t	user_start_addr;
	vm_map_size_t	map_size, mapped_size;
	int prot = uap->prot;
	int flags = uap->flags;
	vm_object_offset_t file_pos = (vm_object_offset_t)uap->pos;
	vm_object_offset_t map_pos;
	vm_map_t	user_map;
	int		alloc_flags;
	boolean_t 	docow;
	kern_return_t	kret;
	struct pshminfo * pinfo;
	struct pshmnode * pnode;
	struct pshmobj * pshmobj;
#if CONFIG_MACF
	int error;
#endif

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
	if ((pshmobj = pinfo->pshm_memobjects) == NULL) {
		PSHM_SUBSYS_UNLOCK();
		return(EINVAL);
	}

#if CONFIG_MACF
	error = mac_posixshm_check_mmap(kauth_cred_get(), pinfo, prot, flags);
	if (error) {
		PSHM_SUBSYS_UNLOCK();
		return(error);
	}
#endif

	PSHM_SUBSYS_UNLOCK();
	user_map = current_map();

	if ((flags & MAP_FIXED) == 0) {
		alloc_flags = VM_FLAGS_ANYWHERE;
		user_addr = vm_map_round_page(user_addr,
					      vm_map_page_mask(user_map)); 
	} else {
		if (user_addr != vm_map_round_page(user_addr,
						   vm_map_page_mask(user_map)))
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

	mapped_size = 0;

	/* reserver the entire space first... */
	kret = vm_map_enter_mem_object(user_map,
				       &user_addr,
				       user_size,
				       0,
				       alloc_flags,
				       IPC_PORT_NULL,
				       0,
				       FALSE,
				       VM_PROT_NONE,
				       VM_PROT_NONE,
				       VM_INHERIT_NONE);
	user_start_addr = user_addr;
	if (kret != KERN_SUCCESS) {
		goto out;
	}

	/* ... and overwrite with the real mappings */
	for (map_pos = 0, pshmobj = pinfo->pshm_memobjects;
	     user_size != 0;
	     map_pos += pshmobj->pshmo_size, pshmobj = pshmobj->pshmo_next) {
		if (pshmobj == NULL) {
			/* nothing there to map !? */
			goto out;
		}
		if (file_pos >= map_pos + pshmobj->pshmo_size) {
			continue;
		}
		map_size = pshmobj->pshmo_size - (file_pos - map_pos);
		if (map_size > user_size) {
			map_size = user_size;
		}
		kret = vm_map_enter_mem_object(
			user_map,
			&user_addr,
			map_size,
			0,
			VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
			pshmobj->pshmo_memobject,
			file_pos - map_pos,
			docow,
			prot,
			VM_PROT_DEFAULT, 
			VM_INHERIT_SHARE);
		if (kret != KERN_SUCCESS) 
			goto out;

		user_addr += map_size;
		user_size -= map_size;
		mapped_size += map_size;
		file_pos += map_size;
	}

	PSHM_SUBSYS_LOCK();
	pnode->mapp_addr = user_start_addr;
	pnode->map_size = mapped_size;
	pinfo->pshm_flags |= (PSHM_MAPPED | PSHM_INUSE);
	PSHM_SUBSYS_UNLOCK();
out:
	if (kret != KERN_SUCCESS) {
		if (mapped_size != 0) {
			(void) mach_vm_deallocate(current_map(),
						  user_start_addr,
						  mapped_size);
		}
	}

	switch (kret) {
	case KERN_SUCCESS:
		*retval = (user_start_addr + pageoff);
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
shm_unlink(__unused proc_t p, struct shm_unlink_args *uap, 
			__unused int32_t *retval)
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
	struct pshmobj *pshmobj, *pshmobj_next;

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
	error = pshm_cache_search(&pinfo, &nd, &pcache, 0);

	if (error == ENOENT) {
		PSHM_SUBSYS_UNLOCK();
		goto bad;

	}
	/* During unlink lookup failure also implies ENOENT */ 
	if (!error) {
		PSHM_SUBSYS_UNLOCK();
		error = ENOENT;
		goto bad;
	} else
		incache = 1;

	if ((pinfo->pshm_flags & (PSHM_DEFINED | PSHM_ALLOCATED))==0) {
		PSHM_SUBSYS_UNLOCK();
		error = EINVAL;
		goto bad;
	}

	if (pinfo->pshm_flags & PSHM_ALLOCATING) {
		/* XXX should we wait for flag to clear and then proceed ? */
		PSHM_SUBSYS_UNLOCK();
		error = EAGAIN;
		goto bad;
	}

	if (pinfo->pshm_flags & PSHM_INDELETE) {
		PSHM_SUBSYS_UNLOCK();
		error = 0;
		goto bad;
	}
#if CONFIG_MACF
	error = mac_posixshm_check_unlink(kauth_cred_get(), pinfo, nameptr);
	if (error) {
		PSHM_SUBSYS_UNLOCK();
		goto bad;
	}
#endif

	AUDIT_ARG(posix_ipc_perm, pinfo->pshm_uid, pinfo->pshm_gid,
		  pinfo->pshm_mode);

	/* 
	 * following file semantics, unlink should be allowed 
	 * for users with write permission only. 
	 */
	if ( (error = pshm_access(pinfo, FWRITE, kauth_cred_get(), p)) ) {
		PSHM_SUBSYS_UNLOCK();
		goto bad;
	}

	pinfo->pshm_flags |= PSHM_INDELETE;
	pshm_cache_delete(pcache);
	pinfo->pshm_flags |= PSHM_REMOVED;
	/* release the existence reference */
 	if (!--pinfo->pshm_usecount) {
#if CONFIG_MACF
		mac_posixshm_label_destroy(pinfo);
#endif
		PSHM_SUBSYS_UNLOCK();
		/*
		 * If this is the last reference going away on the object,
		 * then we need to destroy the backing object.  The name
		 * has an implied but uncounted reference on the object,
		 * once it's created, since it's used as a rendezvous, and
		 * therefore may be subsequently reopened.
		 */
		for (pshmobj = pinfo->pshm_memobjects;
		     pshmobj != NULL;
		     pshmobj = pshmobj_next) {
			mach_memory_entry_port_release(pshmobj->pshmo_memobject);
			pshmobj_next = pshmobj->pshmo_next;
			FREE(pshmobj, M_SHM);
		}
		FREE(pinfo,M_SHM);
	} else {
		PSHM_SUBSYS_UNLOCK();
	}
	FREE(pcache, M_SHM);
	error = 0;
bad:
	FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	return (error);
}

/* already called locked */
static int
pshm_close(struct pshminfo *pinfo, int dropref)
{
	int error = 0;
	struct pshmobj *pshmobj, *pshmobj_next;

	/*
	 * If we are dropping the reference we took on the cache object, don't
	 * enforce the allocation requirement.
	 */
	if ( !dropref && ((pinfo->pshm_flags & PSHM_ALLOCATED) != PSHM_ALLOCATED)) {
		return(EINVAL);
	}
#if DIAGNOSTIC
	if(!pinfo->pshm_usecount) {
		kprintf("negative usecount in pshm_close\n");
	}
#endif /* DIAGNOSTIC */
	pinfo->pshm_usecount--; /* release this fd's reference */

 	if ((pinfo->pshm_flags & PSHM_REMOVED) && !pinfo->pshm_usecount) {
#if CONFIG_MACF
		mac_posixshm_label_destroy(pinfo);
#endif
		PSHM_SUBSYS_UNLOCK();
		/*
		 * If this is the last reference going away on the object,
		 * then we need to destroy the backing object.
		 */
		for (pshmobj = pinfo->pshm_memobjects;
		     pshmobj != NULL;
		     pshmobj = pshmobj_next) {
			mach_memory_entry_port_release(pshmobj->pshmo_memobject);
			pshmobj_next = pshmobj->pshmo_next;
			FREE(pshmobj, M_SHM);
		}
		PSHM_SUBSYS_LOCK();
		FREE(pinfo,M_SHM);
	}
	return (error);
}

/* vfs_context_t passed to match prototype for struct fileops */
static int
pshm_closefile(struct fileglob *fg, __unused vfs_context_t ctx)
{
	int error = EINVAL;
	struct pshmnode *pnode;

	PSHM_SUBSYS_LOCK();

	if ((pnode = (struct pshmnode *)fg->fg_data) != NULL) {
		if (pnode->pinfo != PSHMINFO_NULL) {
			error =  pshm_close(pnode->pinfo, 0);
		}
		FREE(pnode, M_SHM);
	}

	PSHM_SUBSYS_UNLOCK();

	return(error);
}

static int
pshm_read(__unused struct fileproc *fp, __unused struct uio *uio, 
			__unused int flags, __unused vfs_context_t ctx)
{
	return(ENOTSUP);
}

static int
pshm_write(__unused struct fileproc *fp, __unused struct uio *uio, 
			__unused int flags, __unused vfs_context_t ctx)
{
	return(ENOTSUP);
}

static int
pshm_ioctl(__unused struct fileproc *fp, __unused u_long com, 
			__unused caddr_t data, __unused vfs_context_t ctx)
{
	return(ENOTSUP);
}

static int
pshm_select(__unused struct fileproc *fp, __unused int which, __unused void *wql, 
			__unused vfs_context_t ctx)
{
	return(ENOTSUP);
}

static int
pshm_kqfilter(__unused struct fileproc *fp, __unused struct knote *kn, 
				__unused vfs_context_t ctx)
{
	return(ENOTSUP);
}

int
fill_pshminfo(struct pshmnode * pshm, struct pshm_info * info)
{
	struct pshminfo *pinfo;
	struct vinfo_stat *sb;
	
	PSHM_SUBSYS_LOCK();
	if ((pinfo = pshm->pinfo) == PSHMINFO_NULL){
		PSHM_SUBSYS_UNLOCK();
		return(EINVAL);
	}

	sb = &info->pshm_stat;

	bzero(sb, sizeof(struct vinfo_stat)); 
	sb->vst_mode = pinfo->pshm_mode;
	sb->vst_uid = pinfo->pshm_uid;
	sb->vst_gid = pinfo->pshm_gid;
	sb->vst_size = pinfo->pshm_length;

	info->pshm_mappaddr = pshm->mapp_addr;
	bcopy(&pinfo->pshm_name[0], &info->pshm_name[0], PSHMNAMLEN+1); 

	PSHM_SUBSYS_UNLOCK();
	return(0);
}

#if CONFIG_MACF
void
pshm_label_associate(struct fileproc *fp, struct vnode *vp, vfs_context_t ctx)
{
	struct pshmnode *pnode;
	struct pshminfo *pshm;

	PSHM_SUBSYS_LOCK();
	pnode = (struct pshmnode *)fp->f_fglob->fg_data;
	if (pnode != NULL) {
		pshm = pnode->pinfo;
		if (pshm != NULL)
			mac_posixshm_vnode_label_associate(
				vfs_context_ucred(ctx), pshm, pshm->pshm_label,
				vp, vp->v_label);
	}
	PSHM_SUBSYS_UNLOCK();
}
#endif
