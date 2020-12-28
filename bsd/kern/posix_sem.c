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
 * posix_sem.c : Support for POSIX semaphore APIs
 *
 *	File:	posix_sem.c
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
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/malloc.h>
#include <sys/semaphore.h>
#include <sys/sysproto.h>
#include <sys/proc_info.h>

#if CONFIG_MACF
#include <sys/vnode_internal.h>
#include <security/mac_framework.h>
#endif

#include <security/audit/audit.h>

#include <mach/mach_types.h>
#include <mach/vm_prot.h>
#include <mach/semaphore.h>
#include <mach/sync_policy.h>
#include <mach/task.h>
#include <kern/kern_types.h>
#include <kern/task.h>
#include <kern/clock.h>
#include <mach/kern_return.h>


#define f_flag f_fglob->fg_flag
#define f_type f_fglob->fg_ops->fo_type
#define f_msgcount f_fglob->fg_msgcount
#define f_cred f_fglob->fg_cred
#define f_ops f_fglob->fg_ops
#define f_offset f_fglob->fg_offset
#define f_data f_fglob->fg_data
#define PSEMNAMLEN      31      /* maximum name segment length we bother with */

struct pseminfo {
	unsigned int    psem_flags;
	unsigned int    psem_usecount;
	mode_t          psem_mode;
	uid_t           psem_uid;
	gid_t           psem_gid;
	char            psem_name[PSEMNAMLEN + 1];      /* segment name */
	semaphore_t     psem_semobject;
	struct label *  psem_label;
	pid_t           psem_creator_pid;
	uint64_t        psem_creator_uniqueid;
};
#define PSEMINFO_NULL (struct pseminfo *)0

#define PSEM_NONE       1
#define PSEM_DEFINED    2
#define PSEM_ALLOCATED  4
#define PSEM_MAPPED     8
#define PSEM_INUSE      0x10
#define PSEM_REMOVED    0x20
#define PSEM_INCREATE   0x40
#define PSEM_INDELETE   0x80

struct  psemcache {
	LIST_ENTRY(psemcache) psem_hash;        /* hash chain */
	struct  pseminfo *pseminfo;             /* vnode the name refers to */
	int     psem_nlen;              /* length of name */
	char    psem_name[PSEMNAMLEN + 1];      /* segment name */
};
#define PSEMCACHE_NULL (struct psemcache *)0

#define PSEMCACHE_NOTFOUND (0)
#define PSEMCACHE_FOUND    (-1)
#define PSEMCACHE_NEGATIVE (ENOENT)

struct  psemstats {
	long    goodhits;               /* hits that we can really use */
	long    neghits;                /* negative hits that we can use */
	long    badhits;                /* hits we must drop */
	long    falsehits;              /* hits with id mismatch */
	long    miss;           /* misses */
	long    longnames;              /* long names that ignore cache */
};

struct psemname {
	char    *psem_nameptr;  /* pointer to looked up name */
	long    psem_namelen;   /* length of looked up component */
	u_int32_t       psem_hash;      /* hash value of looked up name */
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
LIST_HEAD(psemhashhead, psemcache) * psemhashtbl;        /* Hash Table */
u_long  psemhash;                               /* size of hash table - 1 */
long    psemnument;                     /* number of cache entries allocated */
long    posix_sem_max = 10000;          /* tunable for max POSIX semaphores */
                                        /* 10000 limits to ~1M of memory */
SYSCTL_NODE(_kern, KERN_POSIX, posix, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "Posix");
SYSCTL_NODE(_kern_posix, OID_AUTO, sem, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "Semaphores");
SYSCTL_LONG(_kern_posix_sem, OID_AUTO, max, CTLFLAG_RW | CTLFLAG_LOCKED, &posix_sem_max, "max");

struct psemstats psemstats;             /* cache effectiveness statistics */

static int psem_access(struct pseminfo *pinfo, int mode, kauth_cred_t cred);
static int psem_cache_search(struct pseminfo **,
    struct psemname *, struct psemcache **);
static int psem_delete(struct pseminfo * pinfo);

static int psem_closefile(struct fileglob *fp, vfs_context_t ctx);
static int psem_unlink_internal(struct pseminfo *pinfo, struct psemcache *pcache);

static const struct fileops psemops = {
	.fo_type     = DTYPE_PSXSEM,
	.fo_read     = fo_no_read,
	.fo_write    = fo_no_write,
	.fo_ioctl    = fo_no_ioctl,
	.fo_select   = fo_no_select,
	.fo_close    = psem_closefile,
	.fo_drain    = fo_no_drain,
	.fo_kqfilter = fo_no_kqfilter,
};

static lck_grp_t       *psx_sem_subsys_lck_grp;
static lck_grp_attr_t  *psx_sem_subsys_lck_grp_attr;
static lck_attr_t      *psx_sem_subsys_lck_attr;
static lck_mtx_t        psx_sem_subsys_mutex;

#define PSEM_SUBSYS_LOCK() lck_mtx_lock(& psx_sem_subsys_mutex)
#define PSEM_SUBSYS_UNLOCK() lck_mtx_unlock(& psx_sem_subsys_mutex)
#define PSEM_SUBSYS_ASSERT_HELD() LCK_MTX_ASSERT(&psx_sem_subsys_mutex, LCK_MTX_ASSERT_OWNED)


static int psem_cache_add(struct pseminfo *psemp, struct psemname *pnp, struct psemcache *pcp);
static void psem_cache_delete(struct psemcache *pcp);
int psem_cache_purge_all(proc_t);


/* Initialize the mutex governing access to the posix sem subsystem */
__private_extern__ void
psem_lock_init( void )
{
	psx_sem_subsys_lck_grp_attr = lck_grp_attr_alloc_init();

	psx_sem_subsys_lck_grp = lck_grp_alloc_init("posix shared memory", psx_sem_subsys_lck_grp_attr);

	psx_sem_subsys_lck_attr = lck_attr_alloc_init();
	lck_mtx_init(&psx_sem_subsys_mutex, psx_sem_subsys_lck_grp, psx_sem_subsys_lck_attr);
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
psem_cache_search(struct pseminfo **psemp, struct psemname *pnp,
    struct psemcache **pcache)
{
	struct psemcache *pcp, *nnp;
	struct psemhashhead *pcpp;

	if (pnp->psem_namelen > PSEMNAMLEN) {
		psemstats.longnames++;
		return PSEMCACHE_NOTFOUND;
	}

	pcpp = PSEMHASH(pnp);
	for (pcp = pcpp->lh_first; pcp != 0; pcp = nnp) {
		nnp = pcp->psem_hash.le_next;
		if (pcp->psem_nlen == pnp->psem_namelen &&
		    !bcmp(pcp->psem_name, pnp->psem_nameptr, (u_int)pcp->psem_nlen)) {
			break;
		}
	}

	if (pcp == 0) {
		psemstats.miss++;
		return PSEMCACHE_NOTFOUND;
	}

	/* We found a "positive" match, return the vnode */
	if (pcp->pseminfo) {
		psemstats.goodhits++;
		/* TOUCH(ncp); */
		*psemp = pcp->pseminfo;
		*pcache = pcp;
		return PSEMCACHE_FOUND;
	}

	/*
	 * We found a "negative" match, ENOENT notifies client of this match.
	 * The nc_vpid field records whether this is a whiteout.
	 */
	psemstats.neghits++;
	return PSEMCACHE_NEGATIVE;
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
	if (pnp->psem_namelen > PSEMNAMLEN) {
		panic("cache_enter: name too long");
	}
#endif


	/*  if the entry has already been added by some one else return */
	if (psem_cache_search(&dpinfo, pnp, &dpcp) == PSEMCACHE_FOUND) {
		return EEXIST;
	}
	if (psemnument >= posix_sem_max) {
		return ENOSPC;
	}
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

		for (p = pcpp->lh_first; p != 0; p = p->psem_hash.le_next) {
			if (p == pcp) {
				panic("psem:cache_enter duplicate");
			}
		}
	}
#endif
	LIST_INSERT_HEAD(pcpp, pcp, psem_hash);
	return 0;
}

/*
 * Name cache initialization, from vfs_init() when we are booting
 */
void
psem_cache_init(void)
{
	psemhashtbl = hashinit(posix_sem_max / 2, M_SHM, &psemhash);
}

static void
psem_cache_delete(struct psemcache *pcp)
{
#if DIAGNOSTIC
	if (pcp->psem_hash.le_prev == 0) {
		panic("psem namecache purge le_prev");
	}
	if (pcp->psem_hash.le_next == pcp) {
		panic("namecache purge le_next");
	}
#endif /* DIAGNOSTIC */
	LIST_REMOVE(pcp, psem_hash);
	pcp->psem_hash.le_prev = NULL;
	psemnument--;
}

/*
 * Remove all cached psem entries. Open semaphores (with a positive refcount)
 * will continue to exist, but their cache entries tying them to a particular
 * name/path will be removed making all future lookups on the name fail.
 */
int
psem_cache_purge_all(__unused proc_t p)
{
	struct psemcache *pcp, *tmppcp;
	struct psemhashhead *pcpp;
	int error = 0;

	if (kauth_cred_issuser(kauth_cred_get()) == 0) {
		return EPERM;
	}

	PSEM_SUBSYS_LOCK();
	for (pcpp = &psemhashtbl[psemhash]; pcpp >= psemhashtbl; pcpp--) {
		LIST_FOREACH_SAFE(pcp, pcpp, psem_hash, tmppcp) {
			assert(pcp->psem_nlen);
			/*
			 * unconditionally unlink the cache entry
			 */
			error = psem_unlink_internal(pcp->pseminfo, pcp);
			if (error) {
				goto out;
			}
		}
	}
	assert(psemnument == 0);

out:
	PSEM_SUBSYS_UNLOCK();

	if (error) {
		printf("%s: Error %d removing all semaphores: %ld remain!\n",
		    __func__, error, psemnument);
	}
	return error;
}

int
sem_open(proc_t p, struct sem_open_args *uap, user_addr_t *retval)
{
	size_t i;
	int indx, error;
	struct psemname nd;
	struct pseminfo *pinfo;
	struct fileproc *fp = NULL;
	char *pnbuf = NULL;
	struct pseminfo *new_pinfo = PSEMINFO_NULL;
	struct psemnode *new_pnode = PSEMNODE_NULL;
	struct psemcache *pcache = PSEMCACHE_NULL;
	char * nameptr;
	char * cp;
	size_t pathlen, plen;
	int fmode;
	int cmode = uap->mode;
	int value = uap->value;
	int incache = 0;
	struct psemcache *pcp = PSEMCACHE_NULL;
	kern_return_t kret = KERN_INVALID_ADDRESS;      /* default fail */

	AUDIT_ARG(fflags, uap->oflag);
	AUDIT_ARG(mode, uap->mode);
	AUDIT_ARG(value32, uap->value);

	pinfo = PSEMINFO_NULL;

	/*
	 * Preallocate everything we might need up front to avoid taking
	 * and dropping the lock, opening us up to race conditions.
	 */
	MALLOC_ZONE(pnbuf, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK | M_ZERO);
	if (pnbuf == NULL) {
		error = ENOSPC;
		goto bad;
	}

	pathlen = MAXPATHLEN;
	error = copyinstr(uap->name, pnbuf, MAXPATHLEN, &pathlen);
	if (error) {
		goto bad;
	}
	AUDIT_ARG(text, pnbuf);
	if ((pathlen > PSEMNAMLEN)) {
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
	nd.psem_hash = 0;

	for (cp = nameptr, i = 1; *cp != 0 && i <= plen; i++, cp++) {
		nd.psem_hash += (unsigned char)*cp * i;
	}

	/*
	 * attempt to allocate a new fp; if unsuccessful, the fp will be
	 * left unmodified (NULL).
	 */
	error = falloc(p, &fp, &indx, vfs_context_current());
	if (error) {
		goto bad;
	}

	/*
	 * We allocate a new entry if we are less than the maximum
	 * allowed and the one at the front of the LRU list is in use.
	 * Otherwise we use the one at the front of the LRU list.
	 */
	MALLOC(pcp, struct psemcache *, sizeof(struct psemcache), M_SHM, M_WAITOK | M_ZERO);
	if (pcp == PSEMCACHE_NULL) {
		error = ENOMEM;
		goto bad;
	}

	MALLOC(new_pinfo, struct pseminfo *, sizeof(struct pseminfo), M_SHM, M_WAITOK | M_ZERO);
	if (new_pinfo == NULL) {
		error = ENOSPC;
		goto bad;
	}
#if CONFIG_MACF
	mac_posixsem_label_init(new_pinfo);
#endif

	/*
	 * Provisionally create the semaphore in the new_pinfo; we have to do
	 * this here to prevent locking later.  We use the value of kret to
	 * signal success or failure, which is why we set its default value
	 * to KERN_INVALID_ADDRESS, above.
	 */

	fmode = FFLAGS(uap->oflag);

	if ((fmode & O_CREAT)) {
		if ((value < 0) || (value > SEM_VALUE_MAX)) {
			error = EINVAL;
			goto bad;
		}

		kret = semaphore_create(kernel_task, &new_pinfo->psem_semobject, SYNC_POLICY_FIFO, value);

		if (kret != KERN_SUCCESS) {
			switch (kret) {
			case KERN_RESOURCE_SHORTAGE:
				error = ENOMEM;
				break;
			case KERN_PROTECTION_FAILURE:
				error = EACCES;
				break;
			default:
				error = EINVAL;
			}
			goto bad;
		}
	}

	MALLOC(new_pnode, struct psemnode *, sizeof(struct psemnode), M_SHM, M_WAITOK | M_ZERO);
	if (new_pnode == NULL) {
		error = ENOSPC;
		goto bad;
	}

	PSEM_SUBSYS_LOCK();
	error = psem_cache_search(&pinfo, &nd, &pcache);

	if (error == PSEMCACHE_NEGATIVE) {
		error = EINVAL;
		goto bad_locked;
	}

	if (error == PSEMCACHE_FOUND) {
		incache = 1;
	} else {
		incache = 0;
	}

	cmode &=  ALLPERMS;

	if (((fmode & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) && incache) {
		/* sem exists and opened O_EXCL */
#if notyet
		if (pinfo->psem_flags & PSEM_INDELETE) {
		}
#endif
		AUDIT_ARG(posix_ipc_perm, pinfo->psem_uid,
		    pinfo->psem_gid, pinfo->psem_mode);
		error = EEXIST;
		goto bad_locked;
	}
	if (((fmode & (O_CREAT | O_EXCL)) == O_CREAT) && incache) {
		/* As per POSIX, O_CREAT has no effect */
		fmode &= ~O_CREAT;
	}

	if ((fmode & O_CREAT)) {
		/* create a new one (commit the allocation) */
		pinfo = new_pinfo;
		pinfo->psem_flags = PSEM_DEFINED | PSEM_INCREATE;
		pinfo->psem_usecount = 1;
		pinfo->psem_mode = cmode;
		pinfo->psem_uid = kauth_getuid();
		pinfo->psem_gid = kauth_getgid();
		bcopy(pnbuf, &pinfo->psem_name[0], PSEMNAMLEN);
		pinfo->psem_name[PSEMNAMLEN] = 0;
		pinfo->psem_flags &= ~PSEM_DEFINED;
		pinfo->psem_flags |= PSEM_ALLOCATED;
		pinfo->psem_creator_pid = p->p_pid;
		pinfo->psem_creator_uniqueid = p->p_uniqueid;

#if CONFIG_MACF
		error = mac_posixsem_check_create(kauth_cred_get(), nameptr);
		if (error) {
			goto bad_locked;
		}
		mac_posixsem_label_associate(kauth_cred_get(), pinfo, nameptr);
#endif
	} else {
		/* semaphore should exist as it is without  O_CREAT */
		if (!incache) {
			error = ENOENT;
			goto bad_locked;
		}
		if (pinfo->psem_flags & PSEM_INDELETE) {
			error = ENOENT;
			goto bad_locked;
		}
		AUDIT_ARG(posix_ipc_perm, pinfo->psem_uid,
		    pinfo->psem_gid, pinfo->psem_mode);
#if CONFIG_MACF
		error = mac_posixsem_check_open(kauth_cred_get(), pinfo);
		if (error) {
			goto bad_locked;
		}
#endif
		if ((error = psem_access(pinfo, fmode, kauth_cred_get()))) {
			goto bad_locked;
		}
	}

	if (!incache) {
		/* if successful, this will consume the pcp */
		if ((error = psem_cache_add(pinfo, &nd, pcp))) {
			goto bad_locked;
		}
	}
	pinfo->psem_flags &= ~PSEM_INCREATE;
	pinfo->psem_usecount++;
	new_pnode->pinfo = pinfo;
	PSEM_SUBSYS_UNLOCK();

	/*
	 * if incache, we did not use the new pcp or the new pcp or the
	 * new . and we must free them.
	 */
	if (incache) {
		FREE(pcp, M_SHM);
		pcp = PSEMCACHE_NULL;
		if (new_pinfo != PSEMINFO_NULL) {
			/* return value ignored - we can't _not_ do this */
			(void)semaphore_destroy(kernel_task, new_pinfo->psem_semobject);
#if CONFIG_MACF
			mac_posixsem_label_destroy(new_pinfo);
#endif
			FREE(new_pinfo, M_SHM);
			new_pinfo = PSEMINFO_NULL;
		}
	}

	proc_fdlock(p);
	fp->f_flag = fmode & FMASK;
	fp->f_ops = &psemops;
	fp->f_data = (caddr_t)new_pnode;
	procfdtbl_releasefd(p, indx, NULL);
	fp_drop(p, indx, fp, 1);
	proc_fdunlock(p);

	*retval = CAST_USER_ADDR_T(indx);
	FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	return 0;

bad_locked:
	PSEM_SUBSYS_UNLOCK();
bad:
	if (pcp != PSEMCACHE_NULL) {
		FREE(pcp, M_SHM);
	}

	if (new_pnode != PSEMNODE_NULL) {
		FREE(new_pnode, M_SHM);
	}

	if (fp != NULL) {
		fp_free(p, indx, fp);
	}

	if (new_pinfo != PSEMINFO_NULL) {
		/*
		 * kret signals whether or not we successfully created a
		 * Mach semaphore for this semaphore; if so, we need to
		 * destroy it here.
		 */
		if (kret == KERN_SUCCESS) {
			/* return value ignored - we can't _not_ do this */
			(void)semaphore_destroy(kernel_task, new_pinfo->psem_semobject);
		}
#if CONFIG_MACF
		mac_posixsem_label_destroy(new_pinfo);
#endif
		FREE(new_pinfo, M_SHM);
	}

	if (pnbuf != NULL) {
		FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	}
	return error;
}

/*
 * XXX This code is repeated in several places
 */
static int
psem_access(struct pseminfo *pinfo, int mode, kauth_cred_t cred)
{
	int mode_req = ((mode & FREAD) ? S_IRUSR : 0) |
	    ((mode & FWRITE) ? S_IWUSR : 0);

	/* Otherwise, user id 0 always gets access. */
	if (!suser(cred, NULL)) {
		return 0;
	}

	return posix_cred_access(cred, pinfo->psem_uid, pinfo->psem_gid, pinfo->psem_mode, mode_req);
}

static int
psem_unlink_internal(struct pseminfo *pinfo, struct psemcache *pcache)
{
	PSEM_SUBSYS_ASSERT_HELD();

	if (!pinfo || !pcache) {
		return EINVAL;
	}

	if ((pinfo->psem_flags & (PSEM_DEFINED | PSEM_ALLOCATED)) == 0) {
		return EINVAL;
	}

	if (pinfo->psem_flags & PSEM_INDELETE) {
		return 0;
	}

	AUDIT_ARG(posix_ipc_perm, pinfo->psem_uid, pinfo->psem_gid,
	    pinfo->psem_mode);

	pinfo->psem_flags |= PSEM_INDELETE;
	pinfo->psem_usecount--;

	if (!pinfo->psem_usecount) {
		psem_delete(pinfo);
		FREE(pinfo, M_SHM);
	} else {
		pinfo->psem_flags |= PSEM_REMOVED;
	}

	psem_cache_delete(pcache);
	FREE(pcache, M_SHM);
	return 0;
}


int
sem_unlink(__unused proc_t p, struct sem_unlink_args *uap, __unused int32_t *retval)
{
	size_t i;
	int error = 0;
	struct psemname nd;
	struct pseminfo *pinfo;
	char * nameptr;
	char * cp;
	char * pnbuf;
	size_t pathlen;
	struct psemcache *pcache = PSEMCACHE_NULL;

	pinfo = PSEMINFO_NULL;

	MALLOC_ZONE(pnbuf, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if (pnbuf == NULL) {
		return ENOSPC;         /* XXX non-standard */
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

	nameptr = pnbuf;

#ifdef PSXSEM_NAME_RESTRICT
	if (*nameptr == '/') {
		while (*(nameptr++) == '/') {
			pathlen--;
			error = EINVAL;
			goto bad;
		}
	} else {
		error = EINVAL;
		goto bad;
	}
#endif /* PSXSEM_NAME_RESTRICT */

	nd.psem_nameptr = nameptr;
	nd.psem_namelen = pathlen;
	nd.psem_hash = 0;

	for (cp = nameptr, i = 1; *cp != 0 && i <= pathlen; i++, cp++) {
		nd.psem_hash += (unsigned char)*cp * i;
	}

	PSEM_SUBSYS_LOCK();
	error = psem_cache_search(&pinfo, &nd, &pcache);

	if (error != PSEMCACHE_FOUND) {
		PSEM_SUBSYS_UNLOCK();
		error = ENOENT;
		goto bad;
	}

#if CONFIG_MACF
	error = mac_posixsem_check_unlink(kauth_cred_get(), pinfo, nameptr);
	if (error) {
		PSEM_SUBSYS_UNLOCK();
		goto bad;
	}
#endif
	if ((error = psem_access(pinfo, pinfo->psem_mode, kauth_cred_get()))) {
		PSEM_SUBSYS_UNLOCK();
		goto bad;
	}

	error = psem_unlink_internal(pinfo, pcache);
	PSEM_SUBSYS_UNLOCK();

bad:
	FREE_ZONE(pnbuf, MAXPATHLEN, M_NAMEI);
	return error;
}

int
sem_close(proc_t p, struct sem_close_args *uap, __unused int32_t *retval)
{
	int fd = CAST_DOWN_EXPLICIT(int, uap->sem);
	struct fileproc *fp;
	int error = 0;

	AUDIT_ARG(fd, fd); /* XXX This seems wrong; uap->sem is a pointer */

	proc_fdlock(p);
	error = fp_lookup(p, fd, &fp, 1);
	if (error) {
		proc_fdunlock(p);
		return error;
	}
	if (fp->f_type != DTYPE_PSXSEM) {
		fp_drop(p, fd, fp, 1);
		proc_fdunlock(p);
		return EBADF;
	}
	procfdtbl_markclosefd(p, fd);
	/* release the ref returned from fp_lookup before calling drain */
	(void) os_ref_release_locked(&fp->f_iocount);
	fileproc_drain(p, fp);
	fdrelse(p, fd);
	error = closef_locked(fp, fp->f_fglob, p);
	fileproc_free(fp);
	proc_fdunlock(p);
	return error;
}

int
sem_wait(proc_t p, struct sem_wait_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return sem_wait_nocancel(p, (struct sem_wait_nocancel_args *)uap, retval);
}

int
sem_wait_nocancel(proc_t p, struct sem_wait_nocancel_args *uap, __unused int32_t *retval)
{
	int fd = CAST_DOWN_EXPLICIT(int, uap->sem);
	struct fileproc *fp;
	struct pseminfo * pinfo;
	struct psemnode * pnode;
	kern_return_t kret;
	int error;

	error = fp_getfpsem(p, fd, &fp, &pnode);
	if (error) {
		return error;
	}
	if (((pnode = (struct psemnode *)fp->f_data)) == PSEMNODE_NULL) {
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
#if CONFIG_MACF
	error = mac_posixsem_check_wait(kauth_cred_get(), pinfo);
	if (error) {
		PSEM_SUBSYS_UNLOCK();
		goto out;
	}
#endif
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
	return error;
}

int
sem_trywait(proc_t p, struct sem_trywait_args *uap, __unused int32_t *retval)
{
	int fd = CAST_DOWN_EXPLICIT(int, uap->sem);
	struct fileproc *fp;
	struct pseminfo * pinfo;
	struct psemnode * pnode;
	kern_return_t kret;
	mach_timespec_t wait_time;
	int error;

	error = fp_getfpsem(p, fd, &fp, &pnode);
	if (error) {
		return error;
	}
	if (((pnode = (struct psemnode *)fp->f_data)) == PSEMNODE_NULL) {
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
#if CONFIG_MACF
	error = mac_posixsem_check_wait(kauth_cred_get(), pinfo);
	if (error) {
		PSEM_SUBSYS_UNLOCK();
		goto out;
	}
#endif
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
	return error;
}

int
sem_post(proc_t p, struct sem_post_args *uap, __unused int32_t *retval)
{
	int fd = CAST_DOWN_EXPLICIT(int, uap->sem);
	struct fileproc *fp;
	struct pseminfo * pinfo;
	struct psemnode * pnode;
	kern_return_t kret;
	int error;

	error = fp_getfpsem(p, fd, &fp, &pnode);
	if (error) {
		return error;
	}
	if (((pnode = (struct psemnode *)fp->f_data)) == PSEMNODE_NULL) {
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
#if CONFIG_MACF
	error = mac_posixsem_check_post(kauth_cred_get(), pinfo);
	if (error) {
		PSEM_SUBSYS_UNLOCK();
		goto out;
	}
#endif
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
	return error;
}

static int
psem_close(struct psemnode *pnode, __unused int flags)
{
	int error = 0;
	struct pseminfo *pinfo;

	PSEM_SUBSYS_LOCK();
	if ((pinfo = pnode->pinfo) == PSEMINFO_NULL) {
		PSEM_SUBSYS_UNLOCK();
		return EINVAL;
	}

	if ((pinfo->psem_flags & PSEM_ALLOCATED) != PSEM_ALLOCATED) {
		PSEM_SUBSYS_UNLOCK();
		return EINVAL;
	}
#if DIAGNOSTIC
	if (!pinfo->psem_usecount) {
		kprintf("negative usecount in psem_close\n");
	}
#endif /* DIAGNOSTIC */
	pinfo->psem_usecount--;

	if ((pinfo->psem_flags & PSEM_REMOVED) && !pinfo->psem_usecount) {
		PSEM_SUBSYS_UNLOCK();
		/* lock dropped as only semaphore is destroyed here */
		error = psem_delete(pinfo);
		FREE(pinfo, M_SHM);
	} else {
		PSEM_SUBSYS_UNLOCK();
	}
	/* subsystem lock is dropped when we get here */
	FREE(pnode, M_SHM);
	return error;
}

static int
psem_closefile(struct fileglob *fg, __unused vfs_context_t ctx)
{
	int error;

	/*
	 * Not locked as psem_close is called only from here and is locked
	 * properly
	 */
	error =  psem_close(((struct psemnode *)fg->fg_data), fg->fg_flag);

	return error;
}

static int
psem_delete(struct pseminfo * pinfo)
{
	kern_return_t kret;

	kret = semaphore_destroy(kernel_task, pinfo->psem_semobject);
#if CONFIG_MACF
	mac_posixsem_label_destroy(pinfo);
#endif

	switch (kret) {
	case KERN_INVALID_ADDRESS:
	case KERN_PROTECTION_FAILURE:
		return EINVAL;
	case KERN_ABORTED:
	case KERN_OPERATION_TIMED_OUT:
		return EINTR;
	case KERN_SUCCESS:
		return 0;
	default:
		return EINVAL;
	}
}

int
fill_pseminfo(struct psemnode *pnode, struct psem_info * info)
{
	struct pseminfo *pinfo;
	struct vinfo_stat  *sb;

	PSEM_SUBSYS_LOCK();
	if ((pinfo = pnode->pinfo) == PSEMINFO_NULL) {
		PSEM_SUBSYS_UNLOCK();
		return EINVAL;
	}

#if 0
	if ((pinfo->psem_flags & PSEM_ALLOCATED) != PSEM_ALLOCATED) {
		PSEM_SUBSYS_UNLOCK();
		return EINVAL;
	}
#endif

	sb = &info->psem_stat;
	bzero(sb, sizeof(struct vinfo_stat));

	sb->vst_mode = pinfo->psem_mode;
	sb->vst_uid = pinfo->psem_uid;
	sb->vst_gid = pinfo->psem_gid;
	sb->vst_size = pinfo->psem_usecount;
	bcopy(&pinfo->psem_name[0], &info->psem_name[0], PSEMNAMLEN + 1);

	PSEM_SUBSYS_UNLOCK();
	return 0;
}

#if CONFIG_MACF
void
psem_label_associate(struct fileproc *fp, struct vnode *vp, vfs_context_t ctx)
{
	struct psemnode *pnode;
	struct pseminfo *psem;

	PSEM_SUBSYS_LOCK();
	pnode = (struct psemnode *)fp->f_fglob->fg_data;
	if (pnode != NULL) {
		psem = pnode->pinfo;
		if (psem != NULL) {
			mac_posixsem_vnode_label_associate(
				vfs_context_ucred(ctx), psem, psem->psem_label,
				vp, vp->v_label);
		}
	}
	PSEM_SUBSYS_UNLOCK();
}
#endif
