/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1989, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Poul-Henning Kamp of the FreeBSD Project.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *
 *	@(#)vfs_cache.c	8.5 (Berkeley) 3/22/95
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>
#include <miscfs/specfs/specdev.h>
#include <sys/namei.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/kauth.h>
#include <sys/user.h>
#include <sys/paths.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

/*
 * Name caching works as follows:
 *
 * Names found by directory scans are retained in a cache
 * for future reference.  It is managed LRU, so frequently
 * used names will hang around.  Cache is indexed by hash value
 * obtained from (vp, name) where vp refers to the directory
 * containing name.
 *
 * If it is a "negative" entry, (i.e. for a name that is known NOT to
 * exist) the vnode pointer will be NULL.
 *
 * Upon reaching the last segment of a path, if the reference
 * is for DELETE, or NOCACHE is set (rewrite), and the
 * name is located in the cache, it will be dropped.
 */

/*
 * Structures associated with name cacheing.
 */

LIST_HEAD(nchashhead, namecache) *nchashtbl;	/* Hash Table */
u_long	nchashmask;
u_long	nchash;				/* size of hash table - 1 */
long	numcache;			/* number of cache entries allocated */
int 	desiredNodes;
int 	desiredNegNodes;
int	ncs_negtotal;
int	nc_disabled = 0;
TAILQ_HEAD(, namecache) nchead;		/* chain of all name cache entries */
TAILQ_HEAD(, namecache) neghead;	/* chain of only negative cache entries */


#if COLLECT_STATS

struct	nchstats nchstats;		/* cache effectiveness statistics */

#define	NCHSTAT(v) {		\
        nchstats.v++;		\
}
#define NAME_CACHE_LOCK()		name_cache_lock()
#define NAME_CACHE_UNLOCK()		name_cache_unlock()
#define	NAME_CACHE_LOCK_SHARED()	name_cache_lock()

#else

#define NCHSTAT(v)
#define NAME_CACHE_LOCK()		name_cache_lock()
#define NAME_CACHE_UNLOCK()		name_cache_unlock()
#define	NAME_CACHE_LOCK_SHARED()	name_cache_lock_shared()

#endif


/* vars for name cache list lock */
lck_grp_t * namecache_lck_grp;
lck_grp_attr_t * namecache_lck_grp_attr;
lck_attr_t * namecache_lck_attr;

lck_grp_t * strcache_lck_grp;
lck_grp_attr_t * strcache_lck_grp_attr;
lck_attr_t * strcache_lck_attr;

lck_rw_t  * namecache_rw_lock;
lck_rw_t  * strtable_rw_lock;

#define NUM_STRCACHE_LOCKS 1024

lck_mtx_t strcache_mtx_locks[NUM_STRCACHE_LOCKS];


static vnode_t cache_lookup_locked(vnode_t dvp, struct componentname *cnp);
static const char *add_name_internal(const char *, uint32_t, u_int, boolean_t, u_int);
static void init_string_table(void);
static void cache_delete(struct namecache *, int);
static void cache_enter_locked(vnode_t dvp, vnode_t vp, struct componentname *cnp, const char *strname);

#ifdef DUMP_STRING_TABLE
/*
 * Internal dump function used for debugging
 */
void dump_string_table(void);
#endif	/* DUMP_STRING_TABLE */

static void init_crc32(void);
static unsigned int crc32tab[256];


#define NCHHASH(dvp, hash_val) \
	(&nchashtbl[(dvp->v_id ^ (hash_val)) & nchashmask])



/*
 * This function builds the path to a filename in "buff".  The
 * length of the buffer *INCLUDING* the trailing zero byte is
 * returned in outlen.  NOTE: the length includes the trailing
 * zero byte and thus the length is one greater than what strlen
 * would return.  This is important and lots of code elsewhere
 * in the kernel assumes this behavior.
 * 
 * This function can call vnop in file system if the parent vnode 
 * does not exist or when called for hardlinks via volfs path.  
 * If BUILDPATH_NO_FS_ENTER is set in flags, it only uses values present
 * in the name cache and does not enter the file system.
 *
 * If BUILDPATH_CHECK_MOVED is set in flags, we return EAGAIN when 
 * we encounter ENOENT during path reconstruction.  ENOENT means that 
 * one of the parents moved while we were building the path.  The 
 * caller can special handle this case by calling build_path again.
 *
 * If BUILDPATH_VOLUME_RELATIVE is set in flags, we return path 
 * that is relative to the nearest mount point, i.e. do not 
 * cross over mount points during building the path. 
 *
 * passed in vp must have a valid io_count reference
 */
int
build_path(vnode_t first_vp, char *buff, int buflen, int *outlen, int flags, vfs_context_t ctx)
{
        vnode_t vp, tvp;
	vnode_t vp_with_iocount;
        vnode_t proc_root_dir_vp;
	char *end;
	const char *str;
	int  len;
	int  ret = 0;
	int  fixhardlink;

	if (first_vp == NULLVP)
		return (EINVAL);
		
	if (buflen <= 1)
		return (ENOSPC);

	/*
	 * Grab the process fd so we can evaluate fd_rdir.
	 */
	if (vfs_context_proc(ctx)->p_fd)
		proc_root_dir_vp = vfs_context_proc(ctx)->p_fd->fd_rdir;
	else
		proc_root_dir_vp = NULL;

	vp_with_iocount = NULLVP;
again:
	vp = first_vp;

	end = &buff[buflen-1];
	*end = '\0';

	/*
	 * holding the NAME_CACHE_LOCK in shared mode is
	 * sufficient to stabilize both the vp->v_parent chain
	 * and the 'vp->v_mount->mnt_vnodecovered' chain
	 *
	 * if we need to drop this lock, we must first grab the v_id
	 * from the vnode we're currently working with... if that
	 * vnode doesn't already have an io_count reference (the vp
	 * passed in comes with one), we must grab a reference
	 * after we drop the NAME_CACHE_LOCK via vnode_getwithvid...
	 * deadlocks may result if you call vnode_get while holding
	 * the NAME_CACHE_LOCK... we lazily release the reference
	 * we pick up the next time we encounter a need to drop 
	 * the NAME_CACHE_LOCK or before we return from this routine
	 */
	NAME_CACHE_LOCK_SHARED();

	/*
	 * Check if this is the root of a file system.
	 */
	while (vp && vp->v_flag & VROOT) {
		if (vp->v_mount == NULL) {
			ret = EINVAL;
			goto out_unlock;
		}
	        if ((vp->v_mount->mnt_flag & MNT_ROOTFS) || (vp == proc_root_dir_vp)) {
			/*
			 * It's the root of the root file system, so it's
			 * just "/".
			 */
		        *--end = '/';

			goto out_unlock;
		} else {
			/* 
			 * This the root of the volume and the caller does not 
			 * want to cross mount points.  Therefore just return 
			 * '/' as the relative path. 
			 */
			if (flags & BUILDPATH_VOLUME_RELATIVE) {
				*--end = '/';
				goto out_unlock;
			} else {
				vp = vp->v_mount->mnt_vnodecovered;
			}
		}
	}

	while ((vp != NULLVP) && (vp->v_parent != vp)) {
		int  vid;

		/*
		 * For hardlinks the v_name may be stale, so if its OK
		 * to enter a file system, ask the file system for the
		 * name and parent (below).
		 */
		fixhardlink = (vp->v_flag & VISHARDLINK) &&
		              (vp->v_mount->mnt_kern_flag & MNTK_PATH_FROM_ID) &&
		              !(flags & BUILDPATH_NO_FS_ENTER);

		if (!fixhardlink) {
			str = vp->v_name;

			if (str == NULL || *str == '\0') {
				if (vp->v_parent != NULL)
					ret = EINVAL;
				else
					ret = ENOENT;
				goto out_unlock;
			}
			len = strlen(str);
			/*
			 * Check that there's enough space (including space for the '/')
			 */
			if ((end - buff) < (len + 1)) {
				ret = ENOSPC;
				goto out_unlock;
			}
			/*
			 * Copy the name backwards.
			 */
			str += len;
	
			for (; len > 0; len--)
			       *--end = *--str;
			/*
			 * Add a path separator.
			 */
			*--end = '/';
		}

		/*
		 * Walk up the parent chain.
		 */
		if (((vp->v_parent != NULLVP) && !fixhardlink) ||
				(flags & BUILDPATH_NO_FS_ENTER)) {

			/*
			 * In this if () block we are not allowed to enter the filesystem
			 * to conclusively get the most accurate parent identifier.
			 * As a result, if 'vp' does not identify '/' and it
			 * does not have a valid v_parent, then error out
			 * and disallow further path construction
			 */
			if ((vp->v_parent == NULLVP) && (rootvnode != vp)) {
				/* Only '/' is allowed to have a NULL parent pointer */
				ret = EINVAL;

				/* The code below will exit early if 'tvp = vp' == NULL */
			}
			vp = vp->v_parent;

			/*
			 * if the vnode we have in hand isn't a directory and it
			 * has a v_parent, then we started with the resource fork
			 * so skip up to avoid getting a duplicate copy of the
			 * file name in the path.
			 */
			if (vp && !vnode_isdir(vp) && vp->v_parent) {
				vp = vp->v_parent;
			}
		} else {
			/*
			 * No parent, go get it if supported.
			 */
			struct vnode_attr  va;
			vnode_t  dvp;

			/*
			 * Make sure file system supports obtaining a path from id.
			 */
			if (!(vp->v_mount->mnt_kern_flag & MNTK_PATH_FROM_ID)) {
				ret = ENOENT;
				goto out_unlock;
			}
			vid = vp->v_id;

			NAME_CACHE_UNLOCK();

			if (vp != first_vp && vp != vp_with_iocount) {
				if (vp_with_iocount) {
					vnode_put(vp_with_iocount);
					vp_with_iocount = NULLVP;
				}
				if (vnode_getwithvid(vp, vid))
					goto again;
				vp_with_iocount = vp;
			}
			VATTR_INIT(&va);
			VATTR_WANTED(&va, va_parentid);

			if (fixhardlink) {
				VATTR_WANTED(&va, va_name);
				MALLOC_ZONE(va.va_name, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
			} else {
				va.va_name = NULL;
			}
			/*
			 * Ask the file system for its parent id and for its name (optional).
			 */
			ret = vnode_getattr(vp, &va, ctx);

			if (fixhardlink) {
				if ((ret == 0) && (VATTR_IS_SUPPORTED(&va, va_name))) {
					str = va.va_name;
					vnode_update_identity(vp, NULL, str, strlen(str), 0, VNODE_UPDATE_NAME);
				} else if (vp->v_name) {
					str = vp->v_name;
					ret = 0;
				} else {
					ret = ENOENT;
					goto bad_news;
				}
				len = strlen(str);

				/*
				 * Check that there's enough space.
				 */
				if ((end - buff) < (len + 1)) {
					ret = ENOSPC;
				} else {
					/* Copy the name backwards. */
					str += len;

					for (; len > 0; len--) {
						*--end = *--str;
					}
					/*
					 * Add a path separator.
					 */
					*--end = '/';
				}
bad_news:
				FREE_ZONE(va.va_name, MAXPATHLEN, M_NAMEI);
			}
			if (ret || !VATTR_IS_SUPPORTED(&va, va_parentid)) {
				ret = ENOENT;
				goto out;
			}
			/*
			 * Ask the file system for the parent vnode.
			 */
			if ((ret = VFS_VGET(vp->v_mount, (ino64_t)va.va_parentid, &dvp, ctx)))
				goto out;

			if (!fixhardlink && (vp->v_parent != dvp))
				vnode_update_identity(vp, dvp, NULL, 0, 0, VNODE_UPDATE_PARENT);

			if (vp_with_iocount)
				vnode_put(vp_with_iocount);
			vp = dvp;
			vp_with_iocount = vp;

			NAME_CACHE_LOCK_SHARED();

			/*
			 * if the vnode we have in hand isn't a directory and it
			 * has a v_parent, then we started with the resource fork
			 * so skip up to avoid getting a duplicate copy of the
			 * file name in the path.
			 */
			if (vp && !vnode_isdir(vp) && vp->v_parent)
				vp = vp->v_parent;
		}

		/*
		 * When a mount point is crossed switch the vp.
		 * Continue until we find the root or we find
		 * a vnode that's not the root of a mounted
		 * file system.
		 */
		tvp = vp;

		while (tvp) {
			if (tvp == proc_root_dir_vp)
				goto out_unlock;	/* encountered the root */

			if (!(tvp->v_flag & VROOT) || !tvp->v_mount)
				break;			/* not the root of a mounted FS */

			if (flags & BUILDPATH_VOLUME_RELATIVE) {
				/* Do not cross over mount points */
				tvp = NULL;
			} else {
				tvp = tvp->v_mount->mnt_vnodecovered;
			}
		}
		if (tvp == NULLVP)
			goto out_unlock;
		vp = tvp;

		if (vp && (flags & BUILDPATH_CHECKACCESS)) {
			vid = vp->v_id;

			NAME_CACHE_UNLOCK();

			if (vp != first_vp && vp != vp_with_iocount) {
				if (vp_with_iocount) {
					vnode_put(vp_with_iocount);
					vp_with_iocount = NULLVP;
				}
				if (vnode_getwithvid(vp, vid))
					goto again;
				vp_with_iocount = vp;
			}
			if ((ret = vnode_authorize(vp, NULL, KAUTH_VNODE_SEARCH, ctx)))
				goto out;  	/* no peeking */

			NAME_CACHE_LOCK_SHARED();
		}
	}
out_unlock:
	NAME_CACHE_UNLOCK();
out:
	if (vp_with_iocount)
		vnode_put(vp_with_iocount);
	/*
	 * Slide the name down to the beginning of the buffer.
	 */
	memmove(buff, end, &buff[buflen] - end);

	/*
	 * length includes the trailing zero byte
	 */
	*outlen = &buff[buflen] - end;
 
	/* One of the parents was moved during path reconstruction. 
	 * The caller is interested in knowing whether any of the 
	 * parents moved via BUILDPATH_CHECK_MOVED, so return EAGAIN.
	 */
	if ((ret == ENOENT) && (flags & BUILDPATH_CHECK_MOVED)) {
		ret = EAGAIN;
	}

	return (ret);
}


/*
 * return NULLVP if vp's parent doesn't
 * exist, or we can't get a valid iocount
 * else return the parent of vp
 */
vnode_t
vnode_getparent(vnode_t vp)
{
        vnode_t pvp = NULLVP;
	int	pvid;

	NAME_CACHE_LOCK_SHARED();
	/*
	 * v_parent is stable behind the name_cache lock
	 * however, the only thing we can really guarantee
	 * is that we've grabbed a valid iocount on the
	 * parent of 'vp' at the time we took the name_cache lock...
	 * once we drop the lock, vp could get re-parented
	 */
	if ( (pvp = vp->v_parent) != NULLVP ) {
	        pvid = pvp->v_id;

		NAME_CACHE_UNLOCK();

		if (vnode_getwithvid(pvp, pvid) != 0)
		        pvp = NULL;
	} else
	        NAME_CACHE_UNLOCK();
	return (pvp);
}

const char *
vnode_getname(vnode_t vp)
{
        const char *name = NULL;
	
	NAME_CACHE_LOCK_SHARED();
	
	if (vp->v_name)
	        name = vfs_addname(vp->v_name, strlen(vp->v_name), 0, 0);
	NAME_CACHE_UNLOCK();

	return (name);
}

void
vnode_putname(const char *name)
{
	vfs_removename(name);
}

static const char unknown_vnodename[] = "(unknown vnode name)";

const char *
vnode_getname_printable(vnode_t vp)
{
	const char *name = vnode_getname(vp);
	if (name != NULL)
		return name;
	
	switch (vp->v_type) {
		case VCHR:
		case VBLK:
			{
			/*
			 * Create an artificial dev name from
			 * major and minor device number
			 */
			char dev_name[64];
			(void) snprintf(dev_name, sizeof(dev_name),
					"%c(%u, %u)", VCHR == vp->v_type ? 'c':'b',
					major(vp->v_rdev), minor(vp->v_rdev));
			/*
			 * Add the newly created dev name to the name
			 * cache to allow easier cleanup. Also,
			 * vfs_addname allocates memory for the new name
			 * and returns it.
			 */
			NAME_CACHE_LOCK_SHARED();
			name = vfs_addname(dev_name, strlen(dev_name), 0, 0);
			NAME_CACHE_UNLOCK();
			return name;
			}
		default:
			return unknown_vnodename;
	}
}

void 
vnode_putname_printable(const char *name)
{
	if (name == unknown_vnodename)
		return;
	vnode_putname(name);
}
		

/*
 * if VNODE_UPDATE_PARENT, and we can take
 * a reference on dvp, then update vp with
 * it's new parent... if vp already has a parent,
 * then drop the reference vp held on it
 *
 * if VNODE_UPDATE_NAME,
 * then drop string ref on v_name if it exists, and if name is non-NULL
 * then pick up a string reference on name and record it in v_name...
 * optionally pass in the length and hashval of name if known
 *
 * if VNODE_UPDATE_CACHE, flush the name cache entries associated with vp
 */
void
vnode_update_identity(vnode_t vp, vnode_t dvp, const char *name, int name_len, uint32_t name_hashval, int flags)
{
	struct	namecache *ncp;
        vnode_t	old_parentvp = NULLVP;
#if NAMEDSTREAMS
	int isstream = (vp->v_flag & VISNAMEDSTREAM);
	int kusecountbumped = 0;
#endif
	kauth_cred_t tcred = NULL;
	const char *vname = NULL;
	const char *tname = NULL;

	if (flags & VNODE_UPDATE_PARENT) {
	        if (dvp && vnode_ref(dvp) != 0) {
			dvp = NULLVP;
		}
#if NAMEDSTREAMS
		/* Don't count a stream's parent ref during unmounts */
		if (isstream && dvp && (dvp != vp) && (dvp != vp->v_parent) && (dvp->v_type == VREG)) {
			vnode_lock_spin(dvp);
			++dvp->v_kusecount;
			kusecountbumped = 1;
			vnode_unlock(dvp);
		}
#endif
	} else {
	        dvp = NULLVP;
	}
	if ( (flags & VNODE_UPDATE_NAME) ) {
		if (name != vp->v_name) {
			if (name && *name) {
				if (name_len == 0)
					name_len = strlen(name);
			        tname = vfs_addname(name, name_len, name_hashval, 0);
			}
		} else
			flags &= ~VNODE_UPDATE_NAME;
	}
	if ( (flags & (VNODE_UPDATE_PURGE | VNODE_UPDATE_PARENT | VNODE_UPDATE_CACHE | VNODE_UPDATE_NAME)) ) {

		NAME_CACHE_LOCK();

		if ( (flags & VNODE_UPDATE_PURGE) ) {

			if (vp->v_parent)
				vp->v_parent->v_nc_generation++;

			while ( (ncp = LIST_FIRST(&vp->v_nclinks)) )
				cache_delete(ncp, 1);

			while ( (ncp = LIST_FIRST(&vp->v_ncchildren)) )
				cache_delete(ncp, 1);

			/*
			 * Use a temp variable to avoid kauth_cred_unref() while NAME_CACHE_LOCK is held
			 */
			tcred = vp->v_cred;
			vp->v_cred = NOCRED;
			vp->v_authorized_actions = 0;
		}
		if ( (flags & VNODE_UPDATE_NAME) ) {
			vname = vp->v_name;
			vp->v_name = tname;
		}
		if (flags & VNODE_UPDATE_PARENT) {
			if (dvp != vp && dvp != vp->v_parent) {
				old_parentvp = vp->v_parent;
				vp->v_parent = dvp;
				dvp = NULLVP;

				if (old_parentvp)
					flags |= VNODE_UPDATE_CACHE;
			}
		}
		if (flags & VNODE_UPDATE_CACHE) {
			while ( (ncp = LIST_FIRST(&vp->v_nclinks)) )
				cache_delete(ncp, 1);
		}
		NAME_CACHE_UNLOCK();
	
		if (vname != NULL)
			vfs_removename(vname);

		if (IS_VALID_CRED(tcred))
			kauth_cred_unref(&tcred);
	}
	if (dvp != NULLVP) {
#if NAMEDSTREAMS
		/* Back-out the ref we took if we lost a race for vp->v_parent. */
		if (kusecountbumped) {
			vnode_lock_spin(dvp);
			if (dvp->v_kusecount > 0)
				--dvp->v_kusecount;  
			vnode_unlock(dvp);
		}
#endif
	        vnode_rele(dvp);
	}
	if (old_parentvp) {
	        struct  uthread *ut;

#if NAMEDSTREAMS
		if (isstream) {
		        vnode_lock_spin(old_parentvp);
			if ((old_parentvp->v_type != VDIR) && (old_parentvp->v_kusecount > 0))
				--old_parentvp->v_kusecount;
			vnode_unlock(old_parentvp);
		}
#endif
	        ut = get_bsdthread_info(current_thread());

		/*
		 * indicated to vnode_rele that it shouldn't do a
		 * vnode_reclaim at this time... instead it will
		 * chain the vnode to the uu_vreclaims list...
		 * we'll be responsible for calling vnode_reclaim
		 * on each of the vnodes in this list...
		 */
		ut->uu_defer_reclaims = 1;
		ut->uu_vreclaims = NULLVP;

	        while ( (vp = old_parentvp) != NULLVP ) {
	  
		        vnode_lock_spin(vp);
			vnode_rele_internal(vp, 0, 0, 1);

			/*
			 * check to see if the vnode is now in the state
			 * that would have triggered a vnode_reclaim in vnode_rele
			 * if it is, we save it's parent pointer and then NULL
			 * out the v_parent field... we'll drop the reference
			 * that was held on the next iteration of this loop...
			 * this short circuits a potential deep recursion if we
			 * have a long chain of parents in this state... 
			 * we'll sit in this loop until we run into
			 * a parent in this chain that is not in this state
			 *
			 * make our check and the vnode_rele atomic
			 * with respect to the current vnode we're working on
			 * by holding the vnode lock
			 * if vnode_rele deferred the vnode_reclaim and has put
			 * this vnode on the list to be reaped by us, than
			 * it has left this vnode with an iocount == 1
			 */
			if ( (vp->v_iocount == 1) && (vp->v_usecount == 0) &&
			     ((vp->v_lflag & (VL_MARKTERM | VL_TERMINATE | VL_DEAD)) == VL_MARKTERM)) {
			        /*
				 * vnode_rele wanted to do a vnode_reclaim on this vnode
				 * it should be sitting on the head of the uu_vreclaims chain
				 * pull the parent pointer now so that when we do the
				 * vnode_reclaim for each of the vnodes in the uu_vreclaims
				 * list, we won't recurse back through here
				 *
				 * need to do a convert here in case vnode_rele_internal
				 * returns with the lock held in the spin mode... it 
				 * can drop and retake the lock under certain circumstances
				 */
			        vnode_lock_convert(vp);

			        NAME_CACHE_LOCK();
				old_parentvp = vp->v_parent;
				vp->v_parent = NULLVP;
				NAME_CACHE_UNLOCK();
			} else {
			        /*
				 * we're done... we ran into a vnode that isn't
				 * being terminated
				 */
			        old_parentvp = NULLVP;
			}
			vnode_unlock(vp);
		}
		ut->uu_defer_reclaims = 0;

		while ( (vp = ut->uu_vreclaims) != NULLVP) {
		        ut->uu_vreclaims = vp->v_defer_reclaimlist;
			
			/*
			 * vnode_put will drive the vnode_reclaim if
			 * we are still the only reference on this vnode
			 */
			vnode_put(vp);
		}
	}
}


/*
 * Mark a vnode as having multiple hard links.  HFS makes use of this
 * because it keeps track of each link separately, and wants to know
 * which link was actually used.
 *
 * This will cause the name cache to force a VNOP_LOOKUP on the vnode
 * so that HFS can post-process the lookup.  Also, volfs will call
 * VNOP_GETATTR2 to determine the parent, instead of using v_parent.
 */
void vnode_setmultipath(vnode_t vp)
{
	vnode_lock_spin(vp);

	/*
	 * In theory, we're changing the vnode's identity as far as the
	 * name cache is concerned, so we ought to grab the name cache lock
	 * here.  However, there is already a race, and grabbing the name
	 * cache lock only makes the race window slightly smaller.
	 *
	 * The race happens because the vnode already exists in the name
	 * cache, and could be found by one thread before another thread
	 * can set the hard link flag.
	 */

	vp->v_flag |= VISHARDLINK;

	vnode_unlock(vp);
}



/*
 * backwards compatibility
 */
void vnode_uncache_credentials(vnode_t vp)
{
        vnode_uncache_authorized_action(vp, KAUTH_INVALIDATE_CACHED_RIGHTS);
}


/*
 * use the exclusive form of NAME_CACHE_LOCK to protect the update of the
 * following fields in the vnode: v_cred_timestamp, v_cred, v_authorized_actions
 * we use this lock so that we can look at the v_cred and v_authorized_actions
 * atomically while behind the NAME_CACHE_LOCK in shared mode in 'cache_lookup_path',
 * which is the super-hot path... if we are updating the authorized actions for this
 * vnode, we are already in the super-slow and far less frequented path so its not
 * that bad that we take the lock exclusive for this case... of course we strive
 * to hold it for the minimum amount of time possible
 */

void vnode_uncache_authorized_action(vnode_t vp, kauth_action_t action)
{
        kauth_cred_t tcred = NOCRED;

	NAME_CACHE_LOCK();

	vp->v_authorized_actions &= ~action;

	if (action == KAUTH_INVALIDATE_CACHED_RIGHTS &&
	    IS_VALID_CRED(vp->v_cred)) {
	        /*
		 * Use a temp variable to avoid kauth_cred_unref() while NAME_CACHE_LOCK is held
		 */
	        tcred = vp->v_cred;
		vp->v_cred = NOCRED;
	}
	NAME_CACHE_UNLOCK();

	if (tcred != NOCRED)
		kauth_cred_unref(&tcred);
}


extern int bootarg_vnode_cache_defeat;	/* default = 0, from bsd_init.c */

boolean_t
vnode_cache_is_authorized(vnode_t vp, vfs_context_t ctx, kauth_action_t action)
{
	kauth_cred_t	ucred;
	boolean_t	retval = FALSE;

	/* Boot argument to defeat rights caching */
	if (bootarg_vnode_cache_defeat)
		return FALSE;

	if ( (vp->v_mount->mnt_kern_flag & (MNTK_AUTH_OPAQUE | MNTK_AUTH_CACHE_TTL)) ) {
	        /*
		 * a TTL is enabled on the rights cache... handle it here
		 * a TTL of 0 indicates that no rights should be cached
		 */
	        if (vp->v_mount->mnt_authcache_ttl) {
		        if ( !(vp->v_mount->mnt_kern_flag & MNTK_AUTH_CACHE_TTL) ) {
			        /*
				 * For filesystems marked only MNTK_AUTH_OPAQUE (generally network ones),
				 * we will only allow a SEARCH right on a directory to be cached...
				 * that cached right always has a default TTL associated with it
				 */
			        if (action != KAUTH_VNODE_SEARCH || vp->v_type != VDIR)
				        vp = NULLVP;
			}
			if (vp != NULLVP && vnode_cache_is_stale(vp) == TRUE) {
			        vnode_uncache_authorized_action(vp, vp->v_authorized_actions);
				vp = NULLVP;
			}
		} else
		        vp = NULLVP;
	}
	if (vp != NULLVP) {
	        ucred = vfs_context_ucred(ctx);

		NAME_CACHE_LOCK_SHARED();

		if (vp->v_cred == ucred && (vp->v_authorized_actions & action) == action)
		        retval = TRUE;
		
		NAME_CACHE_UNLOCK();
	}
	return retval;
}


void vnode_cache_authorized_action(vnode_t vp, vfs_context_t ctx, kauth_action_t action)
{
	kauth_cred_t tcred = NOCRED;
	kauth_cred_t ucred;
	struct timeval tv;
	boolean_t ttl_active = FALSE;

	ucred = vfs_context_ucred(ctx);

	if (!IS_VALID_CRED(ucred) || action == 0)
	        return;

	if ( (vp->v_mount->mnt_kern_flag & (MNTK_AUTH_OPAQUE | MNTK_AUTH_CACHE_TTL)) ) {
	        /*
		 * a TTL is enabled on the rights cache... handle it here
		 * a TTL of 0 indicates that no rights should be cached
		 */
	        if (vp->v_mount->mnt_authcache_ttl == 0) 
		        return;

		if ( !(vp->v_mount->mnt_kern_flag & MNTK_AUTH_CACHE_TTL) ) {
		        /*
			 * only cache SEARCH action for filesystems marked
			 * MNTK_AUTH_OPAQUE on VDIRs...
			 * the lookup_path code will time these out
			 */
		        if ( (action & ~KAUTH_VNODE_SEARCH) || vp->v_type != VDIR )
			        return;
		}
		ttl_active = TRUE;

		microuptime(&tv);
	}
	NAME_CACHE_LOCK();

	if (vp->v_cred != ucred) {
	        kauth_cred_ref(ucred);
	        /*
		 * Use a temp variable to avoid kauth_cred_unref() while NAME_CACHE_LOCK is held
		 */
		tcred = vp->v_cred;
		vp->v_cred = ucred;
		vp->v_authorized_actions = 0;
	}
	if (ttl_active == TRUE && vp->v_authorized_actions == 0) {
	        /*
		 * only reset the timestamnp on the
		 * first authorization cached after the previous
		 * timer has expired or we're switching creds...
		 * 'vnode_cache_is_authorized' will clear the 
		 * authorized actions if the TTL is active and
		 * it has expired
		 */
	        vp->v_cred_timestamp = tv.tv_sec;
	}
	vp->v_authorized_actions |= action;

	NAME_CACHE_UNLOCK();

	if (IS_VALID_CRED(tcred))
		kauth_cred_unref(&tcred);
}


boolean_t vnode_cache_is_stale(vnode_t vp)
{
	struct timeval	tv;
	boolean_t	retval;

	microuptime(&tv);

	if ((tv.tv_sec - vp->v_cred_timestamp) > vp->v_mount->mnt_authcache_ttl)
	        retval = TRUE;
	else
	        retval = FALSE;

	return retval;
}



/*
 * Returns:	0			Success
 *		ERECYCLE		vnode was recycled from underneath us.  Force lookup to be re-driven from namei.
 * 						This errno value should not be seen by anyone outside of the kernel.
 */
int 
cache_lookup_path(struct nameidata *ndp, struct componentname *cnp, vnode_t dp, 
		vfs_context_t ctx, int *dp_authorized, vnode_t last_dp)
{
	char		*cp;		/* pointer into pathname argument */
	int		vid;
	int		vvid = 0;	/* protected by vp != NULLVP */
	vnode_t		vp = NULLVP;
	vnode_t		tdp = NULLVP;
	kauth_cred_t	ucred;
	boolean_t	ttl_enabled = FALSE;
	struct timeval	tv;
        mount_t		mp;
	unsigned int	hash;
	int		error = 0;

#if CONFIG_TRIGGERS
	vnode_t 	trigger_vp;
#endif /* CONFIG_TRIGGERS */

	ucred = vfs_context_ucred(ctx);
	ndp->ni_flag &= ~(NAMEI_TRAILINGSLASH);

	NAME_CACHE_LOCK_SHARED();

	if ( dp->v_mount && (dp->v_mount->mnt_kern_flag & (MNTK_AUTH_OPAQUE | MNTK_AUTH_CACHE_TTL)) ) {
		ttl_enabled = TRUE;
		microuptime(&tv);
	}
	for (;;) {
		/*
		 * Search a directory.
		 *
		 * The cn_hash value is for use by cache_lookup
		 * The last component of the filename is left accessible via
		 * cnp->cn_nameptr for callers that need the name.
		 */
	        hash = 0;
		cp = cnp->cn_nameptr;

		while (*cp && (*cp != '/')) {
			hash = crc32tab[((hash >> 24) ^ (unsigned char)*cp++)] ^ hash << 8;
		}
		/*
		 * the crc generator can legitimately generate
		 * a 0... however, 0 for us means that we
		 * haven't computed a hash, so use 1 instead
		 */
		if (hash == 0)
		        hash = 1;
		cnp->cn_hash = hash;
		cnp->cn_namelen = cp - cnp->cn_nameptr;

		ndp->ni_pathlen -= cnp->cn_namelen;
		ndp->ni_next = cp;

		/*
		 * Replace multiple slashes by a single slash and trailing slashes
		 * by a null.  This must be done before VNOP_LOOKUP() because some
		 * fs's don't know about trailing slashes.  Remember if there were
		 * trailing slashes to handle symlinks, existing non-directories
		 * and non-existing files that won't be directories specially later.
		 */
		while (*cp == '/' && (cp[1] == '/' || cp[1] == '\0')) {
		        cp++;
			ndp->ni_pathlen--;

			if (*cp == '\0') {
			        ndp->ni_flag |= NAMEI_TRAILINGSLASH;
				*ndp->ni_next = '\0';
			}
		}
		ndp->ni_next = cp;

		cnp->cn_flags &= ~(MAKEENTRY | ISLASTCN | ISDOTDOT);

		if (*cp == '\0')
		        cnp->cn_flags |= ISLASTCN;

		if (cnp->cn_namelen == 2 && cnp->cn_nameptr[1] == '.' && cnp->cn_nameptr[0] == '.')
		        cnp->cn_flags |= ISDOTDOT;

		*dp_authorized = 0;
#if NAMEDRSRCFORK
		/*
		 * Process a request for a file's resource fork.
		 *
		 * Consume the _PATH_RSRCFORKSPEC suffix and tag the path.
		 */
		if ((ndp->ni_pathlen == sizeof(_PATH_RSRCFORKSPEC)) &&
		    (cp[1] == '.' && cp[2] == '.') &&
		    bcmp(cp, _PATH_RSRCFORKSPEC, sizeof(_PATH_RSRCFORKSPEC)) == 0) {
		    	/* Skip volfs file systems that don't support native streams. */
			if ((dp->v_mount != NULL) &&
			    (dp->v_mount->mnt_flag & MNT_DOVOLFS) &&
			    (dp->v_mount->mnt_kern_flag & MNTK_NAMED_STREAMS) == 0) {
				goto skiprsrcfork;
			}
			cnp->cn_flags |= CN_WANTSRSRCFORK;
			cnp->cn_flags |= ISLASTCN;
			ndp->ni_next[0] = '\0';
			ndp->ni_pathlen = 1;
		}
skiprsrcfork:
#endif

#if CONFIG_MACF

		/* 
		 * Name cache provides authorization caching (see below)
		 * that will short circuit MAC checks in lookup().
		 * We must perform MAC check here.  On denial
		 * dp_authorized will remain 0 and second check will
		 * be perfomed in lookup().
		 */
		if (!(cnp->cn_flags & DONOTAUTH)) {
			error = mac_vnode_check_lookup(ctx, dp, cnp);
			if (error) {
				NAME_CACHE_UNLOCK();
				goto errorout;
			}
		}
#endif /* MAC */
		if (ttl_enabled && ((tv.tv_sec - dp->v_cred_timestamp) > dp->v_mount->mnt_authcache_ttl))
		        break;

		/*
		 * NAME_CACHE_LOCK holds these fields stable
		 */
		if ((dp->v_cred != ucred || !(dp->v_authorized_actions & KAUTH_VNODE_SEARCH)) &&
		    !(dp->v_authorized_actions & KAUTH_VNODE_SEARCHBYANYONE))
		        break;

		/*
		 * indicate that we're allowed to traverse this directory...
		 * even if we fail the cache lookup or decide to bail for
		 * some other reason, this information is valid and is used
		 * to avoid doing a vnode_authorize before the call to VNOP_LOOKUP
		 */
		*dp_authorized = 1;

		if ( (cnp->cn_flags & (ISLASTCN | ISDOTDOT)) ) {
			if (cnp->cn_nameiop != LOOKUP)
				break;
			if (cnp->cn_flags & LOCKPARENT) 
				break;
			if (cnp->cn_flags & NOCACHE)
				break;
			if (cnp->cn_flags & ISDOTDOT) {
				/*
				 * Force directory hardlinks to go to
				 * file system for ".." requests.
				 */
				if (dp && (dp->v_flag & VISHARDLINK)) {
					break;
				}
				/*
				 * Quit here only if we can't use
				 * the parent directory pointer or
				 * don't have one.  Otherwise, we'll
				 * use it below.
				 */
				if ((dp->v_flag & VROOT)  ||
				    dp == ndp->ni_rootdir ||
				    dp->v_parent == NULLVP)
					break;
			}
		}

		if ((cnp->cn_flags & CN_SKIPNAMECACHE)) {
			/*
			 * Force lookup to go to the filesystem with
			 * all cnp fields set up.
			 */
			break;
		}

		/*
		 * "." and ".." aren't supposed to be cached, so check
		 * for them before checking the cache.
		 */
		if (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.')
			vp = dp;
		else if ( (cnp->cn_flags & ISDOTDOT) )
			vp = dp->v_parent;
		else {
			if ( (vp = cache_lookup_locked(dp, cnp)) == NULLVP)
				break;

			if ( (vp->v_flag & VISHARDLINK) ) {
				/*
				 * The file system wants a VNOP_LOOKUP on this vnode
				 */
				vp = NULL;
				break;
			}
		}
		if ( (cnp->cn_flags & ISLASTCN) )
		        break;

		if (vp->v_type != VDIR) {
		        if (vp->v_type != VLNK)
			        vp = NULL;
		        break;
		}

		if ( (mp = vp->v_mountedhere) && ((cnp->cn_flags & NOCROSSMOUNT) == 0)) {

		        if (mp->mnt_realrootvp == NULLVP || mp->mnt_generation != mount_generation ||
				mp->mnt_realrootvp_vid != mp->mnt_realrootvp->v_id)
			        break;
			vp = mp->mnt_realrootvp;
		}

#if CONFIG_TRIGGERS
		/*
		 * After traversing all mountpoints stacked here, if we have a
		 * trigger in hand, resolve it.  Note that we don't need to 
		 * leave the fast path if the mount has already happened.
		 */
		if ((vp->v_resolve != NULL) && 
				(vp->v_resolve->vr_resolve_func != NULL)) {
			break;
		} 
#endif /* CONFIG_TRIGGERS */


		dp = vp;
		vp = NULLVP;

		cnp->cn_nameptr = ndp->ni_next + 1;
		ndp->ni_pathlen--;
		while (*cnp->cn_nameptr == '/') {
		        cnp->cn_nameptr++;
			ndp->ni_pathlen--;
		}
	}
	if (vp != NULLVP)
	        vvid = vp->v_id;
	vid = dp->v_id;
	
	NAME_CACHE_UNLOCK();

	if ((vp != NULLVP) && (vp->v_type != VLNK) &&
	    ((cnp->cn_flags & (ISLASTCN | LOCKPARENT | WANTPARENT | SAVESTART)) == ISLASTCN)) {
	        /*
		 * if we've got a child and it's the last component, and 
		 * the lookup doesn't need to return the parent then we
		 * can skip grabbing an iocount on the parent, since all
		 * we're going to do with it is a vnode_put just before
		 * we return from 'lookup'.  If it's a symbolic link,
		 * we need the parent in case the link happens to be
		 * a relative pathname.
		 */
	        tdp = dp;
	        dp = NULLVP;
	} else {
need_dp:
		/*
		 * return the last directory we looked at
		 * with an io reference held. If it was the one passed
		 * in as a result of the last iteration of VNOP_LOOKUP,
		 * it should already hold an io ref. No need to increase ref.
		 */
		if (last_dp != dp){
			
			if (dp == ndp->ni_usedvp) {
				/*
				 * if this vnode matches the one passed in via USEDVP
				 * than this context already holds an io_count... just
				 * use vnode_get to get an extra ref for lookup to play
				 * with... can't use the getwithvid variant here because
				 * it will block behind a vnode_drain which would result
				 * in a deadlock (since we already own an io_count that the
				 * vnode_drain is waiting on)... vnode_get grabs the io_count
				 * immediately w/o waiting... it always succeeds
				 */
				vnode_get(dp);
			} else if ((error = vnode_getwithvid_drainok(dp, vid))) {
				/*
				 * failure indicates the vnode
				 * changed identity or is being
				 * TERMINATED... in either case
				 * punt this lookup.
				 * 
				 * don't necessarily return ENOENT, though, because
				 * we really want to go back to disk and make sure it's
				 * there or not if someone else is changing this
				 * vnode. That being said, the one case where we do want
				 * to return ENOENT is when the vnode's mount point is
				 * in the process of unmounting and we might cause a deadlock
				 * in our attempt to take an iocount. An ENODEV error return
				 * is from vnode_get* is an indication this but we change that
				 * ENOENT for upper layers.
				 */
				if (error == ENODEV) {
					error = ENOENT;
				} else {
					error = ERECYCLE;
				}
				goto errorout;
			}
		}
	}
	if (vp != NULLVP) {
	        if ( (vnode_getwithvid_drainok(vp, vvid)) ) {
		        vp = NULLVP;

		        /*
			 * can't get reference on the vp we'd like
			 * to return... if we didn't grab a reference
			 * on the directory (due to fast path bypass),
			 * then we need to do it now... we can't return
			 * with both ni_dvp and ni_vp NULL, and no 
			 * error condition
			 */
			if (dp == NULLVP) {
			        dp = tdp;
				goto need_dp;
			}
		}
	}

	ndp->ni_dvp = dp;
	ndp->ni_vp  = vp;

#if CONFIG_TRIGGERS
	trigger_vp = vp ? vp : dp;
	if ((error == 0) && (trigger_vp != NULLVP) && vnode_isdir(trigger_vp)) {
		error = vnode_trigger_resolve(trigger_vp, ndp, ctx);
		if (error) {
			if (vp)
				vnode_put(vp);
			if (dp) 
				vnode_put(dp);
			goto errorout;
		}
	} 
#endif /* CONFIG_TRIGGERS */

errorout:
	/* 
	 * If we came into cache_lookup_path after an iteration of the lookup loop that
	 * resulted in a call to VNOP_LOOKUP, then VNOP_LOOKUP returned a vnode with a io ref
	 * on it.  It is now the job of cache_lookup_path to drop the ref on this vnode 
	 * when it is no longer needed.  If we get to this point, and last_dp is not NULL
	 * and it is ALSO not the dvp we want to return to caller of this function, it MUST be
	 * the case that we got to a subsequent path component and this previous vnode is 
	 * no longer needed.  We can then drop the io ref on it.
	 */
	if ((last_dp != NULLVP) && (last_dp != ndp->ni_dvp)){
		vnode_put(last_dp);
	}
	
	//initialized to 0, should be the same if no error cases occurred.
	return error;
}


static vnode_t
cache_lookup_locked(vnode_t dvp, struct componentname *cnp)
{
	struct namecache *ncp;
	struct nchashhead *ncpp;
	long namelen = cnp->cn_namelen;
	unsigned int hashval = cnp->cn_hash;
	
	if (nc_disabled) {
		return NULL;
	}

	ncpp = NCHHASH(dvp, cnp->cn_hash);
	LIST_FOREACH(ncp, ncpp, nc_hash) {
	        if ((ncp->nc_dvp == dvp) && (ncp->nc_hashval == hashval)) {
			if (memcmp(ncp->nc_name, cnp->cn_nameptr, namelen) == 0 && ncp->nc_name[namelen] == 0)
			        break;
		}
	}
	if (ncp == 0) {
		/*
		 * We failed to find an entry
		 */
		NCHSTAT(ncs_miss);
		return (NULL);
	}
	NCHSTAT(ncs_goodhits);

	return (ncp->nc_vp);
}


unsigned int hash_string(const char *cp, int len);
//
// Have to take a len argument because we may only need to
// hash part of a componentname.
//
unsigned int
hash_string(const char *cp, int len)
{
    unsigned hash = 0;

    if (len) {
            while (len--) {
		    hash = crc32tab[((hash >> 24) ^ (unsigned char)*cp++)] ^ hash << 8;
	    }
    } else {
            while (*cp != '\0') {
		    hash = crc32tab[((hash >> 24) ^ (unsigned char)*cp++)] ^ hash << 8;
	    }
    }
    /*
     * the crc generator can legitimately generate
     * a 0... however, 0 for us means that we
     * haven't computed a hash, so use 1 instead
     */
    if (hash == 0)
            hash = 1;
    return hash;
}


/*
 * Lookup an entry in the cache 
 *
 * We don't do this if the segment name is long, simply so the cache 
 * can avoid holding long names (which would either waste space, or
 * add greatly to the complexity).
 *
 * Lookup is called with dvp pointing to the directory to search,
 * cnp pointing to the name of the entry being sought. If the lookup
 * succeeds, the vnode is returned in *vpp, and a status of -1 is
 * returned. If the lookup determines that the name does not exist
 * (negative cacheing), a status of ENOENT is returned. If the lookup
 * fails, a status of zero is returned.
 */

int
cache_lookup(struct vnode *dvp, struct vnode **vpp, struct componentname *cnp)
{
	struct namecache *ncp;
	struct nchashhead *ncpp;
	long namelen = cnp->cn_namelen;
	unsigned int hashval;
	boolean_t	have_exclusive = FALSE;
	uint32_t vid;
	vnode_t	 vp;

	if (cnp->cn_hash == 0)
		cnp->cn_hash = hash_string(cnp->cn_nameptr, cnp->cn_namelen);
	hashval = cnp->cn_hash;

	if (nc_disabled) {
		return 0;
	}

	NAME_CACHE_LOCK_SHARED();

relook:
	ncpp = NCHHASH(dvp, cnp->cn_hash);
	LIST_FOREACH(ncp, ncpp, nc_hash) {
	        if ((ncp->nc_dvp == dvp) && (ncp->nc_hashval == hashval)) {
			if (memcmp(ncp->nc_name, cnp->cn_nameptr, namelen) == 0 && ncp->nc_name[namelen] == 0)
			        break;
		}
	}
	/* We failed to find an entry */
	if (ncp == 0) {
		NCHSTAT(ncs_miss);
		NAME_CACHE_UNLOCK();
		return (0);
	}

	/* We don't want to have an entry, so dump it */
	if ((cnp->cn_flags & MAKEENTRY) == 0) {
	        if (have_exclusive == TRUE) {
		        NCHSTAT(ncs_badhits);
			cache_delete(ncp, 1);
			NAME_CACHE_UNLOCK();
			return (0);
		}
		NAME_CACHE_UNLOCK();
		NAME_CACHE_LOCK();
		have_exclusive = TRUE;
		goto relook;
	} 
	vp = ncp->nc_vp;

	/* We found a "positive" match, return the vnode */
        if (vp) {
		NCHSTAT(ncs_goodhits);

		vid = vp->v_id;
		NAME_CACHE_UNLOCK();

		if (vnode_getwithvid(vp, vid)) {
#if COLLECT_STATS
		        NAME_CACHE_LOCK();
			NCHSTAT(ncs_badvid);
			NAME_CACHE_UNLOCK();
#endif
			return (0);
		}
		*vpp = vp;
		return (-1);
	}

	/* We found a negative match, and want to create it, so purge */
	if (cnp->cn_nameiop == CREATE || cnp->cn_nameiop == RENAME) {
	        if (have_exclusive == TRUE) {
		        NCHSTAT(ncs_badhits);
			cache_delete(ncp, 1);
			NAME_CACHE_UNLOCK();
			return (0);
		}
		NAME_CACHE_UNLOCK();
		NAME_CACHE_LOCK();
		have_exclusive = TRUE;
		goto relook;
	}

	/*
	 * We found a "negative" match, ENOENT notifies client of this match.
	 */
	NCHSTAT(ncs_neghits);

	NAME_CACHE_UNLOCK();
	return (ENOENT);
}

const char *
cache_enter_create(vnode_t dvp, vnode_t vp, struct componentname *cnp)
{
	const char *strname;

        if (cnp->cn_hash == 0)
	        cnp->cn_hash = hash_string(cnp->cn_nameptr, cnp->cn_namelen);

	/*
	 * grab 2 references on the string entered
	 * one for the cache_enter_locked to consume
	 * and the second to be consumed by v_name (vnode_create call point)
	 */
	strname = add_name_internal(cnp->cn_nameptr, cnp->cn_namelen, cnp->cn_hash, TRUE, 0);

	NAME_CACHE_LOCK();

	cache_enter_locked(dvp, vp, cnp, strname);

	NAME_CACHE_UNLOCK();

	return (strname);
}


/*
 * Add an entry to the cache...
 * but first check to see if the directory
 * that this entry is to be associated with has
 * had any cache_purges applied since we took
 * our identity snapshot... this check needs to
 * be done behind the name cache lock
 */
void
cache_enter_with_gen(struct vnode *dvp, struct vnode *vp, struct componentname *cnp, int gen)
{

        if (cnp->cn_hash == 0)
	        cnp->cn_hash = hash_string(cnp->cn_nameptr, cnp->cn_namelen);

	NAME_CACHE_LOCK();

	if (dvp->v_nc_generation == gen)
	        (void)cache_enter_locked(dvp, vp, cnp, NULL);

	NAME_CACHE_UNLOCK();
}


/*
 * Add an entry to the cache.
 */
void
cache_enter(struct vnode *dvp, struct vnode *vp, struct componentname *cnp)
{
	const char *strname;

        if (cnp->cn_hash == 0)
	        cnp->cn_hash = hash_string(cnp->cn_nameptr, cnp->cn_namelen);

	/*
	 * grab 1 reference on the string entered
	 * for the cache_enter_locked to consume
	 */
	strname = add_name_internal(cnp->cn_nameptr, cnp->cn_namelen, cnp->cn_hash, FALSE, 0);

	NAME_CACHE_LOCK();

	cache_enter_locked(dvp, vp, cnp, strname);

	NAME_CACHE_UNLOCK();
}


static void
cache_enter_locked(struct vnode *dvp, struct vnode *vp, struct componentname *cnp, const char *strname)
{
        struct namecache *ncp, *negp;
	struct nchashhead *ncpp;

	if (nc_disabled) 
		return;

	/*
	 * if the entry is for -ve caching vp is null
	 */
	if ((vp != NULLVP) && (LIST_FIRST(&vp->v_nclinks))) {
	        /*
		 * someone beat us to the punch..
		 * this vnode is already in the cache
		 */
		if (strname != NULL)
			vfs_removename(strname);
		return;
	}
	/*
	 * We allocate a new entry if we are less than the maximum
	 * allowed and the one at the front of the list is in use.
	 * Otherwise we use the one at the front of the list.
	 */
	if (numcache < desiredNodes &&
	    ((ncp = nchead.tqh_first) == NULL ||
	      ncp->nc_hash.le_prev != 0)) {
		/*
		 * Allocate one more entry
		 */
		ncp = (struct namecache *)_MALLOC_ZONE(sizeof(*ncp), M_CACHE, M_WAITOK);
		numcache++;
	} else {
		/*
		 * reuse an old entry
		 */
	        ncp = TAILQ_FIRST(&nchead);
		TAILQ_REMOVE(&nchead, ncp, nc_entry);

		if (ncp->nc_hash.le_prev != 0) {
		       /*
			* still in use... we need to
			* delete it before re-using it
			*/
			NCHSTAT(ncs_stolen);
			cache_delete(ncp, 0);
		}
	}
	NCHSTAT(ncs_enters);

	/*
	 * Fill in cache info, if vp is NULL this is a "negative" cache entry.
	 */
	ncp->nc_vp = vp;
	ncp->nc_dvp = dvp;
	ncp->nc_hashval = cnp->cn_hash;

	if (strname == NULL)
		ncp->nc_name = add_name_internal(cnp->cn_nameptr, cnp->cn_namelen, cnp->cn_hash, FALSE, 0);
	else
		ncp->nc_name = strname;
	/*
	 * make us the newest entry in the cache
	 * i.e. we'll be the last to be stolen
	 */
	TAILQ_INSERT_TAIL(&nchead, ncp, nc_entry);

	ncpp = NCHHASH(dvp, cnp->cn_hash);
#if DIAGNOSTIC
	{
		struct namecache *p;

		for (p = ncpp->lh_first; p != 0; p = p->nc_hash.le_next)
			if (p == ncp)
				panic("cache_enter: duplicate");
	}
#endif
	/*
	 * make us available to be found via lookup
	 */
	LIST_INSERT_HEAD(ncpp, ncp, nc_hash);

	if (vp) {
	       /*
		* add to the list of name cache entries
		* that point at vp
		*/
		LIST_INSERT_HEAD(&vp->v_nclinks, ncp, nc_un.nc_link);
	} else {
	        /*
		 * this is a negative cache entry (vp == NULL)
		 * stick it on the negative cache list.
		 */
	        TAILQ_INSERT_TAIL(&neghead, ncp, nc_un.nc_negentry);
	  
		ncs_negtotal++;

		if (ncs_negtotal > desiredNegNodes) {
		       /*
			* if we've reached our desired limit
			* of negative cache entries, delete
			* the oldest
			*/
		        negp = TAILQ_FIRST(&neghead);
			cache_delete(negp, 1);
		}
	}
	/*
	 * add us to the list of name cache entries that
	 * are children of dvp
	 */
	LIST_INSERT_HEAD(&dvp->v_ncchildren, ncp, nc_child);
}


/*
 * Initialize CRC-32 remainder table.
 */
static void init_crc32(void)
{
        /*
	 * the CRC-32 generator polynomial is:
	 *   x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^10
	 *        + x^8  + x^7  + x^5  + x^4  + x^2  + x + 1
	 */
        unsigned int crc32_polynomial = 0x04c11db7;
	unsigned int i,j;

	/*
	 * pre-calculate the CRC-32 remainder for each possible octet encoding
	 */
	for (i = 0;  i < 256;  i++) {
	        unsigned int crc_rem = i << 24;

		for (j = 0;  j < 8;  j++) {
		        if (crc_rem & 0x80000000)
			        crc_rem = (crc_rem << 1) ^ crc32_polynomial;
			else
			        crc_rem = (crc_rem << 1);
		}
		crc32tab[i] = crc_rem;
	}
}


/*
 * Name cache initialization, from vfs_init() when we are booting
 */
void
nchinit(void)
{
	int	i;

	desiredNegNodes = (desiredvnodes / 10);
	desiredNodes = desiredvnodes + desiredNegNodes;

	TAILQ_INIT(&nchead);
	TAILQ_INIT(&neghead);

	init_crc32();

	nchashtbl = hashinit(MAX(CONFIG_NC_HASH, (2 *desiredNodes)), M_CACHE, &nchash);
	nchashmask = nchash;
	nchash++;

	init_string_table();
	
	/* Allocate name cache lock group attribute and group */
	namecache_lck_grp_attr= lck_grp_attr_alloc_init();

	namecache_lck_grp = lck_grp_alloc_init("Name Cache",  namecache_lck_grp_attr);
	
	/* Allocate name cache lock attribute */
	namecache_lck_attr = lck_attr_alloc_init();

	/* Allocate name cache lock */
	namecache_rw_lock = lck_rw_alloc_init(namecache_lck_grp, namecache_lck_attr);


	/* Allocate string cache lock group attribute and group */
	strcache_lck_grp_attr= lck_grp_attr_alloc_init();

	strcache_lck_grp = lck_grp_alloc_init("String Cache",  strcache_lck_grp_attr);
	
	/* Allocate string cache lock attribute */
	strcache_lck_attr = lck_attr_alloc_init();

	/* Allocate string cache lock */
	strtable_rw_lock = lck_rw_alloc_init(strcache_lck_grp, strcache_lck_attr);

	for (i = 0; i < NUM_STRCACHE_LOCKS; i++)
		lck_mtx_init(&strcache_mtx_locks[i], strcache_lck_grp, strcache_lck_attr);
}

void
name_cache_lock_shared(void)
{
	lck_rw_lock_shared(namecache_rw_lock);
}

void
name_cache_lock(void)
{
	lck_rw_lock_exclusive(namecache_rw_lock);
}

void
name_cache_unlock(void)
{
	lck_rw_done(namecache_rw_lock);
}


int
resize_namecache(u_int newsize)
{
    struct nchashhead	*new_table;
    struct nchashhead	*old_table;
    struct nchashhead	*old_head, *head;
    struct namecache 	*entry, *next;
    uint32_t		i, hashval;
    int			dNodes, dNegNodes;
    u_long		new_size, old_size;

    dNegNodes = (newsize / 10);
    dNodes = newsize + dNegNodes;

    // we don't support shrinking yet
    if (dNodes <= desiredNodes) {
	return 0;
    }
    new_table = hashinit(2 * dNodes, M_CACHE, &nchashmask);
    new_size  = nchashmask + 1;

    if (new_table == NULL) {
	return ENOMEM;
    }

    NAME_CACHE_LOCK();
    // do the switch!
    old_table = nchashtbl;
    nchashtbl = new_table;
    old_size  = nchash;
    nchash    = new_size;

    // walk the old table and insert all the entries into
    // the new table
    //
    for(i=0; i < old_size; i++) {
	old_head = &old_table[i];
	for (entry=old_head->lh_first; entry != NULL; entry=next) {
	    //
	    // XXXdbg - Beware: this assumes that hash_string() does
	    //                  the same thing as what happens in
	    //                  lookup() over in vfs_lookup.c
	    hashval = hash_string(entry->nc_name, 0);
	    entry->nc_hashval = hashval;
	    head = NCHHASH(entry->nc_dvp, hashval);
	    
	    next = entry->nc_hash.le_next;
	    LIST_INSERT_HEAD(head, entry, nc_hash);
	}
    }
    desiredNodes = dNodes;
    desiredNegNodes = dNegNodes;
    
    NAME_CACHE_UNLOCK();
    FREE(old_table, M_CACHE);

    return 0;
}

static void
cache_delete(struct namecache *ncp, int age_entry)
{
        NCHSTAT(ncs_deletes);

        if (ncp->nc_vp) {
	        LIST_REMOVE(ncp, nc_un.nc_link);
	} else {
	        TAILQ_REMOVE(&neghead, ncp, nc_un.nc_negentry);
	        ncs_negtotal--;
	}
        LIST_REMOVE(ncp, nc_child);

	LIST_REMOVE(ncp, nc_hash);
	/*
	 * this field is used to indicate
	 * that the entry is in use and
	 * must be deleted before it can 
	 * be reused...
	 */
	ncp->nc_hash.le_prev = NULL;

	if (age_entry) {
	        /*
		 * make it the next one available
		 * for cache_enter's use
		 */
	        TAILQ_REMOVE(&nchead, ncp, nc_entry);
	        TAILQ_INSERT_HEAD(&nchead, ncp, nc_entry);
	}
	vfs_removename(ncp->nc_name);
	ncp->nc_name = NULL;
}


/*
 * purge the entry associated with the 
 * specified vnode from the name cache
 */
void
cache_purge(vnode_t vp)
{
        struct namecache *ncp;
	kauth_cred_t tcred = NULL;

	if ((LIST_FIRST(&vp->v_nclinks) == NULL) && 
			(LIST_FIRST(&vp->v_ncchildren) == NULL) && 
			(vp->v_cred == NOCRED) &&
			(vp->v_parent == NULLVP))
	        return;

	NAME_CACHE_LOCK();

	if (vp->v_parent)
	        vp->v_parent->v_nc_generation++;

	while ( (ncp = LIST_FIRST(&vp->v_nclinks)) )
	        cache_delete(ncp, 1);

	while ( (ncp = LIST_FIRST(&vp->v_ncchildren)) )
	        cache_delete(ncp, 1);

	/*
	 * Use a temp variable to avoid kauth_cred_unref() while NAME_CACHE_LOCK is held
	 */
	tcred = vp->v_cred;
	vp->v_cred = NOCRED;
	vp->v_authorized_actions = 0;

	NAME_CACHE_UNLOCK();

	if (IS_VALID_CRED(tcred))
	        kauth_cred_unref(&tcred);
}

/*
 * Purge all negative cache entries that are children of the
 * given vnode.  A case-insensitive file system (or any file
 * system that has multiple equivalent names for the same
 * directory entry) can use this when creating or renaming
 * to remove negative entries that may no longer apply.
 */
void
cache_purge_negatives(vnode_t vp)
{
	struct namecache *ncp, *next_ncp;

	NAME_CACHE_LOCK();

	LIST_FOREACH_SAFE(ncp, &vp->v_ncchildren, nc_child, next_ncp)
		if (ncp->nc_vp == NULL)
			cache_delete(ncp , 1);

	NAME_CACHE_UNLOCK();
}

/*
 * Flush all entries referencing a particular filesystem.
 *
 * Since we need to check it anyway, we will flush all the invalid
 * entries at the same time.
 */
void
cache_purgevfs(struct mount *mp)
{
	struct nchashhead *ncpp;
	struct namecache *ncp;

	NAME_CACHE_LOCK();
	/* Scan hash tables for applicable entries */
	for (ncpp = &nchashtbl[nchash - 1]; ncpp >= nchashtbl; ncpp--) {
restart:	  
		for (ncp = ncpp->lh_first; ncp != 0; ncp = ncp->nc_hash.le_next) {
			if (ncp->nc_dvp->v_mount == mp) {
				cache_delete(ncp, 0);
				goto restart;
			}
		}
	}
	NAME_CACHE_UNLOCK();
}



//
// String ref routines
//
static LIST_HEAD(stringhead, string_t) *string_ref_table;
static u_long   string_table_mask;
static uint32_t filled_buckets=0;


typedef struct string_t {
    LIST_ENTRY(string_t)  hash_chain;
    const char *str;
    uint32_t              refcount;
} string_t;


static void
resize_string_ref_table(void)
{
	struct stringhead *new_table;
	struct stringhead *old_table;
	struct stringhead *old_head, *head;
	string_t          *entry, *next;
	uint32_t           i, hashval;
	u_long             new_mask, old_mask;

	/*
	 * need to hold the table lock exclusively
	 * in order to grow the table... need to recheck
	 * the need to resize again after we've taken
	 * the lock exclusively in case some other thread
	 * beat us to the punch
	 */
	lck_rw_lock_exclusive(strtable_rw_lock);

	if (4 * filled_buckets < ((string_table_mask + 1) * 3)) {
		lck_rw_done(strtable_rw_lock);
		return;
	}
	new_table = hashinit((string_table_mask + 1) * 2, M_CACHE, &new_mask);

	if (new_table == NULL) {
		printf("failed to resize the hash table.\n");
		lck_rw_done(strtable_rw_lock);
		return;
	}

	// do the switch!
	old_table         = string_ref_table;
	string_ref_table  = new_table;
	old_mask          = string_table_mask;
	string_table_mask = new_mask;
	filled_buckets	  = 0;

	// walk the old table and insert all the entries into
	// the new table
	//
	for (i = 0; i <= old_mask; i++) {
		old_head = &old_table[i];
		for (entry = old_head->lh_first; entry != NULL; entry = next) {
			hashval = hash_string((const char *)entry->str, 0);
			head = &string_ref_table[hashval & string_table_mask];
			if (head->lh_first == NULL) {
				filled_buckets++;
			}
			next = entry->hash_chain.le_next;
			LIST_INSERT_HEAD(head, entry, hash_chain);
		}
	}
	lck_rw_done(strtable_rw_lock);

	FREE(old_table, M_CACHE);
}


static void
init_string_table(void)
{
	string_ref_table = hashinit(CONFIG_VFS_NAMES, M_CACHE, &string_table_mask);
}


const char *
vfs_addname(const char *name, uint32_t len, u_int hashval, u_int flags)
{
	return (add_name_internal(name, len, hashval, FALSE, flags));
}


static const char *
add_name_internal(const char *name, uint32_t len, u_int hashval, boolean_t need_extra_ref, __unused u_int flags)
{
	struct stringhead *head;
	string_t          *entry;
	uint32_t          chain_len = 0;
	uint32_t	  hash_index;
        uint32_t	  lock_index;
	char              *ptr;
    
	/*
	 * if the length already accounts for the null-byte, then
	 * subtract one so later on we don't index past the end
	 * of the string.
	 */
	if (len > 0 && name[len-1] == '\0') {
		len--;
	}
	if (hashval == 0) {
		hashval = hash_string(name, len);
	}

	/*
	 * take this lock 'shared' to keep the hash stable
	 * if someone else decides to grow the pool they
	 * will take this lock exclusively
	 */
	lck_rw_lock_shared(strtable_rw_lock);

	/*
	 * If the table gets more than 3/4 full, resize it
	 */
	if (4 * filled_buckets >= ((string_table_mask + 1) * 3)) {
		lck_rw_done(strtable_rw_lock);

		resize_string_ref_table();

		lck_rw_lock_shared(strtable_rw_lock);
	}
	hash_index = hashval & string_table_mask;
	lock_index = hash_index % NUM_STRCACHE_LOCKS;

	head = &string_ref_table[hash_index];

	lck_mtx_lock_spin(&strcache_mtx_locks[lock_index]);

	for (entry = head->lh_first; entry != NULL; chain_len++, entry = entry->hash_chain.le_next) {
		if (memcmp(entry->str, name, len) == 0 && entry->str[len] == 0) {
			entry->refcount++;
			break;
		}
	}
	if (entry == NULL) {
		lck_mtx_convert_spin(&strcache_mtx_locks[lock_index]);
		/*
		 * it wasn't already there so add it.
		 */
		MALLOC(entry, string_t *, sizeof(string_t) + len + 1, M_TEMP, M_WAITOK);

		if (head->lh_first == NULL) {
			OSAddAtomic(1, &filled_buckets);
		}
		ptr = (char *)((char *)entry + sizeof(string_t));
		strncpy(ptr, name, len);
		ptr[len] = '\0';
		entry->str = ptr;
		entry->refcount = 1;
		LIST_INSERT_HEAD(head, entry, hash_chain);
	}
	if (need_extra_ref == TRUE)
		entry->refcount++;
    
	lck_mtx_unlock(&strcache_mtx_locks[lock_index]);
	lck_rw_done(strtable_rw_lock);

	return (const char *)entry->str;
}


int
vfs_removename(const char *nameref)
{
	struct stringhead *head;
	string_t          *entry;
	uint32_t           hashval;
	uint32_t	   hash_index;
        uint32_t	   lock_index;
	int		   retval = ENOENT;

	hashval = hash_string(nameref, 0);

	/*
	 * take this lock 'shared' to keep the hash stable
	 * if someone else decides to grow the pool they
	 * will take this lock exclusively
	 */
	lck_rw_lock_shared(strtable_rw_lock);
	/*
	 * must compute the head behind the table lock
	 * since the size and location of the table
	 * can change on the fly
	 */
	hash_index = hashval & string_table_mask;
	lock_index = hash_index % NUM_STRCACHE_LOCKS;

	head = &string_ref_table[hash_index];

	lck_mtx_lock_spin(&strcache_mtx_locks[lock_index]);

	for (entry = head->lh_first; entry != NULL; entry = entry->hash_chain.le_next) {
		if (entry->str == nameref) {
			entry->refcount--;

			if (entry->refcount == 0) {
				LIST_REMOVE(entry, hash_chain);

				if (head->lh_first == NULL) {
					OSAddAtomic(-1, &filled_buckets);
				}
			} else {
				entry = NULL;
			}
			retval = 0;
			break;
		}
	}
	lck_mtx_unlock(&strcache_mtx_locks[lock_index]);
	lck_rw_done(strtable_rw_lock);

	if (entry != NULL)
		FREE(entry, M_TEMP);

	return retval;
}


#ifdef DUMP_STRING_TABLE
void
dump_string_table(void)
{
    struct stringhead *head;
    string_t          *entry;
    u_long            i;
    
    lck_rw_lock_shared(strtable_rw_lock);

    for (i = 0; i <= string_table_mask; i++) {
	head = &string_ref_table[i];
	for (entry=head->lh_first; entry != NULL; entry=entry->hash_chain.le_next) {
	    printf("%6d - %s\n", entry->refcount, entry->str);
	}
    }
    lck_rw_done(strtable_rw_lock);
}
#endif	/* DUMP_STRING_TABLE */
