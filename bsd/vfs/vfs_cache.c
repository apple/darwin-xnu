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
lck_rw_t * namecache_rw_lock;

static vnode_t cache_lookup_locked(vnode_t dvp, struct componentname *cnp);
static int  remove_name_locked(const char *);
static const char *add_name_locked(const char *, size_t, u_int, u_int);
static void init_string_table(void) __attribute__((section("__TEXT, initcode")));
static void cache_delete(struct namecache *, int);
static void cache_enter_locked(vnode_t dvp, vnode_t vp, struct componentname *cnp);

#ifdef DUMP_STRING_TABLE
/*
 * Internal dump function used for debugging
 */
void dump_string_table(void);
#endif	/* DUMP_STRING_TABLE */

static void init_crc32(void) __attribute__((section("__TEXT, initcode")));
static unsigned int crc32tab[256];


#define NCHHASH(dvp, hash_val) \
	(&nchashtbl[(dvp->v_id ^ (hash_val)) & nchashmask])



//
// This function builds the path to a filename in "buff".  The
// length of the buffer *INCLUDING* the trailing zero byte is
// returned in outlen.  NOTE: the length includes the trailing
// zero byte and thus the length is one greater than what strlen
// would return.  This is important and lots of code elsewhere
// in the kernel assumes this behavior.
// 
// This function can call vnop in file system if the parent vnode 
// does not exist or when called for hardlinks via volfs path.  
// If BUILDPATH_NO_FS_ENTER is set in flags, it only uses values present
// in the name cache and does not enter the file system.
//
int
build_path(vnode_t first_vp, char *buff, int buflen, int *outlen, int flags, vfs_context_t ctx)
{
        vnode_t vp;
        vnode_t proc_root_dir_vp;
	char *end;
	const char *str;
	int  len;
	int  ret = 0;
	int  fixhardlink;

	if (first_vp == NULLVP) {
		return (EINVAL);
	}
	/* Grab the process fd so we can evaluate fd_rdir. */
	if (vfs_context_proc(ctx)->p_fd) {
	    proc_root_dir_vp = vfs_context_proc(ctx)->p_fd->fd_rdir;
	} else {
	    proc_root_dir_vp = NULL;
	}
again:
	vp = first_vp;
	end = &buff[buflen-1];
	*end = '\0';

	/* Check if this is the root of a file system. */
	while (vp && vp->v_flag & VROOT) {
		if (vp->v_mount == NULL) {
			return (EINVAL);
		}
	        if ((vp->v_mount->mnt_flag & MNT_ROOTFS) || (vp == proc_root_dir_vp)) {
			/*
			 * It's the root of the root file system, so it's
			 * just "/".
			 */
		        *--end = '/';
			goto out;
		} else {
		        vp = vp->v_mount->mnt_vnodecovered;
		}
	}
	NAME_CACHE_LOCK_SHARED();

	while ((vp != NULLVP) && (vp->v_parent != vp)) {
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
				if (vp->v_parent != NULL) {
					ret = EINVAL;
				} else {
					ret = ENOENT;
				}
				break;
			}
			len = strlen(str);
			/*
			 * Check that there's enough space (including space for the '/')
			 */
			if ((end - buff) < (len + 1)) {
				ret = ENOSPC;
				break;
			}
			/* Copy the name backwards. */
			str += len;
	
			for (; len > 0; len--) {
			       *--end = *--str;
			}
			/* Add a path separator. */
			*--end = '/';
		}

		/*
		 * Walk up the parent chain.
		 */
		if (((vp->v_parent != NULLVP) && !fixhardlink) ||
		    (flags & BUILDPATH_NO_FS_ENTER)) {
			vp = vp->v_parent;

			// if the vnode we have in hand isn't a directory and it
			// has a v_parent, then we started with the resource fork
			// so skip up to avoid getting a duplicate copy of the
			// file name in the path.
			if (vp && !vnode_isdir(vp) && vp->v_parent) {
			    vp = vp->v_parent;
			}
		} else /* No parent, go get it if supported. */ {
			struct vnode_attr  va;
			vnode_t  dvp;
			int  vid;

			/* Make sure file system supports obtaining a path from id. */
			if (!(vp->v_mount->mnt_kern_flag & MNTK_PATH_FROM_ID)) {
				ret = ENOENT;
				break;
			}
		        vid = vp->v_id;
			NAME_CACHE_UNLOCK();

			if (vnode_getwithvid(vp, vid) != 0) {
				/* vnode was recycled, so start over. */
				goto again;
		        }
			
			VATTR_INIT(&va);
			VATTR_WANTED(&va, va_parentid);
			if (fixhardlink) {
				VATTR_WANTED(&va, va_name);
				MALLOC_ZONE(va.va_name, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
			} else {
				va.va_name = NULL;
			}
			/* Ask the file system for its parent id and for its name (optional). */
			ret = vnode_getattr(vp, &va, ctx);
			if (fixhardlink) {
				if (vp->v_name || VATTR_IS_SUPPORTED(&va, va_name)) {
					if (ret == 0) {
						str = va.va_name;
					} else if (vp->v_name) {
						str = vp->v_name;
						ret = 0;
					} else {
						ret = ENOENT;
						goto bad_news;
					}

					len = strlen(str);

					/* Check that there's enough space. */
					if ((end - buff) < (len + 1)) {
						ret = ENOSPC;
					} else {
						/* Copy the name backwards. */
						str += len;
				
						for (; len > 0; len--) {
						       *--end = *--str;
						}
						/* Add a path separator. */
						*--end = '/';
					}
				}
			  bad_news:
				FREE_ZONE(va.va_name, MAXPATHLEN, M_NAMEI);
			}
			if (ret || !VATTR_IS_SUPPORTED(&va, va_parentid)) {
				vnode_put(vp);
				ret = ENOENT;
				goto out;
			}
			/* Ask the file system for the parent vnode. */
			ret = VFS_VGET(vp->v_mount, (ino64_t)va.va_parentid, &dvp, ctx);
			if (ret) {
				vnode_put(vp);
				goto out;
			}
			if (!fixhardlink && (vp->v_parent != dvp)) {
				vnode_update_identity(vp, dvp, NULL, 0, 0, VNODE_UPDATE_PARENT);
			}
			vnode_put(vp);
			vp = dvp;
			/*
			 * We are no longer under the name cache lock here.
			 * So to avoid a race for vnode termination, take a
			 * reference on the vnode and drop that reference
			 * after reacquiring the name cache lock. We use the
			 * vnode_rele_ext call with the dont_reenter flag
			 * set to avoid re-entering the file system which
			 * could possibly re-enter the name cache.
			 */
			if (vnode_ref(dvp) != 0) {
				dvp = NULLVP;
			}
			vnode_put(vp);
			NAME_CACHE_LOCK_SHARED();

			if (dvp) {
				vnode_rele_ext(dvp, 0, 1);
			}

			// if the vnode we have in hand isn't a directory and it
			// has a v_parent, then we started with the resource fork
			// so skip up to avoid getting a duplicate copy of the
			// file name in the path.
			if (vp && !vnode_isdir(vp) && vp->v_parent) {
			    vp = vp->v_parent;
			}
		}
		/*
		 * When a mount point is crossed switch the vp.
		 * Continue until we find the root or we find
		 * a vnode that's not the root of a mounted
		 * file system.
		 */
		while (vp) {
			if (vp == proc_root_dir_vp) {
				NAME_CACHE_UNLOCK();
				goto out;  /* encountered the root */
			}
			if (!(vp->v_flag & VROOT) || !vp->v_mount)
				break;	/* not the root of a mounted FS */
	        	vp = vp->v_mount->mnt_vnodecovered;
		}
	}
	NAME_CACHE_UNLOCK();
out:
	/* Slide the name down to the beginning of the buffer. */
	memmove(buff, end, &buff[buflen] - end);
    
	*outlen = &buff[buflen] - end;  /* length includes the trailing zero byte */
 
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

	NAME_CACHE_LOCK();
	
	if (vp->v_name)
	        name = add_name_locked(vp->v_name, strlen(vp->v_name), 0, 0);
	NAME_CACHE_UNLOCK();

	return (name);
}

void
vnode_putname(const char *name)
{
        NAME_CACHE_LOCK();

	remove_name_locked(name);

	NAME_CACHE_UNLOCK();
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
vnode_update_identity(vnode_t vp, vnode_t dvp, const char *name, int name_len, int name_hashval, int flags)
{
	struct	namecache *ncp;
        vnode_t	old_parentvp = NULLVP;
#if NAMEDSTREAMS
	int isstream = (vp->v_flag & VISNAMEDSTREAM);
	int kusecountbumped = 0;
#endif

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
	NAME_CACHE_LOCK();

	if ( (flags & VNODE_UPDATE_NAME) && (name != vp->v_name) ) {
	        if (vp->v_name != NULL) {
		        remove_name_locked(vp->v_name);
			vp->v_name = NULL;
		}
		if (name && *name) {
		        if (name_len == 0)
			        name_len = strlen(name);
		        vp->v_name = add_name_locked(name, name_len, name_hashval, 0);
		}
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
	  
		        vnode_lock(vp);
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
			 * make our check and the node_rele atomic
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


boolean_t vnode_cache_is_authorized(vnode_t vp, vfs_context_t ctx, kauth_action_t action)
{
	kauth_cred_t	ucred;
	boolean_t	retval = FALSE;

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
 *		ENOENT			No such file or directory
 */
int 
cache_lookup_path(struct nameidata *ndp, struct componentname *cnp, vnode_t dp, vfs_context_t ctx, int *trailing_slash, int *dp_authorized)
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
#if CONFIG_MACF
	int		error;
#endif

	ucred = vfs_context_ucred(ctx);
	*trailing_slash = 0;

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
		        hash ^= crc32tab[((hash >> 24) ^ (unsigned char)*cp++)];
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
			        *trailing_slash = 1;
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
				name_cache_unlock();
				return (error);
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
		        if (cnp->cn_flags & (LOCKPARENT | NOCACHE))
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

		/*
		 * "." and ".." aren't supposed to be cached, so check
		 * for them before checking the cache.
		 */
		if (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.')
			vp = dp;
		else if ((cnp->cn_flags & ISDOTDOT) && dp->v_parent)
			vp = dp->v_parent;
		else {
			if ( (vp = cache_lookup_locked(dp, cnp)) == NULLVP)
				break;
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
		 * with an io reference held
		 */
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
		} else if ( (vnode_getwithvid(dp, vid)) ) {
		        /*
			 * failure indicates the vnode
			 * changed identity or is being
			 * TERMINATED... in either case
			 * punt this lookup.
			 * 
			 * don't necessarily return ENOENT, though, because
			 * we really want to go back to disk and make sure it's
			 * there or not if someone else is changing this
			 * vnode.
			 */
		        return (ERESTART);
		}
	}
	if (vp != NULLVP) {
	        if ( (vnode_getwithvid(vp, vvid)) ) {
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

	return (0);
}


static vnode_t
cache_lookup_locked(vnode_t dvp, struct componentname *cnp)
{
	struct namecache *ncp;
	struct nchashhead *ncpp;
	long namelen = cnp->cn_namelen;
	char *nameptr = cnp->cn_nameptr;
	unsigned int hashval = (cnp->cn_hash & NCHASHMASK);
	vnode_t vp;
	
	ncpp = NCHHASH(dvp, cnp->cn_hash);
	LIST_FOREACH(ncp, ncpp, nc_hash) {
	        if ((ncp->nc_dvp == dvp) && (ncp->nc_hashval == hashval)) {
		        if (memcmp(ncp->nc_name, nameptr, namelen) == 0 && ncp->nc_name[namelen] == 0)
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

	vp = ncp->nc_vp;
	if (vp && (vp->v_flag & VISHARDLINK)) {
			/*
			 * The file system wants a VNOP_LOOKUP on this vnode
			 */
			vp = NULL;
	}
	
	return (vp);
}


//
// Have to take a len argument because we may only need to
// hash part of a componentname.
//
static unsigned int
hash_string(const char *cp, int len)
{
    unsigned hash = 0;

    if (len) {
            while (len--) {
	            hash ^= crc32tab[((hash >> 24) ^ (unsigned char)*cp++)];
	    }
    } else {
            while (*cp != '\0') {
	            hash ^= crc32tab[((hash >> 24) ^ (unsigned char)*cp++)];
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
	char *nameptr = cnp->cn_nameptr;
	unsigned int hashval = (cnp->cn_hash & NCHASHMASK);
	boolean_t	have_exclusive = FALSE;
	uint32_t vid;
	vnode_t	 vp;

	NAME_CACHE_LOCK_SHARED();

	ncpp = NCHHASH(dvp, cnp->cn_hash);
relook:
	LIST_FOREACH(ncp, ncpp, nc_hash) {
	        if ((ncp->nc_dvp == dvp) && (ncp->nc_hashval == hashval)) {
		        if (memcmp(ncp->nc_name, nameptr, namelen) == 0 && ncp->nc_name[namelen] == 0)
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
	 * The nc_whiteout field records whether this is a whiteout.
	 */
	NCHSTAT(ncs_neghits);

	if (ncp->nc_whiteout)
	        cnp->cn_flags |= ISWHITEOUT;
	NAME_CACHE_UNLOCK();
	return (ENOENT);
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
	        cache_enter_locked(dvp, vp, cnp);

	NAME_CACHE_UNLOCK();
}


/*
 * Add an entry to the cache.
 */
void
cache_enter(struct vnode *dvp, struct vnode *vp, struct componentname *cnp)
{
        if (cnp->cn_hash == 0)
	        cnp->cn_hash = hash_string(cnp->cn_nameptr, cnp->cn_namelen);

	NAME_CACHE_LOCK();

	cache_enter_locked(dvp, vp, cnp);

	NAME_CACHE_UNLOCK();
}


static void
cache_enter_locked(struct vnode *dvp, struct vnode *vp, struct componentname *cnp)
{
        struct namecache *ncp, *negp;
	struct nchashhead *ncpp;

	/*
	 * if the entry is for -ve caching vp is null
	 */
	if ((vp != NULLVP) && (LIST_FIRST(&vp->v_nclinks))) {
	        /*
		 * someone beat us to the punch..
		 * this vnode is already in the cache
		 */
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
		ncp = (struct namecache *)_MALLOC_ZONE((u_long)sizeof *ncp, M_CACHE, M_WAITOK);
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
	ncp->nc_whiteout = FALSE;
	ncp->nc_name = add_name_locked(cnp->cn_nameptr, cnp->cn_namelen, cnp->cn_hash, 0);

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
		 * stick it on the negative cache list
		 * and record the whiteout state
		 */
	        TAILQ_INSERT_TAIL(&neghead, ncp, nc_un.nc_negentry);
	  
		if (cnp->cn_flags & ISWHITEOUT)
		        ncp->nc_whiteout = TRUE;
		ncs_negtotal++;

		if (ncs_negtotal > desiredNegNodes) {
		       /*
			* if we've reached our desired limit
			* of negative cache entries, delete
			* the oldest
			*/
		        negp = TAILQ_FIRST(&neghead);
			TAILQ_REMOVE(&neghead, negp, nc_un.nc_negentry);

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
	desiredNegNodes = (desiredvnodes / 10);
	desiredNodes = desiredvnodes + desiredNegNodes;

	TAILQ_INIT(&nchead);
	TAILQ_INIT(&neghead);

	init_crc32();

	nchashtbl = hashinit(MAX(CONFIG_NC_HASH, (2 *desiredNodes)), M_CACHE, &nchash);
	nchashmask = nchash;
	nchash++;

	init_string_table();
	
	/* Allocate mount list lock group attribute and group */
	namecache_lck_grp_attr= lck_grp_attr_alloc_init();

	namecache_lck_grp = lck_grp_alloc_init("Name Cache",  namecache_lck_grp_attr);
	
	/* Allocate mount list lock attribute */
	namecache_lck_attr = lck_attr_alloc_init();

	/* Allocate mount list lock */
	namecache_rw_lock = lck_rw_alloc_init(namecache_lck_grp, namecache_lck_attr);


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
    if (dNodes < desiredNodes) {
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
	remove_name_locked(ncp->nc_name);
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

	if ((LIST_FIRST(&vp->v_nclinks) == NULL) && (LIST_FIRST(&vp->v_ncchildren) == NULL))
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
	struct namecache *ncp;

	NAME_CACHE_LOCK();

	LIST_FOREACH(ncp, &vp->v_ncchildren, nc_child)
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
static uint32_t max_chain_len=0;
static struct stringhead *long_chain_head=NULL;
static uint32_t filled_buckets=0;
static uint32_t num_dups=0;
static uint32_t nstrings=0;

typedef struct string_t {
    LIST_ENTRY(string_t)  hash_chain;
    const char *str;
    uint32_t              refcount;
} string_t;



static int
resize_string_ref_table(void)
{
    struct stringhead *new_table;
    struct stringhead *old_table;
    struct stringhead *old_head, *head;
    string_t          *entry, *next;
    uint32_t           i, hashval;
    u_long             new_mask, old_mask;

    new_table = hashinit((string_table_mask + 1) * 2, M_CACHE, &new_mask);
    if (new_table == NULL) {
	return ENOMEM;
    }

    // do the switch!
    old_table         = string_ref_table;
    string_ref_table  = new_table;
    old_mask          = string_table_mask;
    string_table_mask = new_mask;

    printf("resize: max chain len %d, new table size %lu\n",
	   max_chain_len, new_mask + 1);
    max_chain_len   = 0;
    long_chain_head = NULL;
    filled_buckets  = 0;

    // walk the old table and insert all the entries into
    // the new table
    //
    for(i=0; i <= old_mask; i++) {
	old_head = &old_table[i];
	for (entry=old_head->lh_first; entry != NULL; entry=next) {
	    hashval = hash_string((const char *)entry->str, 0);
	    head = &string_ref_table[hashval & string_table_mask];
	    if (head->lh_first == NULL) {
		filled_buckets++;
	    }

	    next = entry->hash_chain.le_next;
	    LIST_INSERT_HEAD(head, entry, hash_chain);
	}
    }
    
    FREE(old_table, M_CACHE);

    return 0;
}


static void
init_string_table(void)
{
	string_ref_table = hashinit(CONFIG_VFS_NAMES, M_CACHE, &string_table_mask);
}


const char *
vfs_addname(const char *name, size_t len, u_int hashval, u_int flags)
{
        const char * ptr;

	NAME_CACHE_LOCK();
	ptr = add_name_locked(name, len, hashval, flags);
	NAME_CACHE_UNLOCK();

	return(ptr);
}

static const char *
add_name_locked(const char *name, size_t len, u_int hashval, __unused u_int flags)
{
    struct stringhead *head;
    string_t          *entry;
    uint32_t          chain_len = 0;
    char              *ptr;
    
    //
    // If the table gets more than 3/4 full, resize it
    //
    if (4*filled_buckets >= ((string_table_mask + 1) * 3)) {
		if (resize_string_ref_table() != 0) {
			printf("failed to resize the hash table.\n");
		}
    }
    if (hashval == 0) {
	hashval = hash_string(name, 0);
    }

    //
    // if the length already accounts for the null-byte, then
    // subtract one so later on we don't index past the end
    // of the string.
    //
    if (len > 0 && name[len-1] == '\0') {
	len--;
    }

    head = &string_ref_table[hashval & string_table_mask];
    for (entry=head->lh_first; entry != NULL; chain_len++, entry=entry->hash_chain.le_next) {
	if (memcmp(entry->str, name, len) == 0 && entry->str[len] == '\0') {
	    entry->refcount++;
	    num_dups++;
	    break;
	}
    }

    if (entry == NULL) {
	// it wasn't already there so add it.
	MALLOC(entry, string_t *, sizeof(string_t) + len + 1, M_TEMP, M_WAITOK);

	// have to get "head" again because we could have blocked
	// in malloc and thus head could have changed.
	//
	head = &string_ref_table[hashval & string_table_mask];
	if (head->lh_first == NULL) {
	    filled_buckets++;
	}

	ptr = (char *)((char *)entry + sizeof(string_t));
	strncpy(ptr, name, len);
	ptr[len] = '\0';
	entry->str = ptr;
	entry->refcount = 1;
	LIST_INSERT_HEAD(head, entry, hash_chain);

	if (chain_len > max_chain_len) {
	    max_chain_len   = chain_len;
	    long_chain_head = head;
	}

	nstrings++;
    }
    
    return (const char *)entry->str;
}

int
vfs_removename(const char *nameref)
{
	int i;

	NAME_CACHE_LOCK();
	i = remove_name_locked(nameref);
	NAME_CACHE_UNLOCK();

	return(i);
	
}


static int
remove_name_locked(const char *nameref)
{
    struct stringhead *head;
    string_t          *entry;
    uint32_t           hashval;
    const char        *ptr;

    hashval = hash_string(nameref, 0);
    head = &string_ref_table[hashval & string_table_mask];
    for (entry=head->lh_first; entry != NULL; entry=entry->hash_chain.le_next) {
	if (entry->str == nameref) {
	    entry->refcount--;
	    if (entry->refcount == 0) {
		LIST_REMOVE(entry, hash_chain);
		if (head->lh_first == NULL) {
		    filled_buckets--;
		}
		ptr = entry->str;
		entry->str = NULL;
		nstrings--;

		FREE(entry, M_TEMP);
	    } else {
		num_dups--;
	    }

	    return 0;
	}
    }

    return ENOENT;
}


#ifdef DUMP_STRING_TABLE
void
dump_string_table(void)
{
    struct stringhead *head;
    string_t          *entry;
    u_long            i;
    
    NAME_CACHE_LOCK_SHARED();

    for (i = 0; i <= string_table_mask; i++) {
	head = &string_ref_table[i];
	for (entry=head->lh_first; entry != NULL; entry=entry->hash_chain.le_next) {
	    printf("%6d - %s\n", entry->refcount, entry->str);
	}
    }
    NAME_CACHE_UNLOCK();
}
#endif	/* DUMP_STRING_TABLE */
