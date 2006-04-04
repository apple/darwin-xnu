/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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
TAILQ_HEAD(, namecache) nchead;		/* chain of all name cache entries */
TAILQ_HEAD(, namecache) neghead;	/* chain of only negative cache entries */
struct	nchstats nchstats;		/* cache effectiveness statistics */

/* vars for name cache list lock */
lck_grp_t * namecache_lck_grp;
lck_grp_attr_t * namecache_lck_grp_attr;
lck_attr_t * namecache_lck_attr;
lck_mtx_t * namecache_mtx_lock;

static vnode_t cache_lookup_locked(vnode_t dvp, struct componentname *cnp);
static int  remove_name_locked(const char *);
static char *add_name_locked(const char *, size_t, u_int, u_int);
static void init_string_table(void);
static void cache_delete(struct namecache *, int);
static void dump_string_table(void);

static void init_crc32(void);
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
int
build_path(vnode_t first_vp, char *buff, int buflen, int *outlen)
{
        vnode_t vp = first_vp;
	char *end, *str;
	int   len, ret=0, counter=0;

	end = &buff[buflen-1];
	*end = '\0';

	/*
	 * if this is the root dir of a file system...
	 */
	if (vp && (vp->v_flag & VROOT) && vp->v_mount) {
	        /*
		 * then if it's the root fs, just put in a '/' and get out of here
		 */
	        if (vp->v_mount->mnt_flag & MNT_ROOTFS) {
		        *--end = '/';
			goto out;
		} else {
		        /*
			 * else just use the covered vnode to get the mount path
			 */
		        vp = vp->v_mount->mnt_vnodecovered;
		}
	}
	name_cache_lock();

	while (vp && vp->v_parent != vp) {
	        /*
		 * the maximum depth of a file system hierarchy is MAXPATHLEN/2
		 * (with single-char names separated by slashes).  we panic if
		 * we've ever looped more than that.
		 */
	        if (counter++ > MAXPATHLEN/2) {
		        panic("build_path: vnode parent chain is too long! vp 0x%x\n", vp);
		}
		str = vp->v_name;

		if (str == NULL) {
		        if (vp->v_parent != NULL) {
			        ret = EINVAL;
			}
			break;
		}
		len = strlen(str);

		/*
		 * check that there's enough space (make sure to include space for the '/')
		 */
		if ((end - buff) < (len + 1)) {
			ret = ENOSPC;
			break;
		}
		/*
		 * copy it backwards
		 */
		str += len;

		for (; len > 0; len--) {
		       *--end = *--str;
		}
		/*
		 * put in the path separator
		 */
		*--end = '/';

		/*
		 * walk up the chain (as long as we're not the root)  
		 */
		if (vp == first_vp && (vp->v_flag & VROOT)) {
		        if (vp->v_mount && vp->v_mount->mnt_vnodecovered) {
			        vp = vp->v_mount->mnt_vnodecovered->v_parent;
			} else {
			        vp = NULLVP;
			}
		} else {
		        vp = vp->v_parent;
		}
		/*
		 * check if we're crossing a mount point and
		 * switch the vp if we are.
		 */
		if (vp && (vp->v_flag & VROOT) && vp->v_mount) {
		        vp = vp->v_mount->mnt_vnodecovered;
		}
	}
	name_cache_unlock();
out:
	/*
	 * slide it down to the beginning of the buffer
	 */
	memmove(buff, end, &buff[buflen] - end);
    
	*outlen = &buff[buflen] - end;  // length includes the trailing zero byte
 
	return ret;
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

        name_cache_lock();
	/*
	 * v_parent is stable behind the name_cache lock
	 * however, the only thing we can really guarantee
	 * is that we've grabbed a valid iocount on the
	 * parent of 'vp' at the time we took the name_cache lock...
	 * once we drop the lock, vp could get re-parented
	 */
	if ( (pvp = vp->v_parent) != NULLVP ) {
	        pvid = pvp->v_id;

		name_cache_unlock();

		if (vnode_getwithvid(pvp, pvid) != 0)
		        pvp = NULL;
	} else
	        name_cache_unlock();

	return (pvp);
}

char *
vnode_getname(vnode_t vp)
{
        char *name = NULL;

        name_cache_lock();
	
	if (vp->v_name)
	        name = add_name_locked(vp->v_name, strlen(vp->v_name), 0, 0);
	name_cache_unlock();

	return (name);
}

void
vnode_putname(char *name)
{
	name_cache_lock();

	remove_name_locked(name);

	name_cache_unlock();
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
vnode_update_identity(vnode_t vp, vnode_t dvp, char *name, int name_len, int name_hashval, int flags)
{
	struct	namecache *ncp;
        vnode_t	old_parentvp = NULLVP;


	if (flags & VNODE_UPDATE_PARENT) {
	        if (dvp && vnode_ref(dvp) != 0)
		        dvp = NULLVP;
	} else
	        dvp = NULLVP;
	name_cache_lock();

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
	name_cache_unlock();
	
	if (dvp != NULLVP)
	        vnode_rele(dvp);
	
	if (old_parentvp) {
	        struct  uthread *ut;

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
				 */
			        name_cache_lock();
				old_parentvp = vp->v_parent;
				vp->v_parent = NULLVP;
				name_cache_unlock();
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
void vnode_set_hard_link(vnode_t vp)
{
	vnode_lock(vp);

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


void vnode_uncache_credentials(vnode_t vp)
{
        kauth_cred_t ucred = NULL;

        if (vp->v_cred) {
	        vnode_lock(vp);

		ucred = vp->v_cred;
		vp->v_cred = NULL;

		vnode_unlock(vp);

		if (ucred)
		        kauth_cred_rele(ucred);
	}
}


void vnode_cache_credentials(vnode_t vp, vfs_context_t context)
{
	kauth_cred_t ucred;
	kauth_cred_t tcred = NOCRED;
	struct timeval tv;

	ucred = vfs_context_ucred(context);

	if (vp->v_cred != ucred || (vp->v_mount->mnt_kern_flag & MNTK_AUTH_OPAQUE)) {
		vnode_lock(vp);

		microuptime(&tv);
		vp->v_cred_timestamp = tv.tv_sec;

		if (vp->v_cred != ucred) {
			kauth_cred_ref(ucred);
	
			tcred = vp->v_cred;
			vp->v_cred = ucred;
		}
		vnode_unlock(vp);
	
		if (tcred)
			kauth_cred_rele(tcred);
	}
}

/*	reverse_lookup - lookup by walking back up the parent chain while leveraging
 *	use of the name cache lock in order to protect our starting vnode.
 *	NOTE - assumes you already have search access to starting point.
 *  returns 0 when we have reached the root, current working dir, or chroot root 
 *
 */
int
reverse_lookup(vnode_t start_vp, vnode_t *lookup_vpp, struct filedesc *fdp, vfs_context_t context, int *dp_authorized)
{
	int				vid, done = 0;
	int				auth_opaque = 0;
	vnode_t			dp = start_vp;
	vnode_t			vp = NULLVP;
	kauth_cred_t	ucred;
	struct timeval 	tv;

	ucred = vfs_context_ucred(context);
	*lookup_vpp = start_vp;

	name_cache_lock();

	if ( dp->v_mount && (dp->v_mount->mnt_kern_flag & MNTK_AUTH_OPAQUE) ) {
		auth_opaque = 1;
		microuptime(&tv);
	}
	for (;;) {
		*dp_authorized = 0;

		if (auth_opaque && ((tv.tv_sec - dp->v_cred_timestamp) > VCRED_EXPIRED))
			break;
		if (dp->v_cred != ucred)
			break;
		/*
		 * indicate that we're allowed to traverse this directory...
		 * even if we bail for some reason, this information is valid and is used
		 * to avoid doing a vnode_authorize
		 */
		*dp_authorized = 1;

		if ((dp->v_flag & VROOT) != 0 	||		/* Hit "/" */
		    (dp == fdp->fd_cdir) 	||		/* Hit process's working directory */
		    (dp == fdp->fd_rdir)) {			/* Hit process chroot()-ed root */
	 		done = 1;
	 		break;
		}

		if ( (vp = dp->v_parent) == NULLVP)
			break;

		dp = vp;
		*lookup_vpp = dp;
	} /* for (;;) */

	vid = dp->v_id;
	
	name_cache_unlock();
	
	if (done == 0 && dp != start_vp) {
		if (vnode_getwithvid(dp, vid) != 0) {
			*lookup_vpp = start_vp;
		}
	}

	return((done == 1) ? 0 : -1);
}

int 
cache_lookup_path(struct nameidata *ndp, struct componentname *cnp, vnode_t dp, vfs_context_t context, int *trailing_slash, int *dp_authorized)
{
	char		*cp;		/* pointer into pathname argument */
	int		vid, vvid;
	int		auth_opaque = 0;
	vnode_t		vp = NULLVP;
	vnode_t		tdp = NULLVP;
	kauth_cred_t	ucred;
	struct timeval tv;
	unsigned int	hash;

	ucred = vfs_context_ucred(context);
	*trailing_slash = 0;

	name_cache_lock();


	if ( dp->v_mount && (dp->v_mount->mnt_kern_flag & MNTK_AUTH_OPAQUE) ) {
		auth_opaque = 1;
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

		if (auth_opaque && ((tv.tv_sec - dp->v_cred_timestamp) > VCRED_EXPIRED))
		        break;

		if (dp->v_cred != ucred)
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
				 * Quit here only if we can't use
				 * the parent directory pointer or
				 * don't have one.  Otherwise, we'll
				 * use it below.
				 */
				if ((dp->v_flag & VROOT) ||
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
		else if (cnp->cn_flags & ISDOTDOT)
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
		if (vp->v_mountedhere && ((cnp->cn_flags & NOCROSSMOUNT) == 0))
		        break;

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
	
	name_cache_unlock();


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
			 * punt this lookup
			 */
		        return (ENOENT);
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
	register struct namecache *ncp;
	register struct nchashhead *ncpp;
	register long namelen = cnp->cn_namelen;
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
	if (ncp == 0)
		/*
		 * We failed to find an entry
		 */
		return (NULL);

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
cache_lookup(dvp, vpp, cnp)
	struct vnode *dvp;
	struct vnode **vpp;
	struct componentname *cnp;
{
	register struct namecache *ncp;
	register struct nchashhead *ncpp;
	register long namelen = cnp->cn_namelen;
	char *nameptr = cnp->cn_nameptr;
	unsigned int hashval = (cnp->cn_hash & NCHASHMASK);
	uint32_t vid;
	vnode_t	 vp;

	name_cache_lock();

	ncpp = NCHHASH(dvp, cnp->cn_hash);
	LIST_FOREACH(ncp, ncpp, nc_hash) {
	        if ((ncp->nc_dvp == dvp) && (ncp->nc_hashval == hashval)) {
		        if (memcmp(ncp->nc_name, nameptr, namelen) == 0 && ncp->nc_name[namelen] == 0)
			        break;
		}
	}
	/* We failed to find an entry */
	if (ncp == 0) {
		nchstats.ncs_miss++;
		name_cache_unlock();
		return (0);
	}

	/* We don't want to have an entry, so dump it */
	if ((cnp->cn_flags & MAKEENTRY) == 0) {
		nchstats.ncs_badhits++;
		cache_delete(ncp, 1);
		name_cache_unlock();
		return (0);
	} 
	vp = ncp->nc_vp;

	/* We found a "positive" match, return the vnode */
        if (vp) {
		nchstats.ncs_goodhits++;

		vid = vp->v_id;
		name_cache_unlock();

		if (vnode_getwithvid(vp, vid)) {
		        name_cache_lock();
			nchstats.ncs_badvid++;
			name_cache_unlock();
			return (0);
		}
		*vpp = vp;
		return (-1);
	}

	/* We found a negative match, and want to create it, so purge */
	if (cnp->cn_nameiop == CREATE || cnp->cn_nameiop == RENAME) {
		nchstats.ncs_badhits++;
		cache_delete(ncp, 1);
		name_cache_unlock();
		return (0);
	}

	/*
	 * We found a "negative" match, ENOENT notifies client of this match.
	 * The nc_whiteout field records whether this is a whiteout.
	 */
	nchstats.ncs_neghits++;

	if (ncp->nc_whiteout)
	        cnp->cn_flags |= ISWHITEOUT;
	name_cache_unlock();
	return (ENOENT);
}

/*
 * Add an entry to the cache.
 */
void
cache_enter(dvp, vp, cnp)
	struct vnode *dvp;
	struct vnode *vp;
	struct componentname *cnp;
{
        register struct namecache *ncp, *negp;
	register struct nchashhead *ncpp;

        if (cnp->cn_hash == 0)
	        cnp->cn_hash = hash_string(cnp->cn_nameptr, cnp->cn_namelen);

	name_cache_lock();

	/* if the entry is for -ve caching vp is null */
	if ((vp != NULLVP) && (LIST_FIRST(&vp->v_nclinks))) {
	        /*
		 * someone beat us to the punch..
		 * this vnode is already in the cache
		 */
	        name_cache_unlock();
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
			nchstats.ncs_stolen++;
			cache_delete(ncp, 0);
		}
	}
	nchstats.ncs_enters++;

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
		register struct namecache *p;

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
		nchstats.ncs_negtotal++;

		if (nchstats.ncs_negtotal > desiredNegNodes) {
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

	name_cache_unlock();
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

	nchashtbl = hashinit(MAX(4096, (2 *desiredNodes)), M_CACHE, &nchash);
	nchashmask = nchash;
	nchash++;

	init_string_table();
	
	/* Allocate mount list lock group attribute and group */
	namecache_lck_grp_attr= lck_grp_attr_alloc_init();
	lck_grp_attr_setstat(namecache_lck_grp_attr);

	namecache_lck_grp = lck_grp_alloc_init("Name Cache",  namecache_lck_grp_attr);
	
	/* Allocate mount list lock attribute */
	namecache_lck_attr = lck_attr_alloc_init();
	//lck_attr_setdebug(namecache_lck_attr);

	/* Allocate mount list lock */
	namecache_mtx_lock = lck_mtx_alloc_init(namecache_lck_grp, namecache_lck_attr);


}

void
name_cache_lock(void)
{
	lck_mtx_lock(namecache_mtx_lock);
}

void
name_cache_unlock(void)
{
	lck_mtx_unlock(namecache_mtx_lock);

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

    name_cache_lock();
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
    
    name_cache_unlock();
    FREE(old_table, M_CACHE);

    return 0;
}

static void
cache_delete(struct namecache *ncp, int age_entry)
{
        nchstats.ncs_deletes++;

        if (ncp->nc_vp) {
	        LIST_REMOVE(ncp, nc_un.nc_link);
	} else {
	        TAILQ_REMOVE(&neghead, ncp, nc_un.nc_negentry);
	        nchstats.ncs_negtotal--;
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

	if ((LIST_FIRST(&vp->v_nclinks) == NULL) && (LIST_FIRST(&vp->v_ncchildren) == NULL))
	        return;

	name_cache_lock();

	while ( (ncp = LIST_FIRST(&vp->v_nclinks)) )
	        cache_delete(ncp, 1);

	while ( (ncp = LIST_FIRST(&vp->v_ncchildren)) )
	        cache_delete(ncp, 1);

	name_cache_unlock();
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

	name_cache_lock();

	LIST_FOREACH(ncp, &vp->v_ncchildren, nc_child)
		if (ncp->nc_vp == NULL)
			cache_delete(ncp , 1);

	name_cache_unlock();
}

/*
 * Flush all entries referencing a particular filesystem.
 *
 * Since we need to check it anyway, we will flush all the invalid
 * entries at the same time.
 */
void
cache_purgevfs(mp)
	struct mount *mp;
{
	struct nchashhead *ncpp;
	struct namecache *ncp;

	name_cache_lock();
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
	name_cache_unlock();
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
    unsigned char        *str;
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

    printf("resize: max chain len %d, new table size %d\n",
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
	    hashval = hash_string(entry->str, 0);
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
    string_ref_table = hashinit(4096, M_CACHE, &string_table_mask);
}


char *
vfs_addname(const char *name, size_t len, u_int hashval, u_int flags)
{
        char * ptr;

	name_cache_lock();
	ptr = add_name_locked(name, len, hashval, flags);
	name_cache_unlock();

	return(ptr);
}

static char *
add_name_locked(const char *name, size_t len, u_int hashval, __unused u_int flags)
{
    struct stringhead *head;
    string_t          *entry;
    uint32_t          chain_len = 0;
    
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

	entry->str = (char *)((char *)entry + sizeof(string_t));
	strncpy(entry->str, name, len);
	entry->str[len] = '\0';
	entry->refcount = 1;
	LIST_INSERT_HEAD(head, entry, hash_chain);

	if (chain_len > max_chain_len) {
	    max_chain_len   = chain_len;
	    long_chain_head = head;
	}

	nstrings++;
    }
    
    return entry->str;
}

int
vfs_removename(const char *nameref)
{
	int i;

	name_cache_lock();
	i = remove_name_locked(nameref);
	name_cache_unlock();

	return(i);
	
}


static int
remove_name_locked(const char *nameref)
{
    struct stringhead *head;
    string_t          *entry;
    uint32_t           hashval;
    char * ptr;

    hashval = hash_string(nameref, 0);
    head = &string_ref_table[hashval & string_table_mask];
    for (entry=head->lh_first; entry != NULL; entry=entry->hash_chain.le_next) {
	if (entry->str == (unsigned char *)nameref) {
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


void
dump_string_table(void)
{
    struct stringhead *head;
    string_t          *entry;
    u_long            i;
    
    name_cache_lock();
    for (i = 0; i <= string_table_mask; i++) {
	head = &string_ref_table[i];
	for (entry=head->lh_first; entry != NULL; entry=entry->hash_chain.le_next) {
	    printf("%6d - %s\n", entry->refcount, entry->str);
	}
    }
    name_cache_unlock();
}
