/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/errno.h>
#include <sys/malloc.h>

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
 * For simplicity (and economy of storage), names longer than
 * a maximum length of NCHNAMLEN are not cached; they occur
 * infrequently in any case, and are almost never of interest.
 *
 * Upon reaching the last segment of a path, if the reference
 * is for DELETE, or NOCACHE is set (rewrite), and the
 * name is located in the cache, it will be dropped.
 */

/*
 * Structures associated with name cacheing.
 */
#define NCHHASH(dvp, hash_val) \
	(&nchashtbl[((u_long)(dvp) ^ ((dvp)->v_id ^ (hash_val))) & nchash])
LIST_HEAD(nchashhead, namecache) *nchashtbl;	/* Hash Table */
u_long	nchash;				/* size of hash table - 1 */
long	numcache;			/* number of cache entries allocated */
TAILQ_HEAD(, namecache) nclruhead;	/* LRU chain */
struct	nchstats nchstats;		/* cache effectiveness statistics */
u_long nextvnodeid = 0;
int doingcache = 1;			/* 1 => enable the cache */

/*
 * Delete an entry from its hash list and move it to the front
 * of the LRU list for immediate reuse.
 *
 * NOTE: THESE MACROS CAN BLOCK (in the call to remove_name())
 *       SO BE CAREFUL IF YOU HOLD POINTERS TO nclruhead OR
 *       nchashtbl.
 */
#if DIAGNOSTIC
#define PURGE(ncp)  {						\
	if (ncp->nc_hash.le_prev == 0)				\
		panic("namecache purge le_prev");		\
	if (ncp->nc_hash.le_next == ncp)			\
		panic("namecache purge le_next");		\
	LIST_REMOVE(ncp, nc_hash);				\
	ncp->nc_hash.le_prev = 0;				\
	TAILQ_REMOVE(&nclruhead, ncp, nc_lru);			\
	TAILQ_INSERT_HEAD(&nclruhead, ncp, nc_lru);		\
	/* this has to come last because it could block */      \
	remove_name(ncp->nc_name);                              \
	ncp->nc_name = NULL;                                    \
}
#else
#define PURGE(ncp)  {						\
	LIST_REMOVE(ncp, nc_hash);				\
	ncp->nc_hash.le_prev = 0;				\
	TAILQ_REMOVE(&nclruhead, ncp, nc_lru);			\
	TAILQ_INSERT_HEAD(&nclruhead, ncp, nc_lru);		\
 	/* this has to come last because it could block */      \
	remove_name(ncp->nc_name);                              \
	ncp->nc_name = NULL;                                    \
}
#endif /* DIAGNOSTIC */

/*
 * Move an entry that has been used to the tail of the LRU list
 * so that it will be preserved for future use.
 */
#define TOUCH(ncp)  {						\
	if (ncp->nc_lru.tqe_next != 0) {			\
		TAILQ_REMOVE(&nclruhead, ncp, nc_lru);		\
		TAILQ_INSERT_TAIL(&nclruhead, ncp, nc_lru);	\
	}							\
}


//
// Have to take a len argument because we may only need to
// hash part of a componentname.
//
static unsigned int
hash_string(const char *str, int len)
{
    unsigned int i, hashval = 0;

    if (len == 0) {
	for(i=1; *str != 0; i++, str++) {
	    hashval += (unsigned char)*str * i;
	}
    } else {
	for(i=len; i > 0; i--, str++) {
	    hashval += (unsigned char)*str * (len - i + 1);
	}
    }

    return hashval;
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
	register struct namecache *ncp, *nnp;
	register struct nchashhead *ncpp;
	register long namelen = cnp->cn_namelen;
	char *nameptr = cnp->cn_nameptr;

	if (!doingcache) {
		cnp->cn_flags &= ~MAKEENTRY;
		return (0);
	}

	ncpp = NCHHASH(dvp, cnp->cn_hash);
	for (ncp = ncpp->lh_first; ncp != 0; ncp = nnp) {
		nnp = ncp->nc_hash.le_next;

		if (ncp->nc_dvp == dvp &&
		    strncmp(ncp->nc_name, nameptr, namelen) == 0 &&
		    ncp->nc_name[namelen] == 0) {
			/* Make sure the vp isn't stale. */
			if ((ncp->nc_dvpid != dvp->v_id) ||
			    (ncp->nc_vp && ncp->nc_vpid != ncp->nc_vp->v_id)) {
				nchstats.ncs_falsehits++;
				PURGE(ncp);
				continue;
			}
			break;
		}
	}

	/* We failed to find an entry */
	if (ncp == 0) {
		nchstats.ncs_miss++;
		return (0);
	}

	/* We don't want to have an entry, so dump it */
	if ((cnp->cn_flags & MAKEENTRY) == 0) {
		nchstats.ncs_badhits++;
		PURGE(ncp);
		return (0);
	} 

	/* We found a "positive" match, return the vnode */
        if (ncp->nc_vp) {
		if (ncp->nc_vp->v_flag & (VUINIT|VXLOCK|VTERMINATE|VORECLAIM)) {
		    PURGE(ncp);
		    return (0);
		}

		nchstats.ncs_goodhits++;
		TOUCH(ncp);
		*vpp = ncp->nc_vp;
		return (-1);
	}

	/* We found a negative match, and want to create it, so purge */
	if (cnp->cn_nameiop == CREATE) {
		nchstats.ncs_badhits++;
		PURGE(ncp);
		return (0);
	}

	/*
	 * We found a "negative" match, ENOENT notifies client of this match.
	 * The nc_vpid field records whether this is a whiteout.
	 */
	nchstats.ncs_neghits++;
	TOUCH(ncp);
	cnp->cn_flags |= ncp->nc_vpid;
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
	register struct namecache *ncp;
	register struct nchashhead *ncpp;

	if (!doingcache)
		return;

	/*
	 * We allocate a new entry if we are less than the maximum
	 * allowed and the one at the front of the LRU list is in use.
	 * Otherwise we use the one at the front of the LRU list.
	 */
	if (numcache < desiredvnodes &&
	    ((ncp = nclruhead.tqh_first) == NULL ||
	    ncp->nc_hash.le_prev != 0)) {
		/* Add one more entry */
		ncp = (struct namecache *)
			_MALLOC_ZONE((u_long)sizeof *ncp, M_CACHE, M_WAITOK);
		numcache++;
	} else if (ncp = nclruhead.tqh_first) {
		/* reuse an old entry */
		TAILQ_REMOVE(&nclruhead, ncp, nc_lru);
		if (ncp->nc_hash.le_prev != 0) {
#if DIAGNOSTIC
			if (ncp->nc_hash.le_next == ncp)
				panic("cache_enter: le_next");
#endif
			LIST_REMOVE(ncp, nc_hash);
			remove_name(ncp->nc_name);
			ncp->nc_name = NULL;
			ncp->nc_hash.le_prev = 0;
		}
	} else {
		/* give up */
		return;
	}

	/*
	 * Fill in cache info, if vp is NULL this is a "negative" cache entry.
	 * For negative entries, we have to record whether it is a whiteout.
	 * the whiteout flag is stored in the nc_vpid field which is
	 * otherwise unused.
	 */
	ncp->nc_vp = vp;
	if (vp)
		ncp->nc_vpid = vp->v_id;
	else
		ncp->nc_vpid = cnp->cn_flags & ISWHITEOUT;
	ncp->nc_dvp = dvp;
	ncp->nc_dvpid = dvp->v_id;
	ncp->nc_name = add_name(cnp->cn_nameptr, cnp->cn_namelen, cnp->cn_hash, 0);
	TAILQ_INSERT_TAIL(&nclruhead, ncp, nc_lru);
	ncpp = NCHHASH(dvp, cnp->cn_hash);
#if DIAGNOSTIC
	{
		register struct namecache *p;

		for (p = ncpp->lh_first; p != 0; p = p->nc_hash.le_next)
			if (p == ncp)
				panic("cache_enter: duplicate");
	}
#endif
	LIST_INSERT_HEAD(ncpp, ncp, nc_hash);
}

/*
 * Name cache initialization, from vfs_init() when we are booting
 */
void
nchinit()
{
    static void init_string_table(void);

    TAILQ_INIT(&nclruhead);
    nchashtbl = hashinit(MAX(4096, desiredvnodes), M_CACHE, &nchash);

    init_string_table();
}


int
resize_namecache(u_int newsize)
{
    struct nchashhead *new_table;
    struct nchashhead *old_table;
    struct nchashhead *old_head, *head;
    struct namecache  *entry, *next;
    uint32_t           i;
    u_long             new_mask, old_mask;

    // we don't support shrinking yet
    if (newsize < nchash) {
	return 0;
    }

    new_table = hashinit(newsize, M_CACHE, &new_mask);
    if (new_table == NULL) {
	return ENOMEM;
    }

    // do the switch!
    old_table = nchashtbl;
    nchashtbl = new_table;
    old_mask  = nchash;
    nchash    = new_mask;

    // walk the old table and insert all the entries into
    // the new table
    //
    for(i=0; i <= old_mask; i++) {
	old_head = &old_table[i];
	for (entry=old_head->lh_first; entry != NULL; entry=next) {
	    //
	    // XXXdbg - Beware: this assumes that hash_string() does
	    //                  the same thing as what happens in
	    //                  lookup() over in vfs_lookup.c
	    head = NCHHASH(entry->nc_dvp, hash_string(entry->nc_name, 0));

	    next = entry->nc_hash.le_next;
	    LIST_INSERT_HEAD(head, entry, nc_hash);
	}
    }
    
    FREE(old_table, M_CACHE);

    return 0;
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
cache_purge(vp)
	struct vnode *vp;
{
	struct namecache *ncp;
	struct nchashhead *ncpp;

	vp->v_id = ++nextvnodeid;
	if (nextvnodeid != 0)
		return;
	for (ncpp = &nchashtbl[nchash]; ncpp >= nchashtbl; ncpp--) {
		while (ncp = ncpp->lh_first)
			PURGE(ncp);
	}
	vp->v_id = ++nextvnodeid;
}

/*
 * Flush all entries referencing a particular filesystem.
 *
 * Since we need to check it anyway, we will flush all the invalid
 * entriess at the same time.
 */
void
cache_purgevfs(mp)
	struct mount *mp;
{
	struct nchashhead *ncpp;
	struct namecache *ncp, *nnp;

	/* Scan hash tables for applicable entries */
	for (ncpp = &nchashtbl[nchash]; ncpp >= nchashtbl; ncpp--) {
		for (ncp = ncpp->lh_first; ncp != 0; ncp = nnp) {
			nnp = ncp->nc_hash.le_next;
			if (ncp->nc_dvpid != ncp->nc_dvp->v_id ||
			    (ncp->nc_vp && ncp->nc_vpid != ncp->nc_vp->v_id) ||
			    ncp->nc_dvp->v_mount == mp) {
				PURGE(ncp);
			}
		}
	}
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
resize_string_ref_table()
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
add_name(const char *name, size_t len, u_int hashval, u_int flags)
{
    struct stringhead *head;
    string_t          *entry;
    int                chain_len = 0;
    
    //
    // If the table gets more than 3/4 full, resize it
    //
    if (4*filled_buckets >= ((string_table_mask + 1) * 3)) {
		if (resize_string_ref_table() != 0) {
			printf("failed to resize the hash table.\n");
		}
    }

    if (hashval == 0) {
	hashval = hash_string(name, len);
    }

    head = &string_ref_table[hashval & string_table_mask];
    for (entry=head->lh_first; entry != NULL; chain_len++, entry=entry->hash_chain.le_next) {
	if (strncmp(entry->str, name, len) == 0 && entry->str[len] == '\0') {
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

	LIST_INSERT_HEAD(head, entry, hash_chain);
	entry->str = (char *)((char *)entry + sizeof(string_t));
	strncpy(entry->str, name, len);
	entry->str[len] = '\0';
	entry->refcount = 1;

	if (chain_len > max_chain_len) {
	    max_chain_len   = chain_len;
	    long_chain_head = head;
	}

	nstrings++;
    }
    
    return entry->str;
}

int
remove_name(const char *nameref)
{
    struct stringhead *head;
    string_t          *entry;
    uint32_t           hashval;

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
    int                i;
    
    for(i=0; i <= string_table_mask; i++) {
	head = &string_ref_table[i];
	for (entry=head->lh_first; entry != NULL; entry=entry->hash_chain.le_next) {
	    printf("%6d - %s\n", entry->refcount, entry->str);
	}
    }
}
