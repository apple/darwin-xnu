/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
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

/* Copyright (c) 1998 Apple Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1989, 1991, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *	  must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *	  may be used to endorse or promote products derived from this software
 *	  without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)hfs_vhash.c
 *	derived from @(#)ufs_ihash.c	8.7 (Berkeley) 5/17/95
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/queue.h>

#include "hfs.h"
#include "hfs_dbg.h"


/*
 * Structures associated with hfsnode cacheing.
 */
LIST_HEAD(vhashhead, hfsnode) *vhashtbl;
u_long	vhash;		/* size of hash table - 1 */
#define HFSNODEHASH(device, nodeID) (&vhashtbl[((device) + (nodeID)) & vhash])
struct slock hfs_vhash_slock;

/*
 * Initialize hfsnode hash table.
 */
void
hfs_vhashinit()
{

	vhashtbl = hashinit(desiredvnodes, M_HFSMNT, &vhash);
	simple_lock_init(&hfs_vhash_slock);
}

/*
 * Use the device/dirID/forkType tuple to find the incore hfsnode, and return a pointer
 * to it. If it is in core, but locked, wait for it.
 * 
 * Acceptable forkTypes are kData, kRsrcFork, kDirectory, or kDefault which translates to either
 * kDataFork or kDirectory
 *
 * While traversing the hash, expext that a hfsnode is in the midst of being allocated, if so, 
 * then sleep and try again
 */
struct vnode *
hfs_vhashget(dev, nodeID, forkType)
	dev_t dev;
	UInt32 nodeID;
	UInt8	forkType;
{
	struct proc *p = current_proc();
	struct hfsnode *hp;
	struct vnode *vp;

	/* 
	 * Go through the hash list
	 * If a vnode is in the process of being cleaned out or being
	 * allocated, wait for it to be finished and then try again
	 */
loop:
	simple_lock(&hfs_vhash_slock);
	for (hp = HFSNODEHASH(dev, nodeID)->lh_first; hp; hp = hp->h_hash.le_next) {
		if (hp->h_nodeflags & IN_ALLOCATING) {
			/*
			 * vnode is being created. Wait for it to finish...
			 */
			hp->h_nodeflags |= IN_WANT;
			simple_unlock(&hfs_vhash_slock);
			tsleep((caddr_t)hp, PINOD, "hfs_vhashget", 0);
			goto loop;
		}	
		if ((H_FILEID(hp) != nodeID) || (H_DEV(hp) != dev) ||
		    (hp->h_meta->h_metaflags & IN_NOEXISTS))
			continue;

		/* SER XXX kDefault of meta data (ksysfile) is not assumed here */
		if ( (forkType == kAnyFork) ||
			 (H_FORKTYPE(hp) == forkType) || 
			 ((forkType == kDefault) && ((H_FORKTYPE(hp) == kDirectory)
						|| (H_FORKTYPE(hp) == kDataFork)))) {
			vp = HTOV(hp);
			simple_lock(&vp->v_interlock);
			simple_unlock(&hfs_vhash_slock);
			if (vget(vp, LK_EXCLUSIVE | LK_INTERLOCK, p))
				goto loop;
			return (vp);
		}
	}
	simple_unlock(&hfs_vhash_slock);
	return (NULL);
}




/*
 * Lock the hfsnode and insert the hfsnode into the hash table, and return it locked.
 * Returns the sibling meta data if it exists, elses return NULL
 */
void
hfs_vhashins_sibling(dev, nodeID, hp, fm)
	dev_t dev;
	UInt32 nodeID;
	struct hfsnode *hp;
	struct hfsfilemeta **fm;
{
	struct vhashhead *ipp;
	struct hfsnode *thp;
	struct hfsfilemeta *tfm;

	tfm = NULL;
	lockmgr(&hp->h_lock, LK_EXCLUSIVE, (struct slock *)0, current_proc());

	/* 
	 * Go through the hash list to see if a sibling exists
	 * If it does, store it to return
	 * If a vnode is in the process of being cleaned out or being
	 * allocated, wait for it to be finished and then try again
	 */

	ipp = HFSNODEHASH(dev, nodeID);

loop:
	simple_lock(&hfs_vhash_slock);
	for (thp = ipp->lh_first; thp; thp = thp->h_hash.le_next) {
		if (thp->h_nodeflags & IN_ALLOCATING) {
			/*
			 * vnode is being created. Wait for it to finish...
			 */
			thp->h_nodeflags |= IN_WANT;
			simple_unlock(&hfs_vhash_slock);
			tsleep((caddr_t)thp, PINOD, "hfs_vhashins_sibling", 0);
			goto loop;
		}
		if ((H_FILEID(thp) == nodeID) && (H_DEV(thp) == dev)) {
			tfm = hp->h_meta = thp->h_meta;
			break;
		}
	}
	
	/* Add to sibling list..if it can have them */
	if (tfm && (H_FORKTYPE(hp)==kDataFork || H_FORKTYPE(hp)==kRsrcFork)) {
		simple_lock(&tfm->h_siblinglock);
		CIRCLEQ_INSERT_HEAD(&tfm->h_siblinghead, hp, h_sibling);
		simple_unlock(&tfm->h_siblinglock);
	};

	LIST_INSERT_HEAD(ipp, hp, h_hash);
	simple_unlock(&hfs_vhash_slock);
	*fm = tfm;
}



/*
* Lock the hfsnode and insert the hfsnode into the hash table, and return it locked.
 */
void
hfs_vhashins(dev, nodeID, hp)
	dev_t dev;
	UInt32 nodeID;
     struct hfsnode *hp;
{
    struct vhashhead *ipp;

    DBG_ASSERT(hp != NULL);
    DBG_ASSERT(nodeID != 0);

    lockmgr(&hp->h_lock, LK_EXCLUSIVE, (struct slock *)0, current_proc());

    simple_lock(&hfs_vhash_slock);
    ipp = HFSNODEHASH(dev, nodeID);
    LIST_INSERT_HEAD(ipp, hp, h_hash);
    simple_unlock(&hfs_vhash_slock);
}


/*
 * Remove the hfsnode from the hash table and then checks to see if another forks exists.
 */
void
hfs_vhashrem(hp)
	struct hfsnode *hp;
{

	DBG_ASSERT(hp != NULL);
	DBG_ASSERT(hp->h_meta != NULL);
	
	simple_lock(&hfs_vhash_slock);
	
	/* Test to see if there are siblings, should only apply to forks */
	if (hp->h_meta != NULL && hp->h_meta->h_siblinghead.cqh_first != NULL) {
		simple_lock(&hp->h_meta->h_siblinglock);
		CIRCLEQ_REMOVE(&hp->h_meta->h_siblinghead, hp, h_sibling);
		simple_unlock(&hp->h_meta->h_siblinglock);
	};
	
	LIST_REMOVE(hp, h_hash);

#if HFS_DIAGNOSTIC
	hp->h_hash.le_next = NULL;
	hp->h_hash.le_prev = NULL;
#endif

	
	simple_unlock(&hfs_vhash_slock);


}


/*
 * Moves the entries from one bucket to another
 * nodeID is the old bucket id
 */
void
hfs_vhashmove(hp, oldNodeID)
	struct hfsnode *hp;
	UInt32 oldNodeID;
{
	struct vhashhead *oldHeadIndex, *newHeadIndex;
	struct hfsnode *thp, *nextNode;
	UInt32 newNodeID;

	newNodeID = H_FILEID(hp);
	oldHeadIndex = HFSNODEHASH(H_DEV(hp), oldNodeID);
	newHeadIndex = HFSNODEHASH(H_DEV(hp), newNodeID);
	
	/* If it is moving to the same bucket...then we are done */
	if (oldHeadIndex == newHeadIndex)
		return;

loop:
	/* 
	 * Go through the old hash list
	 * If there is a nodeid mismatch, or the nodeid doesnt match the current bucket
	 * remove it and add it to the right bucket.
	 * If a vnode is in the process of being cleaned out or being
	 * allocated, wait for it to be finished and then try again
	 */
	simple_lock(&hfs_vhash_slock);
	for (nextNode = oldHeadIndex->lh_first; nextNode; )	{
		if (nextNode->h_nodeflags & IN_ALLOCATING) {
			/*
			 * vnode is being created. Wait for it to finish...
			 */
			nextNode->h_nodeflags |= IN_WANT;
			simple_unlock(&hfs_vhash_slock);
			tsleep((caddr_t)nextNode, PINOD, "hfs_vhashmove", 0);
			goto loop;
		}
			
		thp = nextNode;
		nextNode = nextNode->h_hash.le_next;
		if (newNodeID == H_FILEID(thp)) {
			LIST_REMOVE(thp, h_hash);
			thp->h_hash.le_next = NULL;
			thp->h_hash.le_next = NULL;
			LIST_INSERT_HEAD(newHeadIndex, thp, h_hash);
		}
	}
	
	simple_unlock(&hfs_vhash_slock);
}

#if HFS_DIAGNOSTIC
/*
 * This will test the hash entry for a given hfsnode
 * It will test:
 *		1. The uniqei existance of the node
 *		2. All other nodes, proper membership to the hash
 *		3. Proper termination of the hash
 *		4. All members have a non-null h_meta
 */
void hfs_vhash_dbg(hp)
	struct hfsnode *hp;
{
	struct proc *p = current_proc();	/* XXX */
	struct vnode *vp;
	struct hfsnode *thp, *tthp;
	int			maxsiblings = 1;
	int			wasFound = false;
	struct vhashhead *ipp, *jpp;
	dev_t 		dev = H_DEV(hp);
	UInt32 		nodeID = H_FILEID(hp);
	UInt8		forkType = H_FORKTYPE(hp);
	u_long		forksfound = 0;
	
	if (forkType==kDataFork || forkType==kRsrcFork)
		maxsiblings++;
		
	if (hp == NULL)
    	DEBUG_BREAK_MSG(("hash_dgh: Null hfsnode"));
	/* 
	 * Go through the hash list
	 * If a vnode is in the process of being cleaned out or being
	 * allocated, wait for it to be finished and then try again
	 */
	ipp = HFSNODEHASH(dev, nodeID);

loop:
	simple_lock(&hfs_vhash_slock);
	for (thp = ipp->lh_first; thp; thp = thp->h_hash.le_next)	{
		if (thp->h_nodeflags & IN_ALLOCATING) {		/* Its in the process of being allocated */
			simple_unlock(&hfs_vhash_slock);
			tsleep((caddr_t)thp, PINOD, "hfs_vhash_ins_meta", 0);
			goto loop;
		};
			
		if (thp->h_meta == NULL)
	    	DEBUG_BREAK_MSG(("hash_dgh: Null hfs_meta"));
	    jpp = (HFSNODEHASH(H_DEV(thp), H_FILEID(thp)));
	    if (ipp != jpp)
	    	DEBUG_BREAK_MSG(("hash_dgh: Member on wrong hash"));

		if ((H_FILEID(thp) == nodeID) && (H_DEV(thp) == dev)) {
			maxsiblings--;
			if (maxsiblings < 0)
		    	DEBUG_BREAK_MSG(("hash_dgh: Too many siblings"));
		    if ((1<<H_FORKTYPE(thp)) & forksfound)
		    	DEBUG_BREAK_MSG(("hash_dgh: Fork already found"));
		    forksfound |= (1<<H_FORKTYPE(thp));
		    
		    if (H_FORKTYPE(thp) == forkType) {
				if (wasFound == true)
			    	DEBUG_BREAK_MSG(("hash_dgh: Already found"));
		    	wasFound = true;
		    };
		};
	};
	simple_unlock(&hfs_vhash_slock);

	if (! wasFound)
    	DEBUG_BREAK_MSG(("hash_dgh: Not found"));

}

#endif /* HFS_DIAGNOSTIC */
