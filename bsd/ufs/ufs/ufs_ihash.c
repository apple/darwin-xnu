/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1989, 1991, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)ufs_ihash.c	8.7 (Berkeley) 5/17/95
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/proc.h>

#include <ufs/ufs/quota.h>
#include <ufs/ufs/inode.h>
#include <ufs/ufs/ufs_extern.h>

/*
 * Structures associated with inode cacheing.
 */
LIST_HEAD(ihashhead, inode) *ihashtbl;
u_long	ihash;		/* size of hash table - 1 */
#define	INOHASH(device, inum)	(&ihashtbl[((device) + (inum)) & ihash])
struct slock ufs_ihash_slock;

/*
 * Initialize inode hash table.
 */
void
ufs_ihashinit()
{

	ihashtbl = hashinit(desiredvnodes, M_UFSMNT, &ihash);
	simple_lock_init(&ufs_ihash_slock);
}

/*
 * Use the device/inum pair to find the incore inode, and return a pointer
 * to it. If it is in core, return it, even if it is locked.
 */
struct vnode *
ufs_ihashlookup(dev, inum)
	dev_t dev;
	ino_t inum;
{
	struct inode *ip;

	simple_lock(&ufs_ihash_slock);
	for (ip = INOHASH(dev, inum)->lh_first; ip; ip = ip->i_hash.le_next)
		if (inum == ip->i_number && dev == ip->i_dev)
			break;
	simple_unlock(&ufs_ihash_slock);

	if (ip)
		return (ITOV(ip));
	return (NULLVP);
}

/*
 * Use the device/inum pair to find the incore inode, and return a pointer
 * to it. If it is in core, but locked, wait for it.
 */
struct vnode *
ufs_ihashget(dev, inum)
	dev_t dev;
	ino_t inum;
{
	struct proc *p = current_proc();	/* XXX */
	struct inode *ip;
	struct vnode *vp;

loop:
	simple_lock(&ufs_ihash_slock);
	for (ip = INOHASH(dev, inum)->lh_first; ip; ip = ip->i_hash.le_next) {
		if (inum == ip->i_number && dev == ip->i_dev) {
			vp = ITOV(ip);
			if (ip->i_flag & IN_TRANSIT) {
				/* inode is getting reclaimed wait till
				 * the operation is complete and return
				 * error
				 */
				ip->i_flag |= IN_WTRANSIT;
				simple_unlock(&ufs_ihash_slock);
				tsleep((caddr_t)ip, PINOD, "ufs_ihashget", 0);
				goto loop;
			}
			simple_lock(&vp->v_interlock);
			simple_unlock(&ufs_ihash_slock);
			if (vget(vp, LK_EXCLUSIVE | LK_INTERLOCK, p))
				goto loop;
			return (vp);
		}
	}
	simple_unlock(&ufs_ihash_slock);
	return (NULL);
}

/*
* Insert the inode into the hash table, and return it locked.
 */
void
ufs_ihashins(ip)
	struct inode *ip;
{
	struct proc *p = current_proc();		/* XXX */
	struct ihashhead *ipp;

	/* lock the inode, then put it on the appropriate hash list */
	lockmgr(&ip->i_lock, LK_EXCLUSIVE, (struct slock *)0, p);

	simple_lock(&ufs_ihash_slock);
	ipp = INOHASH(ip->i_dev, ip->i_number);
	LIST_INSERT_HEAD(ipp, ip, i_hash);
	simple_unlock(&ufs_ihash_slock);
}

/*
 * Remove the inode from the hash table.
 */
void
ufs_ihashrem(ip)
	struct inode *ip;
{
	struct inode *iq;

	simple_lock(&ufs_ihash_slock);
	LIST_REMOVE(ip, i_hash);
#if DIAGNOSTIC
	ip->i_hash.le_next = NULL;
	ip->i_hash.le_prev = NULL;
#endif
	simple_unlock(&ufs_ihash_slock);
}
